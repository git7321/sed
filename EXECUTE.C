/* GNU SED, a batch stream editor.
   Copyright (C) Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA. */

#undef EXPERIMENTAL_DASH_N_OPTIMIZATION
#define INITIAL_BUFFER_SIZE	50
#define FREAD_BUFFER_SIZE	8192

#include "sed.h"
#include <stdio.h>
#include <ctype.h>

#include <errno.h>
#ifndef errno
extern int errno;
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef __GNUC__
# if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__-0 >= 7)
#  define UNUSED	__attribute__((unused))
# endif
#endif
#ifndef UNUSED
# define UNUSED
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#else
# include <string.h>
#endif
#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif

#ifndef HAVE_STRCHR
# define strchr index
# define strrchr rindex
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif
#ifndef EXIT_SUCCESS
# define EXIT_SUCCESS 0
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <sys/stat.h>

struct line {
  char *text;
  char *active;
  size_t length;
  size_t alloc;
  bool chomped;
#ifdef HAVE_MBRTOWC
  mbstate_t mbstate;
#endif
};

struct append_queue {
  const char *fname;
  char *text;
  size_t textlen;
  struct append_queue *next;
  bool free;
};

struct input {
  char **file_list;
  countT bad_count;
  countT line_number;
  bool reset_at_next_file;
  bool (*read_fn) (struct input *);
  char *out_file_name;
  const char *in_file_name;
  FILE *fp;
  bool no_buffering;
};

static bool replaced = false;
static struct output output_file;
static struct line line;
static struct line s_accum;
static struct line hold;
static struct line buffer;

static struct append_queue *append_head = NULL;
static struct append_queue *append_tail = NULL;

#ifdef BOOTSTRAP
# ifdef memchr
#  undef memchr
# endif
# define memchr bootstrap_memchr

static VOID *
bootstrap_memchr(const VOID *s, int c, size_t n)
{
  char *p;

  for (p=(char *)s; n-- > 0; ++p)
    if (*p == c)
      return p;
  return CAST(VOID *)0;
}
#endif

static void
resize_line(struct line *lb, size_t len)
{
  size_t inactive;
  inactive = lb->active - lb->text;

  if (inactive > lb->alloc * 2)
    {
      MEMMOVE(lb->text, lb->active, lb->length);
      lb->alloc += lb->active - lb->text;
      lb->active = lb->text;
      inactive = 0;

      if (lb->alloc > len)
	return;
    }

  lb->alloc *= 2;
  if (lb->alloc < len)
    lb->alloc = len;
  if (lb->alloc < INITIAL_BUFFER_SIZE)
    lb->alloc = INITIAL_BUFFER_SIZE;

  lb->text = REALLOC(lb->text, inactive + lb->alloc, char);
  lb->active = lb->text + inactive;
}

static void
str_append(struct line *to, const char *string, size_t length)
{
  size_t new_length = to->length + length;

  if (to->alloc < new_length)
    resize_line(to, new_length);
  MEMCPY(to->active + to->length, string, length);
  to->length = new_length;

#ifdef HAVE_MBRTOWC
  if (mb_cur_max == 1)
    return;

  while (length)
    {
      int n = MBRLEN (string, length, &to->mbstate);

      if (n == -1)
	{
	  memset (&to->mbstate, 0, sizeof (to->mbstate));
	  n = 1;
	}

      if (n > 0)
	length -= n;
      else
	break;
    }
#endif
}

static void
str_append_modified(struct line *to, const char *string, size_t length,
					enum replacement_types type)
{
  size_t old_length = to->length;
#ifndef HAVE_MBRTOWC
  char *start, *end;
#endif

  if (length == 0)
    return;

#ifdef HAVE_MBRTOWC
  {
    mbstate_t from_stat;

    if (type == REPL_ASIS)
      {
	str_append(to, string, length);
        return;
      }

    if (to->alloc - to->length < length * mb_cur_max)
      resize_line(to, to->length + length * mb_cur_max);

    MEMCPY (&from_stat, &to->mbstate, sizeof(mbstate_t));
    while (length)
      {
	wchar_t wc;
        int n = MBRTOWC (&wc, string, length, &from_stat);

        if (n == -1)
          {
            memset (&to->mbstate, 0, sizeof (from_stat));
            n = 1;
          }

        if (n > 0)
          string += n, length -= n;
        else
	  {
	    str_append(to, string, length);
	    return;
	  }

        if (type & (REPL_UPPERCASE_FIRST | REPL_LOWERCASE_FIRST))
	  {
            if (type & REPL_UPPERCASE_FIRST)
              wc = towupper(wc);
            else
              wc = towlower(wc);

            type &= ~(REPL_LOWERCASE_FIRST | REPL_UPPERCASE_FIRST);
	    if (type == REPL_ASIS)
	      {
		n = WCRTOMB (to->active + to->length, wc, &to->mbstate);
		to->length += n;
		str_append(to, string, length);
	        return;
	      }
          }

        else if (type & REPL_UPPERCASE)
          wc = towupper(wc);
        else
          wc = towlower(wc);

	n = WCRTOMB (to->active + to->length, wc, &to->mbstate);
        to->length += n;
	if (n == -1)
	  {
	    fprintf (stderr, "Case conversion produced an invalid character!");
	    abort ();
	  }
      }
  }
#else
  str_append(to, string, length);
  start = to->active + old_length;
  end = start + length;

  if (type & REPL_UPPERCASE_FIRST)
    {
      *start = toupper(*start);
      start++;
      type &= ~REPL_UPPERCASE_FIRST;
    }
  else if (type & REPL_LOWERCASE_FIRST)
    {
      *start = tolower(*start);
      start++;
      type &= ~REPL_LOWERCASE_FIRST;
    }

  if (type == REPL_ASIS)
    return;

  if (type == REPL_UPPERCASE)
    for (; start != end; start++)
      *start = toupper(*start);
  else
    for (; start != end; start++)
      *start = tolower(*start);
#endif
}

static void
line_init(struct line *buf, size_t initial_size)
{
  buf->text = MALLOC(initial_size, char);
  buf->active = buf->text;
  buf->alloc = initial_size;
  buf->length = 0;
  buf->chomped = true;

#ifdef HAVE_MBRTOWC
  memset (&buf->mbstate, 0, sizeof (buf->mbstate));
#endif

}

static void
line_copy(struct line *from, struct line *to)
{
  to->alloc += to->active - to->text;

  if (to->alloc < from->length)
    {
      to->alloc *= 2;
      if (to->alloc < from->length)
	to->alloc = from->length;
      if (to->alloc < INITIAL_BUFFER_SIZE)
	to->alloc = INITIAL_BUFFER_SIZE;
      FREE(to->text);
      to->text = MALLOC(to->alloc, char);
    }

  to->active = to->text;
  to->length = from->length;
  to->chomped = from->chomped;
  MEMCPY(to->active, from->active, from->length);

#ifdef HAVE_MBRTOWC
  MEMCPY(&to->mbstate, &from->mbstate, sizeof (from->mbstate));
#endif
}

static void
line_append(struct line *from, struct line *to)
{
  str_append(to, "\n", 1);
  str_append(to, from->active, from->length);
  to->chomped = from->chomped;

#ifdef HAVE_MBRTOWC
  MEMCPY (&to->mbstate, &from->mbstate, sizeof (from->mbstate));
#endif
}

static void
line_exchange(struct line *a, struct line *b)
{
  struct line t;

  MEMCPY(&t,  a, sizeof(struct line));
  MEMCPY( a,  b, sizeof(struct line));
  MEMCPY( b, &t, sizeof(struct line));
}

static bool
read_always_fail(struct input *input)
{
  return false;
}

static bool read_file_line (struct input *);
static bool
read_file_line(struct input *input)
{
  static char *b;
  static size_t blen;

  long result = ck_getline (&b, &blen, input->fp);
  if (result <= 0)
    return false;

  if (b[result - 1] == '\n')
    --result;
  else
    line.chomped = false;

  str_append(&line, b, result);
  return true;
}

static __inline void
output_missing_newline(struct output *outf)
{
  if (outf->missing_newline)
    {
      ck_fwrite("\n", 1, 1, outf->fp);
      outf->missing_newline = false;
    }
}

static __inline void
flush_output(FILE *fp)
{
  if (fp != stdout || unbuffered_output)
    ck_fflush(fp);
}

static void
output_line(const char *text, size_t length, bool nl, struct output *outf)
{
  output_missing_newline(outf);

  if (length)
    ck_fwrite(text, 1, length, outf->fp);

  if (nl)
    ck_fwrite("\n", 1, 1, outf->fp);
  else
    outf->missing_newline = true;

  flush_output(outf->fp);
}

static struct append_queue *next_append_slot(void)
{
  struct append_queue *n = MALLOC(1, struct append_queue);

  n->fname = NULL;
  n->text = NULL;
  n->textlen = 0;
  n->next = NULL;
  n->free = false;

  if (append_tail)
      append_tail->next = n;
  else
      append_head = n;
  return append_tail = n;
}

static void
release_append_queue(void)
{
  struct append_queue *p, *q;

  for (p=append_head; p; p=q)
    {
      if (p->free)
        FREE(p->text);

      q = p->next;
      FREE(p);
    }
  append_head = append_tail = NULL;
}

static void
dump_append_queue(void)
{
  struct append_queue *p;

  output_missing_newline(&output_file);
  for (p=append_head; p; p=p->next)
    {
      if (p->text)
        ck_fwrite(p->text, 1, p->textlen, output_file.fp);

      if (p->fname)
	{
	  char buf[FREAD_BUFFER_SIZE];
	  size_t cnt;
	  FILE *fp;

	  fp = ck_fopen(p->fname, "rb", false);
	  if (fp)
	    {
	      while ((cnt = ck_fread(buf, 1, sizeof buf, fp)) > 0)
		ck_fwrite(buf, 1, cnt, output_file.fp);
	      ck_fclose(fp);
	    }
	}
    }

  flush_output(output_file.fp);
  release_append_queue();
}

static char *
get_backup_file_name(const char *name)
{
  char *old_asterisk, *asterisk, *backup, *p;
  int name_length = strlen(name), backup_length = strlen(in_place_extension);

  for (asterisk = in_place_extension - 1, old_asterisk = asterisk + 1;
       asterisk = strchr(old_asterisk, '*');
       old_asterisk = asterisk + 1)
    backup_length += name_length - 1;

  p = backup = xmalloc(backup_length + 1);

  for (asterisk = in_place_extension - 1, old_asterisk = asterisk + 1;
       asterisk = strchr(old_asterisk, '*');
       old_asterisk = asterisk + 1)
    {
      MEMCPY (p, old_asterisk, asterisk - old_asterisk);
      p += asterisk - old_asterisk;
      strcpy (p, name);
      p += name_length;
    }

  strcpy (p, old_asterisk);
  return backup;
}

static void
open_next_file(const char *name, struct input *input)
{
  buffer.length = 0;

  if (name[0] == '-' && name[1] == '\0' && !in_place_extension)
    {
      clearerr(stdin);
      input->fp = stdin;
    }
  else if ( ! (input->fp = ck_fopen(name, "rb", false)) )
    {
      const char *ptr = strerror(errno);
      fprintf(stderr, _("%s: can't read %s: %s\n"), myname, name, ptr);
      input->read_fn = read_always_fail;
      ++input->bad_count;
      return;
    }

  input->read_fn = read_file_line;

  if (in_place_extension)
    {
      int output_fd;
      char *tmpdir = ck_strdup(name), *p;
      struct stat st;

      if (p = strrchr(tmpdir, '/'))
	*(p + 1) = 0;
      else
	strcpy(tmpdir, ".");

      input->in_file_name = name;

      if (isatty (fileno (input->fp)))
        panic(_("couldn't edit %s: is a terminal"), input->in_file_name);

      fstat (fileno (input->fp), &st);
      if (!S_ISREG (st.st_mode))
        panic(_("couldn't edit %s: not a regular file"), input->in_file_name);

      output_file.fp = ck_mkstemp (&input->out_file_name, tmpdir, "sed");
      output_file.missing_newline = false;
      free (tmpdir);

      if (!output_file.fp)
        panic(_("couldn't open temporary file %s: %s"), input->out_file_name, strerror(errno));

      output_fd = fileno (output_file.fp);
#ifdef HAVE_FCHMOD
      fchmod (output_fd, st.st_mode);
#endif
#ifdef HAVE_FCHOWN
      if (fchown (output_fd, st.st_uid, st.st_gid) == -1)
        fchown (output_fd, -1, st.st_gid);
#endif
    }
  else
    output_file.fp = stdout;
}

static void
closedown(struct input *input)
{
  input->read_fn = read_always_fail;
  if (!input->fp)
    return;
  if (input->fp != stdin)
    ck_fclose(input->fp);

  if (in_place_extension && output_file.fp != NULL)
    {
      ck_fclose (output_file.fp);
      if (strcmp(in_place_extension, "*") != 0)
        {
          char *backup_file_name = get_backup_file_name(input->in_file_name);
	  ck_rename (input->in_file_name, backup_file_name, input->out_file_name);
          free (backup_file_name);
	}

      ck_rename (input->out_file_name, input->in_file_name, input->out_file_name);
      free (input->out_file_name);
    }

  input->fp = NULL;
}

static void
reset_addresses(struct vector *vec)
{
  struct sed_cmd *cur_cmd;
  int n;

  for (cur_cmd = vec->v, n = vec->v_length; n--; cur_cmd++)
    if (cur_cmd->a1
	&& cur_cmd->a1->addr_type == ADDR_IS_NUM
	&& cur_cmd->a1->addr_number == 0)
      cur_cmd->range_state = RANGE_ACTIVE;
    else
      cur_cmd->range_state = RANGE_INACTIVE;
}

static bool
read_pattern_space(struct input *input, struct vector *the_program, bool append)
{
  if (append_head)
    dump_append_queue();
  replaced = false;
  if (!append)
    line.length = 0;
  line.chomped = true;

  while ( ! (*input->read_fn)(input) )
    {
      closedown(input);

      if (!*input->file_list)
	return false;

      if (input->reset_at_next_file)
	{
	  input->line_number = 0;
	  reset_addresses (the_program);
	  rewind_read_files ();

	  if (in_place_extension)
	    output_file.missing_newline = false;

	  input->reset_at_next_file = separate_files;
	}

      open_next_file (*input->file_list++, input);
    }

  ++input->line_number;
  return true;
}

static bool
last_file_with_data_p(struct input *input)
{
  for (;;)
   {
      int ch;

      closedown(input);
      if (!*input->file_list)
	return true;
      open_next_file(*input->file_list++, input);
      if (input->fp)
	{
	  if ((ch = getc(input->fp)) != EOF)
	    {
	      ungetc(ch, input->fp);
	      return false;
	    }
	}
   }
}

static bool
test_eof(struct input *input)
{
  int ch;

  if (buffer.length)
    return false;
  if (!input->fp)
    return separate_files || last_file_with_data_p(input);
  if (feof(input->fp))
    return separate_files || last_file_with_data_p(input);
  if ((ch = getc(input->fp)) == EOF)
    return separate_files || last_file_with_data_p(input);
  ungetc(ch, input->fp);
  return false;
}

static bool
match_an_address_p(struct addr *addr, struct input *input)
{
  switch (addr->addr_type)
    {
    case ADDR_IS_NULL:
      return true;

    case ADDR_IS_REGEX:
      return match_regex(addr->addr_regex, line.active, line.length, 0, NULL, 0);

    case ADDR_IS_NUM_MOD:
      return (input->line_number >= addr->addr_number
	      && ((input->line_number - addr->addr_number) % addr->addr_step) == 0);

    case ADDR_IS_STEP:
    case ADDR_IS_STEP_MOD:
      return (addr->addr_number <= input->line_number);

    case ADDR_IS_LAST:
      return test_eof(input);

    case ADDR_IS_NUM:
    default:
      panic("INTERNAL ERROR: bad address type");
    }
  return false;
}

static bool
match_address_p(struct sed_cmd *cmd, struct input *input)
{
  if (!cmd->a1)
    return true;

  if (cmd->range_state != RANGE_ACTIVE)
    {
      if (cmd->a1->addr_type == ADDR_IS_NUM)
	{
	  if (!cmd->a2)
	    return (input->line_number == cmd->a1->addr_number);

	  if (cmd->range_state == RANGE_CLOSED
	      || input->line_number < cmd->a1->addr_number)
	    return false;
	}
      else
	{
          if (!cmd->a2)
	    return match_an_address_p(cmd->a1, input);

	  if (!match_an_address_p(cmd->a1, input))
            return false;
	}

      cmd->range_state = RANGE_ACTIVE;
      switch (cmd->a2->addr_type)
	{
	case ADDR_IS_REGEX:
	  return true;
	case ADDR_IS_NUM:
          if (input->line_number >= cmd->a2->addr_number)
	    cmd->range_state = RANGE_CLOSED;
          return true;
	case ADDR_IS_STEP:
	  cmd->a2->addr_number = input->line_number + cmd->a2->addr_step;
	  return true;
	case ADDR_IS_STEP_MOD:
	  cmd->a2->addr_number = input->line_number + cmd->a2->addr_step
				 - (input->line_number%cmd->a2->addr_step);
	  return true;
	default:
	  break;
        }
    }

  if (cmd->a2->addr_type == ADDR_IS_NUM)
    {
      if (input->line_number >= cmd->a2->addr_number)
	cmd->range_state = RANGE_CLOSED;

      return (input->line_number <= cmd->a2->addr_number);
   }

  if (match_an_address_p(cmd->a2, input))
    cmd->range_state = RANGE_CLOSED;

  return true;
}

static void
do_list(int line_len)
{
  unsigned char *p = CAST(unsigned char *)line.active;
  countT len = line.length;
  countT width = 0;
  char obuf[180];
  char *o;
  size_t olen;
  FILE *fp = output_file.fp;

  output_missing_newline(&output_file);
  for (; len--; ++p) {
      o = obuf;

#if defined isascii || defined HAVE_ISASCII
      if (isascii(*p) && ISPRINT(*p)) {
#else
      if (ISPRINT(*p)) {
#endif
	  *o++ = *p;
	  if (*p == '\\')
	    *o++ = '\\';
      } else {
	  *o++ = '\\';
	  switch (*p) {
	    case '\a': *o++ = 'a'; break;
	    case '\b': *o++ = 'b'; break;
	    case '\f': *o++ = 'f'; break;
	    case '\n': *o++ = 'n'; break;
	    case '\r': *o++ = 'r'; break;
	    case '\t': *o++ = 't'; break;
	    case '\v': *o++ = 'v'; break;
	    default:
	      sprintf(o, "%03o", *p);
	      o += strlen(o);
	      break;
	    }
      }
      olen = o - obuf;
      if ((int)(width+olen) >= line_len && line_len > 0) {
	  ck_fwrite("\\\n", 1, 2, fp);
	  width = 0;
      }
      ck_fwrite(obuf, 1, olen, fp);
      width += olen;
  }
  ck_fwrite("$\n", 1, 2, fp);
  flush_output (fp);
}

static enum replacement_types
append_replacement (struct line *buf, struct replacement *p,
					struct re_registers *regs, enum replacement_types repl_mod)
{
  for (; p; p=p->next)
    {
      int i = p->subst_id;
      enum replacement_types curr_type;

      curr_type = (p->repl_type & REPL_MODIFIERS)
        ? p->repl_type
        : p->repl_type | repl_mod;

      repl_mod = 0;
      if (p->prefix_length)
        {
          str_append_modified(buf, p->prefix, p->prefix_length,
    			      curr_type);
          curr_type &= ~REPL_MODIFIERS;
        }

      if (0 <= i)
        if (regs->end[i] == regs->start[i] && p->repl_type & REPL_MODIFIERS)
	  repl_mod = curr_type & REPL_MODIFIERS;

	else
	  str_append_modified(buf, line.active + regs->start[i],
			      CAST(size_t)(regs->end[i] - regs->start[i]),
			      curr_type);
    }

  return repl_mod;
}

static void
do_subst(struct subst *sub)
{
  size_t start = 0;
  size_t last_end = 0;
  countT count = 0;
  bool again = true;

  static struct re_registers regs;

  if (s_accum.alloc == 0)
    line_init(&s_accum, INITIAL_BUFFER_SIZE);
  s_accum.length = 0;

  if (!match_regex(sub->regx, line.active, line.length, start,
		   &regs, sub->max_id + 1))
    return;

  if (!sub->replacement && sub->numb <= 1)
    if (regs.start[0] == 0 && !sub->global)
      {
	replaced = true;

	line.active += regs.end[0];
	line.length -= regs.end[0];
	line.alloc -= regs.end[0];
	goto post_subst;
      }
    else if (regs.end[0] == (int)line.length)
      {
	replaced = true;

	line.length = regs.start[0];
	goto post_subst;
      }
  do
    {
      enum replacement_types repl_mod = 0;

      size_t offset = regs.start[0];
      size_t matched = regs.end[0] - regs.start[0];

      if (start < offset)
	str_append(&s_accum, line.active + start, offset - start);

      if ((matched > 0 || count == 0 || offset > last_end)
	  && ++count >= sub->numb)
        {
          replaced = true;

          repl_mod = append_replacement (&s_accum, sub->replacement, &regs, repl_mod);
	  again = sub->global;
        }
      else
	{
	  if (matched == 0)
	    {
	      if (start < line.length)
	        matched = 1;
	      else
	        break;
	    }

	  str_append(&s_accum, line.active + offset, matched);
        }

      start = offset + matched;
      last_end = regs.end[0];
    }
  while (again
	 && start <= line.length
	 && match_regex(sub->regx, line.active, line.length, start,
			&regs, sub->max_id + 1));

  if (start < line.length)
    str_append(&s_accum, line.active + start, line.length-start);
  s_accum.chomped = line.chomped;

  line_exchange(&line, &s_accum);

  if (count < sub->numb)
    return;

 post_subst:
  if (sub->print & 1)
    output_line(line.active, line.length, line.chomped, &output_file);

  if (sub->eval)
    {
#ifdef HAVE_POPEN
      FILE *pipe;
      s_accum.length = 0;

      str_append (&line, "", 1);
      pipe = popen(line.active, "rb");

      if (pipe != NULL)
	{
	  while (!feof (pipe))
	    {
	      char buf[4096];
	      int n = fread (buf, sizeof(char), 4096, pipe);
	      if (n > 0)
		str_append(&s_accum, buf, n);
	    }

	  pclose (pipe);

	  line_exchange(&line, &s_accum);
	  if (line.length &&
	      line.active[line.length - 1] == '\n')
	    line.length--;
	}
      else
	panic(_("error in subprocess"));
#else
      panic(_("option `e' not supported"));
#endif
    }

  if (sub->print & 2)
    output_line(line.active, line.length, line.chomped, &output_file);
  if (sub->outf)
    output_line(line.active, line.length, line.chomped, sub->outf);
}

#ifdef EXPERIMENTAL_DASH_N_OPTIMIZATION

static countT branches;

static countT
count_branches(struct vector *program)
{
  struct sed_cmd *cur_cmd = program->v;
  countT isn_cnt = program->v_length;
  countT cnt = 0;

  while (isn_cnt-- > 0)
    {
      switch (cur_cmd->cmd)
	{
	case 'b':
	case 't':
	case 'T':
	case '{':
	  ++cnt;
	}
    }
  return cnt;
}

static struct sed_cmd *
shrink_program(struct vector *vec, struct sed_cmd *cur_cmd)
{
  struct sed_cmd *v = vec->v;
  struct sed_cmd *last_cmd = v + vec->v_length;
  struct sed_cmd *p;
  countT cmd_cnt;

  for (p=v; p < cur_cmd; ++p)
    if (p->cmd != '#')
      MEMCPY(v++, p, sizeof *v);
  cmd_cnt = v - vec->v;

  for (; p < last_cmd; ++p)
    if (p->cmd != '#')
      MEMCPY(v++, p, sizeof *v);
  vec->v_length = v - vec->v;

  return (0 < vec->v_length) ? (vec->v + cmd_cnt) : CAST(struct sed_cmd *)0;
}
#endif /*EXPERIMENTAL_DASH_N_OPTIMIZATION*/

static int
execute_program(struct vector *vec, struct input *input)
{
  struct sed_cmd *cur_cmd;
  struct sed_cmd *end_cmd;

  cur_cmd = vec->v;
  end_cmd = vec->v + vec->v_length;
  while (cur_cmd < end_cmd)
    {
      if (match_address_p(cur_cmd, input) != cur_cmd->addr_bang)
	{
	  switch (cur_cmd->cmd)
	    {
	    case 'a':
	      {
		struct append_queue *aq = next_append_slot();
		aq->text = cur_cmd->x.cmd_txt.text;
		aq->textlen = cur_cmd->x.cmd_txt.text_length;
	      }
	      break;

	    case '{':
	    case 'b':
	      cur_cmd = vec->v + cur_cmd->x.jump_index;
	      continue;

	    case '}':
	    case '#':
	    case ':':
	      break;

	    case 'c':
	      if (cur_cmd->range_state != RANGE_ACTIVE)
		output_line(cur_cmd->x.cmd_txt.text,
			    cur_cmd->x.cmd_txt.text_length - 1, true,
			    &output_file);
	    case 'd':
	      return -1;

	    case 'D':
	      {
		char *p = memchr(line.active, '\n', line.length);
		if (!p)
		  return -1;

		++p;
		line.alloc -= p - line.active;
		line.length -= p - line.active;
		line.active += p - line.active;

		cur_cmd = vec->v;
		continue;
	      }

	    case 'e': {
#ifdef HAVE_POPEN
	      FILE *pipe;
	      int cmd_length = cur_cmd->x.cmd_txt.text_length;
	      if (s_accum.alloc == 0)
		line_init(&s_accum, INITIAL_BUFFER_SIZE);
	      s_accum.length = 0;

	      if (!cmd_length)
		{
		  str_append (&line, "", 1);
		  pipe = popen(line.active, "rb");
		}
	      else
		{
		  cur_cmd->x.cmd_txt.text[cmd_length - 1] = 0;
		  pipe = popen(cur_cmd->x.cmd_txt.text, "rb");
                  output_missing_newline(&output_file);
		}

	      if (pipe != NULL)
		{
		  while (!feof (pipe))
		    {
		      char buf[4096];
		      int n = fread (buf, sizeof(char), 4096, pipe);
		      if (n > 0)
			if (!cmd_length)
			  str_append(&s_accum, buf, n);
			else
			  ck_fwrite(buf, 1, n, output_file.fp);
		    }

		  pclose (pipe);
		  if (!cmd_length)
		    {
		      if (s_accum.length &&
			  s_accum.active[s_accum.length - 1] == '\n')
			s_accum.length--;

		      line_exchange(&line, &s_accum);
		    }
                  else
                    flush_output(output_file.fp);

		}
	      else
		panic(_("error in subprocess"));
#else
	      panic(_("`e' command not supported"));
#endif
	      break;
	    }

	    case 'g':
	      line_copy(&hold, &line);
	      break;

	    case 'G':
	      line_append(&hold, &line);
	      break;

	    case 'h':
	      line_copy(&line, &hold);
	      break;

	    case 'H':
	      line_append(&line, &hold);
	      break;

	    case 'i':
	      output_line(cur_cmd->x.cmd_txt.text,
			  cur_cmd->x.cmd_txt.text_length - 1,
			  true, &output_file);
	      break;

	    case 'l':
	      do_list(cur_cmd->x.int_arg == -1
		      ? lcmd_out_line_len
		      : cur_cmd->x.int_arg);
	      break;

	    case 'L':
              output_missing_newline(&output_file);
	      fmt(line.active, line.active + line.length,
		  cur_cmd->x.int_arg == -1
		  ? lcmd_out_line_len
		  : cur_cmd->x.int_arg,
		  output_file.fp);
              flush_output(output_file.fp);
	      break;

	    case 'n':
	      if (!no_default_output)
		output_line(line.active, line.length, line.chomped, &output_file);
	      if (test_eof(input) || !read_pattern_space(input, vec, false))
		return -1;
	      break;

	    case 'N':
	      str_append(&line, "\n", 1);

              if (test_eof(input) || !read_pattern_space(input, vec, true))
                {
                  line.length--;
                  if (posixicity == POSIXLY_EXTENDED && !no_default_output)
                     output_line(line.active, line.length, line.chomped,
                                 &output_file);
                  return -1;
                }
	      break;

	    case 'p':
	      output_line(line.active, line.length, line.chomped, &output_file);
	      break;

	    case 'P':
	      {
		char *p = memchr(line.active, '\n', line.length);
		output_line(line.active, p ? p - line.active : line.length,
			    p ? true : line.chomped, &output_file);
	      }
	      break;

            case 'q':
              if (!no_default_output)
                output_line(line.active, line.length, line.chomped, &output_file);
	      dump_append_queue();

	    case 'Q':
	      return cur_cmd->x.int_arg == -1 ? 0 : cur_cmd->x.int_arg;

	    case 'r':
	      if (cur_cmd->x.fname)
		{
		  struct append_queue *aq = next_append_slot();
		  aq->fname = cur_cmd->x.fname;
		}
	      break;

	    case 'R':
	      if (cur_cmd->x.fp && !feof (cur_cmd->x.fp))
		{
		  struct append_queue *aq;
		  size_t buflen;
		  char *text = NULL;
		  int result;

		  result = ck_getline (&text, &buflen, cur_cmd->x.fp);
		  if (result != EOF)
		    {
		      aq = next_append_slot();
		      aq->free = true;
		      aq->text = text;
		      aq->textlen = result;
		    }
		}
	      break;

	    case 's':
	      do_subst(cur_cmd->x.cmd_subst);
	      break;

	    case 't':
	      if (replaced)
		{
		  replaced = false;
		  cur_cmd = vec->v + cur_cmd->x.jump_index;
		  continue;
		}
	      break;

	    case 'T':
	      if (!replaced)
		{
		  cur_cmd = vec->v + cur_cmd->x.jump_index;
		  continue;
		}
	      else
		replaced = false;
	      break;

	    case 'w':
	      if (cur_cmd->x.fp)
		output_line(line.active, line.length,
			    line.chomped, cur_cmd->x.outf);
	      break;

	    case 'W':
	      if (cur_cmd->x.fp)
	        {
		  char *p = memchr(line.active, '\n', line.length);
		  output_line(line.active, p ? p - line.active : line.length,
			      p ? true : line.chomped, cur_cmd->x.outf);
	        }
	      break;

	    case 'x':
	      line_exchange(&line, &hold);
	      break;

	    case 'y':
	      {
#ifdef HAVE_MBRTOWC
               if (mb_cur_max > 1)
                 {
                   int idx, prev_idx;
                   char **trans;
                   mbstate_t mbstate;
                   memset(&mbstate, 0, sizeof(mbstate_t));
                   for (idx = 0; idx < (int)line.length;)
                     {
                       int mbclen, i;
                       mbclen = MBRLEN (line.active + idx, line.length - idx,
                                          &mbstate);
                       if (mbclen == -1 || mbclen == -2
                           || mbclen == 0)
                         mbclen = 1;

                       trans = cur_cmd->x.translatemb;
                       for (i = 0; trans[2*i] != NULL; i++)
                         {
                           if (strncmp(line.active + idx, trans[2*i], mbclen) == 0)
                             {
                               bool move_remain_buffer = false;
                               int trans_len = strlen(trans[2*i+1]);

                               if (mbclen < trans_len)
                                 {
                                   int new_len;
                                   new_len = line.length + 1 + trans_len - mbclen;
                                   if ((int)line.alloc < new_len)
                                     {
                                       resize_line(&line, new_len);
                                     }
                                   move_remain_buffer = true;
                                 }
                               else if (mbclen > trans_len)
                                 {
                                   move_remain_buffer = true;
                                 }
                               prev_idx = idx;
                               if (move_remain_buffer)
                                 {
                                   int move_len, move_offset;
                                   char *move_from, *move_to;
                                   move_from = line.active + idx + mbclen;
                                   move_to = line.active + idx + trans_len;
                                   move_len = line.length + 1 - idx - mbclen;
                                   move_offset = trans_len - mbclen;
                                   memmove(move_to, move_from, move_len);
                                   line.length += move_offset;
                                   idx += move_offset;
                                 }
                               strncpy(line.active + prev_idx, trans[2*i+1],
                                       trans_len);
                               break;
                             }
                         }
                       idx += mbclen;
                     }
                 }
               else
#endif /* HAVE_MBRTOWC */
                 {
                   unsigned char *p, *e;
                   p = CAST(unsigned char *)line.active;
                   for (e=p+line.length; p<e; ++p)
                     *p = cur_cmd->x.translate[*p];
                 }
	      }
	      break;

	    case '=':
              output_missing_newline(&output_file);
              fprintf(output_file.fp, "%lu\n",
                      CAST(unsigned long)input->line_number);
              flush_output(output_file.fp);
	      break;

	    default:
	      panic("INTERNAL ERROR: Bad cmd %c", cur_cmd->cmd);
	    }
	}

#ifdef EXPERIMENTAL_DASH_N_OPTIMIZATION
      else if (!separate_files)
	{
	  if (cur_cmd->a1->addr_type == ADDR_IS_NUM
	      && (cur_cmd->a2
		  ? cur_cmd->range_state == RANGE_CLOSED
		  : cur_cmd->a1->addr_number < input->line_number))
	    {
	      cur_cmd->addr_bang = !cur_cmd->addr_bang;
	      cur_cmd->a1->addr_type = ADDR_IS_NULL;
	      if (cur_cmd->a2)
		cur_cmd->a2->addr_type = ADDR_IS_NULL;

	      if (cur_cmd->addr_bang)
		{
		  if (cur_cmd->cmd == 'b' || cur_cmd->cmd == 't'
		      || cur_cmd->cmd == 'T' || cur_cmd->cmd == '}')
		    branches--;

		  cur_cmd->cmd = '#';
	          if (branches == 0)
		    cur_cmd = shrink_program(vec, cur_cmd);
		  if (!cur_cmd && no_default_output)
		    return 0;
		  end_cmd = vec->v + vec->v_length;
		  if (!cur_cmd)
		    cur_cmd = end_cmd;
		  continue;
		}
	    }
	}
#endif /*EXPERIMENTAL_DASH_N_OPTIMIZATION*/

      ++cur_cmd;
    }

    if (!no_default_output)
      output_line(line.active, line.length, line.chomped, &output_file);
    return -1;
}

int
process_files(struct vector *the_program, char **argv)
{
  static char dash[] = "-";
  static char *stdin_argv[2] = { dash, NULL };
  struct input input;
  int status;

  line_init(&line, INITIAL_BUFFER_SIZE);
  line_init(&hold, 0);
  line_init(&buffer, 0);

#ifdef EXPERIMENTAL_DASH_N_OPTIMIZATION
  branches = count_branches(the_program);
#endif /*EXPERIMENTAL_DASH_N_OPTIMIZATION*/
  input.reset_at_next_file = true;
  if (argv && *argv)
    input.file_list = argv;
  else if (in_place_extension)
    panic(_("no input files"));
  else
    input.file_list = stdin_argv;

  input.bad_count = 0;
  input.line_number = 0;
  input.read_fn = read_always_fail;
  input.fp = NULL;

  status = EXIT_SUCCESS;
  while (read_pattern_space(&input, the_program, false))
    {
      status = execute_program(the_program, &input);
      if (status == -1)
	status = EXIT_SUCCESS;
      else
	break;
    }
  closedown(&input);

#ifdef DEBUG_LEAKS
  release_append_queue();
  FREE(buffer.text);
  FREE(hold.text);
  FREE(line.text);
  FREE(s_accum.text);
#endif /*DEBUG_LEAKS*/

  if (input.bad_count)
    status = 2;

  return status;
}

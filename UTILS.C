/* Functions from hack's utils library.
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

#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils.h"

extern size_t getline ();

int
w32_rename(const char *oldfile, const char *newfile)
{
    chmod(newfile, _S_IWRITE);
    unlink(newfile);
    return rename(oldfile, newfile);
}

int
mkstemp (char *template)
{
  char *tmpfilename;
  int fd;
  tmpfilename = _mktemp (template);
  fd = _open (tmpfilename, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE );
  if (fd != -1)
    return fd;
  errno = EEXIST;
  return -1;

}

const char *myname;

struct open_file
  {
    FILE *fp;
    char *name;
    struct open_file *link;
    unsigned temp : 1;
  };

static struct open_file *open_files = NULL;
static void do_ck_fclose P_((FILE *fp));

void
panic(const char *str, ...)
{
  va_list iggy;

  fprintf(stderr, "%s: ", myname);
  va_start(iggy, str);
#ifndef HAVE_VPRINTF
# ifndef HAVE_DOPRNT
  fputs(str, stderr);
# else /* HAVE_DOPRNT */
  _doprnt(str, &iggy, stderr);
# endif /* HAVE_DOPRNT */
#else /* HAVE_VFPRINTF */
  vfprintf(stderr, str, iggy);
#endif /* HAVE_VFPRINTF */
  va_end(iggy);
  putc('\n', stderr);

  while (open_files)
    {
      if (open_files->temp)
	{
	  fclose (open_files->fp);
	  errno = 0;
	  unlink (open_files->name);
          if (errno != 0)
            fprintf (stderr, _("cannot remove %s: %s"), open_files->name, strerror (errno));
	}

      open_files = open_files->link;
    }

  exit(4);
}

static const char *
utils_fp_name(FILE *fp)
{
  struct open_file *p;

  for (p=open_files; p; p=p->link)
    if (p->fp == fp)
      return p->name;
  if (fp == stdin)
    return "stdin";
  else if (fp == stdout)
    return "stdout";
  else if (fp == stderr)
    return "stderr";

  return "<unknown>";
}

FILE *
ck_fopen(const char *name, const char *mode, bool fail)
{
  FILE *fp;
  struct open_file *p;

  fp = fopen (name, mode);
  if (!fp)
    {
      if (fail)
        panic(_("couldn't open file %s: %s"), name, strerror(errno));

      return NULL;
    }

  for (p=open_files; p; p=p->link)
    {
      if (fp == p->fp)
	{
	  FREE(p->name);
	  break;
	}
    }
  if (!p)
    {
      p = MALLOC(1, struct open_file);
      p->link = open_files;
      open_files = p;
    }
  p->name = ck_strdup(name);
  p->fp = fp;
  p->temp = false;
  return fp;
}

FILE *
ck_mkstemp (char **p_filename, char *tmpdir, char *base)
{
  char *template;
  FILE *fp;
  int fd;
  struct open_file *p;

  if (tmpdir == NULL)
    tmpdir = getenv("TEMP");
  if (tmpdir == NULL)
    {
      tmpdir = getenv("TMP");
    }

  template = xmalloc (strlen (tmpdir) + strlen (base) + 8);
  sprintf (template, "%s/%sXXXXXX", tmpdir, base);

  fd = mkstemp (template);
  if (fd == -1)
    panic(_("couldn't open temporary file %s: %s"), template, strerror(errno));

  *p_filename = template;
  fp = fdopen (fd, "wb");

  p = MALLOC(1, struct open_file);
  p->name = ck_strdup (template);
  p->fp = fp;
  p->temp = true;
  p->link = open_files;
  open_files = p;
  return fp;
}

void
ck_fwrite(const VOID *ptr, size_t size, size_t nmemb, FILE *stream)
{
  clearerr(stream);
  if (size && fwrite(ptr, size, nmemb, stream) != nmemb)
    panic(ngettext("couldn't write %d item to %s: %s",
		   "couldn't write %d items to %s: %s", nmemb),
		nmemb, utils_fp_name(stream), strerror(errno));
}

size_t
ck_fread(VOID *ptr, size_t size, size_t nmemb, FILE *stream)
{
  clearerr(stream);
  if (size && (nmemb=fread(ptr, size, nmemb, stream)) <= 0 && ferror(stream))
    panic(_("read error on %s: %s"), utils_fp_name(stream), strerror(errno));

  return nmemb;
}

size_t
ck_getline(char **text, size_t *buflen, FILE *stream)
{
  int result;
  if (!ferror (stream))
    result = getline (text, buflen, stream);

  if (ferror (stream))
    panic (_("read error on %s: %s"), utils_fp_name(stream), strerror(errno));

  return result;
}

void
ck_fflush(FILE *stream)
{
  clearerr(stream);
  if (fflush(stream) == EOF && errno != EBADF)
    panic("couldn't flush %s: %s", utils_fp_name(stream), strerror(errno));
}

void
ck_fclose(FILE *stream)
{
  struct open_file r;
  struct open_file *prev;
  struct open_file *cur;

  r.link = open_files;
  prev = &r;
  while ( (cur = prev->link) )
    {
      if (!stream || stream == cur->fp)
	{
	  do_ck_fclose (cur->fp);
	  prev->link = cur->link;
	  FREE(cur->name);
	  FREE(cur);
	}
      else
	prev = cur;
    }

  open_files = r.link;

  if (!stream)
    {
      do_ck_fclose (stdout);
      do_ck_fclose (stderr);
    }
}

void
do_ck_fclose(FILE *fp)
{
  ck_fflush(fp);
  clearerr(fp);

  if (fclose(fp) == EOF)
    panic("couldn't close %s: %s", utils_fp_name(fp), strerror(errno));
}

void
ck_rename (const char *from, const char *to, const char *unlink_if_fail)
{
  int rd = w32_rename (from, to);
  if (rd != -1)
    return;

  if (unlink_if_fail)
    {
      int save_errno = errno;
      errno = 0;
      unlink (unlink_if_fail);

      if (errno != 0)
        panic (_("cannot remove %s: %s"), unlink_if_fail, strerror (errno));

      errno = save_errno;
    }

  panic (_("cannot rename %s: %s"), from, strerror (errno));
}

VOID *
ck_malloc(size_t size)
{
  VOID *ret = calloc(1, size ? size : 1);
  if (!ret)
    panic("couldn't allocate memory");
  return ret;
}

VOID *
xmalloc(size_t size)
{
  return ck_malloc(size);
}

VOID *
ck_realloc(VOID *ptr, size_t size)
{
  VOID *ret;

  if (size == 0)
    {
      FREE(ptr);
      return NULL;
    }
  if (!ptr)
    return ck_malloc(size);
  ret = realloc(ptr, size);
  if (!ret)
    panic("couldn't re-allocate memory");
  return ret;
}

char *
ck_strdup(const char *str)
{
  char *ret = MALLOC(strlen(str)+1, char);
  return strcpy(ret, str);
}

VOID *
ck_memdup(const VOID *buf, size_t len)
{
  VOID *ret = ck_malloc(len);
  return memcpy(ret, buf, len);
}

void
ck_free(VOID *ptr)
{
  if (ptr)
    free(ptr);
}

struct buffer
  {
    size_t allocated;
    size_t length;
    char *b;
  };

#define MIN_ALLOCATE 50

struct buffer *
init_buffer()
{
  struct buffer *b = MALLOC(1, struct buffer);
  b->b = MALLOC(MIN_ALLOCATE, char);
  b->allocated = MIN_ALLOCATE;
  b->length = 0;
  return b;
}

char *
get_buffer(struct buffer *b)
{
  return b->b;
}

size_t
size_buffer(struct buffer *b)
{
  return b->length;
}

static void
resize_buffer(struct buffer *b, size_t newlen)
{
  char *try = NULL;
  size_t alen = b->allocated;

  if (newlen <= alen)
    return;
  alen *= 2;
  if (newlen < alen)
    try = realloc(b->b, alen);
  if (!try)
    {
      alen = newlen;
      try = REALLOC(b->b, alen, char);
    }
  b->allocated = alen;
  b->b = try;
}

char *
add_buffer(struct buffer *b, const char *p, size_t n)
{
  char *result;
  if (b->allocated - b->length < n)
    resize_buffer(b, b->length+n);
  result = memcpy(b->b + b->length, p, n);
  b->length += n;
  return result;
}

char *
add1_buffer(struct buffer *b, int c)
{
  if (c != EOF)
    {
      char *result;
      if (b->allocated - b->length < 1)
	resize_buffer(b, b->length+1);
      result = b->b + b->length++;
      *result = (char)c;
      return result;
    }

  return NULL;
}

void
free_buffer(struct buffer *b)
{
  if (b)
    FREE(b->b);
  FREE(b);
}

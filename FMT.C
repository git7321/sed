/* `L' command implementation for GNU sed, based on GNU fmt 1.22.
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

#include "sed.h"
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>

#if HAVE_LIMITS_H
# include <limits.h>
#endif

#ifndef UINT_MAX
# define UINT_MAX ((unsigned int) ~(unsigned int) 0)
#endif

#ifndef INT_MAX
# define INT_MAX ((int) (UINT_MAX >> 1))
#endif

#define	LEEWAY	7

typedef long COST;

#define	MAXCOST	(~(((unsigned long) 1) << (8 * sizeof (COST) -1)))

#define	SQR(n)		((n) * (n))
#define	EQUIV(n)	SQR ((COST) (n))

#define	SHORT_COST(n)	EQUIV ((n) * 10)

#define	RAGGED_COST(n)	(SHORT_COST (n) / 2)

#define	LINE_COST	EQUIV (70)

#define	WIDOW_COST(n)	(EQUIV (200) / ((n) + 2))

#define	ORPHAN_COST(n)	(EQUIV (150) / ((n) + 2))

#define	SENTENCE_BONUS	EQUIV (50)

#define	NOBREAK_COST	EQUIV (600)

#define	PAREN_BONUS	EQUIV (40)

#define	PUNCT_BONUS	EQUIV(40)

#define	LINE_CREDIT	EQUIV(3)

#define	MAXWORDS	1000

#define GETC()      (parabuf == end_of_parabuf ? EOF : *parabuf++)

#define	isopen(c)	(strchr ("([`'\"", (c)) != NULL)
#define	isclose(c)	(strchr (")]'\"", (c)) != NULL)
#define	isperiod(c)	(strchr (".?!", (c)) != NULL)

#define	TABWIDTH	8

typedef struct Word WORD;

struct Word
  {
    const char *text;
    short length;
    short space;
    unsigned paren:1;
    unsigned period:1;
    unsigned punct:1;
    unsigned final:1;

    short line_length;
    COST best_cost;
    WORD *next_break;
  };

static bool get_paragraph P_ ((void));
static int get_line P_ ((int c));
static int get_space P_ ((int c));
static int copy_rest P_ ((int c));
static bool same_para P_ ((int c));
static void flush_paragraph P_ ((void));
static void fmt_paragraph P_ ((void));
static void check_punctuation P_ ((WORD *w));
static COST base_cost P_ ((WORD *this));
static COST line_cost P_ ((WORD *next, int len));
static void put_paragraph P_ ((WORD *finish));
static void put_line P_ ((WORD *w, int indent));
static void put_word P_ ((WORD *w));
static void put_space P_ ((int space));

static int max_width;

static const char *parabuf;
static const char *end_of_parabuf;

static FILE *outfile;

static int best_width;
static int in_column;
static int out_column;

static WORD words[MAXWORDS];
static WORD *word_limit;

static int first_indent;
static int other_indent;
static int next_char;
static int last_line_length;

void
fmt (const char *line, const char *line_end, int max_length, FILE *output_file)
{
  parabuf = line;
  end_of_parabuf = line_end;
  outfile = output_file;

  max_width = max_length;
  best_width = max_width * (201 - 2 * LEEWAY) / 200;

  in_column = 0;
  other_indent = 0;
  next_char = GETC();
  while (get_paragraph ())
    {
      fmt_paragraph ();
      put_paragraph (word_limit);
    }
}

static bool
get_paragraph ()
{
  register int c;

  last_line_length = 0;
  c = next_char;

  while (c == '\n' || c == EOF)
    {
      c = copy_rest (c);
      if (c == EOF)
	{
	  next_char = EOF;
	  return false;
	}
      putc ('\n', outfile);
      c = GETC();
    }

  first_indent = in_column;
  word_limit = words;
  c = get_line (c);

  other_indent = in_column;
  while (same_para (c) && in_column == other_indent)
    c = get_line (c);

  (word_limit - 1)->period = (word_limit - 1)->final = true;
  next_char = c;
  return true;
}

static int
copy_rest (register int c)
{
  out_column = 0;
  while (c != '\n' && c != EOF)
    {
      putc (c, outfile);
      c = GETC();
    }
  return c;
}

static bool
same_para (register int c)
{
  return (c != '\n' && c != EOF);
}

static int
get_line (register int c)
{
  int start;
  register WORD *end_of_word;

  end_of_word = &words[MAXWORDS - 2];

  do
    {
      word_limit->text = parabuf - 1;
      do
	c = GETC();
      while (c != EOF && !ISSPACE (c));
      word_limit->length = parabuf - word_limit->text - (c != EOF);
      in_column += word_limit->length;

      check_punctuation (word_limit);

      start = in_column;
      c = get_space (c);
      word_limit->space = in_column - start;
      word_limit->final = (c == EOF
			   || (word_limit->period
			       && (c == '\n' || word_limit->space > 1)));
      if (c == '\n' || c == EOF)
	word_limit->space = word_limit->final ? 2 : 1;
      if (word_limit == end_of_word)
	flush_paragraph ();
      word_limit++;
      if (c == EOF)
	{
	  in_column = first_indent;
	  return EOF;
	}
    }
  while (c != '\n');

  in_column = 0;
  c = GETC();
  return get_space (c);
}

static int
get_space (register int c)
{
  for (;;)
    {
      if (c == ' ')
	in_column++;
      else if (c == '\t')
	in_column = (in_column / TABWIDTH + 1) * TABWIDTH;
      else
	return c;
      c = GETC();
    }
}

static void
check_punctuation (register WORD *w)
{
  register const char *start, *finish;

  start = w->text;
  finish = start + (w->length - 1);
  w->paren = isopen (*start);
  w->punct = ISPUNCT (*finish);
  while (isclose (*finish) && finish > start)
    finish--;
  w->period = isperiod (*finish);
}

static void
flush_paragraph (void)
{
  WORD *split_point;
  register WORD *w;
  COST best_break;

  fmt_paragraph ();

  split_point = word_limit;
  best_break = MAXCOST;
  for (w = words->next_break; w != word_limit; w = w->next_break)
    {
      if (w->best_cost - w->next_break->best_cost < best_break)
	{
	  split_point = w;
	  best_break = w->best_cost - w->next_break->best_cost;
	}
      if (best_break <= MAXCOST - LINE_CREDIT)
	best_break += LINE_CREDIT;
    }
  put_paragraph (split_point);

  memmove ((char *) words, (char *) split_point,
	 (word_limit - split_point + 1) * sizeof (WORD));
  word_limit -= split_point - words;
}

static void
fmt_paragraph (void)
{
  register WORD *start, *w;
  register int len;
  register COST wcost, best;
  int saved_length;

  word_limit->best_cost = 0;
  saved_length = word_limit->length;
  word_limit->length = max_width;

  for (start = word_limit - 1; start >= words; start--)
    {
      best = MAXCOST;
      len = start == words ? first_indent : other_indent;

      w = start;
      len += w->length;
      do
	{
	  w++;

	  wcost = line_cost (w, len) + w->best_cost;
	  if (start == words && last_line_length > 0)
	    wcost += RAGGED_COST (len - last_line_length);
	  if (wcost < best)
	    {
	      best = wcost;
	      start->next_break = w;
	      start->line_length = len;
	    }
	  len += (w - 1)->space + w->length;
	}
      while (len < max_width);
      start->best_cost = best + base_cost (start);
    }

  word_limit->length = saved_length;
}

static COST
base_cost (register WORD *this)
{
  register COST cost;

  cost = LINE_COST;

  if (this > words)
    {
      if ((this - 1)->period)
	{
	  if ((this - 1)->final)
	    cost -= SENTENCE_BONUS;
	  else
	    cost += NOBREAK_COST;
	}
      else if ((this - 1)->punct)
	cost -= PUNCT_BONUS;
      else if (this > words + 1 && (this - 2)->final)
	cost += WIDOW_COST ((this - 1)->length);
    }

  if (this->paren)
    cost -= PAREN_BONUS;
  else if (this->final)
    cost += ORPHAN_COST (this->length);

  return cost;
}

static COST
line_cost (register WORD *next, register int len)
{
  register int n;
  register COST cost;

  if (next == word_limit)
    return 0;
  n = best_width - len;
  cost = SHORT_COST (n);
  if (next->next_break != word_limit)
    {
      n = len - next->line_length;
      cost += RAGGED_COST (n);
    }
  return cost;
}

static void
put_paragraph (register WORD *finish)
{
  register WORD *w;

  put_line (words, first_indent);
  for (w = words->next_break; w != finish; w = w->next_break)
    put_line (w, other_indent);
}

static void
put_line (register WORD *w, int indent)
{
  register WORD *endline;
  out_column = 0;
  put_space (indent);

  endline = w->next_break - 1;
  for (; w != endline; w++)
    {
      put_word (w);
      put_space (w->space);
    }
  put_word (w);
  last_line_length = out_column;
  putc ('\n', outfile);
}

static void
put_word (register WORD *w)
{
  register const char *s;
  register int n;

  s = w->text;
  for (n = w->length; n != 0; n--)
    putc (*s++, outfile);
  out_column += w->length;
}

static void
put_space (int space)
{
  out_column += space;
  while (space--)
    putc (' ', outfile);
}

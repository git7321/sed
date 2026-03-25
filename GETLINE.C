#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>

int
getline (char **lineptr, size_t *n, FILE *stream)
{
  char *line, *p;
  long size, copy;

  if (lineptr == NULL || n == NULL)
    {
      errno = EINVAL;
      return -1;
    }

  if (ferror (stream))
    return -1;

  if (*lineptr == NULL || *n < 2)
    {
#ifndef	MAX_CANON
#define	MAX_CANON	256
#endif
      if (!*lineptr)
        line = (char *) malloc (MAX_CANON);
      else
        line = (char *) realloc (*lineptr, MAX_CANON);
      if (line == NULL)
	return -1;
      *lineptr = line;
      *n = MAX_CANON;
    }

  line = *lineptr;
  size = *n;

  copy = size;
  p = line;

  while (1)
    {
      long len;

      while (--copy > 0)
	{
	  register int c = getc (stream);
	  if (c == EOF)
	    goto lose;
	  else if ((*p++ = (char)c) == '\n')
	    goto win;
	}

      len = p - line;
      size *= 2;
      line = (char *) realloc (line, size);
      if (line == NULL)
	goto lose;
      *lineptr = line;
      *n = size;
      p = line + len;
      copy = size - len;
    }

 lose:
  if (p == *lineptr)
    return -1;

 win:
#if defined(WIN32) || defined(_WIN32) || defined(__CYGWIN__) || defined(MSDOS) || defined(__EMX__)
  if (p - 2 >= *lineptr && p[-2] == '\r')
    p[-2] = p[-1], --p;
#endif
  *p = '\0';
  return p - *lineptr;
}

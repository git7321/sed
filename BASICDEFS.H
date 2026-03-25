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

#ifndef BASICDEFS_H
#define BASICDEFS_H

#include "config.h"
#if defined(_AIX)
#pragma alloca
#else
# if !defined(alloca)
#  ifdef __GNUC__
#   define alloca(size) __builtin_alloca(size)
#  else
#   if HAVE_ALLOCA_H
#    include <alloca.h>
#   else
#    if defined(__hpux)
        void *alloca ();
#    else
#     if !defined(__OS2__) && !defined(WIN32)
	char *alloca ();
#     else
#      include <malloc.h>
#     endif
#    endif
#   endif
#  endif
# endif
#endif

#ifdef HAVE_WCHAR_H
# include <wchar.h>
#endif
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef HAVE_WCTYPE_H
# include <wctype.h>
#endif

#ifdef BOOTSTRAP
# define false 0
# define true 1
# define bool unsigned
# define __bool_true_false_are_defined 1
#else
# include <stdbool.h>
#endif

#if ENABLE_NLS
# include <libintl.h>
#else
# define gettext(msgid) (msgid)
# define ngettext(sing, plur, n) ((n) == 1 ? (sing) : (plur))
#endif
#define _(String) gettext(String)

#ifdef gettext_noop
# define N_(String) gettext_noop(String)
#else
# define N_(String) (String)
#endif

typedef unsigned long countT;

#ifdef LOUD_LINT
# define CAST(x)
#else
# define CAST(x) (x)
#endif

#if (defined __STDC__ && __STDC__-0) || defined __GNUC__ || defined __SUNPRO_C || __PROTOTYPES
# define P_(s)  s
#else
# define P_(s)  ()
#endif

#ifndef VOID
# define VOID     void
# define VCAST(t)
#else
# define VCAST(t) (t)
#endif

#define MALLOC(n,t)	 (VCAST(t *)ck_malloc((n)*sizeof(t)))
#define REALLOC(x,n,t)	 (VCAST(t *)ck_realloc(VCAST(VOID *)(x),(n)*sizeof(t)))
#define MEMDUP(x,n,t)	 (VCAST(t *)ck_memdup(VCAST(VOID *)(x),(n)*sizeof(t)))
#define FREE(x)		 (ck_free(VCAST(VOID *)x))
#define MEMCPY(d,s,l)	 (memcpy(VCAST(VOID *)(d),VCAST(const VOID *)(s),l))
#define MEMMOVE(d,s,l)	 (memmove(VCAST(VOID *)(d),VCAST(const VOID *)(s),l))
#define OB_MALLOC(o,n,t) ((t *)(void *)obstack_alloc(o,(n)*sizeof(t)))

#define obstack_chunk_alloc  ck_malloc
#define obstack_chunk_free   ck_free

#ifdef HAVE_MEMORY_H
# include <memory.h>
#endif

#ifndef HAVE_MEMMOVE
# ifndef memmove
   extern VOID *memmove();
# endif
#endif

#ifndef HAVE_MEMCPY
# ifndef memcpy
#  define memcpy(d, s, n)  memmove(d, s, n)
# endif
#endif

#ifndef HAVE_STRERROR
 extern char *strerror P_((int e));
#endif

#undef ISASCII
#define ISASCII(c) __isascii(c)

#if defined isblank || defined HAVE_ISBLANK
# define ISBLANK(c) (ISASCII (c) && isblank (c))
#else
# define ISBLANK(c) ((c) == ' ' || (c) == '\t')
#endif

#undef ISPRINT
#define ISPRINT(c) (ISASCII (c) && isprint (c))
#define ISDIGIT(c) (ISASCII (c) && isdigit (c))
#define ISALNUM(c) (ISASCII (c) && isalnum (c))
#define ISALPHA(c) (ISASCII (c) && isalpha (c))
#define ISCNTRL(c) (ISASCII (c) && iscntrl (c))
#define ISLOWER(c) (ISASCII (c) && islower (c))
#define ISPUNCT(c) (ISASCII (c) && ispunct (c))
#define ISSPACE(c) (ISASCII (c) && isspace (c))
#define ISUPPER(c) (ISASCII (c) && isupper (c))
#define ISXDIGIT(c) (ISASCII (c) && isxdigit (c))

#ifndef initialize_main
# ifdef __EMX__
#  define initialize_main(argcp, argvp) \
  { _response(argcp, argvp); _wildcard(argcp, argvp); }
# else
#  define initialize_main(argcp, argvp)
# endif
#endif

#endif /*!BASICDEFS_H*/

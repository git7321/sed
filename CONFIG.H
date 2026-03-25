#define STDC_HEADERS     1
#define HAVE_BTOWC       1
#define HAVE_FCNTL_H     1
#define HAVE_GETCWD      1
#define HAVE_IO_H        1
#define HAVE_ISASCII     1
#define HAVE_ISATTY      1
#define HAVE_LIMITS_H    1
#define HAVE_POPEN       1
#define HAVE_STDARG_H    1
#define HAVE_STDBOOL_H   1
#define HAVE_STDLIB_H    1
#define HAVE_STDDEF_H    1
#define HAVE_STRING_H    1
#define HAVE_STRCHR      1
#define HAVE_STRDUP      1
#define HAVE_STRERROR    1
#define HAVE_SYS_TYPES_H 1
#define HAVE_MEMCPY      1
#define HAVE_MEMMOVE     1
#define HAVE_MEMORY_H    1
#define HAVE_VPRINTF     1
#define HAVE_VFPRINTF    1
#define HAVE_STRTOUL     1
#define HAVE_ALLOCA      1
#define inline __inline
#define HAVE_WCHAR_H     1
//#define HAVE_MBRTOWC     1
#define mb_cur_max MB_CUR_MAX
#define PACKAGE "sed"
#define VERSION "4.1.5"
#define SED_FEATURE_VERSION "4.1.5"
typedef int ssize_t;
#define SIZE_MAX UINT_MAX
#if defined(STDC_HEADERS)
#define __STDC__ 1
#endif

#include <io.h>
#include <stdlib.h>
#include <stdio.h>
#include <direct.h>
#include <sys/stat.h>
#include <malloc.h>
#include <string.h>

#ifndef CHAR_BIT
#define CHAR_BIT 8
#endif
#ifndef S_ISREG
# define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
#endif

#ifdef __STDC__
#define chmod       _chmod
#define stat        _stat
#define fstat       _fstat
#define fileno      _fileno
#define open        _open
#define fdopen      _fdopen
#define isatty      _isatty
#define isascii     __isascii
#define O_RDWR      _O_RDWR
#define O_BINARY    _O_BINARY
#define O_CREAT     _O_CREAT
#define O_EXCL      _O_EXCL
#define unlink      _unlink
#define S_IFMT      _S_IFMT
#define S_IFREG     _S_IFREG
#define strcasecmp  _stricmp
#endif
#define popen    _popen
#define pclose   _pclose
#define alloca   _alloca

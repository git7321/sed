/* object stack macros
  Copyright (C) Free Software Foundation, Inc.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.*/

#ifndef _OBSTACK_H
#define _OBSTACK_H

#include <stddef.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __PTR_TO_INT
# define __PTR_TO_INT(P) ((P) - (char *) 0)
#endif

#ifndef __INT_TO_PTR
# define __INT_TO_PTR(P) ((P) + (char *) 0)
#endif

#define _obstack_memcpy(To, From, N) memcpy ((To), (From), (N))

struct _obstack_chunk
{
  char  *limit;
  struct _obstack_chunk *prev;
  char	contents[4];
};

struct obstack
{
  long	chunk_size;
  struct _obstack_chunk *chunk;
  char	*object_base;
  char	*next_free;
  char	*chunk_limit;
  int   temp;
  int   alignment_mask;

  struct _obstack_chunk *(*chunkfun) (void *, long);
  void (*freefun) (void *, struct _obstack_chunk *);
  void *extra_arg;
  unsigned use_extra_arg:1;
  unsigned maybe_empty_object:1;
  unsigned alloc_failed:1;
};

extern void _obstack_newchunk (struct obstack *, int);
extern void _obstack_free (struct obstack *, void *);
extern int _obstack_begin (struct obstack *, int, int,
			    void *(*) (long), void (*) (void *));
extern int _obstack_begin_1 (struct obstack *, int, int,
			     void *(*) (void *, long),
			     void (*) (void *, void *), void *);
extern int _obstack_memory_used (struct obstack *);

void obstack_init (struct obstack *obstack);

void * obstack_alloc (struct obstack *obstack, int size);

void * obstack_copy (struct obstack *obstack, void *address, int size);
void * obstack_copy0 (struct obstack *obstack, void *address, int size);

void obstack_free (struct obstack *obstack, void *block);

void obstack_blank (struct obstack *obstack, int size);

void obstack_grow (struct obstack *obstack, void *data, int size);
void obstack_grow0 (struct obstack *obstack, void *data, int size);

void obstack_1grow (struct obstack *obstack, int data_char);
void obstack_ptr_grow (struct obstack *obstack, void *data);
void obstack_int_grow (struct obstack *obstack, int data);

void * obstack_finish (struct obstack *obstack);

int obstack_object_size (struct obstack *obstack);

int obstack_room (struct obstack *obstack);
void obstack_make_room (struct obstack *obstack, int size);
void obstack_1grow_fast (struct obstack *obstack, int data_char);
void obstack_ptr_grow_fast (struct obstack *obstack, void *data);
void obstack_int_grow_fast (struct obstack *obstack, int data);
void obstack_blank_fast (struct obstack *obstack, int size);

void * obstack_base (struct obstack *obstack);
void * obstack_next_free (struct obstack *obstack);
int obstack_alignment_mask (struct obstack *obstack);
int obstack_chunk_size (struct obstack *obstack);
int obstack_memory_used (struct obstack *obstack);

extern void (*obstack_alloc_failed_handler) (void);
extern int obstack_exit_failure;

#define obstack_base(h) ((h)->object_base)
#define obstack_chunk_size(h) ((h)->chunk_size)
#define obstack_next_free(h)	((h)->next_free)
#define obstack_alignment_mask(h) ((h)->alignment_mask)
#define obstack_init(h) \
  _obstack_begin ((h), 0, 0, \
		  (void *(*) (long)) obstack_chunk_alloc, (void (*) (void *)) obstack_chunk_free)

#define obstack_begin(h, size) \
  _obstack_begin ((h), (size), 0, \
		  (void *(*) (long)) obstack_chunk_alloc, (void (*) (void *)) obstack_chunk_free)

#define obstack_specify_allocation(h, size, alignment, chunkfun, freefun) \
  _obstack_begin ((h), (size), (alignment), \
		    (void *(*) (long)) (chunkfun), (void (*) (void *)) (freefun))

#define obstack_specify_allocation_with_arg(h, size, alignment, chunkfun, freefun, arg) \
  _obstack_begin_1 ((h), (size), (alignment), \
		    (void *(*) (void *, long)) (chunkfun), \
		    (void (*) (void *, void *)) (freefun), (arg))

#define obstack_chunkfun(h, newchunkfun) \
  ((h) -> chunkfun = (struct _obstack_chunk *(*)(void *, long)) (newchunkfun))

#define obstack_freefun(h, newfreefun) \
  ((h) -> freefun = (void (*)(void *, struct _obstack_chunk *)) (newfreefun))

#define obstack_1grow_fast(h,achar) (*((h)->next_free)++ = achar)

#define obstack_blank_fast(h,n) ((h)->next_free += (n))

#define obstack_memory_used(h) _obstack_memory_used (h)

#define obstack_object_size(h) \
 (unsigned) ((h)->next_free - (h)->object_base)

#define obstack_room(h) \
 (unsigned) ((h)->chunk_limit - (h)->next_free)

#define obstack_empty_p(h) \
 ((h)->chunk->prev == 0 && (h)->next_free - (h)->chunk->contents == 0)

#define obstack_make_room(h,length) \
( (h)->temp = (length), \
  (((h)->next_free + (h)->temp > (h)->chunk_limit) \
   ? (_obstack_newchunk ((h), (h)->temp), 0) : 0))

#define obstack_grow(h,where,length) \
( (h)->temp = (length), \
  (((h)->next_free + (h)->temp > (h)->chunk_limit) \
   ? (_obstack_newchunk ((h), (h)->temp), 0) : 0), \
  _obstack_memcpy ((h)->next_free, (char *) (where), (h)->temp), \
  (h)->next_free += (h)->temp)

#define obstack_grow0(h,where,length) \
( (h)->temp = (length), \
  (((h)->next_free + (h)->temp + 1 > (h)->chunk_limit) \
   ? (_obstack_newchunk ((h), (h)->temp + 1), 0) : 0), \
  _obstack_memcpy ((h)->next_free, (char *) (where), (h)->temp), \
  (h)->next_free += (h)->temp, \
  *((h)->next_free)++ = 0)

#define obstack_1grow(h,datum) \
( (((h)->next_free + 1 > (h)->chunk_limit) \
   ? (_obstack_newchunk ((h), 1), 0) : 0), \
  (*((h)->next_free)++ = (datum)))

#define obstack_ptr_grow(h,datum) \
( (((h)->next_free + sizeof (char *) > (h)->chunk_limit) \
   ? (_obstack_newchunk ((h), sizeof (char *)), 0) : 0), \
  (*((char **) (((h)->next_free+=sizeof(char *))-sizeof(char *))) = ((char *) datum)))

#define obstack_int_grow(h,datum) \
( (((h)->next_free + sizeof (int) > (h)->chunk_limit) \
   ? (_obstack_newchunk ((h), sizeof (int)), 0) : 0), \
  (*((int *) (((h)->next_free+=sizeof(int))-sizeof(int))) = ((int) datum)))

#define obstack_ptr_grow_fast(h,aptr) (*((char **) (h)->next_free)++ = (char *) aptr)
#define obstack_int_grow_fast(h,aint) (*((int *) (h)->next_free)++ = (int) aint)

#define obstack_blank(h,length) \
( (h)->temp = (length), \
  (((h)->chunk_limit - (h)->next_free < (h)->temp) \
   ? (_obstack_newchunk ((h), (h)->temp), 0) : 0), \
  ((h)->next_free += (h)->temp))

#define obstack_alloc(h,length) \
 (obstack_blank ((h), (length)), obstack_finish ((h)))

#define obstack_copy(h,where,length) \
 (obstack_grow ((h), (where), (length)), obstack_finish ((h)))

#define obstack_copy0(h,where,length) \
 (obstack_grow0 ((h), (where), (length)), obstack_finish ((h)))

#define obstack_finish(h) \
( ((h)->next_free == (h)->object_base \
   ? (((h)->maybe_empty_object = 1), 0) \
   : 0), \
  (h)->temp = __PTR_TO_INT ((h)->object_base), \
  (h)->next_free \
    = __INT_TO_PTR ((__PTR_TO_INT ((h)->next_free)+(h)->alignment_mask) \
		    & ~ ((h)->alignment_mask)), \
  (((h)->next_free - (char *) (h)->chunk \
    > (h)->chunk_limit - (char *) (h)->chunk) \
   ? ((h)->next_free = (h)->chunk_limit) : 0), \
  (h)->object_base = (h)->next_free, \
  __INT_TO_PTR ((h)->temp))

#define obstack_free(h,obj) \
( (h)->temp = (char *) (obj) - (char *) (h)->chunk, \
  (((h)->temp > 0 && (h)->temp < (h)->chunk_limit - (char *) (h)->chunk) \
   ? (int) ((h)->next_free = (h)->object_base \
    = (h)->temp + (char *) (h)->chunk) \
   : (((obstack_free) ((h), (h)->temp + (char *) (h)->chunk), 0), 0)))

#ifdef __cplusplus
}
#endif

#endif /* obstack.h */

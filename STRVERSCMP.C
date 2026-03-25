/* Compare strings while treating digits characters numerically.
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

#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define  S_N  0x0
#define  S_I  0x3
#define  S_F  0x6
#define  S_Z  0x9

#define  CMP  2
#define  LEN  3

int
strverscmp (const char *s1, const char *s2)
{
  const unsigned char *p1 = (const unsigned char *) s1;
  const unsigned char *p2 = (const unsigned char *) s2;
  unsigned char c1 = *p1++;
  unsigned char c2 = *p2++;
  int state, diff;

  static const uint_least8_t next_state[] =
  {
      S_N, S_I, S_Z,
      S_N, S_I, S_I,
      S_N, S_F, S_F,
      S_N, S_F, S_Z
  };

  static const int_least8_t result_type[] =
  {
      CMP, CMP, CMP, CMP, LEN, CMP, CMP, CMP, CMP,
      CMP, -1,  -1,  +1,  LEN, LEN, +1,  LEN, LEN,
      CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP,
      CMP, +1,  +1,  -1,  CMP, CMP, -1,  CMP, CMP
  };

  if (p1 == p2)
    return 0;

  state = S_N + ((c1 == '0') + (isdigit (c1) != 0));

  while ((diff = c1 - c2) == 0)
   {
    if (c1 == '\0')
	return diff;

      state = next_state[state];
      c1 = *p1++;
      c2 = *p2++;
      state += (c1 == '0') + (isdigit (c1) != 0);
   }

  state = result_type[state * 3 + (((c2 == '0') + (isdigit (c2) != 0)))];

  switch (state)
  {
    case CMP:
      return diff;

    case LEN:
      while (isdigit (*p1++))
	if (!isdigit (*p2++))
	  return 1;

      return isdigit (*p2) ? -1 : diff;

    default:
      return state;
  }
}

/* rwbuf.h  -  read write buffering
 *	Copyright (C) 1999 Werner Koch, Duesseldorf
 *
 * This file is part of GEAM.
 *
 * GEAM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GEAM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef RWBUF_H
#define RWBUF_H

#include "mischelp.h"

int rw_init( int fd );
void rw_timeout( int fd, int read_seconds, int write_seconds );
char *rw_readline( int fd, size_t maxlen, size_t *nbytes, int *truncated );
int rw_writen( int fd, const char *buffer, size_t length );
int rw_writestr( int fd, const char *string );
int rw_printf( int fd, const char *format, ... ) LIBUTIL_GCC_A_PRINTF(2,3);


#endif/*RWBUF_H*/

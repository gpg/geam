/* libutil-config.h - libutil configuration for GAEMibutil functions
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

/****************
 * This header is to be included only by the files in this directory
 * it should not be used by other modules.
 */

#ifndef LIBUTIL_CONFIG_H
#define LIBUTIL_CONFIG_H

#include <sys/types.h>

#ifndef HAVE_BYTE_TYPEDEF
  #undef byte	    /* maybe there is a macro with this name */
  typedef unsigned char byte;
  #define HAVE_BYTE_TYPEDEF
#endif

#include "xmalloc.h"

/* We don't need gettext for this project */
#define _(a)   (a)
#define N_(a)  (a)


#define libutil_xmalloc(a)   xmalloc( (a) )
#define libutil_realloc(a,n) xrealloc( (a), (n) )
#define libutil_strdup(a)    xstrdup( (a) )
#define libutil_free(a)      free( (a) )

#define libutil_log_debug    log_debug
#define libutil_log_info     log_info
#define libutil_log_error    log_error
#define libutil_log_fatal    log_fatal
#define libutil_log_bug      log_bug

#endif /*LIBUTIL_CONFIG_H*/

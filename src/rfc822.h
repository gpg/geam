/* rfc822.h
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

#ifndef RFC822_H
#define RFC822_H

#include "mischelp.h"

struct rfc822_data;
typedef struct rfc822_data *RFC822;

enum rfc822_errors {
    RFC822ERR_NOMEM = 1
};

enum rfc822_events {
    RFC822EVT_OPEN  = 1,
    RFC822EVT_CLOSE,
    RFC822EVT_CANCEL,
    RFC822EVT_T2BODY,
    RFC822EVT_FINISH,
    RFC822EVT_RCVD_SEEN
};

struct rfc822_parse_context;
typedef struct rfc822_parse_context *RFC822_PARSE_CTX;


char *rfc822_timestamp(char *buffer, size_t buflen );

RFC822 rfc822_open( int (*cb)( void *, enum rfc822_events, RFC822 ),
		    void *cb_value );
void rfc822_cancel( RFC822 msg );
void rfc822_close( RFC822 msg );

int rfc822_insert( RFC822 msg, char *line, size_t length );
int rfc822_finish( RFC822 msg );

int rfc822_add_header( RFC822 msg, const char *line );
int rfc822_add_headerf( RFC822 msg, const char *fmt, ... )
						    LIBUTIL_GCC_A_PRINTF(2,3);
int rfc822_rename_header( RFC822 msg, const char *oldname,
				  const char *newname, int which );
int rfc822_remove_header( RFC822 msg, const char *name, int which );

char *rfc822_get_header( RFC822 msg, const char *name, int which );
const char *rfc822_enum_header_lines( RFC822 msg, void **context );
const char *rfc822_enum_body_lines( RFC822 msg, void **context, size_t *n );

RFC822_PARSE_CTX rfc822_parse_header( RFC822 msg, const char *name, int which );
void rfc822_release_parse_ctx( RFC822_PARSE_CTX ctx );
const char *rfc822_query_parameter( RFC822_PARSE_CTX ctx, const char *attr );
const char *rfc822_query_media_type( RFC822_PARSE_CTX ctx, const char **subtype );


#endif/*RFC822_H*/

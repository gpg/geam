/* rfc821.h
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

#ifndef RFC821_H
#define RFC821_H

#include "rfc822.h"

struct rfc821_state;
typedef struct rfc821_state *RFC821;

enum rfc821_errors {
    RFC821ERR_NONE = 0,
    RFC821ERR_GENERAL,
    RFC821ERR_NOMEM,
    RFC821ERR_CONFLICT,
    RFC821ERR_NOSERVICE,
    RFC821ERR_SEND,
    RFC821ERR_RECV,
    RFC821ERR_CMDSEQ,
    RFC821ERR_PATH,
    RFC821ERR_TEMP
};

enum rfc821_flags {
    RFC821FLG_VERBOSE = 1,
    RFC821FLG_DBGSMTP = 2
};

enum rfc821_events {
    RFC821EVT_DATA,	 /* After basic checks of the data command */
    RFC821EVT_DATA_END,  /* After reading all data, before rfc822 close */
};


RFC821 rfc821_open( int (*cb)( void *, enum rfc821_events, RFC821 ),
							   void *cb_value );
void rfc821_set_proto_comment( RFC821 state, const char *comment );
void rfc821_set_flag( RFC821 state, enum rfc821_flags flag, int value );
void rfc821_set_rfc822_cb( RFC821 hd,
			   int (*cb)( void *, enum rfc822_events, RFC822 ),
							   void *cb_value );
int rfc821_handler( RFC821 state, int fd,
		    const char *peer_addr_str, int peer_port );
void rfc821_cancel( RFC821 hd );
void rfc821_close( RFC821 hd );

int rfc821_start_session( RFC821 state, int fd );
int rfc821_send_sender( RFC821 state, const char *path );
int rfc821_send_recipient( RFC821 state, const char *path );
int rfc821_send_body_line( RFC821 state, const char *line, size_t length );

const char *rfc821_query_sender( RFC821 state );
const char *rfc821_enum_recipients( RFC821 state, void **context );

int rfc821_copy_header_lines( RFC821 smtp, RFC822 msg );
int rfc821_copy_body_lines( RFC821 smtp, RFC822 msg );

#endif/*RFC821_H*/

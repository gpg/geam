/* smtpproxy.h
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

#ifndef SMTPPROXY_H
#define SMTPPROXY_H

#include <sys/socket.h>

int smtpproxy_read_configs(void);
int smtpproxy_set_smarthost( const char *inbound_name, int inbound_port,
			     const char *outbound_name, int outbound_port );
void *smtpproxy_handler( int fd, const char *sessid,
				struct sockaddr *peer_addr,
				const char *peer_addr_str, int peer_port );


#endif/*SMTPPROXY_H*/

/* nethelp.h - network helpers
 *	Copyright (C) 2000 Werner Koch, Duesseldorf
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

#ifndef NETHELP_H
#define NETHELP_H

struct network_address_s;
typedef struct network_address_s *NETWORK_ADDRESS;

NETWORK_ADDRESS parse_network_address( const char *string );
void append_network_address( NETWORK_ADDRESS a, NETWORK_ADDRESS b );
void release_network_address( NETWORK_ADDRESS a );
int match_network_address( NETWORK_ADDRESS a, struct sockaddr *saddr );


#endif/*NETHELP_H*/

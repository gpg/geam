/* nethelp.c  - network helper functions
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "types.h"
#include "xmalloc.h"
#include "nethelp.h"

struct network_address_s {
    struct network_address_s *next;
    ulong addr;  /* (in host byte order) */
    ulong mask;
};


/****************
 * input string should be syntactically correct.
 * Returns pointer to next character + 1
 */
static const char *
get_dotted_quad( const char *s, ulong *retval )
{
    ulong value = 0;
    int i;

    for(i=24; *s && i >= 0; s++, i -= 8 ) {
	int n = atoi(s);
	if( n < 0 || n > 255 )
	    return NULL;
	value |= (n&0xff) << i;
	while( isdigit(*s) )
	    s++;
    }
    *retval = value;
    return s;
}

/****************
 * Parse a network address and return an object describing
 * address and the mask. Returns NULL on error. Caller must
 * free the returned object using release_network_address.
 *
 * Valid address formats are:
 *
 *   a.a.a.a	     - mask will either be one for a A,B or C class nentwork
 *   a.a.a.a/m	     - mask is m hight bits set, rest of the nbits are low
 *   a.a.a.a/m.m.m.m - mask exactly specified
 *
 * IPv6 is not yet supported but can be done entirely inside this modules
 * because the return data type is only know here.  A user should always
 * use one of the functions here.
 */
NETWORK_ADDRESS
parse_network_address( const char *string )
{
    int a_dots, m_dots, digs, m_digs, slashes;
    const char *s;
    ulong addr, mask;
    NETWORK_ADDRESS na;


    /* count dots and slashes and check for invalid characters */
    a_dots = m_dots = digs = m_digs = slashes = 0;
    for( s = string; *s; s++ ) {
	if( isdigit( *s ) ) {
	    digs++;
	}
	else {
	    if( !digs || digs > 3 )
		return NULL;
	    digs = 0;
	    if( *s == '/' )
		slashes++;
	    else if( !slashes && *s == '.' )
		a_dots++;
	    else if( *s == '.' )
		m_dots++;
	    else
		return NULL;
	}
    }
    if( !digs || digs > 3 || slashes > 1 || a_dots != 3
	|| ( !slashes && m_dots ) || ( slashes && m_dots != 0 && m_dots != 3)){
	return NULL;
    }

    string = get_dotted_quad( string, &addr );
    if( !string )
	return NULL;
    if( slashes ) {
	if( !*string )
	    return NULL;
	if( m_dots ) {
	    string = get_dotted_quad( string, &mask );
	    if( !string )
		return NULL;
	}
	else {
	    int i, n = atoi(string);
	    if( n < 0 || n > 32 )
		return NULL;
	    for( mask=0, i=n-1; i >= 0; i-- ) {
		mask |= 0x80000000 >> i;
	    }
	}

    }
    else { /* calculate mask from the address */
	int i = (addr & 0xff000000) >> 24;
	if( i < 128 )
	    mask = 0xff000000;
	else if( i < 192 )
	    mask = 0xffff0000;
	else /* class C. we return this also for class D and E networks */
	    mask = 0xffffff00;
    }
    na = xcalloc(1, sizeof *na );
    na->addr = addr;
    na->mask = mask;
    return na;
}

void
release_network_address( NETWORK_ADDRESS a )
{
    NETWORK_ADDRESS a2;

    while( a ) {
	a2 = a->next;
	free( a );
	a = a2;
    }
}

/****************
 * Append address list b to the end of the list with addresses b
 * Do not use b later on.
 */
void
append_network_address( NETWORK_ADDRESS a, NETWORK_ADDRESS b )
{
    while( a->next )
	a = a->next;
    a->next = b;
}

/****************
 * Tell whether saddr matches on of the network addresses.
 */
int
match_network_address( NETWORK_ADDRESS a, struct sockaddr *saddr )
{
    if( saddr->sa_family == AF_INET ) {
	ulong addr = ntohl(((struct sockaddr_in *)saddr)->sin_addr.s_addr);
	for( ; a; a = a->next ) {
	    if( (a->addr & a->mask) == (addr & a->mask) ) {
		return 1; /* match */
	    }
	}
    }
    return 0;
}



/* rfc822.c
 *	Copyright (C) 1999, 2000 Werner Koch, Duesseldorf
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



/* FIXME: According to RFC822 binary 0 are allowed at many places. We
 * do not handle this correct especially in the field parsing code.  It
 * should be easy to fix and the API provides a interfcaes which returns
 * the length but in addition makes sure that returned strings are always
 * ended by a \0
 */


#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>
#include <pth.h>

#include "xmalloc.h"
#include "stringhelp.h"
#include "rfc822.h"

enum token_type {
    tSPACE,
    tATOM,
    tQUOTED,
    tDOMAINLIT,
    tSPECIAL
};

/* For now we directly use our TOKEN as the parse context */
typedef struct rfc822_parse_context *TOKEN;
struct rfc822_parse_context {
    TOKEN next;
    enum token_type type;
    int cont;
    /*TOKEN owner_pantry;*/
    char data[1];
};

struct hdr_line {
    struct hdr_line *next;
    int cont;	    /* this is a continuation of the previous line */
    char line[1];
};

typedef struct hdr_line *HDR_LINE;

struct body_line {
    struct body_line *next;
    size_t length;
    char data[1];
};
typedef struct body_line *BODY_LINE;


struct rfc822_data {
    int (*callback)(void*, enum rfc822_events, RFC822 );
    void *callback_value;
    int callback_error;
    int in_body;
    HDR_LINE hdr_lines;
    HDR_LINE *hdr_lines_head;
    BODY_LINE bdy_lines;
    BODY_LINE *bdy_lines_head;
};

static int insert_header( RFC822 msg, char *line, size_t length );
static int insert_body( RFC822 msg, char *line, size_t length );
static int transition_to_body( RFC822 msg );
static HDR_LINE find_header( RFC822 msg, const char *name,
			     int which, HDR_LINE *rprev );


char *
rfc822_timestamp(char *buffer, size_t buflen )
{
    time_t now;
    struct tm *t;
    int u_yday, u_hour, u_min, zone, zone_s, zone_h, zone_m;
    char *p;

    time( &now );
    t = gmtime( &now );
    u_yday = t->tm_yday;
    u_hour = t->tm_hour;
    u_min  = t->tm_min;

    t = localtime( &now );

    zone = (t->tm_hour - u_hour) * 60 + (t->tm_min - u_min);
    if( t->tm_yday == u_yday )
	; /* same day */
    else if( t->tm_yday == u_yday+1 )
	zone += 1440; /* one ahead */
    else
	zone -= 1440;

    if( zone < 0 ) {
	zone_s = '-';
	zone = -zone;
    }
    else
	zone_s = '+';

    zone_h = zone / 60;
    zone_m = (zone - zone_h*60);


    if( buffer ) {
	p = buffer;
    }
    else {
	buflen = 50;
	p = xmalloc( buflen );
    }
    snprintf(p, buflen, "%.3s, %d %.3s %4d %02d:%02d:%02d %c%02d%02d",
		 "SunMonTueWedThuFriSat" + (t->tm_wday%7)*3,
		 t->tm_mday,
		 "JanFebMarAprMayJunJulAufSepOctNovDez" + (t->tm_mon%12)*3,
		 t->tm_year + 1900,
		 t->tm_hour, t->tm_min, t->tm_sec, zone_s, zone_h, zone_m );
    return p;
}



static int
do_callback( RFC822 msg, enum rfc822_events event )
{
    int rc;

    if( !msg->callback || msg->callback_error )
	return 0;
    rc = msg->callback( msg->callback_value, event, msg );
    if( rc )
	msg->callback_error = rc;
    return rc;
}

static void
release_handle_data( RFC822 msg )
{
    HDR_LINE hdr, hdr2;
    BODY_LINE bdy, bdy2;

    for(hdr = msg->hdr_lines; hdr; hdr = hdr2 ) {
	hdr2 = hdr->next;
	free(hdr);
    }
    msg->hdr_lines = NULL;
    msg->hdr_lines_head = NULL;

    for(bdy = msg->bdy_lines; bdy; bdy = bdy2 ) {
	bdy2 = bdy->next;
	free(bdy);
    }
    msg->bdy_lines = NULL;
    msg->bdy_lines_head = NULL;
}

RFC822
rfc822_open( int (*cb)( void *, enum rfc822_events, RFC822 ), void *cb_value )
{
    RFC822 msg = calloc(1, sizeof *msg );
    if( msg ) {
	msg->hdr_lines_head = &msg->hdr_lines;
	msg->bdy_lines_head = &msg->bdy_lines;
	msg->callback = cb;
	msg->callback_value = cb_value;
	if( do_callback( msg, RFC822EVT_OPEN ) ) {
	    release_handle_data( msg );
	    free(msg);
	    msg = NULL;
	}
    }
    return msg;
}



void
rfc822_cancel( RFC822 msg )
{
    do_callback( msg, RFC822EVT_CANCEL );
    release_handle_data( msg );
    free(msg);
}

void
rfc822_close( RFC822 msg )
{
    do_callback( msg, RFC822EVT_CLOSE );
    release_handle_data( msg );
    free(msg);
}


int
rfc822_insert( RFC822 msg, char *line, size_t length )
{
    return msg->in_body? insert_body( msg, line, length )
		       : insert_header( msg, line, length );
}


int
rfc822_finish( RFC822 msg )
{
    return do_callback( msg, RFC822EVT_FINISH );
}


/****************
 * Note: For program supplied (and therefore syntactically correct)
 *	 header lines, rfc822_add_header() may be used.
 */
int
insert_header( RFC822 msg, char *line, size_t length )
{
    HDR_LINE hdr;

    if( !length ) {
	msg->in_body = 1;
	return transition_to_body(msg);
    }
    trim_trailing_spaces(line);
    /* Hmmm: should we check for invalid header data here? */

    hdr = malloc( sizeof( *hdr ) + strlen(line) );
    if( !hdr )
	return RFC822ERR_NOMEM;
    hdr->next = NULL;
    hdr->cont = (*line == ' ' || *line == '\t');
    strcpy(hdr->line, line );

    *msg->hdr_lines_head = hdr;
    msg->hdr_lines_head = &hdr->next;

    /* lets help the caller to prevent mail loops
     * It is okay to use length here, also this value
     * not correct due to the space trimming */
    if( length >= 9 && !memicmp(line, "Received:", 9) )
	do_callback( msg, RFC822EVT_RCVD_SEEN );
    return 0;
}


/****************
 * Note: We handle the body transparent to allow binary zeroes in it.
 */
int
insert_body( RFC822 msg, char *line, size_t length )
{
    BODY_LINE bdy = malloc( sizeof( *bdy ) + length );
    if( !bdy )
	return RFC822ERR_NOMEM;
    bdy->next = NULL;
    bdy->length = length;
    memcpy(bdy->data, line, length);
    bdy->data[length] = 0;

    *msg->bdy_lines_head = bdy;
    msg->bdy_lines_head = &bdy->next;
    return 0;
}


/****************
 * We have read in all header lines and are about to receive the body
 * part.  The delimiter line has already been processed.
 */
static int
transition_to_body( RFC822 msg )
{
    return do_callback( msg, RFC822EVT_T2BODY );
}


/****************
 * Add header lines to the existing ones.
 * Such a line may include LFs which are used to split the line
 * int several fields.	This must be a valid header line.
 */
int
rfc822_add_header( RFC822 msg, const char *line )
{
    HDR_LINE hdr;
    const char *lf;
    size_t n;
    int do_cb;

    /* send the notification only if we have not processed all header lines */
    do_cb = !msg->in_body && strlen(line) >= 9 && !memicmp(line, "Received:", 9);

    do {
	lf = strchr( line, '\n' );
	n = lf? ( lf - line ) : strlen( line );
	hdr = malloc( sizeof( *hdr ) + n );
	if( !hdr )
	    return RFC822ERR_NOMEM;
	hdr->next = NULL;
	hdr->cont = (*line == ' ' || *line == '\t');
	memcpy(hdr->line, line, n );
	hdr->line[n] = 0;

	*msg->hdr_lines_head = hdr;
	msg->hdr_lines_head = &hdr->next;
    } while( lf && *(line=lf+1) );

    if( do_cb )
	do_callback( msg, RFC822EVT_RCVD_SEEN );

    return 0;
}

int
rfc822_add_headerf( RFC822 msg, const char *fmt, ... )
{
    char *buffer = NULL;
    int rc;
    va_list arg_ptr;

    va_start( arg_ptr, fmt );
    vasprintf( &buffer, fmt, arg_ptr );
    va_end( arg_ptr );
    rc = rfc822_add_header( msg, buffer );
    free(buffer);
    return rc;
}

/****************
 * Rename header:
 *
 * which gives the mode:
 *   0 := Do it for all the fields.
 *  -1 := Take the last occurence
 *   n := Take the n-th  one.
 */
int
rfc822_rename_header( RFC822 msg, const char *oldname,
				  const char *newname, int which )
{
    HDR_LINE h, hprev;
    int seq = which;
    size_t oldlen, newlen, n;
    int glob = 0;
    char *p0, *pc;

    newlen = strlen(newname);
    oldlen = strlen(oldname);
    if( oldlen && oldname[oldlen-1] == '*' ) {
	oldlen--;
	glob = 1;
    }

    hprev = NULL; /* start with the first one */
    seq=which?which:1;
    for(;;) {
	h = find_header( msg, oldname, seq, &hprev );
	if( !h )
	    return 0; /* no such field */
	p0 = h->line;
	pc = p0 + oldlen;
	assert( glob || p0[oldlen]==':' );

	n = pc - p0; /* what we have to replace by newlen */
	if( newlen == n )
	    memcpy( p0, newname, newlen );
	else if( newlen < n ) {
	    memcpy( p0, newname, newlen );
	    memmove( p0+newlen, pc, strlen(pc)+1 );
	}
	else {
	    HDR_LINE hnew = malloc( sizeof( *hnew )
				       + strlen(p0) - oldlen + newlen );
	    if( !hnew )
		return RFC822ERR_NOMEM;
	    hnew->cont = 0;
	    memcpy(hnew->line, newname, newlen );
	    strcpy(hnew->line+newlen, pc );

	    hnew->next = h->next;
	    if( hprev )
		hprev->next = hnew;
	    else
		msg->hdr_lines = hnew;
	    if( msg->hdr_lines_head == &h->next )
		msg->hdr_lines_head = &hnew->next;
	    free(h);
	    h = hnew;
	}

	if( which || !h->next )
	    return 0; /* ready (we only want to rename one field) */
	hprev = h->next; /* so that find_header start with the next one */
    }
}


/****************
 * Remove header:
 *
 * which gives the mode:
 *   0 := Do it for all the fields.
 *  -1 := Take the last occurence
 *   n := Take the n-th  one.
 */
int
rfc822_remove_header( RFC822 msg, const char *name, int which )
{
    HDR_LINE h, hnext, hprev;
    int seq = which;
    size_t len;
    int glob = 0;

    len = strlen(name);
    if( len && name[len-1] == '*' ) {
	len--;
	glob = 1;
    }

    hprev = NULL; /* start with the first one */
    seq=which?which:1;
    for(;;) {
	h = find_header( msg, name, seq, &hprev );
	if( !h )
	    return 0; /* no such field */

	while( h->next && h->next->cont ) {
	    hnext = h->next;
	    free(h);
	    h = hnext;
	}

	hnext = h->next;
	if( hprev ) {
	    hprev->next = hnext;
	    if( msg->hdr_lines_head == &h->next )
		msg->hdr_lines_head = &hprev->next;
	}
	else {
	    msg->hdr_lines = hnext;
	    if( msg->hdr_lines_head == &h->next )
		msg->hdr_lines_head = &msg->hdr_lines;
	}

	free(h);
	h = hnext;

	if( which || !h )
	    return 0; /* ready (we only want to remove one field) */
	hprev = h;
    }
}


/****************
 * Get a copy of a headerline, the line is returned as one long string with
 * LF to separate the continuation line. Caller must free thre return buffer.
 * which may be used to enumerate over all lines.  Wildcards are allowed.
 *
 * which gives the mode:
 *  -1 := Take the last occurence
 *   n := Take the n-th  one.
 */
char *
rfc822_get_header( RFC822 msg, const char *name, int which )
{
    HDR_LINE h, h2;
    char *buf, *p;
    size_t n;

    h = find_header( msg, name, which, NULL );
    if( !h )
	return 0; /* no such field */

    n = strlen(h->line)+1;
    for( h2 = h->next; h2 && h2->cont; h2 = h2->next )
	n += strlen(h2->line)+1;

    buf = p = xmalloc( n );
    p = stpcpy(p, h->line);
    *p++ = '\n';
    for( h2 = h->next; h2 && h2->cont; h2 = h2->next ) {
	p = stpcpy(p, h2->line);
	*p++ = '\n';
    }
    p[-1] = 0;
    return buf;
}


/****************
 * Enumerate all header.  Caller has to provide the address of a pointer
 * which has to be initialzed to NULL, the caller should then never change this
 * pointer until he has closed the enumeration by passing again the address
 * of the pointer but with msg set to NULL.
 * The function returns pointers to all the header lines or NULL when
 * all lines have been enumerated.
 */
const char*
rfc822_enum_header_lines( RFC822 msg, void **context )
{
    struct hdr_line *l;

    if( !msg )	/*close*/
	return NULL; /* this is quite easy in our implementation */

    if( *context == msg )
	return NULL;

    l = *context? (struct hdr_line*)*context : msg->hdr_lines;

    if( l ) {
	*context = l->next? (void*)(l->next) : (void*)msg;
	return l->line;
    }
    *context = msg;  /* mark end of list */
    return NULL;
}


/****************
 * Enumerate the body.	Caller has to provide the address of a pointer
 * which has to be initialzed to NULL, the caller should then never change this
 * pointer until he has closed the enumeration by passing again the address
 * of the pointer but with msg set to NULL.
 * The function returns pointers to all the body lines or NULL when
 * all lines have been enumerated.
 */
const char*
rfc822_enum_body_lines( RFC822 msg, void **context, size_t *nbytes )
{
    struct body_line *l;

    if( !msg )	/*close*/
	return NULL; /* this is quite easy in our implementation */

    if( *context == msg )
	return NULL;

    l = *context? (struct body_line*)*context : msg->bdy_lines;

    if( l ) {
	*context = l->next? (void*)(l->next) : (void*)msg;
	if( nbytes )
	    *nbytes = l->length;
	return l->data;
    }
    *context = msg;  /* mark end of list */
    return NULL;
}


/****************
 * Find a header field.  If the Name does end in an asterisk this is meant
 * to be a wildcard.
 *
 *  which  -1 : Retrieve the last field
 *	   >0 : Retrieve the n-th field
 * rprev may be used to return the predecessor of the returned field;
 * which may be NULL for the very first one. It has to be initialzed
 * to either NULL in which case the search start at the first header line,
 * or it may point to a headerline, where the search should start
 */
static HDR_LINE
find_header( RFC822 msg, const char *name, int which, HDR_LINE *rprev )
{
    HDR_LINE hdr, prev=NULL, mark=NULL;
    char *p;
    size_t namelen, n;
    int found = 0;
    int glob = 0;

    namelen = strlen(name);
    if( namelen  && name[namelen-1] =='*' ) {
	namelen--;
	glob = 1;
    }

    hdr = msg->hdr_lines;
    if( rprev && *rprev ) {
	/* spool forward to the requested starting place.
	 * we cannot simply set this as we have to return
	 * the previous list element too */
	for(; hdr && hdr != *rprev; prev = hdr, hdr = hdr->next )
	    ;
    }

    for(; hdr; prev = hdr, hdr = hdr->next ) {
	if( hdr->cont )
	    continue;
	if( !(p = strchr( hdr->line, ':' )) )
	    continue; /* invalid header, just skip it. */
	n = p - hdr->line;
	if( !n )
	    continue; /* invalid name */
	if( (glob? (namelen <= n) : (namelen == n))
	    && !memicmp( hdr->line, name, namelen ) ) {
	    found++;
	    if( which == -1 )
		mark = hdr;
	    else if( found == which ) {
		if( rprev )
		    *rprev = prev;
		return hdr;
	    }
	}
    }
    if( mark && rprev )
	*rprev = prev;
    return mark;
}



static const char *
skip_ws( const char *s )
{
    while( *s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' )
	s++;
    return s;
}


static void
release_token_list( TOKEN t )
{
    while( t ) {
	TOKEN t2 = t->next;
	/* fixme: If we have owner_pantry, put the token back to
	 * this pantry so that it can be reused later */
	free( t );
	t = t2;
    }
}


static TOKEN
new_token( enum token_type type, const char *buf, size_t length )
{
    TOKEN t;

    /* fixme: look through our pantries to find a suitable
     * token for reuse */
    t = xmalloc( sizeof *t + length );
    t->next = NULL;
    t->type = type;
    t->data[0] = 0;
    if( buf ) {
	memcpy(t->data, buf, length ),
	t->data[length] = 0; /* make sure it is a C string */
    }
    else
	t->data[0] = 0;
    return t;
}

static TOKEN
append_to_token( TOKEN old, const char *buf, size_t length )
{
    size_t n = strlen(old->data);
    TOKEN t;

    t = xmalloc( sizeof *t + n + length );
    t->next = old->next;
    t->type = old->type;
    memcpy( t->data, old->data, n );
    memcpy( t->data+n, buf, length );
    t->data[n+length] = 0;
    old->next = NULL;
    release_token_list(old);
    return t;
}



/****************
 * Parse a field into tokens as defined by rfc822.
 */
static TOKEN
parse_field( HDR_LINE hdr )
{
    static const char specials[] = "<>@.,;:\\[]\"()";
    static const char specials2[]= "<>@.,;:";
    static const char tspecials[] = "/?=<>@,;:\\[]\"()";
    static const char tspecials2[]= "/?=<>@.,;:";
    static struct { const char *name; int namelen; } tspecial_header[] = {
	{ "Content-Type", 12 },
	{ "Content-Transfer-Encoding", 25 },
	{ NULL, 0 }
    };
    const char *delimiters;
    const char *delimiters2;
    const char *line, *s, *s2;
    size_t n;
    int i, invalid = 0;
    TOKEN t, tok, *tok_head;

    if( !hdr )
	return NULL;

    tok = NULL;
    tok_head = &tok;

    line = hdr->line;
    if( !(s = strchr( line, ':' )) )
	return NULL; /* oops */

    n = s - line;
    if( !n )
	return NULL; /* oops: invalid name */
    delimiters	= specials;
    delimiters2 = specials2;
    for(i=0; tspecial_header[i].name; i++ ) {
	if( n == tspecial_header[i].namelen
	    && !memicmp( line, tspecial_header[i].name, n ) )
	{
	    delimiters	= tspecials;
	    delimiters2 = tspecials2;
	    break;
	}
    }

    /* Add this point we could store the fieldname in the parsing structure.
     * If we decide to do this, we should lowercase the name except for the
     * first character which should be uppercased.  This way we don't
     * need to apply the case insensitive compare in the future
     */

    s++; /* move  over the colon */
    for(;;) {
	if( !*s ) {
	    if( !hdr->next || !hdr->next->cont )
		break;
	    hdr = hdr->next;
	    s = hdr->line;
	}

	if( *s == '(' ) {
	    int level = 1;
	    int in_quote = 0;

	    invalid = 0;
	    for(s++ ; ; s++ ) {
		if( !*s ) {
		    if( !hdr->next || !hdr->next->cont )
			break;
		    hdr = hdr->next;
		    s = hdr->line;
		}

		if( in_quote ) {
		    if( *s == '\"' )
			in_quote = 0;
		    else if( *s == '\\' && s[1] ) /* what about continuation?*/
			s++;
		}
		else if( *s == ')' ) {
		    if( !--level )
			break;
		}
		else if( *s == '(' )
		    level++;
		else if( *s == '\"' )
		    in_quote = 1;
	    }
	    if( !*s )
		;/* actually this is an error, but we don't care about it */
	    else
		s++;
	}
	else if( *s == '\"' || *s == '[' ) {
	    /* We do not check for non-allowed nesting of domainliterals */
	    int term = *s == '\"' ? '\"' : ']';
	    invalid = 0;
	    s++;
	    t = NULL;

	    for(;;) {
		for( s2 = s; *s2; s2++ ) {
		    if( *s2 == term )
			break;
		    else if( *s2 == '\\' && s2[1] ) /* what about continuation?*/
			s2++;
		}

		t = t ? append_to_token( t, s, s2-s)
		      : new_token( term == '\"'? tQUOTED
					       : tDOMAINLIT, s, s2-s);

		if( *s2 || !hdr->next || !hdr->next->cont )
		    break;
		hdr = hdr->next;
		s = hdr->line;
	    }
	    *tok_head = t;
	    tok_head = &t->next;
	    s = s2;
	    if( *s )
		s++; /* skip the delimiter */
	}
	else if( (s2 = strchr( delimiters2, *s )) ) {
	    /* special characters which are not handled above */
	    invalid = 0;
	    t = new_token( tSPECIAL, s, 1 );
	    *tok_head = t;
	    tok_head = &t->next;
	    s++;
	}
	else if( *s == ' ' || *s == '\t' || *s == '\r' || *s == '\n' ) {
	    invalid = 0;
	    s = skip_ws(s+1);
	}
	else if( *s > 0x20 && !(*s & 128) ) { /* atom */
	    invalid = 0;
	    for( s2 = s+1; *s2 > 0x20
			   && !(*s2 & 128 )
			   && !strchr( delimiters, *s2 ); s2++ )
		;
	    t = new_token( tATOM, s, s2-s );
	    *tok_head = t;
	    tok_head = &t->next;
	    s = s2;
	}
	else {	/* invalid character */
	    if( !invalid ) { /* for parsing we assume only one space */
		t = new_token( tSPACE, NULL, 0);
		*tok_head = t;
		tok_head = &t->next;
		invalid = 1;
	    }
	    s++;
	}
    }
    return tok;
}




/****************
 * Find and parse a header field.
 * which indicates what to do if there are multiple instance of the same
 * field (like "Received"); the followinf value are defined:
 *  -1 := Take the last occurence
 *   0 := Reserved
 *   n := Take the n-th one.
 * Returns a handle for further operations on the parse context of the field
 * or NULL if the field was not found.
 */
RFC822_PARSE_CTX
rfc822_parse_header( RFC822 msg, const char *name, int which )
{
    HDR_LINE hdr;

    if( !which )
	return NULL;

    hdr = find_header( msg, name, which, NULL );
    if( !hdr )
	return NULL;
    return parse_field( hdr );
}

void
rfc822_release_parse_ctx( RFC822_PARSE_CTX ctx )
{
    if( ctx )
	release_token_list( ctx );
}



/****************
 * Check whether t points to a parameter.
 * A parameter starts with a semicolon and it is assumed that t
 * points to exactly this one.
 */
static int
is_parameter( TOKEN t )
{
    t = t->next;
    if( !t || t->type != tATOM )
	return 0;
    t = t->next;
    if( !t || !(t->type == tSPECIAL && t->data[0]=='=') )
	return 0;
    t = t->next;
    if( !t )
	return 1;  /* we assume that an non existing valie is an empty one */
    return t->type == tQUOTED || t->type == tATOM;
}

/****************
 * Some header (Content-type) have a special syntax where attribute=value
 * pairs are used after a leading semicolon.  the parse_field code
 * knows about these fields and changes the parsing to the one defined
 * in RFC2045.
 * Returns a pointer to the value which is valid as long as the
 * parse context is valid; NULL is returned in case that attr is not
 * defined in the header, a missing value is reppresented by an empty string.
 */
const char *
rfc822_query_parameter( RFC822_PARSE_CTX ctx, const char *attr )
{
    TOKEN t, a;

    for( t = ctx; t ; t = t->next ) {
	/* skip to the next semicolon */
	for( ; t && !(t->type == tSPECIAL && t->data[0]==';'); t = t->next )
	    ;
	if( !t )
	    return NULL;
	if( is_parameter( t ) ) { /* look closer */
	    a = t->next; /* we know that this is an atom */
	    if( !stricmp( a->data, attr ) ) { /* found */
		t = a->next->next;
		/* either t is now an atom, a quoted string or NULL in
		 * which case we retrun an empty string */
		return t? t->data : "";
	    }
	}
    }
    return NULL;
}

/****************
 * This function may be used for the Content-Type header to figure out
 * the media type and subtype.
 * Returns: a pointer to the media type and if subtype is not NULL,
 *	    a pointer to the subtype.
 */
const char *
rfc822_query_media_type( RFC822_PARSE_CTX ctx, const char **subtype )
{
    TOKEN t = ctx;
    const char *type;

    if( t->type != tATOM )
	return NULL;
    type = t->data;
    t = t->next;
    if( !t || t->type != tSPECIAL || t->data[0] != '/' )
	return NULL;
    t = t->next;
    if( !t || t->type != tATOM )
	return NULL;
    if( subtype )
	*subtype = t->data;
    return type;
}





#ifdef TESTING

static void
dump_token_list( TOKEN t )
{
    for( ; t; t = t->next ) {
	switch( t->type ) {
	  case tSPACE:	   printf("  space\n"); break;
	  case tATOM:	   printf("  atom      `%s'\n", t->data ); break;
	  case tQUOTED:    printf("  quoted    `%s'\n", t->data ); break;
	  case tDOMAINLIT: printf("  domainlit `%s'\n", t->data ); break;
	  case tSPECIAL:   printf("  special   `%s'\n", t->data ); break;
	}
    }
}

static void
show_param( RFC822_PARSE_CTX ctx, const char *name )
{
    const char *s;

    if( !ctx )
	return;
    s = rfc822_query_parameter( ctx, name );
    if( !s )
	printf("%s: [not found]\n", name );
    else
	printf("%s: `%s'\n", name, s );
}

int
main( int argc, char **argv )
{
    char line[5000];
    char *name, *newname=NULL;
    size_t length;
    RFC822 msg;
    RFC822_PARSE_CTX ctx;
    const char *s1, *s2;

    if( argc > 2 ) {
	newname = argv[2];
	name = argv[1];
    }
    else if( argc > 1 )
	name = argv[1];
    else
	name = "Content-Type";


    msg = rfc822_open( NULL, NULL );
    if( !msg )
	abort();

    while( fgets( line, sizeof(line), stdin ) ) {
	length = strlen( line );
	if( length && line[length-1] == '\n' )
	    line[--length] = 0;
	if( length && line[length-1] == '\r' )
	    line[--length] = 0;
	if( rfc822_insert( msg, line, length ) )
	    abort();
    }


    if( newname ) {
	HDR_LINE h;

	if( rfc822_rename_header( msg, name, newname, 0 ) )
	    abort();

	for(h = msg->hdr_lines; h; h = h->next )
	    puts( h->line );
    }
    else if( 1 ) {
	HDR_LINE h;

	if( rfc822_remove_header( msg, name,0 ) )
	    abort();

	for(h = msg->hdr_lines; h; h = h->next )
	    puts( h->line );

    }
    else {
	ctx = rfc822_parse_header( msg, name, -1 );
	dump_token_list( ctx);
	s1 = ctx? rfc822_query_media_type( ctx, &s2 ) : NULL;
	if( s1 )
	    printf("media: `%s'  `%s'\n", s1, s2 );
	else
	    printf("media: [not found]\n");
	show_param( ctx, "boundary" );
	show_param( ctx, "protocol" );
	show_param( ctx, "micalg" );

	rfc822_release_parse_ctx( ctx );
    }

    rfc822_close( msg );
    return 0;
}
#endif

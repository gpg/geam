/* rwbuf.c
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <pth.h>


#include "logging.h"
#include "types.h"
#include "rwbuf.h"

#define MAX_FDS 1024  /* Note, taht this also limits the number of
                         concurrent connections we can process. */
#define READ_BUFFER_SIZE  256
#define WRITE_BUFFER_SIZE 128

#define LF '\x0a'
#define CR '\x0d'


struct buf_desc {
	size_t size;   /* allocated size */
	size_t wpos;   /* next write goes here */
	size_t rpos;   /* next read starts here */
	char d[1];
};

struct rwbuf_data {
    int eof;
    int error;
    struct buf_desc *r;
    int rto, wto;  /* read and write timeout in seconds */
};
typedef struct rwbuf_data *RWBUF;


static struct rwbuf_data fd_table[MAX_FDS];


static struct buf_desc*
create_buffer( size_t size )
{
    struct buf_desc *buf;

    buf = malloc( size + sizeof(*buf) - 1 );
    if( buf ) {
	buf->size = size;
	buf->wpos = 0;
	buf->rpos = 0;
    }
    return buf;
}


static struct buf_desc*
resize_buffer( struct buf_desc *old, size_t newsize )
{
    struct buf_desc *new;

    new = realloc( old, newsize + sizeof(*old) - 1 );
    if( new )
	new->size = newsize;
    return new;
}


/****************
 * Initialize a buffer. This function may be used at any
 * time to assign a rw buffer to a file descriptor.
 */
int
rw_init( int fd )
{
    RWBUF a;

    if( fd < 0 || fd >= MAX_FDS )
	return -1;
    a = fd_table + fd;

    if( !a->r && !(a->r = create_buffer( READ_BUFFER_SIZE )) )
	return -1; /* out of memory */
    a->r->rpos = 0;
    a->r->wpos = 0;
    a->eof = 0;
    a->error = 0;
    a->rto = 0;
    a->wto = 0;
    return 0;
}

void
rw_timeout( int fd, int read_seconds, int write_seconds )
{
    RWBUF rw;

    if( fd < 0 || fd >= MAX_FDS )
	BUG();
    rw = fd_table + fd;

    if( read_seconds != -1 )
	rw->rto = read_seconds;
    if( write_seconds != -1 )
	rw->wto = write_seconds;
}

/****************
 * Read a line from fd and return a pointer to a buffer
 * which is allocated for the fd and valid until the next call
 * to a read function on this fd.
 * Reading stops on a LF which will be replaced by binary 0
 * nbytes will have the length of the line w/o this 0.
 * If the line has to be truncated a 0 will we set anyway.
 *
 *
 * Returns: A pointer to this buffer which valid length is
 *	    returned in nbytes.
 *	    EOF or error is indicated by returning NULL.
 *	    if truncated is not NULL, it wiill be set to 1 if
 *	    the line has been truncated or together with a return value.
 *	    of NULL it indicates a timeout
 * Note:  This function uses the internal read buffer and probably
 *	  will extend it to maxlen if required.
 */
char *
rw_readline( int fd, size_t maxlen, size_t *nbytes, int *truncated )
{
    RWBUF rw;
    struct buf_desc *buf;
    int nread, n;
    char *p;
    pth_event_t evt;

    if( truncated )
	*truncated = 0;
    if( !maxlen )  /* we need a maxlen of at least 1 */
	maxlen = READ_BUFFER_SIZE;

    if( fd < 0 || fd >= MAX_FDS )
	BUG();

    rw = fd_table + fd;
    /* make sure that the buffer has been initialized */
    if( !(buf = rw->r) ) {
	buf = rw->r = create_buffer( maxlen < READ_BUFFER_SIZE ?
						READ_BUFFER_SIZE : maxlen );
	if( !buf ) {
	    return NULL;  /* out of core */
	}
    }

    if( rw->eof || rw->error ) {
	return NULL;
    }

    assert( buf->rpos <= buf->wpos );

    if( buf->rpos ) { /* shift the buffer to the beginning */
	/* Hmmm:  We have to see whether it makes sense to
	 * defer this until our buffer gets to short */
	memmove( buf->d, buf->d + buf->rpos,  buf->wpos - buf->rpos );
	buf->wpos -= buf->rpos;
	buf->rpos = 0;
    }

    for(;;) {
	n = buf->wpos < maxlen? buf->wpos : maxlen;
	p = memchr( buf->d, LF, n );
	if( p ) {
	    *p = 0;
	    n = p - buf->d;
	    buf->rpos = n+1;
	    if( nbytes )
		*nbytes = n;
	    return buf->d; /* The complete line has already been read in */
	}
	if( buf->wpos >= maxlen ) {
	    if( truncated )
		*truncated = 1;
	    buf->rpos = maxlen;
	    buf->d[maxlen-1] = 0; /* make sure it is a C string */
	    if( nbytes )
		*nbytes = maxlen;     /* fixme: save this character for later restore */
	    return buf->d;
	}

	/* fill up the buffer */
	n = buf->size - buf->wpos;
	if( n < 10 && buf->size < maxlen ) {
	    /* our buffer seems to be too short. try to reallocate */
	    struct buf_desc *newbuf = resize_buffer( buf, maxlen );
	    if( newbuf ) {
		rw->r = buf = newbuf;
		n = buf->size - buf->wpos;
	    }
	}
	if( n < 1 ) {
	    /* no way to stuff more into our buffer */
	    if( truncated )
		*truncated = 1;
	    buf->rpos = buf->wpos;
	    buf->d[buf->rpos-1] = 0; /* make sure it is a C string */
	    if( nbytes )
		*nbytes = buf->rpos;   /* fixme: save this character for later restore */
	    return buf->d;
	}

	evt = rw->rto ? pth_event( PTH_EVENT_TIME, pth_timeout( rw->rto, 0) )
		      : NULL;
	nread = pth_read_ev( fd, buf->d + buf->wpos, n, evt );
	if( nread < 0 ) {
	    if( evt && pth_event_occurred( evt ) ) {
		pth_event_free(evt, PTH_FREE_THIS);
		if( truncated )
		    *truncated = 1; /* indicate timeout */
	    }
	    rw->error = 1;
	    return NULL;
	}
	if( evt )
	    pth_event_free(evt, PTH_FREE_THIS);
        if( !nread  ) {
	    rw->eof = 1;
	    if( !buf->wpos ) {
		return NULL;
	    }
	    if( truncated )
		*truncated = 1;
	    buf->rpos = buf->wpos;
	    buf->d[buf->rpos-1] = 0; /* make sure it is a C string */
	    if( nbytes )
		*nbytes = buf->rpos;   /* fixme: save this character for later restore */
	    return buf->d;
	}
	buf->wpos += nread;
	/* Actually we should increase rpos and take this in account
	 * while looking for the LF atthe top of the loop.
	 * However, the current approach does work and can be
	 * enhanced later.
	 */
    }

}


int
rw_writen( int fd, const char *buffer, size_t length )
{
    while( length ) {
	int nwritten = pth_write( fd, buffer, length );
	/* pth handles EINTR for us */
	if( nwritten < 0 )
	    return -1; /* write error */
	length -= nwritten;
	buffer += nwritten;
    }
    return 0;  /* okay */
}

int
rw_writestr( int fd, const char *string )
{
    return rw_writen( fd, string, strlen(string) );
}

int
rw_printf( int fd, const char * format, ... )
{
    char buf[990]; /* should be below 1000 to help for SMTP */
    size_t n, len;
    va_list arg_ptr;

    va_start( arg_ptr, format );
    vsnprintf( buf, DIM(buf), format, arg_ptr );
    va_end( arg_ptr );

    len = strlen(buf); /* return value of vsnprint is not reliable */

    /* make sure that we have at least the
     * line ending in the output */
    n = strlen(format);
    if( n > 1 && len > 1 && format[n-2] == '\r' && format[n-1] == '\n' ) {
	if( buf[len-2] != '\r' || buf[len-1] != '\n' ) {
	    buf[len-2] = '\r';
	    buf[len-1] = '\n';
	}
    }
    else if( n && len && format[n-1] == '\n' ) {
	if( buf[len-1] != '\n' ) {
	    buf[len-1] = '\n';
	}
    }
    return rw_writen( fd, buf, len );
}


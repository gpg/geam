/* simple-mta.c  -  A simple SMTP implemenation
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
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef __GLIBC__
  #error This program will only work with the GNU libc
  /* GNU features used:  printf("%m") */
#endif

#include "xmalloc.h"
#include "argparse.h"
#include "logging.h"
#include "rfc821.h"
#include "rfc822.h"
#include "rwbuf.h"


#define DEFAULT_PORT 25


enum opt_values { aNull = 0,
    oListen	  = 'l',
    oServer	  = 's',
    oPort	  = 'p',
    oFrom	  = 'f',
    oTo 	  = 't',
    oVerbose	  = 'v',
    oQuiet	  = 'q',
    oDebug	  = 500,

};

static ARGPARSE_OPTS opts[] = {
    { 301, NULL, 0, "@\nOptions:\n " },
    { oListen,	"listen",    0, "wait for a connection" },
    { oServer,	"server",    0, "run as a server" },
    { oPort,	"port",      1, "|N|use port N (default is 25)"},
    { oFrom,	"from",      2, "|A|set MAIL FROM:<A>"},
    { oTo  ,	"to",        2, "|A|set RCPT TO:<A>"},
    { oVerbose, "verbose",   0, "verbose" },
    { oQuiet,	"quiet",     0, "be more quiet"},
    { oDebug,	"debug",     4|16, "set debugging flags"},
{0} };


struct stringlist {
    struct stringlist *next;
    char d[1];
};

typedef struct server_data {
    int fd;
    const char *filename;
    FILE *stream;
} *SERVER;


static int verbose = 0;
static int debug = 0;

static int start_listening( int port );
static int server_cb_rfc821( void *opaque, enum rfc821_events event, RFC821 smtp );
static int server_cb_rfc822( void *opaque, enum rfc822_events event, RFC822 msg );


/****************
 * Wrappers needed for rwbuf.c so that the PTH library is not needed.
 */
ssize_t
pth_read_ev(int fd, void *p, size_t n, void *evt )
{
    return read( fd, p, n );
}

ssize_t
pth_write(int fd, const void *p, size_t n)
{
    return write( fd, p, n );
}

void *
pth_timeout( int a, int b)
{
    return NULL;
}

void *
pth_event(unsigned long t, ...)
{
    return NULL;
}

int
pth_event_free( void *a, int how)
{
    return 0;
}

int
pth_event_occurred( void *e )
{
    return 0;
}


static const char *
my_strusage( int level )
{
    const char *p;
    switch( level ) {
      case 11: p = "simple-mta";
	break;
      case 13: p = VERSION; break;
      case 14: p = "Copyright (C) 2000 Werner Koch Softwaresysteme"; break;
      case 19: p = "Please report bugs to <bug-geam@gnupg.de>.\n";
	break;
      case 1:
      case 40:	p =
	      "Usage: simple-mta [options] (-h for help)" ;
	break;
      case 41:	p =
	      "Syntax: simple-mta [options] [host] [file]\n"
	      "        simple-mta [options] -l     [file]\n"
	      "Do a SMTP transaction\n";
	break;

      default:	p = NULL;
    }
    return p;
}



int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    int server = 0;
    int port = DEFAULT_PORT;
    int looping = 0;
    const char *filename = NULL;
    const char *hostname = NULL;
    const char *mail_from = "";
    struct stringlist *rcpt_to = NULL;
    struct stringlist *sl;

    set_strusage( my_strusage );

    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags = 0;
    while( arg_parse( &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case oListen: server = 1; break;
	  case oPort: port = pargs.r.ret_int; break;
	  case oServer: looping = 1; break;
	  case oFrom: mail_from = pargs.r.ret_str; break;
	  case oTo:
	    sl = xmalloc( sizeof(*sl) + strlen(pargs.r.ret_str) );
	    strcpy( sl->d, pargs.r.ret_str );
	    sl->next = rcpt_to;
	    rcpt_to = sl;
	    break;
	  case oVerbose: verbose++; break;
	  case oQuiet:	break;
	  case oDebug: debug |= pargs.r.ret_ulong; break;
	  default: pargs.err = 2; break;
	}
    }

    if( (debug & 4) )
	rfc821_set_flag( NULL, RFC821FLG_DBGSMTP, 1 );

    if( server ) {
	if( argc == 1 )
	    filename = *argv;
	else if( argc )
	    usage(1);
    }
    else  {
	if( !argc )
	    hostname = "localhost";
	else if( argc == 1 )
	    hostname = *argv;
	else if( argc == 2 ) {
	    hostname = *argv;
	    filename = argv[1];
	}
	else
	    usage(1);
    }

    signal(SIGPIPE, SIG_IGN); /* better ignore this */

    if( server ) {
	int listen_fd;
	struct sockaddr_in paddr;
	socklen_t plen = sizeof( paddr );
	RFC821 smtp;
	struct server_data state;

	listen_fd = start_listening( port );
	if( listen_fd == -1 )
	    return 1;

	do {
	    memset( &state, 0, sizeof state );
	    state.filename = filename;
	    if( verbose )
		log_info( "waiting on port %d\n", port );

	    state.fd = accept( listen_fd, (struct sockaddr *)&paddr, &plen);
	    if( state.fd == -1 ) {
		log_error( "accept failed: %m\n" );
		continue;
	    }
	    if( verbose )
		log_info( "connect from %s:%d\n",
			  inet_ntoa(paddr.sin_addr), (int)ntohs(paddr.sin_port) );

	    if( rw_init( state.fd ) ) {
		log_error("fd %d: rw_init failed\n", state.fd );
		continue;
	    }

	    smtp = rfc821_open( server_cb_rfc821, &state );
	    if( !smtp ) {
		log_error("rfc821_open failed\n" );
	    }
	    else {
		rfc821_set_proto_comment( smtp, "simple-mta server" );
		rfc821_set_rfc822_cb( smtp, server_cb_rfc822, &state );
		if( rfc821_handler( smtp, state.fd, inet_ntoa(paddr.sin_addr),
						(int)ntohs(paddr.sin_port)) )
		    log_error("smtp processing failed\n" );
		rfc821_close( smtp );
	    }

	    close( state.fd );
	} while( looping );
	close( listen_fd );
    }
    else { /* client */
	int fd, sock;
	struct protoent *pe;
	struct hostent *host;
	struct sockaddr_in addr;
	int rc;
	RFC821 smtp;
	RFC822 msg;

	if( port < 1 || port > 65534 ) {
	    log_error("port %d is invalid\n", port );
	    exit(1);
	}

	if( filename ) {
	    fd = open( filename, O_RDONLY );
	    if( fd == -1 ) {
		log_error("failed to open `%s': %m\n", filename );
		exit(1);
	    }
	}
	else
	    fd = 0;

	if( rw_init( fd ) ) {
	    log_error("rw_init failed\n");
	    exit(1);
	}


	if( !(pe = getprotobyname("tcp")) ) {
	    log_error("getprotobyname failed: %m\n" );
	    exit(1);
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	host = gethostbyname((char*)hostname);
	if( !host ) {
	    log_error("host `%s' not found\n", hostname );
	    exit(1);
	}
	addr.sin_addr = *(struct in_addr*)host->h_addr;


	sock = socket(AF_INET, SOCK_STREAM, pe->p_proto );
	if( sock == -1 ) {
	    log_error("error creating socket: %m\n" );
	    exit(1);
	}

	if( connect( sock, (struct sockaddr *)&addr, sizeof addr) == -1 ) {
	    log_error("error connecting `%s': %m\n", hostname );
	    close(sock);
	    exit(1);
	}

	if( rw_init( sock ) ) {
	    log_error("rw_init failed\n" );
	    exit(1);
	}

	smtp = rfc821_open( NULL, NULL );
	if( !smtp ) {
	    log_error("rfc821_open failed\n" );
	    exit(1);
	}

	rfc821_set_proto_comment( smtp, "simple-mta client" );
	rc = rfc821_start_session( smtp, sock );
	if( rc ) {
	    log_error("rfc821_start_session failed: rc=%d\n", rc );
	    rfc821_cancel( smtp ); close( sock );
	    exit(1);
	}


	msg = rfc822_open( NULL, NULL );
	if( !msg ) {
	    log_error("rfc822_open failed\n" );
	    rfc821_cancel( smtp ); close( sock );
	    exit(1);
	}
	for( ;; ) {
	    size_t length;
	    char *line = rw_readline( fd, 2000, &length, NULL );
	    if( !line )
		break; /* EOF */
	    if( length && line[length-1] == '\r' )
		line[--length] = 0;
	    if( rfc822_insert( msg, line, length ) ) {
		rfc822_cancel( msg );
		rfc821_cancel( smtp ); close( sock );
		exit(1);
	    }
	}
	if( fd != 0 )
	    close(fd);


	rc = rfc821_send_sender( smtp, mail_from );
	if( rc ) {
	    log_error("MAIL command failed: rc=%d\n", rc );
	    rfc822_cancel( msg );
	    rfc821_cancel( smtp ); close( sock );
	    exit(1);
	}

	for( sl = rcpt_to; sl; sl = sl->next ) {
	    rc = rfc821_send_recipient( smtp, sl->d );
	    if( rc ) {
		log_error("RCPT command failed: rc=%d\n", rc );
		rfc822_cancel( msg );
		rfc821_cancel( smtp ); close( sock );
		exit(1);
	    }
	}


	rc = rfc821_copy_header_lines( smtp, msg );
	if( !rc )
	    rc = rfc821_copy_body_lines( smtp, msg );
	if( !rc )
	    rc = rfc821_send_body_line( smtp, NULL, 0 );
	if( rc ) {
	    log_error("DATA command failed: rc=%d\n", rc );
	    rfc822_cancel( msg );
	    rfc821_cancel( smtp ); close( sock );
	    exit(1);
	}
	rfc822_close( msg );
	rfc821_close( smtp ); close( sock );
    }


    return 0;
}


static int
start_listening( int port )
{
    int fd;
    int one = 1;
    struct protoent *pe;
    struct sockaddr_in addr;

    if( port < 1 || port > 65534 ) {
	log_error("port %d is invalid\n", port );
	return -1;
    }

    if( !(pe = getprotobyname("tcp")) ) {
	log_error("getprotobyname failed: %m\n" );
	return -1;
    }

    fd = socket( AF_INET, SOCK_STREAM, pe->p_proto );
    if( fd < 0 ) {
	log_error("error creating socket: %m\n" );
	return -1;
    }
    if( setsockopt( fd, SOL_SOCKET, SO_REUSEADDR,
				    (const void *)&one, sizeof one) ) {
	log_error("error setting SO_REUSEADDR: %m\n" );
	close(fd);
	return -1;
    }

    memset( &addr, 0, sizeof addr );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons(port);
    if( bind( fd, (struct sockaddr*)&addr, sizeof addr ) ) {
	log_error("error binding port %d: %m\n", port );
	close(fd);
	return -1;
    }

    if( listen( fd, 5 ) ) {
	log_error("error listening on port %d: %m\n", port );
	close(fd);
	return -1;
    }

    return fd;
}

/****************
 * This function is called by the rfc821 layer for certain events
 * This rfc821.h for a list of events.	This function should
 * return with 0 for normal success or with an errorcode to let
 * the rfc821 layer return an error code.
 */
static int
server_cb_rfc821( void *opaque, enum rfc821_events event, RFC821 smtp )
{
    SERVER state = opaque;
    int rc = 0;

    /*log_debug("fd %d: server_cb_rfc821: event %d\n", state->fd, event );*/
    switch( event ) {
      case RFC821EVT_DATA:
	if( state->filename ) {
	    state->stream = fopen( state->filename, "wb");
	    if( !state->stream ) {
		log_error("failed to open `%s': %m\n", state->filename );
		rc = 1;
	    }
	}
	else
	    state->stream = stdout;
	break;

      case RFC821EVT_DATA_END:
	break;
    }

    return rc;
}


static int
server_cb_rfc822( void *opaque, enum rfc822_events event, RFC822 msg )
{
    SERVER state = opaque;
    int rc = 0;

    /*log_debug("fd %d: server_cb_rfc822: event %d\n", state->fd, event );*/
    if( event == RFC822EVT_FINISH && state->stream ) {
	void *ectx;
	const char *line;
	size_t n;

	for( ectx=NULL; !rc && (line = rfc822_enum_header_lines( msg, &ectx)); ) {
	    if( fputs( line, state->stream ) == EOF
		|| putc('\n', state->stream ) == EOF ) {
		log_error("fputs() failed: %m\n" );
		rc = 1;
	    }
	}
	rfc822_enum_header_lines( NULL, &ectx ); /* close enumerator */

	putc('\n', state->stream );

	for( ectx=NULL; !rc && (line = rfc822_enum_body_lines( msg, &ectx, &n)); ) {
	    int nn;
	    if( n && (nn=fwrite( line, n, 1, state->stream )) != 1 ) {
		log_error("fwrite() failed n=%d nn=%d: %m\n", n, nn );
		rc = 1;
	    }
	    else if( putc('\n', state->stream ) == EOF ) {
		log_error("putc() failed: %m\n" );
		rc = 1;
	    }
	}
	rfc822_enum_body_lines( NULL, &ectx, NULL ); /* close enumerator */
	if( state->stream == stdout )
	    ;
	else if( fclose(state->stream) ) {
	    log_error("fclose() failed: %m\n" );
	    rc = 1;
	}
	state->stream = NULL;
    }

    return rc;
}



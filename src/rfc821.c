/* rfc821.c
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
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>

#include "geamd.h"
#include "rfc821.h"
#include "rfc822.h"


enum smtp_cmds {
    smtpINVALID = 0,   /* invalid command */
    smtpNOTIMPL,
    smtpNOOP,
    smtpHELO,
    smtpRSET,
    smtpMAIL,
    smtpRCPT,
    smtpDATA,
    smtpQUIT,
};


struct path_list {
    struct path_list *next;
    char d[1];
};

struct rfc821_state {
    int session_type; /* 0 = not initialzed, 1 = client, 2 = server */
    int fd;
    char *peer_addr_str;
    int peer_port;
    int verbose;
    int dbgsmtp;
    const char *proto_comment;
    int did_quit;
    int eof_seen;
    int in_data;
    int helo_seen_done;
    char *helo_string;
    char *reverse_path;
    struct path_list *forward_path;
    struct path_list **forward_path_head;
    int (*cb)(void*, enum rfc821_events, RFC821 );
    void *cb_value;
    int (*cb822)(void*, enum rfc822_events, RFC822 );
    void *cb822_value;
};


static struct {
    int verbose;
    int dbgsmtp;
} defaults;

static int cb_from_rfc822( void *opaque, enum rfc822_events event, RFC822 msg );
static int get_response( RFC821 state );

static void
dump_state( int fd, RFC821 state )
{
    struct path_list *l;

    log_debug("fd %d: dumping state:\n", fd );
    log_debug("   helo=%s `%s'\n", state->helo_seen_done? "yes":"no ",
		      state->helo_string? state->helo_string:"[none]" );
    if( state->reverse_path )
	log_debug("   reverse_path=`%s'\n", state->reverse_path );
    for(l=state->forward_path; l; l = l->next )
	log_debug("   forward_path=`%s'\n", l->d );
}

static void
release_path_list( struct path_list *list )
{
    struct path_list *tmp;

    for( ; list; list = tmp ) {
	tmp = list->next;
	free(list);
    }
}


/****************
 * Return the name of this host, we retrieve it only once.
 * Note, that this function may block on a misconfigured system
 * but in this case we have more problems anyway.
 */
const char *
get_my_name(void)
{
    static char *myname = NULL;

    if( !myname ) {
	struct hostent *host;
	size_t n = 0;
	char *p = NULL;

	do {
	    n += 60;
	    if( n > 2000 )
		log_fatal("gethostname failed\n");
	    free(p);
	    p = xmalloc( n+1 );
	} while( gethostname( p, n ) );

	host = gethostbyname( p );
	if( !host ) {
	    log_error("failed to find own FQDN\n" );
	    myname = xstrdup(p);
	}
	else
	    myname = xstrdup( host->h_name );
	free(p);
    }
    return myname;
}

static int
do_callback( RFC821 state, enum rfc821_events event )
{
    int rc;

    if( !state->cb )
	return 0;
    rc = state->cb( state->cb_value, event, state );
    return rc;
}


/****************
 * Basic checks on the path syntax
 */
static int
check_path( const char *path )
{
    if( *path == '<' ) {
	path++;
	if( !*path || path[strlen(path)-1] != '>' )
	    return -1;
    }
    else if( *path == '>' || (*path && path[strlen(path)-1] == '>') )
	return -1;

    return 0;
}


/****************
 * Parse a SMTP command and return it's code.
 */
static enum smtp_cmds
rfc821_parse_cmd( char **rline, size_t len )
{
    static struct { const char *name;
		    const char *name2;
		    int name2len;
		    enum smtp_cmds cmd;
		  } tbl[] = {
	{ "RCPT", "TO:",  3, smtpRCPT },
	{ "MAIL", "FROM:",5, smtpMAIL },
	{ "DATA", NULL,   0, smtpDATA },
	{ "HELO", NULL,   0, smtpHELO },
	{ "RSET", NULL,   0, smtpRSET },
	{ "QUIT", NULL,   0, smtpQUIT },
	{ "NOOP", NULL,   0, smtpNOOP },
	{ "SEND", NULL,   0, smtpNOTIMPL },
	{ "SOML", NULL,   0, smtpNOTIMPL },
	{ "SAML", NULL,   0, smtpNOTIMPL },
	{ "VRFY", NULL,   0, smtpNOTIMPL },
	{ "EXPN", NULL,   0, smtpNOTIMPL },
	{ "HELP", NULL,   0, smtpNOTIMPL },
	{ "TURN", NULL,   0, smtpNOTIMPL },
	{ NULL, 0 } };
    int i;
    char *p = *rline;

    if( len < 4 || !(!p[4] || p[4] == ' ') )
	return smtpINVALID;
    for(i=0; i < 4; i++ )
	p[i] = toupper(p[i]);
    for(i=0; tbl[i].name; i++ )
	if( !memcmp( p, tbl[i].name, 4 ) ) {
	    p += 4;
	    /* we skip all leading spaces here */
	    while( *p == ' ' )
		p++;
	    if( tbl[i].name2 ) {
		int j;

		for(j=0; j < tbl[i].name2len; j++ )
		    p[j] = toupper(p[j]);
		if( memcmp( p, tbl[i].name2, tbl[i].name2len ) )
		    return smtpINVALID;
		p += tbl[i].name2len;
		while( *p == ' ' )
		    p++;
	    }
	    *rline = p;
	    return tbl[i].cmd;
	}
    return smtpINVALID;
}

static int
rfc821_reply( int fd, int code, const char *desc )
{
    const char *string1 = "";
    if( !desc ) {
	switch( code ) {
	  case 220: string1 = get_my_name();
		    desc = " SMTP Geam " VERSION; break;
	  case 221: string1 = get_my_name();
		    desc = " closing connection"; break;
	  case 250: desc = "OK"; break;

	  case 354: desc = "Start mail input; end with <CRLF>.<CRLF>"; break;

	  case 421: string1 = get_my_name();
		    desc = " SMTP command timeout - closing connection"; break;

	  case 451: desc = "Requested action aborted: "
			   "local error in processing"; break;
	  case 452: desc = "Requested action not taken: "
			   "insufficient system storage"; break;

	  case 500: desc = "Command unrecognized"; break;
	  case 501: desc = "Syntax error in parameters or arguments"; break;
	  case 502: desc = "Command not implemented"; break;
	  case 503: desc = "Bad sequence of commands"; break;

	  case 554: desc = "Transaction failed"; break;

	  default: desc = ""; break;
	}
    }

    return rw_printf( fd, "%03d %s%s\r\n",
			  code, string1, desc )? RFC821ERR_SEND : 0;
}


/****************
 * Allowed replies for HELO
 * S: 250
 * E: 500, 501, 504, 421
 */
static int
rfc821_proc_helo( RFC821 state, int fd, char *line )
{
    trim_spaces(line);
    if( !*line )
	return rfc821_reply( fd, 501, NULL );
    state->helo_seen_done = 1;
    state->helo_string = xstrdup(line);

    return rfc821_reply( fd, 250, NULL );
}

static int
rfc821_proc_noop( RFC821 state, int fd, char *line )
{
    if( !state->helo_seen_done )
	return rfc821_reply( fd, 503, NULL );
    dump_state( fd, state );
    return rfc821_reply( fd, 250, NULL );
}


/****************
 * Allowed replies for MAIL
 * S: 250
 * F: 552, 451, 452
 * E: 500, 501, 421
 * We do accept a path which is not included in angle brackets;
 */
static int
rfc821_proc_mail( RFC821 state, int fd, char *line )
{
    if( !state->helo_seen_done )
	return rfc821_reply( fd, 503, NULL );

    if( check_path( line ) )
	return rfc821_reply( fd, 501, NULL );
    if( *line == '<' ) {
	line++;
	line[strlen(line)-1] = 0;
    }

    free(state->reverse_path);
    state->reverse_path = xstrdup(line);

    release_path_list(state->forward_path); state->forward_path = NULL;
    state->forward_path_head = &state->forward_path;


    return rfc821_reply( fd, 250, NULL );
}

/****************
 * Allowed replies for RCPT
 *  S: 250, 251
 *  F: 550, 551, 552, 553, 450, 451, 452
 *  E: 500, 501, 503, 421
 * We do accept a path which is not included in angle brackets;
 */
static int
rfc821_proc_rcpt( RFC821 state, int fd, char *line )
{
    struct path_list *path;

    if( !state->helo_seen_done || !state->reverse_path )
	return rfc821_reply( fd, 503, NULL );

    if( check_path( line ) )
	return rfc821_reply( fd, 501, NULL );
    if( *line == '<' ) {
	line++;
	line[strlen(line)-1] = 0;
    }

    path = xmalloc( sizeof(*path) + strlen(line) );
    path->next = NULL;
    strcpy( path->d, line);
    *state->forward_path_head = path;
    state->forward_path_head = &path->next;

    return rfc821_reply( fd, 250, NULL );
}


static int
insert_received( RFC821 state, RFC822 msg )
{
    char *t = rfc822_timestamp(NULL,0);
    const char *ipaddr = state->peer_addr_str? state->peer_addr_str : "?";
    const char *myname = get_my_name();
    const char *with = state->proto_comment? state->proto_comment
					   : PACKAGE " " VERSION ;
    char *buf;
    struct path_list *r;
    size_t n = 0;

    for( r = state->forward_path; r ; r = r->next )
	n += strlen( r->d ) + 4; /* need extra space for ",;\n\t" */

    buf = xmalloc( strlen(t)
			 + strlen(state->helo_string)
			 + strlen(ipaddr)
			 + n
			 + strlen(myname)
			 + strlen(with)
			 + 100 );

    /* we should insert the DNS name direct after the "from", but then we need
     * a threaded resolver lib. */
    if( state->forward_path ) {
	char *p;

	sprintf(buf, "Received: from (%s) [%s]\n"
		     "\tby %s with smtp (%s)\n"
		     "\tfor <",
		   state->helo_string, ipaddr, myname, with );

	p = buf + strlen(buf);
	n = 6; /* the "\tfor <" */
	for( r = state->forward_path; r ; r = r->next ) {
	    if( n + strlen( r->d ) >= 72 ) {
		p = stpcpy( p, "\n\t" );
		n = 2;
	    }
	    n += strlen(r->d) + 1;
	    p = stpcpy( p, r->d );
	    *p++ = ',';
	}
	p--; /* so that the last comma gets overwritten */
	if( n + strlen(t) > 65 )
	    sprintf( p, ">;\n\t%s", t );
	else
	    sprintf( p, ">; %s", t );
    }
    else {
	sprintf(buf, "Received: from (%s) [%s]\n"
		     "\tby %s with smtp (%s);\n"
		     "\t%s",
		   state->helo_string, ipaddr, myname, with, t );
    }

    rfc822_add_header( msg, buf );

    free(t);
    free( buf );
    return 0;
}



/****************
 * Allowed replies for DATA
 * I: 354 -> data -> S: 250
 *		     F: 552, 554, 451, 452
 * F: 451, 554
 * E: 500, 501, 503, 421
 */
static int
rfc821_proc_data( RFC821 state, int fd, char *line )
{
    int rc;
    size_t length;
    int truncated;
    RFC822 msg;

    if( !state->helo_seen_done || !state->reverse_path || !state->forward_path )
	return rfc821_reply( fd, 503, NULL );

    if( *line )
	return rfc821_reply( fd, 501, NULL );

    msg = rfc822_open( cb_from_rfc822, state );
    if( !msg )
	return rfc821_reply( fd, 452, NULL ); /* correct error code ? */

    if( do_callback( state, RFC821EVT_DATA ) ) {
	rfc822_cancel( msg );
	return rfc821_reply( fd, 451, NULL ); /* local processing error */
    }


    rc = rfc821_reply( fd, 354, NULL );
    if( rc ) {
	rfc822_cancel( msg );
	return rc;
    }


    /* Fixme: Should we insert the return-path here? */
    insert_received( state, msg );
    for( ;; ) {
	line = rw_readline( fd, 500, &length, &truncated );
	if( !line ) {
	    log_error("fd %d: EOF while receiving data\n", fd );
	    rfc822_cancel( msg );
	    return rfc821_reply( fd, truncated? 421:554, NULL ); /* timeout:transaction failed */
	}
	if( truncated )
	    log_error("fd %d: rw_readline truncated line\n", fd );
	if( length && line[length-1] == '\r' )
	    line[--length] = 0;
	if( state->dbgsmtp > 1 )
	    log_debug("fd %d: got `%s' (%u bytes)\n", fd, line, length );
	if( length && *line == '.' ) {
	    if( length == 1 ) {
		if( state->dbgsmtp )
		    log_debug("fd %d: got `.' \n", fd );
		break;
	    }
	    line++;
	    length--;
	}
	if( rfc822_insert( msg, line, length ) ) {
	    rfc822_cancel( msg );
	    return rfc821_reply( fd, 554, NULL ); /* Transaction failed */
	}
    }

    if( do_callback( state, RFC821EVT_DATA_END ) ) {
	rfc822_cancel( msg );
	return rfc821_reply( fd, 554, NULL ); /* Transaction failed */
    }

    if( rfc822_finish( msg ) ) {
	rfc822_cancel( msg );
	return rfc821_reply( fd, 554, NULL ); /* Transaction failed */
    }

    rfc822_close( msg );
    return rfc821_reply( fd, 250, NULL );
}


/****************
 *
 */
static int
rfc821_proc_rset( RFC821 state, int fd, char *line )
{
    if( !state->helo_seen_done )
	return rfc821_reply( fd, 503, NULL );

    if( *line )
	return rfc821_reply( fd, 501, NULL );

    free(state->reverse_path); state->reverse_path = NULL;
    release_path_list(state->forward_path); state->forward_path = NULL;
    state->forward_path_head = &state->forward_path;

    return rfc821_reply( fd, 250, NULL );
}


RFC821
rfc821_open( int (*cb)( void *, enum rfc821_events, RFC821 ), void *cb_value )
{
    RFC821 state = calloc(1, sizeof *state );

    if( !state )
	return NULL;

    state->forward_path_head = &state->forward_path;
    state->cb = cb;
    state->cb_value = cb_value;
    state->verbose = defaults.verbose;
    state->dbgsmtp = defaults.dbgsmtp;
    return state;
}

void
rfc821_set_flag( RFC821 state, enum rfc821_flags flag, int value )
{
    if( !state ) {
	switch( flag ) {
	  case RFC821FLG_VERBOSE: defaults.verbose = value; break;
	  case RFC821FLG_DBGSMTP: defaults.dbgsmtp = value; break;
	}
    }
    else {
	switch( flag ) {
	  case RFC821FLG_VERBOSE: state->verbose = value; break;
	  case RFC821FLG_DBGSMTP: state->dbgsmtp = value; break;
	}
    }
}


void
rfc821_set_proto_comment( RFC821 state, const char *comment )
{
    state->proto_comment = comment;
}


void
rfc821_set_rfc822_cb( RFC821 state,
		      int (*cb)( void *, enum rfc822_events, RFC822 ),
						       void *cb_value )
{
    state->cb822 = cb;
    state->cb822_value = cb_value;
}

void
rfc821_close( RFC821 state )
{
    /* If we are a client, we have to close the connection  except when we
     * are inside the data transfer, where it is not possible and we assume
     * that this should cancel the transaction */
    if( state->session_type == 1 && !state->did_quit && !state->eof_seen
	&& !state->in_data  ) {
	if( !rw_writestr( state->fd, "QUIT\r\n" ) ) {
	    int reply;

	    state->did_quit = 1;
	    reply = get_response( state );
	    if( reply < 200 || reply > 299 )
		log_error("fd %d: SMTP QUIT failed (%d)\n", state->fd, reply);
	}
    }
    /* If we are a server we should do similar - due to timeout? */


    release_path_list( state->forward_path );
    free( state->reverse_path );
    free( state->helo_string );
    free( state->peer_addr_str );
    free( state );
}

void
rfc821_cancel( RFC821 state )
{
    rfc821_close(state);
}

/****************
 * This function handles an incoming SMTP session.
 */
int
rfc821_handler( RFC821 state, int fd, const char *peer_addr_str, int peer_port )
{
    int rc;
    char *line;
    size_t length;
    int truncated;
    enum smtp_cmds cmd = 0;

    if( !state->session_type )
	state->session_type = 2; /* server */
    else if( state->session_type != 2 )
	return RFC821ERR_CONFLICT;

    state->fd = fd;
    free(state->peer_addr_str);
    state->peer_addr_str = xstrdup(peer_addr_str);
    state->peer_port	 = peer_port;

    rw_timeout( fd, 5*60, 5*60 );
    rc = rfc821_reply( fd, 220, NULL ); /* greeting */
    while( !rc && cmd != smtpQUIT ) {
	rc = 0;
	line = rw_readline( fd, 500, &length, &truncated );
	if( !line ) {
	    if( truncated ) {
		log_error("fd %d: timeout\n", fd );
		/* in this case we should send a timeout reply */
		rfc821_reply( fd, 421, NULL );
	    }
	    else
		log_error("fd %d: read error\n", fd );
	    rc = -1;
	    break;
	}
	if( truncated )
	    log_error("fd %d: rw_readline truncated line\n", fd );
	if( length && line[length-1] == '\r' )
	    line[--length] = 0;
	if( state->dbgsmtp )
	    log_info("fd %d: got `%s' (%u bytes)\n", fd, line, length );
	cmd = rfc821_parse_cmd( &line, length );
	switch( cmd ) {
	  case smtpHELO:
	    rc = rfc821_proc_helo( state, fd, line );
	    break;

	  case smtpNOOP:
	    rc = rfc821_proc_noop( state, fd, line );
	    break;

	  case smtpMAIL:
	    rc = rfc821_proc_mail( state, fd, line );
	    break;

	  case smtpRCPT:
	    rc = rfc821_proc_rcpt( state, fd, line );
	    break;

	  case smtpDATA:
	    rc = rfc821_proc_data( state, fd, line );
	    break;

	  case smtpRSET:
	    rc = rfc821_proc_rset( state, fd, line );
	    break;

	  case smtpQUIT:
	    rc = rfc821_reply( fd, 221, NULL );
	    break;

	  case smtpNOTIMPL:
	    rc = rfc821_reply( fd, 502, NULL );
	    break;

	  default:
	    rc = rfc821_reply( fd, 500, NULL );
	    break;
	}
    }

    return rc;
}

/****************
 * This function is called by the rfc822 layer for certain events
 * This rfc822.c for a list of events.	This function should
 * return with 0 for normal success or with an errorcode to let
 * the rfc822 layer cancel it's processing.
 */
static int
cb_from_rfc822( void *opaque, enum rfc822_events event, RFC822 msg )
{
    RFC821 mystate = opaque;

    /* We don't have any need for it, so we pass it on to the
     * upper layer */
    if( mystate->cb822 )
	return mystate->cb822( mystate->cb822_value, event, msg );
    else
	return 0;
}


/****************
 * Get a resonse from an SMTP server. and return its response code.
 * A return value of -1 indicates a closed session and return codes > 999
 * indicate a protocol violation.
 * This function handles multiline replies and returns the last reply code
 * (We could check that all reply codes are the same but we don't to allow
 *  for non compliant clients)
 */
static int
get_response( RFC821 state )
{
    char *line;
    size_t length;
    int truncated;
    int code;

    do {
	line = rw_readline( state->fd, 1000, &length, &truncated );
	if( !line ) {
	    state->eof_seen = 1;
	    return -1; /* eof */
	}
	if( truncated ) {
	    log_error("fd %d: rw_readline truncated line\n", state->fd );
	    /* fixme: skip rest of line */
	}
	if( length && line[length-1] == '\r' )
	    line[--length] = 0;

	if( length < 3 || !isdigit(line[0])
		       || !isdigit(line[1])
		       || !isdigit(line[2]) )
	    return 1000;  /* impossible return code, use it for syntax error*/
	code = (line[0]-'0')*100 + (line[1]-'0')*10 + (line[2]-'0');
	if( code < 100 || code >= 600 )
	    return 1001;  /* not defined */

    } while( length > 3 && line[3]=='-' );
    if( code >=400 && code < 600 )
	log_info("fd %d: response: `%s'\n", state->fd, line );

    return code;
}

/****************
 * Start a new session by doing the HELO stuff
 * and negotiating options.
 */
int
rfc821_start_session( RFC821 state, int fd )
{
    int reply;

    if( !state->session_type )
	state->session_type = 1; /* client */
    else if( state->session_type != 1 )
	return RFC821ERR_CONFLICT;

    state->fd = fd;

    rw_timeout( fd, 5*60, 5*60 );

    if( !state->helo_seen_done ) {
	/* wait for the greeting */
	reply = get_response( state );
	if( reply != 220 ) {
	    if( reply == 421 )
		log_error("fd %d: smarthost closed channel\n", fd );
	    else
		log_error("fd %d: smarthost failed (%d)\n", fd, reply );
	    return RFC821ERR_NOSERVICE;
	}
    }

    /* For now we only support basic SMTP so we issue a HELO */
    if( rw_printf( fd, "HELO %s\r\n", get_my_name() ) )
	return RFC821ERR_SEND;
    reply = get_response( state );
    if( reply != 250 ) {
	log_error("fd %d: SMTP HELO failed (%d)\n", fd, reply );
	return RFC821ERR_GENERAL;
    }

    state->helo_seen_done = 1;
    return 0;
}



/****************
 * Set the reverse path.  The current implementation sends it immediately.
 */
int
rfc821_send_sender( RFC821 state, const char *path )
{
    char *p, *buf;
    int rc, reply;

    if( !state->helo_seen_done )
	return RFC821ERR_CMDSEQ;

    if( !path )
	path = "";

    if( check_path( path ) )
	return RFC821ERR_PATH;

    buf = xmalloc( strlen(path) + 20 );
    p = stpcpy( buf, "MAIL FROM:<" );
    if( *path == '<' ) {
	p = stpcpy( p, path+1 );
	*--p = 0;
    }
    else
	p = stpcpy( p, path );
    stpcpy( p, ">\r\n" );

    rw_timeout( state->fd, 5*60, -1 );
    rc = rw_writestr( state->fd, buf );
    free(buf);
    if( rc )
	return RFC821ERR_SEND;

    reply = get_response( state );
    if( reply != 250 ) {
	log_error("fd %d: SMTP MAIL failed (%d)\n", state->fd, reply );
	return RFC821ERR_GENERAL;
    }

    return 0;
}


/****************
 * Set a recipient.  The current implementation sends it immediately.
 */
int
rfc821_send_recipient( RFC821 state, const char *path )
{
    char *p, *buf;
    int rc, reply;

    if( !state->helo_seen_done )
	return RFC821ERR_CMDSEQ;

    if( !path || !*path || check_path( path ) )
	return RFC821ERR_PATH;

    buf = xmalloc( strlen(path) + 20 );
    p = stpcpy( buf, "RCPT TO:<" );
    if( *path == '<' ) {
	p = stpcpy( p, path+1 );
	*--p = 0;
    }
    else
	p = stpcpy( p, path );
    stpcpy( p, ">\r\n" );

    rw_timeout( state->fd, 5*60, -1 );
    rc = rw_writestr( state->fd, buf );
    free(buf);
    if( rc )
	return RFC821ERR_SEND;

    reply = get_response( state );
    if( reply != 250 ) {
	log_error("fd %d: SMTP RCPT failed (%d)\n", state->fd, reply );
	return RFC821ERR_GENERAL;
    }

    return 0;
}


/****************
 * Send a line of body and do the hideen dot protocol.
 * We make sure that the line has the correct ending.
 * Use a line of NULL to close the body and wait for the
 * response from the server.
 */
int
rfc821_send_body_line( RFC821 state, const char *line, size_t length )
{
    if( !state->helo_seen_done )
	return RFC821ERR_CMDSEQ;
    if( !state->in_data )
	return RFC821ERR_CMDSEQ;

    rw_timeout( state->fd, -1, 3*60 );
    if( line ) {
	if( length && line[length-1] == '\n' )
	    length--;
	if( length && line[length-1] == '\r' )
	    length--;

	if( length ) {
	    if( *line == '.' ) {
		if( rw_writen( state->fd, line, 1 ) )
		    return RFC821ERR_SEND;
	    }
	    if( rw_writen( state->fd, line, length ) )
		return RFC821ERR_SEND;

	}

	if( rw_writen( state->fd, "\r\n", 2 ) )
	    return RFC821ERR_SEND;
    }
    else if (state->in_data) {
        /* write the end of data dot and wait on response */
	int reply;

	rw_timeout( state->fd, 10*60, -1 );
	if( rw_writen( state->fd, ".\r\n", 3 ) )
	    return RFC821ERR_SEND;
	state->in_data = 0;
	reply = get_response( state );
	if( reply != 250 ) {
	    log_error("fd %d: SMTP DATA failed (%d)\n", state->fd, reply );
	    return RFC821ERR_GENERAL;
	}
    }

    return 0;
}


const char*
rfc821_query_sender( RFC821 state )
{
    return state->reverse_path;
}

/****************
 * Enumerate all recipients.  Caller has to provide the address of a pointer
 * which has to be initialzed to NULL, the caller should then never chnage this
 * pointer until he has closed the enumeration by passing again the address
 * of the pointer but with a state set to NULL.
 * The function returns pointers to all the recipients or NULL when
 * all recipients have been enumerated.
 */
const char*
rfc821_enum_recipients( RFC821 state, void **context )
{
    struct path_list *l;

    if( !state )  /*close*/
	return NULL; /* this is quite easy in our implementation */

    if( *context == state )
	return NULL;

    l = *context? (struct path_list*)*context : state->forward_path;

    if( l ) {
	*context = l->next? (void*)(l->next) : (void*)state;
	return l->d;
    }
    *context = state;  /* mark end of list */
    return NULL;
}


/****************
 * Copy all the header lines from MSG to the SMTP stream
 * NOTE: We use this special function so that we can do a
 *	 faster implmentation in the future.
 */
int
rfc821_copy_header_lines( RFC821 smtp, RFC822 msg )
{
    void *ectx;
    const char *line;
    int reply;

    rw_timeout( smtp->fd, 2*60, -1 );
    if( rw_writestr( smtp->fd, "DATA\r\n" ) )
	return RFC821ERR_SEND;

    reply = get_response( smtp );
    if( reply != 354 ) {
	log_error("fd %d: SMTP DATA failed (%d)\n", smtp->fd, reply );
	return RFC821ERR_GENERAL;
    }
    smtp->in_data = 1;

    rw_timeout( smtp->fd, 5*60, 3*60 );
    for( ectx=NULL; (line = rfc822_enum_header_lines( msg, &ectx)); ) {
	if( rw_printf( smtp->fd, "%s\r\n", line ) )                           {
	    rfc822_enum_header_lines( NULL, &ectx ); /* close enumerator */
	    return RFC821ERR_SEND;
	}
    }
    rfc822_enum_header_lines( NULL, &ectx ); /* close enumerator */

    /* and write the delimiter line */
    if( rw_writestr( smtp->fd, "\r\n" ) )
	return RFC821ERR_SEND;

    return 0;
}


/****************
 * Copy all the body lines from MSG to the SMTP stream
 * NOTE: We use this special function so that we can do a
 *	 faster implmentation in the future.
 *	 We really need a write buffer in rwbuf.c
 */
int
rfc821_copy_body_lines( RFC821 smtp, RFC822 msg )
{
    void *ectx;
    const char *line;
    size_t n;
    int rc = 0;

    for( ectx=NULL; (line = rfc822_enum_body_lines( msg, &ectx, &n)); ) {
	rc = rfc821_send_body_line( smtp, line, n );
	if( rc )
	    break;
    }
    rfc822_enum_body_lines( NULL, &ectx, NULL ); /* close enumerator */

    return rc;
}


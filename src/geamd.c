/* geamd.c  -  The GEAM daemon
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
#include <ctype.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pth.h>
#include <grp.h>  /* for initgroups() */

#include "geamd.h"
#include "argparse.h"
#include "smtpproxy.h"
#include "rfc821.h"
#include "nethelp.h"

#define DEFAULT_PORT 8025
#define GPG_PROGRAM "/usr/local/bin/gpg"


enum opt_values { aNull = 0,
    oVerbose	  = 'v',
    oQuiet	  = 'q',
    oOptions	  = 'C',
    oPort	  = 500,
    oNoFork,
    oInnerhostName,
    oInnerhostPort,
    oOuterhostName,
    oOuterhostPort,
    oReceivedHeadersMax,
    oAliasFile,
    oEncryptFile,
    oDecryptFile,
    oGPGBinary,
    oGPGHomedir,
    oLogFile,
    oUserName,
    oGroupName,
    oInnerNet,

    oDebug
};

static ARGPARSE_OPTS opts[] = {
    { 301, NULL, 0, N_("@\nOptions:\n ") },
    { oVerbose, "verbose",   0, N_("verbose") },
    { oQuiet,	"quiet",     0, N_("be more quiet")},
    { oDebug,	"debug",     4|16, N_("set debugging flags")},
    { oNoFork,	"no-fork",   0, N_("do not run as a daemon")},
    { oOptions, "config",    2, N_("|FILE|read options from FILE")},
    { oPort,	"port",      1, N_("|N|listen on port N")},
    { oInnerhostName, "inner-host-name", 2, "@" },
    { oInnerhostPort, "inner-host-port", 1, "@" },
    { oOuterhostName, "outer-host-name", 2, "@" },
    { oOuterhostPort, "outer-host-port", 1, "@" },
    { oInnerNet, "inner-net", 2, "@" },
    { oReceivedHeadersMax, "received-headers-max", 1, "@" },
    { oAliasFile,  "alias-file", 2 , "|FILE|read aliases from FILE" },
    { oEncryptFile,"encrypt-file", 2 , "|FILE|read encrypt info from FILE" },
    { oDecryptFile,"decrypt-file", 2 , "|FILE|read decrypt info from FILE" },
    { oGPGBinary, "gpg-program", 2 , "@" },
    { oGPGHomedir,"gpg-homedir", 2 , "@" },
    { oLogFile,   "log-file", 2, "@" },
    { oUserName,  "user", 2, "@" },
    { oGroupName,  "group", 2, "@" },
{0} };


struct start_args {
    int fd;
    struct sockaddr peer_addr;
    int peer_port;
    char peer_addr_str[1];
};

static void *start_proxy_handler( void *arg );
static void  handlesignals( int signo );
static void  become_daemon(void);
static int   start_listening( int port );
static void  change_userid( const char *username, const char *groupname );


static const char *
my_strusage( int level )
{
    const char *p;
    switch( level ) {
      case 11: p = "geamd";
	break;
      case 13: p = VERSION; break;
      case 14: p = "Copyright (C) 2000 Werner Koch Softwaresysteme"; break;
      case 19: p = _("Please report bugs to <bug-geam@gnupg.de>.\n");
	break;
      case 1:
      case 40:	p =
	    _("Usage: geamd [options] (-h for help)");
	break;
      case 41:	p =
	    _("Syntax: geamd [options]\n"
	      "run the SMTP encryption proxy\n");
	break;

      default:	p = NULL;
    }
    return p;
}

static void
add_inner_net( const char *s )
{
    NETWORK_ADDRESS a;

    a = parse_network_address( s );
    if( !a ) {
	log_error(_("invalid network address '%s'\n"), s);
	exit(2);
    }
    if( !opt.inner_nets ) {
	opt.inner_nets = a;
    }
    else {
	append_network_address( opt.inner_nets, a );
    }
}

int
main( int argc, char **argv )
{
    ARGPARSE_ARGS pargs;
    int orig_argc;
    char **orig_argv;
    FILE *configfp = NULL;
    char *configname;
    unsigned int configlineno;
    int nofork = 0;
    int port = DEFAULT_PORT;
    pth_attr_t tattr;
    pth_event_t ev;
    int listen_fd;
    char *innerhost_name = NULL;
    int innerhost_port = 0;
    char *outerhost_name = NULL;
    int outerhost_port = 0;
    sigset_t sigs;
    int signo;
    const char *logfile;
    const char *username;
    const char *groupname;

    set_strusage( my_strusage );
    /*log_set_name("gaemd"); */
    srand48( time(NULL) );

    /* setup defaults */
    configname = xstrdup( "/etc/geam/geamd.conf" );
    opt.alias_file = "aliases";
    opt.encrypt_file = "encrypt";
    opt.decrypt_file = "decrypt";
    opt.received_headers_max = 30;
    opt.gpg_binary = GPG_PROGRAM;
    opt.gpg_homedir = "/etc/geam/gpg";
    logfile = "/var/log/geam/geamd";
    username = "mail";
    groupname = "mail";

    opt.debug = 0;

    /* check whether we have a config file on the commandline */
    orig_argc = argc;
    orig_argv = argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags= 1|(1<<6);  /* do not remove the args, ignore version */
    while( arg_parse( &pargs, opts) ) {
	if( pargs.r_opt == oOptions )
	    configname = pargs.r.ret_str;
    }

    argc = orig_argc;
    argv = orig_argv;
    pargs.argc = &argc;
    pargs.argv = &argv;
    pargs.flags=  1;  /* do not remove the args */
  next_pass:
    if( configfp ) {
	fclose( configfp );
	configfp = NULL;
    }
    else if( configname ) {
	configlineno = 0;
	configfp = fopen( configname, "r" );
	if( !configfp ) {
	    log_error(_("can't open configuration file `%s': %s\n"),
				    configname, strerror(errno) );
	    configname = NULL;
	}
    }

    while( optfile_parse( configfp, configname, &configlineno, &pargs, opts) ) {
	switch( pargs.r_opt ) {
	  case oQuiet: opt.quiet = 1; break;
	  case oVerbose: opt.verbose++; break;
	  case oDebug: opt.debug |= pargs.r.ret_ulong; break;
	  case oNoFork: nofork = 1; break;
	  case oPort: port = pargs.r.ret_int; break;
	  case oInnerhostName:
	    free(innerhost_name);
	    innerhost_name = xstrdup(pargs.r.ret_str);
	    break;
	  case oInnerhostPort: innerhost_port = pargs.r.ret_int; break;
	  case oOuterhostName:
	    free(outerhost_name);
	    outerhost_name = xstrdup(pargs.r.ret_str);
	    break;
	  case oOuterhostPort: outerhost_port = pargs.r.ret_int; break;

	  case oInnerNet:
	    add_inner_net( pargs.r.ret_str );
	    break;

	  case oReceivedHeadersMax:
	    opt.received_headers_max = pargs.r.ret_int;
	    break;

	  case oAliasFile: opt.alias_file = pargs.r.ret_str;  break;
	  case oEncryptFile: opt.encrypt_file = pargs.r.ret_str;  break;
	  case oDecryptFile: opt.decrypt_file = pargs.r.ret_str;  break;

	  case oGPGBinary: opt.gpg_binary = pargs.r.ret_str;  break;
	  case oGPGHomedir: opt.gpg_homedir = pargs.r.ret_str;	break;
	  case oLogFile: logfile = pargs.r.ret_str; break;
	  case oUserName: username = pargs.r.ret_str; break;
	  case oGroupName: groupname = pargs.r.ret_str; break;

	  case oOptions:  break; /* already processed */
	  default : pargs.err = configfp? 1:2; break;
	}
    }
    if ( configfp )
	goto next_pass;

    if( configname && *configname == '/' )  {
	/* The options file has an absolute path. We modify the other
	 * configuration files, so that they are in the same directory
	 * - but only when they have a relative path too */
	size_t dirlen = strrchr( configname, '/' ) - configname;

	if( *opt.alias_file != '/' ) {
	    char *p = xmalloc( dirlen + strlen(opt.alias_file) + 2 );
	    memcpy(p, configname, dirlen );
	    strcpy(stpcpy(p+dirlen,"/"),opt.alias_file);
	    opt.alias_file = p;
	}
	if( *opt.encrypt_file != '/' ) {
	    char *p = xmalloc( dirlen + strlen(opt.encrypt_file) + 2 );
	    memcpy(p, configname, dirlen );
	    strcpy(stpcpy(p+dirlen,"/"),opt.encrypt_file);
	    opt.encrypt_file = p;
	}
	if( *opt.decrypt_file != '/' ) {
	    char *p = xmalloc( dirlen + strlen(opt.decrypt_file) + 2 );
	    memcpy(p, configname, dirlen );
	    strcpy(stpcpy(p+dirlen,"/"),opt.decrypt_file);
	    opt.decrypt_file = p;
	}
	if( *opt.gpg_homedir != '/' ) {
	    char *p = xmalloc( dirlen + strlen(opt.gpg_homedir) + 2 );
	    memcpy(p, configname, dirlen );
	    strcpy(stpcpy(p+dirlen,"/"),opt.gpg_homedir);
	    opt.gpg_homedir = p;
	}

    }
    else if( configname ) {
	/* Because we chdir to /, we do not alow a relative name
	 * for the configuration name.	This file name is used to deduce
	 * the base for the other relative filenames - we better put out
	 * a wrning in this case */
	log_info("no absolute path name given for configuration file\n");
    }


    log_set_file( logfile );
    if( DBG_SMTP )
	rfc821_set_flag( NULL, RFC821FLG_DBGSMTP, 1 );

    if( !nofork )
	become_daemon();

    log_info( "%s %s started (pid=%u)\n", strusage(11), strusage(13),
						(unsigned int)getpid() );
    if( smtpproxy_set_smarthost( innerhost_name, innerhost_port,
				 outerhost_name, outerhost_port ) ) {
	log_error("invalid smarthost\n");
	exit(1);
    }

    if( smtpproxy_read_configs() ) {
	log_error("failed to read the configuration information\n");
	exit(1);
    }

    if( !pth_init() )
	log_fatal("failed to initialize the Pth library\n");
    signal( SIGPIPE, SIG_IGN );

    listen_fd = start_listening( port );
    if( listen_fd == -1 )
	return 1;

    change_userid( username, groupname );

    tattr = pth_attr_new();
    pth_attr_set( tattr, PTH_ATTR_JOINABLE,  0 );
    pth_attr_set( tattr, PTH_ATTR_STACK_SIZE, 32*1024);
    pth_attr_set( tattr, PTH_ATTR_NAME, "smtpproxy");

    sigemptyset( &sigs );
    sigaddset( &sigs, SIGHUP );
    sigaddset( &sigs, SIGUSR1 );
    sigaddset( &sigs, SIGUSR2 );
    sigaddset( &sigs, SIGINT  );
    sigaddset( &sigs, SIGTERM );
    ev = pth_event(PTH_EVENT_SIGS, &sigs, &signo );
    for(;;) {
	struct start_args *sarg;
	char *p;
	struct sockaddr_in paddr;
	socklen_t plen = sizeof( paddr );
	int fd;

	if( opt.shutdown_pending ) {
	    if( pth_ctrl( PTH_CTRL_GETTHREADS ) == 1 )
		break;

	    /* Do not accept anymore connections and wait for the threads
	     * to terminate */
	    signo = 0;
	    pth_wait(ev);
	    if( pth_event_occurred( ev ) && signo ) {
		handlesignals( signo );
	    }

	    continue;
	}

	fd = pth_accept_ev( listen_fd, (struct sockaddr *)&paddr, &plen, ev);
	if( fd == -1 ) {
	    if( pth_event_occurred( ev ) ) {
		handlesignals( signo );
		continue;
	    }
	    log_error( "accept failed: %s - waiting 1s\n", strerror(errno) );
	    pth_sleep(1);
	    continue;
	}

	p = inet_ntoa(paddr.sin_addr);
	sarg = xmalloc( sizeof *sarg + strlen(p) );
	sarg->fd = fd;
	sarg->peer_port = (int)ntohs(paddr.sin_port);
	memcpy( &sarg->peer_addr, (struct sockaddr *)&paddr, sizeof( paddr ) );
	strcpy( sarg->peer_addr_str, p );

	if( !pth_spawn( tattr, start_proxy_handler, sarg ) ) {
	    log_error( "error spawning connection handler: %s\n",
						   strerror(errno) );
	    close(fd);
	}
    }

    pth_event_free(ev, PTH_FREE_ALL);
    log_info( "%s %s stopped\n", strusage(11), strusage(13) );


    return 0;
}


static char *
encode36( char *buf, unsigned long value, int minlen )
{
    char *p, *p0;
    int n;

    p = buf;
    do {
	n = value % 36;
	if( n < 10 )
	    *p++ = n + '0';
	else
	    *p++ = (n-10)+'a';

    } while( (value /= 36 ) );
    *p = 0;
    for( p0=buf, p--; p0 < p; ) {
	char c = *p0;
	*p0++ = *p;
	*p-- = c;
    }
    n = strlen(buf);

    if( n < minlen ) {
	memmove(buf+(minlen-n), buf, n+1);
	memset(buf, '0', (minlen-n));
    }

    return buf;
}





static void *
start_proxy_handler( void *arg )
{
    void *rv;
    struct start_args *a = arg;
    char sessid[30], pbuf[10], tbuf[10], cbuf[10];
    static int counter;

    encode36(pbuf, getpid(), 4);
    encode36(tbuf, time(NULL), 6);
    encode36(cbuf, counter, 3 );
    if( ++counter >= (36*36*36) )
	counter = 0;
    /* we make sure that the session ID will always start with a digit
     * even if the sessio  ID gets larger by prefixing the 0 */
    snprintf( sessid, sizeof sessid, "%s%s-%s-%s",
			isdigit(*pbuf)?"":"0",
			pbuf, tbuf, cbuf );

    log_info( "%s connect from %s:%d (fd=%d)\n", sessid,
	      a->peer_addr_str, a->peer_port, a->fd );

    rv = smtpproxy_handler( a->fd, sessid, &a->peer_addr,
					   a->peer_addr_str,
					   a->peer_port );
    log_info( "%s ready\n", sessid );
    free( a );

    return rv;
}

static void
handlesignals( int signo )
{
    switch( signo )
    {
      case SIGHUP:
	log_info("SIGHUP received - re-reading configuration\n");
	smtpproxy_read_configs();
	break;

      case SIGUSR1:
	if( opt.verbose < 5 )
	    opt.verbose++;
	if( opt.verbose == 3 )
	    rfc821_set_flag( NULL, RFC821FLG_DBGSMTP, 1 );
	log_info("SIGUSR1 received - verbosity set to %d\n", opt.verbose );
	break;

      case SIGUSR2:
	if( opt.verbose == 3 )
	    rfc821_set_flag( NULL, RFC821FLG_DBGSMTP, 0 );
	if( opt.verbose  )
	    opt.verbose--;
	log_info("SIGUSR1 received - verbosity set to %d\n", opt.verbose );
	break;

      case SIGTERM:
	if( !opt.shutdown_pending )
	    log_info("SIGTERM received - shutting down ...\n" );
	else
	    log_info("SIGTERM received - still %ld running threads\n",
					  pth_ctrl( PTH_CTRL_GETTHREADS ) );
	opt.shutdown_pending++;
	if( opt.shutdown_pending > 2 ) {
	    log_info("shutdown forced\n" );
	    log_info("%s %s stopped\n", strusage(11), strusage(13) );
	    exit(0);
	}
	break;

      case SIGINT:
	log_info( "SIGINT received - immediate shutdown\n" );
	log_info( "%s %s stopped\n", strusage(11), strusage(13) );
	exit(0);
	break;

      default:
	log_info("signal %d received - no action defined\n", signo);
    }
}



static void
become_daemon()
{
    long nfile;
    int i, n;
    int childpid;

    if( opt.verbose )
	log_info("becoming a daemon ...\n");
    fflush(NULL);

    /* FIXME: handle the TTY signals */

    if( (childpid = fork()) == -1 )
	log_fatal("can't fork first child: %s\n", strerror(errno));
    else if( childpid > 0 )
	exit(0); /* terminate parent */

    /* Disassociate from controlling terminal etc. */
    if( setsid() == -1 )
	log_fatal("setsid() failed: %s\n", strerror(errno) );

    /* close all files but not the log files */
    if( (nfile=sysconf( _SC_OPEN_MAX )) < 0 ) {
      #ifdef _POSIX_OPEN_MAX
	nfile = _POSIX_OPEN_MAX;
      #else
	nfile = 20; /* assume a reasonable value */
      #endif
    }
    n = log_get_fd();
    for(i=0; i < nfile; i++ )
	if( i != n )
	    close(i);
    errno = 0;

    if( chdir("/") )
	log_fatal("chdir to root failed: %s\n", strerror(errno) );
    umask(0);

    if( opt.verbose )
	log_info("now running as daemon\n");
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
	log_error("getprotobyname failed: %s\n", strerror(errno) );
	return -1;
    }

    fd = socket( AF_INET, SOCK_STREAM, pe->p_proto );
    if( fd < 0 ) {
	log_error("error creating socket: %s\n", strerror(errno) );
	return -1;
    }
    if( setsockopt( fd, SOL_SOCKET, SO_REUSEADDR,
				    (const void *)&one, sizeof one) ) {
	log_error("error setting SO_REUSEADDR: %s\n", strerror(errno) );
	close(fd);
	return -1;
    }

    memset( &addr, 0, sizeof addr );
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl( INADDR_ANY );
    addr.sin_port = htons(port);
    if( bind( fd, (struct sockaddr*)&addr, sizeof addr ) ) {
	log_error("error binding port %d: %s\n", port, strerror(errno) );
	close(fd);
	return -1;
    }

    if( listen( fd, 5 ) ) {
	log_error("error listening on port %d: %s\n", port, strerror(errno) );
	close(fd);
	return -1;
    }

    return fd;
}

static void
change_userid( const char *username, const char *groupname )
{
    uid_t uid;
    struct passwd *pw;
    gid_t gid;
    struct group *gr;

    if( geteuid() ) {
	log_info("note: user ID not changed\n");
	return;
    }

    pw = getpwnam( username );
    if( !pw ) {
	log_error("change user to `%s' failed: no such user\n", groupname );
	exit(1);
    }
    uid = pw->pw_uid;
    gr = getgrnam( groupname );
    if( !gr ) {
	log_error("change group to `%s' failed: no such group\n", groupname );
	exit(1);
    }
    gid = gr->gr_gid;

    if( setgid( gid ) ) {
	log_error("change group to `%s' failed: %m\n", groupname );
	exit(1);
    }

    if( initgroups( username, gid ) ) {
	log_error("initgroups for `%s' failed: %m\n", username );
	exit(1);
    }

    if( setuid( uid ) ) {
	log_error("change user to `%s' failed: %m\n", username );
	exit(1);
    }
    log_info("running as %s:%s (%u:%u)\n", username,groupname,
			(unsigned int)uid, (unsigned int)gid );

}



/* smtpproxy.c
 *	Copyright (C) 1999, 2000 Werner Koch, Duesseldorf
 *      Copyright (C) 2004 g10 Code GmbH
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


/* Notes:
 * We are mixing some things up here.  A better design would put
 * the MIME stuff into rfc822 and provide a mime abstraction layer.
 * Due to the current time contstraints, I can't do this now and
 * hack the code here.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pth.h>


#include "geamd.h"
#include "smtpproxy.h"
#include "rfc821.h"
#include "rfc822.h"

/* Maximum number of connections we can handle concurrently.  This
   must be far less than the number of filedescriptors rwbuf.c can
   handle.  200 seems to be a reasonable high value for common
   machines. */
#define MAX_CONNECTIONS 200


static int connection_counter;

struct encrypt_item;
struct decrypt_item;

enum action_modes {
    aPASSTHRU,
    aBOUNCE,
    aENCRYPT,
    aCHECK_DECRYPT,
    aDECRYPT
};

struct proxy_state {
    const char *sid;
    int fd;
    struct sockaddr *peer_addr;
    RFC821 smtphd;
    int fail_data;
    int fail_data_temp;
    int fwd_fd;  /* fd of the smarthost connection */
    RFC821 fwd_smtphd;
    int rcvd_hdr_count;
    char *boundary; /* top level boundary */
    enum action_modes action;
    int saved_lines_size;
    char **saved_lines;
    struct encrypt_item *rcpt_keys;
    char *fallback_recp;
    pid_t command_pid;
    struct {
	RFC822 msg;
	int fd;
	int error;
    } filter_feed;
    struct {
	RFC822 msg;
	int fd;
        int error; /* Error code as returned by rfc821. */
	int in_header;
    } filter_eat;
};
typedef struct proxy_state *PROXY_STATE;


struct smarthost {
    int proto;
    struct sockaddr_in addr;
    char *name;
    int port;
};

static struct {
    struct smarthost inbound;
    struct smarthost outbound;
} smarthost;

struct encrypt_item {
    struct encrypt_item *next;
    char fpr[41];  /* or the key ID */
    char key[1];
};

struct decrypt_item {
    struct decrypt_item *next;
    char keyid[17];
    char key[1];
};

#define ENCRYPT_BUCKETS 997
static struct encrypt_item **encrypt_table;
static __inline__ unsigned int
hash_encrypt( const char *s )
{
    unsigned long h = 0, cy;
    for( ; *s ; s++ ) {
	h = (h << 4) + *s;
	if( (cy = (h & 0xf0000000)) ) {
	    h ^= (cy >> 24);
	    h ^= cy;
	}
    }
    return h % ENCRYPT_BUCKETS;
}

#define DECRYPT_BUCKETS 997
static struct decrypt_item **decrypt_table;
static __inline__ unsigned int
hash_decrypt( const char *s )
{
    unsigned long h = 0, cy;
    for( ; *s ; s++ ) {
	h = (h << 4) + *s;
	if( (cy = (h & 0xf0000000)) ) {
	    h ^= (cy >> 24);
	    h ^= cy;
	}
    }
    return h % DECRYPT_BUCKETS;
}

struct alias_item {
    struct alias_item *next;
    struct encrypt_item *ei;
    char isdom;
    int allow_decrypt;
    char name[1];
};

#define ALIAS_BUCKETS 997
static struct alias_item **alias_table;
static __inline__ unsigned int
hash_alias( const char *s )
{
    unsigned long h = 0, cy;
    for( ; *s ; s++ ) {
	h = (h << 4) + *s;
	if( (cy = (h & 0xf0000000)) ) {
	    h ^= (cy >> 24);
	    h ^= cy;
	}
    }
    return h % ALIAS_BUCKETS;
}



static int cb_from_rfc821( void *opaque, enum rfc821_events event, RFC821 );
static int cb_from_rfc822( void *opaque, enum rfc822_events event, RFC822 );
static int run_command( PROXY_STATE proxy, RFC822 msg,
	     const char *command,
	     char *const *argv,
	     char *const *envp,
	     void (*callback)( PROXY_STATE, RFC822, int, int, int ) );

static char *
my_strsep( char **point, const char *delim )
{
    char *token = strsep( point, delim );
    *point += strspn( *point, delim );
    return token;
}

static void
release_encrypt_table( struct encrypt_item **tbl )
{
    int i;

    if( !tbl )
	return;
    for(i=0; i < ENCRYPT_BUCKETS; i++ ) {
	while( tbl[i] ) {
	    struct encrypt_item *tmp = tbl[i]->next;
	    free(tbl[i]);
	    tbl[i] = tmp;
	}
    }
    free( tbl );
}


static struct encrypt_item **
read_encrypt_table(void)
{
    struct encrypt_item **tbl, *item;
    const char *fname = opt.encrypt_file;
    FILE *fp;
    char line[256], *p;
    int lnr;
    const char *err = NULL;
    size_t n;

    fp = fopen( fname, "r" );
    if( !fp ) {
	log_error("can't open `%s': %m\n", fname );
	return NULL;
    }

    tbl = xcalloc( ENCRYPT_BUCKETS, sizeof *tbl );

    lnr = 0;
    while( fgets( line, DIM(line)-1, fp ) ) {
	char *key, *mthd, *fpr;
	int h;

	lnr++;
	if( *line && line[strlen(line)-1] != '\n' ) {
	    err = "line too long";
	    break;
	}
	for( p = line; isspace(*p); p++ )
	    ;
	if( !*p || *p == '#' )
	    continue;
	key = my_strsep( &p, " \t\r\v\n" );
	if( !key ) {
	    err = "syntax error (no key)";
	    break;
	}
	mthd = my_strsep( &p, " \t\r\v\n" );
	if( !mthd ) {
	    err = "syntax error (no method)";
	    break;
	}
	fpr = my_strsep( &p, " \t\r\v\n" );
	if( !fpr ) {
	    err = "syntax error (no key info)";
	    break;
	}
	if( *p ) {
	    err = "syntax error (trailing garbage)";
	    break;
	}
	if( stricmp( mthd, "gpg" ) && stricmp( mthd, "gpg" )
				   && stricmp( mthd, "openpgp" ) ) {
	    err = "invalid method"; /* we do only support OpenPGP for now */
	    break;
	}
	if( (n=strlen(fpr)) > DIM(item->fpr)-1
	    || (n!=32 && n!=40 && n != 16 && n !=8 ) ) {
	    err = "invalid size of the key/IDfingerprint";
	    break;
	}
	item = xmalloc( sizeof *item + strlen( key ) );
	h = hash_encrypt( key );
	item->next = tbl[h];
	strcpy(item->fpr, fpr);
	strcpy(item->key, key);
	tbl[h] = item;
    }
    if( err )
	log_error("%s:%d: %s\n", fname, lnr, err );
    else if( ferror(fp) ) {
	err = "";
	log_error("%s:%d: read error: %m\n", fname, lnr );
    }
    fclose(fp);

    if( err ) {
	release_encrypt_table( tbl );
	tbl = NULL;
    }
    return tbl;
}

static void
release_decrypt_table( struct decrypt_item **tbl )
{
    int i;

    if( !tbl )
	return;
    for(i=0; i < DECRYPT_BUCKETS; i++ ) {
	while( tbl[i] ) {
	    struct decrypt_item *tmp = tbl[i]->next;
	    free(tbl[i]);
	    tbl[i] = tmp;
	}
    }
    free( tbl );
}


static struct decrypt_item **
read_decrypt_table(void)
{
    struct decrypt_item **tbl, *item;
    const char *fname = opt.decrypt_file;
    FILE *fp;
    char line[256], *p;
    int lnr;
    const char *err = NULL;
    size_t n;

    fp = fopen( fname, "r" );
    if( !fp ) {
	log_error("can't open `%s': %m\n", fname );
	return NULL;
    }

    tbl = xcalloc( DECRYPT_BUCKETS, sizeof *tbl );

    lnr = 0;
    while( fgets( line, DIM(line)-1, fp ) ) {
	char *key, *mthd, *keyid;
	int h;

	lnr++;
	if( *line && line[strlen(line)-1] != '\n' ) {
	    err = "line too long";
	    break;
	}
	for( p = line; isspace(*p); p++ )
	    ;
	if( !*p || *p == '#' )
	    continue;
	key = my_strsep( &p, " \t\r\v\n" );
	if( !key ) {
	    err = "syntax error (no key)";
	    break;
	}
	mthd = my_strsep( &p, " \t\r\v\n" );
	if( !mthd ) {
	    err = "syntax error (no method)";
	    break;
	}
	keyid = my_strsep( &p, " \t\r\v\n" );
	if( !keyid ) {
	    err = "syntax error (no key ID)";
	    break;
	}
	if( *p ) {
	    err = "syntax error (trailing garbage)";
	    break;
	}
	if( stricmp( mthd, "gpg" ) && stricmp( mthd, "gpg" )
				   && stricmp( mthd, "openpgp" ) ) {
	    err = "invalid method"; /* we do only support OpenPGP for now */
	    break;
	}
	if( (n=strlen(keyid)) > DIM(item->keyid)-1 || n!=16 ) {
	    err = "invalid size of the key ID";
	    break;
	}
	item = xmalloc( sizeof *item + strlen( key ) );
	h = hash_decrypt( keyid );
	item->next = tbl[h];
	strcpy(item->keyid, keyid);
	strcpy(item->key, key);
	tbl[h] = item;
    }
    if( err )
	log_error("%s:%d: %s\n", fname, lnr, err );
    else if( ferror(fp) ) {
	err = "";
	log_error("%s:%d: read error: %m\n", fname, lnr );
    }
    fclose(fp);

    if( err ) {
	release_decrypt_table( tbl );
	tbl = NULL;
    }
    return tbl;
}


static void
release_alias_table( struct alias_item **tbl )
{
    int i;

    if( !tbl )
	return;
    for(i=0; i < ALIAS_BUCKETS; i++ ) {
	while( tbl[i] ) {
	    struct alias_item *tmp = tbl[i]->next;
	    free(tbl[i]);
	    tbl[i] = tmp;
	}
    }
    free( tbl );
}


static struct alias_item **
read_alias_table( struct encrypt_item **etbl )
{
    struct alias_item **tbl, *item;
    const char *fname = opt.alias_file;
    FILE *fp;
    char line[256], *p;
    int lnr;
    const char *err = NULL;
    int errcount = 0;

    fp = fopen( fname, "r" );
    if( !fp ) {
	log_error("can't open `%s': %m\n", fname );
	return NULL;
    }

    tbl = xcalloc( ALIAS_BUCKETS, sizeof *tbl );

    lnr = 0;
    while( fgets( line, DIM(line)-1, fp ) ) {
	char *lside, *rside;
	int h;

	lnr++;
	if( *line && line[strlen(line)-1] != '\n' ) {
	    err = "line too long";
	    break;
	}
	for( p = line; isspace(*p); p++ )
	    ;
	if( !*p || *p == '#' )
	    continue;
	rside = strchr( p, ':' );
	if( !rside ) {
	    err = "syntax error (colon missing)";
	    break;
	}
	*rside++ = 0;
	lside = p;
	trim_spaces(lside);
	if( !*lside ) {
	    err = "syntax error (empty left side)";
	    break;
	}
	if( strcspn( lside, " \t\r\v\n" ) != strlen(lside) ) {
	    err = "syntax error (invalid left side)";
	    break;
	}
	trim_spaces( rside );
	if( !*rside )
	    rside = NULL;
	else {
	    if( strcspn( rside, " \t\r\v\n" ) != strlen(rside) ) {
		err = "syntax error (trailing garbage)";
		break;
	    }
	}

	item = xmalloc( sizeof *item + strlen( lside ) );
	h = hash_alias( lside );
	item->next = tbl[h];
	strcpy(item->name, lside );
	item->ei = NULL;
	item->allow_decrypt = 0;
	item->isdom = !strchr( lside, '@' );
	tbl[h] = item;
	if( rside && !stricmp( rside, "DECRYPT" ) )
	    item->allow_decrypt = 1;
	else if( rside ) {
	    /* link it to the encrypt table */
	    struct encrypt_item *ei;
	    for( ei=etbl[hash_encrypt(rside)]; ei; ei = ei->next ) {
		if( !stricmp( ei->key, rside) )
		    break;
	    }
	    if( ei )
		item->ei = ei;
	    else {
		log_error("%s:%d: '%s' not found in encrypt table\n",
				fname, lnr, rside );
		errcount++;
	    }
	}
    }
    if( errcount )
	err="";
    else if( err )
	log_error("%s:%d: %s\n", fname, lnr, err );
    else if( ferror(fp) ) {
	err = "";
	log_error("%s:%d: read error: %m\n", fname, lnr );
    }
    fclose(fp);

    if( err ) {
	release_alias_table( tbl );
	tbl = NULL;
    }
    return tbl;
}


int
smtpproxy_read_configs()
{
    struct encrypt_item **et;
    struct decrypt_item **dt;
    struct alias_item **at;

    et = read_encrypt_table();
    if( !et ) {
	return -1;
    }
    at = read_alias_table( et );
    if( !at ) {
	release_encrypt_table( et );
	return -1;
    }
    dt = read_decrypt_table();
    if( !dt ) {
	release_alias_table( at );
	release_encrypt_table( et );
	return -1;
    }

    release_encrypt_table( encrypt_table );
    encrypt_table = et;
    release_alias_table( alias_table );
    alias_table = at;
    release_decrypt_table( decrypt_table );
    decrypt_table = dt;

    return 0;
}


/****************
 * NOTE: Make sure the main function has done an srand48() !
 */
void *
smtpproxy_handler( int fd, const char *sessid, struct sockaddr *peer_addr,
			   const char *peer_addr_str, int peer_port )
{
    PROXY_STATE state = xcalloc( 1, sizeof *state );
    int i;

    connection_counter++;

    state->sid = sessid;
    state->fd = fd;
    state->fwd_fd = -1;
    state->peer_addr = peer_addr;

    if( rw_init( fd ) ) {
	log_error("fd %d: rw_init failed\n", fd );
	goto leave;
    }

    if (connection_counter > MAX_CONNECTIONS)
      {
        /* We are under a high load; don't even send a HELLO. */
	log_error("%s too many connections - sending 421\n", state->sid );
        rfc821_reply (fd, 421, NULL);
        goto leave;
      }

    state->smtphd = rfc821_open( cb_from_rfc821, state );
    if( !state->smtphd ) {
	log_error("%s rfc821_open failed\n", state->sid );
	goto leave;
    }
    rfc821_set_rfc822_cb( state->smtphd, cb_from_rfc822, state );
    if( rfc821_handler( state->smtphd, fd, peer_addr_str, peer_port ) )
	log_error("%s processing failed\n", state->sid );
    rfc821_close( state->smtphd );

  leave:
    if( state && state->fwd_smtphd )
	rfc821_close( state->fwd_smtphd );
    if( state && state->fwd_fd != -1 ) {
	close(state->fwd_fd );
    }
    free( state->boundary );
    if( state->saved_lines ) {
	for(i=0; state->saved_lines[i]; i++ )
	    free( state->saved_lines[i] );
    }
    {
	struct encrypt_item *r, *r2;

	for(r = state->rcpt_keys; r; r = r2 ) {
	    r2 = r->next;
	    free( r );
	}
    }
    free( state->fallback_recp );
    free( state );
    close( fd );
    connection_counter--;
    return NULL;
}


static const struct alias_item *
query_aliases( const char *name, int decrypt )
{
    struct alias_item *ai;

    /* first see whether we have a complete address */
    for( ai=alias_table[hash_alias(name)]; ai; ai = ai->next ) {
	if( !ai->allow_decrypt == !decrypt
	    && !ai->isdom && !stricmp( ai->name, name) )
	    break;
    }
    if( !ai ) { /* No: find by domain */
	char *dom = strchr(name, '@' );
	if( dom && dom[1] ) {
	    dom++;
	    for( ai=alias_table[hash_alias(dom)]; ai; ai = ai->next ) {
		if( !ai->allow_decrypt == !decrypt
		    && ai->isdom && !stricmp( ai->name, dom) )
		    break;
	    }
	}
    }
    return ai;
}

/****************
 * check whether this message should be encrypted.  This is done by
 * looking on all the recipients. At this point we have already read
 * the message headers.
 * Returns: 1 = Yes, do encrypt the message
 * Note: This also sets the proxy action to PASSTRHU or BOUNCE
 *	 when it returns 0.
 */
static int
encryption_needed( PROXY_STATE proxy, RFC822 msg )
{
    void *ectx;
    const char *recp;

    if( DBG_VERBOSE )
	log_debug("checking whether this message needs encryption ...\n");

    for( ectx=NULL; (recp = rfc821_enum_recipients( proxy->smtphd, &ectx)); ) {
	const struct alias_item *ai = query_aliases( recp, 0 );
	if( ai && ai->ei ) {
	    struct encrypt_item *newi;
	    log_info("%s => `%s' - encrypt\n", proxy->sid, recp );
	    newi = xmalloc( sizeof *newi + strlen(ai->ei->key) );
	    strcpy(newi->fpr, ai->ei->fpr );
	    strcpy(newi->key, ai->ei->key );
	    newi->next = proxy->rcpt_keys;
	    proxy->rcpt_keys = newi;
	}
	else if( ai )
	    log_info("%s => `%s' - do not encrypt\n", proxy->sid, recp );
	else
	    log_info("%s => `%s' - undefined\n", proxy->sid, recp );

    }
    rfc821_enum_recipients( NULL, &ectx );

    if( proxy->rcpt_keys )
	return 1; /* okay */

    /* Fixme: We should here see whether we really let this message pass
     * or bounce it back.  Need a configure option for this and take
     * undefined and "Precedence: list" in acount */
    proxy->action = aPASSTHRU;
    return 0;
}


static void
save_content_line( PROXY_STATE proxy, char *line )
{
    int i;

    if( !proxy->saved_lines ) {
	proxy->saved_lines_size = 5;
	proxy->saved_lines = xcalloc( proxy->saved_lines_size+1,
				      sizeof *proxy->saved_lines );
    }

    for(i=0; proxy->saved_lines[i]; i++ )
	;
    if( i >= proxy->saved_lines_size ) {
	char **array;

	proxy->saved_lines_size += 5;
	array= xcalloc( proxy->saved_lines_size+1, sizeof *array );
	for(i=0; (array[i] = proxy->saved_lines[i]); i++ )
	    ;
	free( proxy->saved_lines );
	proxy->saved_lines = array;
    }
    proxy->saved_lines[i] = line;
}

/****************
 * Create a new boundary in a way that it is very unlikly
 * that this will occur in th following text.  It would be easy
 * to ensure uniqueness if everything is either quoted-printable
 * or base64 encoded (note that conversion is allowed) but because
 * Mime bodies may be nested, it may happen that yje same boundary
 * has already been used. Bad, but very unlikely - in our application
 * here we cannot prescan the text as it may come from a pipe; what we
 * could do is to see during output whether this happens and in this
 * case simply closing the connection, so that the transaction
 * will fail and the sender can retry it again.
 *
 *   boundary := 0*69<bchars> bcharsnospace
 *   bchars := bcharsnospace / " "
 *   bcharsnospace := DIGIT / ALPHA / "'" / "(" / ")" /
 *		      "+" / "_" / "," / "-" / "." /
 *		      "/" / ":" / "=" / "?"
 */

static char *
create_boundary(void)
{
    static char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz"
			"1234567890'()+_,./:=?";
    char buf[17];
    int i, equal;
    int pid = getpid();

    /* We make the boudary depend on the pid, so that all
     * running processed generate different values even when they
     * have been started within the same second and srand48(time(NULL))
     * has been used.  I cant see whether this is really an advantage
     * but it doesn't do any harm.
     */
    equal = -1;
    for( i=0; i < sizeof(buf)-1; i++ ) {
	buf[i] = tbl[(lrand48()^pid) % (sizeof(tbl)-1)]; /* fill with random */
	if( buf[i] == '=' && equal == -1 )
	    equal = i;
    }
    buf[i] = 0;
    /* now make sure that we do have the sequence "=." in it which cannot
     * be matched by quoted-printable or base64 encoding */
    if( equal != -1 && (equal+1) < i )
	buf[equal+1] = '.';
    else {
	buf[0] = '=';
	buf[1] = '.';
    }

    return xstrdup(buf);
}


static void
prepare_encryption( PROXY_STATE proxy, RFC822 msg )
{
    RFC822_PARSE_CTX ctt;
    int i;
    const char *s;
    char *p;

    if( !encryption_needed( proxy, msg ) ) {
	return;
    }

    if( DBG_VERBOSE )
	log_debug("preparing encryption\n");

    /* First see whether this message is already MIMEified */
    ctt = rfc822_parse_header( msg, "MIME-version", 1 );
    if( ctt ) {
	rfc822_release_parse_ctx( ctt );
	/* Save the old content- fields which we will need later
	 * to create the mime body part and then delete them */
	for(i=1; (p=rfc822_get_header(msg, "Content-*", i )); i++ )
	    save_content_line( proxy, p );
	rfc822_remove_header( msg, "Content-*", 0 );
    }
    else {
	/* Not a MIME-message: Insert a MIME header and rename all
	 * Content-* fields to Old-Content-*
	 */
	rfc822_rename_header( msg, "Content-*", "Old-Content-", 0); /* fixme: check rc */
	rfc822_add_header( msg, "Mime-Version: 1.0"); /* fixme: check rc */
    }
    /* Create out nice new content line */
    s = "Content-Type: multipart/encrypted; "
		       "protocol=\"application/pgp-encrypted\";\n"
		       "\tboundary=\"%s\"" ;
    /* After receiving a RSET a boundary will will be tehre so we have
       to release it first. */
    free (proxy->boundary);
    proxy->boundary = create_boundary();
    p = xmalloc( strlen(s) + strlen(proxy->boundary) + 10 );
    sprintf( p, s, proxy->boundary );
    rfc822_add_header( msg, p ); /* fixme: check rc */
    free(p);
    proxy->action = aENCRYPT;
}


static int
do_set_smarthost( const char *server, int port, struct smarthost *sh )
{
    struct protoent *pe;
    struct hostent *host;

    if( !server )
	server = "localhost";

    if( !port )
	port = 25;
    else if( port < 1 || port > 65534 ) {
	log_error("smarthost port %d is invalid\n", port );
	return -1;
    }

    if( !(pe = getprotobyname("tcp")) ) {
	log_error("getprotobyname failed: %s\n", strerror(errno) );
	return -1;
    }
    sh->proto = pe->p_proto;

    sh->addr.sin_family = AF_INET;
    sh->addr.sin_port = htons(port);
    host = gethostbyname((char*)server);
    if( !host ) {
	log_error("smarthost `%s' is invalid\n", server );
	return -1;
    }

    sh->addr.sin_addr = *(struct in_addr*)host->h_addr;
    free(sh->name);
    sh->name = xstrdup(server);
    sh->port = port;
    return 0;
}

/****************
 * This function is used on startup to prepare
 * a smarthost for connecting.	This is basically needed because
 * we don't use ADNS yes which is needed to to host name resultion
 * in an asyncronos way.  This wayit is easier.
 */
int
smtpproxy_set_smarthost( const char *inbound_name, int inbound_port,
			 const char *outbound_name, int outbound_port )
{
    int rc;

    rc = do_set_smarthost(inbound_name, inbound_port, &smarthost.inbound );
    if( !rc )
       rc = do_set_smarthost(outbound_name, outbound_port,&smarthost.outbound );
    return rc;
}


static int
is_sender_local( PROXY_STATE proxy )
{
    if( !opt.inner_nets )
	return 1;  /* none defined - assume sender is on the inner net */
    return match_network_address( opt.inner_nets, proxy->peer_addr );
}

static int
connect_smarthost( struct smarthost *sh )
{
    int sock = socket(AF_INET, SOCK_STREAM, sh->proto );
    if( sock == -1 ) {
	log_error("error creating socket: %s\n", strerror(errno) );
	return -1;
    }

    if( pth_connect( sock, (struct sockaddr *)&sh->addr,
					 sizeof sh->addr) == -1 ) {
	log_error("error connecting `%s:%d': %s\n",
			    sh->name, sh->port, strerror(errno) );
	close(sock);
	return -1;
    }

    return sock;
}


/****************
 * Open a connection to the Smarthost and initiate transaction.
 * TEMP_FAILURE will be set on error if the error might be transient,
 * e.g. the forwarding host is currently not available or overloaded.
 *
 * Performance hint:  We could keep a list of pending connections and
 *		      reuse them for all threads.
 * Note:  This must be used after proc_header()
 */
static int
open_smarthost( PROXY_STATE state, RFC822 msg, int *temp_failure )
{
    int rc;
    const char *path;
    struct smarthost *sh;

    *temp_failure = 0;
    /* figure out which one to use:
     * If we ae going to decrypt, we will always use the
     * inbound host.  If we have knowledge that the message
     * is not from the inside, we will use the inbound host too.
     * In all other cases the outbound host is used.
     */
    if( state->action == aDECRYPT )
	sh = &smarthost.inbound;
    else if( is_sender_local(state) )
	sh = &smarthost.outbound;
    else
	sh = &smarthost.inbound;

    if( (state->fwd_fd = connect_smarthost( sh )) == -1 )
      {
        *temp_failure = 1;
	return -1;
      }

    if( rw_init( state->fwd_fd ) ) {
	log_error("%s rw_init(%d) failed\n", state->sid, state->fwd_fd );
	close( state->fwd_fd ); state->fwd_fd = -1;
        /* The only reason why this may fail are out of memory
           conditions and out of file descriptors.  The latter is for
           sure a temporary problem, thus we have to fail only
           temporary. */
        *temp_failure = 1;
	return -1;
    }

    state->fwd_smtphd = rfc821_open( NULL, NULL );
    if( !state->fwd_smtphd ) {
	log_error("%s rfc821_open failed\n", state->sid );
	close( state->fwd_fd ); state->fwd_fd = -1;
	return -1;
    }

    rc = rfc821_start_session( state->fwd_smtphd, state->fwd_fd );
    if( rc ) {
	log_error("%s rfc821_start_session failed: rc=%d\n", state->sid, rc );
	rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
	close( state->fwd_fd ); state->fwd_fd = -1;
        if (rc == RFC821ERR_TEMP)
          *temp_failure = 1;
	return -1;
    }

    /* Make sure that we do not have a return-path, so that a
     * failure in some downstream MTA does not send back decrypted
     * text with a bounce message. */
    if( state->action == aDECRYPT )
	path = "";
    else
	path = rfc821_query_sender( state->smtphd );
    if( !path ) {
	log_error("%s can't proxy without sender path\n", state->sid );
	rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
	close( state->fwd_fd ); state->fwd_fd = -1;
	return -1;
    }

    rc = rfc821_send_sender( state->fwd_smtphd, path );
    if( rc ) {
	log_error("%s failed to proxy sender path: %d\n", state->sid, rc );
	rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
	close( state->fwd_fd ); state->fwd_fd = -1;
        if (rc == RFC821ERR_TEMP)
          *temp_failure = 1;
	return -1;
    }

    if( state->action == aENCRYPT ) {
	void *ectx;
	const char *recp;

	for( ectx=NULL; (recp=rfc821_enum_recipients(state->smtphd,&ectx)); ) {
	    rc = rfc821_send_recipient( state->fwd_smtphd, recp );
	    if( rc ) {
		log_error("%s failed to proxy recipient: %d\n",
						    state->sid, rc );
		/* FIXME: We should only close the connection when all
		 * recipients do fail and instead send a notification back */
		rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
		close( state->fwd_fd ); state->fwd_fd = -1;
                if (rc == RFC821ERR_TEMP)
                  *temp_failure = 1;
		return -1;
	    }
	}
	rfc821_enum_recipients( NULL, &ectx );
    }
    else if( state->action == aDECRYPT ) {
	void *ectx;
	const char *recp;
	int any = 0;


	for( ectx=NULL; (recp=rfc821_enum_recipients(state->smtphd,&ectx)); ) {
	    if( !query_aliases( recp, 1 ) ) {
		log_error("%s recipient `%s' is not allowed\n",
						    state->sid, recp);

		rfc822_add_headerf( msg, "X-Geam-Comment: "
					 "decrypting for <%s> not allowed",
								recp );
		continue;
	    }

	    log_info("%s recipient `%s' allowed\n", state->sid, recp);
	    rc = rfc821_send_recipient( state->fwd_smtphd, recp );
	    if( rc ) {
		log_error("%s failed to proxy recipient to: %d\n",
							    state->sid, rc );
		/* FIXME: We should only close the connection when all
		 * recipients do fail and instead send a notification back */
		rfc821_enum_recipients( NULL, &ectx );
		rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
		close( state->fwd_fd ); state->fwd_fd = -1;
                if (rc == RFC821ERR_TEMP)
                  *temp_failure = 1;
		return -1;
	    }
	    any = 1;
	}
	rfc821_enum_recipients( NULL, &ectx );

	if( !any && state->fallback_recp ) {
	    /* use the recipient as defined in the decrypt table */
	    log_info("%s using fallback recipient `%s'\n",
					    state->sid, state->fallback_recp);
	    rfc822_add_headerf( msg, "X-Geam-Comment: using <%s> as fallback",
							state->fallback_recp);
	    rc = rfc821_send_recipient( state->fwd_smtphd,
					state->fallback_recp );
	    if( rc ) {
		log_error("%s failed to proxy recipient to: %d\n",
							state->sid, rc );
		/* FIXME: We should only close the connection when all
		 * recipients do fail and instead send a notification back */
		rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
		close( state->fwd_fd ); state->fwd_fd = -1;
                if (rc == RFC821ERR_TEMP)
                  *temp_failure = 1;
		return -1;
	    }
	}
    }
    else {
	void *ectx;
	for( ectx=NULL; (path = rfc821_enum_recipients( state->smtphd, &ectx)); ) {
	    rc = rfc821_send_recipient( state->fwd_smtphd, path );
	    if( rc ) {
		rfc821_enum_recipients( NULL, &ectx ); /* close enumerator */
		log_error("%s failed to proxy recipient path: %d\n", state->sid, rc );
		/* FIXME: We should only close the connection when all
		 * recipients do fail and instead send a notification back */
		rfc821_cancel( state->fwd_smtphd ); state->fwd_smtphd = NULL;
		close( state->fwd_fd ); state->fwd_fd = -1;
                if (rc == RFC821ERR_TEMP)
                  *temp_failure = 1;
		return -1;
	    }
	}
	rfc821_enum_recipients( NULL, &ectx ); /* close enumerator */
    }

    /* fixme: open data */
    if( opt.verbose )
	log_info("%s forwarding to `%s:%d' initiated\n",
				   state->sid, sh->name, sh->port );

    return 0;


}

/****************
 * This function is called when we have read in all the mail headers.
 * We do some preprocessing on them now.
 */
static void
proc_header( PROXY_STATE proxy, RFC822 msg )
{
    RFC822_PARSE_CTX ctt;

    /* First see whether this message is already MIMEified */
    ctt = rfc822_parse_header( msg, "MIME-version", 1 );
    if( ctt ) {
	/* We simply assume that this is a valid MIME-version field */
	rfc822_release_parse_ctx( ctt );
	ctt = rfc822_parse_header( msg, "Content-Type", -1 );
    }
    if( !ctt ) {
	/* We do not have a content-type or it is not a MIME message.
	 * we now have to check
	 * whether the reciepients are on the to-be-encrypted list
	 * and than do so.  In all other cases we are not going to
	 * change the message
	 */
	prepare_encryption( proxy, msg );
    }
    else {
	/* Have a closer look at the Content-type and decide whether
	 * we have to encrypt it. ...
	 */
	const char *mtype, *msubtype, *protocol;

	mtype = rfc822_query_media_type( ctt, &msubtype );
	if( mtype && !stricmp( mtype, "multipart")
		  && !stricmp( msubtype, "encrypted")
		  && (protocol = rfc822_query_parameter( ctt, "protocol"))
		  && !stricmp( protocol, "application/pgp-encrypted" ) ) {
	    /* Well, this is already a PGP encrypted message.
	     * We can't do much here, because we have to run gpg to see
	     * whether we can decrypt this message; to do this we have to feed
	     * the beginning of the message to gpg to get the key IDs.
	     */
	    proxy->action = aCHECK_DECRYPT;
	}
	else
	    prepare_encryption( proxy, msg );
    }

    rfc822_release_parse_ctx( ctt );
}


/****************
 * feed data to the filter program (gpg).  This runs in it's
 * own thread.
 */
static void *
filter_feeder( void *thread_arg )
{
    PROXY_STATE proxy = thread_arg;
    RFC822 msg = proxy->filter_feed.msg;
    int fd     = proxy->filter_feed.fd;
    void *ectx;
    const char *line;
    size_t n;

    if( DBG_VERBOSE )
	log_debug("filter_feeder: started (fd=%d)\n", fd );

    /* Write the saved content-* lines to start a new Mime body which
     * will be in the encrypted part*/
    if( proxy->saved_lines ) {
	int i;
	for(i=0; (line=proxy->saved_lines[i]); i++ ) {
	    n = strlen(line);
	    if( n && rw_writen( fd, line, n ) ) {
		proxy->filter_feed.error = -1;
		break;
	    }
	    if( rw_writen( fd, "\r\n", 2 ) ) {
		proxy->filter_feed.error = -1;
		break;
	    }
	}
	if( rw_writen( fd, "\r\n", 2 ) )
	    proxy->filter_feed.error = -1;
    }


    for( ectx=NULL; (line = rfc822_enum_body_lines( msg, &ectx, &n)); ) {
	if( n && rw_writen( fd, line, n ) ) {
	    proxy->filter_feed.error = -1;
	    break;
	}
	if( rw_writen( fd, "\n", 1 ) ) {
	    proxy->filter_feed.error = -1;
	    break;
	}
    }
    rfc822_enum_body_lines( NULL, &ectx, NULL ); /* close enumerator */
    close(fd);	/* send a EOF to the child */

    if( proxy->filter_feed.error )
	log_error("filter_feeder: abended\n" );
    else if( DBG_VERBOSE )
	log_debug("filter_feeder: ended\n" );

    return NULL;
}

/****************
 * eat data from the filter program (gpg).  This runs in it's
 * own thread.
 */
static void *
filter_eater( void *thread_arg )
{
    PROXY_STATE proxy = thread_arg;
    int fd     = proxy->filter_eat.fd;
    char *line;
    size_t length;
    int rc;
    int count = 0;

    if( DBG_VERBOSE )
	log_debug("filter_eater: started (fd=%d)\n", fd);

    if( rw_init( fd ) ) {
	log_error("fd %d: rw_init failed\n", fd );
	return NULL;
    }
    /* Because we use armored output, we can be sure that the length
     * of an output line is quit short; so we use 80 here */
    while( (line = rw_readline( fd, 80, &length, NULL )) ) {
	count++;
	rc = rfc821_send_body_line( proxy->fwd_smtphd, line, length );
	if( rc ) {
	    proxy->filter_eat.error = rc;
	    break;
	}
    }

    if( proxy->filter_eat.error )
	log_error("filter_eater: abended (%d lines)\n", count );
    else if( DBG_VERBOSE )
	log_debug("filter_eater: ended (%d lines)\n", count );

    return NULL;
}

/****************
 * eat data from the filter program (gpg).  This runs in it's
 * own thread.
 */
static void *
dummy_eater( void *thread_arg )
{
    PROXY_STATE proxy = thread_arg;
    int fd     = proxy->filter_eat.fd;
    char *line;
    size_t length;
    int count = 0;

    if( DBG_VERBOSE )
	log_debug("filter_eater: started (fd=%d)\n", fd);

    if( rw_init( fd ) ) {
	log_error("fd %d: rw_init failed\n", fd );
	return NULL;
    }
    /* Because we use armored output, we can be sure that the length
     * of an output line is quit short; so we use 80 here */
    while( (line = rw_readline( fd, 80, &length, NULL )) ) {
	count++;
    }

    if( proxy->filter_eat.error )
	log_error("dummy_eater: abended (%d lines)\n", count );
    else if( DBG_VERBOSE )
	log_debug("dummy_eater: ended (%d lines)\n", count );

    return NULL;
}



/****************
 * Do the actual encryption work, that is passing the data to gpg, reading
 * it's output and forwarding it to the smarthost while checking gpg's
 * status messages.
 */
static void
encryption_callback( PROXY_STATE proxy, RFC822 msg,
		     int input_fd, int output_fd, int status_fd )
{
    pth_attr_t tattr = pth_attr_new();
    pth_t feeder = NULL;
    pth_t eater  = NULL;
    char *line, *event, *args;

    if( DBG_VERBOSE )
	log_debug("encryption_cb: creating threads\n");
    proxy->filter_feed.msg = msg;
    proxy->filter_feed.fd  = input_fd;
    proxy->filter_feed.error = 0;
    proxy->filter_eat.msg  = msg;
    proxy->filter_eat.fd   = output_fd;
    proxy->filter_eat.error = 0;

    pth_attr_set( tattr, PTH_ATTR_NAME, "filter_feeder");
    if( !(feeder=pth_spawn( tattr, filter_feeder, proxy )) ) {
	log_error( "%s error spawning filter_feeder: %s\n", proxy->sid, strerror(errno) );
	goto failure;
    }
    pth_attr_set( tattr, PTH_ATTR_NAME, "filter_eater");
    if( !(eater=pth_spawn( tattr, filter_eater, proxy )) ) {
	log_error( "%s error spawning filter_eater: %s\n", proxy->sid, strerror(errno) );
	goto failure;
    }

    /* not that we have setup our workers we can relax and watch GnuPG's
     * status messages */
    if( rw_init( status_fd ) ) {
	log_error("fd %d: rw_init failed\n", status_fd );
	goto failure;
    }
    while( (line = rw_readline( status_fd, 500, NULL, NULL )) ) {
	if( opt.verbose > 1 )
	    log_info("%s gpg status=`%s'\n", proxy->sid, line );
	if( strncmp( line, "[GNUPG:] ", 9 ) )
	    continue;
	event = line + 9;
	args  = strchr( event, ' ' );
	if( !args )
	    args = event+strlen(event); /* point to an empty string */
	else
	    *args++ = 0;
	while( *args == ' ' )
	    args++;
	if( DBG_VERBOSE )
	    log_debug("    event=`%s' args=`%s'\n", event, args);

	if( !strcmp( event, "NEED_PASSPHRASE" ) ) {
	    log_error("%s configuration problem: passphrase needed", proxy->sid );
	    kill( proxy->command_pid, SIGINT );
	    goto failure;
	}
    }
    if( pth_join( feeder, NULL ) )
	feeder = NULL;
    if( pth_join( eater, NULL ) )
	eater = NULL;

  failure:
    if( feeder )
	pth_abort( feeder );
    if( eater )
	pth_abort( eater );
    pth_attr_destroy( tattr );
    /* fixme: make a note in proxy that we have a failure */
}



static int
run_encryption_command( PROXY_STATE proxy, RFC822 msg )
{
    int status;
    static char *envp[] = {
			    NULL };
    static char *options[] = { "gpg",      /* fixme: take form opt.gpg_binary*/
			    "--homedir=",
			    "--no-options",
			    "--batch",
			    "--always-trust",
			    "--encrypt",
			    "--armor",
			    "--verbose",
			    "--batch",
			    "--status-fd=2",
			    NULL };
    struct encrypt_item *ei;
    char **argv;
    int i, n;

    for(i=n=0; options[i]; i++ )
	n++;
    for(ei=proxy->rcpt_keys; ei; ei = ei->next )
	n++;
    n++;
    argv = xcalloc(n, sizeof *argv );
    for(i=n=0; options[i]; i++ )
	if( i == 1 ) {
	    char *p = xmalloc( strlen(options[i])
			       + strlen( opt.gpg_homedir ) + 1 );
	    strcpy(stpcpy(p,options[i]),opt.gpg_homedir);
	    argv[n++] = p;
	}
	else
	    argv[n++] = xstrdup(options[i]);

    for(ei=proxy->rcpt_keys; ei; ei = ei->next ) {
	char *p = xmalloc( 10 + strlen( ei->fpr ) );
	strcpy( stpcpy(p,"-r "), ei->fpr );
	argv[n++] = p;
    }


    status = run_command( proxy, msg, opt.gpg_binary, argv, envp,
			  encryption_callback );
    for(i=0; argv[i]; i++ )
	free( argv[i] );
    free( argv );

    if( status ) {
	log_error("%s encryption failed: status=%d\n", proxy->sid, status );
	return -1;
    }

    return 0;
}


/****************
 * Perform the check_decryption operation.
 */
static void
check_decryption_callback( PROXY_STATE proxy, RFC822 msg,
			   int input_fd, int output_fd, int status_fd )
{
    pth_attr_t tattr = pth_attr_new();
    pth_t feeder = NULL;
    pth_t eater  = NULL;
    char *line, *event, *args, *p;
    int done=0;

    if( DBG_VERBOSE )
	log_debug("check_decryption_cb: creating threads\n");
    proxy->filter_feed.msg = msg;
    proxy->filter_feed.fd  = input_fd;
    proxy->filter_feed.error = 0;
    proxy->filter_eat.msg  = msg;
    proxy->filter_eat.fd   = output_fd;
    proxy->filter_eat.error = 0;

    pth_attr_set( tattr, PTH_ATTR_NAME, "filter_feeder");
    if( !(feeder=pth_spawn( tattr, filter_feeder, proxy )) ) {
	log_error( "error spawning filter_feeder: %s\n", strerror(errno) );
	goto failure;
    }
    pth_attr_set( tattr, PTH_ATTR_NAME, "dummy_eater");
    if( !(eater=pth_spawn( tattr, dummy_eater, proxy )) ) {
	log_error( "error spawning dummy_eater: %s\n", strerror(errno) );
	goto failure;
    }

    /* now that we have setup our workers we can relax and watch GnuPG's
     * status messages */
    if( rw_init( status_fd ) ) {
	log_error("fd %d: rw_init failed\n", status_fd );
	goto failure;
    }
    while( (line = rw_readline( status_fd, 500, NULL, NULL )) ) {
	if( DBG_GPG )
	    log_info("%s gpg status=`%s'\n", proxy->sid, line );
	if( strncmp( line, "[GNUPG:] ", 9 ) )
	    continue;
	event = line + 9;
	args  = strchr( event, ' ' );
	if( !args )
	    args = event+strlen(event); /* point to an empty string */
	else
	    *args++ = 0;
	while( *args == ' ' )
	    args++;

	if( !done && !strcmp( event, "ENC_TO" ) ) { /* check this key */
	    char *keyid = args;
	    struct decrypt_item *di;

	    if( (p = strchr( keyid, ' ' )) )
		*p=0;
	    for( di=decrypt_table[hash_decrypt(keyid)]; di; di = di->next ) {
		if( !stricmp( di->keyid, keyid) )
		    break;
	    }
	    if( di ) { /* Okay, we know about it */
		log_info("%s keyID `%s' accepted (`%s')\n", proxy->sid, keyid, di->key );
		proxy->action = aDECRYPT;
		proxy->fallback_recp = xstrdup(di->key);
		done = 1;
	    }
	}
    }
    if( pth_join( feeder, NULL ) )
	feeder = NULL;
    if( pth_join( eater, NULL ) )
	eater = NULL;

  failure:
    if( feeder )
	pth_abort( feeder );
    if( eater )
	pth_abort( eater );
    pth_attr_destroy( tattr );
}


static int
run_check_decryption_command( PROXY_STATE proxy, RFC822 msg )
{
    int status;
    static char *envp[] = {
			    NULL };
    static char *options[] = { "gpg",
			    "--homedir=",
			    "--no-options",
			    "--batch",
			    "--verbose",
			    "--decrypt",
			    "--list-only",
			    "--batch",
			    "--status-fd=2",
			    NULL };
    char **argv;
    int i, n;

    for(i=n=0; options[i]; i++ )
	n++;
    n++;
    argv = xcalloc(n, sizeof *argv );
    for(i=n=0; options[i]; i++ )
	if( i == 1 ) {
	    char *p = xmalloc( strlen(options[i])
			       + strlen( opt.gpg_homedir ) + 1 );
	    strcpy(stpcpy(p,options[i]),opt.gpg_homedir);
	    argv[n++] = p;
	}
	else
	    argv[n++] = xstrdup(options[i]);

    proxy->action = aPASSTHRU;
    status = run_command( proxy, msg, opt.gpg_binary, argv, envp,
			  check_decryption_callback );
    for(i=0; argv[i]; i++ )
	free( argv[i] );
    free( argv );

    /* We can just ignore errors here */
    if ( status && opt.verbose ) 
	log_info ("%s check_decryption failed: status=%d\n",
                 proxy->sid, status );

    return 0;
}


static int
decrypt_eater_rfc822_cb( void *opaque, enum rfc822_events event, RFC822 msg )
{
    PROXY_STATE proxy = opaque;
    if( event == RFC822EVT_T2BODY )
	proxy->filter_eat.in_header = 0;
    return 0;
}

/****************
 * eat data from the filter program (gpg).  This runs in it's
 * own thread.	It is a special version of filter_eater becuase it has to
 * to some other things.
 */
static void *
decrypt_eater( void *thread_arg )
{
    PROXY_STATE proxy = thread_arg;
    int fd     = proxy->filter_eat.fd;
    char *line;
    size_t length;
    int rc;
    int count = 0;
    int prepared = 0;
    RFC822 mime_body;

    if( DBG_VERBOSE )
	log_debug("decrypt_eater: started (fd=%d)\n", fd);


    proxy->filter_eat.in_header = 1;
    mime_body = rfc822_open( decrypt_eater_rfc822_cb, proxy );
    if( !mime_body ) {
	log_error("fd %d: rfc822_open for mime body failed\n", fd );
	return NULL;
    }

    if( rw_init( fd ) ) {
	log_error("fd %d: rw_init failed\n", fd );
	return NULL;
    }
    /* Because we use armored output, we can be sure that the length
     * of an output line is quit short; so we use 80 here */
    while( (line = rw_readline( fd, 80, &length, NULL )) ) {
	count++;
	if( proxy->filter_eat.in_header ) {
	    /* collect all the mime headers */
	    if( length && line[length-1] == '\r' )
		line[--length] = 0;
	    if( rfc822_insert( mime_body, line, length ) )
		log_fatal("collecting mime header failed\n" );
	    continue;
	}
	if( !prepared ) {
	    int i;
	    char *p;

	    rfc822_rename_header( proxy->filter_eat.msg,
				  "Content-*", "Old-Content-", 0);
	    for(i=1; (p=rfc822_get_header(mime_body, "Content-*", i )); i++ ) {
		rfc822_add_header( proxy->filter_eat.msg, p );
		free( p );
	    }

	    p = rfc822_timestamp(NULL,0);
	    rfc822_add_headerf( proxy->filter_eat.msg,
				"X-Geam-Comment: decrypted on %s", p );
	    free(p);

	    rfc822_remove_header( mime_body, "Content-*", 0 );
	    /* move all left over headers to the rfc822 header */
	    rfc822_rename_header( mime_body, "*", "Old-Mimebody-", 0);
	    for(i=1; (p=rfc822_get_header(mime_body, "*", i )); i++ ) {
		rfc822_add_header( proxy->filter_eat.msg, p );
		free( p );
	    }

	    if( (rc = rfc821_copy_header_lines( proxy->fwd_smtphd,
						proxy->filter_eat.msg)) ) {
              proxy->filter_eat.error = rc;
              log_error("%s copy header lines failed: rc=%d\n",
                        proxy->sid, rc);
              break;
	    }
	    prepared=1;
	}


	rc = rfc821_send_body_line( proxy->fwd_smtphd, line, length );
	if( rc ) {
	    proxy->filter_eat.error = rc;
	    break;
	}
    }

    if( proxy->filter_eat.error )
	log_error("decrypy_eater: abended (%d lines)\n", count );
    else if( DBG_VERBOSE )
	log_debug("decrypt_eater: ended (%d lines)\n", count );

    rfc822_cancel( mime_body );
    return NULL;
}

/****************
 * Do the actual decryption work, that is passing the data to gpg, reading
 * it's output and forwarding it to the smarthost while modifiying the
 * mime content lines.
 */
static void
decryption_callback( PROXY_STATE proxy, RFC822 msg,
		     int input_fd, int output_fd, int status_fd )
{
    pth_attr_t tattr = pth_attr_new();
    pth_t feeder = NULL;
    pth_t eater  = NULL;
    char *line, *event, *args;

    if( DBG_VERBOSE )
	log_debug("decryption_cb: creating threads\n");
    proxy->filter_feed.msg = msg;
    proxy->filter_feed.fd  = input_fd;
    proxy->filter_feed.error = 0;
    proxy->filter_eat.msg  = msg;
    proxy->filter_eat.fd   = output_fd;
    proxy->filter_eat.error = 0;

    pth_attr_set( tattr, PTH_ATTR_NAME, "filter_feeder");
    if( !(feeder=pth_spawn( tattr, filter_feeder, proxy )) ) {
	log_error( "error spawning filter_feeder: %s\n", strerror(errno) );
	goto failure;
    }
    pth_attr_set( tattr, PTH_ATTR_NAME, "filter_eater");
    if( !(eater=pth_spawn( tattr, decrypt_eater, proxy )) ) {
	log_error( "error spawning filter_eater: %s\n", strerror(errno) );
	goto failure;
    }

    /* now that we have setup our workers we can relax and watch GnuPG's
     * status messages */
    if( rw_init( status_fd ) ) {
	log_error("fd %d: rw_init failed\n", status_fd );
	goto failure;
    }
    while( (line = rw_readline( status_fd, 500, NULL, NULL )) ) {
	if( DBG_GPG )
	    log_info("%s gpg status=`%s'\n", proxy->sid, line );
	if( strncmp( line, "[GNUPG:] ", 9 ) )
	    continue;
	event = line + 9;
	args  = strchr( event, ' ' );
	if( !args )
	    args = event+strlen(event); /* point to an empty string */
	else
	    *args++ = 0;
	while( *args == ' ' )
	    args++;

	if( !strcmp( event, "NEED_PASSPHRASE" ) ) {
	    log_error("configuration problem: passphrase needed." );
	    kill( proxy->command_pid, SIGINT );
	    goto failure;
	}
    }
    if( pth_join( feeder, NULL ) )
	feeder = NULL;
    if( pth_join( eater, NULL ) )
	eater = NULL;

  failure:
    if( feeder )
	pth_abort( feeder );
    if( eater )
	pth_abort( eater );
    pth_attr_destroy( tattr );
}

static int
run_decryption_command( PROXY_STATE proxy, RFC822 msg )
{
    int status;
    static char *envp[] = {
			    NULL };
    static char *options[] = { "gpg",
			    "--homedir=",
			    "--no-options",
			    "--verbose",
			    "--batch",
			    "--decrypt",
			    "--batch",
			    "--status-fd=2",
			    NULL };
    char **argv;
    int i, n;


    for(i=n=0; options[i]; i++ )
	n++;
    n++;
    argv = xcalloc(n, sizeof *argv );
    for(i=n=0; options[i]; i++ )
	if( i == 1 ) {
	    char *p = xmalloc( strlen(options[i])
			       + strlen( opt.gpg_homedir ) + 1 );
	    strcpy(stpcpy(p,options[i]),opt.gpg_homedir);
	    argv[n++] = p;
	}
	else
	    argv[n++] = xstrdup(options[i]);

    status = run_command( proxy, msg, opt.gpg_binary, argv, envp,
			  decryption_callback );
    for(i=0; argv[i]; i++ )
	free( argv[i] );
    free( argv );

    if( status || proxy->filter_eat.error ) {
	log_error("%s decryption failed: status=%d eat.error=%d\n",
                  proxy->sid, status, proxy->filter_eat.error );
	return -1;
    }

    return 0;
}



static int
copy_data( PROXY_STATE proxy, RFC822 msg, int *temp_failure )
{
    int rc;

    *temp_failure = 0;
    if( !proxy->fwd_smtphd ) {
	log_error("%s copy_data w/o an open smarthost\n", proxy->sid );
	return -1;
    }

    assert( proxy->action != aCHECK_DECRYPT );

    if( proxy->action == aENCRYPT ) {
	if( (rc = rfc821_copy_header_lines( proxy->fwd_smtphd, msg )) )
          {
            if (rc ==- RFC821ERR_TEMP)
              *temp_failure = 1;
	    goto failure;
          }
	if( (rc = rw_printf( proxy->fwd_fd,
			     "\r\n"  /*better add one additional empty line */
			     "--%s\r\n"
			     "Content-Type: application/pgp-encrypted\r\n"
			     "\r\n"
			     "Version: 1\r\n"
			     "\r\n"
			     "--%s\r\n"
			     "Content-Type: application/octet-stream\r\n"
			     "\r\n", proxy->boundary, proxy->boundary )  ))
	    goto failure;

        if( (rc = run_encryption_command( proxy, msg ) ) )
          {
            if (proxy->filter_eat.error == RFC821ERR_TEMP)
              *temp_failure = 1;
	    goto failure;
          }

	if( (rc = rw_printf( proxy->fwd_fd,
			     "\r\n"
			     "--%s--\r\n"
			     "\r\n",/* better add a trailing blank line */
			      proxy->boundary )  ))
	    goto failure;
	if( (rc = rfc821_send_body_line( proxy->fwd_smtphd, NULL, 0 )) )
          {
            if (rc ==- RFC821ERR_TEMP)
              *temp_failure = 1;
            goto failure;
          }
    }
    else if( proxy->action == aDECRYPT ) {
	if( (rc = run_decryption_command( proxy, msg ) ) )
          {
            if (proxy->filter_eat.error == RFC821ERR_TEMP)
              *temp_failure = 1;
	    goto failure;
          }

	if( (rc = rfc821_send_body_line( proxy->fwd_smtphd, NULL, 0 )) )
          {
            if (rc == RFC821ERR_TEMP)
              *temp_failure = 1;
	    goto failure;
          }
    }
    else {
      rc = rfc821_copy_header_lines( proxy->fwd_smtphd, msg );
      if (!rc)
	rc = rfc821_copy_body_lines( proxy->fwd_smtphd, msg );
      if (!rc)
        rc = rfc821_send_body_line( proxy->fwd_smtphd, NULL, 0 );
      if (rc)
        {
          if (rc == RFC821ERR_TEMP)
            *temp_failure = 1;
          goto failure;
        }
    }


    return 0;

  failure:
    log_error("%s failed to proxy message: %d\n", proxy->sid, rc );
    rfc821_cancel( proxy->fwd_smtphd ); proxy->fwd_smtphd = NULL;
    close( proxy->fwd_fd ); proxy->fwd_fd = -1;
    return -1;
}


/****************
 * This function is called by the rfc821 layer for certain events
 * This rfc821.h for a list of events.	This function should
 * return with 0 for normal success or with an errorcode to let
 * the rfc821 layer return an error code.
 */
static int
cb_from_rfc821( void *opaque, enum rfc821_events event, RFC821 smtp )
{
    PROXY_STATE proxy = opaque;
    int rc = 0;

    /*log_debug("fd %d: smtpproxy#cb_from_rfc821: event %d\n", proxy->fd, event );*/
    switch( event ) {
      case RFC821EVT_DATA:
	proxy->fail_data = 0;
	proxy->fail_data_temp = 0;
	proxy->rcvd_hdr_count = 0;
	break;

      case RFC821EVT_DATA_END:
	if( proxy->fail_data )
          rc = proxy->fail_data_temp? 2 : 1;
	break;

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
    PROXY_STATE proxy = opaque;
    int rc = 0;
    int temp_failure = 0;

    /*log_debug("fd %d: smtpproxy#cb_from_rfc822: event %d\n", proxy->fd, event );*/
    switch( event ) {
      case RFC822EVT_T2BODY:
	proc_header( proxy, msg );
	if( proxy->action == aCHECK_DECRYPT )
	    ; /* we can't open the smarthost now */
	else if( open_smarthost( proxy, msg, &temp_failure ) )
          {
	    proxy->fail_data = 1;
            if (temp_failure)
              proxy->fail_data_temp = 1;
          }
	break;

      case RFC822EVT_FINISH:
	if( proxy->fail_data )
	    ;
	else if( proxy->action == aCHECK_DECRYPT ) {
	    rc = run_check_decryption_command( proxy, msg );
	    if( !rc ) {
		/* now open the smarthost and proxy the data */
		rc = open_smarthost( proxy, msg, &temp_failure);
		if( !rc )
		    rc = copy_data( proxy, msg, &temp_failure );
	    }
	}
	else
	    rc = copy_data( proxy, msg, &temp_failure );
	if( rc )
          {
	    proxy->fail_data = 1;
            if (temp_failure)
              {
                proxy->fail_data_temp = 1;
                rc = 2;
              }
          }
	break;

      case RFC822EVT_RCVD_SEEN:
	if( ++proxy->rcvd_hdr_count > opt.received_headers_max )
	    proxy->fail_data = 1; /* mail looped */
	break;

      default: 
        break;

    }

    return rc;
}


static void
close_mypipe( int *pipedes )
{
    int i;

    for(i=0; i < 2; i++ ) {
	if( pipedes[i] != -1 ) {
	    close(pipedes[i]);
	    pipedes[i] = -1;
	}
    }
}


/****************
 * Run a command and return it's exit status or -1 if we could not
 * do the fork.  callback is used to do the actuall processing.
 */
static int
run_command( PROXY_STATE proxy, RFC822 msg,
	     const char *command,
	     char *const *argv,
	     char *const *envp,
	     void (*callback)( PROXY_STATE, RFC822, int, int, int )
	   )
{
    pid_t pid;
    int status = -1;
    int input_pipe[2] = {-1, -1}; /* data to the command */
    int output_pipe[2]= {-1, -1}; /* data from the command */
    int status_pipe[2]= {-1, -1}; /* status data from the command */

    if( pipe(input_pipe) || pipe(output_pipe) || pipe(status_pipe)  )
	log_error("pipe() failed: %s\n", strerror(errno) );
    else if( (pid = pth_fork()) == -1)
	log_error("fork() failed: %s\n", strerror(errno) );
    else if( pid ) { /* parent */
	int rc;

	close( input_pipe[0] ); input_pipe[0] = -1;
	close(output_pipe[1] );output_pipe[1] = -1;
	close(status_pipe[1] );status_pipe[1] = -1;

	fcntl( input_pipe[1], F_SETFD, FD_CLOEXEC);
	fcntl(output_pipe[0], F_SETFD, FD_CLOEXEC);
	fcntl(status_pipe[0], F_SETFD, FD_CLOEXEC);

	if( opt.verbose )
	    log_info("%s pid %d `%s' started\n", proxy->sid, pid, command );
	proxy->command_pid = pid;
	callback( proxy, msg,  input_pipe[1], output_pipe[0], status_pipe[0] );
	input_pipe[1] = -1; /* is already closed */

	rc = pth_waitpid( pid, &status, 0 );
	if( rc == -1 ) {
	    log_error("%s waitpid(%d) failed: %m\n", proxy->sid, pid );
	    status = -1;
	}
	else if( rc ) {
	    if( WIFSIGNALED( status ) )
		log_error("%s pid %d got signal %d\n", proxy->sid, pid, (int)WTERMSIG(status) );
	    else if( !WIFEXITED( status ) )
		log_info("%s pid %d failed (%d)\n", proxy->sid, pid, status );
	    else if( opt.verbose || WEXITSTATUS(status) )
		log_info("%s pid %d exit status %d\n", proxy->sid, pid, (int)WEXITSTATUS(status) );
	}
	else { /* can't happen w/o WNOHANG, but anyway ... */
	    if( opt.verbose )
	       log_info("%s pid %d does not exist anymore\n", proxy->sid, pid );
	    status = 0;
	}
	close(output_pipe[0]); output_pipe[0] = -1;
	close(status_pipe[0]); status_pipe[0] = -1;
	return status;
    }
    else { /* child */
	close( input_pipe[1] ); input_pipe[1] = -1;
	close(output_pipe[0] );output_pipe[0] = -1;
	close(status_pipe[0] );status_pipe[0] = -1;

	/* connect stdin and stdout */
	if( dup2(input_pipe[0], 0 ) == -1 )
	    _exit(63);
	close( input_pipe[0] ); input_pipe[0] = -1;
	if( dup2(output_pipe[1], 1 ) == -1 )
	    _exit(63);
	close(output_pipe[1] ); input_pipe[1] = -1;
	/* we want fixed filedescriptios in our command string,
	 * so we assign status to 2 */
	if( dup2(status_pipe[1], 2 ) == -1 )
	    _exit(63);
	close(status_pipe[1] );status_pipe[1] = -1;

	execve( command, argv, envp );
	_exit(127);
    }

    close_mypipe( input_pipe );
    close_mypipe( output_pipe );
    close_mypipe( status_pipe );
    return status;

}


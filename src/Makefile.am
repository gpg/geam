
EXTRA_DIST = geamd.conf aliases encrypt decrypt

sbin_PROGRAMS = geamd
noinst_PROGRAMS = simple-mta

geamd_SOURCES = geamd.c  geamd.h \
		smtpproxy.c smtpproxy.h \
		options.h \
		types.h  \
		rwbuf.h rwbuf.c \
		nethelp.h nethelp.c \
		rfc821.h rfc821.c \
		rfc822.h rfc822.c

simple_mta_SOURCES = simple-mta.c \
		types.h  \
		rwbuf.h rwbuf.c \
		rfc821.h rfc821.c \
		rfc822.h rfc822.c


INCLUDES = -I$(top_srcdir)/lib $(PTH_CFLAGS)
LDADD = ../lib/libutil.a $(PTH_LIBS)
simple_mta_LDADD = ../lib/libutil.a

if MAINTAINER_MODE

rfc822: $(srcdir)/rfc822.c
	$(COMPILE) -DTESTING -o rfc822 $(srcdir)/rfc822.c ../lib/libutil.a

misc: $(srcdir)/misc.c
	$(COMPILE) -DTESTING -o misc $(srcdir)/misc.c ../lib/libutil.a

endif


dnl
dnl autoconf macros for this project
dnl


dnl GNUPG_CHECK_TYPEDEF(TYPE, HAVE_NAME)
dnl Check whether a typedef exists and create a #define $2 if it exists
dnl
AC_DEFUN(GNUPG_CHECK_TYPEDEF,
  [ AC_MSG_CHECKING(for $1 typedef)
    AC_CACHE_VAL(gnupg_cv_typedef_$1,
    [AC_TRY_COMPILE([#include <stdlib.h>
    #include <sys/types.h>], [
    #undef $1
    int a = sizeof($1);
    ], gnupg_cv_typedef_$1=yes, gnupg_cv_typedef_$1=no )])
    AC_MSG_RESULT($gnupg_cv_typedef_$1)
    if test "$gnupg_cv_typedef_$1" = yes; then
        AC_DEFINE($2)
    fi
  ])


# Configure paths for PTH
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-08

dnl AM_PATH_PTH([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for Pth, and define PTH_CFLAGS and PTH_LIBS
dnl
AC_DEFUN(AM_PATH_PTH,
[dnl
dnl Get the cflags and libraries from the pth-config script
dnl
AC_ARG_WITH(pth-prefix,
          [  --with-pth-prefix=PFX   Prefix where Pth is installed (optional)],
          pth_config_prefix="$withval", pth_config_prefix="")
AC_ARG_ENABLE(pthtest,
          [  --disable-pthtest    Do not try to compile and run a test Pth program],
          , enable_pthtest=yes)

  if test x$pth_config_prefix != x ; then
     pth_config_args="$pth_config_args --prefix=$pth_config_prefix"
     if test x${PTH_CONFIG+set} != xset ; then
        PTH_CONFIG=$pth_config_prefix/bin/pth-config
     fi
  fi

  AC_PATH_PROG(PTH_CONFIG, pth-config, no)
  min_pth_version=ifelse([$1], ,1.2.1,$1)
  AC_MSG_CHECKING(for Pth - version >= $min_pth_version)
  no_pth=""
  if test "$PTH_CONFIG" = "no" ; then
    no_pth=yes
  else
    PTH_CFLAGS=`$PTH_CONFIG $pth_config_args --cflags`
    PTH_LIBS=`$PTH_CONFIG $pth_config_args --ldflags --libs`
    pth_config_major_version=`$PTH_CONFIG $pth_config_args --version | \
           sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\1/'`
    pth_config_minor_version=`$PTH_CONFIG $pth_config_args --version | \
           sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\2/'`
    pth_config_micro_version=`$PTH_CONFIG $pth_config_args --version | \
           sed 's/.* \([[0-9]]*\)\.\([[0-9]]*\)\.\([[0-9]]*\).*/\3/'`
    if test "x$enable_pthtest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $PTH_CFLAGS"
      LIBS="$LIBS $PTH_LIBS"
dnl
dnl Now check if the installed Pth is sufficiently new. Also sanity
dnl checks the results of pth-config to some extent
dnl
      rm -f conf.pthtest
      AC_TRY_RUN([
#include <pth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main ()
{
    int major, minor, micro;
    unsigned int major_pth, minor_pth, micro_pth, patlvl_pth;
    char *tmp_version;
    char ver_string[20];

    system ("touch conf.pthtest");

    /* HP/UX 9 (%@#!) writes to sscanf strings */
    tmp_version = strdup("$min_pth_version");
    if( !tmp_version )
        exit(1);
    if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
       printf("%s, bad version string\n", "$min_pth_version");
       exit(1);
    }

    sprintf( ver_string, "%lX", pth_version() );
    if ( sscanf(ver_string, "%1x%2x%1x%2x",
                     &major_pth, &minor_pth, &patlvl_pth, &micro_pth) != 4) {
       printf("%s, pth returned bad version string\n", ver_string );
       exit(1);
    }

    if ((major_pth != $pth_config_major_version) ||
        (minor_pth != $pth_config_minor_version) ||
        (micro_pth != $pth_config_micro_version))
    {
      printf("\n*** 'pth-config --version' returned %d.%d.%d, but Pth (%u.%u.%u)\n",
             $pth_config_major_version, $pth_config_minor_version, $pth_config_micro_version,
             major_pth, minor_pth, micro_pth);
      printf("*** was found! If pth-config was correct, then it is best\n");
      printf("*** to remove the old version of Pth. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If pth-config was wrong, set the environment variable PTH_CONFIG\n");
      printf("*** to point to the correct copy of pth-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( pth_version() != PTH_VERSION )
    {
      printf("*** Pth header file (version %lx) does not match\n", PTH_VERSION);
      printf("*** library (version %lx)\n", pth_version() );
    }
    else
    {
      if ((major_pth > major) ||
         ((major_pth == major) && (minor_pth > minor)) ||
         ((major_pth == major) && (minor_pth == minor) && (micro_pth >= micro)))
      {
        return 0;
      }
     else
      {
        printf("\n*** An old version of Pth (%u.%u.%u) was found.\n",
               major_pth, minor_pth, micro_pth);
        printf("*** You need a version of Pth newer than %d.%d.%d. The latest version of\n",
               major, minor, micro);
        printf("*** Pth is always available from ftp://ftp.gnu.org/gnu/pub/.\n");
        printf("***\n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the pth-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of Pth, but you can also set the PTH_CONFIG environment to point to the\n");
        printf("*** correct copy of pth-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_pth=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_pth" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     AC_MSG_RESULT(no)
     if test "$PTH_CONFIG" = "no" ; then
       echo "*** The pth-config script installed by Pth could not be found"
       echo "*** If Pth was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the PTH_CONFIG environment variable to the"
       echo "*** full path to pth-config."
     else
       if test -f conf.pthtest ; then
        :
       else
          echo "*** Could not run Pth test program, checking why..."
          CFLAGS="$CFLAGS $PTH_CFLAGS"
          LIBS="$LIBS $PTH_LIBS"
          AC_TRY_LINK([
#include <pth.h>
#include <stdio.h>
],      [ return !!pth_version(); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding Pth or finding the wrong"
          echo "*** version of Pth. If it is not finding Pth, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means Pth was incorrectly installed"
          echo "*** or that you have moved Pth since it was installed. In the latter case, you"
          echo "*** may want to edit the pth-config script: $PTH_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     PTH_CFLAGS=""
     PTH_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(PTH_CFLAGS)
  AC_SUBST(PTH_LIBS)
  rm -f conf.pthtest
])



dnl GPH_PROG_DOCBOOK()
dnl Check whether we have the needed Docbook environment
dnl and issue a warning if this is not the case.
dnl
dnl This test defines these variables for substitution:
dnl    DB2HTML - command used to convert Docbook to HTML
dnl    DB2TEX  - command used to convert Docbook to TeX
dnl    DB2MAN  - command used to convert Docbook to man pages
dnl    JADE    - command to invoke jade
dnl    JADETEX - command to invoke jadetex
dnl    DSL_FOR_HTML - the stylesheet used to for the Docbook->HTML conversion
dnl    DSL_FOR_TEX  - the stylesheet used to for the Docbook->TeX conversion
dnl The following make conditionals are defined
dnl    HAVE_DB2MAN  - defined when db2man is available
dnl    HAVE_DB2TEX  - defined when db2tex is available
dnl    HAVE_DB2HTML - defined when db2html is available
dnl    HAVE_DOCBOOK - defined when the entire Docbook environment is present
dnl    HAVE_JADE    - defined when jade is installed
dnl    HAVE_JADETEX - defined when jadetex is installed
dnl
dnl (wk 2000-04-12)
dnl
AC_DEFUN(GPH_PROG_DOCBOOK,
  [  AC_REQUIRE([AC_CONFIG_AUX_DIR_DEFAULT])dnl
     all=yes
     AC_PATH_PROG(DB2MAN, docbook-to-man, no)
     test "$DB2MAN" = no && all=no
     AM_CONDITIONAL(HAVE_DB2MAN, test "$DB2MAN" != no )

     AC_PATH_PROG(JADE, jade, no)
     test "$JADE" = no && all=no
     AM_CONDITIONAL(HAVE_JADE, test "$JADE" != no )

     AC_PATH_PROG(JADETEX, jadetex, no)
     test "$JADETEX" = no && all=no
     AM_CONDITIONAL(HAVE_JADETEX, test "$JADETEX" != no )

     stylesheet_dirs='
/usr/local/lib/dsssl/stylesheets/docbook
/usr/local/share/dsssl/stylesheets/docbook
/usr/local/lib/sgml/stylesheet/dsssl/docbook/nwalsh
/usr/local/share/sgml/stylesheet/dsssl/docbook/nwalsh
/usr/lib/dsssl/stylesheets/docbook
/usr/share/dsssl/stylesheets/docbook
/usr/lib/sgml/stylesheet/dsssl/docbook/nwalsh
/usr/share/sgml/stylesheet/dsssl/docbook/nwalsh
/usr/lib/sgml/stylesheets/nwalsh-modular 
/usr/share/sgml/stylesheets/nwalsh-modular 
'

    AC_MSG_CHECKING(for TeX stylesheet)
    DSL_FOR_TEX=none
    for d in ${stylesheet_dirs}; do
        file=${d}/print/docbook.dsl
        if test -f $file; then
            DSL_FOR_TEX=$file
            break
        fi
    done
    AC_MSG_RESULT([$DSL_FOR_TEX])
    okay=no
    if test $DSL_FOR_TEX = none ; then
       DB2TEX="$missing_dir/missing db2tex"
       all=no
    else
       DB2TEX="$JADE -t tex"
       okay=yes
    fi
    AC_SUBST(DB2TEX)
    AC_SUBST(DSL_FOR_TEX)
    AM_CONDITIONAL(HAVE_DB2TEX, test $okay = yes )

    if ( $ac_aux_dir/db2html.in --version) < /dev/null > /dev/null 2>&1; then
        :
    else
        AC_ERROR([needed $ac_aux_dir/db2html.in not found])
    fi

    AC_MSG_CHECKING(for HTML stylesheet)
    DSL_FOR_HTML="none"
    for d in ${stylesheet_dirs}; do
        file=${d}/html/docbook.dsl
        if test -f $file; then
            DSL_FOR_HTML=$file
            break
        fi
    done
    AC_MSG_RESULT([$DSL_FOR_HTML])
    okay=no
    if test $DSL_FOR_HTML = none ; then
       DB2HTML="$missing_dir/missing db2html"
       all=no
    else
       DB2HTML="`cd $ac_aux_dir && pwd`/db2html --copyfiles"
       okay=yes
    fi
    AC_SUBST(DB2HTML)
    AC_SUBST(DSL_FOR_HTML)
    AM_CONDITIONAL(HAVE_DB2HTML, test $okay = yes )

    AM_CONDITIONAL(HAVE_DOCBOOK, test "$all" != yes )
    if test $all = no ; then
        AC_MSG_WARN([[
***
*** It seems that the Docbook environment is not installed as required.
*** We will try to build everything,  but if you either touch some files
*** or use a bogus make tool, you may run into problems.
*** Docbook is normally only needed to build the documentation.
***]])
    fi
  ])


dnl *-*wedit:notab*-*  Please keep this as the last line.

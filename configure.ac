dnl
dnl autoconf for Pacemaker
dnl
dnl License: GNU General Public License (GPL)

dnl ===============================================
dnl Bootstrap 
dnl ===============================================
AC_PREREQ(2.53)

dnl Suggested structure:
dnl     information on the package
dnl     checks for programs
dnl     checks for libraries
dnl     checks for header files
dnl     checks for types
dnl     checks for structures
dnl     checks for compiler characteristics
dnl     checks for library functions
dnl     checks for system services

AC_INIT(pacemaker, 1.0.4, pacemaker@oss.clusterlabs.org)
CRM_DTD_VERSION="1.0"

PKG_FEATURES=""
HB_PKG=heartbeat

AC_CONFIG_AUX_DIR(.)
AC_CANONICAL_HOST

dnl Where #defines go (e.g. `AC_CHECK_HEADERS' below)
dnl
dnl Internal header: include/config.h
dnl   - Contains ALL defines
dnl   - include/config.h.in is generated automatically by autoheader
dnl   - NOT to be included in any header files except lha_internal.h
dnl     (which is also not to be included in any other header files)
dnl
dnl External header: include/crm_config.h
dnl   - Contains a subset of defines checked here
dnl   - Manually edit include/crm_config.h.in to have configure include
dnl     new defines
dnl   - Should not include HAVE_* defines
dnl   - Safe to include anywhere
AM_CONFIG_HEADER(include/config.h include/crm_config.h)
ALL_LINGUAS="en fr"

AC_ARG_WITH(version,
    [  --with-version=version   Override package version (if you're a packager needing to pretend) ],
    [ PACKAGE_VERSION="$withval" ])

AC_ARG_WITH(pkg-name,
    [  --with-pkg-name=name     Override package name (if you're a packager needing to pretend) ],
    [ PACKAGE_NAME="$withval" ])

AM_INIT_AUTOMAKE($PACKAGE_NAME, $PACKAGE_VERSION)
AC_DEFINE_UNQUOTED(PACEMAKER_VERSION, "$PACKAGE_VERSION", Current pacemaker version)

CC_IN_CONFIGURE=yes
export CC_IN_CONFIGURE

LDD=ldd

dnl ========================================================================
dnl Compiler characteristics
dnl ========================================================================

AC_PROG_CC dnl Can force other with environment variable "CC".
AM_PROG_CC_C_O
AC_PROG_CC_STDC

AC_LIBTOOL_DLOPEN               dnl Enable dlopen support...
AC_LIBLTDL_CONVENIENCE          dnl make libltdl a convenience lib
AC_PROG_LIBTOOL

AC_C_STRINGIZE
AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)
AC_STRUCT_TIMEZONE

dnl ===============================================
dnl Helpers 
dnl ===============================================
cc_supports_flag() {
         local CFLAGS="$@"
         AC_MSG_CHECKING(whether $CC supports "$@")
         AC_COMPILE_IFELSE([int main(){return 0;}] ,[RC=0; AC_MSG_RESULT(yes)],[RC=1; AC_MSG_RESULT(no)])
         return $RC
}

extract_header_define() {
	  AC_MSG_CHECKING(for $2 in $1)
	  Cfile=/tmp/extract_define.$2.${$}
	  printf "#include <stdio.h>\n" > ${Cfile}.c
	  printf "#include <%s>\n" $1 >> ${Cfile}.c
	  printf "int main(int argc, char **argv) { printf(\"%%s\", %s); return 0; }\n" $2 >> ${Cfile}.c
	  $CC $CFLAGS ${Cfile}.c -o ${Cfile}
	  value=`${Cfile}`
	  AC_MSG_RESULT($value)
	  printf $value
	  rm -f ${Cfile}.c ${Cfile}
	}

dnl ===============================================
dnl Configure Options
dnl ===============================================

dnl Some systems, like Solaris require a custom package name
AC_ARG_WITH(pkgname,
    [  --with-pkgname=name     name for pkg (typically for Solaris) ],
    [ PKGNAME="$withval" ],
    [ PKGNAME="LXHAhb" ],
  )
AC_SUBST(PKGNAME)

AC_ARG_ENABLE([ansi],
[  --enable-ansi force GCC to compile to ANSI/ANSI standard for older compilers.
     [default=yes]])

AC_ARG_ENABLE([fatal-warnings],
[  --enable-fatal-warnings very pedantic and fatal warnings for gcc
     [default=yes]])

AC_ARG_ENABLE([pretty],
[  --enable-pretty 
     Pretty-print compiler output unless there is an error
     [default=no]])

AC_ARG_ENABLE([quiet],
[  --enable-quiet 
     Supress make output unless there is an error
     [default=no]])

AC_ARG_ENABLE([thread-safe],
[  --enable-thread-safe Enable some client libraries to be thread safe.
     [default=no]])

AC_ARG_ENABLE([bundled-ltdl],
[  --enable-bundled-ltdl  Configure, build and install the standalone ltdl library bundled with ${PACKAGE} [default=no]]) 
LTDL_LIBS=""

AC_ARG_WITH(ais,
    [  --with-ais     
       Support the OpenAIS messaging and membership layer ],
    [ SUPPORT_AIS=$withval ],
    [ SUPPORT_AIS=try ],
)

AC_ARG_WITH(heartbeat,
    [  --with-heartbeat     
       Support the Heartbeat messaging and membership layer ],
    [ SUPPORT_HEARTBEAT=$withval ],
    [ SUPPORT_HEARTBEAT=try ],
)

AC_ARG_WITH(snmp,
    [  --with-snmp     
       Support the SNMP protocol ],
    [ SUPPORT_SNMP=$withval ],
    [ SUPPORT_SNMP=try ],
)

AC_ARG_WITH(esmtp,
    [  --with-esmtp  
       Support the sending mail notifications with the esmtp library ],
    [ SUPPORT_ESMTP=$withval ],
    [ SUPPORT_ESMTP=try ],
)

AISPREFIX=""
AC_ARG_WITH(ais-prefix,
    [  --with-ais-prefix=DIR  Prefix used when OpenAIS was installed [$prefix]],
    [ AISPREFIX=$withval ], 
    [ AISPREFIX=$prefix ])

LCRSODIR=""
AC_ARG_WITH(lcrso-dir, 
    [  --with-lcrso-dir=DIR   OpenAIS lcrso files. ],
    [ LCRSODIR="$withval" ])

INITDIR=""
AC_ARG_WITH(initdir,
    [  --with-initdir=DIR      directory for init (rc) scripts [${INITDIR}]],
    [ INITDIR="$withval" ])

dnl ===============================================
dnl General Processing
dnl ===============================================

AC_SUBST(HB_PKG)

INIT_EXT=""
echo Our Host OS: $host_os/$host


AC_MSG_NOTICE(Sanitizing prefix: ${prefix})
case $prefix in
  NONE)	prefix=/usr;;
esac

AC_MSG_NOTICE(Sanitizing exec_prefix: ${exec_prefix})
case $exec_prefix in
  dnl For consistency with Heartbeat, map NONE->$prefix
  NONE)	  exec_prefix=$prefix;;
  prefix) exec_prefix=$prefix;;
esac

AC_MSG_NOTICE(Sanitizing ais_prefix: ${AISPREFIX})
case $AISPREFIX in
  dnl For consistency with Heartbeat, map NONE->$prefix
  NONE)	  AISPREFIX=$prefix;;
  prefix) AISPREFIX=$prefix;;
esac

AC_MSG_NOTICE(Sanitizing INITDIR: ${INITDIR})
case $INITDIR in
  prefix) INITDIR=$prefix;;
  "")
    AC_MSG_CHECKING(which init (rc) directory to use)
      for initdir in /etc/init.d /etc/rc.d/init.d /sbin/init.d	\
	   /usr/local/etc/rc.d /etc/rc.d
      do
        if
          test -d $initdir
        then
          INITDIR=$initdir
          break
        fi
      done
      AC_MSG_RESULT($INITDIR);;
esac
AC_SUBST(INITDIR)

AC_MSG_NOTICE(Sanitizing libdir: ${libdir})
case $libdir in
  dnl For consistency with Heartbeat, map NONE->$prefix
  *prefix*|NONE)
    AC_MSG_CHECKING(which lib directory to use)
    for aDir in lib64 lib
    do
      trydir="${exec_prefix}/${aDir}"
      if
        test -d ${trydir}
      then
        libdir=${trydir}
        break
      fi
    done
    AC_MSG_RESULT($libdir);
    ;;
esac

dnl Expand autoconf variables so that we dont end up with '${prefix}' 
dnl in #defines and python scripts
dnl NOTE: Autoconf deliberately leaves them unexpanded to allow
dnl    make exec_prefix=/foo install
dnl No longer being able to do this seems like no great loss to me...

eval prefix="`eval echo ${prefix}`"
eval exec_prefix="`eval echo ${exec_prefix}`"
eval bindir="`eval echo ${bindir}`"
eval sbindir="`eval echo ${sbindir}`"
eval libexecdir="`eval echo ${libexecdir}`"
eval datadir="`eval echo ${datadir}`"
eval sysconfdir="`eval echo ${sysconfdir}`"
eval sharedstatedir="`eval echo ${sharedstatedir}`"
eval localstatedir="`eval echo ${localstatedir}`"
eval libdir="`eval echo ${libdir}`"
eval includedir="`eval echo ${includedir}`"
eval oldincludedir="`eval echo ${oldincludedir}`"
eval infodir="`eval echo ${infodir}`"
eval mandir="`eval echo ${mandir}`"

dnl Home-grown variables
eval INITDIR="${INITDIR}"
eval docdir="`eval echo ${docdir}`"

for j in prefix exec_prefix bindir sbindir libexecdir datadir sysconfdir \
    sharedstatedir localstatedir libdir includedir oldincludedir infodir \
    mandir INITDIR docdir
do 
  dirname=`eval echo '${'${j}'}'`
  if
    test ! -d "$dirname"
  then
    AC_MSG_WARN([$j directory ($dirname) does not exist!])
  fi
done

dnl This OS-based decision-making is poor autotools practice;
dnl feature-based mechanisms are strongly preferred.
dnl
dnl So keep this section to a bare minimum; regard as a "necessary evil". 

case "$host_os" in
*bsd*)		LIBS="-L/usr/local/lib"
		CPPFLAGS="$CPPFLAGS -I/usr/local/include"
		INIT_EXT=".sh"
		;;
*solaris*)
		;;
*linux*)	
		AC_DEFINE_UNQUOTED(ON_LINUX, 1, Compiling for Linux platform)
 		;;
darwin*)	
		AC_DEFINE_UNQUOTED(ON_DARWIN, 1, Compiling for Darwin platform)
  		LIBS="$LIBS -L${prefix}/lib"
  		CFLAGS="$CFLAGS -I${prefix}/include"
		;;
esac

dnl Eventually remove this 
CFLAGS="$CFLAGS -I${prefix}/include/heartbeat"

AC_SUBST(INIT_EXT)
AC_DEFINE_UNQUOTED(HA_LOG_FACILITY, LOG_DAEMON, Default logging facility)

AC_MSG_NOTICE(Host CPU: $host_cpu)

case "$host_cpu" in
  ppc64|powerpc64)
    case $CFLAGS in
     *powerpc64*)			;;
     *)	if test "$GCC" = yes; then
	  CFLAGS="$CFLAGS -m64"
	fi				;;
    esac
esac

AC_MSG_CHECKING(which format is needed to print uint64_t)
case "$host_cpu" in
  s390x)U64T="%lu";;
  *64*) U64T="%lu";;
  *)    U64T="%llu";;
esac
AC_MSG_RESULT($U64T)
AC_DEFINE_UNQUOTED(U64T, "$U64T", Correct printf format for logging uint64_t)

AC_CHECK_HEADERS(hb_config.h)
AC_CHECK_HEADERS(glue_config.h)
GLUE_HEADER=none
if test "$ac_cv_header_hb_config_h" = "yes"; then
   GLUE_HEADER=hb_config.h
      
elif test "$ac_cv_header_glue_config_h" = "yes";  then
   GLUE_HEADER=glue_config.h

else
   AC_MSG_FAILURE(Core development headers were not found)
fi

dnl Variables needed for substitution
CRM_DTD_DIRECTORY="${datadir}/pacemaker"
AC_DEFINE_UNQUOTED(CRM_DTD_DIRECTORY,"$CRM_DTD_DIRECTORY", Location for the Pacemaker Relax-NG Schema)
AC_SUBST(CRM_DTD_DIRECTORY)

AC_DEFINE_UNQUOTED(CRM_DTD_VERSION,"$CRM_DTD_VERSION", Current version of the Pacemaker Relax-NG Schema)
AC_SUBST(CRM_DTD_VERSION)

CRM_DAEMON_USER=`extract_header_define $GLUE_HEADER HA_CCMUSER`
AC_DEFINE_UNQUOTED(CRM_DAEMON_USER,"$CRM_DAEMON_USER", User to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_USER)

CRM_DAEMON_GROUP=`extract_header_define $GLUE_HEADER HA_APIGROUP`
AC_DEFINE_UNQUOTED(CRM_DAEMON_GROUP,"$CRM_DAEMON_GROUP", Group to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_GROUP)

dnl Eventually move out of the heartbeat dir tree and create symlinks when needed
CRM_DAEMON_DIR=`extract_header_define $GLUE_HEADER HA_LIBHBDIR`
AC_DEFINE_UNQUOTED(CRM_DAEMON_DIR,"$CRM_DAEMON_DIR", Location for Pacemaker daemons)
AC_SUBST(CRM_DAEMON_DIR)

CRM_STATE_DIR=${localstatedir}/run/crm
AC_DEFINE_UNQUOTED(CRM_STATE_DIR,"$CRM_STATE_DIR", Where to keep state files and sockets)
AC_SUBST(CRM_STATE_DIR)

PE_STATE_DIR="${localstatedir}/lib/pengine"
AC_DEFINE_UNQUOTED(PE_STATE_DIR,"$PE_STATE_DIR", Where to keep PEngine outputs)
AC_SUBST(PE_STATE_DIR)

dnl Eventually move out of the heartbeat dir tree and create compatability code
dnl HA_VARLIBDIR="${localstatedir}/lib"
HA_VARLIBDIR=`extract_header_define $GLUE_HEADER HA_VARLIBDIR`
CRM_CONFIG_DIR="$HA_VARLIBDIR/heartbeat/crm"
AC_DEFINE_UNQUOTED(CRM_CONFIG_DIR,"$CRM_CONFIG_DIR", Where to keep CIB configuration files)
AC_SUBST(CRM_CONFIG_DIR)

dnl Needed so that the AIS plugin can clear out the directory as Heartbeat does
HA_STATE_DIR=`extract_header_define $GLUE_HEADER HA_VARRUNDIR`
AC_DEFINE_UNQUOTED(HA_STATE_DIR,"$HA_STATE_DIR", Where Heartbeat keeps state files and sockets)
AC_SUBST(HA_STATE_DIR)

dnl The next two are needed for haresources2cib.py
HA_HBCONF_DIR=`extract_header_define $GLUE_HEADER HA_HBCONF_DIR`
AC_SUBST(HA_HBCONF_DIR)

HB_RA_DIR=`extract_header_define $GLUE_HEADER HB_RA_DIR`
AC_SUBST(HB_RA_DIR)

dnl Needed for the location of hostcache in CTS.py
HA_VARLIBHBDIR=`extract_header_define $GLUE_HEADER HA_VARLIBHBDIR`
AC_SUBST(HA_VARLIBHBDIR)

OCF_ROOT_DIR=`extract_header_define $GLUE_HEADER OCF_ROOT_DIR`
if test "X$OCF_ROOT_DIR" = X; then
  AC_MSG_ERROR(Could not locate OCF directory)
fi
AC_SUBST(OCF_ROOT_DIR)

OCF_RA_DIR=`extract_header_define $GLUE_HEADER OCF_RA_DIR`
AC_DEFINE_UNQUOTED(OCF_RA_DIR,"$OCF_RA_DIR", Location for OCF RAs)
AC_SUBST(OCF_RA_DIR)

AC_PATH_PROGS(HG, hg false)
AC_MSG_CHECKING(build version)
BUILD_VERSION=unknown
if test -f $srcdir/.hg_archival.txt; then
   BUILD_VERSION=`cat $srcdir/.hg_archival.txt | awk '/node:/ { print $2 }'`
elif test -x $HG -a -d .hg; then
   BUILD_VERSION=`$HG id -itb`
   if test $? != 0; then
       BUILD_VERSION=unknown
   fi
fi

AC_DEFINE_UNQUOTED(BUILD_VERSION, "$BUILD_VERSION", Build version)
AC_MSG_RESULT($BUILD_VERSION)
AC_SUBST(BUILD_VERSION)

dnl ===============================================
dnl Program Paths
dnl ===============================================

PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin"
export PATH


dnl Replacing AC_PROG_LIBTOOL with AC_CHECK_PROG because LIBTOOL
dnl was NOT being expanded all the time thus causing things to fail.
AC_CHECK_PROGS(LIBTOOL, glibtool libtool libtool15 libtool13)

AM_PATH_PYTHON
AC_CHECK_PROGS(MAKE, gmake make)
AC_PATH_PROGS(HTML2TXT, lynx w3m)
AC_PATH_PROGS(HELP2MAN, help2man)
AC_PATH_PROGS(POD2MAN, pod2man, pod2man)
AC_PATH_PROGS(SSH, ssh, /usr/bin/ssh)
AC_PATH_PROGS(SCP, scp, /usr/bin/scp)
AC_PATH_PROGS(HG, hg, /bin/false)
AC_PATH_PROGS(TAR, tar)
AC_PATH_PROGS(MD5, md5)
AC_PATH_PROGS(TEST, test)
AC_PATH_PROGS(PKGCONFIG, pkg-config)
AC_PATH_PROGS(XML2CONFIG, xml2-config)
AC_PATH_PROGS(VALGRIND_BIN, valgrind, /usr/bin/valgrind)
AC_DEFINE_UNQUOTED(VALGRIND_BIN, "$VALGRIND_BIN", Valgrind command)

if test x"${LIBTOOL}" = x""; then
   AC_MSG_ERROR(You need (g)libtool installed in order to build ${PACKAGE})
fi
if test x"${MAKE}" = x""; then
   AC_MSG_ERROR(You need (g)make installed in order to build ${PACKAGE})
fi

AM_CONDITIONAL(BUILD_HELP, test x"${HELP2MAN}" != x"")
if test x"${HELP2MAN}" != x""; then
   PKG_FEATURES="$PKG_FEATURES manpages"
fi

dnl ===============================================
dnl Libraries
dnl ===============================================
AC_CHECK_LIB(socket, socket)			dnl -lsocket
AC_CHECK_LIB(c, dlopen)				dnl if dlopen is in libc...
AC_CHECK_LIB(dl, dlopen)			dnl -ldl (for Linux)
AC_CHECK_LIB(rt, sched_getscheduler)            dnl -lrt (for Tru64)
AC_CHECK_LIB(gnugetopt, getopt_long)		dnl -lgnugetopt ( if available )
AC_CHECK_LIB(pam, pam_start)			dnl -lpam (if available)
AC_CHECK_LIB(uuid, uuid_parse)			dnl e2fsprogs
AC_CHECK_LIB(uuid, uuid_create)			dnl ossp

if test x"${PKGCONFIG}" = x""; then
   AC_MSG_ERROR(You need pkgconfig installed in order to build ${PACKAGE})
fi

dnl
dnl     On many systems libcrypto is needed when linking against libsnmp.
dnl     Check to see if it exists, and if so use it.
dnl
AC_CHECK_LIB(crypto, CRYPTO_free, CRYPTOLIB="-lcrypto",)
AC_SUBST(CRYPTOLIB)

if test "x${enable_thread_safe}" = "xyes"; then
        GPKGNAME="gthread-2.0"
else
        GPKGNAME="glib-2.0"
fi

if 
   $PKGCONFIG --exists $GPKGNAME
then
	GLIBCONFIG="$PKGCONFIG $GPKGNAME"
else
	set -x
        echo PKG_CONFIG_PATH=$PKG_CONFIG_PATH
	$PKGCONFIG --exists $GPKGNAME; echo $?
	$PKGCONFIG --cflags $GPKGNAME; echo $?
	$PKGCONFIG $GPKGNAME; echo $?
	set +x
        
	AC_MSG_ERROR(You need glib2-devel installed in order to build ${PACKAGE})
fi
AC_MSG_RESULT(using $GLIBCONFIG)

#
#	Where is dlopen?
#
if test "$ac_cv_lib_c_dlopen" = yes; then
	LIBADD_DL=""
elif test "$ac_cv_lib_dl_dlopen" = yes; then
	LIBADD_DL=-ldl
else
        LIBADD_DL=${lt_cv_dlopen_libs}
fi
dnl
dnl Check for location of gettext
dnl
dnl On at least Solaris 2.x, where it is in libc, specifying lintl causes
dnl grief. Ensure minimal result, not the sum of all possibilities.
dnl And do libc first.
dnl Known examples:
dnl    c:      Linux, Solaris 2.6+
dnl    intl:   BSD, AIX

AC_CHECK_LIB(c, gettext)
if test x$ac_cv_lib_c_gettext != xyes; then
   AC_CHECK_LIB(intl, gettext)
fi

if test x$ac_cv_lib_c_gettext != xyes -a x$ac_cv_lib_intl_gettext != xyes; then
   AC_MSG_ERROR(You need gettext installed in order to build ${PACKAGE})
fi

if test "X$GLIBCONFIG" != X; then
	AC_MSG_CHECKING(for special glib includes: )
	GLIBHEAD=`$GLIBCONFIG --cflags`
	AC_MSG_RESULT($GLIBHEAD)
	CPPFLAGS="$CPPFLAGS $GLIBHEAD"

	AC_MSG_CHECKING(for glib library flags)
	GLIBLIB=`$GLIBCONFIG --libs`
	AC_MSG_RESULT($GLIBLIB)
	LIBS="$LIBS $GLIBLIB"
fi

dnl ========================================================================
dnl Headers
dnl ========================================================================

AC_HEADER_STDC
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(asm/types.h)
AC_CHECK_HEADERS(assert.h)
AC_CHECK_HEADERS(auth-client.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(dirent.h)
AC_CHECK_HEADERS(errno.h)
AC_CHECK_HEADERS(fcntl.h)
AC_CHECK_HEADERS(getopt.h)
AC_CHECK_HEADERS(glib.h)
AC_CHECK_HEADERS(grp.h)
AC_CHECK_HEADERS(limits.h)
AC_CHECK_HEADERS(linux/errqueue.h)
AC_CHECK_HEADERS(malloc.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(netinet/ip.h)
AC_CHECK_HEADERS(pam/pam_appl.h)
AC_CHECK_HEADERS(pthread.h)
AC_CHECK_HEADERS(pwd.h)
AC_CHECK_HEADERS(security/pam_appl.h)
AC_CHECK_HEADERS(sgtty.h)
AC_CHECK_HEADERS(signal.h)
AC_CHECK_HEADERS(stdarg.h)
AC_CHECK_HEADERS(stddef.h)
AC_CHECK_HEADERS(stdio.h)
AC_CHECK_HEADERS(stdlib.h)
AC_CHECK_HEADERS(string.h)
AC_CHECK_HEADERS(strings.h)
AC_CHECK_HEADERS(sys/dir.h)
AC_CHECK_HEADERS(sys/ioctl.h)
AC_CHECK_HEADERS(sys/param.h)
AC_CHECK_HEADERS(sys/poll.h)
AC_CHECK_HEADERS(sys/resource.h)
AC_CHECK_HEADERS(sys/select.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/sockio.h)
AC_CHECK_HEADERS(sys/stat.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(sys/timeb.h)
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(sys/uio.h)
AC_CHECK_HEADERS(sys/un.h)
AC_CHECK_HEADERS(sys/utsname.h)
AC_CHECK_HEADERS(sys/wait.h)
AC_CHECK_HEADERS(time.h)
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(winsock.h)

dnl These headers need prerequisits before the tests will pass 
dnl AC_CHECK_HEADERS(net/if.h)
dnl AC_CHECK_HEADERS(netinet/icmp6.h)
dnl AC_CHECK_HEADERS(netinet/ip6.h)
dnl AC_CHECK_HEADERS(netinet/ip_icmp.h)

AC_MSG_CHECKING(for special libxml2 includes)
if test "x$XML2CONFIG" = "x"; then
   AC_MSG_ERROR(libxml2 config not found)
else
   XML2HEAD="`$XML2CONFIG --cflags`"
   AC_MSG_RESULT($XML2HEAD)
   AC_CHECK_LIB(xml2, xmlReadMemory)
   AC_CHECK_LIB(xslt, xsltApplyStylesheet)
fi

CPPFLAGS="$CPPFLAGS $XML2HEAD"

AC_CHECK_HEADERS(libxml/xpath.h)
AC_CHECK_HEADERS(libxslt/xslt.h)
if test "$ac_cv_header_libxml_xpath_h" != "yes"; then
   AC_MSG_ERROR(The libxml developement headers were not found)
fi
if test "$ac_cv_header_libxslt_xslt_h" != "yes"; then
   AC_MSG_ERROR(The libxslt developement headers were not found)
fi

dnl ========================================================================
dnl Structures
dnl ========================================================================

AC_CHECK_MEMBERS([struct tm.tm_gmtoff],,,[[#include <time.h>]])

dnl ========================================================================
dnl Functions
dnl ========================================================================

AC_CHECK_FUNCS(g_log_set_default_handler)
AC_CHECK_FUNCS(getopt, AC_DEFINE(HAVE_DECL_GETOPT,  1, [Have getopt function]))

dnl ========================================================================
dnl   ltdl
dnl ========================================================================

AC_CHECK_LIB(ltdl, lt_dlopen, [LTDL_foo=1])
if test "x${enable_bundled_ltdl}" = "xyes"; then
   if test $ac_cv_lib_ltdl_lt_dlopen = yes; then
      AC_MSG_NOTICE([Disabling usage of installed ltdl])
   fi
   ac_cv_lib_ltdl_lt_dlopen=no
fi

LIBLTDL_DIR=""
if test $ac_cv_lib_ltdl_lt_dlopen != yes ; then
   AC_MSG_NOTICE([Installing local ltdl])
   LIBLTDL_DIR=libltdl
   ( cd $srcdir ; $TAR -xvf libltdl.tar )
   if test "$?" -ne 0; then
     AC_MSG_ERROR([$TAR of libltdl.tar in $srcdir failed])
   fi
   AC_CONFIG_SUBDIRS(libltdl)
else
   LIBS="$LIBS -lltdl"
   AC_MSG_NOTICE([Using installed ltdl])
   INCLTDL=""
   LIBLTDL=""
fi

AC_SUBST(INCLTDL)
AC_SUBST(LIBLTDL)
AC_SUBST(LIBLTDL_DIR)

dnl ========================================================================
dnl   bzip2
dnl ========================================================================
AC_CHECK_HEADERS(bzlib.h)
AC_CHECK_LIB(bz2, BZ2_bzBuffToBuffCompress)

if test x$ac_cv_lib_bz2_BZ2_bzBuffToBuffCompress != xyes ; then
   AC_MSG_ERROR(BZ2 libraries not found)
fi

if test x$ac_cv_header_bzlib_h != xyes; then
   AC_MSG_ERROR(BZ2 Development headers not found)
fi


dnl ========================================================================
dnl   ncurses
dnl ========================================================================
dnl
dnl A few OSes (e.g. Linux) deliver a default "ncurses" alongside "curses".
dnl Many non-Linux deliver "curses"; sites may add "ncurses".
dnl
dnl However, the source-code recommendation for both is to #include "curses.h"
dnl (i.e. "ncurses" still wants the include to be simple, no-'n', "curses.h").
dnl
dnl ncurse takes precedence.
dnl
AC_CHECK_HEADERS(curses.h)
AC_CHECK_HEADERS(curses/curses.h)
AC_CHECK_HEADERS(ncurses.h)
AC_CHECK_HEADERS(ncurses/ncurses.h)

dnl Although n-library is preferred, only look for it if the n-header was found.
CURSESLIBS=''
if test "$ac_cv_header_ncurses_h" = "yes"; then
  AC_CHECK_LIB(ncurses, printw,
    [CURSESLIBS='-lncurses'; AC_DEFINE(HAVE_LIBNCURSES,1, have ncurses library)]
  )
fi

if test "$ac_cv_header_ncurses_ncurses_h" = "yes"; then
  AC_CHECK_LIB(ncurses, printw,
    [CURSESLIBS='-lncurses'; AC_DEFINE(HAVE_LIBNCURSES,1, have ncurses library)]
  )
fi

dnl Only look for non-n-library if there was no n-library.
if test X"$CURSESLIBS" = X"" -a "$ac_cv_header_curses_h" = "yes"; then
  AC_CHECK_LIB(curses, printw,
    [CURSESLIBS='-lcurses'; AC_DEFINE(HAVE_LIBCURSES,1, have curses library)]
  )
fi

dnl Only look for non-n-library if there was no n-library.
if test X"$CURSESLIBS" = X"" -a "$ac_cv_header_curses_curses_h" = "yes"; then
  AC_CHECK_LIB(curses, printw,
    [CURSESLIBS='-lcurses'; AC_DEFINE(HAVE_LIBCURSES,1, have curses library)]
  )
fi

if test "x$CURSESLIBS" != "x"; then
   PKG_FEATURES="$PKG_FEATURES ncurses"
fi

dnl Check for printw() prototype compatibility
if test X"$CURSESLIBS" != X"" && cc_supports_flag -Wcast-qual && cc_supports_flag -Werror; then 
    AC_MSG_CHECKING(whether printw() requires argument of "const char *")
    ac_save_LIBS=$LIBS
    LIBS="$CURSESLIBS  $LIBS"
    ac_save_CFLAGS=$CFLAGS
    CFLAGS="-Wcast-qual -Werror"

    AC_LINK_IFELSE(
	    [AC_LANG_PROGRAM(
	      [
#if defined(HAVE_CURSES_H)
#  include <curses.h>
#elif defined(HAVE_NCURSES_H)
#  include <ncurses.h>
#endif
	      ],
	      [printw((const char *)"Test");]
	    )], 
	    [ac_cv_compatible_printw=yes],
	    [ac_cv_compatible_printw=no]
    )

    LIBS=$ac_save_LIBS
    CFLAGS=$ac_save_CFLAGS

    AC_MSG_RESULT([$ac_cv_compatible_printw])

    if test "$ac_cv_compatible_printw" = no; then
		AC_MSG_WARN([The printw() function of your ncurses or curses library is old, we will disable usage of the library. If you want to use this library anyway, please update to newer version of the library, ncurses 5.4 or later is recommended. You can get the library from http://www.gnu.org/software/ncurses/.])
		AC_MSG_NOTICE([Disabling curses])
		AC_DEFINE(HAVE_INCOMPATIBLE_PRINTW, 1, [Do we have incompatible printw() in curses library?])
    fi
fi

AC_SUBST(CURSESLIBS)

dnl ========================================================================
dnl    Cluster infrastructure - Heartbeat
dnl ========================================================================

dnl On Debian, AC_CHECK_LIBS fail if a library has any unresolved symbols
dnl So check for all the depenancies (so they're added to LIBS) before checking for -lplumb

AC_CHECK_LIB(pils, PILLoadPlugin)
AC_CHECK_LIB(plumb, G_main_add_IPC_Channel)

if test x"$ac_cv_lib_plumb_G_main_add_IPC_Channel" != x"yes"; then
   AC_MSG_FAILURE(Core Heartbeat utility libraries not found: $ac_cv_lib_plumb_G_main_add_IPC_Channel)
fi

dnl Compatability checks
AC_CHECK_FUNCS(msgfromIPC_timeout)
AC_CHECK_MEMBERS([struct lrm_ops.fail_rsc],,,[[#include <lrm/lrm_api.h>]])

dnl ========================================================================
dnl    Cluster stack - Heartbeat
dnl ========================================================================

case $SUPPORT_HEARTBEAT in
     1|yes|true) 
        AC_CHECK_LIB(hbclient, ll_cluster_new, 
   		[SUPPORT_HEARTBEAT=1], [AC_MSG_FAILURE(Unable to support Heartbeat: client libraries not found)]);;
     try)
        AC_CHECK_LIB(hbclient, ll_cluster_new, 
   		[SUPPORT_HEARTBEAT=1], [SUPPORT_HEARTBEAT=0]);;
     *) SUPPORT_HEARTBEAT=0;;
esac

AM_CONDITIONAL(BUILD_HEARTBEAT_SUPPORT, test $SUPPORT_HEARTBEAT = 1)
AC_DEFINE_UNQUOTED(SUPPORT_HEARTBEAT, $SUPPORT_HEARTBEAT, Support the Heartbeat messaging and membership layer)


dnl ========================================================================
dnl    Cluster stack - OpenAIS
dnl ========================================================================

AISLIB=""

dnl Normalize the values
case $SUPPORT_AIS in
     1|yes|true) missingisfatal=1;;
     try)        missingisfatal=0;;
     *) SUPPORT_AIS=no;;
esac

AC_MSG_CHECKING(for native AIS)
AISMSGLIB=""
AIS_VERSION="none"
COROSYNC_PKG="$PKGCONFIG libcoroipcc"

if test $SUPPORT_AIS = no; then
   AC_MSG_RESULT(no... not requested.)

else
   AC_MSG_RESULT($SUPPORT_AIS, with '$AISPREFIX')

   AC_CHECK_HEADERS(openais/saAis.h)
   AC_CHECK_HEADERS(corosync/coroipcc.h)

   $COROSYNC_PKG --exists
   if test $? = 0; then
       AIS_VERSION="corosync"

   elif test "$ac_cv_header_openais_saAis_h" = "yes"; then
       AIS_VERSION="whitetank"
   else
       aisreason="Whitetank headers not found"
   fi  
fi

if test $AIS_VERSION != "none"; then
   AC_MSG_CHECKING(for OpenAIS branch)
   AC_MSG_RESULT($AIS_VERSION)
fi

if test $AIS_VERSION = "corosync"; then
   if test "$ac_cv_header_corosync_coroipcc_h" != "yes"; then
       AIS_VERSION="none"
       aisreason="Corosync headers not found"
   fi

   saveLIBS="$LIBS"
   LIBS="$LIBS `$COROSYNC_PKG --libs-only-L`"
   AC_CHECK_LIB(coroipcc, coroipcc_msg_send_reply_receive, [])
   LIBS="$saveLIBS"

   if test $ac_cv_lib_coroipcc_coroipcc_msg_send_reply_receive != yes; then
        AC_MSG_RESULT(Cannot locate AIS messaging library)
	aisreason="requred Corosync libraries not found"
        AIS_VERSION="none"
   fi

fi

dnl continue?
if test $AIS_VERSION = "whitetank"; then
   dnl Find it in lib, lib64, or wherever it wants to live...
   AC_MSG_CHECKING(location of OpenAIS libraries)
   dnl CoroSync location
   alib=`ls ${AISPREFIX}/*/libcpg.so | head -n 1`
   if test -z "$alib"; then
      dnl Whitetank location
      alib=`ls ${AISPREFIX}/*/*/libcpg.so | head -n 1`
   fi
   AISLIB=`dirname $alib`
   AC_MSG_RESULT($AISLIB)
   if test "x$AISLIB" = "x"; then
     AC_MSG_WARN(Use --with-ais-prefix to specify the prefix OpenAIS was installed with)
     aisreason="library directory not found"
     AIS_VERSION="none"

   elif test ! -d "$AISLIB"; then
     AC_MSG_WARN(Use --with-ais-prefix to specify the prefix OpenAIS was installed with)
     aisreason="specified library directory does not exist"
     AIS_VERSION="none"
   fi
fi

dnl continue?
if test $AIS_VERSION = "whitetank"; then
   AC_MSG_CHECKING(location of OpenAIS plugins)
   if test -z "$LCRSODIR"; then
      LCRSODIR="$libexecdir/lcrso"
      alib=`ls ${AISPREFIX}/*/lcrso/objdb.lcrso | head -n 1`
      LCRSODIR=`dirname $alib`
   fi
   AC_MSG_RESULT($LCRSODIR)

   if test "x$LCRSODIR" = "x"; then
     AC_MSG_RESULT(Invalid.  Please specify the correct location with --with-lcrso-dir)
     aisreason="plugin directory not found"
     AIS_VERSION="none"

   elif test ! -d "$LCRSODIR"; then
     AC_MSG_RESULT(Invalid.  Please specify the correct location with --with-lcrso-dir)
     aisreason="specified plugin directory does not exist"
     AIS_VERSION="none"
   fi
fi

dnl continue?
if test $AIS_VERSION = "whitetank"; then
     dnl Don't add the messaging library to LIBS since most daemons don't need/use it
     saveLIBS="$LIBS"
     LIBS="$LIBS -L${AISLIB} -R${AISLIB}"

     AC_CHECK_LIB(SaMsg, saSendReceiveReply, [])
     AC_CHECK_LIB(SaMsg, openais_msg_send_reply_receive, [])

     if test $ac_cv_lib_SaMsg_openais_msg_send_reply_receive = yes; then
       :  OpenAIS
     elif test $ac_cv_lib_SaMsg_saSendReceiveReply = yes; then
       :  OpenAIS
	AC_DEFINE_UNQUOTED(TRADITIONAL_AIS_IPC, 1, "Use the 'old' AIS IPC interface")
     else
        AC_MSG_RESULT(Cannot locate AIS messaging library)
	aisreason="requred libraries not found"
        AIS_VERSION="none"
     fi
     LIBS="$saveLIBS"
fi

SUPPORT_AIS=1
case $AIS_VERSION in
    corosync)
	AC_DEFINE_UNQUOTED(AIS_COROSYNC, 1, "AIS target is the corosync series")
   	LCRSODIR=`$PKGCONFIG corosync --variable=lcrsodir`
   	CFLAGS="$CFLAGS `$COROSYNC_PKG --cflags`"
	AISMSGLIB=`$COROSYNC_PKG --libs`
	;;
    whitetank) 
	AC_DEFINE_UNQUOTED(AIS_WHITETANK, 1, "AIS target is the whitetank series")
	CFLAGS="$CFLAGS -I$AISPREFIX/include/openais"
	AISMSGLIB="-L${AISLIB} -R${AISLIB} -lSaMsg"
	;;
    none)
     	SUPPORT_AIS=0
	if test "x$aisreason" != x; then
     	  if test $missingisfatal = 0; then
	    AC_MSG_WARN(Unable to support OpenAIS: $aisreason) 
          else
	    AC_MSG_FAILURE(Unable to support OpenAIS: $aisreason) 
          fi
        fi
	;;
    *) AC_MSG_FAILURE(Unknown OpenAIS branch: $AIS_VERSION);;
esac

AC_DEFINE_UNQUOTED(SUPPORT_AIS, $SUPPORT_AIS, Support the OpenAIS messaging and membership layer)
AM_CONDITIONAL(BUILD_AIS_SUPPORT, test $SUPPORT_AIS = 1)

dnl
dnl    Cluster stack - Sanity
dnl

STACKS=""
CLUSTERLIBS=""
if test $SUPPORT_HEARTBEAT = 1; then
   STACKS="$STACKS heartbeat"
   CLUSTERLIBS="$CLUSTERLIBS -lhbclient -lccmclient"
fi

if test $SUPPORT_AIS = 1; then
   STACKS="$STACKS $AIS_VERSION"
   CLUSTERLIBS="$CLUSTERLIBS ${AISMSGLIB}"
else
   AISPREFIX=""
   LCRSODIR="$libdir"
fi

PKG_FEATURES="$PKG_FEATURES$STACKS"

AC_MSG_CHECKING(for supported stacks)
if test x"$STACKS" = x; then
   AC_MSG_FAILURE(You must choose at least one cluster stack to support)
fi
AC_MSG_RESULT($STACKS)

AC_SUBST(CLUSTERLIBS)
AC_SUBST(LCRSODIR)

dnl ========================================================================
dnl    SNMP
dnl ========================================================================

case $SUPPORT_SNMP in
     1|yes|true) missingisfatal=1;;
     try)        missingisfatal=0;;
     *)		 SUPPORT_SNMP=no;;
esac

SNMPLIB=""

AC_MSG_CHECKING(for snmp support)
if test $SUPPORT_SNMP = no; then
   AC_MSG_RESULT(no... not requested.)

else
   SNMPCONFIG=""
   AC_MSG_RESULT($SUPPORT_SNMP)
   AC_CHECK_HEADERS(net-snmp/net-snmp-config.h)

   if test "x${ac_cv_header_net_snmp_net_snmp_config_h}" != "xyes"; then
	SUPPORT_SNMP="no"
   fi

   if test $SUPPORT_SNMP != no; then
	AC_PATH_PROGS(SNMPCONFIG, net-snmp-config)
	if test "X${SNMPCONFIG}" = "X"; then
		AC_MSG_RESULT(You need the net_snmp development package to continue.)
		SUPPORT_SNMP=no
	fi
   fi

   if test $SUPPORT_SNMP != no; then
	AC_MSG_CHECKING(for special snmp libraries)
	SNMPLIBS=`$SNMPCONFIG --agent-libs`
	AC_MSG_RESULT($SNMPLIBS)
   fi

   if test $SUPPORT_SNMP != no; then
      savedLibs=$LIBS
      LIBS="$LIBS $SNMPLIBS"
      AC_CHECK_FUNCS(netsnmp_transport_open_client)
      if test $ac_cv_func_netsnmp_transport_open_client != yes; then
      	 SUPPORT_SNMP=no
      fi
      LIBS=$savedLibs
   fi

   if test $SUPPORT_SNMP = no; then
   	SUPPORT_SNMP=0
     	if test $missingisfatal = 0; then
	    AC_MSG_WARN(Unable to support SNMP) 
        else
	    AC_MSG_FAILURE(Unable to support SNMP) 
        fi
   else
   	SUPPORT_SNMP=1
   fi
fi

if test $SUPPORT_SNMP = 1; then
   PKG_FEATURES="$PKG_FEATURES snmp"
fi

AC_SUBST(SNMPLIBS)
AM_CONDITIONAL(ENABLE_SNMP, test "$SUPPORT_SNMP" = "1")
AC_DEFINE_UNQUOTED(ENABLE_SNMP, $SUPPORT_SNMP, Build in support for sending SNMP traps)

dnl ========================================================================
dnl    ESMTP
dnl ========================================================================

case $SUPPORT_ESMTP in
     1|yes|true) missingisfatal=1;;
     try)        missingisfatal=0;;
     *)		 SUPPORT_ESMTP=no;;
esac

ESMTPLIB=""

AC_MSG_CHECKING(for esmtp support)
if test $SUPPORT_ESMTP = no; then
   AC_MSG_RESULT(no... not requested.)

else
   ESMTPCONFIG=""
   AC_MSG_RESULT($SUPPORT_ESMTP)
   AC_CHECK_HEADERS(libesmtp.h)

   if test "x${ac_cv_header_libesmtp_h}" != "xyes"; then
	ENABLE_ESMTP="no"
   fi

   if test $SUPPORT_ESMTP != no; then
	AC_PATH_PROGS(ESMTPCONFIG, libesmtp-config)
	if test "X${ESMTPCONFIG}" = "X"; then
		AC_MSG_RESULT(You need the libesmtp development package to continue.)
		SUPPORT_ESMTP=no
	fi
   fi

   if test $SUPPORT_ESMTP != no; then
	AC_MSG_CHECKING(for special esmtp libraries)
	ESMTPLIBS=`$ESMTPCONFIG --libs | tr '\n' ' '`
	AC_MSG_RESULT($ESMTPLIBS)
   fi

   if test $SUPPORT_ESMTP = no; then
   	SUPPORT_ESMTP=0
     	if test $missingisfatal = 0; then
	    AC_MSG_WARN(Unable to support ESMTP) 
        else
	    AC_MSG_FAILURE(Unable to support ESMTP) 
        fi
   else
   	SUPPORT_ESMTP=1
   fi
fi

if test $SUPPORT_ESMTP = 1; then
   PKG_FEATURES="$PKG_FEATURES libesmtp"
fi

AC_SUBST(ESMTPLIBS)
AM_CONDITIONAL(ENABLE_ESMTP, test "$SUPPORT_ESMTP" = "1")
AC_DEFINE_UNQUOTED(ENABLE_ESMTP, $SUPPORT_ESMTP, Build in support for sending mail notifications with ESMTP)

dnl ========================================================================
dnl    GnuTLS
dnl ========================================================================

AC_CHECK_HEADERS(gnutls/gnutls.h)
AC_CHECK_HEADERS(security/pam_appl.h pam/pam_appl.h)

dnl GNUTLS library: Attempt to determine by 'libgnutls-config' program.
dnl If no 'libgnutls-config', try traditional autoconf means.
AC_PATH_PROGS(LIBGNUTLS_CONFIG, libgnutls-config)

if test -n "$LIBGNUTLS_CONFIG"; then
	AC_MSG_CHECKING(for gnutls header flags)
	GNUTLSHEAD="`$LIBGNUTLS_CONFIG --cflags`";
	AC_MSG_RESULT($GNUTLSHEAD)
	AC_MSG_CHECKING(for gnutls library flags)
	GNUTLSLIBS="`$LIBGNUTLS_CONFIG --libs`";
	AC_MSG_RESULT($GNUTLSLIBS)
else
	AC_CHECK_LIB(gnutls, gnutls_init)
fi
AC_SUBST(GNUTLSHEAD)
AC_SUBST(GNUTLSLIBS)

dnl ========================================================================
dnl checks for library functions to replace them
dnl
dnl     NoSuchFunctionName:
dnl             is a dummy function which no system supplies.  It is here to make
dnl             the system compile semi-correctly on OpenBSD which doesn't know
dnl             how to create an empty archive
dnl
dnl     scandir: Only on BSD.
dnl             System-V systems may have it, but hidden and/or deprecated.
dnl             A replacement function is supplied for it.
dnl
dnl     setenv: is some bsdish function that should also be avoided (use
dnl             putenv instead)
dnl             On the other hand, putenv doesn't provide the right API for the
dnl             code and has memory leaks designed in (sigh...)  Fortunately this
dnl             A replacement function is supplied for it.
dnl
dnl     strerror: returns a string that corresponds to an errno.
dnl             A replacement function is supplied for it.
dnl
dnl     unsetenv: is some bsdish function that should also be avoided (No 
dnl             replacement)
dnl             A replacement function is supplied for it.
dnl
dnl	strnlen: is a gnu function similar to strlen, but safer.
dnl		We wrote a tolearably-fast replacement function for it.
dnl
dnl	strndup: is a gnu function similar to strdup, but safer.
dnl		We wrote a tolearably-fast replacement function for it.
dnl
dnl	daemon: is a GNU function.  The daemon() function is for programs wishing to
dnl             detach themselves from the controlling terminal and run in the
dnl             background as system daemon
dnl             A replacement function is supplied for it.

AC_REPLACE_FUNCS(alphasort inet_pton NoSuchFunctionName scandir setenv strerror unsetenv strnlen strndup daemon strlcpy strlcat)

dnl ========================================================================
dnl Compiler flags
dnl ========================================================================

dnl Make sure that CFLAGS is not exported. If the user did
dnl not have CFLAGS in their environment then this should have
dnl no effect. However if CFLAGS was exported from the user's
dnl environment, then the new CFLAGS will also be exported
dnl to sub processes.

CC_ERRORS=""
CC_EXTRAS=""

if export | fgrep " CFLAGS=" > /dev/null; then
	export -n CFLAGS || true # We don't want to bomb out if this fails
fi

if test "$GCC" != yes; then
        CFLAGS="$CFLAGS -g"
	enable_fatal_warnings=no
else
        CFLAGS="$CFLAGS -ggdb3 -O0"

	# We had to eliminate -Wnested-externs because of libtool changes
        EXTRA_FLAGS="-fgnu89-inline
		-fstack-protector-all
		-Wall
		-Waggregate-return
		-Wbad-function-cast 
		-Wcast-qual 
		-Wcast-align 
		-Wdeclaration-after-statement
		-Wendif-labels
		-Wfloat-equal
		-Wformat=2
		-Wformat-security
		-Wformat-nonliteral
		-Winline
		-Wmissing-prototypes 
		-Wmissing-declarations 
		-Wmissing-format-attribute
		-Wnested-externs
		-Wno-long-long
		-Wno-strict-aliasing
		-Wpointer-arith 
		-Wstrict-prototypes
    		-Wunsigned-char
		-Wwrite-strings"

# Additional warnings it might be nice to enable one day
#		-Wshadow
#		-Wunreachable-code

	for j in $EXTRA_FLAGS
	do
	  if
	    cc_supports_flag $j
	  then
	    CC_EXTRAS="$CC_EXTRAS $j"
	  fi
	done

dnl In lib/ais/Makefile.am there's a gcc option available as of v4.x

	GCC_MAJOR=`gcc -v 2>&1 | awk 'END{print $3}' | sed 's/[.].*//'`
	AM_CONDITIONAL(GCC_4, test "${GCC_MAJOR}" = 4)

dnl System specific options

	case "$host_os" in
  	*linux*|*bsd*)
		if test "${enable_fatal_warnings}" = "unknown"; then
        		enable_fatal_warnings=yes
        	fi
          	;;
	esac

	if test "x${enable_fatal_warnings}" != xno && cc_supports_flag -Werror ; then
	   enable_fatal_warnings=yes
	else
	   enable_fatal_warnings=no
        fi

	if test "x${enable_ansi}" != xno && cc_supports_flag -std=iso9899:199409 ; then
	  AC_MSG_NOTICE(Enabling ANSI Compatibility)
	  CC_EXTRAS="$CC_EXTRAS -ansi -D_GNU_SOURCE -DANSI_ONLY"
	fi

  	AC_MSG_NOTICE(Activated additional gcc flags: ${CC_EXTRAS})
fi

CFLAGS="$CFLAGS $CC_EXTRAS"

NON_FATAL_CFLAGS="$CFLAGS"
AC_SUBST(NON_FATAL_CFLAGS)

dnl
dnl We reset CFLAGS to include our warnings *after* all function
dnl checking goes on, so that our warning flags don't keep the
dnl AC_*FUNCS() calls above from working.  In particular, -Werror will
dnl *always* cause us troubles if we set it before here.
dnl
dnl
if test "x${enable_fatal_warnings}" = xyes ; then
   AC_MSG_NOTICE(Enabling Fatal Warnings)
   CFLAGS="$CFLAGS -Werror"
fi
AC_SUBST(CFLAGS)

dnl This is useful for use in Makefiles that need to remove one specific flag
CFLAGS_COPY="$CFLAGS"
AC_SUBST(CFLAGS_COPY)

AC_SUBST(LIBADD_DL)	dnl extra flags for dynamic linking libraries
AC_SUBST(LIBADD_INTL)	dnl extra flags for GNU gettext stuff...

AC_SUBST(LOCALE)

dnl Options for cleaning up the compiler output 
PRETTY_CC=""
QUIET_LIBTOOL_OPTS=""
QUIET_MAKE_OPTS=""
if test x"${enable_pretty}" = "xyes"; then
   enable_quiet="yes"
   echo "install_sh: ${install_sh}"
   PRETTY_CC="`pwd`/tools/ccdv"
   dnl It would be nice if this was rebuilt when needed too...
   mkdir `pwd`/tools/ 2>/dev/null
   ${CC} $CFLAGS -o `pwd`/tools/ccdv ${srcdir}/tools/ccdv.c
   CC="\$(PRETTY_CC) ${CC}"
fi
if test "x${enable_quiet}" = "xyes"; then
   QUIET_LIBTOOL_OPTS="--quiet"
   QUIET_MAKE_OPTS="--quiet"
fi

AC_MSG_RESULT(Supress make details: ${enable_quiet})
AC_MSG_RESULT(Pretty print compiler output: ${enable_pretty})

dnl Put the above variables to use
LIBTOOL="${LIBTOOL} --tag=CC \$(QUIET_LIBTOOL_OPTS)"
MAKE="${MAKE} \$(QUIET_MAKE_OPTS)"

AC_SUBST(CC)
AC_SUBST(MAKE)
AC_SUBST(LIBTOOL)
AC_SUBST(PRETTY_CC)
AC_SUBST(QUIET_MAKE_OPTS)
AC_SUBST(QUIET_LIBTOOL_OPTS)

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES(Makefile				        \
README							        \
cts/Makefile					        	\
	cts/CTSvars.py						\
	cts/LSBDummy						\
cib/Makefile							\
crmd/Makefile							\
pengine/Makefile						\
debian/Makefile							\
doc/Makefile							\
	doc/cibadmin.8						\
	doc/crm_resource.8					\
include/Makefile						\
	include/crm/Makefile					\
		include/crm/common/Makefile			\
		include/crm/pengine/Makefile			\
	include/fencing/Makefile				\
replace/Makefile						\
lib/Makefile							\
	lib/ais/Makefile					\
	lib/common/Makefile					\
	lib/cib/Makefile					\
	lib/pengine/Makefile					\
	lib/transition/Makefile					\
	lib/fencing/Makefile					\
	lib/plugins/Makefile					\
		lib/plugins/lrm/Makefile			\
fencing/Makefile                                                \
        fencing/stonithd/Makefile                               \
		fencing/test/Makefile                           \
		fencing/test/STONITHDBasicSanityCheck           \
extra/Makefile							\
	extra/resources/Makefile				\
tools/Makefile							\
	tools/haresources2cib.py				\
	tools/hb2openais.sh					\
	tools/crm_primitive.py					\
	tools/crm						\
	tools/shell/Makefile						\
	tools/shell/templates/Makefile						\
	tools/shell/regression/Makefile						\
	tools/shell/regression/regression.sh						\
	tools/shell/regression/lrmregtest-lsb						\
	tools/shell/regression/testcases/Makefile						\
xml/Makefile							\
	xml/pacemaker.rng					\
	xml/resources.rng					\
	xml/constraints.rng					\
	xml/rule.rng						\
	xml/nvset.rng						\
		)

dnl Now process the entire list of files added by previous 
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()

dnl *****************
dnl Configure summary
dnl *****************

AC_MSG_RESULT([])
AC_MSG_RESULT([$PACKAGE configuration:])
AC_MSG_RESULT([  Version                  = ${VERSION} (Build: $BUILD_VERSION)])
AC_MSG_RESULT([  Features                 =${PKG_FEATURES}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Prefix                   = ${prefix}])
AC_MSG_RESULT([  Executables              = ${sbindir}])
AC_MSG_RESULT([  Man pages                = ${mandir}])
AC_MSG_RESULT([  Libraries                = ${libdir}])
AC_MSG_RESULT([  Header files             = ${includedir}])
AC_MSG_RESULT([  Arch-independent files   = ${datadir}])
AC_MSG_RESULT([  State information        = ${localstatedir}])
AC_MSG_RESULT([  System configuration     = ${sysconfdir}])
AC_MSG_RESULT([  AIS Plugins              = ${LCRSODIR}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Use system LTDL          = ${ac_cv_lib_ltdl_lt_dlopen}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  HA group name            = ${CRM_DAEMON_GROUP}])
AC_MSG_RESULT([  HA user name             = ${CRM_DAEMON_USER}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  CFLAGS                   = ${CFLAGS}])
AC_MSG_RESULT([  Libraries                = ${LIBS}])
AC_MSG_RESULT([  Stack Libraries          = ${CLUSTERLIBS}])


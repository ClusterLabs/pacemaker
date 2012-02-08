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

AC_INIT(pacemaker, 1.1.6, pacemaker@oss.clusterlabs.org)
CRM_DTD_VERSION="1.2"

PCMK_FEATURES=""
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

PACKAGE_SERIES=`echo $PACKAGE_VERSION | awk -F. '{ print $1"."$2 }'`
AC_SUBST(PACKAGE_SERIES)
AC_SUBST(PACKAGE_VERSION)

dnl automake >= 1.11 offers --enable-silent-rules for suppressing the output from
dnl normal compilation.  When a failure occurs, it will then display the full 
dnl command line
dnl Wrap in m4_ifdef to avoid breaking on older platforms
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

dnl Example 2.4. Silent Custom Rule to Generate a File
dnl %-bar.pc: %.pc
dnl	$(AM_V_GEN)$(LN_S) $(notdir $^) $@

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

AC_PROG_LEX
AC_PROG_YACC

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
         AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ ]], [[ ]])], [RC=0; AC_MSG_RESULT(yes)],[RC=1; AC_MSG_RESULT(no)])
         return $RC
}

extract_header_define() {
	  AC_MSG_CHECKING(for $2 in $1)
	  Cfile=$srcdir/extract_define.$2.${$}
	  printf "#include <stdio.h>\n" > ${Cfile}.c
	  printf "#include <%s>\n" $1 >> ${Cfile}.c
	  printf "int main(int argc, char **argv) { printf(\"%%s\", %s); return 0; }\n" $2 >> ${Cfile}.c
	  $CC $CFLAGS ${Cfile}.c -o ${Cfile}
	  value=`${Cfile}`
	  AC_MSG_RESULT($value)
	  printf $value
	  rm -rf ${Cfile}.c ${Cfile} ${Cfile}.dSYM
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
     [default=no]])

AC_ARG_ENABLE([fatal-warnings],
[  --enable-fatal-warnings very pedantic and fatal warnings for gcc
     [default=yes]])

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

AC_ARG_ENABLE([no-stack],
    [  --enable-no-stack
       Only build the Policy Engine and pieces needed to support it [default=no]])

AC_ARG_WITH(ais,
    [  --with-ais     
       Support the Corosync messaging and membership layer ],
    [ SUPPORT_CS=$withval ],
    [ SUPPORT_CS=try ],
)

AC_ARG_WITH(corosync,
    [  --with-corosync     
       Support the Corosync messaging and membership layer ],
    [ SUPPORT_CS=$withval ],
    [ SUPPORT_CS=try ],
)

AC_ARG_WITH(heartbeat,
    [  --with-heartbeat     
       Support the Heartbeat messaging and membership layer ],
    [ SUPPORT_HEARTBEAT=$withval ],
    [ SUPPORT_HEARTBEAT=try ],
)

AC_ARG_WITH(cman,
    [  --with-cman     
       Support the consumption of membership and quorum from cman ],
    [ SUPPORT_CMAN=$withval ],
    [ SUPPORT_CMAN=try ],
)

AC_ARG_WITH(cpg,
    [  --with-cs-quorum     
       Support the consumption of membership and quorum from corosync ],
    [ SUPPORT_CS_QUORUM=$withval ],
    [ SUPPORT_CS_QUORUM=try ],
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

AC_ARG_WITH(acl,
    [  --with-acl
       Support CIB ACL ],
    [ SUPPORT_ACL=$withval ],
    [ SUPPORT_ACL=no ],
)

CSPREFIX=""
AC_ARG_WITH(ais-prefix,
    [  --with-ais-prefix=DIR  Prefix used when Corosync was installed [$prefix]],
    [ CSPREFIX=$withval ], 
    [ CSPREFIX=$prefix ])

LCRSODIR=""
AC_ARG_WITH(lcrso-dir, 
    [  --with-lcrso-dir=DIR   Corosync lcrso files. ],
    [ LCRSODIR="$withval" ])

INITDIR=""
AC_ARG_WITH(initdir,
    [  --with-initdir=DIR      directory for init (rc) scripts [${INITDIR}]],
    [ INITDIR="$withval" ])

SUPPORT_TRACING=0
AC_ARG_WITH(tracedata,
    [  --with-tracedata     
       Support the dynamic enablement of addition trace logging ],
    [ SUPPORT_TRACING=$withval ])

SUPPORT_PROFILING=0
AC_ARG_WITH(profiling,
    [  --with-profiling     
       Support gprof profiling ],
    [ SUPPORT_PROFILING=$withval ])

SUPPORT_GCOV=0
AC_ARG_WITH(gcov,
    [  --with-gcov
       Support gcov coverage testing ],
    [ SUPPORT_GCOV=$withval ])

PUBLICAN_BRAND="common"
AC_ARG_WITH(brand,
    [  --with-brand=brand  Brand to use for generated documentation [$PUBLICAN_BRAND]],
    [ PUBLICAN_BRAND="$withval" ])
AC_SUBST(PUBLICAN_BRAND)

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

AC_MSG_NOTICE(Sanitizing ais_prefix: ${CSPREFIX})
case $CSPREFIX in
  dnl For consistency with Heartbeat, map NONE->$prefix
  NONE)	  CSPREFIX=$prefix;;
  prefix) CSPREFIX=$prefix;;
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
if test x"${docdir}" = x""; then
   docdir=${datadir}/doc/${PACKAGE}-${VERSION}
   #docdir=${datadir}/doc/packages/${PACKAGE}
fi
AC_SUBST(docdir)

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
  		CFLAGS="$CFLAGS -I${prefix}/include"
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

ac_save_CFLAGS=$CFLAGS
CFLAGS="-Wall -Werror"

AC_COMPILE_IFELSE(
    [AC_LANG_PROGRAM(
      [
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
      ],
      [
int max = 512;	
uint64_t bignum = 42;
char *buffer = malloc(max);
const char *random = "random";
snprintf(buffer, max-1, "<quorum id=%lu quorate=%s/>", bignum, random);
fprintf(stderr, "Result: %s\n", buffer);
      ]
    )], 
    [U64T="%lu"],
    [U64T="%llu"]
)
CFLAGS=$ac_save_CFLAGS

AC_MSG_RESULT($U64T)
AC_DEFINE_UNQUOTED(U64T, "$U64T", Correct printf format for logging uint64_t)

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
AC_PATH_PROGS(ASCIIDOC, asciidoc)
AC_PATH_PROGS(PUBLICAN, publican)
AC_PATH_PROGS(INKSCAPE, inkscape)
AC_PATH_PROGS(XSLTPROC, xsltproc)
AC_PATH_PROGS(FLEX, flex)
AC_PATH_PROGS(BISON, bison)
AC_PATH_PROGS(FOP, fop)
AC_PATH_PROGS(SSH, ssh, /usr/bin/ssh)
AC_PATH_PROGS(SCP, scp, /usr/bin/scp)
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
   PCMK_FEATURES="$PCMK_FEATURES generated-manpages"
fi

MANPAGE_XSLT=""
if test x"${XSLTPROC}" != x""; then
  AC_MSG_CHECKING(docbook to manpage transform)
  XSLT=`find ${datadir} -name docbook.xsl`
  for xsl in $XSLT; do
    dname=`dirname $xsl`
    bname=`basename $dname`
    if test "$bname" = "manpages"; then
       MANPAGE_XSLT="$xsl"
       break
    fi
  done
fi
AC_MSG_RESULT($MANPAGE_XSLT)
AC_SUBST(MANPAGE_XSLT)

AM_CONDITIONAL(BUILD_XML_HELP, test x"${MANPAGE_XSLT}" != x"")
if test x"${MANPAGE_XSLT}" != x""; then
   PCMK_FEATURES="$PCMK_FEATURES agent-manpages"
fi

AM_CONDITIONAL(BUILD_ASCIIDOC, test x"${ASCIIDOC}" != x"")
if test x"${ASCIIDOC}" != x""; then
   PCMK_FEATURES="$PCMK_FEATURES ascii-docs"
fi

AM_CONDITIONAL(BUILD_DOCBOOK, test x"${PUBLICAN}" != x"" -a x"${INKSCAPE}" != x"")
if test x"${PUBLICAN}" != x"" -a x"${INKSCAPE}" != x""; then
   AC_MSG_NOTICE(Enabling publican)
   PCMK_FEATURES="$PCMK_FEATURES publican-docs"
fi

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

AC_REPLACE_FUNCS(alphasort inet_pton NoSuchFunctionName scandir setenv strerror strchrnul unsetenv strnlen strndup daemon strlcpy strlcat)

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

USE_GHASH_COMPAT=0
AC_CHECK_LIB(glib-2.0, g_hash_table_get_values)
if test "x$ac_cv_lib_glib_2_0_g_hash_table_get_values" != x""yes; then
   AC_MSG_WARN(Your version of Glib is too old, you should have at least 2.14)
   USE_GHASH_COMPAT=1
fi
AC_DEFINE_UNQUOTED(USE_GHASH_COMPAT, $USE_GHASH_COMPAT, Use g_hash_table compatibility functions)
AC_SUBST(USE_GHASH_COMPAT)


if 
    $PKGCONFIG --exists systemd
then
    systemdunitdir=`$PKGCONFIG --variable=systemdsystemunitdir systemd`
    AC_SUBST(systemdunitdir)
fi
AM_CONDITIONAL(HAVE_SYSTEMD, test -n "$systemdunitdir" -a "x$systemdunitdir" != xno)

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
AC_CHECK_MEMBERS([lrm_op_t.rsc_deleted],,,[[#include <lrm/lrm_api.h>]])

dnl ========================================================================
dnl Functions
dnl ========================================================================

AC_CHECK_FUNCS(g_log_set_default_handler)
AC_CHECK_FUNCS(getopt, AC_DEFINE(HAVE_DECL_GETOPT,  1, [Have getopt function]))
AC_CHECK_FUNCS(nanosleep, AC_DEFINE(HAVE_DECL_NANOSLEEP,  1, [Have nanosleep function]))

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
   PCMK_FEATURES="$PCMK_FEATURES ncurses"
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
dnl    Profiling and GProf
dnl ========================================================================

case $SUPPORT_PROFILING in
     1|yes|true) 
	SUPPORT_PROFILING=1

        dnl Enable gprof
	#LIBS="$LIBS -pg"
	#CFLAGS="$CFLAGS -pg"

	dnl Disable various compiler optimizations
	CFLAGS="$CFLAGS -fno-omit-frame-pointer"
	#CFLAGS="$CFLAGS -fno-inline-functions -fno-inline-functions-called-once -fno-optimize-sibling-calls"
	dnl CFLAGS="$CFLAGS -fno-default-inline -fno-inline"

	dnl Update features
	PCMK_FEATURES="$PCMK_FEATURES gprof"
	;;
     *) SUPPORT_PROFILING=0;;
esac
AC_DEFINE_UNQUOTED(SUPPORT_PROFILING, $SUPPORT_PROFILING, Support for gprof profiling)

case $SUPPORT_GCOV in
     1|yes|true) 
	SUPPORT_GCOV=1

        dnl Enable gprof
	#LIBS="$LIBS -pg"
	#CFLAGS="$CFLAGS -pg"

	dnl Disable various compiler optimizations
	CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage -fno-inline -fno-default-inline"

	dnl Turn off optimization so code coverage tool
	dnl can get accurate line numbers
	CFLAGS=`echo "$CFLAGS" | sed -e 's/-O[0-9]*//g'`
	CFLAGS="$CFLAGS -O0"

	dnl Update features
	PCMK_FEATURES="$PCMK_FEATURES gcov"
	;;
     *) SUPPORT_PROFILING=0;;
esac
AC_DEFINE_UNQUOTED(SUPPORT_GCOV, $SUPPORT_GCOV, Support for gcov coverage testing)

case $SUPPORT_TRACING in
     1|yes|true) SUPPORT_TRACING=1; PCMK_FEATURES="$PCMK_FEATURES trace-logging";;
     *) SUPPORT_TRACING=0;;
esac
AC_DEFINE_UNQUOTED(SUPPORT_TRACING, $SUPPORT_TRACING, Support the dynamic enablement of addition trace logging)


dnl ========================================================================
dnl    Cluster infrastructure - Heartbeat / LibQB
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

if test x${enable_no_stack} = xyes; then
    SUPPORT_HEARTBEAT=no
    SUPPORT_CS=no
fi

PKG_CHECK_MODULES(libqb, libqb, HAVE_libqb=1, HAVE_libqb=0)
AC_CHECK_HEADERS(qb/qbipc_common.h)

if test $HAVE_libqb = 1; then
   PCMK_FEATURES="$PCMK_FEATURES libqb"
fi

AC_DEFINE_UNQUOTED(LIBQB_LOGGING, $HAVE_libqb, Use libqb for logging)
AC_DEFINE_UNQUOTED(LIBQB_IPC, 0, Use libqb for IPC)

LIBS="$LIBS $libqb_LIBS"

AC_CHECK_HEADERS(hb_config.h)
AC_CHECK_HEADERS(glue_config.h)
AC_CHECK_HEADERS(agent_config.h)
GLUE_HEADER=none
if test "$ac_cv_header_glue_config_h" = "yes";  then
   GLUE_HEADER=glue_config.h

elif test "$ac_cv_header_hb_config_h" = "yes"; then
   GLUE_HEADER=hb_config.h

else
   AC_MSG_FAILURE(Core development headers were not found)
fi

dnl ===============================================
dnl Variables needed for substitution
dnl ===============================================
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

CRM_STATE_DIR=${localstatedir}/run/crm
AC_DEFINE_UNQUOTED(CRM_STATE_DIR,"$CRM_STATE_DIR", Where to keep state files and sockets)
AC_SUBST(CRM_STATE_DIR)

PE_STATE_DIR="${localstatedir}/lib/pengine"
AC_DEFINE_UNQUOTED(PE_STATE_DIR,"$PE_STATE_DIR", Where to keep PEngine outputs)
AC_SUBST(PE_STATE_DIR)

dnl Eventually move out of the heartbeat dir tree and create compatability code
CRM_CONFIG_DIR="${localstatedir}/lib/heartbeat/crm"
AC_DEFINE_UNQUOTED(CRM_CONFIG_DIR,"$CRM_CONFIG_DIR", Where to keep CIB configuration files)
AC_SUBST(CRM_CONFIG_DIR)

CRM_DAEMON_DIR="${libexecdir}/pacemaker"
AC_DEFINE_UNQUOTED(CRM_DAEMON_DIR,"$CRM_DAEMON_DIR", Location for Pacemaker daemons)
AC_SUBST(CRM_DAEMON_DIR)

HB_DAEMON_DIR=`extract_header_define $GLUE_HEADER HA_LIBHBDIR`
AC_DEFINE_UNQUOTED(HB_DAEMON_DIR,"$HB_DAEMON_DIR", Location for Heartbeat expects Pacemaker daemons to be in)
AC_SUBST(HB_DAEMON_DIR)

dnl Needed so that the Corosync plugin can clear out the directory as Heartbeat does
HA_STATE_DIR=`extract_header_define $GLUE_HEADER HA_VARRUNDIR`
AC_DEFINE_UNQUOTED(HA_STATE_DIR,"$HA_STATE_DIR", Where Heartbeat keeps state files and sockets)
AC_SUBST(HA_STATE_DIR)

CRM_RSCTMP_DIR=
if test "$ac_cv_header_agent_config_h" = "yes";  then
   CRM_RSCTMP_DIR=`extract_header_define agent_config.h HA_RSCTMPDIR`
else
   AC_MSG_WARN(Agents development headers were not found.)
fi

if test x$CRM_RSCTMP_DIR = x; then
   CRM_RSCTMP_DIR="$HA_STATE_DIR/heartbeat/rsctmp"
fi
AC_MSG_CHECKING(Scratch dir for resource agents)
AC_MSG_RESULT($CRM_RSCTMP_DIR)
AC_DEFINE_UNQUOTED(CRM_RSCTMP_DIR,"$CRM_RSCTMP_DIR", Where resource agents should keep state files)
AC_SUBST(CRM_RSCTMP_DIR)

dnl Needed for the location of hostcache in CTS.py
HA_VARLIBHBDIR=`extract_header_define $GLUE_HEADER HA_VARLIBHBDIR`
AC_SUBST(HA_VARLIBHBDIR)

AC_DEFINE_UNQUOTED(UUID_FILE,"$localstatedir/lib/heartbeat/hb_uuid", Location of Heartbeat's UUID file)

OCF_ROOT_DIR=`extract_header_define $GLUE_HEADER OCF_ROOT_DIR`
if test "X$OCF_ROOT_DIR" = X; then
  AC_MSG_ERROR(Could not locate OCF directory)
fi
AC_SUBST(OCF_ROOT_DIR)

OCF_RA_DIR=`extract_header_define $GLUE_HEADER OCF_RA_DIR`
AC_DEFINE_UNQUOTED(OCF_RA_DIR,"$OCF_RA_DIR", Location for OCF RAs)
AC_SUBST(OCF_RA_DIR)

dnl Extract this value from glue_config.h once we no longer support anything else
STONITH_PLUGIN_DIR="$libdir/stonith/plugins/stonith/"
AC_DEFINE_UNQUOTED(STONITH_PLUGIN_DIR,"$STONITH_PLUGIN_DIR", Location for Stonith plugins)
AC_SUBST(STONITH_PLUGIN_DIR)

RH_STONITH_DIR="$sbindir"
AC_DEFINE_UNQUOTED(RH_STONITH_DIR,"$RH_STONITH_DIR", Location for Red Hat Stonith agents)

RH_STONITH_PREFIX="fence_"
AC_DEFINE_UNQUOTED(RH_STONITH_PREFIX,"$RH_STONITH_PREFIX", Prefix for Red Hat Stonith agents)

AC_PATH_PROGS(GIT, git false)
AC_MSG_CHECKING(build version)

BUILD_VERSION=$Format:%H$
if test $BUILD_VERSION != ":%H$"; then
   AC_MSG_RESULT(archive hash: $BUILD_VERSION)

elif test -x $GIT -a -d .git; then
   BUILD_VERSION=`$GIT log --pretty="format:%h" -n 1`
   AC_MSG_RESULT(git hash: $BUILD_VERSION)

else
   # The current directory name make a reasonable default
   # Most generated archives will include the hash or tag 
   BASE=`basename $PWD`
   BUILD_VERSION=`echo $BASE | sed s:.*[Pp]acemaker-::`
   AC_MSG_RESULT(directory based hash: $BUILD_VERSION)
fi

AC_DEFINE_UNQUOTED(BUILD_VERSION, "$BUILD_VERSION", Build version)
AC_SUBST(BUILD_VERSION)


STACKS=""
CLUSTERLIBS=""

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

if test $SUPPORT_HEARTBEAT = 1; then
   STACKS="$STACKS heartbeat"
   AC_DEFINE_UNQUOTED(CCM_LIBRARY, "libccmclient.so.1", Library to load for ccm support)
   AC_DEFINE_UNQUOTED(HEARTBEAT_LIBRARY, "libhbclient.so.1", Library to load for heartbeat support)
fi

AM_CONDITIONAL(BUILD_HEARTBEAT_SUPPORT, test $SUPPORT_HEARTBEAT = 1)
AC_DEFINE_UNQUOTED(SUPPORT_HEARTBEAT, $SUPPORT_HEARTBEAT, Support the Heartbeat messaging and membership layer)
AC_SUBST(SUPPORT_HEARTBEAT)

dnl ========================================================================
dnl    Cluster stack - Corosync
dnl ========================================================================

dnl Normalize the values
case $SUPPORT_CS in
     1|yes|true) missingisfatal=1;;
     try)        missingisfatal=0;;
     *) SUPPORT_CS=no;;
esac

AC_MSG_CHECKING(for native corosync)
COROSYNC_LIBS=""
CS_USES_LIBQB=0

PCMK_SERVICE_ID=9
LCRSODIR="$libdir"

if test $SUPPORT_CS = no; then
    AC_MSG_RESULT(no (disabled))
else
    AC_MSG_RESULT($SUPPORT_CS, with '$CSPREFIX')
    PKG_CHECK_MODULES(cpg,    libcpg) dnl Fatal
    PKG_CHECK_MODULES(cfg,    libcfg) dnl Fatal
    PKG_CHECK_MODULES(cmap,   libcmap,   HAVE_cmap=1,   HAVE_cmap=0)
    PKG_CHECK_MODULES(cman,   libcman,   HAVE_cman=1,   HAVE_cman=0)
    PKG_CHECK_MODULES(confdb, libconfdb, HAVE_confdb=1, HAVE_confdb=0)
    PKG_CHECK_MODULES(fenced, libfenced, HAVE_fenced=1, HAVE_fenced=0)
    PKG_CHECK_MODULES(quorum, libquorum, HAVE_quorum=1, HAVE_quorum=0)
    PKG_CHECK_MODULES(oldipc, libcoroipcc, HAVE_oldipc=1, HAVE_oldipc=0)

    if test $HAVE_oldipc = 1; then
        SUPPORT_CS=1
	CFLAGS="$CFLAGS $oldipc_FLAGS $cpg_FLAGS $cfg_FLAGS"
        COROSYNC_LIBS="$COROSYNC_LIBS $oldipc_LIBS $cpg_LIBS $cfg_LIBS"
    
    elif test $HAVE_libqb = 1; then
        SUPPORT_CS=1
        CS_USES_LIBQB=1
	CFLAGS="$CFLAGS $libqb_FLAGS $cpg_FLAGS $cfg_FLAGS"
        COROSYNC_LIBS="$COROSYNC_LIBS $libqb_LIBS $cpg_LIBS $cfg_LIBS"

    else
        aisreason="corosync/libqb IPC libraries not found by pkg_config"
    fi

    AC_DEFINE_UNQUOTED(HAVE_CONFDB, $HAVE_confdb, Have the old herarchial Corosync config API)
    AC_DEFINE_UNQUOTED(HAVE_CMAP, $HAVE_cmap, Have the new non-herarchial Corosync config API)
fi

if test $SUPPORT_CS = 1 -a x$HAVE_cmap = x1; then
    dnl Support for plugins was removed about the time the cmap API was added
    dnl The only option now is the built-in quorum API
    CFLAGS="$CFLAGS $cmap_CFLAGS $quorum_CFLAGS"
    COROSYNC_LIBS="$COROSYNC_LIBS $cmap_LIBS $quorum_LIBS"
	
    STACKS="$STACKS corosync-native"
    AC_DEFINE_UNQUOTED(SUPPORT_CS_QUORUM, 1, Support the consumption of membership and quorum from corosync)
fi

if test $SUPPORT_CS = 1 -a x$HAVE_confdb = x1; then
    dnl Need confdb to support cman and the plugins
    LCRSODIR=`$PKGCONFIG corosync --variable=lcrsodir`
    STACKS="$STACKS corosync-plugin"
    COROSYNC_LIBS="$COROSYNC_LIBS $confdb_LIBS"

    if test $SUPPORT_CMAN != no; then
        if test $HAVE_cman = 1 -a $HAVE_fenced = 1; then
            SUPPORT_CMAN=1
	    STACKS="$STACKS cman"
            CFLAGS="$CFLAGS $cman_FLAGS $fenced_FLAGS"
            COROSYNC_LIBS="$COROSYNC_LIBS $cman_LIBS $fenced_LIBS"
        fi
    fi
fi

dnl Normalize SUPPORT_CS and SUPPORT_CMAN for use with #if directives
if test $SUPPORT_CMAN != 1; then
    SUPPORT_CMAN=0
fi

if test $SUPPORT_CS = 1; then
    CLUSTERLIBS="$CLUSTERLIBS $COROSYNC_LIBS"

elif test $SUPPORT_CS != no; then
    SUPPORT_CS=0
    if test $missingisfatal = 0; then
        AC_MSG_WARN(Unable to support Corosync: $aisreason) 
    else
        AC_MSG_FAILURE(Unable to support Corosync: $aisreason) 
    fi
fi

AC_DEFINE_UNQUOTED(SUPPORT_COROSYNC, $SUPPORT_CS,    Support the Corosync messaging and membership layer)
AC_DEFINE_UNQUOTED(SUPPORT_CMAN,     $SUPPORT_CMAN,  Support the consumption of membership and quorum from cman)
AC_DEFINE_UNQUOTED(CS_USES_LIBQB,    $CS_USES_LIBQB, Does corosync use libqb for its ipc)
AC_DEFINE_UNQUOTED(PCMK_SERVICE_ID,  $PCMK_SERVICE_ID, Corosync service number)

AM_CONDITIONAL(BUILD_CS_SUPPORT, test $SUPPORT_CS = 1)
AM_CONDITIONAL(BUILD_CS_PLUGIN, test $HAVE_confdb = 1) dnl confdb went away at about the same time as plugins

AC_SUBST(SUPPORT_CMAN)
AC_SUBST(SUPPORT_CS)

dnl
dnl    Cluster stack - Sanity
dnl

if test x${enable_no_stack} = xyes; then
    AC_MSG_NOTICE(No cluster stack supported.  Just building the Policy Engine)
    PCMK_FEATURES="$PCMK_FEATURES no-cluster-stack"
else
    AC_MSG_CHECKING(for supported stacks)
    if test x"$STACKS" = x; then
      AC_MSG_FAILURE(You must support at least one cluster stack (heartbeat or corosync) )
    fi
    AC_MSG_RESULT($STACKS)
    PCMK_FEATURES="$PCMK_FEATURES $STACKS"
fi

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

SNMPLIBS=""

AC_MSG_CHECKING(for snmp support)
if test $SUPPORT_SNMP = no; then
   AC_MSG_RESULT(no (disabled))
   SUPPORT_SNMP=0
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

        dnl    On many systems libcrypto is needed when linking against libsnmp.
        dnl    Check to see if it exists, and if so use it.
	dnl AC_CHECK_LIB(crypto, CRYPTO_free, CRYPTOLIB="-lcrypto",)
	dnl AC_SUBST(CRYPTOLIB)

        AC_CHECK_FUNCS(netsnmp_transport_open_client)
        if test $ac_cv_func_netsnmp_transport_open_client != yes; then
            AC_CHECK_FUNCS(netsnmp_tdomain_transport)
            if test $ac_cv_func_netsnmp_tdomain_transport != yes; then
                SUPPORT_SNMP=no
	    else
                AC_DEFINE_UNQUOTED(NETSNMPV53, 1, [Use the older 5.3 version of the net-snmp API])
            fi
        fi
        LIBS=$savedLibs
    fi

    if test $SUPPORT_SNMP = no; then
   	SNMPLIBS=""
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
   PCMK_FEATURES="$PCMK_FEATURES snmp"
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
   AC_MSG_RESULT(no (disabled))
   SUPPORT_ESMTP=0
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
        PCMK_FEATURES="$PCMK_FEATURES libesmtp"
   fi
fi

AC_SUBST(ESMTPLIBS)
AM_CONDITIONAL(ENABLE_ESMTP, test "$SUPPORT_ESMTP" = "1")
AC_DEFINE_UNQUOTED(ENABLE_ESMTP, $SUPPORT_ESMTP, Build in support for sending mail notifications with ESMTP)

dnl ========================================================================
dnl    ACL 
dnl ========================================================================

case $SUPPORT_ACL in
     1|yes|true) missingisfatal=1;;
     try)        missingisfatal=0;;
     *)		 SUPPORT_ACL=no;;
esac

AC_MSG_CHECKING(for acl support)
if test $SUPPORT_ACL = no; then
   AC_MSG_RESULT(no (disabled))
   SUPPORT_ACL=0
else
   AC_MSG_RESULT($SUPPORT_ACL)

   AC_CHECK_MEMBERS([struct IPC_CHANNEL.farside_uid],
		    [SUPPORT_ACL=1], [SUPPORT_ACL=0], [[#include <clplumbing/ipc.h>]])

   if test $SUPPORT_ACL = 0; then
     	if test $missingisfatal = 0; then
	    AC_MSG_WARN(Unable to support ACL. You need to use cluster-glue >= 1.0.6) 
        else
	    AC_MSG_FAILURE(Unable to support ACL. You need to use cluster-glue >= 1.0.6) 
        fi
   fi
fi

if test $SUPPORT_ACL = 1; then
   PCMK_FEATURES="$PCMK_FEATURES acls"
fi

AM_CONDITIONAL(ENABLE_ACL, test "$SUPPORT_ACL" = "1")
AC_DEFINE_UNQUOTED(ENABLE_ACL, $SUPPORT_ACL, Build in support for CIB ACL)

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
fi
AC_CHECK_LIB(gnutls, gnutls_init)
AC_CHECK_FUNCS(gnutls_priority_set_direct)

AC_SUBST(GNUTLSHEAD)
AC_SUBST(GNUTLSLIBS)


dnl ========================================================================
dnl    System Health
dnl ========================================================================

dnl Check if servicelog development package is installed
SERVICELOG=servicelog-1
SERVICELOG_EXISTS="no"
AC_MSG_CHECKING(for $SERVICELOG packages)
if
    $PKGCONFIG --exists $SERVICELOG
then
    PKG_CHECK_MODULES([SERVICELOG], [servicelog-1])
    SERVICELOG_EXISTS="yes"
fi
AC_MSG_RESULT($SERVICELOG_EXISTS)
AM_CONDITIONAL(BUILD_SERVICELOG, test "$SERVICELOG_EXISTS" = "yes")

dnl Check if OpenIMPI packages and servicelog are installed
OPENIPMI="OpenIPMI OpenIPMIposix"
OPENIPMI_SERVICELOG_EXISTS="no"
AC_MSG_CHECKING(for $SERVICELOG $OPENIPMI packages)
if
    $PKGCONFIG --exists $OPENIPMI $SERVICELOG
then
    PKG_CHECK_MODULES([OPENIPMI_SERVICELOG],[OpenIPMI OpenIPMIposix])
    OPENIPMI_SERVICELOG_EXISTS="yes"
fi
AC_MSG_RESULT($OPENIPMI_SERVICELOG_EXISTS)
AM_CONDITIONAL(BUILD_OPENIPMI_SERVICELOG, test "$OPENIPMI_SERVICELOG_EXISTS" = "yes")

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
	SAVED_CFLAGS="$CFLAGS"
	unset CFLAGS
	CFLAGS="$SAVED_CFLAGS"
	unset SAVED_CFLAGS
fi

if test "$GCC" != yes; then
        CFLAGS="$CFLAGS -g"
	enable_fatal_warnings=no
else
        CFLAGS="$CFLAGS -ggdb"

	# We had to eliminate -Wnested-externs because of libtool changes
        EXTRA_FLAGS="-fgnu89-inline
		-fstack-protector-all
		-Wall
		-Waggregate-return
		-Wbad-function-cast 
		-Wcast-align 
		-Wdeclaration-after-statement
		-Wendif-labels
		-Wfloat-equal
		-Wformat=2
		-Wformat-security
		-Wformat-nonliteral
		-Wmissing-prototypes 
		-Wmissing-declarations 
		-Wnested-externs
		-Wno-long-long
		-Wno-strict-aliasing
		-Wno-unused-but-set-variable
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

	if test "x${enable_ansi}" = xyes && cc_supports_flag -std=iso9899:199409 ; then
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
QUIET_LIBTOOL_OPTS=""
QUIET_MAKE_OPTS=""
if test "x${enable_quiet}" = "xyes"; then
   QUIET_LIBTOOL_OPTS="--quiet"
   QUIET_MAKE_OPTS="--quiet"
fi

AC_MSG_RESULT(Supress make details: ${enable_quiet})

dnl Put the above variables to use
LIBTOOL="${LIBTOOL} --tag=CC \$(QUIET_LIBTOOL_OPTS)"
MAKE="${MAKE} \$(QUIET_MAKE_OPTS)"

AC_SUBST(CC)
AC_SUBST(MAKE)
AC_SUBST(LIBTOOL)
AC_SUBST(QUIET_MAKE_OPTS)
AC_SUBST(QUIET_LIBTOOL_OPTS)
AC_DEFINE_UNQUOTED(CRM_FEATURES, "$PCMK_FEATURES", Set of enabled features)
AC_SUBST(PCMK_FEATURES)

dnl The Makefiles and shell scripts we output
AC_CONFIG_FILES(Makefile				        \
cts/Makefile					        	\
	cts/CTSvars.py						\
	cts/LSBDummy						\
	cts/benchmark/Makefile					\
		cts/benchmark/clubench				\
cib/Makefile							\
crmd/Makefile							\
pengine/Makefile						\
	pengine/regression.core.sh				\
doc/Makefile							\
	doc/Pacemaker_Explained/publican.cfg			\
	doc/Clusters_from_Scratch/publican.cfg			\
include/Makefile						\
	include/crm/Makefile					\
		include/crm/common/Makefile			\
		include/crm/pengine/Makefile			\
replace/Makefile						\
lib/Makefile							\
	lib/pcmk.pc						\
	lib/pcmk-pe.pc						\
	lib/pcmk-cib.pc						\
	lib/ais/Makefile					\
	lib/common/Makefile					\
	lib/cluster/Makefile					\
	lib/cib/Makefile					\
	lib/pengine/Makefile					\
	lib/transition/Makefile					\
	lib/fencing/Makefile					\
	lib/plugins/Makefile					\
		lib/plugins/lrm/Makefile			\
mcp/Makefile							\
	mcp/pacemaker						\
	mcp/pacemaker.service					\
fencing/Makefile                                                \
extra/Makefile							\
	extra/resources/Makefile				\
	extra/rgmanager/Makefile				\
tools/Makefile							\
	tools/crm_report					\
	tools/coverage.sh					\
	tools/hb2openais.sh					\
	tools/crm_primitive.py					\
shell/Makefile							\
	shell/templates/Makefile				\
	shell/regression/Makefile				\
	shell/regression/testcases/Makefile			\
	shell/modules/Makefile					\
	shell/modules/ui.py					\
	shell/modules/ra.py					\
	shell/modules/vars.py					\
	shell/modules/help.py					\
xml/Makefile							\
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
AC_MSG_RESULT([  Features                 =${PCMK_FEATURES}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Prefix                   = ${prefix}])
AC_MSG_RESULT([  Executables              = ${sbindir}])
AC_MSG_RESULT([  Man pages                = ${mandir}])
AC_MSG_RESULT([  Libraries                = ${libdir}])
AC_MSG_RESULT([  Header files             = ${includedir}])
AC_MSG_RESULT([  Arch-independent files   = ${datadir}])
AC_MSG_RESULT([  State information        = ${localstatedir}])
AC_MSG_RESULT([  System configuration     = ${sysconfdir}])
AC_MSG_RESULT([  Corosync Plugins         = ${LCRSODIR}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  Use system LTDL          = ${ac_cv_lib_ltdl_lt_dlopen}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  HA group name            = ${CRM_DAEMON_GROUP}])
AC_MSG_RESULT([  HA user name             = ${CRM_DAEMON_USER}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  CFLAGS                   = ${CFLAGS}])
AC_MSG_RESULT([  Libraries                = ${LIBS}])
AC_MSG_RESULT([  Stack Libraries          = ${CLUSTERLIBS}])


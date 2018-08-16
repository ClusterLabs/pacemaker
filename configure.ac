dnl
dnl autoconf for Pacemaker
dnl
dnl Copyright 2009-2018 Andrew Beekhof <andrew@beekhof.net>
dnl
dnl This source code is licensed under the GNU General Public License version 2
dnl or later (GPLv2+) WITHOUT ANY WARRANTY.

dnl ===============================================
dnl Bootstrap
dnl ===============================================
AC_PREREQ(2.64)

AC_CONFIG_MACRO_DIR([m4])
AC_DEFUN([AC_DATAROOTDIR_CHECKED])

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

m4_include([version.m4])
AC_INIT([pacemaker], VERSION_NUMBER, [users@clusterlabs.org], [pacemaker],
        PCMK_URL)

PCMK_FEATURES=""

AC_CONFIG_AUX_DIR(.)
AC_CANONICAL_HOST

dnl Where #defines go (e.g. `AC_CHECK_HEADERS' below)
dnl
dnl Internal header: include/config.h
dnl   - Contains ALL defines
dnl   - include/config.h.in is generated automatically by autoheader
dnl   - NOT to be included in any header files except crm_internal.h
dnl     (which is also not to be included in any other header files)
dnl
dnl External header: include/crm_config.h
dnl   - Contains a subset of defines checked here
dnl   - Manually edit include/crm_config.h.in to have configure include
dnl     new defines
dnl   - Should not include HAVE_* defines
dnl   - Safe to include anywhere
AC_CONFIG_HEADERS([include/config.h include/crm_config.h])

AC_ARG_WITH(version,
    [  --with-version=version   Override package version (if you are a packager needing to pretend) ],
    [ PACKAGE_VERSION="$withval" ])

AC_ARG_WITH(pkg-name,
    [  --with-pkg-name=name     Override package name (if you are a packager needing to pretend) ],
    [ PACKAGE_NAME="$withval" ])

dnl 1.11:           minimum automake version required
dnl foreign:        don't require GNU-standard top-level files
dnl silent-rules:   allow "--enable-silent-rules" (no-op in 1.13+)
dnl subdir-objects: keep .o's with their .c's (no-op in 2.0+)
AM_INIT_AUTOMAKE([1.11 foreign silent-rules subdir-objects])

dnl Example 2.4. Silent Custom Rule to Generate a File
dnl %-bar.pc: %.pc
dnl	$(AM_V_GEN)$(LN_S) $(notdir $^) $@

AC_DEFINE_UNQUOTED(PACEMAKER_VERSION, "$PACKAGE_VERSION",
                   [Current pacemaker version])

dnl Versioned attributes implementation is not yet production-ready
AC_DEFINE_UNQUOTED(ENABLE_VERSIONED_ATTRS, 0, [Enable versioned attributes])

PACKAGE_SERIES=`echo $PACKAGE_VERSION | awk -F. '{ print $1"."$2 }'`
AC_SUBST(PACKAGE_SERIES)
AC_SUBST(PACKAGE_VERSION)

CC_IN_CONFIGURE=yes
export CC_IN_CONFIGURE

LDD=ldd

dnl ========================================================================
dnl Compiler characteristics
dnl ========================================================================

AC_PROG_CC dnl Can force other with environment variable "CC".
AC_PROG_CC_STDC
gl_EARLY
gl_INIT

LT_INIT([dlopen])
LTDL_INIT([convenience])

AC_TYPE_SIZE_T
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)

dnl ===============================================
dnl Helpers
dnl ===============================================
cc_supports_flag() {
    local CFLAGS="-Werror $@"
    AC_MSG_CHECKING(whether $CC supports "$@")
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ ]], [[ ]])],
                      [RC=0; AC_MSG_RESULT(yes)],
                      [RC=1; AC_MSG_RESULT(no)])
    return $RC
}

# Some tests need to use their own CFLAGS

cc_temp_flags() {
    ac_save_CFLAGS="$CFLAGS"
    CFLAGS="$*"
}

cc_restore_flags() {
    CFLAGS=$ac_save_CFLAGS
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
    [  --enable-ansi  Force GCC to compile to ANSI standard for older compilers. @<:@no@:>@])

AC_ARG_ENABLE([fatal-warnings],
    [  --enable-fatal-warnings  Enable pedantic and fatal warnings for gcc @<:@yes@:>@])

AC_ARG_ENABLE([quiet],
    [  --enable-quiet  Suppress make output unless there is an error @<:@no@:>@])

AC_ARG_ENABLE([no-stack],
    [  --enable-no-stack  Build only the scheduler and its requirements @<:@no@:>@])

AC_ARG_ENABLE([upstart],
    [  --enable-upstart  Enable support for managing resources via Upstart @<:@try@:>@ ],
    [],
    [enable_upstart=try],
)

AC_ARG_ENABLE([systemd],
    [  --enable-systemd  Enable support for managing resources via systemd @<:@try@:>@],
    [],
    [enable_systemd=try],
)

AC_ARG_ENABLE(hardening,
    [  --enable-hardening  Harden the resulting executables/libraries @<:@try@:>@],
    [ HARDENING="${enableval}" ],
    [ HARDENING=try ],
)

# By default, we add symlinks at the pre-2.0.0 daemon name locations, so that:
# (1) tools that directly invoke those names for metadata etc. will still work
# (2) this installation can be used in a bundle container image used with
#     cluster hosts running Pacemaker 1.1.17+
# If you know your target systems will not have any need for it, you can
# disable this option. Once the above use cases are no longer in wide use, we
# can disable this option by default, and once we no longer want to support
# them at all, we can drop the option altogether.
AC_ARG_ENABLE(legacy-links,
    [  --enable-legacy-links  Add symlinks for old daemon names @<:@yes@:>@],
    [ LEGACY_LINKS="${enableval}" ],
    [ LEGACY_LINKS=yes ],
)
AM_CONDITIONAL(BUILD_LEGACY_LINKS, test "x${LEGACY_LINKS}" = "xyes")

AC_ARG_WITH(corosync,
    [  --with-corosync  Support the Corosync messaging and membership layer ],
    [ SUPPORT_CS=$withval ],
    [ SUPPORT_CS=try ],
)

AC_ARG_WITH(nagios,
    [  --with-nagios  Support nagios remote monitoring ],
    [ SUPPORT_NAGIOS=$withval ],
    [ SUPPORT_NAGIOS=try ],
)

AC_ARG_WITH(nagios-plugin-dir,
    [  --with-nagios-plugin-dir=DIR  Directory for nagios plugins @<:@LIBEXECDIR/nagios/plugins@:>@],
    [ NAGIOS_PLUGIN_DIR="$withval" ]
)

AC_ARG_WITH(nagios-metadata-dir,
    [  --with-nagios-metadata-dir=DIR  Directory for nagios plugins metadata @<:@DATADIR/nagios/plugins-metadata@:>@],
    [ NAGIOS_METADATA_DIR="$withval" ]
)

AC_ARG_WITH(acl,
    [  --with-acl  Support CIB ACL ],
    [ SUPPORT_ACL=$withval ],
    [ SUPPORT_ACL=yes ],
)

AC_ARG_WITH(cibsecrets,
    [  --with-cibsecrets  Support separate file for CIB secrets ],
    [ SUPPORT_CIBSECRETS=$withval ],
    [ SUPPORT_CIBSECRETS=no ],
)

PCMK_GNUTLS_PRIORITIES="NORMAL"
AC_ARG_WITH(gnutls-priorities,
    [  --with-gnutls-priorities  GnuTLS cipher priorities @<:@NORMAL@:>@ ],
    [ test x"$withval" = x"no" || PCMK_GNUTLS_PRIORITIES="$withval" ])

INITDIR=""
AC_ARG_WITH(initdir,
    [  --with-initdir=DIR  Directory for init (rc) scripts],
    [ INITDIR="$withval" ])

SUPPORT_PROFILING=0
AC_ARG_WITH(profiling,
    [  --with-profiling  Disable optimizations for effective profiling ],
    [ SUPPORT_PROFILING=$withval ])

AC_ARG_WITH(coverage,
    [  --with-coverage   Disable optimizations for effective profiling ],
    [ SUPPORT_COVERAGE=$withval ])

PUBLICAN_BRAND="common"
AC_ARG_WITH(brand,
    [  --with-brand=brand  Brand to use for generated documentation (set empty for no docs) @<:@common@:>@],
    [ test x"$withval" = x"no" || PUBLICAN_BRAND="$withval" ])
AC_SUBST(PUBLICAN_BRAND)

CONFIGDIR=""
AC_ARG_WITH(configdir,
    [  --with-configdir=DIR  Directory for Pacemaker configuration file @<:@SYSCONFDIR/sysconfig@:>@],
    [ CONFIGDIR="$withval" ]
)

CRM_LOG_DIR=""
AC_ARG_WITH(logdir,
    [  --with-logdir=DIR  Directory for Pacemaker log file @<:@LOCALSTATEDIR/log/pacemaker@:>@ ],
    [ CRM_LOG_DIR="$withval" ]
)

CRM_BUNDLE_DIR=""
AC_ARG_WITH(bundledir,
    [  --with-bundledir=DIR  Directory for Pacemaker bundle logs @<:@LOCALSTATEDIR/log/pacemaker/bundles@:>@ ],
    [ CRM_BUNDLE_DIR="$withval" ]
)

dnl ===============================================
dnl General Processing
dnl ===============================================

AC_PROG_LN_S
AC_PROG_MKDIR_P

if cc_supports_flag -Werror; then
    WERROR="-Werror"
else
    WERROR=""
fi

# Normalize enable_fatal_warnings (defaulting to yes, when compiler supports it)
if test "x${enable_fatal_warnings}" != "xno" ; then
    if test "$GCC" = "yes" && test "x${WERROR}" != "x" ; then
        enable_fatal_warnings=yes
    else
        AC_MSG_NOTICE(Compiler does not support fatal warnings)
        enable_fatal_warnings=no
    fi
fi

INIT_EXT=""
echo Our Host OS: $host_os/$host

AC_MSG_NOTICE(Sanitizing prefix: ${prefix})
case $prefix in
    NONE)
        prefix=/usr
        dnl Fix default variables - "prefix" variable if not specified
        if test "$localstatedir" = "\${prefix}/var"; then
            localstatedir="/var"
        fi
        if test "$sysconfdir" = "\${prefix}/etc"; then
            sysconfdir="/etc"
        fi
        ;;
esac

AC_MSG_NOTICE(Sanitizing exec_prefix: ${exec_prefix})
case $exec_prefix in
    prefix|NONE)
        exec_prefix=$prefix
        ;;
esac

AC_MSG_NOTICE(Sanitizing INITDIR: ${INITDIR})
case $INITDIR in
    prefix) INITDIR=$prefix;;
    "")
        AC_MSG_CHECKING(which init (rc) directory to use)
        for initdir in /etc/init.d /etc/rc.d/init.d /sbin/init.d \
            /usr/local/etc/rc.d /etc/rc.d
        do
            if
                test -d $initdir
            then
                INITDIR=$initdir
                break
            fi
        done
        AC_MSG_RESULT($INITDIR)
        ;;
esac
AC_SUBST(INITDIR)

AC_MSG_NOTICE(Sanitizing libdir: ${libdir})
case $libdir in
    prefix|NONE)
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

dnl Expand autoconf variables so that we don't end up with '${prefix}'
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
fi
AC_SUBST(docdir)
if test x"${CONFIGDIR}" = x""; then
    CONFIGDIR="${sysconfdir}/sysconfig"
fi
AC_SUBST(CONFIGDIR)

if test x"${CRM_LOG_DIR}" = x""; then
    CRM_LOG_DIR="${localstatedir}/log/pacemaker"
fi
AC_DEFINE_UNQUOTED(CRM_LOG_DIR,"$CRM_LOG_DIR", Location for Pacemaker log file)
AC_SUBST(CRM_LOG_DIR)

if test x"${CRM_BUNDLE_DIR}" = x""; then
    CRM_BUNDLE_DIR="${localstatedir}/log/pacemaker/bundles"
fi
AC_DEFINE_UNQUOTED(CRM_BUNDLE_DIR,"$CRM_BUNDLE_DIR", Location for Pacemaker bundle logs)
AC_SUBST(CRM_BUNDLE_DIR)


if test x"${PCMK_GNUTLS_PRIORITIES}" = x""; then
    AC_MSG_ERROR([Empty string not applicable with --with-gnutls-priorities])
fi
AC_DEFINE_UNQUOTED([PCMK_GNUTLS_PRIORITIES], ["$PCMK_GNUTLS_PRIORITIES"],
                   [GnuTLS cipher priorities])

for j in prefix exec_prefix bindir sbindir libexecdir datadir sysconfdir \
    sharedstatedir localstatedir libdir includedir oldincludedir infodir \
    mandir INITDIR docdir CONFIGDIR
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
    *bsd*)
        AC_DEFINE_UNQUOTED(ON_BSD, 1, Compiling for BSD platform)
        LIBS="-L/usr/local/lib"
        CPPFLAGS="$CPPFLAGS -I/usr/local/include"
        INIT_EXT=".sh"
        ;;
    *solaris*)
        AC_DEFINE_UNQUOTED(ON_SOLARIS, 1, Compiling for Solaris platform)
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

AC_SUBST(INIT_EXT)
AC_MSG_NOTICE(Host CPU: $host_cpu)

case "$host_cpu" in
    ppc64|powerpc64)
        case $CFLAGS in
         *powerpc64*)
             ;;
         *)
             if test "$GCC" = yes; then
                 CFLAGS="$CFLAGS -m64"
             fi
             ;;
        esac
        ;;
esac

# C99 doesn't guarantee uint64_t type and related format specifiers, but
# prerequisites, corosync + libqb, use that widely, so the target platforms
# are already pre-constrained to those "64bit-clean" (doesn't imply native
# bit width) and hence we deliberately refrain from artificial surrogates
# (sans manipulation through cached values).
AC_CACHE_VAL(
    [pcmk_cv_decl_inttypes],
    [
        AC_CHECK_DECLS(
            [PRIu64, PRIu32, PRIx32,
             SCNu64],
            [pcmk_cv_decl_inttypes="PRIu64 PRIu32 PRIx32 SCNu64"],
            [
                # test shall only react on "no" cached result & error out respectively
                if test "x$ac_cv_have_decl_PRIu64" = xno; then
                    AC_MSG_ERROR([lack of inttypes.h based specifier serving uint64_t (PRIu64)])
                elif test "x$ac_cv_have_decl_PRIu32" = xno; then
                    AC_MSG_ERROR([lack of inttypes.h based specifier serving uint32_t (PRIu32)])
                elif test "x$ac_cv_have_decl_PRIx32" = xno; then
                    AC_MSG_ERROR([lack of inttypes.h based hexa specifier serving uint32_t (PRIx32)])
                elif test "x$ac_cv_have_decl_SCNu64" = xno; then
                    AC_MSG_ERROR([lack of inttypes.h based specifier gathering uint64_t (SCNu64)])
                fi
            ],
            [[#include <inttypes.h>]]
        )
    ]
)
(
    set $pcmk_cv_decl_inttypes
    AC_DEFINE_UNQUOTED([U64T],  [$1], [Correct format specifier for U64T])
    AC_DEFINE_UNQUOTED([U32T],  [$2], [Correct format specifier for U32T])
    AC_DEFINE_UNQUOTED([X32T],  [$3], [Correct format specifier for X32T])
    AC_DEFINE_UNQUOTED([U64TS], [$4], [Correct format specifier for U64TS])
)

dnl ===============================================
dnl Program Paths
dnl ===============================================

PATH="$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/bin"
export PATH

dnl Replacing AC_PROG_LIBTOOL with AC_CHECK_PROG because LIBTOOL
dnl was NOT being expanded all the time thus causing things to fail.
AC_CHECK_PROGS(LIBTOOL, glibtool libtool libtool15 libtool13)

dnl Pacemaker's executable python scripts will invoke the python specified by
dnl configure's PYTHON variable. If not specified, AM_PATH_PYTHON will check a
dnl built-in list with (unversioned) "python" having precedence. To configure
dnl Pacemaker to use a specific python interpreter version, define PYTHON
dnl when calling configure, for example: ./configure PYTHON=/usr/bin/python3.6

dnl Ensure PYTHON is an absolute path
AC_PATH_PROG([PYTHON], [$PYTHON])

case "x$PYTHON" in
    x*python3*|x*platform-python*)
        dnl When used with Python 3, Pacemaker requires a minimum of 3.2
        AM_PATH_PYTHON([3.2])
        ;;
    *)
        dnl Otherwise, Pacemaker requires a minimum of 2.7
        AM_PATH_PYTHON([2.7])
        ;;
esac

AC_CHECK_PROGS(MAKE, gmake make)
AC_PATH_PROGS(HTML2TXT, lynx w3m)
AC_PATH_PROGS(HELP2MAN, help2man)
AC_PATH_PROGS(POD2MAN, pod2man, pod2man)
AC_PATH_PROGS(ASCIIDOC, asciidoc)
AC_PATH_PROGS(PUBLICAN, publican)
AC_PATH_PROGS(INKSCAPE, inkscape)
AC_PATH_PROGS(XSLTPROC, xsltproc)
AC_PATH_PROGS(XMLCATALOG, xmlcatalog)
AC_PATH_PROGS(FOP, fop)
AC_PATH_PROGS(SSH, ssh, /usr/bin/ssh)
AC_PATH_PROGS(SCP, scp, /usr/bin/scp)
AC_PATH_PROGS(TAR, tar)
AC_PATH_PROGS(MD5, md5)
dnl BASH is already an environment variable, so use something else
AC_PATH_PROG([BASH_PATH], [bash])
AC_PATH_PROGS(TEST, test)
PKG_PROG_PKG_CONFIG
AC_PATH_PROGS(VALGRIND_BIN, valgrind, /usr/bin/valgrind)
AC_DEFINE_UNQUOTED(VALGRIND_BIN, "$VALGRIND_BIN", Valgrind command)

if test x"${LIBTOOL}" = x""; then
    AC_MSG_ERROR(You need (g)libtool installed in order to build ${PACKAGE})
fi
if test x"${MAKE}" = x""; then
    AC_MSG_ERROR(You need (g)make installed in order to build ${PACKAGE})
fi

dnl Bash is needed for building man pages and running regression tests
if test x"${BASH_PATH}" = x""; then
    AC_MSG_ERROR(bash must be installed in order to build ${PACKAGE})
fi

AM_CONDITIONAL(BUILD_HELP, test x"${HELP2MAN}" != x"")
if test x"${HELP2MAN}" != x""; then
    PCMK_FEATURES="$PCMK_FEATURES generated-manpages"
fi

MANPAGE_XSLT=""
if test x"${XSLTPROC}" != x""; then
    AC_MSG_CHECKING(docbook to manpage transform)
    # first try to figure out correct template using xmlcatalog query,
    # resort to extensive (semi-deterministic) file search if that fails
    DOCBOOK_XSL_URI='http://docbook.sourceforge.net/release/xsl/current'
    DOCBOOK_XSL_PATH='manpages/docbook.xsl'
    MANPAGE_XSLT=$(${XMLCATALOG} "" ${DOCBOOK_XSL_URI}/${DOCBOOK_XSL_PATH} \
                   | sed -n 's|^file://||p;q')
    if test x"${MANPAGE_XSLT}" = x""; then
        DIRS=$(find "${datadir}" -name $(basename $(dirname ${DOCBOOK_XSL_PATH})) \
               -type d | LC_ALL=C sort)
        XSLT=$(basename ${DOCBOOK_XSL_PATH})
        for d in ${DIRS}; do
            if test -f "${d}/${XSLT}"; then
                 MANPAGE_XSLT="${d}/${XSLT}"
                 break
            fi
        done
    fi
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

publican_intree_brand=no
if test x"${PUBLICAN_BRAND}" != x"" \
   && test x"${PUBLICAN}" != x"" \
   && test x"${INKSCAPE}" != x""; then

    dnl special handling for clusterlabs brand (possibly in-tree version used)
    test "${PUBLICAN_BRAND}" != "clusterlabs" \
        || test -d /usr/share/publican/Common_Content/clusterlabs
    if test $? -ne 0; then
        dnl Unknown option: brand_dir vs. Option brand_dir requires an argument
        if ${PUBLICAN} build --brand_dir 2>&1 | grep -Eq 'brand_dir$'; then
            AC_MSG_WARN([Cannot use in-tree clusterlabs brand, resorting to common])
            PUBLICAN_BRAND=common
        else
            publican_intree_brand=yes
        fi
    fi
    AC_MSG_NOTICE([Enabling Publican-generated documentation using ${PUBLICAN_BRAND} brand])
    PCMK_FEATURES="$PCMK_FEATURES publican-docs"
fi
AM_CONDITIONAL([BUILD_DOCBOOK],
               [test x"${PUBLICAN_BRAND}" != x"" \
                && test x"${PUBLICAN}" != x"" \
                && test x"${INKSCAPE}" != x""])
AM_CONDITIONAL([PUBLICAN_INTREE_BRAND],
               [test x"${publican_intree_brand}" = x"yes"])

dnl Pacemaker's shell scripts (and thus man page builders) rely on GNU getopt
AC_MSG_CHECKING([for GNU-compatible getopt])
IFS_orig=$IFS
IFS=:
for PATH_DIR in $PATH; do
    IFS=$IFS_orig
    GETOPT_PATH="${PATH_DIR}/getopt"
    if test -f "$GETOPT_PATH" && test -x "$GETOPT_PATH" ; then
        $GETOPT_PATH -T >/dev/null 2>/dev/null
        if test $? -eq 4; then
            break
        fi
    fi
    GETOPT_PATH=""
done
IFS=$IFS_orig
if test -n "$GETOPT_PATH"; then
  AC_MSG_RESULT([$GETOPT_PATH])
else
  AC_MSG_RESULT([no])
  AC_MSG_ERROR(Pacemaker build requires a GNU-compatible getopt)
fi
AC_SUBST([GETOPT_PATH])

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
dnl     strnlen: is a gnu function similar to strlen, but safer.
dnl            We wrote a tolearably-fast replacement function for it.
dnl
dnl     strndup: is a gnu function similar to strdup, but safer.
dnl            We wrote a tolearably-fast replacement function for it.

AC_REPLACE_FUNCS(alphasort NoSuchFunctionName scandir setenv strerror strchrnul unsetenv strnlen strndup)

dnl ===============================================
dnl Libraries
dnl ===============================================
AC_CHECK_LIB(socket, socket)                    dnl -lsocket
AC_CHECK_LIB(c, dlopen)                         dnl if dlopen is in libc...
AC_CHECK_LIB(dl, dlopen)                        dnl -ldl (for Linux)
AC_CHECK_LIB(rt, sched_getscheduler)            dnl -lrt (for Tru64)
AC_CHECK_LIB(gnugetopt, getopt_long)            dnl -lgnugetopt ( if available )
AC_CHECK_LIB(pam, pam_start)                    dnl -lpam (if available)

AC_CHECK_FUNCS([sched_setscheduler])

AC_CHECK_LIB(uuid, uuid_parse)                  dnl load the library if necessary
AC_CHECK_FUNCS(uuid_unparse)                    dnl OSX ships uuid_* as standard functions

AC_CHECK_HEADERS(uuid/uuid.h)

if test "x$ac_cv_func_uuid_unparse" != xyes; then
    AC_MSG_ERROR(You do not have the libuuid development package installed)
fi

if test x"${PKG_CONFIG}" = x""; then
    AC_MSG_ERROR(You need pkgconfig installed in order to build ${PACKAGE})
fi

# Require glib 2.16.0 (2008-03) or later for g_hash_table_iter_init() etc.
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.16.0],
                  [CPPFLAGS="${CPPFLAGS} ${GLIB_CFLAGS}"
                   LIBS="${LIBS} ${GLIB_LIBS}"])

#
# Where is dlopen?
#
if test "$ac_cv_lib_c_dlopen" = yes; then
    LIBADD_DL=""
elif test "$ac_cv_lib_dl_dlopen" = yes; then
    LIBADD_DL=-ldl
else
    LIBADD_DL=${lt_cv_dlopen_libs}
fi

dnl FreeBSD needs -lcompat for ftime() used by lrmd.c
AC_CHECK_LIB([compat], [ftime], [COMPAT_LIBS='-lcompat'])
AC_SUBST(COMPAT_LIBS)

dnl ========================================================================
dnl Headers
dnl ========================================================================

dnl Some distributions insert #warnings into deprecated headers such as
dnl timeb.h. If we will enable fatal warnings for the build, then enable
dnl them for the header checks as well, otherwise the build could fail
dnl even though the header check succeeds. (We should probably be doing
dnl this in more places.)
if test "x${enable_fatal_warnings}" = xyes ; then
    cc_temp_flags "$CFLAGS $WERROR"
fi
AC_CHECK_HEADERS(arpa/inet.h)
AC_CHECK_HEADERS(ctype.h)
AC_CHECK_HEADERS(dirent.h)
AC_CHECK_HEADERS(errno.h)
AC_CHECK_HEADERS(getopt.h)
AC_CHECK_HEADERS(glib.h)
AC_CHECK_HEADERS(grp.h)
AC_CHECK_HEADERS(limits.h)
AC_CHECK_HEADERS(linux/swab.h)
AC_CHECK_HEADERS(malloc.h)
AC_CHECK_HEADERS(netdb.h)
AC_CHECK_HEADERS(netinet/in.h)
AC_CHECK_HEADERS(netinet/ip.h)
AC_CHECK_HEADERS(pwd.h)
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
AC_CHECK_HEADERS(sys/reboot.h)
AC_CHECK_HEADERS(sys/resource.h)
AC_CHECK_HEADERS(sys/socket.h)
AC_CHECK_HEADERS(sys/signalfd.h)
AC_CHECK_HEADERS(sys/sockio.h)
AC_CHECK_HEADERS(sys/stat.h)
AC_CHECK_HEADERS(sys/time.h)
AC_CHECK_HEADERS(sys/timeb.h)
AC_CHECK_HEADERS(sys/types.h)
AC_CHECK_HEADERS(sys/utsname.h)
AC_CHECK_HEADERS(sys/wait.h)
AC_CHECK_HEADERS(time.h)
AC_CHECK_HEADERS(unistd.h)
if test "x${enable_fatal_warnings}" = xyes ; then
    cc_restore_flags
fi

dnl These headers need prerequisites before the tests will pass
dnl AC_CHECK_HEADERS(net/if.h)

PKG_CHECK_MODULES(LIBXML2, [libxml-2.0],
                  [CPPFLAGS="${CPPFLAGS} ${LIBXML2_CFLAGS}"
                   LIBS="${LIBS} ${LIBXML2_LIBS}"])
AC_CHECK_HEADERS(libxml/xpath.h)
if test "$ac_cv_header_libxml_xpath_h" != "yes"; then
    AC_MSG_ERROR(libxml development headers not found)
fi

AC_CHECK_LIB(xslt, xsltApplyStylesheet, [],
             AC_MSG_ERROR(Unsupported libxslt library version))
AC_CHECK_HEADERS(libxslt/xslt.h)
if test "$ac_cv_header_libxslt_xslt_h" != "yes"; then
    AC_MSG_ERROR(libxslt development headers not found)
fi

AC_CACHE_CHECK(whether __progname and __progname_full are available,
               pf_cv_var_progname,
               AC_TRY_LINK([extern char *__progname, *__progname_full;],
                           [__progname = "foo"; __progname_full = "foo bar";],
                           pf_cv_var_progname="yes", pf_cv_var_progname="no"))

if test "$pf_cv_var_progname" = "yes"; then
    AC_DEFINE(HAVE___PROGNAME,1,[ ])
fi

dnl ========================================================================
dnl Structures
dnl ========================================================================

AC_CHECK_MEMBERS([struct tm.tm_gmtoff],,,[[#include <time.h>]])
AC_CHECK_MEMBERS([lrm_op_t.rsc_deleted],,,[[#include <lrm/lrm_api.h>]])
AC_CHECK_MEMBER([struct dirent.d_type],
    AC_DEFINE(HAVE_STRUCT_DIRENT_D_TYPE,1,[Define this if struct dirent has d_type]),,
    [#include <dirent.h>])

dnl ========================================================================
dnl Functions
dnl ========================================================================

AC_CHECK_FUNCS(getopt, AC_DEFINE(HAVE_DECL_GETOPT,  1, [Have getopt function]))
AC_CHECK_FUNCS(nanosleep, AC_DEFINE(HAVE_DECL_NANOSLEEP,  1, [Have nanosleep function]))

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
dnl sighandler_t is missing from Illumos, Solaris11 systems
dnl ========================================================================

AC_MSG_CHECKING([for sighandler_t])
AC_TRY_COMPILE([#include <signal.h>],[sighandler_t *f;],
has_sighandler_t=yes,has_sighandler_t=no)
AC_MSG_RESULT($has_sighandler_t)
if test "$has_sighandler_t" = "yes" ; then
    AC_DEFINE( HAVE_SIGHANDLER_T, 1, [Define if sighandler_t available] )
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
                 [AC_DEFINE(HAVE_LIBNCURSES,1, have ncurses library)])
    CURSESLIBS=`$PKG_CONFIG --libs ncurses` || CURSESLIBS='-lncurses'
fi

if test "$ac_cv_header_ncurses_ncurses_h" = "yes"; then
    AC_CHECK_LIB(ncurses, printw,
                 [AC_DEFINE(HAVE_LIBNCURSES,1, have ncurses library)])
    CURSESLIBS=`$PKG_CONFIG --libs ncurses` || CURSESLIBS='-lncurses'
fi

dnl Only look for non-n-library if there was no n-library.
if test X"$CURSESLIBS" = X"" -a "$ac_cv_header_curses_h" = "yes"; then
    AC_CHECK_LIB(curses, printw,
                 [CURSESLIBS='-lcurses'; AC_DEFINE(HAVE_LIBCURSES,1, have curses library)])
fi

dnl Only look for non-n-library if there was no n-library.
if test X"$CURSESLIBS" = X"" -a "$ac_cv_header_curses_curses_h" = "yes"; then
    AC_CHECK_LIB(curses, printw,
                 [CURSESLIBS='-lcurses'; AC_DEFINE(HAVE_LIBCURSES,1, have curses library)])
fi

if test "x$CURSESLIBS" != "x"; then
    PCMK_FEATURES="$PCMK_FEATURES ncurses"
fi

dnl Check for printw() prototype compatibility
if test X"$CURSESLIBS" != X"" && cc_supports_flag -Wcast-qual; then
    ac_save_LIBS=$LIBS
    LIBS="$CURSESLIBS"
    cc_temp_flags "-Wcast-qual $WERROR"
    # avoid broken test because of hardened build environment in Fedora 23+
    # - https://fedoraproject.org/wiki/Changes/Harden_All_Packages
    # - https://bugzilla.redhat.com/1297985
    if cc_supports_flag -fPIC; then
        CFLAGS="$CFLAGS -fPIC"
    fi

    AC_MSG_CHECKING(whether printw() requires argument of "const char *")
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM([
#if defined(HAVE_NCURSES_H)
#  include <ncurses.h>
#elif defined(HAVE_NCURSES_NCURSES_H)
#  include <ncurses/ncurses.h>
#elif defined(HAVE_CURSES_H)
#  include <curses.h>
#endif
                         ],
                         [printw((const char *)"Test");]
        )],
        [pcmk_cv_compatible_printw=yes],
        [pcmk_cv_compatible_printw=no]
    )

    LIBS=$ac_save_LIBS
    cc_restore_flags

    AC_MSG_RESULT([$pcmk_cv_compatible_printw])

    if test "$pcmk_cv_compatible_printw" = no; then
        AC_MSG_WARN([The printw() function of your ncurses or curses library is old, we will disable usage of the library. If you want to use this library anyway, please update to newer version of the library, ncurses 5.4 or later is recommended. You can get the library from http://www.gnu.org/software/ncurses/.])
        AC_MSG_NOTICE([Disabling curses])
        AC_DEFINE(HAVE_INCOMPATIBLE_PRINTW, 1, [Do we have incompatible printw() in curses library?])
    fi
fi

AC_SUBST(CURSESLIBS)

dnl ========================================================================
dnl    Profiling and GProf
dnl ========================================================================

AC_MSG_NOTICE(Old CFLAGS: $CFLAGS)
case $SUPPORT_COVERAGE in
    1|yes|true)
        SUPPORT_PROFILING=1
        PCMK_FEATURES="$PCMK_FEATURES coverage"
        CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
        dnl During linking, make sure to specify -lgcov or -coverage
        ;;
esac

case $SUPPORT_PROFILING in
    1|yes|true)
        SUPPORT_PROFILING=1

        dnl Disable various compiler optimizations
        CFLAGS="$CFLAGS -fno-omit-frame-pointer -fno-inline -fno-builtin "
        dnl CFLAGS="$CFLAGS -fno-inline-functions -fno-default-inline -fno-inline-functions-called-once -fno-optimize-sibling-calls"

        dnl Turn off optimization so tools can get accurate line numbers
        CFLAGS=`echo $CFLAGS | sed -e 's/-O.\ //g' -e 's/-Wp,-D_FORTIFY_SOURCE=.\ //g' -e 's/-D_FORTIFY_SOURCE=.\ //g'`
        CFLAGS="$CFLAGS -O0 -g3 -gdwarf-2"

        dnl Update features
        PCMK_FEATURES="$PCMK_FEATURES profile"
        ;;
     *)
        SUPPORT_PROFILING=0
        ;;
esac
AC_MSG_NOTICE(New CFLAGS: $CFLAGS)
AC_DEFINE_UNQUOTED(SUPPORT_PROFILING, $SUPPORT_PROFILING, Support for profiling)

dnl ========================================================================
dnl    Cluster infrastructure - LibQB
dnl ========================================================================

if test x${enable_no_stack} = xyes; then
    SUPPORT_CS=no
fi

PKG_CHECK_MODULES(libqb, libqb >= 0.13)
CPPFLAGS="$libqb_CFLAGS $CPPFLAGS"
LIBS="$libqb_LIBS $LIBS"

dnl libqb 0.14.0+ (2012-06)
AC_CHECK_LIB(qb, qb_ipcs_connection_auth_set)

PCMK_FEATURES="$PCMK_FEATURES libqb-logging libqb-ipc"

dnl libqb 0.17.0+ (2014-02)
AC_CHECK_FUNCS(qb_ipcs_connection_get_buffer_size,
               AC_DEFINE(HAVE_IPCS_GET_BUFFER_SIZE, 1,
                         [Have qb_ipcc_get_buffer_size function]))

dnl libqb not yet released (as of 2018-05)
CHECK_ENUM_VALUE([qb/qblog.h],[qb_log_conf],[QB_LOG_CONF_MAX_LINE_LEN])
CHECK_ENUM_VALUE([qb/qblog.h],[qb_log_conf],[QB_LOG_CONF_ELLIPSIS])

dnl Support Linux-HA fence agents if available
if test "$cross_compiling" != "yes"; then
    CPPFLAGS="$CPPFLAGS -I${prefix}/include/heartbeat"
fi
AC_CHECK_HEADERS(stonith/stonith.h)
if test "$ac_cv_header_stonith_stonith_h" = "yes";  then
    dnl On Debian, AC_CHECK_LIBS fail if a library has any unresolved symbols
    dnl So check for all the dependencies (so they're added to LIBS) before checking for -lplumb
    AC_CHECK_LIB(pils, PILLoadPlugin)
    AC_CHECK_LIB(plumb, G_main_add_IPC_Channel)
    PCMK_FEATURES="$PCMK_FEATURES lha-fencing"
fi
AM_CONDITIONAL([BUILD_LHA_SUPPORT], [test "$ac_cv_header_stonith_stonith_h" = "yes"])

dnl ===============================================
dnl Variables needed for substitution
dnl ===============================================
CRM_SCHEMA_DIRECTORY="${datadir}/pacemaker"
AC_DEFINE_UNQUOTED(CRM_SCHEMA_DIRECTORY,"$CRM_SCHEMA_DIRECTORY", Location for the Pacemaker Relax-NG Schema)
AC_SUBST(CRM_SCHEMA_DIRECTORY)

CRM_CORE_DIR="${localstatedir}/lib/pacemaker/cores"
AC_DEFINE_UNQUOTED(CRM_CORE_DIR,"$CRM_CORE_DIR", Location to store core files produced by Pacemaker daemons)
AC_SUBST(CRM_CORE_DIR)

CRM_DAEMON_USER="hacluster"
AC_DEFINE_UNQUOTED(CRM_DAEMON_USER,"$CRM_DAEMON_USER", User to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_USER)

CRM_DAEMON_GROUP="haclient"
AC_DEFINE_UNQUOTED(CRM_DAEMON_GROUP,"$CRM_DAEMON_GROUP", Group to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_GROUP)

CRM_STATE_DIR=${localstatedir}/run/crm
AC_DEFINE_UNQUOTED(CRM_STATE_DIR,"$CRM_STATE_DIR", Where to keep state files and sockets)
AC_SUBST(CRM_STATE_DIR)

CRM_PACEMAKER_DIR=${localstatedir}/lib/pacemaker
AC_DEFINE_UNQUOTED(CRM_PACEMAKER_DIR,"$CRM_PACEMAKER_DIR", Location to store directory produced by Pacemaker daemons)
AC_SUBST(CRM_PACEMAKER_DIR)

CRM_BLACKBOX_DIR=${localstatedir}/lib/pacemaker/blackbox
AC_DEFINE_UNQUOTED(CRM_BLACKBOX_DIR,"$CRM_BLACKBOX_DIR", Where to keep blackbox dumps)
AC_SUBST(CRM_BLACKBOX_DIR)

PE_STATE_DIR="${localstatedir}/lib/pacemaker/pengine"
AC_DEFINE_UNQUOTED(PE_STATE_DIR,"$PE_STATE_DIR", Where to keep scheduler outputs)
AC_SUBST(PE_STATE_DIR)

CRM_CONFIG_DIR="${localstatedir}/lib/pacemaker/cib"
AC_DEFINE_UNQUOTED(CRM_CONFIG_DIR,"$CRM_CONFIG_DIR", Where to keep configuration files)
AC_SUBST(CRM_CONFIG_DIR)

CRM_CONFIG_CTS="${localstatedir}/lib/pacemaker/cts"
AC_DEFINE_UNQUOTED(CRM_CONFIG_CTS,"$CRM_CONFIG_CTS", Where to keep cts stateful data)
AC_SUBST(CRM_CONFIG_CTS)

CRM_DAEMON_DIR="${libexecdir}/pacemaker"
AC_DEFINE_UNQUOTED(CRM_DAEMON_DIR,"$CRM_DAEMON_DIR", Location for Pacemaker daemons)
AC_SUBST(CRM_DAEMON_DIR)

HA_STATE_DIR="${localstatedir}/run"
AC_DEFINE_UNQUOTED(HA_STATE_DIR,"$HA_STATE_DIR", Where sbd keeps its PID file)
AC_SUBST(HA_STATE_DIR)

CRM_RSCTMP_DIR="${localstatedir}/run/resource-agents"
AC_DEFINE_UNQUOTED(CRM_RSCTMP_DIR,"$CRM_RSCTMP_DIR", Where resource agents should keep state files)
AC_SUBST(CRM_RSCTMP_DIR)

PACEMAKER_CONFIG_DIR="${sysconfdir}/pacemaker"
AC_DEFINE_UNQUOTED(PACEMAKER_CONFIG_DIR,"$PACEMAKER_CONFIG_DIR", Where to keep configuration files like authkey)
AC_SUBST(PACEMAKER_CONFIG_DIR)

OCF_ROOT_DIR="/usr/lib/ocf"
if test "X$OCF_ROOT_DIR" = X; then
    AC_MSG_ERROR(Could not locate OCF directory)
fi
AC_SUBST(OCF_ROOT_DIR)

OCF_RA_DIR="$OCF_ROOT_DIR/resource.d"
AC_DEFINE_UNQUOTED(OCF_RA_DIR,"$OCF_RA_DIR", Location for OCF RAs)
AC_SUBST(OCF_RA_DIR)

RH_STONITH_DIR="$sbindir"
AC_DEFINE_UNQUOTED(RH_STONITH_DIR,"$RH_STONITH_DIR", Location for Red Hat Stonith agents)
AC_DEFINE_UNQUOTED(SBIN_DIR,"$sbindir", Location for system binaries)

RH_STONITH_PREFIX="fence_"
AC_DEFINE_UNQUOTED(RH_STONITH_PREFIX,"$RH_STONITH_PREFIX", Prefix for Red Hat Stonith agents)

AC_PATH_PROGS(GIT, git false)
AC_MSG_CHECKING(build version)

BUILD_VERSION=$Format:%h$
if test $BUILD_VERSION != ":%h$"; then
    AC_MSG_RESULT(archive hash: $BUILD_VERSION)
elif test -x $GIT -a -d .git; then
    BUILD_VERSION=`$GIT log --pretty="format:%h" -n 1`
    AC_MSG_RESULT(git hash: $BUILD_VERSION)
else
    # The current directory name make a reasonable default
    # Most generated archives will include the hash or tag
    BASE=`basename $PWD`
    BUILD_VERSION=`echo $BASE | sed s:.*[[Pp]]acemaker-::`
    AC_MSG_RESULT(directory based hash: $BUILD_VERSION)
fi

AC_DEFINE_UNQUOTED(BUILD_VERSION, "$BUILD_VERSION", Build version)
AC_SUBST(BUILD_VERSION)

HAVE_dbus=1
PKG_CHECK_MODULES([DBUS], [dbus-1],
		  [CPPFLAGS="${CPPFLAGS} ${DBUS_CFLAGS}"],
		  [HAVE_dbus=0])
AC_DEFINE_UNQUOTED(SUPPORT_DBUS, $HAVE_dbus, Support dbus)
AM_CONDITIONAL(BUILD_DBUS, test $HAVE_dbus = 1)
AC_CHECK_TYPES([DBusBasicValue],,,[[#include <dbus/dbus.h>]])

if test "x${enable_systemd}" != xno; then
    if test $HAVE_dbus = 0; then
        if test "x${enable_systemd}" = xyes; then
            AC_MSG_FAILURE([cannot enable systemd without DBus])
        else
            enable_systemd=no
        fi
    fi
    if test "x${enable_systemd}" = xtry; then
        AC_MSG_CHECKING([for systemd version query result via dbus-send])
        ret=$({ dbus-send --system --print-reply \
                    --dest=org.freedesktop.systemd1 \
                    /org/freedesktop/systemd1 \
                    org.freedesktop.DBus.Properties.Get \
                    string:org.freedesktop.systemd1.Manager \
                    string:Version 2>/dev/null \
                || echo "this borked"; } | tail -n1)
        # sanitize output a bit (interested just in value, not type),
        # ret is intentionally unenquoted so as to normalize whitespace
        ret=$(echo ${ret} | cut -d' ' -f2-)
        AC_MSG_RESULT([${ret}])
        if test "x${ret}" != xborked \
           || systemctl --version 2>/dev/null | grep -q systemd; then
            enable_systemd=yes
        else
            enable_systemd=no
        fi
    fi
fi

AC_MSG_CHECKING([whether to enable support for managing resources via systemd])
AC_MSG_RESULT([${enable_systemd}])
HAVE_systemd=0
if test "x${enable_systemd}" = xyes; then
    HAVE_systemd=1
    PCMK_FEATURES="$PCMK_FEATURES systemd"

    AC_MSG_CHECKING([for systemd path for system unit files])
    systemdunitdir="${systemdunitdir-}"
    PKG_CHECK_VAR([systemdunitdir], [systemd],
                  [systemdsystemunitdir], [], [systemdunitdir=no])
    AC_MSG_RESULT([${systemdunitdir}])
    if test "x${systemdunitdir}" = xno; then
        AC_MSG_FAILURE([cannot enable systemd when systemdunitdir unresolved])
    fi
fi
AC_SUBST(systemdunitdir)

AC_DEFINE_UNQUOTED(SUPPORT_SYSTEMD, $HAVE_systemd, Support systemd based system services)
AM_CONDITIONAL(BUILD_SYSTEMD, test $HAVE_systemd = 1)
AC_SUBST(SUPPORT_SYSTEMD)

if test "x${enable_upstart}" != xno; then
    if test $HAVE_dbus = 0; then
        if test "x${enable_upstart}" = xyes; then
            AC_MSG_FAILURE([cannot enable Upstart without DBus])
        else
            enable_upstart=no
        fi
    fi
    if test "x${enable_upstart}" = xtry; then
        AC_MSG_CHECKING([for Upstart version query result via dbus-send])
        ret=$({ dbus-send --system --print-reply --dest=com.ubuntu.Upstart \
                    /com/ubuntu/Upstart org.freedesktop.DBus.Properties.Get \
                    string:com.ubuntu.Upstart0_6 string:version 2>/dev/null \
                || echo "this borked"; } | tail -n1)
        # sanitize output a bit (interested just in value, not type),
        # ret is intentionally unenquoted so as to normalize whitespace
        ret=$(echo ${ret} | cut -d' ' -f2-)
        AC_MSG_RESULT([${ret}])
        if test "x${ret}" != xborked \
           || initctl --version 2>/dev/null | grep -q upstart; then
            enable_upstart=yes
        else
            enable_upstart=no
        fi
    fi
fi
AC_MSG_CHECKING([whether to enable support for managing resources via Upstart])
AC_MSG_RESULT([${enable_upstart}])
HAVE_upstart=0
if test "x${enable_upstart}" = xyes; then
    HAVE_upstart=1
    PCMK_FEATURES="$PCMK_FEATURES upstart"
fi

AC_DEFINE_UNQUOTED(SUPPORT_UPSTART, $HAVE_upstart, Support upstart based system services)
AM_CONDITIONAL(BUILD_UPSTART, test $HAVE_upstart = 1)
AC_SUBST(SUPPORT_UPSTART)

case $SUPPORT_NAGIOS in
    1|yes|true|try)
        SUPPORT_NAGIOS=1
        ;;
    *)
        SUPPORT_NAGIOS=0
        ;;
esac

if test $SUPPORT_NAGIOS = 1; then
    PCMK_FEATURES="$PCMK_FEATURES nagios"
fi

AC_DEFINE_UNQUOTED(SUPPORT_NAGIOS, $SUPPORT_NAGIOS, Support nagios plugins)
AM_CONDITIONAL(BUILD_NAGIOS, test $SUPPORT_NAGIOS = 1)

if test x"$NAGIOS_PLUGIN_DIR" = x""; then
    NAGIOS_PLUGIN_DIR="${libexecdir}/nagios/plugins"
fi

AC_DEFINE_UNQUOTED(NAGIOS_PLUGIN_DIR, "$NAGIOS_PLUGIN_DIR", Directory for nagios plugins)
AC_SUBST(NAGIOS_PLUGIN_DIR)

if test x"$NAGIOS_METADATA_DIR" = x""; then
    NAGIOS_METADATA_DIR="${datadir}/nagios/plugins-metadata"
fi

AC_DEFINE_UNQUOTED(NAGIOS_METADATA_DIR, "$NAGIOS_METADATA_DIR", Directory for nagios plugins metadata)
AC_SUBST(NAGIOS_METADATA_DIR)

STACKS=""
CLUSTERLIBS=""

dnl ========================================================================
dnl    Cluster stack - Corosync
dnl ========================================================================

dnl Normalize the values
case $SUPPORT_CS in
    1|yes|true)
        SUPPORT_CS=yes
        missingisfatal=1
        ;;
    try)
        missingisfatal=0
        ;;
    *)
        SUPPORT_CS=no
        ;;
esac

AC_MSG_CHECKING(for native corosync)
COROSYNC_LIBS=""

if test $SUPPORT_CS = no; then
    AC_MSG_RESULT(no (disabled))
    SUPPORT_CS=0
else
    AC_MSG_RESULT($SUPPORT_CS)
    SUPPORT_CS=1
    PKG_CHECK_MODULES(cpg,    libcpg) dnl Fatal
    PKG_CHECK_MODULES(cfg,    libcfg) dnl Fatal
    PKG_CHECK_MODULES(cmap,   libcmap) dnl Fatal
    PKG_CHECK_MODULES(quorum, libquorum) dnl Fatal
    PKG_CHECK_MODULES(libcorosync_common, libcorosync_common) dnl Fatal

    CFLAGS="$CFLAGS $libqb_FLAGS $cpg_FLAGS $cfg_FLAGS $cmap_CFLAGS $quorum_CFLAGS $libcorosync_common_CFLAGS"
    COROSYNC_LIBS="$COROSYNC_LIBS $libqb_LIBS $cpg_LIBS $cfg_LIBS $cmap_LIBS $quorum_LIBS $libcorosync_common_LIBS"
    CLUSTERLIBS="$CLUSTERLIBS $COROSYNC_LIBS"
    STACKS="$STACKS corosync-native"
fi

AC_DEFINE_UNQUOTED(SUPPORT_COROSYNC, $SUPPORT_CS,    Support the Corosync messaging and membership layer)
AM_CONDITIONAL(BUILD_CS_SUPPORT, test $SUPPORT_CS = 1)
AC_SUBST(SUPPORT_COROSYNC)

dnl
dnl    Cluster stack - Sanity
dnl

if test x${enable_no_stack} = xyes; then
    AC_MSG_NOTICE(No cluster stack supported, building only the scheduler)
    PCMK_FEATURES="$PCMK_FEATURES no-cluster-stack"
else
    AC_MSG_CHECKING(for supported stacks)
    if test x"$STACKS" = x; then
        AC_MSG_FAILURE(You must support at least one cluster stack)
    fi
    AC_MSG_RESULT($STACKS)
    PCMK_FEATURES="$PCMK_FEATURES $STACKS"
fi

PCMK_FEATURES="$PCMK_FEATURES atomic-attrd"
AC_SUBST(CLUSTERLIBS)

dnl ========================================================================
dnl    ACL
dnl ========================================================================

case $SUPPORT_ACL in
    1|yes|true)
        missingisfatal=1
        ;;
    try)
        missingisfatal=0
        ;;
    *)
        SUPPORT_ACL=no
        ;;
esac

AC_MSG_CHECKING(for acl support)
if test $SUPPORT_ACL = no; then
    AC_MSG_RESULT(no (disabled))
    SUPPORT_ACL=0
else
    AC_MSG_RESULT($SUPPORT_ACL)

    SUPPORT_ACL=1
    AC_CHECK_LIB(qb, qb_ipcs_connection_auth_set)
    if test $ac_cv_lib_qb_qb_ipcs_connection_auth_set != yes; then
        SUPPORT_ACL=0
    fi

    if test $SUPPORT_ACL = 0; then
        if test $missingisfatal = 0; then
            AC_MSG_WARN(Unable to support ACL. You need to use libqb > 0.13.0)
        else
            AC_MSG_FAILURE(Unable to support ACL. You need to use libqb > 0.13.0)
        fi
    fi
fi

if test $SUPPORT_ACL = 1; then
    PCMK_FEATURES="$PCMK_FEATURES acls"
fi

AM_CONDITIONAL(ENABLE_ACL, test "$SUPPORT_ACL" = "1")
AC_DEFINE_UNQUOTED(ENABLE_ACL, $SUPPORT_ACL, Build in support for CIB ACL)

dnl ========================================================================
dnl    CIB secrets
dnl ========================================================================

case $SUPPORT_CIBSECRETS in
    1|yes|true|try)
        SUPPORT_CIBSECRETS=1
        ;;
    *)
        SUPPORT_CIBSECRETS=0
        ;;
esac

AC_DEFINE_UNQUOTED(SUPPORT_CIBSECRETS, $SUPPORT_CIBSECRETS, Support CIB secrets)
AM_CONDITIONAL(BUILD_CIBSECRETS, test $SUPPORT_CIBSECRETS = 1)

if test $SUPPORT_CIBSECRETS = 1; then
    PCMK_FEATURES="$PCMK_FEATURES cibsecrets"

    LRM_CIBSECRETS_DIR="${localstatedir}/lib/pacemaker/lrm/secrets"
    AC_DEFINE_UNQUOTED(LRM_CIBSECRETS_DIR,"$LRM_CIBSECRETS_DIR", Location for CIB secrets)
    AC_SUBST(LRM_CIBSECRETS_DIR)
fi

dnl ========================================================================
dnl    GnuTLS
dnl ========================================================================

dnl gnutls_priority_set_direct available since 2.1.7 (released 2007-11-29)
AC_CHECK_LIB(gnutls, gnutls_priority_set_direct)
if test "$ac_cv_lib_gnutls_gnutls_priority_set_direct" != ""; then
    AC_CHECK_HEADERS(gnutls/gnutls.h)
fi

dnl ========================================================================
dnl    PAM
dnl ========================================================================

AC_CHECK_HEADERS(security/pam_appl.h pam/pam_appl.h)

dnl ========================================================================
dnl    System Health
dnl ========================================================================

dnl Check if servicelog development package is installed
SERVICELOG=servicelog-1
SERVICELOG_EXISTS="no"
AC_MSG_CHECKING(for $SERVICELOG packages)
if
    $PKG_CONFIG --exists $SERVICELOG
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
    $PKG_CONFIG --exists $OPENIPMI $SERVICELOG
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
if export | fgrep " CFLAGS=" > /dev/null; then
    SAVED_CFLAGS="$CFLAGS"
    unset CFLAGS
    CFLAGS="$SAVED_CFLAGS"
    unset SAVED_CFLAGS
fi

AC_ARG_VAR([CFLAGS_HARDENED_LIB], [extra C compiler flags for hardened libraries])
AC_ARG_VAR([LDFLAGS_HARDENED_LIB], [extra linker flags for hardened libraries])

AC_ARG_VAR([CFLAGS_HARDENED_EXE], [extra C compiler flags for hardened executables])
AC_ARG_VAR([LDFLAGS_HARDENED_EXE], [extra linker flags for hardened executables])

CC_EXTRAS=""

if test "$GCC" != yes; then
    CFLAGS="$CFLAGS -g"
else
    CFLAGS="$CFLAGS -ggdb"

dnl When we don't have diagnostic push / pull, we can't explicitly disable
dnl checking for nonliteral formats in the places where they occur on purpose
dnl thus we disable nonliteral format checking globally as we are aborting
dnl on warnings. 
dnl what makes the things really ugly is that nonliteral format checking is 
dnl obviously available as an extra switch in very modern gcc but for older
dnl gcc this is part of -Wformat=2 
dnl so if we have push/pull we can enable -Wformat=2 -Wformat-nonliteral
dnl if we don't have push/pull but -Wformat-nonliteral we can enable -Wformat=2
dnl otherwise none of both

    gcc_diagnostic_push_pull=no
    cc_temp_flags "$CFLAGS $WERROR"
    AC_MSG_CHECKING([for gcc diagnostic push / pull])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[
#pragma GCC diagnostic push
#pragma GCC diagnostic pop
                      ]])],
                      [
                          AC_MSG_RESULT([yes])
                          gcc_diagnostic_push_pull=yes
                      ], AC_MSG_RESULT([no]))
    cc_restore_flags

    if cc_supports_flag "-Wformat-nonliteral"; then
        gcc_format_nonliteral=yes
    else
        gcc_format_nonliteral=no
    fi
        
    # We had to eliminate -Wnested-externs because of libtool changes
    # Make sure to order options so that the former stand for prerequisites
    # of the latter (e.g., -Wformat-nonliteral requires -Wformat).
    EXTRA_FLAGS="-fgnu89-inline
                -Wall
                -Waggregate-return
                -Wbad-function-cast
                -Wcast-align
                -Wdeclaration-after-statement
                -Wendif-labels
                -Wfloat-equal
                -Wformat-security
                -Wmissing-prototypes
                -Wmissing-declarations
                -Wnested-externs
                -Wno-long-long
                -Wno-strict-aliasing
                -Wpointer-arith
                -Wstrict-prototypes
                -Wwrite-strings
                -Wunused-but-set-variable
                -Wunsigned-char"

    if test "x$gcc_diagnostic_push_pull" = "xyes"; then
        AC_DEFINE([GCC_FORMAT_NONLITERAL_CHECKING_ENABLED], [],
                  [gcc can complain about nonliterals in format])
        EXTRA_FLAGS="$EXTRA_FLAGS
                    -Wformat=2 
                    -Wformat-nonliteral"
    else
        if test "x$gcc_format_nonliteral" = "xyes"; then
            EXTRA_FLAGS="$EXTRA_FLAGS -Wformat=2"
        fi
    fi

# Additional warnings it might be nice to enable one day
#                -Wshadow
#                -Wunreachable-code
    for j in $EXTRA_FLAGS
    do
        if
            cc_supports_flag $CC_EXTRAS $j
        then
            CC_EXTRAS="$CC_EXTRAS $j"
        fi
    done

    if test "x${enable_ansi}" = xyes && cc_supports_flag -std=iso9899:199409 ; then
        AC_MSG_NOTICE(Enabling ANSI Compatibility)
        CC_EXTRAS="$CC_EXTRAS -ansi -D_GNU_SOURCE -DANSI_ONLY"
    fi

    AC_MSG_NOTICE(Activated additional gcc flags: ${CC_EXTRAS})
fi

dnl
dnl Hardening flags
dnl
dnl The prime control of whether to apply (targeted) hardening build flags and
dnl which ones is --{enable,disable}-hardening option passed to ./configure:
dnl
dnl --enable-hardening=try (default):
dnl     depending on whether any of CFLAGS_HARDENED_EXE, LDFLAGS_HARDENED_EXE,
dnl     CFLAGS_HARDENED_LIB or LDFLAGS_HARDENED_LIB environment variables
dnl     (see below) is set and non-null, all these custom flags (even if not
dnl     set) are used as are, otherwise the best effort is made to offer
dnl     reasonably strong hardening in several categories (RELRO, PIE,
dnl     "bind now", stack protector) according to what the selected toolchain
dnl     can offer
dnl
dnl --enable-hardening:
dnl     same effect as --enable-hardening=try when the environment variables
dnl     in question are suppressed
dnl
dnl --disable-hardening:
dnl     do not apply any targeted hardening measures at all
dnl
dnl The user-injected environment variables that regulate the hardening in
dnl default case are as follows:
dnl
dnl * CFLAGS_HARDENED_EXE, LDFLAGS_HARDENED_EXE
dnl    compiler and linker flags (respectively) for daemon programs
dnl    (pacemakerd, pacemaker-attrd, pacemaker-controld, pacemaker-execd,
dnl    cib, stonithd, pacemaker-remoted, pacemaker-schedulerd)
dnl
dnl * CFLAGS_HARDENED_LIB, LDFLAGS_HARDENED_LIB
dnl    compiler and linker flags (respectively) for libraries linked
dnl    with the daemon programs
dnl
dnl Note that these are purposedly targeted variables (addressing particular
dnl targets all over the scattered Makefiles) and have no effect outside of
dnl the predestined scope (e.g., CLI utilities).  For a global reach,
dnl use CFLAGS, LDFLAGS, etc. as usual.
dnl
dnl For guidance on the suitable flags consult, for instance:
dnl https://fedoraproject.org/wiki/Changes/Harden_All_Packages#Detailed_Harden_Flags_Description
dnl https://owasp.org/index.php/C-Based_Toolchain_Hardening#GCC.2FBinutils
dnl

if test "x${HARDENING}" != "xtry"; then
    unset CFLAGS_HARDENED_EXE
    unset CFLAGS_HARDENED_LIB
    unset LDFLAGS_HARDENED_EXE
    unset LDFLAGS_HARDENED_LIB
fi
if test "x${HARDENING}" = "xno"; then
    AC_MSG_NOTICE([Hardening: explicitly disabled])
elif test "x${HARDENING}" = "xyes" \
     || test "$(env | grep -Ec '^(C|LD)FLAGS_HARDENED_(EXE|LIB)=.')" = 0; then
    dnl We'll figure out on our own...
    CFLAGS_HARDENED_EXE=
    CFLAGS_HARDENED_LIB=
    LDFLAGS_HARDENED_EXE=
    LDFLAGS_HARDENED_LIB=
    relro=0
    pie=0
    bindnow=0
    # daemons incl. libs: partial RELRO
    flag="-Wl,-z,relro"
    CC_CHECK_LDFLAGS(["${flag}"],
                     [LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}";
                      LDFLAGS_HARDENED_LIB="${LDFLAGS_HARDENED_LIB} ${flag}";
                      relro=1])
    # daemons: PIE for both CFLAGS and LDFLAGS
    if cc_supports_flag -fPIE; then
        flag="-pie"
        CC_CHECK_LDFLAGS(["${flag}"],
                         [CFLAGS_HARDENED_EXE="${CFLAGS_HARDENED_EXE} -fPIE";
                          LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}";
                          pie=1])
    fi
    # daemons incl. libs: full RELRO if sensible + as-needed linking
    #                     so as to possibly mitigate startup performance
    #                     hit caused by excessive linking with unneeded
    #                     libraries
    if test "${relro}" = 1 && test "${pie}" = 1; then
        flag="-Wl,-z,now"
        CC_CHECK_LDFLAGS(["${flag}"],
                         [LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}";
                          LDFLAGS_HARDENED_LIB="${LDFLAGS_HARDENED_LIB} ${flag}";
                          bindnow=1])
    fi
    if test "${bindnow}" = 1; then
        flag="-Wl,--as-needed"
        CC_CHECK_LDFLAGS(["${flag}"],
                         [LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}";
                          LDFLAGS_HARDENED_LIB="${LDFLAGS_HARDENED_LIB} ${flag}"])
    fi
    # universal: prefer strong > all > default stack protector if possible
    flag=
    if cc_supports_flag -fstack-protector-strong; then
        flag="-fstack-protector-strong"
    elif cc_supports_flag -fstack-protector-all; then
        flag="-fstack-protector-all"
    elif cc_supports_flag -fstack-protector; then
        flag="-fstack-protector"
    fi
    if test -n "${flag}"; then
        CC_EXTRAS="${CC_EXTRAS} ${flag}"
        stackprot=1
    fi
    if test "${relro}" = 1 \
    || test "${pie}" = 1 \
    || test "${stackprot}" = 1; then
        AC_MSG_NOTICE([Hardening: relro=${relro} pie=${pie} bindnow=${bindnow} stackprot=${flag}])
    else
        AC_MSG_WARN([Hardening: no suitable features in the toolchain detected])
    fi
else
    AC_MSG_NOTICE([Hardening: using custom flags])
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
    CFLAGS="$CFLAGS $WERROR"
fi
AC_SUBST(CFLAGS)

dnl This is useful for use in Makefiles that need to remove one specific flag
CFLAGS_COPY="$CFLAGS"
AC_SUBST(CFLAGS_COPY)

AC_SUBST(LIBADD_DL)        dnl extra flags for dynamic linking libraries
AC_SUBST(LIBADD_INTL)        dnl extra flags for GNU gettext stuff...

AC_SUBST(LOCALE)

dnl Options for cleaning up the compiler output
QUIET_LIBTOOL_OPTS=""
QUIET_MAKE_OPTS=""
if test "x${enable_quiet}" = "xyes"; then
    QUIET_LIBTOOL_OPTS="--quiet"
    QUIET_MAKE_OPTS="--quiet"
fi

AC_MSG_RESULT(Suppress make details: ${enable_quiet})

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

dnl Files we output that need to be executable
AC_CONFIG_FILES([cts/CTSlab.py], [chmod +x cts/CTSlab.py])
AC_CONFIG_FILES([cts/LSBDummy], [chmod +x cts/LSBDummy])
AC_CONFIG_FILES([cts/OCFIPraTest.py], [chmod +x cts/OCFIPraTest.py])
AC_CONFIG_FILES([cts/cluster_test], [chmod +x cts/cluster_test])
AC_CONFIG_FILES([cts/cts], [chmod +x cts/cts])
AC_CONFIG_FILES([cts/cts-cli], [chmod +x cts/cts-cli])
AC_CONFIG_FILES([cts/cts-coverage], [chmod +x cts/cts-coverage])
AC_CONFIG_FILES([cts/cts-exec], [chmod +x cts/cts-exec])
AC_CONFIG_FILES([cts/cts-fencing], [chmod +x cts/cts-fencing])
AC_CONFIG_FILES([cts/cts-log-watcher], [chmod +x cts/cts-log-watcher])
AC_CONFIG_FILES([cts/cts-regression], [chmod +x cts/cts-regression])
AC_CONFIG_FILES([cts/cts-scheduler], [chmod +x cts/cts-scheduler])
AC_CONFIG_FILES([cts/cts-support], [chmod +x cts/cts-support])
AC_CONFIG_FILES([cts/lxc_autogen.sh], [chmod +x cts/lxc_autogen.sh])
AC_CONFIG_FILES([cts/benchmark/clubench], [chmod +x cts/benchmark/clubench])
AC_CONFIG_FILES([cts/fence_dummy], [chmod +x cts/fence_dummy])
AC_CONFIG_FILES([cts/pacemaker-cts-dummyd], [chmod +x cts/pacemaker-cts-dummyd])
AC_CONFIG_FILES([daemons/fenced/fence_legacy], [chmod +x daemons/fenced/fence_legacy])
AC_CONFIG_FILES([extra/resources/ClusterMon],  [chmod +x extra/resources/ClusterMon])
AC_CONFIG_FILES([extra/resources/HealthSMART], [chmod +x extra/resources/HealthSMART])
AC_CONFIG_FILES([extra/resources/SysInfo],     [chmod +x extra/resources/SysInfo])
AC_CONFIG_FILES([extra/resources/ifspeed],     [chmod +x extra/resources/ifspeed])
AC_CONFIG_FILES([extra/resources/o2cb],        [chmod +x extra/resources/o2cb])
AC_CONFIG_FILES([tools/crm_failcount], [chmod +x tools/crm_failcount])
AC_CONFIG_FILES([tools/crm_master], [chmod +x tools/crm_master])
AC_CONFIG_FILES([tools/crm_report], [chmod +x tools/crm_report])
AC_CONFIG_FILES([tools/crm_standby], [chmod +x tools/crm_standby])
AC_CONFIG_FILES([tools/cibsecret], [chmod +x tools/cibsecret])

dnl Other files we output
AC_CONFIG_FILES(Makefile                                            \
                Doxyfile                                            \
                cts/Makefile                                        \
                cts/CTS.py                                          \
                cts/CTSvars.py                                      \
                cts/benchmark/Makefile                              \
                cts/pacemaker-cts-dummyd@.service                   \
                daemons/Makefile                                    \
                daemons/attrd/Makefile                              \
                daemons/based/Makefile                              \
                daemons/controld/Makefile                           \
                daemons/execd/Makefile                              \
                daemons/execd/pacemaker_remote                      \
                daemons/execd/pacemaker_remote.service              \
                daemons/fenced/Makefile                             \
                daemons/pacemakerd/Makefile                         \
                daemons/pacemakerd/pacemaker                        \
                daemons/pacemakerd/pacemaker.service                \
                daemons/pacemakerd/pacemaker.upstart                \
                daemons/pacemakerd/pacemaker.combined.upstart       \
                daemons/schedulerd/Makefile                         \
                doc/Makefile                                        \
                doc/Clusters_from_Scratch/publican.cfg              \
                doc/Pacemaker_Administration/publican.cfg           \
                doc/Pacemaker_Development/publican.cfg              \
                doc/Pacemaker_Explained/publican.cfg                \
                doc/Pacemaker_Remote/publican.cfg                   \
                extra/Makefile                                      \
                extra/alerts/Makefile                               \
                extra/resources/Makefile                            \
                extra/logrotate/Makefile                            \
                extra/logrotate/pacemaker                           \
                include/Makefile                                    \
                include/crm/Makefile                                \
                include/crm/cib/Makefile                            \
                include/crm/common/Makefile                         \
                include/crm/cluster/Makefile                        \
                include/crm/fencing/Makefile                        \
                include/crm/pengine/Makefile                        \
                replace/Makefile                                    \
                lib/Makefile                                        \
                lib/pacemaker.pc                                    \
                lib/pacemaker-cib.pc                                \
                lib/pacemaker-lrmd.pc                               \
                lib/pacemaker-service.pc                            \
                lib/pacemaker-pengine.pc                            \
                lib/pacemaker-fencing.pc                            \
                lib/pacemaker-cluster.pc                            \
                lib/common/Makefile                                 \
                lib/cluster/Makefile                                \
                lib/cib/Makefile                                    \
                lib/gnu/Makefile                                    \
                lib/pengine/Makefile                                \
                lib/transition/Makefile                             \
                lib/fencing/Makefile                                \
                lib/lrmd/Makefile                                   \
                lib/services/Makefile                               \
                tools/Makefile                                      \
                tools/report.collector                              \
                tools/report.common                                 \
                tools/crm_mon.service                               \
                tools/crm_mon.upstart                               \
                xml/Makefile                                        \
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
AC_MSG_RESULT([])
AC_MSG_RESULT([  HA group name            = ${CRM_DAEMON_GROUP}])
AC_MSG_RESULT([  HA user name             = ${CRM_DAEMON_USER}])
AC_MSG_RESULT([])
AC_MSG_RESULT([  CFLAGS                   = ${CFLAGS}])
AC_MSG_RESULT([  CFLAGS_HARDENED_EXE      = ${CFLAGS_HARDENED_EXE}])
AC_MSG_RESULT([  CFLAGS_HARDENED_LIB      = ${CFLAGS_HARDENED_LIB}])
AC_MSG_RESULT([  LDFLAGS_HARDENED_EXE     = ${LDFLAGS_HARDENED_EXE}])
AC_MSG_RESULT([  LDFLAGS_HARDENED_LIB     = ${LDFLAGS_HARDENED_LIB}])
AC_MSG_RESULT([  Libraries                = ${LIBS}])
AC_MSG_RESULT([  Stack Libraries          = ${CLUSTERLIBS}])

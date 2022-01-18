dnl
dnl autoconf for Pacemaker
dnl
dnl Copyright 2009-2021 the Pacemaker project contributors
dnl
dnl The version control history for this file may have further details.
dnl
dnl This source code is licensed under the GNU General Public License version 2
dnl or later (GPLv2+) WITHOUT ANY WARRANTY.

dnl ===============================================
dnl Bootstrap
dnl ===============================================
AC_PREREQ(2.64)

dnl AC_CONFIG_MACRO_DIR is deprecated as of autoconf 2.70 (2020-12-08).
dnl Once we can require that version, we can simplify this, and no longer
dnl need ACLOCAL_AMFLAGS in Makefile.am.
m4_ifdef([AC_CONFIG_MACRO_DIRS],
         [AC_CONFIG_MACRO_DIRS([m4])],
         [AC_CONFIG_MACRO_DIR([m4])])

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

m4_include([m4/version.m4])
AC_INIT([pacemaker], VERSION_NUMBER, [users@clusterlabs.org], [pacemaker],
        PCMK_URL)

PCMK_FEATURES=""

LT_CONFIG_LTDL_DIR([libltdl])
AC_CONFIG_AUX_DIR([libltdl/config])
AC_CANONICAL_HOST

dnl Where #defines that autoconf makes (e.g. HAVE_whatever) go
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

dnl 1.13:           minimum automake version required
dnl foreign:        don't require GNU-standard top-level files
dnl tar-ustar:      use (older) POSIX variant of generated tar rather than v7
dnl subdir-objects: keep .o's with their .c's (no-op in 2.0+)
AM_INIT_AUTOMAKE([1.13 foreign tar-ustar subdir-objects])

dnl Require minimum version of pkg-config
PKG_PROG_PKG_CONFIG(0.27)
AS_IF([test "x${PKG_CONFIG}" != x], [],
      [AC_MSG_FAILURE([Could not find required build tool pkg-config (0.27 or later)])])
PKG_INSTALLDIR
PKG_NOARCH_INSTALLDIR

dnl Example 2.4. Silent Custom Rule to Generate a File
dnl %-bar.pc: %.pc
dnl	$(AM_V_GEN)$(LN_S) $(notdir $^) $@

dnl Versioned attributes implementation is not yet production-ready
AC_DEFINE_UNQUOTED(ENABLE_VERSIONED_ATTRS, 0, [Enable versioned attributes])

CC_IN_CONFIGURE=yes
export CC_IN_CONFIGURE

LDD=ldd

dnl ========================================================================
dnl Compiler characteristics
dnl ========================================================================

dnl A particular compiler can be forced by setting the CC environment variable
AC_PROG_CC

dnl Use at least C99 if possible. This will generate an "obsolete" warning
dnl since autoconf 2.70, but is needed for older versions.
AC_PROG_CC_STDC

dnl C++ is not needed for build, just maintainer utilities
AC_PROG_CXX

dnl We use md5.c from gnulib, which has its own m4 macros. Per its docs:
dnl "The macro gl_EARLY must be called as soon as possible after verifying that
dnl the C compiler is working. ... The core part of the gnulib checks are done
dnl by the macro gl_INIT." In addition, prevent gnulib from introducing OpenSSL
dnl as a dependency.
gl_EARLY
gl_SET_CRYPTO_CHECK_DEFAULT([no])
gl_INIT

# --enable-new-dtags: Use RUNPATH instead of RPATH.
# It is necessary to have this done before libtool does linker detection.
# See also: https://github.com/kronosnet/kronosnet/issues/107
AX_CHECK_LINK_FLAG([-Wl,--enable-new-dtags],
                  [AM_LDFLAGS=-Wl,--enable-new-dtags],
                  [AC_MSG_ERROR(["Linker support for --enable-new-dtags is required"])])
AC_SUBST([AM_LDFLAGS])

saved_LDFLAGS="$LDFLAGS"
LDFLAGS="$AM_LDFLAGS $LDFLAGS"
LT_INIT([dlopen])
LDFLAGS="$saved_LDFLAGS"
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
    AC_MSG_CHECKING([whether $CC supports $@])
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[ ]], [[ ]])],
                      [RC=0; AC_MSG_RESULT([yes])],
                      [RC=1; AC_MSG_RESULT([no])])
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

# expand_path_option $path_variable_name $default
expand_path_option() {
    # The first argument is the variable *name* (not value)
    ac_path_varname="$1"

    # Get the original value of the variable
    ac_path_value=$(eval echo "\${${ac_path_varname}}")

    # Expand any literal variable expressions in the value so that we don't
    # end up with something like '${prefix}' in #defines etc.
    #
    # Autoconf deliberately leaves values unexpanded to allow overriding
    # the configure script choices in make commands (for example,
    # "make exec_prefix=/foo install"). No longer being able to do this seems
    # like no great loss.
    eval ac_path_value=$(eval echo "${ac_path_value}")

    # Use (expanded) default if necessary
    AS_IF([test x"${ac_path_value}" = x""],
	  [eval ac_path_value=$(eval echo "$2")])

    # Require a full path
    AS_CASE(["$ac_path_value"],
            [/*], [eval ${ac_path_varname}="$ac_path_value"],
            [*], [AC_MSG_ERROR([$ac_path_varname value "$ac_path_value" is not a full path])]
    )
}

# yes_no_try $user_response $default
DISABLED=0
REQUIRED=1
OPTIONAL=2
yes_no_try() {
    local value
    AS_IF([test x"$1" = x""], [value="$2"], [value="$1"])
    AS_CASE(["`echo "$value" | tr '[A-Z]' '[a-z]'`"],
            [0|no|false|disable], [return $DISABLED],
            [1|yes|true|enable], [return $REQUIRED],
            [try|check], [return $OPTIONAL]
    )
    AC_MSG_ERROR([Invalid option value "$value"])
}

check_systemdsystemunitdir() {
    AC_MSG_CHECKING([which system unit file directory to use])
    PKG_CHECK_VAR([systemdsystemunitdir], [systemd], [systemdsystemunitdir])
    AC_MSG_RESULT([${systemdsystemunitdir}])
    test x"$systemdsystemunitdir" != x""
    return $?
}

dnl ===============================================
dnl Configure Options
dnl ===============================================

dnl Actual library checks come later, but pkg-config can be used here to grab
dnl external values to use as defaults for configure options

dnl Per the autoconf docs, --enable-*/--disable-* options should control
dnl features inherent to Pacemaker, while --with-*/--without-* options should
dnl control the use of external software. However, --enable-*/--disable-* may
dnl implicitly require additional external dependencies, and
dnl --with-*/--without-* may implicitly enable or disable features, so the
dnl line is blurry.
dnl
dnl We also use --with-* options for custom file, directory, and path
dnl locations, since autoconf does not provide an option type for those.

dnl --enable-* options: build process

AC_ARG_ENABLE([quiet],
    [AS_HELP_STRING([--enable-quiet],
        [suppress make output unless there is an error @<:@no@:>@])]
)
yes_no_try "$enable_quiet" "no"
enable_quiet=$?

AC_ARG_ENABLE([fatal-warnings],
    [AS_HELP_STRING([--enable-fatal-warnings],
        [enable pedantic and fatal warnings for gcc @<:@try@:>@])],
)
yes_no_try "$enable_fatal_warnings" "try"
enable_fatal_warnings=$?

AC_ARG_ENABLE([hardening],
    [AS_HELP_STRING([--enable-hardening],
        [harden the resulting executables/libraries @<:@try@:>@])]
)
yes_no_try "$enable_hardening" "try"
enable_hardening=$?

dnl --enable-* options: features

AC_ARG_ENABLE([systemd],
    [AS_HELP_STRING([--enable-systemd],
        [enable support for managing resources via systemd @<:@try@:>@])]
)
yes_no_try "$enable_systemd" "try"
enable_systemd=$?

AC_ARG_ENABLE([upstart],
    [AS_HELP_STRING([--enable-upstart],
        [enable support for managing resources via Upstart (deprecated) @<:@try@:>@])]
)
yes_no_try "$enable_upstart" "try"
enable_upstart=$?

dnl --enable-* options: features inherent to Pacemaker

AC_ARG_ENABLE([compat-2.0],
    [AS_HELP_STRING([--enable-compat-2.0], m4_normalize([
        preserve certain output as it was in 2.0; this option will be
        available only for the lifetime of the 2.1 series @<:@no@:>@]))]
)
yes_no_try "$enable_compat_2_0" "no"
enable_compat_2_0=$?
AS_IF([test $enable_compat_2_0 -ne $DISABLED],
      [
          AC_DEFINE_UNQUOTED([PCMK__COMPAT_2_0], [1],
                             [Keep certain output compatible with 2.0 release series])
          PCMK_FEATURES="$PCMK_FEATURES compat-2.0"
      ]
)

# Add an option to create symlinks at the pre-2.0.0 daemon name locations, so
# that users and tools can continue to invoke those names directly (e.g., for
# meta-data). This option will be removed in a future release.
AC_ARG_ENABLE([legacy-links],
    [AS_HELP_STRING([--enable-legacy-links],
        [add symlinks for old daemon names (deprecated) @<:@no@:>@])]
)
yes_no_try "$enable_legacy_links" "no"
enable_legacy_links=$?
AM_CONDITIONAL([BUILD_LEGACY_LINKS], [test $enable_legacy_links -ne $DISABLED])

AM_GNU_GETTEXT([external])
AM_GNU_GETTEXT_VERSION([0.18])

AC_ARG_ENABLE(nls,
    [  --enable-nls            enable Native Language Support],
    USE_NLS=$enableval, USE_NLS=no)

AS_IF([test "x${USE_NLS}" = "xyes"],
      [
          AC_DEFINE([PCMK__SUPPORT_NLS],[1],[Define to 1 if USE_NLS should be enabled])
])

dnl --with-* options: external software support, and custom locations

dnl This argument is defined via an M4 macro so default can be a variable
AC_DEFUN([VERSION_ARG],
    [AC_ARG_WITH([version],
        [AS_HELP_STRING([--with-version=VERSION],
            [override package version @<:@$1@:>@])],
        [ PACEMAKER_VERSION="$withval" ],
        [ PACEMAKER_VERSION="$PACKAGE_VERSION" ])]
)
VERSION_ARG(VERSION_NUMBER)

# Redefine PACKAGE_VERSION and VERSION according to PACEMAKER_VERSION in case
# the user used --with-version. Unfortunately, this can only affect the
# substitution variables and later uses in this file, not the config.h
# constants, so we have to be careful to use only PACEMAKER_VERSION in C code.
PACKAGE_VERSION=$PACEMAKER_VERSION
VERSION=$PACEMAKER_VERSION

CRM_DAEMON_USER=""
AC_ARG_WITH([daemon-user],
    [AS_HELP_STRING([--with-daemon-user=USER],
        [user to run unprivileged Pacemaker daemons as (advanced option: changing this may break other cluster components unless similarly configured) @<:@hacluster@:>@])],
    [ CRM_DAEMON_USER="$withval" ]
)

CRM_DAEMON_GROUP=""
AC_ARG_WITH([daemon-group],
    [AS_HELP_STRING([--with-daemon-group=GROUP],
        [group to run unprivileged Pacemaker daemons as (advanced option: changing this may break other cluster components unless similarly configured) @<:@haclient@:>@])],
    [ CRM_DAEMON_GROUP="$withval" ]
)

BUG_URL=""
AC_ARG_WITH([bug-url],
    [AS_HELP_STRING([--with-bug-url=DIR], m4_normalize([
        address where users should submit bug reports
        @<:@https://bugs.clusterlabs.org/enter_bug.cgi?product=Pacemaker@:>@]))],
    [ BUG_URL="$withval" ]
)

dnl --with-* options: features

AC_ARG_WITH([cibsecrets],
    [AS_HELP_STRING([--with-cibsecrets],
        [support separate file for CIB secrets @<:@no@:>@])]
)
yes_no_try "$with_cibsecrets" "no"
with_cibsecrets=$?

AC_ARG_WITH([gnutls],
    [AS_HELP_STRING([--with-gnutls],
        [support Pacemaker Remote and remote-tls-port using GnuTLS @<:@try@:>@])]
)
yes_no_try "$with_gnutls" "try"
with_gnutls=$?

PCMK_GNUTLS_PRIORITIES="NORMAL"
AC_ARG_WITH([gnutls-priorities],
    [AS_HELP_STRING([--with-gnutls-priorities],
        [default GnuTLS cipher priorities @<:@NORMAL@:>@])],
    [ test x"$withval" = x"no" || PCMK_GNUTLS_PRIORITIES="$withval" ]
)

AC_ARG_WITH([concurrent-fencing-default],
    [AS_HELP_STRING([--with-concurrent-fencing-default],
        [default value for concurrent-fencing cluster option @<:@false@:>@])],
)
AS_CASE([$with_concurrent_fencing_default],
        [""], [with_concurrent_fencing_default="false"],
        [false], [],
        [true], [PCMK_FEATURES="$PCMK_FEATURES default-concurrent-fencing"],
        [AC_MSG_ERROR([Invalid value "$with_concurrent_fencing_default" for --with-concurrent-fencing-default])]
)
AC_DEFINE_UNQUOTED([PCMK__CONCURRENT_FENCING_DEFAULT],
                   ["$with_concurrent_fencing_default"],
                   [Default value for concurrent-fencing cluster option])

AC_ARG_WITH([sbd-sync-default],
    [AS_HELP_STRING([--with-sbd-sync-default], m4_normalize([
        default value used by sbd if SBD_SYNC_RESOURCE_STARTUP
        environment variable is not set @<:@false@:>@]))],
)
AS_CASE([$with_sbd_sync_default],
        [""], [with_sbd_sync_default=false],
        [false], [],
        [true], [PCMK_FEATURES="$PCMK_FEATURES default-sbd-sync"],
        [AC_MSG_ERROR([Invalid value "$with_sbd_sync_default" for --with-sbd-sync-default])]
)
AC_DEFINE_UNQUOTED([PCMK__SBD_SYNC_DEFAULT],
                   [$with_sbd_sync_default],
                   [Default value for SBD_SYNC_RESOURCE_STARTUP environment variable])

AC_ARG_WITH([resource-stickiness-default],
    [AS_HELP_STRING([--with-resource-stickiness-default],
        [If positive, value to add to new CIBs as explicit resource default for resource-stickiness @<:@0@:>@])],
)
errmsg="Invalid value \"$with_resource_stickiness_default\" for --with-resource-stickiness-default"
AS_CASE([$with_resource_stickiness_default],
        [0|""], [with_resource_stickiness_default="0"],
        [*[[!0-9]]*], [AC_MSG_ERROR([$errmsg])],
        [PCMK_FEATURES="$PCMK_FEATURES default-resource-stickiness"]
)
AC_DEFINE_UNQUOTED([PCMK__RESOURCE_STICKINESS_DEFAULT],
                   [$with_resource_stickiness_default],
                   [Default value for resource-stickiness resource meta-attribute])

AC_ARG_WITH([corosync],
    [AS_HELP_STRING([--with-corosync],
        [support the Corosync messaging and membership layer @<:@try@:>@])]
)
yes_no_try "$with_corosync" "try"
with_corosync=$?

dnl @TODO This should be a corosync pkgconfig variable
PCMK__COROSYNC_CONF=""
AC_ARG_WITH([corosync-conf],
    [AS_HELP_STRING([--with-corosync-conf], m4_normalize([
        location of Corosync configuration file
        @<:@SYSCONFDIR/corosync/corosync.conf@:>@]))],
    [ PCMK__COROSYNC_CONF="$withval" ]
)

AC_ARG_WITH([nagios],
    [AS_HELP_STRING([--with-nagios], [support nagios resources])]
)
yes_no_try "$with_nagios" "try"
with_nagios=$?

dnl --with-* options: directory locations

AC_ARG_WITH([nagios-plugin-dir],
    [AS_HELP_STRING([--with-nagios-plugin-dir=DIR],
        [directory for nagios plugins @<:@LIBEXECDIR/nagios/plugins@:>@])],
    [ NAGIOS_PLUGIN_DIR="$withval" ]
)

AC_ARG_WITH([nagios-metadata-dir],
    [AS_HELP_STRING([--with-nagios-metadata-dir=DIR],
        [directory for nagios plugins metadata @<:@DATADIR/nagios/plugins-metadata@:>@])],
    [ NAGIOS_METADATA_DIR="$withval" ]
)

INITDIR=""
AC_ARG_WITH([initdir],
    [AS_HELP_STRING([--with-initdir=DIR],
        [directory for init (rc) scripts])],
    [ INITDIR="$withval" ]
)

systemdsystemunitdir="${systemdsystemunitdir-}"
AC_ARG_WITH([systemdsystemunitdir],
    [AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
        [directory for systemd unit files (advanced option: must match what systemd uses)])],
    [ systemdsystemunitdir="$withval" ]
)

CONFIGDIR=""
AC_ARG_WITH([configdir],
    [AS_HELP_STRING([--with-configdir=DIR],
        [directory for Pacemaker configuration file @<:@SYSCONFDIR/sysconfig@:>@])],
    [ CONFIGDIR="$withval" ]
)

dnl --runstatedir is available as of autoconf 2.70 (2020-12-08). When users
dnl have an older version, they can use our --with-runstatedir.
pcmk_runstatedir=""
AC_ARG_WITH([runstatedir],
    [AS_HELP_STRING([--with-runstatedir=DIR],
        [modifiable per-process data @<:@LOCALSTATEDIR/run@:>@ (ignored if --runstatedir is available)])],
    [ pcmk_runstatedir="$withval" ]
)

CRM_LOG_DIR=""
AC_ARG_WITH([logdir],
    [AS_HELP_STRING([--with-logdir=DIR],
        [directory for Pacemaker log file @<:@LOCALSTATEDIR/log/pacemaker@:>@])],
    [ CRM_LOG_DIR="$withval" ]
)

CRM_BUNDLE_DIR=""
AC_ARG_WITH([bundledir],
    [AS_HELP_STRING([--with-bundledir=DIR],
        [directory for Pacemaker bundle logs @<:@LOCALSTATEDIR/log/pacemaker/bundles@:>@])],
    [ CRM_BUNDLE_DIR="$withval" ]
)

dnl Get default from resource-agents if possible. Otherwise, the default uses
dnl /usr/lib rather than libdir because it's determined by the OCF project and
dnl not Pacemaker. Even if a user wants to install Pacemaker to /usr/local or
dnl such, the OCF agents will be expected in their usual location. However, we
dnl do give the user the option to override it.
PKG_CHECK_VAR([OCF_ROOT_DIR], [resource-agents], [ocfrootdir], [],
              [OCF_ROOT_DIR="/usr/lib/ocf"])
AC_ARG_WITH([ocfdir],
    [AS_HELP_STRING([--with-ocfdir=DIR], m4_normalize([
        OCF resource agent root directory (advanced option: changing this
        may break other cluster components unless similarly configured)
        @<:@value from resource-agents package if available otherwise
        /usr/lib/ocf@:>@]))],
    [ OCF_ROOT_DIR="$withval" ]
)
AC_SUBST(OCF_ROOT_DIR)
AC_DEFINE_UNQUOTED([OCF_ROOT_DIR], ["$OCF_ROOT_DIR"],
                   [OCF root directory for resource agents and libraries])

PKG_CHECK_VAR([OCF_RA_PATH], [resource-agents], [ocfrapath], [],
              [OCF_RA_PATH="$OCF_ROOT_DIR/resource.d"])
AC_ARG_WITH([ocfrapath],
    [AS_HELP_STRING([--with-ocfrapath=DIR], m4_normalize([
        OCF resource agent directories (colon-separated) to search
        @<:@value from resource-agents package if available otherwise
        OCFDIR/resource.d@:>@]))],
    [ OCF_RA_PATH="$withval" ]
)
AC_SUBST(OCF_RA_PATH)

OCF_RA_INSTALL_DIR="$OCF_ROOT_DIR/resource.d"
AC_ARG_WITH([ocfrainstalldir],
    [AS_HELP_STRING([--with-ocfrainstalldir=DIR], m4_normalize([
        OCF installation directory for Pacemakers resource agents
        @<:@OCFDIR/resource.d@:>@]))],
    [ OCF_RA_INSTALL_DIR="$withval" ]
)
AC_SUBST(OCF_RA_INSTALL_DIR)

dnl Get default from fence-agents if available
PKG_CHECK_VAR([FA_PREFIX], [fence-agents], [prefix],
              [PCMK__FENCE_BINDIR="${FA_PREFIX}/sbin"],
              [PCMK__FENCE_BINDIR="$sbindir"])
AC_ARG_WITH([fence-bindir],
    [AS_HELP_STRING([--with-fence-bindir=DIR], m4_normalize([
        directory for executable fence agents @<:@value from fence-agents
        package if available otherwise SBINDIR@:>@]))],
    [ PCMK__FENCE_BINDIR="$withval" ]
)
AC_SUBST(PCMK__FENCE_BINDIR)

dnl --with-* options: non-production testing

AC_ARG_WITH([profiling],
    [AS_HELP_STRING([--with-profiling],
        [disable optimizations, for effective profiling @<:@no@:>@])]
)
yes_no_try "$with_profiling" "no"
with_profiling=$?

AC_ARG_WITH([coverage],
    [AS_HELP_STRING([--with-coverage],
        [disable optimizations, for effective profiling and coverage testing @<:@no@:>@])]
)
yes_no_try "$with_coverage" "no"
with_coverage=$?

AC_ARG_WITH([sanitizers],
  [AS_HELP_STRING([--with-sanitizers=...,...],
    [enable SANitizer build, do *NOT* use for production. Only ASAN/UBSAN/TSAN are currently supported])],
  [ SANITIZERS="$withval" ],
  [ SANITIZERS="" ])

dnl Environment variable options

AC_ARG_VAR([CFLAGS_HARDENED_LIB], [extra C compiler flags for hardened libraries])
AC_ARG_VAR([LDFLAGS_HARDENED_LIB], [extra linker flags for hardened libraries])

AC_ARG_VAR([CFLAGS_HARDENED_EXE], [extra C compiler flags for hardened executables])
AC_ARG_VAR([LDFLAGS_HARDENED_EXE], [extra linker flags for hardened executables])


dnl ===============================================
dnl General Processing
dnl ===============================================

AC_DEFINE_UNQUOTED(PACEMAKER_VERSION, "$VERSION",
                   [Version number of this Pacemaker build])

PACKAGE_SERIES=`echo $VERSION | awk -F. '{ print $1"."$2 }'`
AC_SUBST(PACKAGE_SERIES)

AC_PROG_LN_S
AC_PROG_MKDIR_P

# Check for fatal warning support
AS_IF([test $enable_fatal_warnings -ne $DISABLED && test "$GCC" = "yes" && cc_supports_flag -Werror],
      [WERROR="-Werror"],
      [
          WERROR=""
          AS_CASE([$enable_fatal_warnings],
                  [$REQUIRED], [AC_MSG_ERROR([Compiler does not support fatal warnings])],
                  [$OPTIONAL], [
                      AC_MSG_NOTICE([Compiler does not support fatal warnings])
                      enable_fatal_warnings=$DISABLED
                  ])
      ])

AC_MSG_NOTICE([Sanitizing prefix: ${prefix}])
AS_IF([test "$prefix" = "NONE"],
      [
          prefix=/usr
          dnl Fix default variables - "prefix" variable if not specified
          AS_IF([test "$localstatedir" = "\${prefix}/var"],
                [localstatedir="/var"])
          AS_IF([test "$sysconfdir" = "\${prefix}/etc"],
                [sysconfdir="/etc"])
      ])

AC_MSG_NOTICE([Sanitizing exec_prefix: ${exec_prefix}])
case $exec_prefix in
    prefix|NONE)
        exec_prefix=$prefix
        ;;
esac

AC_MSG_NOTICE([Sanitizing INITDIR: ${INITDIR}])
case $INITDIR in
    prefix) INITDIR=$prefix;;
    "")
        AC_MSG_CHECKING([which init (rc) directory to use])
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
        AC_MSG_RESULT([$INITDIR])
        ;;
esac
AC_SUBST(INITDIR)

AC_MSG_NOTICE([Sanitizing libdir: ${libdir}])
case $libdir in
    prefix|NONE)
        AC_MSG_CHECKING([which lib directory to use])
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
        AC_MSG_RESULT([$libdir]);
        ;;
esac

dnl Expand values of autoconf-provided directory options
expand_path_option prefix
expand_path_option exec_prefix
expand_path_option bindir
expand_path_option sbindir
expand_path_option libexecdir
expand_path_option datadir
expand_path_option sysconfdir
expand_path_option sharedstatedir
expand_path_option localstatedir
expand_path_option libdir
expand_path_option includedir
expand_path_option oldincludedir
expand_path_option infodir
expand_path_option mandir

dnl Home-grown variables

expand_path_option localedir "${datadir}/locale"
AC_DEFINE_UNQUOTED([PCMK__LOCALE_DIR],["$localedir"], [Base directory for message catalogs])

AS_IF([test x"${runstatedir}" = x""], [runstatedir="${pcmk_runstatedir}"])
expand_path_option runstatedir "${localstatedir}/run"
AC_DEFINE_UNQUOTED([PCMK_RUN_DIR], ["$runstatedir"],
                   [Location for modifiable per-process data])
AC_SUBST(runstatedir)

expand_path_option INITDIR
AC_DEFINE_UNQUOTED([PCMK__LSB_INIT_DIR], ["$INITDIR"],
                   [Location for LSB init scripts])

expand_path_option docdir "${datadir}/doc/${PACKAGE}-${VERSION}"
AC_SUBST(docdir)

expand_path_option CONFIGDIR "${sysconfdir}/sysconfig"
AC_SUBST(CONFIGDIR)

expand_path_option PCMK__COROSYNC_CONF "${sysconfdir}/corosync/corosync.conf"
AC_SUBST(PCMK__COROSYNC_CONF)

expand_path_option CRM_LOG_DIR "${localstatedir}/log/pacemaker"
AC_DEFINE_UNQUOTED(CRM_LOG_DIR,"$CRM_LOG_DIR", Location for Pacemaker log file)
AC_SUBST(CRM_LOG_DIR)

expand_path_option CRM_BUNDLE_DIR "${localstatedir}/log/pacemaker/bundles"
AC_DEFINE_UNQUOTED(CRM_BUNDLE_DIR,"$CRM_BUNDLE_DIR", Location for Pacemaker bundle logs)
AC_SUBST(CRM_BUNDLE_DIR)

expand_path_option PCMK__FENCE_BINDIR
AC_DEFINE_UNQUOTED(PCMK__FENCE_BINDIR,"$PCMK__FENCE_BINDIR",
                   [Location for executable fence agents])

expand_path_option OCF_RA_PATH
AC_DEFINE_UNQUOTED([OCF_RA_PATH], ["$OCF_RA_PATH"],
                   [OCF directories to search for resource agents ])

AS_IF([test x"${PCMK_GNUTLS_PRIORITIES}" != x""], [],
      [AC_MSG_ERROR([--with-gnutls-priorities value must not be empty])])
AC_DEFINE_UNQUOTED([PCMK_GNUTLS_PRIORITIES], ["$PCMK_GNUTLS_PRIORITIES"],
                   [GnuTLS cipher priorities])

if test x"${BUG_URL}" = x""; then
    BUG_URL="https://bugs.clusterlabs.org/enter_bug.cgi?product=Pacemaker"
fi
AC_SUBST(BUG_URL)

for j in prefix exec_prefix bindir sbindir libexecdir datadir sysconfdir \
    sharedstatedir localstatedir libdir includedir oldincludedir infodir \
    mandir INITDIR docdir CONFIGDIR localedir
do
    dirname=`eval echo '${'${j}'}'`
    if
        test ! -d "$dirname"
    then
        AC_MSG_WARN([$j directory ($dirname) does not exist (yet)])
    fi
done

us_auth=
AC_CHECK_HEADER([sys/socket.h], [
    AC_CHECK_DECL([SO_PEERCRED], [
        # Linux
        AC_CHECK_TYPE([struct ucred], [
            us_auth=peercred_ucred;
            AC_DEFINE([US_AUTH_PEERCRED_UCRED], [1],
                      [Define if Unix socket auth method is
                       getsockopt(s, SO_PEERCRED, &ucred, ...)])
        ], [
            # OpenBSD
            AC_CHECK_TYPE([struct sockpeercred], [
                us_auth=localpeercred_sockepeercred;
                AC_DEFINE([US_AUTH_PEERCRED_SOCKPEERCRED], [1],
                          [Define if Unix socket auth method is
                           getsockopt(s, SO_PEERCRED, &sockpeercred, ...)])
            ], [], [[#include <sys/socket.h>]])
        ], [[#define _GNU_SOURCE
             #include <sys/socket.h>]])
    ], [], [[#include <sys/socket.h>]])
])

AS_IF([test -z "${us_auth}"], [
    # FreeBSD
    AC_CHECK_DECL([getpeereid], [
        us_auth=getpeereid;
        AC_DEFINE([US_AUTH_GETPEEREID], [1],
                  [Define if Unix socket auth method is
                   getpeereid(s, &uid, &gid)])
    ], [
        # Solaris/OpenIndiana
        AC_CHECK_DECL([getpeerucred], [
            us_auth=getpeerucred;
            AC_DEFINE([US_AUTH_GETPEERUCRED], [1],
                      [Define if Unix socket auth method is
                       getpeercred(s, &ucred)])
        ], [
            AC_MSG_FAILURE([No way to authenticate a Unix socket peer])
        ], [[#include <ucred.h>]])
    ])
])

dnl OS-based decision-making is poor autotools practice; feature-based
dnl mechanisms are strongly preferred. Keep this section to a bare minimum;
dnl regard as a "necessary evil".
INIT_EXT=""
PROCFS=0
case "$host_os" in
    dnl Solaris and some *BSD versions support procfs but not files we need
    *bsd*)
        INIT_EXT=".sh"
        ;;
    *linux*)
        PROCFS=1
        ;;
    darwin*)
        LIBS="$LIBS -L${prefix}/lib"
        CFLAGS="$CFLAGS -I${prefix}/include"
        ;;
esac

AC_SUBST(INIT_EXT)
AC_DEFINE_UNQUOTED([SUPPORT_PROCFS], [$PROCFS],
                   [Define to 1 if procfs is supported])

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
AS_IF([test "x${LIBTOOL}" != "x"], [],
      [AC_MSG_FAILURE([Could not find required build tool libtool (or equivalent)])])

dnl Pacemaker's executable python scripts will invoke the python specified by
dnl configure's PYTHON variable. If not specified, AM_PATH_PYTHON will check a
dnl built-in list with (unversioned) "python" having precedence. To configure
dnl Pacemaker to use a specific python interpreter version, define PYTHON
dnl when calling configure, for example: ./configure PYTHON=/usr/bin/python3.6

dnl Ensure PYTHON is an absolute path
AS_IF([test x"${PYTHON}" != x""], [AC_PATH_PROG([PYTHON], [$PYTHON])])

dnl Require a minimum Python version
AM_PATH_PYTHON([3.4])

AC_PATH_PROGS([ASCIIDOC_CONV], [asciidoc asciidoctor])
AC_PATH_PROG([HELP2MAN], [help2man])
AC_PATH_PROG([SPHINX], [sphinx-build])
AC_PATH_PROG([INKSCAPE], [inkscape])
AC_PATH_PROG([XSLTPROC], [xsltproc])
AC_PATH_PROG([XMLCATALOG], [xmlcatalog])

dnl Bash is needed for building man pages and running regression tests.
dnl BASH is already an environment variable, so use something else.
AC_PATH_PROG([BASH_PATH], [bash])
AS_IF([test "x${BASH_PATH}" != "x"], [],
      [AC_MSG_FAILURE([Could not find required build tool bash])])

AC_PATH_PROGS(VALGRIND_BIN, valgrind, /usr/bin/valgrind)
AC_DEFINE_UNQUOTED(VALGRIND_BIN, "$VALGRIND_BIN", Valgrind command)

AM_CONDITIONAL(BUILD_HELP, test x"${HELP2MAN}" != x"")
if test x"${HELP2MAN}" != x""; then
    PCMK_FEATURES="$PCMK_FEATURES generated-manpages"
fi

MANPAGE_XSLT=""
if test x"${XSLTPROC}" != x""; then
    AC_MSG_CHECKING([for DocBook-to-manpage transform])
    # first try to figure out correct template using xmlcatalog query,
    # resort to extensive (semi-deterministic) file search if that fails
    DOCBOOK_XSL_URI='http://docbook.sourceforge.net/release/xsl/current'
    DOCBOOK_XSL_PATH='manpages/docbook.xsl'
    MANPAGE_XSLT=$(${XMLCATALOG} "" ${DOCBOOK_XSL_URI}/${DOCBOOK_XSL_PATH} \
                   | sed -n 's|^file://||p;q')
    if test x"${MANPAGE_XSLT}" = x""; then
        DIRS=$(find "${datadir}" -name $(basename $(dirname ${DOCBOOK_XSL_PATH})) \
               -type d 2>/dev/null | LC_ALL=C sort)
        XSLT=$(basename ${DOCBOOK_XSL_PATH})
        for d in ${DIRS}
        do
            if test -f "${d}/${XSLT}"; then
                 MANPAGE_XSLT="${d}/${XSLT}"
                 break
            fi
        done
    fi
fi
AC_MSG_RESULT([$MANPAGE_XSLT])
AC_SUBST(MANPAGE_XSLT)

AM_CONDITIONAL(BUILD_XML_HELP, test x"${MANPAGE_XSLT}" != x"")
if test x"${MANPAGE_XSLT}" != x""; then
    PCMK_FEATURES="$PCMK_FEATURES agent-manpages"
fi

AM_CONDITIONAL([IS_ASCIIDOC], [echo "${ASCIIDOC_CONV}" | grep -Eq 'asciidoc$'])
AM_CONDITIONAL([BUILD_ASCIIDOC], [test "x${ASCIIDOC_CONV}" != x])
if test "x${ASCIIDOC_CONV}" != x; then
    PCMK_FEATURES="$PCMK_FEATURES ascii-docs"
fi

AM_CONDITIONAL([BUILD_SPHINX_DOCS],
               [test x"${SPHINX}" != x"" && test x"${INKSCAPE}" != x""])
AM_COND_IF([BUILD_SPHINX_DOCS], [PCMK_FEATURES="$PCMK_FEATURES books"])

dnl Pacemaker's shell scripts (and thus man page builders) rely on GNU getopt
AC_MSG_CHECKING([for GNU-compatible getopt])
IFS_orig=$IFS
IFS=:
for PATH_DIR in $PATH
do
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
AS_IF([test -n "$GETOPT_PATH"], [AC_MSG_RESULT([$GETOPT_PATH])],
      [
          AC_MSG_RESULT([no])
          AC_MSG_ERROR([Could not find required build tool GNU-compatible getopt])
      ])
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
dnl     strerror: returns a string that corresponds to an errno.
dnl             A replacement function is supplied for it.
dnl
dnl     strnlen: is a gnu function similar to strlen, but safer.
dnl            We wrote a tolerably-fast replacement function for it.
dnl
dnl     strndup: is a gnu function similar to strdup, but safer.
dnl            We wrote a tolerably-fast replacement function for it.

AC_REPLACE_FUNCS(alphasort NoSuchFunctionName scandir strerror strchrnul strnlen strndup)

dnl ===============================================
dnl Libraries
dnl ===============================================
AC_CHECK_LIB(socket, socket)                    dnl -lsocket
AC_CHECK_LIB(c, dlopen)                         dnl if dlopen is in libc...
AC_CHECK_LIB(dl, dlopen)                        dnl -ldl (for Linux)
AC_CHECK_LIB(rt, sched_getscheduler)            dnl -lrt (for Tru64)
AC_CHECK_LIB(gnugetopt, getopt_long)            dnl -lgnugetopt ( if available )
AC_CHECK_LIB(pam, pam_start)                    dnl -lpam (if available)

PKG_CHECK_MODULES([UUID], [uuid],
                  [CPPFLAGS="${CPPFLAGS} ${UUID_CFLAGS}"
                   LIBS="${LIBS} ${UUID_LIBS}"])

AC_CHECK_FUNCS([sched_setscheduler])
if test "$ac_cv_func_sched_setscheduler" != yes; then
        PC_LIBS_RT=""
else
        PC_LIBS_RT="-lrt"
fi
AC_SUBST(PC_LIBS_RT)

# Require minimum glib version
PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.42.0],
                  [CPPFLAGS="${CPPFLAGS} ${GLIB_CFLAGS}"
                   LIBS="${LIBS} ${GLIB_LIBS}"])

# Check whether high-resolution sleep function is available
AC_CHECK_FUNCS([nanosleep usleep])

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

PKG_CHECK_MODULES(LIBXML2, [libxml-2.0],
                  [CPPFLAGS="${CPPFLAGS} ${LIBXML2_CFLAGS}"
                   LIBS="${LIBS} ${LIBXML2_LIBS}"])

REQUIRE_LIB([xslt], [xsltApplyStylesheet])

dnl ========================================================================
dnl Headers
dnl ========================================================================

# Some distributions insert #warnings into deprecated headers. If we will
# enable fatal warnings for the build, then enable them for the header checks
# as well, otherwise the build could fail even though the header check
# succeeds. (We should probably be doing this in more places.)
cc_temp_flags "$CFLAGS $WERROR"

# Optional headers (inclusion of these should be conditional in C code)
AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([linux/swab.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([sys/signalfd.h])
AC_CHECK_HEADERS([uuid/uuid.h])
AC_CHECK_HEADERS([security/pam_appl.h pam/pam_appl.h])

# Required headers
REQUIRE_HEADER([arpa/inet.h])
REQUIRE_HEADER([ctype.h])
REQUIRE_HEADER([dirent.h])
REQUIRE_HEADER([errno.h])
REQUIRE_HEADER([glib.h])
REQUIRE_HEADER([grp.h])
REQUIRE_HEADER([limits.h])
REQUIRE_HEADER([netdb.h])
REQUIRE_HEADER([netinet/in.h])
REQUIRE_HEADER([netinet/ip.h], [
    #include <sys/types.h>
    #include <netinet/in.h>
])
REQUIRE_HEADER([pwd.h])
REQUIRE_HEADER([signal.h])
REQUIRE_HEADER([stdio.h])
REQUIRE_HEADER([stdlib.h])
REQUIRE_HEADER([string.h])
REQUIRE_HEADER([strings.h])
REQUIRE_HEADER([sys/ioctl.h])
REQUIRE_HEADER([sys/param.h])
REQUIRE_HEADER([sys/reboot.h])
REQUIRE_HEADER([sys/resource.h])
REQUIRE_HEADER([sys/socket.h])
REQUIRE_HEADER([sys/stat.h])
REQUIRE_HEADER([sys/time.h])
REQUIRE_HEADER([sys/types.h])
REQUIRE_HEADER([sys/utsname.h])
REQUIRE_HEADER([sys/wait.h])
REQUIRE_HEADER([time.h])
REQUIRE_HEADER([unistd.h])
REQUIRE_HEADER([libxml/xpath.h])
REQUIRE_HEADER([libxslt/xslt.h])

cc_restore_flags

AC_CHECK_FUNCS([uuid_unparse], [],
               [AC_MSG_FAILURE([Could not find required C function uuid_unparse()])])

AC_CACHE_CHECK([whether __progname and __progname_full are available],
               [pf_cv_var_progname], AC_LINK_IFELSE([
                   AC_LANG_PROGRAM([[extern char *__progname, *__progname_full;]],
                                   [[__progname = "foo"; __progname_full = "foo bar";]],
                                   [pf_cv_var_progname="yes"],
                                   [pf_cv_var_progname="no"])
               ]))
AS_IF([test "$pf_cv_var_progname" = "yes"], [AC_DEFINE(HAVE___PROGNAME,1,[ ])])

dnl ========================================================================
dnl Generic declarations
dnl ========================================================================

AC_CHECK_DECLS([CLOCK_MONOTONIC], [PCMK_FEATURES="$PCMK_FEATURES monotonic"], [], [[
    #include <time.h>
]])

dnl ========================================================================
dnl Unit test declarations
dnl ========================================================================

AC_CHECK_DECLS([assert_float_equal], [], [], [[
    #include <stdarg.h>
    #include <stddef.h>
    #include <setjmp.h>
    #include <cmocka.h>
]])

cc_temp_flags "$CFLAGS -Wl,--wrap=uname"

WRAPPABLE_UNAME="no"

AC_MSG_CHECKING([if uname() can be wrapped])
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/utsname.h>
int __wrap_uname(struct utsname *buf) {
return 100;
}
int main(int argc, char **argv) {
struct utsname x;
return uname(&x) == 100 ? 0 : 1;
}
]])],
                   [ WRAPPABLE_UNAME="yes" ], [ WRAPPABLE_UNAME="no"])
AC_MSG_RESULT([$WRAPPABLE_UNAME])
AM_CONDITIONAL([WRAPPABLE_UNAME], [test "$WRAPPABLE_UNAME" = "yes"])

cc_restore_flags

dnl ========================================================================
dnl Structures
dnl ========================================================================

AC_CHECK_MEMBERS([struct tm.tm_gmtoff],,,[[#include <time.h>]])
AC_CHECK_MEMBER([struct dirent.d_type],
    AC_DEFINE(HAVE_STRUCT_DIRENT_D_TYPE,1,[Define this if struct dirent has d_type]),,
    [#include <dirent.h>])

dnl ========================================================================
dnl Functions
dnl ========================================================================

REQUIRE_FUNC([getopt])
REQUIRE_FUNC([setenv])
REQUIRE_FUNC([unsetenv])

AC_CACHE_CHECK(whether sscanf supports %m,
               pf_cv_var_sscanf,
               AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdio.h>
const char *s = "some-command-line-arg";
int main(int argc, char **argv) {
char *name = NULL;
int n = sscanf(s, "%ms", &name);
return n == 1 ? 0 : 1;
}
]])],
                                 pf_cv_var_sscanf="yes", pf_cv_var_sscanf="no", pf_cv_var_sscanf="no"))

AS_IF([test "$pf_cv_var_sscanf" = "yes"], [AC_DEFINE(SSCANF_HAS_M, 1, [ ])])

dnl ========================================================================
dnl   bzip2
dnl ========================================================================
REQUIRE_HEADER([bzlib.h])
REQUIRE_LIB([bz2], [BZ2_bzBuffToBuffCompress])

dnl ========================================================================
dnl sighandler_t is missing from Illumos, Solaris11 systems
dnl ========================================================================

AC_MSG_CHECKING([for sighandler_t])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <signal.h>]], [[sighandler_t *f;]])],
                  [
                      AC_MSG_RESULT([yes])
                      AC_DEFINE([HAVE_SIGHANDLER_T], [1],
                                [Define to 1 if sighandler_t is available])
                  ],
                  [AC_MSG_RESULT([no])])

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
dnl ncurses takes precedence.
dnl
AC_CHECK_HEADERS([curses.h curses/curses.h ncurses.h ncurses/ncurses.h])

dnl Although n-library is preferred, only look for it if the n-header was found.
CURSESLIBS=''
PC_NAME_CURSES=""
PC_LIBS_CURSES=""
AS_IF([test "$ac_cv_header_ncurses_h" = "yes"], [
    AC_CHECK_LIB(ncurses, printw,
                 [AC_DEFINE(HAVE_LIBNCURSES,1, have ncurses library)])
    CURSESLIBS=`$PKG_CONFIG --libs ncurses` || CURSESLIBS='-lncurses'
    PC_NAME_CURSES="ncurses"
])

AS_IF([test "$ac_cv_header_ncurses_ncurses_h" = "yes"], [
    AC_CHECK_LIB(ncurses, printw,
                 [AC_DEFINE(HAVE_LIBNCURSES,1, have ncurses library)])
    CURSESLIBS=`$PKG_CONFIG --libs ncurses` || CURSESLIBS='-lncurses'
    PC_NAME_CURSES="ncurses"
])

dnl Only look for non-n-library if there was no n-library.
AS_IF([test X"$CURSESLIBS" = X"" && test "$ac_cv_header_curses_h" = "yes"], [
    AC_CHECK_LIB(curses, printw,
                 [CURSESLIBS='-lcurses'; AC_DEFINE(HAVE_LIBCURSES,1, have curses library)])
    PC_LIBS_CURSES="$CURSESLIBS"
])

dnl Only look for non-n-library if there was no n-library.
AS_IF([test X"$CURSESLIBS" = X"" && test "$ac_cv_header_curses_curses_h" = "yes"], [
    AC_CHECK_LIB(curses, printw,
                 [CURSESLIBS='-lcurses'; AC_DEFINE(HAVE_LIBCURSES,1, have curses library)])
    PC_LIBS_CURSES="$CURSESLIBS"
])

if test "x$CURSESLIBS" != "x"; then
    PCMK_FEATURES="$PCMK_FEATURES ncurses"
fi

dnl Check for printw() prototype compatibility
AS_IF([test X"$CURSESLIBS" != X"" && cc_supports_flag -Wcast-qual], [
    ac_save_LIBS=$LIBS
    LIBS="$CURSESLIBS"
    cc_temp_flags "-Wcast-qual $WERROR"
    # avoid broken test because of hardened build environment in Fedora 23+
    # - https://fedoraproject.org/wiki/Changes/Harden_All_Packages
    # - https://bugzilla.redhat.com/1297985
    AS_IF([cc_supports_flag -fPIC], [CFLAGS="$CFLAGS -fPIC"])

    AC_MSG_CHECKING([whether curses library is compatible])
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
        [AC_MSG_RESULT([yes])],
        [
            AC_MSG_RESULT([no])
            AC_MSG_WARN(m4_normalize([Disabling curses because the printw()
                                      function of your (n)curses library is old.
                                      If you wish to enable curses, update to a
                                      newer version (ncurses 5.4 or later is
                                      recommended, available from
                                      https://invisible-island.net/ncurses/)
                                     ]))
            AC_DEFINE([HAVE_INCOMPATIBLE_PRINTW], [1],
                      [Define to 1 if curses library has incompatible printw()])
        ]
    )

    LIBS=$ac_save_LIBS
    cc_restore_flags
])

AC_SUBST(CURSESLIBS)
AC_SUBST(PC_NAME_CURSES)
AC_SUBST(PC_LIBS_CURSES)

dnl ========================================================================
dnl    Profiling and GProf
dnl ========================================================================

CFLAGS_ORIG="$CFLAGS"
AS_IF([test $with_coverage -ne $DISABLED],
      [
        with_profiling=$REQUIRED
        PCMK_FEATURES="$PCMK_FEATURES coverage"
        CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
        dnl During linking, make sure to specify -lgcov or -coverage
      ]
)

AS_IF([test $with_profiling -ne $DISABLED],
      [
          with_profiling=$REQUIRED
          PCMK_FEATURES="$PCMK_FEATURES profile"

          dnl Disable various compiler optimizations
          CFLAGS="$CFLAGS -fno-omit-frame-pointer -fno-inline -fno-builtin"
          dnl CFLAGS="$CFLAGS -fno-inline-functions"
          dnl CFLAGS="$CFLAGS -fno-default-inline"
          dnl CFLAGS="$CFLAGS -fno-inline-functions-called-once"
          dnl CFLAGS="$CFLAGS -fno-optimize-sibling-calls"

          dnl Turn off optimization so tools can get accurate line numbers
          CFLAGS=`echo $CFLAGS | sed \
                  -e 's/-O.\ //g' \
                  -e 's/-Wp,-D_FORTIFY_SOURCE=.\ //g' \
                  -e 's/-D_FORTIFY_SOURCE=.\ //g'`
          CFLAGS="$CFLAGS -O0 -g3 -gdwarf-2"

          AC_MSG_NOTICE([CFLAGS before adding profiling options: $CFLAGS_ORIG])
          AC_MSG_NOTICE([CFLAGS after: $CFLAGS])
      ]
)
AC_DEFINE_UNQUOTED([SUPPORT_PROFILING], [$with_profiling], [Support profiling])
AM_CONDITIONAL([BUILD_PROFILING], [test "$with_profiling" = "$REQUIRED"])

dnl ========================================================================
dnl    Cluster infrastructure - LibQB
dnl ========================================================================

PKG_CHECK_MODULES(libqb, libqb >= 0.17)
CPPFLAGS="$libqb_CFLAGS $CPPFLAGS"
LIBS="$libqb_LIBS $LIBS"

dnl libqb 2.0.2+ (2020-10)
AC_CHECK_FUNCS(qb_ipcc_auth_get,
               AC_DEFINE(HAVE_IPCC_AUTH_GET, 1,
                         [Have qb_ipcc_auth_get function]))

dnl libqb 2.0.0+ (2020-05)
CHECK_ENUM_VALUE([qb/qblog.h],[qb_log_conf],[QB_LOG_CONF_MAX_LINE_LEN])
CHECK_ENUM_VALUE([qb/qblog.h],[qb_log_conf],[QB_LOG_CONF_ELLIPSIS])

dnl Support Linux-HA fence agents if available
if test "$cross_compiling" != "yes"; then
    CPPFLAGS="$CPPFLAGS -I${prefix}/include/heartbeat"
fi
AC_CHECK_HEADERS([stonith/stonith.h],
                 [
                     AC_CHECK_LIB([pils], [PILLoadPlugin])
                     AC_CHECK_LIB([plumb], [G_main_add_IPC_Channel])
                     PCMK_FEATURES="$PCMK_FEATURES lha"
                 ])
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

if test x"${CRM_DAEMON_USER}" = x""; then
    CRM_DAEMON_USER="hacluster"
fi
AC_DEFINE_UNQUOTED(CRM_DAEMON_USER,"$CRM_DAEMON_USER", User to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_USER)

if test x"${CRM_DAEMON_GROUP}" = x""; then
    CRM_DAEMON_GROUP="haclient"
fi
AC_DEFINE_UNQUOTED(CRM_DAEMON_GROUP,"$CRM_DAEMON_GROUP", Group to run Pacemaker daemons as)
AC_SUBST(CRM_DAEMON_GROUP)

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

CRM_STATE_DIR="${runstatedir}/crm"
AC_DEFINE_UNQUOTED([CRM_STATE_DIR], ["$CRM_STATE_DIR"],
                   [Where to keep state files and sockets])
AC_SUBST(CRM_STATE_DIR)

CRM_RSCTMP_DIR="${runstatedir}/resource-agents"
AC_DEFINE_UNQUOTED(CRM_RSCTMP_DIR,"$CRM_RSCTMP_DIR", Where resource agents should keep state files)
AC_SUBST(CRM_RSCTMP_DIR)

PACEMAKER_CONFIG_DIR="${sysconfdir}/pacemaker"
AC_DEFINE_UNQUOTED(PACEMAKER_CONFIG_DIR,"$PACEMAKER_CONFIG_DIR", Where to keep configuration files like authkey)
AC_SUBST(PACEMAKER_CONFIG_DIR)

AC_DEFINE_UNQUOTED(SBIN_DIR,"$sbindir",[Location for system binaries])

AC_PATH_PROGS(GIT, git false)

AC_MSG_CHECKING([build version])
BUILD_VERSION=$Format:%h$
if test $BUILD_VERSION != ":%h$"; then
    AC_MSG_RESULT([$BUILD_VERSION (archive hash)])
elif test -x $GIT && test -d .git; then
    BUILD_VERSION=`$GIT log --pretty="format:%h" -n 1`
    AC_MSG_RESULT([$BUILD_VERSION (git hash)])
else
    # The current directory name make a reasonable default
    # Most generated archives will include the hash or tag
    BASE=`basename $PWD`
    BUILD_VERSION=`echo $BASE | sed s:.*[[Pp]]acemaker-::`
    AC_MSG_RESULT([$BUILD_VERSION (directory name)])
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
if test $HAVE_dbus = 0; then
        PC_NAME_DBUS=""
else
        PC_NAME_DBUS="dbus-1"
fi
AC_SUBST(PC_NAME_DBUS)

AS_CASE([$enable_systemd],
        [$REQUIRED], [
            AS_IF([test $HAVE_dbus = 0],
                  [AC_MSG_FAILURE([Cannot support systemd resources without DBus])])
            AS_IF([test "$ac_cv_have_decl_CLOCK_MONOTONIC" = "no"],
                  [AC_MSG_FAILURE([Cannot support systemd resources without monotonic clock])])
            AS_IF([check_systemdsystemunitdir], [],
                  [AC_MSG_FAILURE([Cannot support systemd resources without systemdsystemunitdir])])
        ],
        [$OPTIONAL], [
            AS_IF([test $HAVE_dbus = 0 \
                   || test "$ac_cv_have_decl_CLOCK_MONOTONIC" = "no"],
                  [enable_systemd=$DISABLED],
                  [
                      AC_MSG_CHECKING([for systemd version (using dbus-send)])
                      ret=$({ dbus-send --system --print-reply \
                                  --dest=org.freedesktop.systemd1 \
                                  /org/freedesktop/systemd1 \
                                  org.freedesktop.DBus.Properties.Get \
                                  string:org.freedesktop.systemd1.Manager \
                                  string:Version 2>/dev/null \
                              || echo "version unavailable"; } | tail -n1)
                      # sanitize output a bit (interested just in value, not type),
                      # ret is intentionally unenquoted so as to normalize whitespace
                      ret=$(echo ${ret} | cut -d' ' -f2-)
                      AC_MSG_RESULT([${ret}])
                      AS_IF([test "$ret" != "unavailable" \
                             || systemctl --version 2>/dev/null | grep -q systemd],
                            [
                                AS_IF([check_systemdsystemunitdir],
                                      [enable_systemd=$REQUIRED],
                                      [enable_systemd=$DISABLED])
                            ],
                            [enable_systemd=$DISABLED]
                      )
                  ])
        ],
)
AC_MSG_CHECKING([whether to enable support for managing resources via systemd])
AS_IF([test $enable_systemd -eq $DISABLED], [AC_MSG_RESULT([no])],
      [
          AC_MSG_RESULT([yes])
          PCMK_FEATURES="$PCMK_FEATURES systemd"
      ]
)
AC_SUBST([systemdsystemunitdir])
AC_DEFINE_UNQUOTED([SUPPORT_SYSTEMD], [$enable_systemd],
                   [Support systemd resources])
AM_CONDITIONAL([BUILD_SYSTEMD], [test $enable_systemd = $REQUIRED])
AC_SUBST(SUPPORT_SYSTEMD)

AS_CASE([$enable_upstart],
        [$REQUIRED], [
            AS_IF([test $HAVE_dbus = 0],
                  [AC_MSG_FAILURE([Cannot support Upstart resources without DBus])])
        ],
        [$OPTIONAL], [
            AS_IF([test $HAVE_dbus = 0], [enable_upstart=$DISABLED],
                  [
                      AC_MSG_CHECKING([for Upstart version (using dbus-send)])
                      ret=$({ dbus-send --system --print-reply \
                                  --dest=com.ubuntu.Upstart \
                                  /com/ubuntu/Upstart org.freedesktop.DBus.Properties.Get \
                                  string:com.ubuntu.Upstart0_6 string:version 2>/dev/null \
                              || echo "version unavailable"; } | tail -n1)
                      # sanitize output a bit (interested just in value, not type),
                      # ret is intentionally unenquoted so as to normalize whitespace
                      ret=$(echo ${ret} | cut -d' ' -f2-)
                      AC_MSG_RESULT([${ret}])
                      AS_IF([test "$ret" != "unavailable" \
                             || initctl --version 2>/dev/null | grep -q upstart],
                            [enable_upstart=$REQUIRED],
                            [enable_upstart=$DISABLED]
                      )
                  ])
        ],
)
AC_MSG_CHECKING([whether to enable support for managing resources via Upstart])
AS_IF([test $enable_upstart -eq $DISABLED], [AC_MSG_RESULT([no])],
      [
          AC_MSG_RESULT([yes])
          PCMK_FEATURES="$PCMK_FEATURES upstart"
      ]
)
AC_DEFINE_UNQUOTED([SUPPORT_UPSTART], [$enable_upstart],
                   [Support Upstart resources])
AM_CONDITIONAL([BUILD_UPSTART], [test $enable_upstart -eq $REQUIRED])
AC_SUBST(SUPPORT_UPSTART)

AS_CASE([$with_nagios],
        [$REQUIRED], [
            AS_IF([test "$ac_cv_have_decl_CLOCK_MONOTONIC" = "no"],
                  [AC_MSG_FAILURE([Cannot support nagios resources without monotonic clock])])
        ],
        [$OPTIONAL], [
            AS_IF([test "$ac_cv_have_decl_CLOCK_MONOTONIC" = "no"],
                  [with_nagios=$DISABLED], [with_nagios=$REQUIRED])
        ]
)
AS_IF([test $with_nagios -eq $REQUIRED], [PCMK_FEATURES="$PCMK_FEATURES nagios"])
AC_DEFINE_UNQUOTED([SUPPORT_NAGIOS], [$with_nagios], [Support nagios plugins])
AM_CONDITIONAL([BUILD_NAGIOS], [test $with_nagios -eq $REQUIRED])

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
PC_NAME_CLUSTER=""

dnl ========================================================================
dnl    Cluster stack - Corosync
dnl ========================================================================

COROSYNC_LIBS=""

AS_CASE([$with_corosync],
        [$REQUIRED], [
            # These will be fatal if unavailable
            PKG_CHECK_MODULES([cpg], [libcpg])
            PKG_CHECK_MODULES([cfg], [libcfg])
            PKG_CHECK_MODULES([cmap], [libcmap])
            PKG_CHECK_MODULES([quorum], [libquorum])
            PKG_CHECK_MODULES([libcorosync_common], [libcorosync_common])
        ]
        [$OPTIONAL], [
            PKG_CHECK_MODULES([cpg], [libcpg], [], [with_corosync=$DISABLED])
            PKG_CHECK_MODULES([cfg], [libcfg], [], [with_corosync=$DISABLED])
            PKG_CHECK_MODULES([cmap], [libcmap], [], [with_corosync=$DISABLED])
            PKG_CHECK_MODULES([quorum], [libquorum], [], [with_corosync=$DISABLED])
            PKG_CHECK_MODULES([libcorosync_common], [libcorosync_common], [], [with_corosync=$DISABLED])
            AS_IF([test $with_corosync -ne $DISABLED], [with_corosync=$REQUIRED])
        ]
)
AS_IF([test $with_corosync -ne $DISABLED],
      [
          AC_MSG_CHECKING([for Corosync 2 or later])
          AC_MSG_RESULT([yes])
          CFLAGS="$CFLAGS $libqb_CFLAGS $cpg_CFLAGS $cfg_CFLAGS $cmap_CFLAGS $quorum_CFLAGS $libcorosync_common_CFLAGS"
          COROSYNC_LIBS="$COROSYNC_LIBS $cpg_LIBS $cfg_LIBS $cmap_LIBS $quorum_LIBS $libcorosync_common_LIBS"
          CLUSTERLIBS="$CLUSTERLIBS $COROSYNC_LIBS"
          PC_NAME_CLUSTER="$PC_CLUSTER_NAME libcfg libcmap libcorosync_common libcpg libquorum"
          STACKS="$STACKS corosync-ge-2"

          dnl Shutdown tracking added (back) to corosync Jan 2021
          saved_LIBS="$LIBS"
          LIBS="$LIBS $COROSYNC_LIBS"
          AC_CHECK_FUNCS(corosync_cfg_trackstart,
          AC_DEFINE(HAVE_COROSYNC_CFG_TRACKSTART, 1,
                         [Have corosync_cfg_trackstart function]))
          LIBS="$saved_LIBS"
      ]
)
AC_DEFINE_UNQUOTED([SUPPORT_COROSYNC], [$with_corosync],
                   [Support the Corosync messaging and membership layer])
AM_CONDITIONAL([BUILD_CS_SUPPORT], [test $with_corosync -eq $REQUIRED])
AC_SUBST([SUPPORT_COROSYNC])

dnl
dnl    Cluster stack - Sanity
dnl

AS_IF([test "x$STACKS" != "x"], [AC_MSG_NOTICE([Supported stacks:${STACKS}])],
      [AC_MSG_FAILURE([At least one cluster stack must be supported])])

PCMK_FEATURES="${PCMK_FEATURES}${STACKS}"

AC_SUBST(CLUSTERLIBS)
AC_SUBST(PC_NAME_CLUSTER)

dnl ========================================================================
dnl    CIB secrets
dnl ========================================================================

AS_IF([test $with_cibsecrets -ne $DISABLED],
      [
          with_cibsecrets=$REQUIRED
          PCMK_FEATURES="$PCMK_FEATURES cibsecrets"
          LRM_CIBSECRETS_DIR="${localstatedir}/lib/pacemaker/lrm/secrets"
          AC_DEFINE_UNQUOTED([LRM_CIBSECRETS_DIR], ["$LRM_CIBSECRETS_DIR"],
                             [Location for CIB secrets])
          AC_SUBST([LRM_CIBSECRETS_DIR])
      ]
)
AC_DEFINE_UNQUOTED([SUPPORT_CIBSECRETS], [$with_cibsecrets], [Support CIB secrets])
AM_CONDITIONAL([BUILD_CIBSECRETS], [test $with_cibsecrets -eq $REQUIRED])

dnl ========================================================================
dnl    GnuTLS
dnl ========================================================================

dnl Require GnuTLS >=2.12.0 (2011-03) for Pacemaker Remote support
PC_NAME_GNUTLS=""
AS_CASE([$with_gnutls],
        [$REQUIRED], [
            REQUIRE_LIB([gnutls], [gnutls_sec_param_to_pk_bits])
            REQUIRE_HEADER([gnutls/gnutls.h])
        ],
        [$OPTIONAL], [
            AC_CHECK_LIB([gnutls], [gnutls_sec_param_to_pk_bits],
                         [], [with_gnutls=$DISABLED])
            AC_CHECK_HEADERS([gnutls/gnutls.h], [], [with_gnutls=$DISABLED])
        ]
)
AS_IF([test $with_gnutls -ne $DISABLED],
      [
          PC_NAME_GNUTLS="gnutls"
          PCMK_FEATURES="$PCMK_FEATURES remote"
      ]
)
AC_SUBST([PC_NAME_GNUTLS])
AM_CONDITIONAL([BUILD_REMOTE], [test $with_gnutls -ne $DISABLED])

dnl ========================================================================
dnl    System Health
dnl ========================================================================

dnl Check if servicelog development package is installed
SERVICELOG=servicelog-1
SERVICELOG_EXISTS="no"
AC_MSG_CHECKING([for $SERVICELOG packages])
if
    $PKG_CONFIG --exists $SERVICELOG
then
    PKG_CHECK_MODULES([SERVICELOG], [servicelog-1])
    SERVICELOG_EXISTS="yes"
    PCMK_FEATURES="$PCMK_FEATURES servicelog"
fi
AC_MSG_RESULT([$SERVICELOG_EXISTS])
AM_CONDITIONAL(BUILD_SERVICELOG, test "$SERVICELOG_EXISTS" = "yes")

dnl Check if OpenIMPI packages and servicelog are installed
OPENIPMI="OpenIPMI OpenIPMIposix"
OPENIPMI_SERVICELOG_EXISTS="no"
AC_MSG_CHECKING([for $SERVICELOG $OPENIPMI packages])
if
    $PKG_CONFIG --exists $OPENIPMI $SERVICELOG
then
    PKG_CHECK_MODULES([OPENIPMI_SERVICELOG],[OpenIPMI OpenIPMIposix])
    REQUIRE_HEADER([malloc.h])
    OPENIPMI_SERVICELOG_EXISTS="yes"
    PCMK_FEATURES="$PCMK_FEATURES ipmiservicelogd"
fi
AC_MSG_RESULT([$OPENIPMI_SERVICELOG_EXISTS])
AM_CONDITIONAL(BUILD_OPENIPMI_SERVICELOG, test "$OPENIPMI_SERVICELOG_EXISTS" = "yes")

# --- ASAN/UBSAN/TSAN (see man gcc) ---
# when using SANitizers, we need to pass the -fsanitize..
# to both CFLAGS and LDFLAGS. The CFLAGS/LDFLAGS must be
# specified as first in the list or there will be runtime
# issues (for example user has to LD_PRELOAD asan for it to work
# properly).

AS_IF([test -n "${SANITIZERS}"], [
  SANITIZERS=$(echo $SANITIZERS | sed -e 's/,/ /g')
  for SANITIZER in $SANITIZERS
  do
    AS_CASE([$SANITIZER],
            [asan|ASAN], [
                SANITIZERS_CFLAGS="$SANITIZERS_CFLAGS -fsanitize=address"
                SANITIZERS_LDFLAGS="$SANITIZERS_LDFLAGS -fsanitize=address -lasan"
                PCMK_FEATURES="$PCMK_FEATURES asan"
                REQUIRE_LIB([asan],[main])
            ],
            [ubsan|UBSAN], [
                SANITIZERS_CFLAGS="$SANITIZERS_CFLAGS -fsanitize=undefined"
                SANITIZERS_LDFLAGS="$SANITIZERS_LDFLAGS -fsanitize=undefined -lubsan"
                PCMK_FEATURES="$PCMK_FEATURES ubsan"
                REQUIRE_LIB([ubsan],[main])
            ],
            [tsan|TSAN], [
                SANITIZERS_CFLAGS="$SANITIZERS_CFLAGS -fsanitize=thread"
                SANITIZERS_LDFLAGS="$SANITIZERS_LDFLAGS -fsanitize=thread -ltsan"
                PCMK_FEATURES="$PCMK_FEATURES tsan"
                REQUIRE_LIB([tsan],[main])
            ])
  done
])


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

CC_EXTRAS=""

AS_IF([test "$GCC" != yes], [CFLAGS="$CFLAGS -g"], [
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

    AS_IF([cc_supports_flag "-Wformat-nonliteral"],
          [gcc_format_nonliteral=yes],
          [gcc_format_nonliteral=no])
        
    # We had to eliminate -Wnested-externs because of libtool changes
    # Make sure to order options so that the former stand for prerequisites
    # of the latter (e.g., -Wformat-nonliteral requires -Wformat).
    EXTRA_FLAGS="-fgnu89-inline"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wall"
    EXTRA_FLAGS="$EXTRA_FLAGS -Waggregate-return"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wbad-function-cast"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wcast-align"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wdeclaration-after-statement"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wendif-labels"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wfloat-equal"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wformat-security"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wmissing-prototypes"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wmissing-declarations"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wnested-externs"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wno-long-long"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wno-strict-aliasing"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wpointer-arith"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wstrict-prototypes"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wwrite-strings"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wunused-but-set-variable"
    EXTRA_FLAGS="$EXTRA_FLAGS -Wunsigned-char"

    AS_IF([test "x$gcc_diagnostic_push_pull" = "xyes"],
          [
              AC_DEFINE([GCC_FORMAT_NONLITERAL_CHECKING_ENABLED], [],
                        [gcc can complain about nonliterals in format])
              EXTRA_FLAGS="$EXTRA_FLAGS -Wformat=2 -Wformat-nonliteral"
          ],
          [test "x$gcc_format_nonliteral" = "xyes"],
          [EXTRA_FLAGS="$EXTRA_FLAGS -Wformat=2"])

# Additional warnings it might be nice to enable one day
#                -Wshadow
#                -Wunreachable-code
    for j in $EXTRA_FLAGS
    do
        AS_IF([cc_supports_flag $CC_EXTRAS $j], [CC_EXTRAS="$CC_EXTRAS $j"])
    done

    AC_MSG_NOTICE([Using additional gcc flags: ${CC_EXTRAS}])
])

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
dnl    pacemaker-based, pacemaker-fenced, pacemaker-remoted,
dnl    pacemaker-schedulerd)
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

AS_IF([test $enable_hardening -eq $OPTIONAL],
      [
          AS_IF([test "$(env | grep -Ec '^(C|LD)FLAGS_HARDENED_(EXE|LIB)=.')" = 0],
                [enable_hardening=$REQUIRED],
                [AC_MSG_NOTICE([Hardening: using custom flags from environment])]
          )
      ],
      [
          unset CFLAGS_HARDENED_EXE
          unset CFLAGS_HARDENED_LIB
          unset LDFLAGS_HARDENED_EXE
          unset LDFLAGS_HARDENED_LIB
      ]
)
AS_CASE([$enable_hardening],
        [$DISABLED], [AC_MSG_NOTICE([Hardening: explicitly disabled])],
        [$REQUIRED], [
            CFLAGS_HARDENED_EXE=
            CFLAGS_HARDENED_LIB=
            LDFLAGS_HARDENED_EXE=
            LDFLAGS_HARDENED_LIB=
            relro=0
            pie=0
            bindnow=0
            stackprot="none"
            # daemons incl. libs: partial RELRO
            flag="-Wl,-z,relro"
            CC_CHECK_LDFLAGS(["${flag}"],
                             [
                                 LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}"
                                 LDFLAGS_HARDENED_LIB="${LDFLAGS_HARDENED_LIB} ${flag}"
                                 relro=1
                             ])
            # daemons: PIE for both CFLAGS and LDFLAGS
            AS_IF([cc_supports_flag -fPIE],
                  [
                      flag="-pie"
                      CC_CHECK_LDFLAGS(["${flag}"],
                                       [
                                           CFLAGS_HARDENED_EXE="${CFLAGS_HARDENED_EXE} -fPIE"
                                           LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}"
                                           pie=1
                                       ])
                  ]
            )
            # daemons incl. libs: full RELRO if sensible + as-needed linking
            #                     so as to possibly mitigate startup performance
            #                     hit caused by excessive linking with unneeded
            #                     libraries
            AS_IF([test "${relro}" = 1 && test "${pie}" = 1],
                  [
                      flag="-Wl,-z,now"
                      CC_CHECK_LDFLAGS(["${flag}"],
                                       [
                                           LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}"
                                           LDFLAGS_HARDENED_LIB="${LDFLAGS_HARDENED_LIB} ${flag}"
                                           bindnow=1
                                       ])
                  ]
            )
            AS_IF([test "${bindnow}" = 1],
                  [
                      flag="-Wl,--as-needed"
                      CC_CHECK_LDFLAGS(["${flag}"],
                                       [
                                           LDFLAGS_HARDENED_EXE="${LDFLAGS_HARDENED_EXE} ${flag}"
                                           LDFLAGS_HARDENED_LIB="${LDFLAGS_HARDENED_LIB} ${flag}"
                                       ])
                  ])
            # universal: prefer strong > all > default stack protector if possible
            flag=
            AS_IF([cc_supports_flag -fstack-protector-strong],
                  [
                      flag="-fstack-protector-strong"
                      stackprot="strong"
                  ],
                  [cc_supports_flag -fstack-protector-all],
                  [
                      flag="-fstack-protector-all"
                      stackprot="all"
                  ],
                  [cc_supports_flag -fstack-protector],
                  [
                      flag="-fstack-protector"
                      stackprot="default"
                  ]
            )
            AS_IF([test -n "${flag}"], [CC_EXTRAS="${CC_EXTRAS} ${flag}"])
            # universal: enable stack clash protection if possible
            AS_IF([cc_supports_flag -fstack-clash-protection],
                  [
                      CC_EXTRAS="${CC_EXTRAS} -fstack-clash-protection"
                      AS_IF([test "${stackprot}" = "none"],
                            [stackprot="clash-only"],
                            [stackprot="${stackprot}+clash"]
                      )
                  ]
            )
            # Log a summary
            AS_IF([test "${relro}" = 1 || test "${pie}" = 1 || test "${stackprot}" != "none"],
                  [AC_MSG_NOTICE(m4_normalize([Hardening:
                        relro=${relro}
                        pie=${pie}
                        bindnow=${bindnow}
                        stackprot=${stackprot}]))
                  ],
                  [AC_MSG_WARN([Hardening: no suitable features in the toolchain detected])]
            )
        ],
)

CFLAGS="$SANITIZERS_CFLAGS $CFLAGS $CC_EXTRAS"
LDFLAGS="$SANITIZERS_LDFLAGS $LDFLAGS"
CFLAGS_HARDENED_EXE="$SANITIZERS_CFLAGS $CFLAGS_HARDENED_EXE"
LDFLAGS_HARDENED_EXE="$SANITIZERS_LDFLAGS $LDFLAGS_HARDENED_EXE"

NON_FATAL_CFLAGS="$CFLAGS"
AC_SUBST(NON_FATAL_CFLAGS)

dnl
dnl We reset CFLAGS to include our warnings *after* all function
dnl checking goes on, so that our warning flags don't keep the
dnl AC_*FUNCS() calls above from working.  In particular, -Werror will
dnl *always* cause us troubles if we set it before here.
dnl
dnl
AS_IF([test $enable_fatal_warnings -ne $DISABLED], [
    AC_MSG_NOTICE([Enabling fatal compiler warnings])
    CFLAGS="$CFLAGS $WERROR"
])
AC_SUBST(CFLAGS)

dnl This is useful for use in Makefiles that need to remove one specific flag
CFLAGS_COPY="$CFLAGS"
AC_SUBST(CFLAGS_COPY)

AC_SUBST(LIBADD_DL)        dnl extra flags for dynamic linking libraries

AC_SUBST(LOCALE)

dnl Options for cleaning up the compiler output
AS_IF([test $enable_quiet -ne $DISABLED],
      [
          AC_MSG_NOTICE([Suppressing make details])
          QUIET_LIBTOOL_OPTS="--silent"
          QUIET_MAKE_OPTS="-s"  # POSIX compliant
      ],
      [
          QUIET_LIBTOOL_OPTS=""
          QUIET_MAKE_OPTS=""
      ]
)

dnl Put the above variables to use
LIBTOOL="${LIBTOOL} --tag=CC \$(QUIET_LIBTOOL_OPTS)"
MAKEFLAGS="${MAKEFLAGS} ${QUIET_MAKE_OPTS}"

# Make features list available (sorted alphabetically, without leading space)
PCMK_FEATURES=`echo "$PCMK_FEATURES" | sed -e 's/^ //' -e 's/ /\n/g' | sort | xargs`
AC_DEFINE_UNQUOTED(CRM_FEATURES, "$PCMK_FEATURES", Set of enabled features)
AC_SUBST(PCMK_FEATURES)

AC_SUBST(CC)
AC_SUBST(MAKEFLAGS)
AC_SUBST(LIBTOOL)
AC_SUBST(QUIET_LIBTOOL_OPTS)

dnl Files we output that need to be executable
CONFIG_FILES_EXEC([cts/cts-cli],
                  [cts/cts-coverage],
                  [cts/cts-exec],
                  [cts/cts-fencing],
                  [cts/cts-regression],
                  [cts/cts-scheduler],
                  [cts/lxc_autogen.sh],
                  [cts/benchmark/clubench],
                  [cts/lab/CTSlab.py],
                  [cts/lab/OCFIPraTest.py],
                  [cts/lab/cluster_test],
                  [cts/lab/cts],
                  [cts/lab/cts-log-watcher],
                  [cts/support/LSBDummy],
                  [cts/support/cts-support],
                  [cts/support/fence_dummy],
                  [cts/support/pacemaker-cts-dummyd],
                  [daemons/fenced/fence_legacy],
                  [daemons/fenced/fence_watchdog],
                  [doc/abi-check],
                  [extra/resources/ClusterMon],
                  [extra/resources/HealthSMART],
                  [extra/resources/SysInfo],
                  [extra/resources/ifspeed],
                  [extra/resources/o2cb],
                  [maint/bumplibs],
                  [tools/crm_failcount],
                  [tools/crm_master],
                  [tools/crm_report],
                  [tools/crm_standby],
                  [tools/cibsecret],
                  [tools/pcmk_simtimes])

dnl Other files we output
AC_CONFIG_FILES(Makefile                                            \
                cts/Makefile                                        \
                cts/benchmark/Makefile                              \
                cts/lab/Makefile                                    \
                cts/lab/CTSvars.py                                  \
                cts/scheduler/Makefile                              \
                cts/scheduler/dot/Makefile                          \
                cts/scheduler/exp/Makefile                          \
                cts/scheduler/scores/Makefile                       \
                cts/scheduler/stderr/Makefile                       \
                cts/scheduler/summary/Makefile                      \
                cts/scheduler/xml/Makefile                          \
                cts/support/Makefile                                \
                cts/support/pacemaker-cts-dummyd@.service           \
                daemons/Makefile                                    \
                daemons/attrd/Makefile                              \
                daemons/based/Makefile                              \
                daemons/controld/Makefile                           \
                daemons/execd/Makefile                              \
                daemons/execd/pacemaker_remote                      \
                daemons/execd/pacemaker_remote.service              \
                daemons/fenced/Makefile                             \
                daemons/pacemakerd/Makefile                         \
                daemons/pacemakerd/pacemaker.service                \
                daemons/pacemakerd/pacemaker.upstart                \
                daemons/pacemakerd/pacemaker.combined.upstart       \
                daemons/schedulerd/Makefile                         \
                devel/Makefile                                      \
                doc/Doxyfile                                        \
                doc/Makefile                                        \
                doc/sphinx/Makefile                                 \
                etc/Makefile                                        \
                etc/init.d/pacemaker                                \
                etc/logrotate.d/pacemaker                           \
                extra/Makefile                                      \
                extra/alerts/Makefile                               \
                extra/resources/Makefile                            \
                include/Makefile                                    \
                include/crm/Makefile                                \
                include/crm/cib/Makefile                            \
                include/crm/common/Makefile                         \
                include/crm/cluster/Makefile                        \
                include/crm/fencing/Makefile                        \
                include/crm/pengine/Makefile                        \
                include/pcmki/Makefile                              \
                replace/Makefile                                    \
                lib/Makefile                                        \
                lib/libpacemaker.pc                                 \
                lib/pacemaker.pc                                    \
                lib/pacemaker-cib.pc                                \
                lib/pacemaker-lrmd.pc                               \
                lib/pacemaker-service.pc                            \
                lib/pacemaker-pe_rules.pc                           \
                lib/pacemaker-pe_status.pc                          \
                lib/pacemaker-fencing.pc                            \
                lib/pacemaker-cluster.pc                            \
                lib/common/Makefile                                 \
                lib/common/tests/Makefile                           \
                lib/common/tests/acl/Makefile                   \
                lib/common/tests/agents/Makefile                    \
                lib/common/tests/cmdline/Makefile                   \
                lib/common/tests/flags/Makefile                     \
                lib/common/tests/io/Makefile                        \
                lib/common/tests/iso8601/Makefile                   \
                lib/common/tests/nvpair/Makefile                    \
                lib/common/tests/operations/Makefile                \
                lib/common/tests/results/Makefile                   \
                lib/common/tests/strings/Makefile                   \
                lib/common/tests/utils/Makefile                     \
                lib/common/tests/xpath/Makefile                     \
                lib/cluster/Makefile                                \
                lib/cib/Makefile                                    \
                lib/gnu/Makefile                                    \
                lib/pacemaker/Makefile                              \
                lib/pengine/Makefile                                \
                lib/pengine/tests/Makefile                          \
                lib/pengine/tests/rules/Makefile                    \
                lib/fencing/Makefile                                \
                lib/lrmd/Makefile                                   \
                lib/services/Makefile                               \
                maint/Makefile                                      \
                rpm/Makefile                                        \
                tests/Makefile                                      \
                tools/Makefile                                      \
                tools/report.collector                              \
                tools/report.common                                 \
                tools/crm_mon.service                               \
                tools/crm_mon.upstart                               \
                xml/Makefile                                        \
                xml/pacemaker-schemas.pc                            \
                po/Makefile.in                                      \
)

dnl Now process the entire list of files added by previous
dnl  calls to AC_CONFIG_FILES()
AC_OUTPUT()

dnl *****************
dnl Configure summary
dnl *****************

AC_MSG_NOTICE([])
AC_MSG_NOTICE([$PACKAGE configuration:])
AC_MSG_NOTICE([  Version                  = ${VERSION} (Build: $BUILD_VERSION)])
AC_MSG_NOTICE([  Features                 = ${PCMK_FEATURES}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  Prefix                   = ${prefix}])
AC_MSG_NOTICE([  Executables              = ${sbindir}])
AC_MSG_NOTICE([  Man pages                = ${mandir}])
AC_MSG_NOTICE([  Libraries                = ${libdir}])
AC_MSG_NOTICE([  Header files             = ${includedir}])
AC_MSG_NOTICE([  Arch-independent files   = ${datadir}])
AC_MSG_NOTICE([  State information        = ${localstatedir}])
AC_MSG_NOTICE([  System configuration     = ${sysconfdir}])
AC_MSG_NOTICE([  OCF agents               = ${OCF_ROOT_DIR}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  HA group name            = ${CRM_DAEMON_GROUP}])
AC_MSG_NOTICE([  HA user name             = ${CRM_DAEMON_USER}])
AC_MSG_NOTICE([])
AC_MSG_NOTICE([  CFLAGS                   = ${CFLAGS}])
AC_MSG_NOTICE([  CFLAGS_HARDENED_EXE      = ${CFLAGS_HARDENED_EXE}])
AC_MSG_NOTICE([  CFLAGS_HARDENED_LIB      = ${CFLAGS_HARDENED_LIB}])
AC_MSG_NOTICE([  LDFLAGS_HARDENED_EXE     = ${LDFLAGS_HARDENED_EXE}])
AC_MSG_NOTICE([  LDFLAGS_HARDENED_LIB     = ${LDFLAGS_HARDENED_LIB}])
AC_MSG_NOTICE([  Libraries                = ${LIBS}])
AC_MSG_NOTICE([  Stack Libraries          = ${CLUSTERLIBS}])
AC_MSG_NOTICE([  Unix socket auth method  = ${us_auth}])

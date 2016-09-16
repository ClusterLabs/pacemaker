dnl
dnl local autoconf/automake macros for pacemaker
dnl

dnl Check if the flag is supported by linker (cacheable)
dnl CC_CHECK_LDFLAGS([FLAG], [ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
dnl
dnl Origin (declared license: GPLv2+ with less restrictive exception):
dnl https://git.gnome.org/browse/glib/tree/m4macros/attributes.m4?h=2.49.1
dnl (AC_LANG_PROGRAM substituted by Jan Pokorny <jpokorny@redhat.com>)

AC_DEFUN([CC_CHECK_LDFLAGS], [
  AC_CACHE_CHECK([if $CC supports $1 flag],
    AS_TR_SH([cc_cv_ldflags_$1]),
    [ac_save_LDFLAGS="$LDFLAGS"
     LDFLAGS="$LDFLAGS $1"
     AC_LINK_IFELSE([AC_LANG_PROGRAM([[]], [[]])],
       [eval "AS_TR_SH([cc_cv_ldflags_$1])='yes'"],
       [eval "AS_TR_SH([cc_cv_ldflags_$1])="])
     LDFLAGS="$ac_save_LDFLAGS"
    ])

  AS_IF([eval test x$]AS_TR_SH([cc_cv_ldflags_$1])[ = xyes],
    [$2], [$3])
])


dnl PKG_CHECK_VAR(VARIABLE, MODULE, CONFIG-VARIABLE,
dnl [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl -------------------------------------------
dnl Since: 0.28
dnl
dnl Retrieves the value of the pkg-config variable for the given module.
dnl
dnl Origin (declared license: GPLv2+ with less restrictive exception):
dnl https://cgit.freedesktop.org/pkg-config/tree/pkg.m4.in?h=pkg-config-0.29.1#n261
dnl (AS_VAR_COPY replaced with backward-compatible equivalent and guard
dnl to prefer system-wide variant by Jan Pokorny <jpokorny@redhat.com>)

m4_ifndef([PKG_CHECK_VAR],[
AC_DEFUN([PKG_CHECK_VAR],
[AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl
AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl

_PKG_CONFIG([$1], [variable="][$3]["], [$2])
dnl AS_VAR_COPY([$1], [pkg_cv_][$1])
$1=AS_VAR_GET([pkg_cv_][$1])

AS_VAR_IF([$1], [""], [$5], [$4])dnl
])dnl PKG_CHECK_VAR
])dnl m4_ifndef

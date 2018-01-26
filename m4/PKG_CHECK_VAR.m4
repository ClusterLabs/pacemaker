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

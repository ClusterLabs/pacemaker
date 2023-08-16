# REQUIRE_PROG([variable], [prog-to-check-for])
#
# Error if a program can't be found on the path
#
dnl
dnl Copyright 2023 the Pacemaker project contributors
dnl
dnl The version control history for this file may have further details.
dnl
dnl This source code is licensed under the GNU General Public License version 2
dnl or later (GPLv2+) WITHOUT ANY WARRANTY.

dnl Usage: REQUIRE_PROG([variable], [prog-to-check-for])
AC_DEFUN([REQUIRE_PROG], [
    AC_PATH_PROG([$1], [$2])
    AS_IF([test x"$(eval echo "\${$1}")" != x""], [],
          [AC_MSG_FAILURE([Could not find required build tool $2])])
])

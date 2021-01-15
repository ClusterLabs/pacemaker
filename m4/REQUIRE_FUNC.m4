# REQUIRE_FUNC([FUNC])
#
# Error if a standard C library function can't be found
#
dnl
dnl Copyright 2021 the Pacemaker project contributors
dnl
dnl The version control history for this file may have further details.
dnl
dnl This source code is licensed under the GNU General Public License version 2
dnl or later (GPLv2+) WITHOUT ANY WARRANTY.

dnl Usage: REQUIRE_FUNC(function-name)
AC_DEFUN([REQUIRE_FUNC], [
    AC_CHECK_FUNC([$1], [], [AC_MSG_ERROR(Could not find required C function $1)])
])

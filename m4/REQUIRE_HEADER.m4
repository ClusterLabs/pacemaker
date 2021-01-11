# REQUIRE_HEADER([HEADER])
#
# Error if a C header file can't be found
#
dnl
dnl Copyright 2020 the Pacemaker project contributors
dnl
dnl The version control history for this file may have further details.
dnl
dnl This source code is licensed under the GNU General Public License version 2
dnl or later (GPLv2+) WITHOUT ANY WARRANTY.

dnl Usage: REQUIRE_HEADER(header-file, [prerequisite-includes])
AC_DEFUN([REQUIRE_HEADER], [
    AC_CHECK_HEADERS([$1], [], [AC_MSG_ERROR(Could not find required C header $1)], [$2])
])

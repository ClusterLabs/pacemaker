#
# Copyright 2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.

# REQUIRE_LIB(LIBRARY, FUNCTION)
#
# Error if a C library can't be found or doesn't contain a specified function
#
AC_DEFUN([REQUIRE_LIB], [
    AC_CHECK_LIB([$1],[$2],,[AC_MSG_FAILURE([Unable to find required C library lib$1])])
])

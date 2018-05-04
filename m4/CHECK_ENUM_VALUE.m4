# CHECK_ENUM_VALUE([HEADER], [ENUM_NAME], [ENUM_VALUE])
#
# Define HAVE_[ENUM_NAME]_[ENUM_VALUE] if the specified enum value is
# available.
dnl
dnl Copyright 2018 Andrew Beekhof <andrew@beekhof.net>
dnl
dnl This source code is licensed under the GNU General Public License version 2
dnl or later (GPLv2+) WITHOUT ANY WARRANTY.

AC_DEFUN([CHECK_ENUM_VALUE], [
    AC_MSG_CHECKING(whether $1 defines enum $2 value $3)
    AC_COMPILE_IFELSE([AC_LANG_PROGRAM([#include <$1>],
                                       [enum $2 check_$2_$3 = $3])],
                      [AC_DEFINE_UNQUOTED(HAVE_$2_$3, 1,
                                          [Whether enum $2 supports $3])
                       AC_MSG_RESULT(yes)],
                      [AC_MSG_RESULT(no)])
])

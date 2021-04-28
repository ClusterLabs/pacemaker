#
# Copyright 2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.

# CONFIG_FILE_EXEC(FILE [...])
#
# Mark single FILE as configure-generated, and make it executable once created.
#
AC_DEFUN([CONFIG_FILE_EXEC], [AC_CONFIG_FILES([$1], [chmod +x "$1"])])

# CONFIG_FILES_EXEC(FILE [...])
#
# Mark multiple FILEs as configure-generated, and make them executable.
#
AC_DEFUN([CONFIG_FILES_EXEC], [
    m4_case([$#], [0], [],
                  [1], [CONFIG_FILE_EXEC([$1])],
                  [CONFIG_FILE_EXEC([$1])
                   CONFIG_FILES_EXEC(m4_shift($@))])
])

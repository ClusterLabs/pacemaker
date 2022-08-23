#
# Copyright 2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

LDADD += $(top_builddir)/lib/pengine/libpe_status_test.la

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = pe__cmp_node_name_test

TESTS = $(check_PROGRAMS)

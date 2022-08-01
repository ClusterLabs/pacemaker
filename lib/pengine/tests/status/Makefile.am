#
# Copyright 2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
AM_CPPFLAGS = -I$(top_srcdir)/include \
			  -I$(top_builddir)/include \
			  -I$(top_srcdir)/lib/common
LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la \
		$(top_builddir)/lib/pengine/libpe_status_test.la
AM_LDFLAGS = $(LDFLAGS_WRAP)

include $(top_srcdir)/mk/tap.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = pe_find_node_any_test \
				 pe_find_node_id_test \
				 pe_find_node_test \
				 pe_new_working_set_test \
				 set_working_set_defaults_test

TESTS = $(check_PROGRAMS)

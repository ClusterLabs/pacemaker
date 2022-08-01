#
# Copyright 2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include \
			  -I$(top_builddir) -I$(top_srcdir)
LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la \
		$(top_builddir)/lib/pengine/libpe_status_test.la \
		-lcmocka

include $(top_srcdir)/mk/tap.mk

AM_TESTS_ENVIRONMENT += PCMK_CTS_CLI_DIR=$(top_srcdir)/cts/cli

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = native_find_rsc_test \
				 pe_base_name_eq_test

TESTS = $(check_PROGRAMS)

#
# Copyright 2020-2025 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = pcmk__compare_versions_test		\
		 pcmk__daemon_user_test			\
		 pcmk__fail_attr_name_test 		\
		 pcmk__failcount_name_test 		\
		 pcmk__getpid_s_test 			\
		 pcmk__lastfailure_name_test 		\
		 pcmk__lookup_user_test			\
		 pcmk__realloc_test 			\
		 pcmk__timeout_ms2s_test

TESTS = $(check_PROGRAMS)

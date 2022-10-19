#
# Copyright 2020-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS =				\
	compare_version_test			\
	crm_meta_name_test			\
	crm_meta_value_test			\
	crm_user_lookup_test			\
	pcmk_daemon_user_test			\
	pcmk_str_is_infinity_test		\
	pcmk_str_is_minus_infinity_test \
	pcmk__getpid_s_test

if WRAPPABLE_UNAME
check_PROGRAMS += pcmk_hostname_test
endif

TESTS = $(check_PROGRAMS)

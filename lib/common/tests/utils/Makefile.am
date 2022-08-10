#
# Copyright 2020-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

AM_CPPFLAGS = -I$(top_srcdir)/include		\
	      -I$(top_builddir)/include		\
	      -I$(top_srcdir)/lib/common
LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la
AM_CFLAGS = -DPCMK__UNIT_TESTING
AM_LDFLAGS = $(LDFLAGS_WRAP)

include $(top_srcdir)/mk/tap.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS =				\
	compare_version_test			\
	crm_meta_name_test			\
	crm_meta_value_test			\
	crm_user_lookup_test			\
	pcmk_daemon_user_test			\
	pcmk_str_is_infinity_test		\
	pcmk_str_is_minus_infinity_test

if WRAPPABLE_UNAME
check_PROGRAMS += pcmk_hostname_test
endif

TESTS = $(check_PROGRAMS)

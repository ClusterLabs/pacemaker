#
# Copyright 2021-2022 the Pacemaker project contributors
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
check_PROGRAMS =	pcmk__xe_attr_is_true_test \
					pcmk__xe_get_bool_attr_test \
					pcmk__xe_set_bool_attr_test

TESTS = $(check_PROGRAMS)

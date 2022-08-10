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
check_PROGRAMS = copy_in_properties_test \
				 expand_plus_plus_test \
				 fix_plus_plus_recursive_test \
				 parse_op_key_test \
				 pcmk_is_probe_test \
				 pcmk_xe_is_probe_test \
				 pcmk_xe_mask_probe_failure_test

TESTS = $(check_PROGRAMS)

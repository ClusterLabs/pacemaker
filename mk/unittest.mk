#
# Copyright 2022-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

AM_CPPFLAGS = -I$(top_builddir)/include		\
	      -I$(top_srcdir)/include		\
	      -I$(top_srcdir)/lib/common

AM_CFLAGS = -DPCMK__UNIT_TESTING
# Add -fno-builtin and -fno-inline to allow mocking realloc.
AM_CFLAGS += -fno-builtin
AM_CFLAGS += -fno-inline

AM_LDFLAGS = $(LDFLAGS_WRAP)

LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la
if BUILD_COVERAGE
LDADD += -lgcov
endif
LDADD += -lcmocka
# When -fno-builtin is used, -lm also needs to be added.  See the comments in
# lib/common/Makefile.am for libcrmcommon_test_la_CFLAGS.
LDADD += -lm

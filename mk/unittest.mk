#
# Copyright 2022 the Pacemaker project contributors
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

AM_LDFLAGS = $(LDFLAGS_WRAP)

LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la \
	-lcmocka

#
# Copyright 2020-2021 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/lib/common/mock.mk

AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include -I$(top_srcdir)/lib/common
LDADD = $(top_builddir)/lib/common/libcrmcommon.la -lcmocka

include $(top_srcdir)/mk/tap.mk

pcmk_hostname_test_LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la -lcmocka
pcmk_hostname_test_LDFLAGS = -Wl,--wrap=uname

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS =	\
	pcmk_hostname_test \
	pcmk_str_is_infinity_test		\
	pcmk_str_is_minus_infinity_test

TESTS = $(check_PROGRAMS)

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
LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la \
		-lcmocka
AM_CFLAGS = -DPCMK__UNIT_TESTING
AM_LDFLAGS = $(LDFLAGS_WRAP)

include $(top_srcdir)/mk/tap.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS =	pcmk__call_message_test \
					pcmk__output_new_test \
					pcmk__register_format_test \
					pcmk__register_formats_test \
					pcmk__register_message_test \
					pcmk__register_messages_test \
					pcmk__unregister_formats_test

TESTS = $(check_PROGRAMS)

#
# Copyright 2021-2026 the Pacemaker project contributors
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
check_PROGRAMS = pcmk__call_message_test
check_PROGRAMS += pcmk__output_and_clear_error_test
check_PROGRAMS += pcmk__output_free_test
check_PROGRAMS += pcmk__output_new_test
check_PROGRAMS += pcmk__register_format_test
check_PROGRAMS += pcmk__register_formats_test
check_PROGRAMS += pcmk__register_message_test
check_PROGRAMS += pcmk__register_messages_test
check_PROGRAMS += pcmk__unregister_formats_test

TESTS = $(check_PROGRAMS)

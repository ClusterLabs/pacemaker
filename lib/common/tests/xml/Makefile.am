#
# Copyright 2022-2026 the Pacemaker project contributors
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
check_PROGRAMS = pcmk__xml_escape_test
check_PROGRAMS += pcmk__xml_is_name_char_test
check_PROGRAMS += pcmk__xml_is_name_start_char_test
check_PROGRAMS += pcmk__xml_new_doc_test
check_PROGRAMS += pcmk__xml_sanitize_id_test

TESTS = $(check_PROGRAMS)

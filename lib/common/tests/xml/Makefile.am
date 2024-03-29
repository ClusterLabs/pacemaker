#
# Copyright 2022-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = pcmk__xe_copy_attrs_test	\
		 pcmk__xe_first_child_test	\
		 pcmk__xe_foreach_child_test 	\
		 pcmk__xe_set_score_test	\
		 pcmk__xml_escape_test		\
		 pcmk__xml_init_test		\
		 pcmk__xml_is_name_char_test	\
		 pcmk__xml_is_name_start_char_test	\
		 pcmk__xml_needs_escape_test	\
		 pcmk__xml_sanitize_id_test

TESTS = $(check_PROGRAMS)

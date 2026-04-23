#
# Copyright 2024-2026 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/common.mk
include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore
check_PROGRAMS = pcmk__xe_attr_is_true_test
check_PROGRAMS += pcmk__xe_copy_attrs_test
check_PROGRAMS += pcmk__xe_first_child_test
check_PROGRAMS += pcmk__xe_foreach_child_test
check_PROGRAMS += pcmk__xe_get_bool_test
check_PROGRAMS += pcmk__xe_get_datetime_test
check_PROGRAMS += pcmk__xe_get_flags_test
check_PROGRAMS += pcmk__xe_get_score_test
check_PROGRAMS += pcmk__xe_next_test
check_PROGRAMS += pcmk__xe_set_bool_test
check_PROGRAMS += pcmk__xe_set_id_test
check_PROGRAMS += pcmk__xe_set_score_test
check_PROGRAMS += pcmk__xe_sort_attrs_test

TESTS = $(check_PROGRAMS)

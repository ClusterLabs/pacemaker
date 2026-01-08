#
# Copyright 2020-2026 the Pacemaker project contributors
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
check_PROGRAMS = pcmk__cmp_by_type_test
check_PROGRAMS += pcmk__evaluate_attr_expression_test
check_PROGRAMS += pcmk__evaluate_date_expression_test
check_PROGRAMS += pcmk__evaluate_date_spec_test
check_PROGRAMS += pcmk__evaluate_condition_test
check_PROGRAMS += pcmk__evaluate_op_expression_test
check_PROGRAMS += pcmk__evaluate_rsc_expression_test
check_PROGRAMS += pcmk__parse_combine_test
check_PROGRAMS += pcmk__parse_comparison_test
check_PROGRAMS += pcmk__parse_source_test
check_PROGRAMS += pcmk__parse_type_test
check_PROGRAMS += pcmk__replace_submatches_test
check_PROGRAMS += pcmk__unpack_duration_test
check_PROGRAMS += pcmk_evaluate_rule_test

TESTS = $(check_PROGRAMS)

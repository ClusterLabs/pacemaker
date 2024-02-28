#
# Copyright 2020-2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = pcmk__evaluate_date_expression_test	\
		 pcmk__evaluate_date_spec_test		\
		 pcmk__parse_comparison_test		\
		 pcmk__parse_type_test			\
		 pcmk__replace_submatches_test		\
		 pcmk__unpack_duration_test

TESTS = $(check_PROGRAMS)

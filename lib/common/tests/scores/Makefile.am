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
check_PROGRAMS = pcmk__add_scores_test
check_PROGRAMS += pcmk_parse_score_test
check_PROGRAMS += pcmk_readable_score_test
check_PROGRAMS += pcmk_str_is_infinity_test
check_PROGRAMS += pcmk_str_is_minus_infinity_test

TESTS = $(check_PROGRAMS)

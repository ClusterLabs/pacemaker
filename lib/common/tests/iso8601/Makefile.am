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
check_PROGRAMS = crm_time_add_days_test
check_PROGRAMS += crm_time_add_seconds_test
check_PROGRAMS += crm_time_add_years_test
check_PROGRAMS += crm_time_parse_duration_test
check_PROGRAMS += pcmk__add_time_from_xml_test
check_PROGRAMS += pcmk__readable_interval_test
check_PROGRAMS += pcmk__set_time_if_earlier_test
check_PROGRAMS += pcmk__time_format_hr_test

TESTS = $(check_PROGRAMS)

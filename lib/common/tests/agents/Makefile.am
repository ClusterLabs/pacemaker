#
# Copyright 2020-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = crm_generate_ra_key_test \
				 crm_parse_agent_spec_test \
				 pcmk__effective_rc_test \
				 pcmk_get_ra_caps_test \
				 pcmk_stonith_param_test

TESTS = $(check_PROGRAMS)

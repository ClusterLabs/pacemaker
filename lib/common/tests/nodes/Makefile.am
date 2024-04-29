#
# Copyright 2024 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

include $(top_srcdir)/mk/tap.mk
include $(top_srcdir)/mk/unittest.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = pcmk__find_node_in_list_test		\
		 pcmk_foreach_active_resource_test	\
		 pcmk_node_is_clean_test		\
		 pcmk_node_is_in_maintenance_test	\
		 pcmk_node_is_online_test		\
		 pcmk_node_is_pending_test		\
		 pcmk_node_is_shutting_down_test	\
		 pcmk__xe_add_node_test

TESTS = $(check_PROGRAMS)

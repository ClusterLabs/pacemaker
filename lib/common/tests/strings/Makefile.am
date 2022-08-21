#
# Copyright 2020-2022 the Pacemaker project contributors
#
# The version control history for this file may have further details.
#
# This source code is licensed under the GNU General Public License version 2
# or later (GPLv2+) WITHOUT ANY WARRANTY.
#

AM_CPPFLAGS = -I$(top_srcdir)/include		\
	      -I$(top_builddir)/include		\
	      -I$(top_srcdir)/lib/common
LDADD = $(top_builddir)/lib/common/libcrmcommon_test.la \
	-lcmocka
AM_CFLAGS = -DPCMK__UNIT_TESTING $(CFLAGS_MOCK)
AM_LDFLAGS = $(LDFLAGS_WRAP)

include $(top_srcdir)/mk/tap.mk

# Add "_test" to the end of all test program names to simplify .gitignore.
check_PROGRAMS = \
		crm_get_msec_test 	\
		crm_is_true_test 	\
		crm_str_to_boolean_test 	\
		pcmk__add_word_test		\
		pcmk__btoa_test			\
		pcmk__char_in_any_str_test	\
		pcmk__compress_test	\
		pcmk__ends_with_test 		\
		pcmk__guint_from_hash_test	\
		pcmk__numeric_strcasecmp_test \
		pcmk__parse_ll_range_test	\
		pcmk__s_test				\
		pcmk__scan_double_test		\
		pcmk__scan_min_int_test		\
		pcmk__scan_port_test		\
		pcmk__starts_with_test 		\
		pcmk__str_any_of_test		\
		pcmk__str_in_list_test		\
		pcmk__str_table_dup_test	\
		pcmk__str_update_test		\
		pcmk__strcmp_test 			\
		pcmk__strkey_table_test 	\
		pcmk__strikey_table_test 	\
		pcmk__trim_test

TESTS = $(check_PROGRAMS)

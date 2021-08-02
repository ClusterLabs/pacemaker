/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

static void
bad_input(void) {
    g_assert_cmpint(crm_get_msec(NULL), ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(crm_get_msec("     "), ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(crm_get_msec("abcxyz"), ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(crm_get_msec("100xs"), ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(crm_get_msec(" 100 xs "), ==, PCMK__PARSE_INT_DEFAULT);
    g_assert_cmpint(crm_get_msec("-100ms"), ==, PCMK__PARSE_INT_DEFAULT);
}

static void
good_input(void) {
    g_assert_cmpint(crm_get_msec("100"), ==, 100000);
    g_assert_cmpint(crm_get_msec(" 100 "), ==, 100000);
    g_assert_cmpint(crm_get_msec("\t100\n"), ==, 100000);

    g_assert_cmpint(crm_get_msec("100ms"), ==, 100);
    g_assert_cmpint(crm_get_msec("100 MSEC"), ==, 100);
    g_assert_cmpint(crm_get_msec("1000US"), ==, 1);
    g_assert_cmpint(crm_get_msec("1000usec"), ==, 1);
    g_assert_cmpint(crm_get_msec("12s"), ==, 12000);
    g_assert_cmpint(crm_get_msec("12 sec"), ==, 12000);
    g_assert_cmpint(crm_get_msec("1m"), ==, 60000);
    g_assert_cmpint(crm_get_msec("13 min"), ==, 780000);
    g_assert_cmpint(crm_get_msec("2\th"), ==, 7200000);
    g_assert_cmpint(crm_get_msec("1 hr"), ==, 3600000);
}

static void
overflow(void) {
    g_assert_cmpint(crm_get_msec("9223372036854775807s"), ==, LLONG_MAX);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/get_msec/bad_input", bad_input);
    g_test_add_func("/common/strings/get_msec/good_input", good_input);
    g_test_add_func("/common/strings/get_msec/overflow", overflow);
    return g_test_run();
}

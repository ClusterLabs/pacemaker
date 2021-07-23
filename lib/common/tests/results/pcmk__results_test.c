/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <bzlib.h>

static void
test_for_pcmk_rc_name(void) {
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_name(pcmk_rc_error-1), "pcmk_rc_unknown_format", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_name(pcmk_rc_ok), "pcmk_rc_ok", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_name(pcmk_rc_ok), "pcmk_rc_ok", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_name(-7777777), "Unknown", pcmk__str_none), ==, 0);
}

static void
test_for_pcmk_rc_str(void) {
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_str(pcmk_rc_error-1), "Unknown output format", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_str(pcmk_rc_ok), "OK", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(pcmk_rc_str(-1), "Unknown error", pcmk__str_none), ==, 0);
}

static void
test_for_crm_exit_name(void) {
    g_assert_cmpint(pcmk__strcmp(crm_exit_name(CRM_EX_OK), "CRM_EX_OK", pcmk__str_none), ==, 0);
}

static void
test_for_crm_exit_str(void) {
    g_assert_cmpint(pcmk__strcmp(crm_exit_str(CRM_EX_OK), "OK", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(crm_exit_str(129), "Interrupted by signal", pcmk__str_none), ==, 0);
    g_assert_cmpint(pcmk__strcmp(crm_exit_str(-7777777), "Unknown exit status", pcmk__str_none), ==, 0);
}

static void
test_for_pcmk_rc2exitc(void) {
    g_assert_cmpint(pcmk_rc2exitc(pcmk_rc_ok), ==, CRM_EX_OK);
    g_assert_cmpint(pcmk_rc2exitc(-7777777), ==, CRM_EX_ERROR);  
}

static void
test_for_bz2_strerror(void) {
    g_assert_cmpint(pcmk__strcmp(bz2_strerror(BZ_STREAM_END), "Ok", pcmk__str_none), ==, 0);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/common/results/test_for_pcmk_rc_name", test_for_pcmk_rc_name);
    g_test_add_func("/common/results/test_for_pcmk_rc_str", test_for_pcmk_rc_str);
    g_test_add_func("/common/results/test_for_crm_exit_name", test_for_crm_exit_name);
    g_test_add_func("/common/results/test_for_crm_exit_str", test_for_crm_exit_str);
    g_test_add_func("/common/results/test_for_pcmk_rc2exitc", test_for_pcmk_rc2exitc);
    g_test_add_func("/common/results/test_for_bz2_strerror", test_for_bz2_strerror);

    return g_test_run();
}

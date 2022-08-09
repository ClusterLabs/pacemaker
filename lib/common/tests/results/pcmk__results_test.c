/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>
#include <bzlib.h>

static void
test_for_pcmk_rc_name(void **state) {
    assert_string_equal(pcmk_rc_name(pcmk_rc_error-1), "pcmk_rc_unknown_format");
    assert_string_equal(pcmk_rc_name(pcmk_rc_ok), "pcmk_rc_ok");
    assert_string_equal(pcmk_rc_name(pcmk_rc_ok), "pcmk_rc_ok");
    assert_string_equal(pcmk_rc_name(-7777777), "Unknown");
}

static void
test_for_pcmk_rc_str(void **state) {
    assert_string_equal(pcmk_rc_str(pcmk_rc_error-1), "Unknown output format");
    assert_string_equal(pcmk_rc_str(pcmk_rc_ok), "OK");
    assert_string_equal(pcmk_rc_str(-1), "Error");
}

static void
test_for_crm_exit_name(void **state) {
    assert_string_equal(crm_exit_name(CRM_EX_OK), "CRM_EX_OK");
}

static void
test_for_crm_exit_str(void **state) {
    assert_string_equal(crm_exit_str(CRM_EX_OK), "OK");
    assert_string_equal(crm_exit_str(129), "Interrupted by signal");
    assert_string_equal(crm_exit_str(-7777777), "Unknown exit status");
}

static void
test_for_pcmk_rc2exitc(void **state) {
    assert_int_equal(pcmk_rc2exitc(pcmk_rc_ok), CRM_EX_OK);
    assert_int_equal(pcmk_rc2exitc(-7777777), CRM_EX_ERROR);
}

static void
test_for_bz2_strerror(void **state) {
    assert_string_equal(bz2_strerror(BZ_STREAM_END), "Ok");
}

int main(int argc, char **argv) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_for_pcmk_rc_name),
        cmocka_unit_test(test_for_pcmk_rc_str),
        cmocka_unit_test(test_for_crm_exit_name),
        cmocka_unit_test(test_for_crm_exit_str),
        cmocka_unit_test(test_for_pcmk_rc2exitc),
        cmocka_unit_test(test_for_bz2_strerror),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

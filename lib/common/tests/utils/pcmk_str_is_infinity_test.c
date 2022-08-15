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

static void
uppercase_str_passes(void **state)
{
    assert_true(pcmk_str_is_infinity("INFINITY"));
    assert_true(pcmk_str_is_infinity("+INFINITY"));
}

static void
mixed_case_str_fails(void **state)
{
    assert_false(pcmk_str_is_infinity("infinity"));
    assert_false(pcmk_str_is_infinity("+infinity"));
    assert_false(pcmk_str_is_infinity("Infinity"));
    assert_false(pcmk_str_is_infinity("+Infinity"));
}

static void
added_whitespace_fails(void **state)
{
    assert_false(pcmk_str_is_infinity(" INFINITY"));
    assert_false(pcmk_str_is_infinity("INFINITY "));
    assert_false(pcmk_str_is_infinity(" INFINITY "));
    assert_false(pcmk_str_is_infinity("+ INFINITY"));
}

static void
empty_str_fails(void **state)
{
    assert_false(pcmk_str_is_infinity(NULL));
    assert_false(pcmk_str_is_infinity(""));
}

static void
minus_infinity_fails(void **state)
{
    assert_false(pcmk_str_is_infinity("-INFINITY"));
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(uppercase_str_passes),
        cmocka_unit_test(mixed_case_str_fails),
        cmocka_unit_test(added_whitespace_fails),
        cmocka_unit_test(empty_str_fails),
        cmocka_unit_test(minus_infinity_fails),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

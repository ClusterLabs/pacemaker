/*
 * Copyright 2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
empty_input_string(void **state)
{
    long long result;

    assert_int_equal(pcmk__scan_ll(NULL, &result, 47), pcmk_rc_ok);
    assert_int_equal(result, 47);
}

static void
bad_input_string(void **state)
{
    long long result;

    assert_int_equal(pcmk__scan_ll("asdf", &result, 47), EINVAL);
    assert_int_equal(result, 47);
    assert_int_equal(pcmk__scan_ll("as12", &result, 47), EINVAL);
    assert_int_equal(result, 47);
}

static void
trailing_chars(void **state)
{
    long long result;

    assert_int_equal(pcmk__scan_ll("12as", &result, 47), pcmk_rc_ok);
    assert_int_equal(result, 12);
}

static void
no_result_variable(void **state)
{
    assert_int_equal(pcmk__scan_ll("1234", NULL, 47), pcmk_rc_ok);
    assert_int_equal(pcmk__scan_ll("asdf", NULL, 47), EINVAL);
}

static void
typical_case(void **state)
{
    long long result;

    assert_int_equal(pcmk__scan_ll("1234", &result, 47), pcmk_rc_ok);
    assert_int_equal(result, 1234);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input_string),
                cmocka_unit_test(bad_input_string),
                cmocka_unit_test(trailing_chars),
                cmocka_unit_test(no_result_variable),
                cmocka_unit_test(typical_case))

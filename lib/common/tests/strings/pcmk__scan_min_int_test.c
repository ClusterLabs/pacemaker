/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
empty_input_string(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_min_int("", &result, 1), EINVAL);
    assert_int_equal(result, 1);

    assert_int_equal(pcmk__scan_min_int(NULL, &result, 1), pcmk_rc_ok);
    assert_int_equal(result, 1);
}

static void
input_below_minimum(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_min_int("100", &result, 1024), pcmk_rc_ok);
    assert_int_equal(result, 1024);
}

static void
input_above_maximum(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_min_int("20000000000000000", &result, 100), EOVERFLOW);
    assert_int_equal(result, INT_MAX);
}

static void
input_just_right(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_min_int("1024", &result, 1024), pcmk_rc_ok);
    assert_int_equal(result, 1024);

    assert_int_equal(pcmk__scan_min_int("2048", &result, 1024), pcmk_rc_ok);
    assert_int_equal(result, 2048);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input_string),
                cmocka_unit_test(input_below_minimum),
                cmocka_unit_test(input_above_maximum),
                cmocka_unit_test(input_just_right))

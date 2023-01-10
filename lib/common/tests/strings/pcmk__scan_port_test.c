/*
 * Copyright 2022 the Pacemaker project contributors
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
    int result;

    assert_int_equal(pcmk__scan_port("", &result), EINVAL);
    assert_int_equal(result, -1);
}

static void
bad_input_string(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_port("abc", &result), EINVAL);
    assert_int_equal(result, -1);
}

static void
out_of_range(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_port("-1", &result), pcmk_rc_before_range);
    assert_int_equal(result, -1);
    assert_int_equal(pcmk__scan_port("65536",  &result), pcmk_rc_after_range);
    assert_int_equal(result, -1);
}

static void
typical_case(void **state)
{
    int result;

    assert_int_equal(pcmk__scan_port("0", &result), pcmk_rc_ok);
    assert_int_equal(result, 0);

    assert_int_equal(pcmk__scan_port("80", &result), pcmk_rc_ok);
    assert_int_equal(result, 80);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input_string),
                cmocka_unit_test(bad_input_string),
                cmocka_unit_test(out_of_range),
                cmocka_unit_test(typical_case))

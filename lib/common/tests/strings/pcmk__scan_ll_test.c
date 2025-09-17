/*
 * Copyright 2023-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <limits.h>

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

    assert_int_equal(pcmk__scan_ll("asdf", &result, 47), pcmk_rc_bad_input);
    assert_int_equal(result, 47);
    assert_int_equal(pcmk__scan_ll("as12", &result, 47), pcmk_rc_bad_input);
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
    assert_int_equal(pcmk__scan_ll("asdf", NULL, 47), pcmk_rc_bad_input);
}

static void
out_of_range(void **state)
{
    long long result = 0LL;
    char *very_long = pcmk__assert_asprintf(" %lld0", LLONG_MAX);

    assert_int_equal(pcmk__scan_ll(very_long, &result, 47), ERANGE);
    assert_true(result == LLONG_MAX);

    very_long[0] = '-';
    assert_int_equal(pcmk__scan_ll(very_long, &result, 47), ERANGE);
    assert_true(result == LLONG_MIN);

    free(very_long);
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
                cmocka_unit_test(out_of_range),
                cmocka_unit_test(typical_case))

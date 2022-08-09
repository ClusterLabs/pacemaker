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
empty_input_string(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range(NULL, &start, &end), pcmk_rc_unknown_format);
    assert_int_equal(pcmk__parse_ll_range("", &start, &end), pcmk_rc_unknown_format);
}

static void
missing_separator(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("1234", &start, &end), pcmk_rc_ok);
    assert_int_equal(start, 1234);
    assert_int_equal(end, 1234);
}

static void
only_separator(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("-", &start, &end), pcmk_rc_unknown_format);
    assert_int_equal(start, PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(end, PCMK__PARSE_INT_DEFAULT);
}

static void
no_range_end(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("2000-", &start, &end), pcmk_rc_ok);
    assert_int_equal(start, 2000);
    assert_int_equal(end, PCMK__PARSE_INT_DEFAULT);
}

static void
no_range_start(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("-2020", &start, &end), pcmk_rc_ok);
    assert_int_equal(start, PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(end, 2020);
}

static void
range_start_and_end(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("2000-2020", &start, &end), pcmk_rc_ok);
    assert_int_equal(start, 2000);
    assert_int_equal(end, 2020);

    assert_int_equal(pcmk__parse_ll_range("2000-2020-2030", &start, &end), pcmk_rc_unknown_format);
}

static void
garbage(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("2000x-", &start, &end), pcmk_rc_unknown_format);
    assert_int_equal(start, PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(end, PCMK__PARSE_INT_DEFAULT);

    assert_int_equal(pcmk__parse_ll_range("-x2000", &start, &end), pcmk_rc_unknown_format);
    assert_int_equal(start, PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(end, PCMK__PARSE_INT_DEFAULT);
}

static void
strtoll_errors(void **state)
{
    long long start, end;

    assert_int_equal(pcmk__parse_ll_range("20000000000000000000-", &start, &end), pcmk_rc_unknown_format);
    assert_int_equal(pcmk__parse_ll_range("100-20000000000000000000", &start, &end), pcmk_rc_unknown_format);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input_string),
        cmocka_unit_test(missing_separator),
        cmocka_unit_test(only_separator),
        cmocka_unit_test(no_range_end),
        cmocka_unit_test(no_range_start),
        cmocka_unit_test(range_start_and_end),
        cmocka_unit_test(strtoll_errors),

        cmocka_unit_test(garbage),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

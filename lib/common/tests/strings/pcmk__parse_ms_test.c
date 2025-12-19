/*
 * Copyright 2021-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

//! Magic initial value to test whether a "result" output variable has changed
static const long long magic = -12345678;

#define assert_parse_ms(input, expected_rc, expected_result)            \
    do {                                                                \
        long long result = magic;                                       \
                                                                        \
        assert_int_equal(pcmk__parse_ms(input, &result), expected_rc);  \
        assert_int_equal(result, expected_result);                      \
    } while (0)

static void
bad_input(void **state)
{
    assert_parse_ms(NULL, EINVAL, magic);
    assert_parse_ms("     ", pcmk_rc_bad_input, magic);
    assert_parse_ms("abcxyz", pcmk_rc_bad_input, magic);
    assert_parse_ms("100xs", pcmk_rc_bad_input, magic);
    assert_parse_ms(" 100 xs ", pcmk_rc_bad_input, magic);

    assert_parse_ms("3.xs", pcmk_rc_bad_input, magic);
    assert_parse_ms("  3.   xs  ", pcmk_rc_bad_input, magic);
    assert_parse_ms("3.14xs", pcmk_rc_bad_input, magic);
    assert_parse_ms("  3.14  xs  ", pcmk_rc_bad_input, magic);
}

static void
good_input(void **state)
{
    assert_parse_ms("100", pcmk_rc_ok, 100000);
    assert_parse_ms(" 100 ", pcmk_rc_ok, 100000);
    assert_parse_ms("\t100\n", pcmk_rc_ok, 100000);

    assert_parse_ms("100ms", pcmk_rc_ok, 100);
    assert_parse_ms(" 100 ms ", pcmk_rc_ok, 100);
    assert_parse_ms("100 MSEC", pcmk_rc_ok, 100);
    assert_parse_ms("-100ms", pcmk_rc_ok, -100);
    assert_parse_ms("1000US", pcmk_rc_ok, 1);
    assert_parse_ms("1000usec", pcmk_rc_ok, 1);
    assert_parse_ms("12s", pcmk_rc_ok, 12000);
    assert_parse_ms("12 sec", pcmk_rc_ok, 12000);
    assert_parse_ms("1m", pcmk_rc_ok, 60000);
    assert_parse_ms("13 min", pcmk_rc_ok, 780000);
    assert_parse_ms("2\th", pcmk_rc_ok, 7200000);
    assert_parse_ms("1 hr", pcmk_rc_ok, 3600000);

    assert_parse_ms("3.", pcmk_rc_ok, 3000);
    assert_parse_ms("  3.  ms  ", pcmk_rc_ok, 3);
    assert_parse_ms("3.14", pcmk_rc_ok, 3000);
    assert_parse_ms("  3.14  ms  ", pcmk_rc_ok, 3);

    // Questionable
    assert_parse_ms("3.14.", pcmk_rc_ok, 3000);
    assert_parse_ms("  3.14.  ms  ", pcmk_rc_ok, 3);
    assert_parse_ms("3.14.159", pcmk_rc_ok, 3000);
    assert_parse_ms("  3.14.159  ", pcmk_rc_ok, 3000);
    assert_parse_ms("3.14.159ms", pcmk_rc_ok, 3);
    assert_parse_ms("  3.14.159  ms  ", pcmk_rc_ok, 3);

    // Questionable
    assert_parse_ms(" 100 mshr ", pcmk_rc_ok, 100);
    assert_parse_ms(" 100 ms hr ", pcmk_rc_ok, 100);
    assert_parse_ms(" 100 sasdf ", pcmk_rc_ok, 100000);
    assert_parse_ms(" 100 s asdf ", pcmk_rc_ok, 100000);
    assert_parse_ms(" 3.14 shour ", pcmk_rc_ok, 3000);
    assert_parse_ms(" 3.14 s hour ", pcmk_rc_ok, 3000);
    assert_parse_ms(" 3.14 ms!@#$ ", pcmk_rc_ok, 3);
}

static void
overflow(void **state)
{
    char *input = NULL;

    input = pcmk__assert_asprintf("%llu", (unsigned long long) LLONG_MAX + 1);
    assert_parse_ms(input, ERANGE, LLONG_MAX);
    free(input);

    // Hopefully we can rely on two's complement integers
    input = pcmk__assert_asprintf("-%llu", (unsigned long long) LLONG_MIN + 1);
    assert_parse_ms(input, ERANGE, LLONG_MIN);
    free(input);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(good_input),
                cmocka_unit_test(overflow))

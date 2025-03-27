/*
 * Copyright 2021-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
bad_input(void **state) {
    assert_int_equal(crm_get_msec(NULL), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("     "), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("abcxyz"), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("100xs"), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec(" 100 xs "), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("-100ms"), PCMK__PARSE_INT_DEFAULT);

    assert_int_equal(crm_get_msec("3.xs"), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("  3.   xs  "), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("3.14xs"), PCMK__PARSE_INT_DEFAULT);
    assert_int_equal(crm_get_msec("  3.14  xs  "), PCMK__PARSE_INT_DEFAULT);
}

static void
good_input(void **state) {
    assert_int_equal(crm_get_msec("100"), 100000);
    assert_int_equal(crm_get_msec(" 100 "), 100000);
    assert_int_equal(crm_get_msec("\t100\n"), 100000);

    assert_int_equal(crm_get_msec("100ms"), 100);
    assert_int_equal(crm_get_msec(" 100 ms "), 100);
    assert_int_equal(crm_get_msec("100 MSEC"), 100);
    assert_int_equal(crm_get_msec("1000US"), 1);
    assert_int_equal(crm_get_msec("1000usec"), 1);
    assert_int_equal(crm_get_msec("12s"), 12000);
    assert_int_equal(crm_get_msec("12 sec"), 12000);
    assert_int_equal(crm_get_msec("1m"), 60000);
    assert_int_equal(crm_get_msec("13 min"), 780000);
    assert_int_equal(crm_get_msec("2\th"), 7200000);
    assert_int_equal(crm_get_msec("1 hr"), 3600000);

    assert_int_equal(crm_get_msec("3."), 3000);
    assert_int_equal(crm_get_msec("  3.  ms  "), 3);
    assert_int_equal(crm_get_msec("3.14"), 3000);
    assert_int_equal(crm_get_msec("  3.14  ms  "), 3);

    // Questionable
    assert_int_equal(crm_get_msec("3.14."), 3000);
    assert_int_equal(crm_get_msec("  3.14.  ms  "), 3);
    assert_int_equal(crm_get_msec("3.14.159"), 3000);
    assert_int_equal(crm_get_msec("  3.14.159  "), 3000);
    assert_int_equal(crm_get_msec("3.14.159ms"), 3);
    assert_int_equal(crm_get_msec("  3.14.159  ms  "), 3);

    // Questionable
    assert_int_equal(crm_get_msec(" 100 mshr "), 100);
    assert_int_equal(crm_get_msec(" 100 ms hr "), 100);
    assert_int_equal(crm_get_msec(" 100 sasdf "), 100000);
    assert_int_equal(crm_get_msec(" 100 s asdf "), 100000);
    assert_int_equal(crm_get_msec(" 3.14 shour "), 3000);
    assert_int_equal(crm_get_msec(" 3.14 s hour "), 3000);
    assert_int_equal(crm_get_msec(" 3.14 ms!@#$ "), 3);
}

static void
overflow(void **state) {
    assert_int_equal(crm_get_msec("9223372036854775808s"), LLONG_MAX);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(good_input),
                cmocka_unit_test(overflow))

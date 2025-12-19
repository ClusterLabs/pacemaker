/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>      // NULL
#include <limits.h>     // INT_MAX

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>

#define assert_add_days(orig_date_time, days, expected_date_time)   \
    do {                                                            \
        crm_time_t *orig = crm_time_new(orig_date_time);            \
        crm_time_t *expected = crm_time_new(expected_date_time);    \
                                                                    \
        assert_non_null(orig);                                      \
        assert_non_null(expected);                                  \
                                                                    \
        crm_time_add_days(orig, days);                              \
        assert_int_equal(crm_time_compare(orig, expected), 0);      \
                                                                    \
        crm_time_free(orig);                                        \
        crm_time_free(expected);                                    \
    } while (0)

static void
invalid_argument(void **state)
{
    pcmk__assert_asserts(crm_time_add_days(NULL, 1));
}

static void
positive_same_year(void **state)
{
    assert_add_days("2024-01-01 00:30:00 +01:00", 1,
                    "2024-01-02 00:30:00 +01:00");

    assert_add_days("2024-01-31 01:40:50 +02:00", 1,
                    "2024-02-01 01:40:50 +02:00");

    assert_add_days("2024-02-28 11:45:11 +03:00", 1,
                    "2024-02-29 11:45:11 +03:00");

    assert_add_days("2024-02-28 12:59:59 -03:00", 2,
                    "2024-03-01 12:59:59 -03:00");

    assert_add_days("2024-01-01 00:00:00 +00:00", 365,
                    "2024-12-31 00:00:00 +00:00");

    assert_add_days("2025-01-01 23:00:00 +00:00", 364,
                    "2025-12-31 23:00:00 +00:00");
}

static void
negative_same_year(void **state)
{
    assert_add_days("2024-01-02 00:30:00 +01:00", -1,
                    "2024-01-01 00:30:00 +01:00");

    assert_add_days("2024-02-01 01:40:50 +02:00", -1,
                    "2024-01-31 01:40:50 +02:00");

    assert_add_days("2024-03-01 11:45:11 +03:00", -1,
                    "2024-02-29 11:45:11 +03:00");

    assert_add_days("2024-03-01 12:59:59 -03:00", -2,
                    "2024-02-28 12:59:59 -03:00");

    assert_add_days("2024-12-31 00:00:00 +00:00", -365,
                    "2024-01-01 00:00:00 +00:00");

    assert_add_days("2025-12-31 23:00:00 +00:00", -364,
                    "2025-01-01 23:00:00 +00:00");
}

static void
positive_year_changes(void **state)
{
    // Non-leap year before March to leap year before March
    assert_add_days("2023-01-01 00:40:20 +02:00", 365,
                    "2024-01-01 00:40:20 +02:00");

    // Non-leap year before March to leap year after February
    assert_add_days("2023-01-01 00:40:20 +02:00", 426,
                    "2024-03-02 00:40:20 +02:00");

    // Non-leap year after February to leap year before March
    assert_add_days("2023-03-02 00:40:20 +02:00", 325,
                    "2024-01-21 00:40:20 +02:00");

    // Non-leap year after February to leap year after February
    assert_add_days("2023-03-02 00:40:20 +02:00", 385,
                    "2024-03-21 00:40:20 +02:00");

    // Leap year before March to non-leap year before March
    assert_add_days("2024-01-01 00:40:20 +02:00", 366,
                    "2025-01-01 00:40:20 +02:00");

    // Leap year before March to non-leap year after February
    assert_add_days("2024-01-01 00:40:20 +02:00", 430,
                    "2025-03-06 00:40:20 +02:00");

    // Leap year after February to non-leap year before March
    assert_add_days("2024-12-31 09:41:23 +06:00", 1,
                    "2025-01-01 09:41:23 +06:00");

    // Leap year after February to non-leap year after February
    assert_add_days("2024-12-31 09:41:23 +06:00", 90,
                    "2025-03-31 09:41:23 +06:00");

    // From and to non-leap years
    assert_add_days("2025-01-01 01:00:00 -02:00", 366,
                    "2026-01-02 01:00:00 -02:00");

    // Past "leap year if divisible by 4"
    assert_add_days("2025-01-01 00:00:00 +00:00", 1500,
                    "2029-02-09 00:00:00 +00:00");

    // Past "except if divisible by 100"
    assert_add_days("2025-01-01 00:00:00 +00:00", 28000,
                    "2101-08-31 00:00:00 +00:00");

    // Past "except if divisible by 400"
    assert_add_days("2025-01-01 00:00:00 +00:00", 150000,
                    "2435-09-09 00:00:00 +00:00");
}

static void
negative_year_changes(void **state)
{
    // Non-leap year before March to leap year before March
    assert_add_days("2025-01-01 00:40:20 +02:00", -366,
                    "2024-01-01 00:40:20 +02:00");

    // Non-leap year before March to leap year after February
    assert_add_days("2025-01-01 00:40:20 +02:00", -300,
                    "2024-03-07 00:40:20 +02:00");

    // Leap year before March to non-leap year before March
    assert_add_days("2024-01-01 00:40:20 +02:00", -365,
                    "2023-01-01 00:40:20 +02:00");

    // Leap year before March to non-leap year after February
    assert_add_days("2024-01-01 00:40:20 +02:00", -1,
                    "2023-12-31 00:40:20 +02:00");

    // Past "leap year if divisible by 4"
    assert_add_days("1990-01-01 00:00:00 +00:00", -2000,
                    "1984-07-11 00:00:00 +00:00");

    // Past "except if divisible by 100"
    assert_add_days("1990-01-01 00:00:00 +00:00", -33000,
                    "1899-08-26 00:00:00 +00:00");

    // Past "except if divisible by 400"
    assert_add_days("1990-01-01 00:00:00 +00:00", -150000,
                    "1579-04-26 00:00:00 +00:00");
}

static void
year_out_of_range(void **state)
{
    char *orig_datetime = NULL;
    char *expected_datetime = NULL;

    // Year too large
    orig_datetime = pcmk__assert_asprintf("%d-01-01 00:00:00 +00:00", INT_MAX);
    expected_datetime = pcmk__assert_asprintf("%d-12-31 00:00:00 +00:00",
                                              INT_MAX);
    assert_add_days(orig_datetime, 400, expected_datetime);
    free(orig_datetime);
    free(expected_datetime);

    // Year too small
    assert_add_days("01-02-01 00:00:00 +00:00", -40,
                    "01-01-01 00:00:00 +00:00");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_argument),
                cmocka_unit_test(positive_same_year),
                cmocka_unit_test(negative_same_year),
                cmocka_unit_test(positive_year_changes),
                cmocka_unit_test(negative_year_changes),
                cmocka_unit_test(year_out_of_range));

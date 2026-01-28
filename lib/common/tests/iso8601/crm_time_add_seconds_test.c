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

#define assert_add_seconds(orig_date_time, seconds, expected_date_time) \
    do {                                                                \
        crm_time_t *orig = crm_time_new(orig_date_time);                \
        crm_time_t *expected = crm_time_new(expected_date_time);        \
                                                                        \
        assert_non_null(orig);                                          \
        assert_non_null(expected);                                      \
                                                                        \
        crm_time_add_seconds(orig, seconds);                            \
        assert_int_equal(crm_time_compare(orig, expected), 0);          \
                                                                        \
        crm_time_free(orig);                                            \
        crm_time_free(expected);                                        \
    } while (0)

static void
invalid_argument(void **state)
{
    pcmk__assert_asserts(crm_time_add_seconds(NULL, 1));
}

static void
add_zero(void **state)
{
    assert_add_seconds("2024-01-01 00:30:00 +01:00", 0,
                       "2024-01-01 00:30:00 +01:00");
}

static void
add_less_than_one_day(void **state)
{
    // Minute boundary not crossed
    assert_add_seconds("2024-01-01 00:30:00 +01:00", 1,
                       "2024-01-01 00:30:01 +01:00");
    assert_add_seconds("2024-01-01 00:30:00 +01:00", 59,
                       "2024-01-01 00:30:59 +01:00");

    // Minute boundary crossed
    assert_add_seconds("2024-01-01 00:30:59 +02:00", 1,
                       "2024-01-01 00:31:00 +02:00");
    assert_add_seconds("2024-01-01 00:44:30 +02:00", 60,
                       "2024-01-01 00:45:30 +02:00");
    assert_add_seconds("2024-01-01 00:44:30 +02:00", 125,
                       "2024-01-01 00:46:35 +02:00");

    // Hour boundary crossed
    assert_add_seconds("2024-01-01 00:59:59 -03:00", 1,
                       "2024-01-01 01:00:00 -03:00");
    assert_add_seconds("2024-01-01 00:23:34 -03:00", 3600,
                       "2024-01-01 01:23:34 -03:00");
    assert_add_seconds("2024-01-01 00:23:34 -03:00", 7210,
                       "2024-01-01 02:23:44 -03:00");

    // Day boundary crossed
    assert_add_seconds("2024-01-01 23:59:59 +04:00", 1,
                       "2024-01-02 00:00:00 +04:00");
    assert_add_seconds("2024-02-28 00:05:00 +04:00", 86200,
                       "2024-02-29 00:01:40 +04:00");

    // Month boundary crossed
    assert_add_seconds("2023-02-28 00:05:00 -05:00", 86200,
                       "2023-03-01 00:01:40 -05:00");
    assert_add_seconds("2024-02-29 23:59:00 -05:00", 60,
                       "2024-03-01 00:00:00 -05:00");

    // Year boundary crossed
    assert_add_seconds("2024-12-31 23:59:59 +06:00", 1,
                       "2025-01-01 00:00:00 +06:00");
}

static void
add_more_than_one_day(void **state)
{
    // Month boundary not crossed
    assert_add_seconds("2024-01-01 00:00:00 +01:00", 86400 * 2,
                       "2024-01-03 00:00:00 +01:00");
    assert_add_seconds("2024-02-27 23:59:59 +01:00", 86400 * 2,
                       "2024-02-29 23:59:59 +01:00");

    // Month boundary crossed
    assert_add_seconds("2023-02-26 23:59:59 -02:00", 86400 * 2 + 1,
                       "2023-03-01 00:00:00 -02:00");
    assert_add_seconds("2024-02-27 23:59:59 -02:00", 86400 * 2 + 1,
                       "2024-03-01 00:00:00 -02:00");

    // Year boundary crossed
    assert_add_seconds("2024-12-01 00:00:00 +06:00", 86400 * 31,
                       "2025-01-01 00:00:00 +06:00");
}

static void
subtract_less_than_one_day(void **state)
{
    // Minute boundary not crossed
    assert_add_seconds("2024-01-01 00:30:01 +01:00", -1,
                       "2024-01-01 00:30:00 +01:00");
    assert_add_seconds("2024-01-01 00:30:30 +01:00", -5,
                       "2024-01-01 00:30:25 +01:00");
    assert_add_seconds("2024-01-01 00:30:59 +01:00", -59,
                       "2024-01-01 00:30:00 +01:00");

    // Minute boundary crossed
    assert_add_seconds("2024-01-01 00:30:00 +02:00", -1,
                       "2024-01-01 00:29:59 +02:00");
    assert_add_seconds("2024-01-01 00:44:30 +02:00", -60,
                       "2024-01-01 00:43:30 +02:00");
    assert_add_seconds("2024-01-01 00:14:30 +02:00", -125,
                       "2024-01-01 00:12:25 +02:00");

    // Hour boundary crossed
    assert_add_seconds("2024-01-01 01:00:00 -03:00", -1,
                       "2024-01-01 00:59:59 -03:00");
    assert_add_seconds("2024-01-01 01:23:34 -03:00", -3600,
                       "2024-01-01 00:23:34 -03:00");
    assert_add_seconds("2024-01-01 02:23:34 -03:00", -7210,
                       "2024-01-01 00:23:24 -03:00");

    // Day boundary crossed
    assert_add_seconds("2024-01-02 00:00:00 +04:00", -1,
                       "2024-01-01 23:59:59 +04:00");
    assert_add_seconds("2024-02-29 00:01:40 +04:00", -86200,
                       "2024-02-28 00:05:00 +04:00");

    // Month boundary crossed
    assert_add_seconds("2023-03-01 00:01:40 -05:00", -86200,
                       "2023-02-28 00:05:00 -05:00");
    assert_add_seconds("2024-03-01 00:00:00 -05:00", -60,
                       "2024-02-29 23:59:00 -05:00");

    // Year boundary crossed
    assert_add_seconds("2025-01-01 00:00:00 +06:00", -1,
                       "2024-12-31 23:59:59 +06:00");
}

static void
subtract_more_than_one_day(void **state)
{
    // Month boundary not crossed
    assert_add_seconds("2024-01-03 00:00:00 +01:00", 86400 * -2,
                       "2024-01-01 00:00:00 +01:00");
    assert_add_seconds("2024-02-29 23:59:59 +01:00", 86400 * -2,
                       "2024-02-27 23:59:59 +01:00");

    // Month boundary crossed
    assert_add_seconds("2023-03-03 00:00:00 -02:00", 86400 * -2 - 1,
                       "2023-02-28 23:59:59 -02:00");
    assert_add_seconds("2024-03-03 00:00:00 -02:00", 86400 * -2 - 1,
                       "2024-02-29 23:59:59 -02:00");

    // Year boundary crossed
    assert_add_seconds("2025-01-01 00:00:00 +06:00", 86400 * -31,
                       "2024-12-01 00:00:00 +06:00");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_argument),
                cmocka_unit_test(add_zero),
                cmocka_unit_test(add_less_than_one_day),
                cmocka_unit_test(add_more_than_one_day),
                cmocka_unit_test(subtract_less_than_one_day),
                cmocka_unit_test(subtract_more_than_one_day));

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

#define assert_add_years(orig_date_time, years, expected_date_time) \
    do {                                                            \
        crm_time_t *orig = crm_time_new(orig_date_time);            \
        crm_time_t *expected = crm_time_new(expected_date_time);    \
                                                                    \
        assert_non_null(orig);                                      \
        assert_non_null(expected);                                  \
                                                                    \
        crm_time_add_years(orig, years);                            \
        assert_int_equal(crm_time_compare(orig, expected), 0);      \
                                                                    \
        crm_time_free(orig);                                        \
        crm_time_free(expected);                                    \
    } while (0)

static void
invalid_argument(void **state)
{
    pcmk__assert_asserts(crm_time_add_years(NULL, 1));
}

static void
add_positive(void **state)
{
    assert_add_years("2024-01-01 00:30:00 +01:00", 1,
                     "2025-01-01 00:30:00 +01:00");

    assert_add_years("2024-12-31 01:40:50 +02:00", 1000,
                     "3024-12-31 01:40:50 +02:00");
}

static void
add_negative(void **state)
{
    assert_add_years("2024-01-01 00:30:00 +01:00", -1,
                     "2023-01-01 00:30:00 +01:00");

    assert_add_years("2024-12-31 01:40:50 +02:00", -1000,
                     "1024-12-31 01:40:50 +02:00");
}

static void
out_of_range(void **state)
{
    char *expected_datetime = NULL;

    expected_datetime = pcmk__assert_asprintf("%d-01-01 00:00:00 +00:00",
                                              INT_MAX);
    assert_add_years("2024-01-01 00:00:00 +00:00", INT_MAX, expected_datetime);
    free(expected_datetime);

    assert_add_years("2024-01-01 00:00:00 +00:00", -3000,
                     "01-01-01 00:00:00 +00:00");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid_argument),
                cmocka_unit_test(add_positive),
                cmocka_unit_test(add_negative),
                cmocka_unit_test(out_of_range));

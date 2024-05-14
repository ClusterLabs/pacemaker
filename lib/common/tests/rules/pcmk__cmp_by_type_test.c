/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <limits.h>                         // INT_MIN, INT_MAX

#include <crm/common/util.h>                // crm_strdup_printf()
#include <crm/common/rules_internal.h>
#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

static void
null_compares_lesser(void **state)
{
    assert_int_equal(pcmk__cmp_by_type(NULL, NULL, pcmk__type_string), 0);
    assert_true(pcmk__cmp_by_type("0", NULL, pcmk__type_integer) > 0);
    assert_true(pcmk__cmp_by_type(NULL, "0", pcmk__type_number) < 0);
}

static void
invalid_compares_equal(void **state)
{
    assert_int_equal(pcmk__cmp_by_type("0", "1", pcmk__type_unknown), 0);
    assert_int_equal(pcmk__cmp_by_type("hi", "bye", pcmk__type_unknown), 0);
    assert_int_equal(pcmk__cmp_by_type("-1.0", "2.0", pcmk__type_unknown), 0);
}

static void
compare_string_type(void **state)
{
    assert_int_equal(pcmk__cmp_by_type("bye", "bye", pcmk__type_string), 0);
    assert_int_equal(pcmk__cmp_by_type("bye", "BYE", pcmk__type_string), 0);
    assert_true(pcmk__cmp_by_type("bye", "hello", pcmk__type_string) < 0);
    assert_true(pcmk__cmp_by_type("bye", "HELLO", pcmk__type_string) < 0);
    assert_true(pcmk__cmp_by_type("bye", "boo", pcmk__type_string) > 0);
    assert_true(pcmk__cmp_by_type("bye", "Boo", pcmk__type_string) > 0);
}

static void
compare_integer_type(void **state)
{
    char *int_min = crm_strdup_printf("%d", INT_MIN);
    char *int_max = crm_strdup_printf("%d", INT_MAX);

    assert_int_equal(pcmk__cmp_by_type("0", "0", pcmk__type_integer), 0);
    assert_true(pcmk__cmp_by_type("0", "1", pcmk__type_integer) < 0);
    assert_true(pcmk__cmp_by_type("1", "0", pcmk__type_integer) > 0);
    assert_true(pcmk__cmp_by_type("3999", "399", pcmk__type_integer) > 0);
    assert_true(pcmk__cmp_by_type(int_min, int_max, pcmk__type_integer) < 0);
    assert_true(pcmk__cmp_by_type(int_max, int_min, pcmk__type_integer) > 0);
    free(int_min);
    free(int_max);

    // Non-integers compare as strings
    assert_int_equal(pcmk__cmp_by_type("0", "x", pcmk__type_integer),
                     pcmk__cmp_by_type("0", "x", pcmk__type_string));
    assert_int_equal(pcmk__cmp_by_type("x", "0", pcmk__type_integer),
                     pcmk__cmp_by_type("x", "0", pcmk__type_string));
    assert_int_equal(pcmk__cmp_by_type("x", "X", pcmk__type_integer),
                     pcmk__cmp_by_type("x", "X", pcmk__type_string));
}

static void
compare_number_type(void **state)
{
    assert_int_equal(pcmk__cmp_by_type("0", "0.0", pcmk__type_number), 0);
    assert_true(pcmk__cmp_by_type("0.345", "0.5", pcmk__type_number) < 0);
    assert_true(pcmk__cmp_by_type("5", "3.1", pcmk__type_number) > 0);
    assert_true(pcmk__cmp_by_type("3999", "399", pcmk__type_number) > 0);

    // Non-numbers compare as strings
    assert_int_equal(pcmk__cmp_by_type("0.0", "x", pcmk__type_number),
                     pcmk__cmp_by_type("0.0", "x", pcmk__type_string));
    assert_int_equal(pcmk__cmp_by_type("x", "0.0", pcmk__type_number),
                     pcmk__cmp_by_type("x", "0.0", pcmk__type_string));
    assert_int_equal(pcmk__cmp_by_type("x", "X", pcmk__type_number),
                     pcmk__cmp_by_type("x", "X", pcmk__type_string));
}

static void
compare_version_type(void **state)
{
    assert_int_equal(pcmk__cmp_by_type("1.0", "1.0", pcmk__type_version), 0);
    assert_true(pcmk__cmp_by_type("1.0.0", "1.0.1", pcmk__type_version) < 0);
    assert_true(pcmk__cmp_by_type("5.0", "3.1.15", pcmk__type_version) > 0);
    assert_true(pcmk__cmp_by_type("3999", "399", pcmk__type_version) > 0);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_compares_lesser),
                cmocka_unit_test(invalid_compares_equal),
                cmocka_unit_test(compare_string_type),
                cmocka_unit_test(compare_integer_type),
                cmocka_unit_test(compare_number_type),
                cmocka_unit_test(compare_version_type))

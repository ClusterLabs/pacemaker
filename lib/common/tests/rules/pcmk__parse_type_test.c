/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>

#include <crm/common/rules_internal.h>
#include <crm/common/unittest_internal.h>

static void
invalid(void **state)
{
    assert_int_equal(pcmk__parse_type("nope", pcmk__comparison_unknown,
                                      NULL, NULL),
                     pcmk__type_unknown);
}

static void
valid(void **state)
{
    assert_int_equal(pcmk__parse_type(PCMK_VALUE_STRING,
                                      pcmk__comparison_unknown, NULL, NULL),
                     pcmk__type_string);

    assert_int_equal(pcmk__parse_type(PCMK_VALUE_INTEGER,
                                      pcmk__comparison_unknown, NULL, NULL),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(PCMK_VALUE_NUMBER,
                                      pcmk__comparison_unknown, NULL, NULL),
                     pcmk__type_number);

    assert_int_equal(pcmk__parse_type(PCMK_VALUE_VERSION,
                                      pcmk__comparison_unknown, NULL, NULL),
                     pcmk__type_version);
}

static void
case_insensitive(void **state)
{
    assert_int_equal(pcmk__parse_type("STRING", pcmk__comparison_unknown,
                                      NULL, NULL),
                     pcmk__type_string);

    assert_int_equal(pcmk__parse_type("Integer", pcmk__comparison_unknown,
                                      NULL, NULL),
                     pcmk__type_integer);
}

static void
default_number(void **state)
{
    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_lt, "1.0", "2.5"),
                     pcmk__type_number);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_lte, "1.", "2"),
                     pcmk__type_number);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gt, "1", ".5"),
                     pcmk__type_number);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gte, "1.0", "2"),
                     pcmk__type_number);
}

static void
default_integer(void **state)
{
    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_lt, "1", "2"),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_lte, "1", "2"),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gt, "1", "2"),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gte, "1", "2"),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gte, NULL, NULL),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gte, "1", NULL),
                     pcmk__type_integer);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_gte, NULL, "2.5"),
                     pcmk__type_number);
}

static void
default_string(void **state)
{
    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_unknown,
                                      NULL, NULL),
                     pcmk__type_string);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_defined,
                                      NULL, NULL),
                     pcmk__type_string);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_undefined,
                                      NULL, NULL),
                     pcmk__type_string);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_eq, NULL, NULL),
                     pcmk__type_string);

    assert_int_equal(pcmk__parse_type(NULL, pcmk__comparison_ne, NULL, NULL),
                     pcmk__type_string);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(invalid),
                cmocka_unit_test(valid),
                cmocka_unit_test(case_insensitive),
                cmocka_unit_test(default_number),
                cmocka_unit_test(default_integer),
                cmocka_unit_test(default_string))

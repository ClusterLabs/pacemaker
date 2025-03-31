/*
 * Copyright 2020-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scores.h>              // pcmk_str_is_infinity()
#include <crm/common/unittest_internal.h>

static void
uppercase_str_passes(void **state)
{
    assert_true(pcmk_str_is_infinity("INFINITY"));
    assert_true(pcmk_str_is_infinity("+INFINITY"));
}

static void
mixed_case_str_fails(void **state)
{
    assert_false(pcmk_str_is_infinity("infinity"));
    assert_false(pcmk_str_is_infinity("+infinity"));
    assert_false(pcmk_str_is_infinity("Infinity"));
    assert_false(pcmk_str_is_infinity("+Infinity"));
}

static void
added_whitespace_fails(void **state)
{
    assert_false(pcmk_str_is_infinity(" INFINITY"));
    assert_false(pcmk_str_is_infinity("INFINITY "));
    assert_false(pcmk_str_is_infinity(" INFINITY "));
    assert_false(pcmk_str_is_infinity("+ INFINITY"));
}

static void
empty_str_fails(void **state)
{
    assert_false(pcmk_str_is_infinity(NULL));
    assert_false(pcmk_str_is_infinity(""));
}

static void
minus_infinity_fails(void **state)
{
    assert_false(pcmk_str_is_infinity("-INFINITY"));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(uppercase_str_passes),
                cmocka_unit_test(mixed_case_str_fails),
                cmocka_unit_test(added_whitespace_fails),
                cmocka_unit_test(empty_str_fails),
                cmocka_unit_test(minus_infinity_fails))

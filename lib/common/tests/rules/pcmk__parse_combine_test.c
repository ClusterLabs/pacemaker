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
default_and(void **state)
{
    assert_int_equal(pcmk__parse_combine(NULL), pcmk__combine_and);
}

static void
invalid(void **state)
{
    assert_int_equal(pcmk__parse_combine(""), pcmk__combine_unknown);
    assert_int_equal(pcmk__parse_combine(" "), pcmk__combine_unknown);
    assert_int_equal(pcmk__parse_combine("but"), pcmk__combine_unknown);
}

static void
valid(void **state)
{
    assert_int_equal(pcmk__parse_combine(PCMK_VALUE_AND), pcmk__combine_and);
    assert_int_equal(pcmk__parse_combine(PCMK_VALUE_OR), pcmk__combine_or);
}

static void
case_insensitive(void **state)
{
    assert_int_equal(pcmk__parse_combine("And"),
                     pcmk__combine_and);

    assert_int_equal(pcmk__parse_combine("OR"),
                     pcmk__combine_or);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(default_and),
                cmocka_unit_test(invalid),
                cmocka_unit_test(valid),
                cmocka_unit_test(case_insensitive))

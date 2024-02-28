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
#include "crmcommon_private.h"

static void
null_unknown(void **state)
{
    assert_int_equal(pcmk__parse_comparison(NULL), pcmk__comparison_unknown);
}

static void
invalid(void **state)
{
    assert_int_equal(pcmk__parse_comparison("nope"), pcmk__comparison_unknown);
}

static void
valid(void **state)
{
    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_DEFINED),
                     pcmk__comparison_defined);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_NOT_DEFINED),
                     pcmk__comparison_undefined);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_EQ),
                     pcmk__comparison_eq);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_NE),
                     pcmk__comparison_ne);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_LT),
                     pcmk__comparison_lt);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_LTE),
                     pcmk__comparison_lte);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_GT),
                     pcmk__comparison_gt);

    assert_int_equal(pcmk__parse_comparison(PCMK_VALUE_GTE),
                     pcmk__comparison_gte);
}

static void
case_insensitive(void **state)
{
    assert_int_equal(pcmk__parse_comparison("DEFINED"),
                     pcmk__comparison_defined);

    assert_int_equal(pcmk__parse_comparison("Not_Defined"),
                     pcmk__comparison_undefined);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_unknown),
                cmocka_unit_test(invalid),
                cmocka_unit_test(valid),
                cmocka_unit_test(case_insensitive))

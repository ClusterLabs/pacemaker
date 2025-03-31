/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scores.h>              // pcmk_readable_score()
#include <crm/common/unittest_internal.h>

static void
outside_limits(void **state)
{
    assert_string_equal(pcmk_readable_score(PCMK_SCORE_INFINITY * 2),
                        PCMK_VALUE_INFINITY);
    assert_string_equal(pcmk_readable_score(-PCMK_SCORE_INFINITY * 2),
                        PCMK_VALUE_MINUS_INFINITY);
}

static void
inside_limits(void **state)
{
    assert_string_equal(pcmk_readable_score(0), "0");
    assert_string_equal(pcmk_readable_score(1024), "1024");
    assert_string_equal(pcmk_readable_score(-1024), "-1024");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(outside_limits),
                cmocka_unit_test(inside_limits))

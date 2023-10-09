/*
 * Copyright 2022-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
score1_minus_inf(void **state)
{
    assert_int_equal(pcmk__add_scores(-CRM_SCORE_INFINITY, -CRM_SCORE_INFINITY), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(-CRM_SCORE_INFINITY, -1), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(-CRM_SCORE_INFINITY, 0), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(-CRM_SCORE_INFINITY, 1), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(-CRM_SCORE_INFINITY, CRM_SCORE_INFINITY), -CRM_SCORE_INFINITY);
}

static void
score2_minus_inf(void **state)
{
    assert_int_equal(pcmk__add_scores(-1, -CRM_SCORE_INFINITY), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(0, -CRM_SCORE_INFINITY), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(1, -CRM_SCORE_INFINITY), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(CRM_SCORE_INFINITY, -CRM_SCORE_INFINITY), -CRM_SCORE_INFINITY);
}

static void
score1_pos_inf(void **state)
{
    assert_int_equal(pcmk__add_scores(CRM_SCORE_INFINITY, CRM_SCORE_INFINITY), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(CRM_SCORE_INFINITY, -1), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(CRM_SCORE_INFINITY, 0), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(CRM_SCORE_INFINITY, 1), CRM_SCORE_INFINITY);
}

static void
score2_pos_inf(void **state)
{
    assert_int_equal(pcmk__add_scores(-1, CRM_SCORE_INFINITY), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(0, CRM_SCORE_INFINITY), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(1, CRM_SCORE_INFINITY), CRM_SCORE_INFINITY);
}

static void
result_infinite(void **state)
{
    assert_int_equal(pcmk__add_scores(INT_MAX, INT_MAX), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(INT_MIN, INT_MIN), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(2000000, 50), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(CRM_SCORE_INFINITY/2, CRM_SCORE_INFINITY/2), CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(-CRM_SCORE_INFINITY/2, -CRM_SCORE_INFINITY/2), -CRM_SCORE_INFINITY);
    assert_int_equal(pcmk__add_scores(-4000000, 50), -CRM_SCORE_INFINITY);
}

static void
result_finite(void **state)
{
    assert_int_equal(pcmk__add_scores(0, 0), 0);
    assert_int_equal(pcmk__add_scores(0, 100), 100);
    assert_int_equal(pcmk__add_scores(200, 0), 200);
    assert_int_equal(pcmk__add_scores(200, -50), 150);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(score1_minus_inf),
                cmocka_unit_test(score2_minus_inf),
                cmocka_unit_test(score1_pos_inf),
                cmocka_unit_test(score2_pos_inf),
                cmocka_unit_test(result_infinite),
                cmocka_unit_test(result_finite))

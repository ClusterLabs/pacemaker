/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/agents.h>

static void
is_stonith_param(void **state)
{
    assert_false(pcmk_stonith_param(NULL));
    assert_false(pcmk_stonith_param(""));
    assert_false(pcmk_stonith_param("unrecognized"));
    assert_false(pcmk_stonith_param("pcmk_unrecognized"));
    assert_false(pcmk_stonith_param("x" PCMK_STONITH_ACTION_LIMIT));
    assert_false(pcmk_stonith_param(PCMK_STONITH_ACTION_LIMIT "x"));

    assert_true(pcmk_stonith_param(PCMK_STONITH_ACTION_LIMIT));
    assert_true(pcmk_stonith_param(PCMK_STONITH_DELAY_BASE));
    assert_true(pcmk_stonith_param(PCMK_STONITH_DELAY_MAX));
    assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_ARGUMENT));
    assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_CHECK));
    assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_LIST));
    assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_MAP));
    assert_true(pcmk_stonith_param(PCMK_STONITH_PROVIDES));
    assert_true(pcmk_stonith_param(PCMK_STONITH_STONITH_TIMEOUT));
}

static void
is_stonith_action_param(void **state)
{
    /* Currently, the function accepts any string not containing underbars as
     * the action name, so we do not need to verify particular action names.
     */
    assert_false(pcmk_stonith_param("pcmk_on_unrecognized"));
    assert_true(pcmk_stonith_param("pcmk_on_action"));
    assert_true(pcmk_stonith_param("pcmk_on_timeout"));
    assert_true(pcmk_stonith_param("pcmk_on_retries"));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(is_stonith_param),
                cmocka_unit_test(is_stonith_action_param))

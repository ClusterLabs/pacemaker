/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/common/agents.h>

static void
is_stonith_param(void)
{
    g_assert_false(pcmk_stonith_param(NULL));
    g_assert_false(pcmk_stonith_param(""));
    g_assert_false(pcmk_stonith_param("unrecognized"));
    g_assert_false(pcmk_stonith_param("pcmk_unrecognized"));
    g_assert_false(pcmk_stonith_param("x" PCMK_STONITH_ACTION_LIMIT));
    g_assert_false(pcmk_stonith_param(PCMK_STONITH_ACTION_LIMIT "x"));

    g_assert_true(pcmk_stonith_param(PCMK_STONITH_ACTION_LIMIT));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_DELAY_BASE));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_DELAY_MAX));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_ARGUMENT));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_CHECK));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_LIST));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_HOST_MAP));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_PROVIDES));
    g_assert_true(pcmk_stonith_param(PCMK_STONITH_STONITH_TIMEOUT));
}

static void
is_stonith_action_param(void)
{
    /* Currently, the function accepts any string not containing underbars as
     * the action name, so we do not need to verify particular action names.
     */
    g_assert_false(pcmk_stonith_param("pcmk_on_unrecognized"));
    g_assert_true(pcmk_stonith_param("pcmk_on_action"));
    g_assert_true(pcmk_stonith_param("pcmk_on_timeout"));
    g_assert_true(pcmk_stonith_param("pcmk_on_retries"));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/utils/parse_op_key/is_stonith_param",
                    is_stonith_param);
    g_test_add_func("/common/utils/parse_op_key/is_stonith_action_param",
                    is_stonith_action_param);
    return g_test_run();
}

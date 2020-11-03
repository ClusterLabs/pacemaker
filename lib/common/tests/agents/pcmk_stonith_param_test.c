/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <glib.h>

#include <crm_internal.h>
#include <crm/common/agents.h>

static void
is_stonith_param(void)
{
    g_assert_cmpint(pcmk_stonith_param(NULL), ==, false);
    g_assert_cmpint(pcmk_stonith_param(""), ==, false);
    g_assert_cmpint(pcmk_stonith_param("unrecognized"), ==, false);
    g_assert_cmpint(pcmk_stonith_param("pcmk_unrecognized"), ==, false);
    g_assert_cmpint(pcmk_stonith_param("x" PCMK_STONITH_ACTION_LIMIT), ==, false);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_ACTION_LIMIT "x"), ==, false);

    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_ACTION_LIMIT), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_DELAY_BASE), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_DELAY_MAX), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_HOST_ARGUMENT), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_HOST_CHECK), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_HOST_LIST), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_HOST_MAP), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_PROVIDES), ==, true);
    g_assert_cmpint(pcmk_stonith_param(PCMK_STONITH_STONITH_TIMEOUT), ==, true);
}

static void
is_stonith_action_param(void)
{
    /* Currently, the function accepts any string not containing underbars as
     * the action name, so we do not need to verify particular action names.
     */
    g_assert_cmpint(pcmk_stonith_param("pcmk_on_unrecognized"), ==, false);
    g_assert_cmpint(pcmk_stonith_param("pcmk_on_action"), ==, true);
    g_assert_cmpint(pcmk_stonith_param("pcmk_on_timeout"), ==, true);
    g_assert_cmpint(pcmk_stonith_param("pcmk_on_retries"), ==, true);
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

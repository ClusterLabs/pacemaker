/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <limits.h>

#include <crm/common/iso8601_internal.h>

static void
readable_interval(void)
{
    g_assert_cmpint(strcmp(pcmk__readable_interval(0), "0s"), ==, 0);
    g_assert_cmpint(strcmp(pcmk__readable_interval(30000), "30s"), ==, 0);
    g_assert_cmpint(strcmp(pcmk__readable_interval(150000), "2m30s"), ==, 0);
    g_assert_cmpint(strcmp(pcmk__readable_interval(3333), "3.333s"), ==, 0);
    g_assert_cmpint(strcmp(pcmk__readable_interval(UINT_MAX), "49d17h2m47.295s"), ==, 0);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/utils/pcmk__readable_interval/readable_interval",
                    readable_interval);
    return g_test_run();
}

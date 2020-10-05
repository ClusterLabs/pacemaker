/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

static void
btoa(void) {
    g_assert_cmpstr(pcmk__btoa(false), ==, "false");
    g_assert_cmpstr(pcmk__btoa(true), ==, "true");
    g_assert_cmpstr(pcmk__btoa(1 == 0), ==, "false");
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/btoa/btoa", btoa);
    return g_test_run();
}

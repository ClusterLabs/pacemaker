/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <stdio.h>
#include <stdbool.h>
#include <crm_internal.h>

static void
all_set(void) {
    g_assert_false(pcmk_all_flags_set(0x000, 0x003));
    g_assert_true(pcmk_all_flags_set(0x00f, 0x003));
    g_assert_false(pcmk_all_flags_set(0x00f, 0x010));
    g_assert_false(pcmk_all_flags_set(0x00f, 0x011));
    g_assert_true(pcmk_all_flags_set(0x000, 0x000));
    g_assert_true(pcmk_all_flags_set(0x00f, 0x000));
}

static void
one_is_set(void) {
    // pcmk_is_set() is a simple macro alias for pcmk_all_flags_set()
    g_assert_true(pcmk_is_set(0x00f, 0x001));
    g_assert_false(pcmk_is_set(0x00f, 0x010));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/flags/all_set/all_set", all_set);
    g_test_add_func("/common/flags/all_set/is_set", one_is_set);
    return g_test_run();
}

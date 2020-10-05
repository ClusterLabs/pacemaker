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
clear_none(void) {
    g_assert_cmphex(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                         "test", 0x0f0, 0x00f, NULL), ==, 0x0f0);
    g_assert_cmphex(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                         "test", 0x0f0, 0xf0f, NULL), ==, 0x0f0);
}

static void
clear_some(void) {
    g_assert_cmphex(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                         "test", 0x0f0, 0x020, NULL), ==, 0x0d0);
    g_assert_cmphex(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                         "test", 0x0f0, 0x030, NULL), ==, 0x0c0);
}

static void
clear_all(void) {
    g_assert_cmphex(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                         "test", 0x0f0, 0x0f0, NULL), ==, 0x000);
    g_assert_cmphex(pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                         "test", 0x0f0, 0xfff, NULL), ==, 0x000);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/flags/clear/clear_none", clear_none);
    g_test_add_func("/common/flags/clear/clear_some", clear_some);
    g_test_add_func("/common/flags/clear/clear_all", clear_all);
    return g_test_run();
}

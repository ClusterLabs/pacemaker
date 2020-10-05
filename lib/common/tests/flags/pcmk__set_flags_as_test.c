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
set_flags(void) {
    g_assert_cmphex(pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                       "test", 0x0f0, 0x00f, NULL), ==, 0x0ff);
    g_assert_cmphex(pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                       "test", 0x0f0, 0xf0f, NULL), ==, 0xfff);
    g_assert_cmphex(pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE, "Test",
                                       "test", 0x0f0, 0xfff, NULL), ==, 0xfff);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/flags/set/set_flags", set_flags);
    return g_test_run();
}

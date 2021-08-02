/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

static void
bad_input(void) {
    g_assert_false(pcmk__starts_with(NULL, "x"));
    g_assert_false(pcmk__starts_with("abc", NULL));
}

static void
starts_with(void) {
    g_assert_true(pcmk__starts_with("abc", "a"));
    g_assert_true(pcmk__starts_with("abc", "ab"));
    g_assert_true(pcmk__starts_with("abc", "abc"));

    g_assert_false(pcmk__starts_with("abc", "A"));
    g_assert_false(pcmk__starts_with("abc", "bc"));

    g_assert_false(pcmk__starts_with("", "x"));
    g_assert_true(pcmk__starts_with("xyz", ""));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/starts_with/bad_input", bad_input);
    g_test_add_func("/common/strings/starts_with/starts_with", starts_with);
    return g_test_run();
}

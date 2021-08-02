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
    g_assert_false(pcmk__ends_with(NULL, "xyz"));

    g_assert_true(pcmk__ends_with(NULL, NULL));
    g_assert_true(pcmk__ends_with(NULL, ""));
    g_assert_true(pcmk__ends_with("", NULL));
    g_assert_true(pcmk__ends_with("", ""));
    g_assert_true(pcmk__ends_with("abc", NULL));
    g_assert_true(pcmk__ends_with("abc", ""));
}

static void
ends_with(void) {
    g_assert_true(pcmk__ends_with("abc", "abc"));
    g_assert_true(pcmk__ends_with("abc", "bc"));
    g_assert_true(pcmk__ends_with("abc", "c"));
    g_assert_true(pcmk__ends_with("abcbc", "bc"));

    g_assert_false(pcmk__ends_with("abc", "def"));
    g_assert_false(pcmk__ends_with("abc", "defg"));
    g_assert_false(pcmk__ends_with("abc", "bcd"));
    g_assert_false(pcmk__ends_with("abc", "ab"));

    g_assert_false(pcmk__ends_with("abc", "BC"));
}

static void
ends_with_ext(void) {
    g_assert_true(pcmk__ends_with_ext("ab.c", ".c"));
    g_assert_true(pcmk__ends_with_ext("ab.cb.c", ".c"));

    g_assert_false(pcmk__ends_with_ext("ab.c", ".def"));
    g_assert_false(pcmk__ends_with_ext("ab.c", ".defg"));
    g_assert_false(pcmk__ends_with_ext("ab.c", ".cd"));
    g_assert_false(pcmk__ends_with_ext("ab.c", "ab"));

    g_assert_false(pcmk__ends_with_ext("ab.c", ".C"));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/ends_with/bad_input", bad_input);
    g_test_add_func("/common/strings/ends_with/ends_with", ends_with);
    g_test_add_func("/common/strings/ends_with/ends_with_ext", ends_with_ext);
    return g_test_run();
}

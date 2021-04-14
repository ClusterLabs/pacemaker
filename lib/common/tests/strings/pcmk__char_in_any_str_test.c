/*
 * Copyright 2020-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

static void
empty_list(void)
{
    g_assert_false(pcmk__char_in_any_str('x', NULL));
    g_assert_false(pcmk__char_in_any_str('\0', NULL));
}

static void
null_char(void)
{
    g_assert_true(pcmk__char_in_any_str('\0', "xxx", "yyy", NULL));
    g_assert_true(pcmk__char_in_any_str('\0', "", NULL));
}

static void
in_list(void)
{
    g_assert_true(pcmk__char_in_any_str('x', "aaa", "bbb", "xxx", NULL));
}

static void
not_in_list(void)
{
    g_assert_false(pcmk__char_in_any_str('x', "aaa", "bbb", NULL));
    g_assert_false(pcmk__char_in_any_str('A', "aaa", "bbb", NULL));
    g_assert_false(pcmk__char_in_any_str('x', "", NULL));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/char_in_any_str/empty_list", empty_list);
    g_test_add_func("/common/strings/char_in_any_str/null_char", null_char);
    g_test_add_func("/common/strings/char_in_any_str/in", in_list);
    g_test_add_func("/common/strings/char_in_any_str/not_in", not_in_list);

    return g_test_run();
}


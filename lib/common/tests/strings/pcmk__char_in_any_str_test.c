#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#include <crm_internal.h>

static void
empty_list(void)
{
    g_assert_cmpint(pcmk__char_in_any_str('x', NULL), ==, false);
    g_assert_cmpint(pcmk__char_in_any_str('\0', NULL), ==, false);
}

static void
null_char(void)
{
    g_assert_cmpint(pcmk__char_in_any_str('\0', "xxx", "yyy", NULL), ==, true);
    g_assert_cmpint(pcmk__char_in_any_str('\0', "", NULL), ==, true);
}

static void
in_list(void)
{
    g_assert_cmpint(pcmk__char_in_any_str('x', "aaa", "bbb", "xxx", NULL), ==, true);
}

static void
not_in_list(void)
{
    g_assert_cmpint(pcmk__char_in_any_str('x', "aaa", "bbb", NULL), ==, false);
    g_assert_cmpint(pcmk__char_in_any_str('A', "aaa", "bbb", NULL), ==, false);
    g_assert_cmpint(pcmk__char_in_any_str('x', "", NULL), ==, false);
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


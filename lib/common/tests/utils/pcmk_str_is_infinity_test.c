#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#include <crm_internal.h>

static void
uppercase_str_passes(void)
{
    g_assert_true(pcmk_str_is_infinity("INFINITY"));
    g_assert_true(pcmk_str_is_infinity("+INFINITY"));
}

static void
mixed_case_str_fails(void)
{
    g_assert_false(pcmk_str_is_infinity("infinity"));
    g_assert_false(pcmk_str_is_infinity("+infinity"));
    g_assert_false(pcmk_str_is_infinity("Infinity"));
    g_assert_false(pcmk_str_is_infinity("+Infinity"));
}

static void
added_whitespace_fails(void)
{
    g_assert_false(pcmk_str_is_infinity(" INFINITY"));
    g_assert_false(pcmk_str_is_infinity("INFINITY "));
    g_assert_false(pcmk_str_is_infinity(" INFINITY "));
    g_assert_false(pcmk_str_is_infinity("+ INFINITY"));
}

static void
empty_str_fails(void)
{
    g_assert_false(pcmk_str_is_infinity(NULL));
    g_assert_false(pcmk_str_is_infinity(""));
}

static void
minus_infinity_fails(void)
{
    g_assert_false(pcmk_str_is_infinity("-INFINITY"));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/utils/infinity/uppercase", uppercase_str_passes);
    g_test_add_func("/common/utils/infinity/mixed_case", mixed_case_str_fails);
    g_test_add_func("/common/utils/infinity/whitespace", added_whitespace_fails);
    g_test_add_func("/common/utils/infinity/empty", empty_str_fails);
    g_test_add_func("/common/utils/infinity/minus_infinity", minus_infinity_fails);

    return g_test_run();
}

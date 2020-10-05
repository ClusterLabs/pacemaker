#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#include <crm_internal.h>

static void
uppercase_str_passes(void)
{
    g_assert_cmpint(pcmk_str_is_minus_infinity("-INFINITY"), ==, true);
}

static void
mixed_case_str_fails(void)
{
    g_assert_cmpint(pcmk_str_is_minus_infinity("-infinity"), ==, false);
    g_assert_cmpint(pcmk_str_is_minus_infinity("-Infinity"), ==, false);
}

static void
added_whitespace_fails(void)
{
    g_assert_cmpint(pcmk_str_is_minus_infinity(" -INFINITY"), ==, false);
    g_assert_cmpint(pcmk_str_is_minus_infinity("-INFINITY "), ==, false);
    g_assert_cmpint(pcmk_str_is_minus_infinity(" -INFINITY "), ==, false);
    g_assert_cmpint(pcmk_str_is_minus_infinity("- INFINITY"), ==, false);
}

static void
empty_str_fails(void)
{
    g_assert_cmpint(pcmk_str_is_minus_infinity(NULL), ==, false);
    g_assert_cmpint(pcmk_str_is_minus_infinity(""), ==, false);
}

static void
infinity_fails(void)
{
    g_assert_cmpint(pcmk_str_is_minus_infinity("INFINITY"), ==, false);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/utils/minus_infinity/uppercase", uppercase_str_passes);
    g_test_add_func("/common/utils/minus_infinity/mixed_case", mixed_case_str_fails);
    g_test_add_func("/common/utils/minus_infinity/whitespace", added_whitespace_fails);
    g_test_add_func("/common/utils/minus_infinity/empty", empty_str_fails);
    g_test_add_func("/common/utils/minus_infinity/infinity", infinity_fails);

    return g_test_run();
}

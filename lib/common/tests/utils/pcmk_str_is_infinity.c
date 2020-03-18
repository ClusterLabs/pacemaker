#include <glib.h>

#include <crm_internal.h>

static void
uppercase_str_passes(void) {
    g_assert(pcmk_str_is_infinity("INFINITY") == TRUE);
    g_assert(pcmk_str_is_infinity("+INFINITY") == TRUE);
}

static void
mixed_case_str_fails(void) {
    g_assert(pcmk_str_is_infinity("infinity") == FALSE);
    g_assert(pcmk_str_is_infinity("+infinity") == FALSE);
    g_assert(pcmk_str_is_infinity("Infinity") == FALSE);
    g_assert(pcmk_str_is_infinity("+Infinity") == FALSE);
}

static void
added_whitespace_fails(void) {
    g_assert(pcmk_str_is_infinity(" INFINITY") == FALSE);
    g_assert(pcmk_str_is_infinity("INFINITY ") == FALSE);
    g_assert(pcmk_str_is_infinity(" INFINITY ") == FALSE);
    g_assert(pcmk_str_is_infinity("+ INFINITY") == FALSE);
}

static void
empty_str_fails(void) {
    g_assert(pcmk_str_is_infinity(NULL) == FALSE);
    g_assert(pcmk_str_is_infinity("") == FALSE);
}

static void
minus_infinity_fails(void) {
    g_assert(pcmk_str_is_infinity("-INFINITY") == FALSE);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/utils/infinity/uppercase", uppercase_str_passes);
    g_test_add_func("/common/utils/infinity/mixed_case", mixed_case_str_fails);
    g_test_add_func("/common/utils/infinity/whitespace", added_whitespace_fails);
    g_test_add_func("/common/utils/infinity/empty", empty_str_fails);
    g_test_add_func("/common/utils/infinity/minus_infinity", minus_infinity_fails);

    return g_test_run();
}

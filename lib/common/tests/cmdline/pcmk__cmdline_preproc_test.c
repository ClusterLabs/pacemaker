/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/common/cmdline_internal.h>

#define LISTS_EQ(a, b) { \
    g_assert_cmpint(g_strv_length((gchar **) (a)), ==, g_strv_length((gchar **) (b))); \
    for (int i = 0; i < g_strv_length((a)); i++) { \
        g_assert_cmpstr((a)[i], ==, (b)[i]); \
    } \
}

static void
empty_input(void) {
    g_assert_cmpint(pcmk__cmdline_preproc(NULL, "") == NULL, ==, TRUE);
}

static void
no_specials(void) {
    const char *argv[] = { "-a", "-b", "-c", "-d", NULL };
    const gchar *expected[] = { "-a", "-b", "-c", "-d", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);

    processed = pcmk__cmdline_preproc((char **) argv, "");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
single_dash(void) {
    const char *argv[] = { "-", NULL };
    const gchar *expected[] = { "-", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
double_dash(void) {
    const char *argv[] = { "-a", "--", "-bc", NULL };
    const gchar *expected[] = { "-a", "--", "-bc", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
special_args(void) {
    const char *argv[] = { "-aX", "-Fval", NULL };
    const gchar *expected[] = { "-a", "X", "-F", "val", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "aF");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
special_arg_at_end(void) {
    const char *argv[] = { "-a", NULL };
    const gchar *expected[] = { "-a", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "a");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
long_arg(void) {
    const char *argv[] = { "--blah=foo", NULL };
    const gchar *expected[] = { "--blah=foo", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/cmdline/preproc/empty_input", empty_input);
    g_test_add_func("/common/cmdline/preproc/no_specials", no_specials);
    g_test_add_func("/common/cmdline/preproc/single_dash", single_dash);
    g_test_add_func("/common/cmdline/preproc/double_dash", double_dash);
    g_test_add_func("/common/cmdline/preproc/special_args", special_args);
    g_test_add_func("/common/cmdline/preproc/special_arg_at_end", special_arg_at_end);
    g_test_add_func("/common/cmdline/preproc/long_arg", long_arg);
    return g_test_run();
}

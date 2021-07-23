/*
 * Copyright 2020-2021 the Pacemaker project contributors
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
    g_assert_null(pcmk__cmdline_preproc(NULL, ""));
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

static void
negative_score(void) {
    const char *argv[] = { "-v", "-1000", NULL };
    const gchar *expected[] = { "-v", "-1000", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
negative_score_2(void) {
    const char *argv[] = { "-1i3", NULL };
    const gchar *expected[] = { "-1", "-i", "-3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash(void) {
    const char *argv[] = { "-n", "crm_mon_options", "-v", "--opt1 --opt2", NULL };
    const gchar *expected[] = { "-n", "crm_mon_options", "-v", "--opt1 --opt2", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash_2(void) {
    const char *argv[] = { "-n", "crm_mon_options", "-v", "-1i3", NULL };
    const gchar *expected[] = { "-n", "crm_mon_options", "-v", "-1i3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash_3(void) {
    const char *argv[] = { "-abc", "-1i3", NULL };
    const gchar *expected[] = { "-a", "-b", "-c", "-1i3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "c");
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
    g_test_add_func("/common/cmdline/preproc/negative_score", negative_score);
    g_test_add_func("/common/cmdline/preproc/negative_score_2", negative_score_2);
    g_test_add_func("/common/cmdline/preproc/string_arg_with_dash", string_arg_with_dash);
    g_test_add_func("/common/cmdline/preproc/string_arg_with_dash_2", string_arg_with_dash_2);
    g_test_add_func("/common/cmdline/preproc/string_arg_with_dash_3", string_arg_with_dash_3);
    return g_test_run();
}

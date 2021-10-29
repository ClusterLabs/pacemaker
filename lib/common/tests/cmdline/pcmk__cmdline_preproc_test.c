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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <glib.h>

#define LISTS_EQ(a, b) { \
    assert_int_equal(g_strv_length((gchar **) (a)), g_strv_length((gchar **) (b))); \
    for (int i = 0; i < g_strv_length((a)); i++) { \
        assert_string_equal((a)[i], (b)[i]); \
    } \
}

static void
empty_input(void **state) {
    assert_null(pcmk__cmdline_preproc(NULL, ""));
}

static void
no_specials(void **state) {
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
single_dash(void **state) {
    const char *argv[] = { "-", NULL };
    const gchar *expected[] = { "-", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
double_dash(void **state) {
    const char *argv[] = { "-a", "--", "-bc", NULL };
    const gchar *expected[] = { "-a", "--", "-bc", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
special_args(void **state) {
    const char *argv[] = { "-aX", "-Fval", NULL };
    const gchar *expected[] = { "-a", "X", "-F", "val", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "aF");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
special_arg_at_end(void **state) {
    const char *argv[] = { "-a", NULL };
    const gchar *expected[] = { "-a", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "a");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
long_arg(void **state) {
    const char *argv[] = { "--blah=foo", NULL };
    const gchar *expected[] = { "--blah=foo", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
negative_score(void **state) {
    const char *argv[] = { "-v", "-1000", NULL };
    const gchar *expected[] = { "-v", "-1000", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
negative_score_2(void **state) {
    const char *argv[] = { "-1i3", NULL };
    const gchar *expected[] = { "-1", "-i", "-3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash(void **state) {
    const char *argv[] = { "-n", "crm_mon_options", "-v", "--opt1 --opt2", NULL };
    const gchar *expected[] = { "-n", "crm_mon_options", "-v", "--opt1 --opt2", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash_2(void **state) {
    const char *argv[] = { "-n", "crm_mon_options", "-v", "-1i3", NULL };
    const gchar *expected[] = { "-n", "crm_mon_options", "-v", "-1i3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash_3(void **state) {
    const char *argv[] = { "-abc", "-1i3", NULL };
    const gchar *expected[] = { "-a", "-b", "-c", "-1i3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "c");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input),
        cmocka_unit_test(no_specials),
        cmocka_unit_test(single_dash),
        cmocka_unit_test(double_dash),
        cmocka_unit_test(special_args),
        cmocka_unit_test(special_arg_at_end),
        cmocka_unit_test(long_arg),
        cmocka_unit_test(negative_score),
        cmocka_unit_test(negative_score_2),
        cmocka_unit_test(string_arg_with_dash),
        cmocka_unit_test(string_arg_with_dash_2),
        cmocka_unit_test(string_arg_with_dash_3),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

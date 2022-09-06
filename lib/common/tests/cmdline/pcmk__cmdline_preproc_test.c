/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/cmdline_internal.h>

#include <glib.h>
#include <stdint.h>

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
    const char *argv[] = { "crm_mon", "-a", "-b", "-c", "-d", "-1", NULL };
    const gchar *expected[] = { "crm_mon", "-a", "-b", "-c", "-d", "-1", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);

    processed = pcmk__cmdline_preproc((char **) argv, "");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
single_dash(void **state) {
    const char *argv[] = { "crm_mon", "-", NULL };
    const gchar *expected[] = { "crm_mon", "-", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
double_dash(void **state) {
    const char *argv[] = { "crm_mon", "-a", "--", "-bc", NULL };
    const gchar *expected[] = { "crm_mon", "-a", "--", "-bc", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
special_args(void **state) {
    const char *argv[] = { "crm_mon", "-aX", "-Fval", NULL };
    const gchar *expected[] = { "crm_mon", "-a", "X", "-F", "val", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "aF");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
special_arg_at_end(void **state) {
    const char *argv[] = { "crm_mon", "-a", NULL };
    const gchar *expected[] = { "crm_mon", "-a", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "a");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
long_arg(void **state) {
    const char *argv[] = { "crm_mon", "--blah=foo", NULL };
    const gchar *expected[] = { "crm_mon", "--blah=foo", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
negative_score(void **state) {
    const char *argv[] = { "crm_mon", "-v", "-1000", NULL };
    const gchar *expected[] = { "crm_mon", "-v", "-1000", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
negative_score_2(void **state) {
    const char *argv[] = { "crm_mon", "-1i3", NULL };
    const gchar *expected[] = { "crm_mon", "-1", "-i", "-3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, NULL);
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash(void **state) {
    const char *argv[] = { "crm_mon", "-n", "crm_mon_options", "-v", "--opt1 --opt2", NULL };
    const gchar *expected[] = { "crm_mon", "-n", "crm_mon_options", "-v", "--opt1 --opt2", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash_2(void **state) {
    const char *argv[] = { "crm_mon", "-n", "crm_mon_options", "-v", "-1i3", NULL };
    const gchar *expected[] = { "crm_mon", "-n", "crm_mon_options", "-v", "-1i3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "v");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

static void
string_arg_with_dash_3(void **state) {
    const char *argv[] = { "crm_mon", "-abc", "-1i3", NULL };
    const gchar *expected[] = { "crm_mon", "-a", "-b", "-c", "-1i3", NULL };

    gchar **processed = pcmk__cmdline_preproc((char **) argv, "c");
    LISTS_EQ(processed, expected);
    g_strfreev(processed);
}

PCMK__UNIT_TEST(NULL, NULL,
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
                cmocka_unit_test(string_arg_with_dash_3))

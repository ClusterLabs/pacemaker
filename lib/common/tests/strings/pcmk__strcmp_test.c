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
same_pointer(void) {
    const char *s1 = "abcd";
    const char *s2 = "wxyz";

    g_assert_cmpint(pcmk__strcmp(s1, s1, pcmk__str_none), ==, 0);
    g_assert_true(pcmk__str_eq(s1, s1, pcmk__str_none));
    g_assert_cmpint(pcmk__strcmp(s1, s2, pcmk__str_none), !=, 0);
    g_assert_false(pcmk__str_eq(s1, s2, pcmk__str_none));
    g_assert_cmpint(pcmk__strcmp(NULL, NULL, pcmk__str_none), ==, 0);
}

static void
one_is_null(void) {
    const char *s1 = "abcd";

    g_assert_cmpint(pcmk__strcmp(s1, NULL, pcmk__str_null_matches), ==, 0);
    g_assert_true(pcmk__str_eq(s1, NULL, pcmk__str_null_matches));
    g_assert_cmpint(pcmk__strcmp(NULL, s1, pcmk__str_null_matches), ==, 0);
    g_assert_cmpint(pcmk__strcmp(s1, NULL, pcmk__str_none), >, 0);
    g_assert_false(pcmk__str_eq(s1, NULL, pcmk__str_none));
    g_assert_cmpint(pcmk__strcmp(NULL, s1, pcmk__str_none), <, 0);
}

static void
case_matters(void) {
    const char *s1 = "abcd";
    const char *s2 = "ABCD";

    g_assert_cmpint(pcmk__strcmp(s1, s2, pcmk__str_none), >, 0);
    g_assert_false(pcmk__str_eq(s1, s2, pcmk__str_none));
    g_assert_cmpint(pcmk__strcmp(s2, s1, pcmk__str_none), <, 0);
}

static void
case_insensitive(void) {
    const char *s1 = "abcd";
    const char *s2 = "ABCD";

    g_assert_cmpint(pcmk__strcmp(s1, s2, pcmk__str_casei), ==, 0);
    g_assert_true(pcmk__str_eq(s1, s2, pcmk__str_casei));
}

static void
regex(void) {
    const char *s1 = "abcd";
    const char *s2 = "ABCD";

    g_assert_cmpint(pcmk__strcmp(NULL, "a..d", pcmk__str_regex), ==, 1);
    g_assert_cmpint(pcmk__strcmp(s1, NULL, pcmk__str_regex), ==, 1);
    g_assert_cmpint(pcmk__strcmp(s1, "a..d", pcmk__str_regex), ==, 0);
    g_assert_true(pcmk__str_eq(s1, "a..d", pcmk__str_regex));
    g_assert_cmpint(pcmk__strcmp(s1, "xxyy", pcmk__str_regex), !=, 0);
    g_assert_false(pcmk__str_eq(s1, "xxyy", pcmk__str_regex));
    g_assert_cmpint(pcmk__strcmp(s2, "a..d", pcmk__str_regex|pcmk__str_casei), ==, 0);
    g_assert_true(pcmk__str_eq(s2, "a..d", pcmk__str_regex|pcmk__str_casei));
    g_assert_cmpint(pcmk__strcmp(s2, "a..d", pcmk__str_regex), !=, 0);
    g_assert_false(pcmk__str_eq(s2, "a..d", pcmk__str_regex));
    g_assert_cmpint(pcmk__strcmp(s2, "*ab", pcmk__str_regex), ==, 1);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/strcmp/same_pointer", same_pointer);
    g_test_add_func("/common/strings/strcmp/one_is_null", one_is_null);
    g_test_add_func("/common/strings/strcmp/case_matters", case_matters);
    g_test_add_func("/common/strings/strcmp/case_insensitive", case_insensitive);
    g_test_add_func("/common/strings/strcmp/regex", regex);

    return g_test_run();
}

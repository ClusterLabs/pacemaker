/*
 * Copyright 2021 the Pacemaker project contributors
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
empty_input_list(void) {
    g_assert_false(pcmk__str_in_list(NULL, NULL, pcmk__str_none));
    g_assert_false(pcmk__str_in_list(NULL, NULL, pcmk__str_null_matches));
    g_assert_false(pcmk__str_in_list(NULL, "xxx", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(NULL, "", pcmk__str_none));
}

static void
empty_string(void) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "xxx");

    g_assert_false(pcmk__str_in_list(list, NULL, pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, NULL, pcmk__str_null_matches));
    g_assert_false(pcmk__str_in_list(list, "", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(list, "", pcmk__str_null_matches));

    g_list_free(list);
}

static void
star_matches(void) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "*");

    g_assert_true(pcmk__str_in_list(list, "xxx", pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, "yyy", pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, "XXX", pcmk__str_casei));
    g_assert_true(pcmk__str_in_list(list, "", pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, NULL, pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, NULL, pcmk__str_null_matches));

    g_list_free(list);
}

static void
star_doesnt_match(void) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "*");
    list = g_list_append(list, (gpointer) "more");

    g_assert_false(pcmk__str_in_list(list, "xxx", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(list, "yyy", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(list, "XXX", pcmk__str_casei));
    g_assert_false(pcmk__str_in_list(list, "", pcmk__str_none));

    g_list_free(list);
}

static void
in_list(void) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "xxx");
    list = g_list_prepend(list, (gpointer) "yyy");
    list = g_list_prepend(list, (gpointer) "zzz");

    g_assert_true(pcmk__str_in_list(list, "xxx", pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, "XXX", pcmk__str_casei));
    g_assert_true(pcmk__str_in_list(list, "yyy", pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, "YYY", pcmk__str_casei));
    g_assert_true(pcmk__str_in_list(list, "zzz", pcmk__str_none));
    g_assert_true(pcmk__str_in_list(list, "ZZZ", pcmk__str_casei));

    g_list_free(list);
}

static void
not_in_list(void) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "xxx");
    list = g_list_prepend(list, (gpointer) "yyy");

    g_assert_false(pcmk__str_in_list(list, "xx", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(list, "XXX", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(list, "zzz", pcmk__str_none));
    g_assert_false(pcmk__str_in_list(list, "zzz", pcmk__str_casei));

    g_list_free(list);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/common/strings/in_list/empty_list", empty_input_list);
    g_test_add_func("/common/strings/in_list/empty_string", empty_string);
    g_test_add_func("/common/strings/in_list/star_matches", star_matches);
    g_test_add_func("/common/strings/in_list/star_doesnt_match", star_doesnt_match);
    g_test_add_func("/common/strings/in_list/in", in_list);
    g_test_add_func("/common/strings/in_list/not_in", not_in_list);

    return g_test_run();
}

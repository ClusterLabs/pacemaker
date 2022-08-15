/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

static void
empty_input_list(void **state) {
    assert_false(pcmk__str_in_list(NULL, NULL, pcmk__str_none));
    assert_false(pcmk__str_in_list(NULL, NULL, pcmk__str_null_matches));
    assert_false(pcmk__str_in_list("xxx", NULL, pcmk__str_none));
    assert_false(pcmk__str_in_list("", NULL, pcmk__str_none));
}

static void
empty_string(void **state) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "xxx");

    assert_false(pcmk__str_in_list(NULL, list, pcmk__str_none));
    assert_true(pcmk__str_in_list(NULL, list, pcmk__str_null_matches));
    assert_false(pcmk__str_in_list("", list, pcmk__str_none));
    assert_false(pcmk__str_in_list("", list, pcmk__str_null_matches));

    g_list_free(list);
}

static void
star_matches(void **state) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "*");
    list = g_list_append(list, (gpointer) "more");

    assert_true(pcmk__str_in_list("xxx", list, pcmk__str_star_matches));
    assert_true(pcmk__str_in_list("yyy", list, pcmk__str_star_matches));
    assert_true(pcmk__str_in_list("XXX", list, pcmk__str_star_matches|pcmk__str_casei));
    assert_true(pcmk__str_in_list("", list, pcmk__str_star_matches));

    g_list_free(list);
}

static void
star_doesnt_match(void **state) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "*");

    assert_false(pcmk__str_in_list("xxx", list, pcmk__str_none));
    assert_false(pcmk__str_in_list("yyy", list, pcmk__str_none));
    assert_false(pcmk__str_in_list("XXX", list, pcmk__str_casei));
    assert_false(pcmk__str_in_list("", list, pcmk__str_none));
    assert_false(pcmk__str_in_list(NULL, list, pcmk__str_star_matches));

    g_list_free(list);
}

static void
in_list(void **state) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "xxx");
    list = g_list_prepend(list, (gpointer) "yyy");
    list = g_list_prepend(list, (gpointer) "zzz");

    assert_true(pcmk__str_in_list("xxx", list, pcmk__str_none));
    assert_true(pcmk__str_in_list("XXX", list, pcmk__str_casei));
    assert_true(pcmk__str_in_list("yyy", list, pcmk__str_none));
    assert_true(pcmk__str_in_list("YYY", list, pcmk__str_casei));
    assert_true(pcmk__str_in_list("zzz", list, pcmk__str_none));
    assert_true(pcmk__str_in_list("ZZZ", list, pcmk__str_casei));

    g_list_free(list);
}

static void
not_in_list(void **state) {
    GList *list = NULL;

    list = g_list_prepend(list, (gpointer) "xxx");
    list = g_list_prepend(list, (gpointer) "yyy");

    assert_false(pcmk__str_in_list("xx", list, pcmk__str_none));
    assert_false(pcmk__str_in_list("XXX", list, pcmk__str_none));
    assert_false(pcmk__str_in_list("zzz", list, pcmk__str_none));
    assert_false(pcmk__str_in_list("zzz", list, pcmk__str_casei));

    g_list_free(list);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(empty_input_list),
        cmocka_unit_test(empty_string),
        cmocka_unit_test(star_matches),
        cmocka_unit_test(star_doesnt_match),
        cmocka_unit_test(in_list),
        cmocka_unit_test(not_in_list),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

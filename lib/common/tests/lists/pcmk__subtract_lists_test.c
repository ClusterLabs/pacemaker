/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/lists_internal.h>

#include <glib.h>

static void
different_lists(void **state)
{
    GList *from = NULL;
    GList *items = NULL;
    GList *result = NULL;

    from = g_list_append(from, strdup("abc"));
    from = g_list_append(from, strdup("def"));
    from = g_list_append(from, strdup("ghi"));

    items = g_list_append(items, strdup("123"));
    items = g_list_append(items, strdup("456"));

    result = pcmk__subtract_lists(from, items, (GCompareFunc) strcmp);

    assert_int_equal(g_list_length(result), 3);
    assert_string_equal(g_list_nth_data(result, 0), "abc");
    assert_string_equal(g_list_nth_data(result, 1), "def");
    assert_string_equal(g_list_nth_data(result, 2), "ghi");

    g_list_free(result);
    g_list_free_full(from, free);
    g_list_free_full(items, free);
}

static void
remove_first_item(void **state)
{
    GList *from = NULL;
    GList *items = NULL;
    GList *result = NULL;

    from = g_list_append(from, strdup("abc"));
    from = g_list_append(from, strdup("def"));
    from = g_list_append(from, strdup("ghi"));

    items = g_list_append(items, strdup("abc"));

    result = pcmk__subtract_lists(from, items, (GCompareFunc) strcmp);

    assert_int_equal(g_list_length(result), 2);
    assert_string_equal(g_list_nth_data(result, 0), "def");
    assert_string_equal(g_list_nth_data(result, 1), "ghi");

    g_list_free(result);
    g_list_free_full(from, free);
    g_list_free_full(items, free);
}

static void
remove_middle_item(void **state)
{
    GList *from = NULL;
    GList *items = NULL;
    GList *result = NULL;

    from = g_list_append(from, strdup("abc"));
    from = g_list_append(from, strdup("def"));
    from = g_list_append(from, strdup("ghi"));

    items = g_list_append(items, strdup("def"));

    result = pcmk__subtract_lists(from, items, (GCompareFunc) strcmp);

    assert_int_equal(g_list_length(result), 2);
    assert_string_equal(g_list_nth_data(result, 0), "abc");
    assert_string_equal(g_list_nth_data(result, 1), "ghi");

    g_list_free(result);
    g_list_free_full(from, free);
    g_list_free_full(items, free);
}

static void
remove_last_item(void **state)
{
    GList *from = NULL;
    GList *items = NULL;
    GList *result = NULL;

    from = g_list_append(from, strdup("abc"));
    from = g_list_append(from, strdup("def"));
    from = g_list_append(from, strdup("ghi"));

    items = g_list_append(items, strdup("ghi"));

    result = pcmk__subtract_lists(from, items, (GCompareFunc) strcmp);

    assert_int_equal(g_list_length(result), 2);
    assert_string_equal(g_list_nth_data(result, 0), "abc");
    assert_string_equal(g_list_nth_data(result, 1), "def");

    g_list_free(result);
    g_list_free_full(from, free);
    g_list_free_full(items, free);
}

static void
remove_all_items(void **state)
{
    GList *from = NULL;
    GList *items = NULL;
    GList *result = NULL;

    from = g_list_append(from, strdup("abc"));
    from = g_list_append(from, strdup("def"));
    from = g_list_append(from, strdup("ghi"));

    items = g_list_append(items, strdup("abc"));
    items = g_list_append(items, strdup("def"));
    items = g_list_append(items, strdup("ghi"));

    result = pcmk__subtract_lists(from, items, (GCompareFunc) strcmp);

    assert_int_equal(g_list_length(result), 0);

    g_list_free(result);
    g_list_free_full(from, free);
    g_list_free_full(items, free);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(different_lists),
        cmocka_unit_test(remove_first_item),
        cmocka_unit_test(remove_middle_item),
        cmocka_unit_test(remove_last_item),
        cmocka_unit_test(remove_all_items),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

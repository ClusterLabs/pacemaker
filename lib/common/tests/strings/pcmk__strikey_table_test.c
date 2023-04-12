/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

static void
store_strs(void **state)
{
    GHashTable *tbl = NULL;

    tbl = pcmk__strikey_table(free, free);
    assert_non_null(tbl);

    assert_true(g_hash_table_insert(tbl, strdup("key-abc"), strdup("val-abc")));
    assert_int_equal(g_hash_table_size(tbl), 1);
    assert_string_equal(g_hash_table_lookup(tbl, "key-abc"), "val-abc");

    assert_false(g_hash_table_insert(tbl, strdup("key-abc"), strdup("val-def")));
    assert_int_equal(g_hash_table_size(tbl), 1);
    assert_string_equal(g_hash_table_lookup(tbl, "key-abc"), "val-def");

    assert_false(g_hash_table_insert(tbl, strdup("key-ABC"), strdup("val-ABC")));
    assert_int_equal(g_hash_table_size(tbl), 1);
    assert_string_equal(g_hash_table_lookup(tbl, "key-ABC"), "val-ABC");

    g_hash_table_destroy(tbl);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(store_strs))

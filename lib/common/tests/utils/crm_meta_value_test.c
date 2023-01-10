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
#include <crm/msg_xml.h>

#include <glib.h>

static void
empty_params(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);

    assert_null(crm_meta_value(NULL, NULL));
    assert_null(crm_meta_value(tbl, NULL));

    g_hash_table_destroy(tbl);
}

static void
key_not_in_table(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);

    assert_null(crm_meta_value(tbl, XML_RSC_ATTR_NOTIFY));
    assert_null(crm_meta_value(tbl, XML_RSC_ATTR_STICKINESS));

    g_hash_table_destroy(tbl);
}

static void
key_in_table(void **state)
{
    GHashTable *tbl = pcmk__strkey_table(free, free);

    g_hash_table_insert(tbl, crm_meta_name(XML_RSC_ATTR_NOTIFY), strdup("1"));
    g_hash_table_insert(tbl, crm_meta_name(XML_RSC_ATTR_STICKINESS), strdup("2"));

    assert_string_equal(crm_meta_value(tbl, XML_RSC_ATTR_NOTIFY), "1");
    assert_string_equal(crm_meta_value(tbl, XML_RSC_ATTR_STICKINESS), "2");

    g_hash_table_destroy(tbl);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_params),
                cmocka_unit_test(key_not_in_table),
                cmocka_unit_test(key_in_table))

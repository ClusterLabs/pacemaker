/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>   // GList, GHashTable, etc.

#include <crm/common/unittest_internal.h>

static GHashTable *
create_id_table(va_list args)
{
    GHashTable *table = NULL;

    for (const char *value = va_arg(args, const char *); value != NULL;
         value = va_arg(args, const char *)) {

        if (table == NULL) {
            table = pcmk__strkey_table(NULL, NULL);
        }
        g_hash_table_add(table, (gpointer) value);
    }

    return table;
}

/*!
 * \internal
 * \brief Test an invocation of pcmk__xe_dereference_children()
 *
 * \param[in] xml_string    XML to parse, with "test" child to pass to tested
 *                          function
 * \param[in] element_name  Element name to pass to tested function
 * \param[in] ...           NULL-terminated list of child "testattr" values to
 *                          expect in tested function's returned list
 */
static void
assert_deref(const char *xml_string, const char *element_name, ...)
{
    xmlNode *xml = NULL;
    GHashTable *table = NULL;
    GList *list = NULL;
    va_list ap;

    // Parse given XML
    if (xml_string != NULL) {
        xml = pcmk__xml_parse(xml_string);
        assert_non_null(xml);
    }

    // Create a hash table with all expected child IDs
    va_start(ap, element_name);
    table = create_id_table(ap);
    va_end(ap);

    // Call tested function on "test" child
    list = pcmk__xe_dereference_children(pcmk__xe_first_child(xml, "test",
                                                              NULL, NULL),
                                         element_name);

    // Ensure returned list has exactly the expected child IDs
    if (table == NULL) {
        assert_null(list);
    } else {
        while (list != NULL) {
            const char *value = pcmk__xe_get((xmlNode *) list->data,
                                             "testattr");

            assert_true(g_hash_table_remove(table, value));
            list = list->next;
        }
        assert_int_equal(g_hash_table_size(table), 0);
        g_hash_table_destroy(table);
    }

    g_list_free(list);
    pcmk__xml_free(xml);
}

static void
null_for_null(void **state)
{
    assert_deref(NULL, NULL, NULL);
    assert_deref(NULL, "test", NULL);
}

#define XML_NO_CHILDREN "<xml><test/></xml>"
#define XML_NO_ELEMENT_CHILDREN "<xml><test><!-- comment -->text</test></xml>"

static void
null_for_no_children(void **state)
{
    assert_deref(XML_NO_CHILDREN, NULL, NULL);
    assert_deref(XML_NO_CHILDREN, "test", NULL);
    assert_deref(XML_NO_ELEMENT_CHILDREN, NULL, NULL);
    assert_deref(XML_NO_ELEMENT_CHILDREN, "test", NULL);
}

#define XML_NO_IDREF                                        \
    "<xml>\n"                                               \
    "  <test>\n"                                            \
    "    <!-- comment -->\n"                                \
    "    <other id='other1' testattr='othervalue1' />\n"    \
    "    <child id='child1' testattr='childvalue1' />\n"    \
    "    <other id='other2' testattr='othervalue2' />\n"    \
    "    <child id='child2' testattr='childvalue2' />\n"    \
    "    <child id='child3' testattr='childvalue3' />\n"    \
    "    <other id='other3' testattr='othervalue3' />\n"    \
    "  </test>\n"                                           \
    "</xml>\n"

static void
without_idref(void **state)
{
    assert_deref(XML_NO_IDREF, NULL,
                 "othervalue1", "othervalue2", "othervalue3",
                 "childvalue1", "childvalue2", "childvalue3", NULL);

    assert_deref(XML_NO_IDREF, "other",
                 "othervalue1", "othervalue2", "othervalue3", NULL);

    assert_deref(XML_NO_IDREF, "child",
                 "childvalue1", "childvalue2", "childvalue3", NULL);

    assert_deref(XML_NO_IDREF, "nonexistent", NULL);
}

#define XML_WITH_IDREF                                      \
    "<xml>\n"                                               \
    "  <other id='other1' testattr='othervalue1' />\n"      \
    "  <child id='child2' testattr='childvalue2' />\n"      \
    "  <test>\n"                                            \
    "    <!-- comment -->\n"                                \
    "    <other id-ref='other1'/>\n"                        \
    "    <child id='child1' testattr='childvalue1' />\n"    \
    "    <other id='other2' testattr='othervalue2' />\n"    \
    "    <child id-ref='child2' />\n"                       \
    "    <child id='child3' testattr='childvalue3' />\n"    \
    "    <other id='other3' testattr='othervalue3' />\n"    \
    "  </test>\n"                                           \
    "</xml>\n"

static void
with_idref(void **state)
{
    assert_deref(XML_WITH_IDREF, NULL,
                 "othervalue1", "othervalue2", "othervalue3",
                 "childvalue1", "childvalue2", "childvalue3", NULL);

    assert_deref(XML_WITH_IDREF, "other",
                 "othervalue1", "othervalue2", "othervalue3", NULL);

    assert_deref(XML_WITH_IDREF, "child",
                 "childvalue1", "childvalue2", "childvalue3", NULL);

    assert_deref(XML_WITH_IDREF, "nonexistent", NULL);
}

#define XML_WITH_BROKEN_IDREF                               \
    "<xml>\n"                                               \
    "  <test>\n"                                            \
    "    <!-- comment -->\n"                                \
    "    <other id-ref='other1'/>\n"                        \
    "    <child id='child1' testattr='childvalue1' />\n"    \
    "    <other id='other2' testattr='othervalue2' />\n"    \
    "    <child id-ref='child2' />\n"                       \
    "    <child id='child3' testattr='childvalue3' />\n"    \
    "    <other id='other3' testattr='othervalue3' />\n"    \
    "  </test>\n"                                           \
    "</xml>\n"

static void
with_broken_idref(void **state)
{
    assert_deref(XML_WITH_BROKEN_IDREF, NULL,
                 "othervalue2", "othervalue3",
                 "childvalue1", "childvalue3", NULL);

    assert_deref(XML_WITH_BROKEN_IDREF, "other",
                 "othervalue2", "othervalue3", NULL);

    assert_deref(XML_WITH_BROKEN_IDREF, "child",
                 "childvalue1", "childvalue3", NULL);

    assert_deref(XML_WITH_BROKEN_IDREF, "nonexistent", NULL);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_for_null),
                cmocka_unit_test(null_for_no_children),
                cmocka_unit_test(without_idref),
                cmocka_unit_test(with_idref),
                cmocka_unit_test(with_broken_idref))

/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>   // GList, GHashTable, etc.

#include <crm/common/unittest_internal.h>

static void
assert_deref_one(const xmlNode *xml, const char *element_name,
                 GList *expected_ids)
{
    GList *resolved_nodes = pcmk__xe_dereference_children(xml, element_name);
    GList *resolved_ids = NULL;

    for (const GList *iter = resolved_nodes; iter != NULL; iter = iter->next) {
        const xmlNode *data = iter->data;
        const char *value = pcmk__xe_get(data, "testattr");

        resolved_ids = g_list_prepend(resolved_ids, (void *) value);
    }

    // Ensure returned list has exactly the expected child IDs
    resolved_ids = g_list_sort(resolved_ids, (GCompareFunc) g_strcmp0);

    assert_int_equal(g_list_length(expected_ids), g_list_length(resolved_ids));

    for (const GList *e_iter = expected_ids, *r_iter = resolved_ids;
         (e_iter != NULL) && (r_iter != NULL);
         e_iter = e_iter->next, r_iter = r_iter->next) {

        const char *e_value = e_iter->data;
        const char *r_value = r_iter->data;

        assert_string_equal(e_value, r_value);
    }

    g_list_free(resolved_nodes);
    g_list_free(resolved_ids);
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
    const xmlNode *child = NULL;
    GList *expected_ids = NULL;
    va_list ap;

    // Parse given XML
    if (xml_string != NULL) {
        xml = pcmk__xml_parse(xml_string);
        assert_non_null(xml);
    }

    // Create a list of all expected child IDs
    va_start(ap, element_name);
    for (const char *value = va_arg(ap, const char *);
         value != NULL; value = va_arg(ap, const char *)) {

        expected_ids = g_list_prepend(expected_ids, (void *) value);
    }
    va_end(ap);

    expected_ids = g_list_sort(expected_ids, (GCompareFunc) g_strcmp0);

    // Call tested function on "test" child
    child = pcmk__xe_first_child(xml, "test", NULL, NULL);

    assert_deref_one(child, element_name, expected_ids);

    g_list_free(expected_ids);
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

// There may be no valid use case for this, but it should work
#define XML_WITH_DUPLICATE_IDREF                            \
    "<xml>\n"                                               \
    "  <other id='other1' testattr='othervalue1' />\n"      \
    "  <child id='child2' testattr='childvalue2' />\n"      \
    "  <test>\n"                                            \
    "    <!-- comment -->\n"                                \
    "    <other id-ref='other1'/>\n"                        \
    "    <child id='child1' testattr='childvalue1' />\n"    \
    "    <other id-ref='other1'/>\n"                        \
    "    <other id='other2' testattr='othervalue2' />\n"    \
    "    <child id-ref='child2' />\n"                       \
    "    <child id='child3' testattr='childvalue3' />\n"    \
    "    <other id='other3' testattr='othervalue3' />\n"    \
    "  </test>\n"                                           \
    "</xml>\n"

static void
with_duplicate_idref(void **state)
{
    assert_deref(XML_WITH_DUPLICATE_IDREF, NULL,
                 "othervalue1", "othervalue1", "othervalue2", "othervalue3",
                 "childvalue1", "childvalue2", "childvalue3", NULL);

    assert_deref(XML_WITH_DUPLICATE_IDREF, "other",
                 "othervalue1", "othervalue1", "othervalue2", "othervalue3",
                 NULL);

    assert_deref(XML_WITH_DUPLICATE_IDREF, "child",
                 "childvalue1", "childvalue2", "childvalue3", NULL);

    assert_deref(XML_WITH_DUPLICATE_IDREF, "nonexistent", NULL);
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
                cmocka_unit_test(with_duplicate_idref),
                cmocka_unit_test(with_broken_idref))

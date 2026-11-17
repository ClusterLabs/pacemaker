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

/*!
 * \internal
 * \brief Test an invocation of pcmk__xe_resolve_idref()
 *
 * \param[in] xml           Element whose \c PCMK_XA_ID_REF attribute to check
 * \param[in] doc           Document to search for node with matching \c PCMK_XA_ID
 * \param[in] expected_xml  Expected element, where \c PCMK_XA_ID_REF is pointing
 */
static void
assert_id_deref(xmlNode *xml, xmlDoc* doc, xmlNode* expected_xml)
{
    xmlNode* result = pcmk__xe_resolve_idref(xml, doc);
    assert_ptr_equal(result, expected_xml);
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
recursive_deref(const char *xml_string)
{
    xmlNode *xml = NULL;
    xmlNode *parent = NULL;
    xmlNode *child = NULL;
    xmlDoc *doc = NULL;
    xmlNode *ref = NULL;

    // Parse given XML
    if (xml_string != NULL) {
        xml = pcmk__xml_parse(xml_string);
        assert_non_null(xml);
        doc = xml->doc;
    }

    // Call tested function on "test" child
    parent = pcmk__xe_first_child(xml, "test", NULL, NULL);
    child = pcmk__xe_first_child(parent, "rule", NULL, NULL);
    ref = pcmk__xe_first_child(child, "rule", NULL, NULL);

    assert_id_deref(ref, doc, NULL);

    pcmk__xml_free(parent);
    pcmk__xml_free(xml);
}

#define XML_RECURSIVE_REF                                   \
    "<xml>\n"                                               \
    "  <test>\n"                                            \
    "    <rule id='rule1'>\n"                               \
    "       <rule id-ref='rule1'/>\n"                       \
    "    </rule>\n"                                         \
    "  </test>\n"                                           \
    "</xml>\n"

static void
recursive_ref(void **state)
{
    recursive_deref(XML_RECURSIVE_REF);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(recursive_ref))
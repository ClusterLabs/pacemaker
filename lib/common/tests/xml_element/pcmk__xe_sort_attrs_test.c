/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>                           // GHashTable, etc.
#include <libxml/tree.h>                    // xmlNode
#include <libxml/xmlstring.h>               // xmlChar

#include "crmcommon_private.h"              // xml_node_private_t

/*!
 * \internal
 * \brief Add an attribute to a table mapping attribute names to XML flags
 *
 * \param[in]     attr       XML attribute
 * \param[in,out] user_data  Flags table (<tt>GHashTable *</tt>)
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_const_attr().
 */
static bool
add_attr_to_flags_table(const xmlAttr *attr, void *user_data)
{
    GHashTable *attr_flags = user_data;

    const xml_node_private_t *nodepriv = attr->_private;
    uint32_t flags = ((nodepriv != NULL)? nodepriv->flags : pcmk__xf_none);

    g_hash_table_insert(attr_flags, pcmk__str_copy((const char *) attr->name),
                        GUINT_TO_POINTER((guint) flags));
    return true;
}

/*!
 * \internal
 * \brief Sort an XML element's attributes and compare against a reference
 *
 * This also verifies that any flags set on the original attributes are
 * preserved.
 *
 * \param[in,out] test_xml       XML whose attributes to sort
 * \param[in]     reference_xml  XML whose attribute order to compare against
 *                               (attributes must have the same values as in
 *                               \p test_xml)
 */
static void
assert_order(xmlNode *test_xml, const xmlNode *reference_xml)
{
    GHashTable *attr_flags = pcmk__strkey_table(free, NULL);
    const xmlAttr *test_attr = NULL;
    const xmlAttr *ref_attr = NULL;

    // Save original flags
    pcmk__xe_foreach_const_attr(test_xml, add_attr_to_flags_table, attr_flags);

    pcmk__xe_sort_attrs(test_xml);

    test_attr = pcmk__xe_first_attr(test_xml);
    ref_attr = pcmk__xe_first_attr(reference_xml);

    for (; (test_attr != NULL) && (ref_attr != NULL);
         test_attr = test_attr->next, ref_attr = ref_attr->next) {

        const char *test_name = (const char *) test_attr->name;
        xml_node_private_t *nodepriv = test_attr->_private;
        uint32_t flags = (nodepriv != NULL)? nodepriv->flags : pcmk__xf_none;

        gpointer old_flags_ptr = g_hash_table_lookup(attr_flags, test_name);
        uint32_t old_flags = pcmk__xf_none;

        if (old_flags_ptr != NULL) {
            old_flags = GPOINTER_TO_UINT(old_flags_ptr);
        }

        // Flags must not change
        assert_true(flags == old_flags);

        // Attributes must be in expected order with expected values
        assert_string_equal(test_name, (const char *) ref_attr->name);
        assert_string_equal(pcmk__xml_attr_value(test_attr),
                            pcmk__xml_attr_value(ref_attr));
    }

    // Attribute lists must be the same length
    assert_null(test_attr);
    assert_null(ref_attr);

    g_hash_table_destroy(attr_flags);
}

static void
null_arg(void **state)
{
    // Ensure it doesn't crash
    pcmk__xe_sort_attrs(NULL);
}

static void
nothing_to_sort(void **state)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");
    xmlNode *reference_xml = NULL;

    // No attributes
    reference_xml = pcmk__xml_copy(NULL, test_xml);
    assert_order(test_xml, reference_xml);
    pcmk__xml_free(reference_xml);

    // Only one attribute
    pcmk__xe_set(test_xml, "name", "value");
    reference_xml = pcmk__xml_copy(NULL, test_xml);
    assert_order(test_xml, reference_xml);
    pcmk__xml_free(reference_xml);

    pcmk__xml_free(test_xml);
}

static void
already_sorted(void **state)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");
    xmlNode *reference_xml = pcmk__xe_create(NULL, "test");

    xmlAttr *attr = NULL;

    pcmk__xe_set(test_xml, "admin", "john");
    pcmk__xe_set(test_xml, "dummy", "value");
    pcmk__xe_set(test_xml, "location", "usa");

    // Set flags in test_xml's attributes for testing flag preservation
    attr = xmlHasProp(test_xml, (const xmlChar *) "admin");
    if (attr != NULL) {
        xml_node_private_t *nodepriv = attr->_private;

        if (nodepriv != NULL) {
            pcmk__clear_xml_flags(nodepriv, pcmk__xf_created|pcmk__xf_dirty);
        }
    }

    attr = xmlHasProp(test_xml, (const xmlChar *) "location");
    if (attr != NULL) {
        xml_node_private_t *nodepriv = attr->_private;

        if (nodepriv != NULL) {
            pcmk__set_xml_flags(nodepriv, pcmk__xf_ignore_attr_pos);
        }
    }

    pcmk__xe_set(reference_xml, "admin", "john");
    pcmk__xe_set(reference_xml, "dummy", "value");
    pcmk__xe_set(reference_xml, "location", "usa");

    assert_order(test_xml, reference_xml);

    pcmk__xml_free(test_xml);
    pcmk__xml_free(reference_xml);
}

static void
need_sort(void **state)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test");
    xmlNode *reference_xml = pcmk__xe_create(NULL, "test");

    xmlAttr *attr = NULL;

    pcmk__xe_set(test_xml, "location", "usa");
    pcmk__xe_set(test_xml, "admin", "john");
    pcmk__xe_set(test_xml, "dummy", "value");

    // Set flags in test_xml's attributes for testing flag preservation
    attr = xmlHasProp(test_xml, (const xmlChar *) "location");
    if (attr != NULL) {
        xml_node_private_t *nodepriv = attr->_private;

        if (nodepriv != NULL) {
            pcmk__set_xml_flags(nodepriv, pcmk__xf_ignore_attr_pos);
        }
    }

    attr = xmlHasProp(test_xml, (const xmlChar *) "admin");
    if (attr != NULL) {
        xml_node_private_t *nodepriv = attr->_private;

        if (nodepriv != NULL) {
            pcmk__clear_xml_flags(nodepriv, pcmk__xf_created|pcmk__xf_dirty);
        }
    }

    pcmk__xe_set(reference_xml, "admin", "john");
    pcmk__xe_set(reference_xml, "dummy", "value");
    pcmk__xe_set(reference_xml, "location", "usa");

    assert_order(test_xml, reference_xml);

    pcmk__xml_free(test_xml);
    pcmk__xml_free(reference_xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_arg),
                cmocka_unit_test(nothing_to_sort),
                cmocka_unit_test(already_sorted),
                cmocka_unit_test(need_sort))

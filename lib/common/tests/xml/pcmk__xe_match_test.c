/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

const char *str1 =
    "<xml>\n"
    "  <!-- This is an A node -->\n"
    "  <nodeA attrA=\"123\" " XML_ATTR_ID "=\"1\">\n"
    "    content\n"
    "  </nodeA>\n"
    "  <!-- This is an A node -->\n"
    "  <nodeA attrA=\"456\" " XML_ATTR_ID "=\"2\">\n"
    "    content\n"
    "  </nodeA>\n"
    "  <!-- This is an A node -->\n"
    "  <nodeA attrB=\"XYZ\" " XML_ATTR_ID "=\"3\">\n"
    "    content\n"
    "  </nodeA>\n"
    "  <!-- This is a B node -->\n"
    "  <nodeB attrA=\"123\" " XML_ATTR_ID "=\"4\">\n"
    "    content\n"
    "  </nodeA>\n"
    "  <!-- This is a B node -->\n"
    "  <nodeB attrB=\"ABC\" " XML_ATTR_ID "=\"5\">\n"
    "    content\n"
    "  </nodeA>\n"
    "</xml>";

static void
bad_input(void **state) {
    xmlNode *xml = string2xml(str1);

    assert_null(pcmk__xe_match(NULL, NULL, NULL, NULL));
    assert_null(pcmk__xe_match(NULL, NULL, NULL, "attrX"));

    free_xml(xml);
}

static void
not_found(void **state) {
    xmlNode *xml = string2xml(str1);

    /* No node with an attrX attribute */
    assert_null(pcmk__xe_match(xml, NULL, "attrX", NULL));
    /* No nodeX node */
    assert_null(pcmk__xe_match(xml, "nodeX", NULL, NULL));
    /* No nodeA node with attrX */
    assert_null(pcmk__xe_match(xml, "nodeA", "attrX", NULL));
    /* No nodeA node with attrA=XYZ */
    assert_null(pcmk__xe_match(xml, "nodeA", "attrA", "XYZ"));

    free_xml(xml);
}

static void
find_attrB(void **state) {
    xmlNode *xml = string2xml(str1);
    xmlNode *result = NULL;

    /* Find the first node with attrB */
    result = pcmk__xe_match(xml, NULL, "attrB", NULL);
    assert_non_null(result);
    assert_string_equal(crm_element_value(result, "id"), "3");

    /* Find the first nodeB with attrB */
    result = pcmk__xe_match(xml, "nodeB", "attrB", NULL);
    assert_non_null(result);
    assert_string_equal(crm_element_value(result, "id"), "5");

    free_xml(xml);
}

static void
find_attrA_matching(void **state) {
    xmlNode *xml = string2xml(str1);
    xmlNode *result = NULL;

    /* Find attrA=456 */
    result = pcmk__xe_match(xml, NULL, "attrA", "456");
    assert_non_null(result);
    assert_string_equal(crm_element_value(result, "id"), "2");

    /* Find a nodeB with attrA=123 */
    result = pcmk__xe_match(xml, "nodeB", "attrA", "123");
    assert_non_null(result);
    assert_string_equal(crm_element_value(result, "id"), "4");

    free_xml(xml);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(not_found),
                cmocka_unit_test(find_attrB),
                cmocka_unit_test(find_attrA_matching));

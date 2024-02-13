/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static void
bad_input(void **state) {
    xmlNode *node = NULL;

    pcmk__assert_asserts(pcmk__xe_add_node(NULL, NULL, 0));

    node = pcmk__xe_create(NULL, "test");

    pcmk__xe_add_node(node, NULL, 0);
    assert_null(xmlHasProp(node, (pcmkXmlStr) PCMK__XA_ATTR_HOST));
    assert_null(xmlHasProp(node, (pcmkXmlStr) PCMK__XA_ATTR_HOST_ID));

    pcmk__xe_add_node(node, NULL, -100);
    assert_null(xmlHasProp(node, (pcmkXmlStr) PCMK__XA_ATTR_HOST));
    assert_null(xmlHasProp(node, (pcmkXmlStr) PCMK__XA_ATTR_HOST_ID));

    pcmk__xml_free(node);
}

static void
expected_input(void **state) {
    xmlNode *node = pcmk__xe_create(NULL, "test");
    int i;

    pcmk__xe_add_node(node, "somenode", 47);
    assert_string_equal("somenode",
                        crm_element_value(node, PCMK__XA_ATTR_HOST));
    assert_int_equal(pcmk_rc_ok,
                     crm_element_value_int(node, PCMK__XA_ATTR_HOST_ID, &i));
    assert_int_equal(i, 47);

    pcmk__xml_free(node);
}

static void
repeated_use(void **state) {
    xmlNode *node = pcmk__xe_create(NULL, "test");
    int i;

    /* Later calls override settings from earlier calls. */
    pcmk__xe_add_node(node, "nodeA", 1);
    pcmk__xe_add_node(node, "nodeB", 2);
    pcmk__xe_add_node(node, "nodeC", 3);

    assert_string_equal("nodeC", crm_element_value(node, PCMK__XA_ATTR_HOST));
    assert_int_equal(pcmk_rc_ok,
                     crm_element_value_int(node, PCMK__XA_ATTR_HOST_ID, &i));
    assert_int_equal(i, 3);

    pcmk__xml_free(node);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(expected_input),
                cmocka_unit_test(repeated_use))

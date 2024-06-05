/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/cib/internal.h>
#include <crm/common/unittest_internal.h>
#include <crm/common/xml.h>
#include <pacemaker.h>

static char *cib_path = NULL;

static int
setup_test(void **state)
{
    cib_path = pcmk__cib_test_copy_cib("tickets.xml");

    if (cib_path == NULL) {
        return -1;
    }

    return 0;
}

static int
teardown_test(void **state)
{
    pcmk__cib_test_cleanup(cib_path);
    cib_path = NULL;
    return 0;
}

static void
bad_arguments(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_get_attr(NULL, "ticketA", "XYZ", NULL), EINVAL);

    assert_int_equal(pcmk_ticket_get_attr(&xml, NULL, "attrA", NULL), EINVAL);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
    xml = NULL;

    assert_int_equal(pcmk_ticket_get_attr(&xml, "ticketA", NULL, NULL), EINVAL);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static void
unknown_ticket(void **state)
{
    xmlNode *xml = NULL;

    /* Both an unknown ticket and an unknown attribute on a known ticket
     * return ENXIO so we can't really differentiate between the two here.
     * Still, we'd better test both.
     */
    assert_int_equal(pcmk_ticket_get_attr(&xml, "XYZ", "attrA", NULL), ENXIO);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
    xml = NULL;

    assert_int_equal(pcmk_ticket_get_attr(&xml, "ticketA", "XYZ", NULL), ENXIO);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static void
verify_results(xmlNode *xml, const char *ticket_id, const char *attr_name,
               const char *attr_value)
{
    xmlNode *node = NULL;
    xmlXPathObject *xpath_obj = NULL;

    /* Verify that the XML result has only one <ticket>, and that its ID is
     * what we asked for.
     */
    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS "/" PCMK_XE_TICKET);
    assert_int_equal(numXpathResults(xpath_obj), 1);

    node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(node, PCMK_XA_ID), ticket_id);
    freeXpathObject(xpath_obj);

    /* Verify that it has an <attribute> child whose name and value are what
     * we expect.
     */
    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS "/" PCMK_XE_TICKET
                                  "/" PCMK_XE_ATTRIBUTE);
    assert_int_equal(numXpathResults(xpath_obj), 1);

    node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(node, PCMK_XA_NAME), attr_name);
    assert_string_equal(crm_element_value(node, PCMK_XA_VALUE), attr_value);

    freeXpathObject(xpath_obj);
}

static void
attribute_exists(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_get_attr(&xml, "ticketA", "owner", NULL), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    verify_results(xml, "ticketA", "owner", "1");

    pcmk__xml_free(xml);
}

static void
default_no_ticket(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_get_attr(&xml, "ticketX", "ABC", "DEFAULT"), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    verify_results(xml, "ticketX", "ABC", "DEFAULT");

    pcmk__xml_free(xml);
}

static void
default_no_attribute(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_get_attr(&xml, "ticketA", "ABC", "DEFAULT"), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    verify_results(xml, "ticketA", "ABC", "DEFAULT");

    pcmk__xml_free(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test_setup_teardown(bad_arguments, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(attribute_exists, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(default_no_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(default_no_attribute, setup_test, teardown_test))

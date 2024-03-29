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
    assert_int_equal(pcmk_ticket_info(NULL, "ticketA"), EINVAL);
}

static void
unknown_ticket(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_info(&xml, "XYZ"), ENXIO);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static void
all_tickets(void **state)
{
    xmlNode *node = NULL;
    xmlXPathObject *xpath_obj = NULL;
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_info(&xml, NULL), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify that the XML result has three <ticket> elements, with the attributes
     * we expect.  The input has four tickets, but when they are loaded into the
     * scheduler's hash table, the duplicate IDs will collide leaving us with
     * three.
     */
    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS "/" PCMK_XE_TICKET);
    assert_int_equal(numXpathResults(xpath_obj), 3);
    freeXpathObject(xpath_obj);

    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS
                                  "/" PCMK_XE_TICKET "[@" PCMK_XA_ID "=\"ticketA\"]");

    node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(node, PCMK_XA_STATUS), PCMK_VALUE_REVOKED);
    assert_string_equal(crm_element_value(node, PCMK__XA_GRANTED), "false");
    assert_string_equal(crm_element_value(node, PCMK_XA_STANDBY), PCMK_VALUE_FALSE);
    assert_string_equal(crm_element_value(node, "owner"), "1");
    freeXpathObject(xpath_obj);

    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS
                                  "/" PCMK_XE_TICKET "[@" PCMK_XA_ID "=\"ticketB\"]");

    node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(node, PCMK_XA_STATUS), PCMK_VALUE_GRANTED);
    assert_string_equal(crm_element_value(node, PCMK__XA_GRANTED), "true");
    assert_string_equal(crm_element_value(node, PCMK_XA_STANDBY), PCMK_VALUE_FALSE);
    assert_null(crm_element_value(node, "owner"));
    freeXpathObject(xpath_obj);

    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS
                                  "/" PCMK_XE_TICKET "[@" PCMK_XA_ID "=\"ticketC\"]");

    node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(node, PCMK_XA_STATUS), PCMK_VALUE_GRANTED);
    assert_string_equal(crm_element_value(node, PCMK__XA_GRANTED), "true");
    assert_string_equal(crm_element_value(node, PCMK_XA_STANDBY), PCMK_VALUE_FALSE);
    assert_null(crm_element_value(node, "owner"));

    freeXpathObject(xpath_obj);
    pcmk__xml_free(xml);
}

static void
single_ticket(void **state)
{
    xmlNode *node = NULL;
    xmlXPathObject *xpath_obj = NULL;
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_info(&xml, "ticketA"), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify that the XML result has only one <ticket>, with the attributes
     * we expect.
     */
    xpath_obj = xpath_search(xml, "//" PCMK_XE_PACEMAKER_RESULT "/" PCMK_XE_TICKETS
                                  "/" PCMK_XE_TICKET "[@" PCMK_XA_ID "=\"ticketA\"]");
    assert_int_equal(numXpathResults(xpath_obj), 1);

    node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(node, PCMK_XA_STATUS), PCMK_VALUE_REVOKED);
    assert_string_equal(crm_element_value(node, PCMK__XA_GRANTED), "false");
    assert_string_equal(crm_element_value(node, PCMK_XA_STANDBY), PCMK_VALUE_FALSE);
    assert_string_equal(crm_element_value(node, "owner"), "1");

    freeXpathObject(xpath_obj);
    pcmk__xml_free(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test_setup_teardown(bad_arguments, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(all_tickets, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(single_ticket, setup_test, teardown_test))

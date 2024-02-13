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

#include <pacemaker-internal.h>

static char *cib_path = NULL;

static void
cib_not_connected(void **state)
{
    xmlNode *xml = NULL;
    cib_t *cib = cib_new();

    /* Without any special setup, cib_new() here will use the native CIB which
     * means IPC calls.  But there's nothing listening for those calls, so
     * signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk__get_ticket_state(cib, "ticketA", &xml), ENOTCONN);
    cib__clean_up_connection(&cib);
}

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
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    pcmk__assert_asserts(pcmk__get_ticket_state(NULL, "ticketA", &xml));
    pcmk__assert_asserts(pcmk__get_ticket_state(cib, "ticketA", NULL));

    cib__clean_up_connection(&cib);
}

static void
unknown_ticket(void **state)
{
    xmlNode *xml = NULL;
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    assert_int_equal(pcmk__get_ticket_state(cib, "XYZ", &xml), ENXIO);

    pcmk__xml_free(xml);
    cib__clean_up_connection(&cib);
}

static void
ticket_exists(void **state)
{
    xmlNode *xml = NULL;
    xmlXPathObject *xpath_obj = NULL;
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    assert_int_equal(pcmk__get_ticket_state(cib, "ticketA", &xml), pcmk_rc_ok);

    /* Verify that the XML result has only one <ticket>, and that its ID is
     * what we asked for.
     */
    xpath_obj = xpath_search(xml, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]");
    assert_int_equal(numXpathResults(xpath_obj), 1);

    freeXpathObject(xpath_obj);
    pcmk__xml_free(xml);
    cib__clean_up_connection(&cib);
}

static void
multiple_tickets(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *ticket_node = NULL;
    xmlXPathObject *xpath_obj = NULL;
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    assert_int_equal(pcmk__get_ticket_state(cib, NULL, &xml), pcmk_rc_ok);

    /* Verify that the XML result has four <ticket> elements, and that their
     * IDs are as expected.
     */
    xpath_obj = xpath_search(xml, "//" PCMK__XE_TICKET_STATE);

    assert_int_equal(numXpathResults(xpath_obj), 4);

    ticket_node = getXpathResult(xpath_obj, 0);
    assert_string_equal(crm_element_value(ticket_node, PCMK_XA_ID), "ticketA");

    ticket_node = getXpathResult(xpath_obj, 1);
    assert_string_equal(crm_element_value(ticket_node, PCMK_XA_ID), "ticketB");

    ticket_node = getXpathResult(xpath_obj, 2);
    assert_string_equal(crm_element_value(ticket_node, PCMK_XA_ID), "ticketC");

    ticket_node = getXpathResult(xpath_obj, 3);
    assert_string_equal(crm_element_value(ticket_node, PCMK_XA_ID), "ticketC");

    freeXpathObject(xpath_obj);
    pcmk__xml_free(xml);
    cib__clean_up_connection(&cib);
}

static void
duplicate_tickets(void **state)
{
    xmlNode *xml = NULL;
    xmlXPathObject *xpath_obj = NULL;
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    assert_int_equal(pcmk__get_ticket_state(cib, "ticketC", &xml), pcmk_rc_duplicate_id);

    /* Verify that the XML result has two <ticket> elements, and that their
     * IDs are as expected.
     */
    xpath_obj = xpath_search(xml, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketC\"]");

    assert_int_equal(numXpathResults(xpath_obj), 2);
    freeXpathObject(xpath_obj);
    pcmk__xml_free(xml);
    cib__clean_up_connection(&cib);
}

/* There are two kinds of tests in this file:
 *
 * (1) Those that test what happens if the CIB is not set up correctly, and
 * (2) Those that test what happens when run against a CIB.
 *
 * Therefore, we need two kinds of setup/teardown functions.  We only do
 * minimal overall setup for the entire group, and then setup the CIB for
 * those tests that need it.
 */
PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test_setup_teardown(cib_not_connected, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(bad_arguments, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(ticket_exists, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(multiple_tickets, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(duplicate_tickets, setup_test, teardown_test))

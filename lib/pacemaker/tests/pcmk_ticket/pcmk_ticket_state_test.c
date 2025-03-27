/*
 * Copyright 2024-2025 the Pacemaker project contributors
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

#include <libxml/xpath.h>                   // xmlXPathObject, etc.

static char *cib_path = NULL;

static void
cib_not_connected(void **state)
{
    xmlNode *xml = NULL;

    /* Without any special setup, cib_new() in pcmk_ticket_state will use the
     * native CIB which means IPC calls.  But there's nothing listening for those
     * calls, so signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk_ticket_state(&xml, "ticketA"), ENOTCONN);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
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
    assert_int_equal(pcmk_ticket_state(NULL, "ticketA"), EINVAL);
}

static void
unknown_ticket(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_state(&xml, "XYZ"), ENXIO);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static void
ticket_exists(void **state)
{
    xmlNode *xml = NULL;
    xmlXPathObject *xpath_obj = NULL;

    assert_int_equal(pcmk_ticket_state(&xml, "ticketA"), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify that the XML result has only one <ticket>, and that its ID is
     * what we asked for.
     */
    xpath_obj = pcmk__xpath_search(xml->doc,
                                   "//" PCMK_XE_PACEMAKER_RESULT
                                   "/" PCMK_XE_TICKETS "/" PCMK_XE_TICKET
                                   "[@" PCMK_XA_ID "=\"ticketA\"]");

    assert_int_equal(pcmk__xpath_num_results(xpath_obj), 1);
    xmlXPathFreeObject(xpath_obj);
    pcmk__xml_free(xml);
}

static void
multiple_tickets(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *ticket_node = NULL;
    xmlXPathObject *xpath_obj = NULL;

    assert_int_equal(pcmk_ticket_state(&xml, NULL), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify that the XML result has four <ticket> elements, and that their
     * IDs are as expected.
     */
    xpath_obj = pcmk__xpath_search(xml->doc,
                                   "//" PCMK_XE_PACEMAKER_RESULT
                                   "/" PCMK_XE_TICKETS "/" PCMK_XE_TICKET);

    assert_int_equal(pcmk__xpath_num_results(xpath_obj), 4);

    ticket_node = pcmk__xpath_result(xpath_obj, 0);
    assert_non_null(ticket_node);
    assert_string_equal(pcmk__xe_get(ticket_node, PCMK_XA_ID), "ticketA");

    ticket_node = pcmk__xpath_result(xpath_obj, 1);
    assert_non_null(ticket_node);
    assert_string_equal(pcmk__xe_get(ticket_node, PCMK_XA_ID), "ticketB");

    ticket_node = pcmk__xpath_result(xpath_obj, 2);
    assert_non_null(ticket_node);
    assert_string_equal(pcmk__xe_get(ticket_node, PCMK_XA_ID), "ticketC");

    ticket_node = pcmk__xpath_result(xpath_obj, 3);
    assert_non_null(ticket_node);
    assert_string_equal(pcmk__xe_get(ticket_node, PCMK_XA_ID), "ticketC");

    xmlXPathFreeObject(xpath_obj);
    pcmk__xml_free(xml);
}

static void
duplicate_tickets(void **state)
{
    xmlNode *xml = NULL;
    xmlXPathObject *xpath_obj = NULL;

    assert_int_equal(pcmk_ticket_state(&xml, "ticketC"), pcmk_rc_duplicate_id);

    /* Verify that the XML result has two <ticket> elements, and that their
     * IDs are as expected.
     */
    xpath_obj = pcmk__xpath_search(xml->doc,
                                   "//" PCMK_XE_PACEMAKER_RESULT
                                   "/" PCMK_XE_TICKETS "/" PCMK_XE_TICKET
                                   "[@" PCMK_XA_ID "=\"ticketC\"]");

    assert_int_equal(pcmk__xpath_num_results(xpath_obj), 2);
    xmlXPathFreeObject(xpath_obj);
    pcmk__xml_free(xml);
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
PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(cib_not_connected),
                cmocka_unit_test_setup_teardown(bad_arguments, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(ticket_exists, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(multiple_tickets, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(duplicate_tickets, setup_test, teardown_test))

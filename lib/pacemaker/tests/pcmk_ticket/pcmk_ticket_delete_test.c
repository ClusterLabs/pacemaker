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

static void
cib_not_connected(void **state)
{
    xmlNode *xml = NULL;

    /* Without any special setup, cib_new() in pcmk_ticket_delete will use the
     * native CIB which means IPC calls.  But there's nothing listening for those
     * calls, so signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk_ticket_delete(&xml, "ticketA", false), ENOTCONN);
    pcmk__assert_validates(xml);
    free_xml(xml);
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

    assert_int_equal(pcmk_ticket_delete(NULL, "ticketA", false), EINVAL);

    assert_int_equal(pcmk_ticket_delete(&xml, NULL, false), EINVAL);
    pcmk__assert_validates(xml);
    free_xml(xml);
}

static void
unknown_ticket(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_delete(&xml, "XYZ", false), ENXIO);
    pcmk__assert_validates(xml);
    free_xml(xml);
    xml = NULL;

    assert_int_equal(pcmk_ticket_delete(&xml, "XYZ", true), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);
}

static void
ticket_granted(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_delete(&xml, "ticketB", false), EACCES);
    pcmk__assert_validates(xml);
    free_xml(xml);
}

static void
ticket_exists(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    assert_int_equal(pcmk_ticket_delete(&xml, "ticketA", false), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify there's no <ticket_state id="ticketA"> */
    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_null(xml_search);

    free_xml(xml);
    cib__clean_up_connection(&cib);
}

static void
force_delete_ticket(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    assert_int_equal(pcmk_ticket_delete(&xml, "ticketB", true), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify there's no <ticket_state id="ticketB"> */
    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketB\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_null(xml_search);

    free_xml(xml);
    cib__clean_up_connection(&cib);
}

static void
duplicate_tickets(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    assert_int_equal(pcmk_ticket_delete(&xml, "ticketC", true), pcmk_rc_ok);
    pcmk__assert_validates(xml);

    /* Verify there's no <ticket_state id="ticketC"> */
    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketC\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_null(xml_search);

    free_xml(xml);
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
PCMK__UNIT_TEST(pcmk__cib_test_setup_group, NULL,
                cmocka_unit_test(cib_not_connected),
                cmocka_unit_test_setup_teardown(bad_arguments, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(ticket_granted, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(ticket_exists, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(force_delete_ticket, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(duplicate_tickets, setup_test, teardown_test))

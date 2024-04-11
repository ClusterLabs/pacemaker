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

    /* Without any special setup, cib_new() in pcmk_ticket_remove_attr will use the
     * native CIB which means IPC calls.  But there's nothing listening for those
     * calls, so signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk_ticket_remove_attr(&xml, NULL, NULL, false), ENOTCONN);
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

    assert_int_equal(pcmk_ticket_remove_attr(NULL, "ticketA", NULL, false), EINVAL);

    assert_int_equal(pcmk_ticket_remove_attr(&xml, NULL, NULL, false), EINVAL);
    pcmk__assert_validates(xml);
    free_xml(xml);
}

static void
no_attrs(void **state)
{
    GList *attrs = NULL;
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    /* Deleting no attributes on a ticket that doesn't exist is a no-op */
    assert_int_equal(pcmk_ticket_remove_attr(&xml, "XYZ", NULL, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);
    xml = NULL;

    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"XYZ\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_null(xml_search);

    /* Deleting no attributes on a ticket that exists is also a no-op */
    assert_int_equal(pcmk_ticket_remove_attr(&xml, "ticketA", NULL, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);
    xml = NULL;

    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_string_equal("1", crm_element_value(xml_search, "owner"));
    free_xml(xml_search);

    /* Another way of specifying no attributes */
    assert_int_equal(pcmk_ticket_remove_attr(&xml, "XYZ", attrs, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);

    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"XYZ\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_null(xml_search);

    g_list_free(attrs);
    cib__clean_up_connection(&cib);
}

static void
remove_missing_attrs(void **state)
{
    GList *attrs = NULL;
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    attrs = g_list_append(attrs, strdup("XYZ"));

    /* Deleting an attribute that doesn't exist is a no-op */
    assert_int_equal(pcmk_ticket_remove_attr(&xml, "ticketA", attrs, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("1", crm_element_value(xml_search, "owner"));
    assert_null(crm_element_value(xml_search, "XYZ"));

    free_xml(xml_search);
    g_list_free_full(attrs, free);
    cib__clean_up_connection(&cib);
}

static void
remove_existing_attr(void **state)
{
    GList *attrs = NULL;
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    attrs = g_list_append(attrs, strdup("owner"));

    assert_int_equal(pcmk_ticket_remove_attr(&xml, "ticketA", attrs, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_null(crm_element_value(xml_search, "owner"));

    free_xml(xml_search);
    g_list_free_full(attrs, free);
    cib__clean_up_connection(&cib);
}

static void
remove_granted_without_force(void **state)
{
    GList *attrs = NULL;
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    attrs = g_list_append(attrs, strdup(PCMK__XA_GRANTED));

    assert_int_equal(pcmk_ticket_remove_attr(&xml, "ticketB", attrs, false), EACCES);
    pcmk__assert_validates(xml);
    free_xml(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketB\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("true", crm_element_value(xml_search, PCMK__XA_GRANTED));

    free_xml(xml_search);
    g_list_free_full(attrs, free);
    cib__clean_up_connection(&cib);
}

static void
remove_granted_with_force(void **state)
{
    GList *attrs = NULL;
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    attrs = g_list_append(attrs, strdup(PCMK__XA_GRANTED));

    assert_int_equal(pcmk_ticket_remove_attr(&xml, "ticketB", attrs, true), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    free_xml(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketB\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_null(crm_element_value(xml_search, PCMK__XA_GRANTED));

    free_xml(xml_search);
    g_list_free_full(attrs, free);
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
                cmocka_unit_test_setup_teardown(no_attrs, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(remove_missing_attrs, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(remove_existing_attr, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(remove_granted_without_force, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(remove_granted_with_force, setup_test, teardown_test))

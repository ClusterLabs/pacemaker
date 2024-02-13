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

    /* Without any special setup, cib_new() in pcmk_ticket_set_attr will use the
     * native CIB which means IPC calls.  But there's nothing listening for those
     * calls, so signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk_ticket_set_attr(&xml, NULL, NULL, false), ENOTCONN);
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
    xmlNode *xml = NULL;

    assert_int_equal(pcmk_ticket_set_attr(NULL, "ticketA", NULL, false), EINVAL);

    assert_int_equal(pcmk_ticket_set_attr(&xml, NULL, NULL, false), EINVAL);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static void
unknown_ticket_no_attrs(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib = cib_new();

    cib->cmds->signon(cib, crm_system_name, cib_command);

    /* Setting no attributes on a ticket that doesn't exist is a no-op */
    assert_int_equal(pcmk_ticket_set_attr(&xml, "XYZ", NULL, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
    xml = NULL;

    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"XYZ\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_null(xml_search);

    /* Another way of specifying no attributes */
    assert_int_equal(pcmk_ticket_set_attr(&xml, "XYZ", attrs, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"XYZ\"]",
                     &xml_search, cib_xpath | cib_scope_local);
    assert_null(xml_search);

    g_hash_table_destroy(attrs);
    cib__clean_up_connection(&cib);
}

static void
unknown_ticket_with_attrs(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    pcmk__insert_dup(attrs, "attrA", "123");
    pcmk__insert_dup(attrs, "attrB", "456");

    /* Setting attributes on a ticket that doesn't exist causes the ticket to
     * be created with the given attributes
     */
    assert_int_equal(pcmk_ticket_set_attr(&xml, "XYZ", attrs, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"XYZ\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("123", crm_element_value(xml_search, "attrA"));
    assert_string_equal("456", crm_element_value(xml_search, "attrB"));

    pcmk__xml_free(xml_search);
    g_hash_table_destroy(attrs);
    cib__clean_up_connection(&cib);
}

static void
overwrite_existing_attr(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    pcmk__insert_dup(attrs, "owner", "2");

    assert_int_equal(pcmk_ticket_set_attr(&xml, "ticketA", attrs, false), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("2", crm_element_value(xml_search, "owner"));

    pcmk__xml_free(xml_search);
    g_hash_table_destroy(attrs);
    cib__clean_up_connection(&cib);
}

static void
not_granted_to_granted_without_force(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    pcmk__insert_dup(attrs, PCMK__XA_GRANTED, "true");

    assert_int_equal(pcmk_ticket_set_attr(&xml, "ticketA", attrs, false), EACCES);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("false", crm_element_value(xml_search, PCMK__XA_GRANTED));
    assert_null(crm_element_value(xml_search, PCMK_XA_LAST_GRANTED));

    pcmk__xml_free(xml_search);
    g_hash_table_destroy(attrs);
    cib__clean_up_connection(&cib);
}

static void
not_granted_to_granted_with_force(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    pcmk__insert_dup(attrs, PCMK__XA_GRANTED, "true");

    assert_int_equal(pcmk_ticket_set_attr(&xml, "ticketA", attrs, true), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketA\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("true", crm_element_value(xml_search, PCMK__XA_GRANTED));
    assert_non_null(crm_element_value(xml_search, PCMK_XA_LAST_GRANTED));

    pcmk__xml_free(xml_search);
    g_hash_table_destroy(attrs);
    cib__clean_up_connection(&cib);
}

static void
granted_to_not_granted_without_force(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    pcmk__insert_dup(attrs, PCMK__XA_GRANTED, "false");

    assert_int_equal(pcmk_ticket_set_attr(&xml, "ticketB", attrs, false), EACCES);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketB\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("true", crm_element_value(xml_search, PCMK__XA_GRANTED));
    assert_null(crm_element_value(xml_search, PCMK_XA_LAST_GRANTED));

    pcmk__xml_free(xml_search);
    g_hash_table_destroy(attrs);
    cib__clean_up_connection(&cib);
}

static void
granted_to_not_granted_with_force(void **state)
{
    GHashTable *attrs = pcmk__strkey_table(free, free);
    xmlNode *xml = NULL;
    xmlNode *xml_search = NULL;
    cib_t *cib;

    pcmk__insert_dup(attrs, PCMK__XA_GRANTED, "false");

    assert_int_equal(pcmk_ticket_set_attr(&xml, "ticketB", attrs, true), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);
    cib->cmds->query(cib, "//" PCMK__XE_TICKET_STATE "[@" PCMK_XA_ID "=\"ticketB\"]",
                     &xml_search, cib_xpath | cib_scope_local);

    assert_string_equal("false", crm_element_value(xml_search, PCMK__XA_GRANTED));
    assert_null(crm_element_value(xml_search, PCMK_XA_LAST_GRANTED));

    pcmk__xml_free(xml_search);
    g_hash_table_destroy(attrs);
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
                cmocka_unit_test(cib_not_connected),
                cmocka_unit_test_setup_teardown(bad_arguments, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket_no_attrs, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_ticket_with_attrs, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(overwrite_existing_attr, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(not_granted_to_granted_without_force, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(not_granted_to_granted_with_force, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(granted_to_not_granted_without_force, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(granted_to_not_granted_with_force, setup_test, teardown_test))

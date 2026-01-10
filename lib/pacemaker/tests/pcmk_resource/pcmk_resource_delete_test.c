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

static char *cib_path = NULL;

static void
cib_not_connected(void **state)
{
    xmlNode *xml = NULL;

    /* Without any special setup, cib_new() in pcmk_resource_delete will use the
     * native CIB which means IPC calls.  But there's nothing listening for those
     * calls, so signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk_resource_delete(&xml, "rsc", "primitive"), ENOTCONN);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static int
setup_test(void **state)
{
    cib_path = pcmk__cib_test_copy_cib("crm_mon.xml");

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
bad_input(void **state)
{
    xmlNode *xml = NULL;

    /* There is a primitive resource named "Fencing", so we're just checking
     * that it returns EINVAL if both parameters aren't given.
     */
    assert_int_equal(pcmk_resource_delete(&xml, "Fencing", NULL), EINVAL);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
    xml = NULL;

    assert_int_equal(pcmk_resource_delete(&xml, NULL, "primitive"), EINVAL);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);
}

static xmlNode *
find_rsc(const char *rsc)
{
    GString *xpath = g_string_sized_new(1024);
    xmlNode *xml_search = NULL;
    cib_t *cib = NULL;

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);

    pcmk__g_strcat(xpath,
                   pcmk_cib_xpath_for(PCMK_XE_RESOURCES),
                   "//*[@" PCMK_XA_ID "=\"", rsc, "\"]", NULL);

    cib->cmds->query(cib, (const char *) xpath->str, &xml_search, cib_xpath);

    g_string_free(xpath, TRUE);
    cib__clean_up_connection(&cib);
    return xml_search;
}

static void
incorrect_type(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *result = NULL;

    /* cib__process_delete() returns pcmk_rc_ok even if given the wrong type, so
     * we have to do an XPath query of the CIB to make sure it's still there
     */
    assert_int_equal(pcmk_resource_delete(&xml, "Fencing", "clone"), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    result = find_rsc("Fencing");
    assert_non_null(result);

    pcmk__xml_free(result);
}

static void
correct_type(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *result = NULL;

    assert_int_equal(pcmk_resource_delete(&xml, "Fencing", "primitive"), pcmk_rc_ok);
    pcmk__assert_validates(xml);
    pcmk__xml_free(xml);

    result = find_rsc("Fencing");
    assert_null(result);

    pcmk__xml_free(result);
}

static void
unknown_resource(void **state)
{
    xmlNode *xml = NULL;

    /* cib__process_delete() returns pcmk_rc_ok even if asked to delete
     * something that doesn't exist
     */
    assert_int_equal(pcmk_resource_delete(&xml, "no_such_resource", "primitive"), pcmk_rc_ok);
    pcmk__assert_validates(xml);
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
                cmocka_unit_test_setup_teardown(bad_input, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(incorrect_type, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(correct_type, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_resource, setup_test, teardown_test))

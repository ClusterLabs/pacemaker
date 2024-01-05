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
#include <crm/msg_xml.h>
#include <pacemaker.h>

static char *cib_path = NULL;

static int
setup_group(void **state)
{
    /* This needs to be run before we attempt to read in a CIB or it will fail
     * to validate.  There's no harm in doing this before all tests.
     */
    crm_xml_init();
    return 0;
}

static void
cib_not_connected(void **state)
{
    xmlNode *xml = NULL;

    /* Without any special setup, cib_new() in pcmk_resource_delete will use the
     * native CIB which means IPC calls.  But there's nothing listening for those
     * calls, so signon() will return ENOTCONN.  Check that we handle that.
     */
    assert_int_equal(pcmk_resource_delete(&xml, "rsc", "primitive"), ENOTCONN);
    free_xml(xml);
}

static int
setup_test(void **state)
{
    char *in_path = crm_strdup_printf("%s/crm_mon.xml", getenv("PCMK_CTS_CLI_DIR"));
    char *contents = NULL;
    int fd;

    /* Copy the CIB over to a temp location so we can modify it. */
    cib_path = crm_strdup_printf("%s/test-cib.XXXXXX", pcmk__get_tmpdir());

    fd = mkstemp(cib_path);
    if (fd < 0) {
        free(cib_path);
        return -1;
    }

    if (pcmk__file_contents(in_path, &contents) != pcmk_rc_ok) {
        free(cib_path);
        close(fd);
        return -1;
    }

    if (pcmk__write_sync(fd, contents) != pcmk_rc_ok) {
        free(cib_path);
        free(in_path);
        free(contents);
        close(fd);
        return -1;
    }

    setenv("CIB_file", cib_path, 1);
    return 0;
}

static int
teardown_test(void **state)
{
    unlink(cib_path);
    free(cib_path);
    cib_path = NULL;

    unsetenv("CIB_file");
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
    free_xml(xml);
    xml = NULL;

    assert_int_equal(pcmk_resource_delete(&xml, NULL, "primitive"), EINVAL);
    free_xml(xml);
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

    cib->cmds->query(cib, (const char *) xpath->str, &xml_search,
                     cib_xpath|cib_scope_local);

    g_string_free(xpath, TRUE);
    cib__clean_up_connection(&cib);
    return xml_search;
}

static void
incorrect_type(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *result = NULL;

    /* cib_process_delete returns pcmk_ok even if given the wrong type so
     * we have to do an xpath query of the CIB to make sure it's still
     * there.
     */
    assert_int_equal(pcmk_resource_delete(&xml, "Fencing", "clone"), pcmk_rc_ok);
    free_xml(xml);

    result = find_rsc("Fencing");
    assert_non_null(result);

    free_xml(result);
}

static void
correct_type(void **state)
{
    xmlNode *xml = NULL;
    xmlNode *result = NULL;

    assert_int_equal(pcmk_resource_delete(&xml, "Fencing", "primitive"), pcmk_rc_ok);
    free_xml(xml);

    result = find_rsc("Fencing");
    assert_null(result);

    free_xml(result);
}

static void
unknown_resource(void **state)
{
    xmlNode *xml = NULL;

    /* cib_process_delete returns pcmk_ok even if asked to delete something
     * that doesn't exist.
     */
    assert_int_equal(pcmk_resource_delete(&xml, "no_such_resource", "primitive"), pcmk_rc_ok);
    free_xml(xml);
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
PCMK__UNIT_TEST(setup_group, NULL,
                cmocka_unit_test(cib_not_connected),
                cmocka_unit_test_setup_teardown(bad_input, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(incorrect_type, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(correct_type, setup_test, teardown_test),
                cmocka_unit_test_setup_teardown(unknown_resource, setup_test, teardown_test))

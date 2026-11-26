/*
 * Copyright 2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml.h>

#define ORIG_CIB                                                            \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES "/>"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

#define DELETE_CHANGE(path)                                                 \
    "<" PCMK_XE_DIFF " " PCMK_XA_FORMAT "=\"2\">"                           \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_DELETE "\"" \
                        " " PCMK_XA_PATH "=\"" path "\"/>"                  \
    "</" PCMK_XE_DIFF ">"

#define CREATE_CHANGE(path)                                                 \
    "<" PCMK_XE_DIFF " " PCMK_XA_FORMAT "=\"2\">"                           \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_CREATE "\"" \
                        " " PCMK_XA_PATH "=\"" path "\""                    \
                        " " PCMK_XE_POSITION "=\"0\">"                      \
        "<" PCMK_XE_CIB "/>"                                                \
      "</" PCMK_XE_CHANGE ">"                                               \
    "</" PCMK_XE_DIFF ">"

static void
assert_apply(const char *patchset_s, int expected_rc, bool nodes_remain)
{
    xmlNode *cib = pcmk__xml_parse(ORIG_CIB);
    xmlNode *patchset = pcmk__xml_parse(patchset_s);
    xmlNode *config = NULL;
    xmlNode *nodes = NULL;

    assert_int_equal(xml_apply_patchset(cib, patchset, false), expected_rc);

    // The document and its root element must still be intact
    assert_ptr_equal(xmlDocGetRootElement(cib->doc), cib);
    assert_null(cib->next);
    assert_string_equal((const char *) cib->name, PCMK_XE_CIB);

    config = pcmk__xe_first_child(cib, PCMK_XE_CONFIGURATION, NULL, NULL);
    assert_non_null(config);

    nodes = pcmk__xe_first_child(config, PCMK_XE_NODES, NULL, NULL);
    if (nodes_remain) {
        assert_non_null(nodes);
    } else {
        assert_null(nodes);
    }

    pcmk__xml_free(patchset);
    pcmk__xml_free(cib);
}

static void
delete_malformed_path(void **state)
{
    // These used to match the document node or the root element
    assert_apply(DELETE_CHANGE(PCMK_XE_CIB), pcmk_ok, true);
    assert_apply(DELETE_CHANGE("/"), pcmk_ok, true);
    assert_apply(DELETE_CHANGE(PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION),
                 pcmk_ok, true);
    assert_apply(DELETE_CHANGE("/" PCMK_XE_CIB "//" PCMK_XE_CONFIGURATION),
                 pcmk_ok, true);
}

static void
create_malformed_path(void **state)
{
    // This used to add a second root element to the document
    assert_apply(CREATE_CHANGE(PCMK_XE_CIB), -pcmk_err_diff_failed, true);
}

static void
delete_valid_path(void **state)
{
    assert_apply(DELETE_CHANGE("/" PCMK_XE_CIB
                               "/" PCMK_XE_CONFIGURATION
                               "/" PCMK_XE_NODES),
                 pcmk_ok, false);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(delete_malformed_path),
                cmocka_unit_test(create_malformed_path),
                cmocka_unit_test(delete_valid_path))

/*
 * Copyright 2025 the Pacemaker project contributors
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

/* A create change targeting <resources> is held until the second pass, then a
 * delete change frees <resources>. Before the fix, the second pass read the
 * freed node (heap use-after-free).
 */
#define CREATE_THEN_DELETE                                                  \
    "<" PCMK_XE_DIFF " " PCMK_XA_FORMAT "=\"2\">"                           \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_CREATE "\"" \
                        " " PCMK_XA_PATH "=\"/" PCMK_XE_CIB                 \
                            "/" PCMK_XE_CONFIGURATION                       \
                            "/" PCMK_XE_RESOURCES "\""                      \
                        " " PCMK_XE_POSITION "=\"0\">"                      \
        "<" PCMK_XE_PRIMITIVE " " PCMK_XA_ID "=\"r\"/>"                     \
      "</" PCMK_XE_CHANGE ">"                                               \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_DELETE "\"" \
                        " " PCMK_XA_PATH "=\"/" PCMK_XE_CIB                 \
                            "/" PCMK_XE_CONFIGURATION                       \
                            "/" PCMK_XE_RESOURCES "\"/>"                    \
    "</" PCMK_XE_DIFF ">"

// A delete change targeting the document's root element frees the whole tree.
#define DELETE_ROOT                                                         \
    "<" PCMK_XE_DIFF " " PCMK_XA_FORMAT "=\"2\">"                           \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_DELETE "\"" \
                        " " PCMK_XA_PATH "=\"/" PCMK_XE_CIB "\"/>"          \
    "</" PCMK_XE_DIFF ">"

// A well-formed patchset that creates a resource under <resources>.
#define VALID_CREATE                                                        \
    "<" PCMK_XE_DIFF " " PCMK_XA_FORMAT "=\"2\">"                           \
      "<" PCMK_XE_CHANGE " " PCMK_XA_OPERATION "=\"" PCMK_VALUE_CREATE "\"" \
                        " " PCMK_XA_PATH "=\"/" PCMK_XE_CIB                 \
                            "/" PCMK_XE_CONFIGURATION                       \
                            "/" PCMK_XE_RESOURCES "\""                      \
                        " " PCMK_XE_POSITION "=\"0\">"                      \
        "<" PCMK_XE_PRIMITIVE " " PCMK_XA_ID "=\"r\"/>"                     \
      "</" PCMK_XE_CHANGE ">"                                               \
    "</" PCMK_XE_DIFF ">"

static int
apply(const char *patchset_s)
{
    xmlNode *cib = pcmk__xml_parse(ORIG_CIB);
    xmlNode *patchset = pcmk__xml_parse(patchset_s);
    int rc = xml_apply_patchset(cib, patchset, true);

    // The tree must still be intact (not freed out from under us)
    assert_string_equal((const char *) cib->name, PCMK_XE_CIB);

    pcmk__xml_free(patchset);
    pcmk__xml_free(cib);
    return rc;
}

static void
delete_of_pending_create_target_refused(void **state)
{
    assert_int_equal(apply(CREATE_THEN_DELETE), -pcmk_err_diff_failed);
}

static void
delete_of_root_refused(void **state)
{
    assert_int_equal(apply(DELETE_ROOT), -pcmk_err_diff_failed);
}

static void
valid_create_applied(void **state)
{
    assert_int_equal(apply(VALID_CREATE), pcmk_ok);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(delete_of_pending_create_target_refused),
                cmocka_unit_test(delete_of_root_refused),
                cmocka_unit_test(valid_create_applied))

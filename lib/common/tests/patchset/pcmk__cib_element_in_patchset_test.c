/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml.h>

#define ORIG_CIB                                                            \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES ">"                                               \
          "<" PCMK_XE_NODE " " PCMK_XA_ID "=\"1\""                          \
                           " " PCMK_XA_UNAME "=\"node-1\"/>"                \
        "</" PCMK_XE_NODES ">"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

static xmlNode *
create_patchset(const char *source_s, const char *target_s)
{
    xmlNode *source = pcmk__xml_parse(source_s);
    xmlNode *target = pcmk__xml_parse(target_s);
    xmlNode *patchset = NULL;

    pcmk__xml_doc_set_flags(target->doc, pcmk__xf_ignore_attr_pos);
    pcmk__xml_mark_changes(source, target);
    patchset = xml_create_patchset(2, source, target, NULL, false);

    pcmk__xml_free(source);
    pcmk__xml_free(target);
    return patchset;
}

#define assert_in_patchset(source_s, target_s, element)                 \
    do {                                                                \
        xmlNode *patchset = create_patchset(source_s, target_s);        \
                                                                        \
        assert_true(pcmk__cib_element_in_patchset(patchset, element));  \
        pcmk__xml_free(patchset);                                       \
    } while (0)

#define assert_not_in_patchset(source_s, target_s, element)             \
    do {                                                                \
        xmlNode *patchset = create_patchset(source_s, target_s);        \
                                                                        \
        assert_false(pcmk__cib_element_in_patchset(patchset, element)); \
        pcmk__xml_free(patchset);                                       \
    } while (0)

static void
null_patchset_asserts(void **state)
{
    pcmk__assert_asserts(pcmk__cib_element_in_patchset(NULL, NULL));
    pcmk__assert_asserts(pcmk__cib_element_in_patchset(NULL, PCMK_XE_NODES));
}

// PCMK_XE_ALERTS element has been created relative to ORIG_CIB
#define CREATE_CIB                                                          \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES ">"                                               \
          "<" PCMK_XE_NODE " " PCMK_XA_ID "=\"1\""                          \
                           " " PCMK_XA_UNAME "=\"node-1\"/>"                \
        "</" PCMK_XE_NODES ">"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
        "<" PCMK_XE_ALERTS "/>"                                             \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

static void
create_op(void **state)
{
    // Requested element was created
    assert_in_patchset(ORIG_CIB, CREATE_CIB, PCMK_XE_ALERTS);

    // Requested element's descendant was created
    assert_in_patchset(ORIG_CIB, CREATE_CIB, PCMK_XE_CONFIGURATION);
    assert_in_patchset(ORIG_CIB, CREATE_CIB, NULL);

    // Requested element was not changed
    assert_not_in_patchset(ORIG_CIB, CREATE_CIB, PCMK_XE_STATUS);
}

static void
delete_op(void **state)
{
    // Requested element was deleted
    assert_in_patchset(CREATE_CIB, ORIG_CIB, PCMK_XE_ALERTS);

    // Requested element's descendant was deleted
    assert_in_patchset(CREATE_CIB, ORIG_CIB, PCMK_XE_CONFIGURATION);
    assert_in_patchset(CREATE_CIB, ORIG_CIB, NULL);

    // Requested element was not changed
    assert_not_in_patchset(CREATE_CIB, ORIG_CIB, PCMK_XE_STATUS);
}

// PCMK_XE_CIB XML attribute was added relative to ORIG_CIB
#define MODIFY_ADD_CIB                                                      \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\""                        \
                    " " PCMK_XA_CRM_FEATURE_SET "=\"3.19.7\">"              \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES ">"                                               \
          "<" PCMK_XE_NODE " " PCMK_XA_ID "=\"1\""                          \
                           " " PCMK_XA_UNAME "=\"node-1\"/>"                \
        "</" PCMK_XE_NODES ">"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

// PCMK_XE_CIB XML attribute was updated relative to ORIG_CIB
#define MODIFY_UPDATE_CIB                                                   \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"1\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES ">"                                               \
          "<" PCMK_XE_NODE " " PCMK_XA_ID "=\"1\""                          \
                           " " PCMK_XA_UNAME "=\"node-1\"/>"                \
        "</" PCMK_XE_NODES ">"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

// PCMK_XE_NODE XML attribute was added relative to ORIG_CIB
#define MODIFY_ADD_NODE_CIB                                                 \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES ">"                                               \
          "<" PCMK_XE_NODE " " PCMK_XA_ID "=\"1\""                          \
                           " " PCMK_XA_UNAME "=\"node-1\""                  \
                           " " PCMK_XA_TYPE "=\"member\"/>"                 \
        "</" PCMK_XE_NODES ">"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

// PCMK_XE_NODE XML attribute was updated relative to ORIG_CIB
#define MODIFY_UPDATE_NODE_CIB                                              \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES ">"                                               \
          "<" PCMK_XE_NODE " " PCMK_XA_ID "=\"1\""                          \
                           " " PCMK_XA_UNAME "=\"node-2\"/>"                \
        "</" PCMK_XE_NODES ">"                                              \
        "<" PCMK_XE_RESOURCES "/>"                                          \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

static void
modify_op(void **state)
{
    // Requested element was modified (attribute added)
    assert_in_patchset(ORIG_CIB, MODIFY_ADD_CIB, PCMK_XE_CIB);

    // Requested element was modified (attribute updated)
    assert_in_patchset(ORIG_CIB, MODIFY_UPDATE_CIB, PCMK_XE_CIB);

    // Requested element was modified (attribute deleted)
    assert_in_patchset(MODIFY_ADD_CIB, ORIG_CIB, PCMK_XE_CIB);

    // Requested element's descendant was modified (attribute added)
    assert_in_patchset(ORIG_CIB, MODIFY_ADD_NODE_CIB, PCMK_XE_CIB);
    assert_in_patchset(ORIG_CIB, MODIFY_ADD_NODE_CIB, NULL);

    // Requested element's descendant was modified (attribute updated)
    assert_in_patchset(ORIG_CIB, MODIFY_UPDATE_NODE_CIB, PCMK_XE_CIB);
    assert_in_patchset(ORIG_CIB, MODIFY_UPDATE_NODE_CIB, NULL);

    // Requested element's descenant was modified (attribute deleted)
    assert_in_patchset(MODIFY_ADD_NODE_CIB, ORIG_CIB, PCMK_XE_CIB);
    assert_in_patchset(MODIFY_ADD_NODE_CIB, ORIG_CIB, NULL);

    // Requested element was not changed
    assert_not_in_patchset(ORIG_CIB, MODIFY_ADD_CIB, PCMK_XE_STATUS);
    assert_not_in_patchset(ORIG_CIB, MODIFY_UPDATE_CIB, PCMK_XE_STATUS);
    assert_not_in_patchset(ORIG_CIB, MODIFY_ADD_NODE_CIB, PCMK_XE_STATUS);
    assert_not_in_patchset(ORIG_CIB, MODIFY_UPDATE_NODE_CIB, PCMK_XE_STATUS);
}

// PCMK_XE_RESOURCES and PCMK_XE_CONSTRAINTS are swapped relative to ORIG_CIB
#define MOVE_CIB                                                            \
    "<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH "=\"0\""                        \
                    " " PCMK_XA_EPOCH "=\"0\""                              \
                    " " PCMK_XA_NUM_UPDATES "=\"0\">"                       \
      "<" PCMK_XE_CONFIGURATION ">"                                         \
        "<" PCMK_XE_CRM_CONFIG "/>"                                         \
        "<" PCMK_XE_NODES "/>"                                              \
        "<" PCMK_XE_CONSTRAINTS "/>"                                        \
        "<" PCMK_XE_RESOURCES "/>"                                          \
      "</" PCMK_XE_CONFIGURATION ">"                                        \
      "<" PCMK_XE_STATUS "/>"                                               \
    "</" PCMK_XE_CIB ">"

static void
move_op(void **state)
{
    // Requested element was moved
    assert_in_patchset(ORIG_CIB, MOVE_CIB, PCMK_XE_RESOURCES);
    assert_in_patchset(ORIG_CIB, MOVE_CIB, PCMK_XE_CONSTRAINTS);

    // Requested element's descendant was moved
    assert_in_patchset(ORIG_CIB, MOVE_CIB, PCMK_XE_CONFIGURATION);
    assert_in_patchset(ORIG_CIB, MOVE_CIB, NULL);

    // Requested element was not changed
    assert_not_in_patchset(ORIG_CIB, MOVE_CIB, PCMK_XE_STATUS);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_patchset_asserts),
                cmocka_unit_test(create_op),
                cmocka_unit_test(delete_op),
                cmocka_unit_test(modify_op),
                cmocka_unit_test(move_op))

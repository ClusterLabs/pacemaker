/*
 * Copyright 2021-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

static void
op_is_probe_test(void **state)
{
    xmlNode *node = NULL;

    assert_false(pcmk_xe_is_probe(NULL));

    node = pcmk__xml_parse("<" PCMK__XE_LRM_RSC_OP "/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = pcmk__xml_parse("<" PCMK__XE_LRM_RSC_OP " "
                                  PCMK__XA_OPERATION_KEY "=\"blah\" "
                                  PCMK_META_INTERVAL "=\"30s\"/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = pcmk__xml_parse("<" PCMK__XE_LRM_RSC_OP " "
                                  PCMK_XA_OPERATION
                                      "=\"" PCMK_ACTION_MONITOR "\" "
                                  PCMK_META_INTERVAL "=\"30s\"/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = pcmk__xml_parse("<" PCMK__XE_LRM_RSC_OP " "
                                  PCMK_XA_OPERATION
                                      "=\"" PCMK_ACTION_START "\" "
                                  PCMK_META_INTERVAL "=\"0\"/>");
    assert_false(pcmk_xe_is_probe(node));
    free_xml(node);

    node = pcmk__xml_parse("<" PCMK__XE_LRM_RSC_OP " "
                                  PCMK_XA_OPERATION
                                      "=\"" PCMK_ACTION_MONITOR "\" "
                                  PCMK_META_INTERVAL "=\"0\"/>");
    assert_true(pcmk_xe_is_probe(node));
    free_xml(node);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test(op_is_probe_test))

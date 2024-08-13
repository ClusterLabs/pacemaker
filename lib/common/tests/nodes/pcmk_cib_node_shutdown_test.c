/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>          // NULL
#include <libxml/tree.h>    // xmlNode

#include <crm/common/nodes.h>
#include <crm/common/unittest_internal.h>

// Minimum CIB structure needed for function's XPath search
#define CIB_XML                                                     \
    "<" PCMK_XE_CIB ">"                                             \
      "<" PCMK_XE_STATUS ">"                                        \
        "<" PCMK__XE_NODE_STATE " " PCMK_XA_UNAME "='node1'>"       \
          "<" PCMK__XE_TRANSIENT_ATTRIBUTES ">"                     \
            "<" PCMK_XE_INSTANCE_ATTRIBUTES ">"                     \
              "<" PCMK_XE_NVPAIR " "                                \
                  PCMK_XA_NAME "='" PCMK__NODE_ATTR_SHUTDOWN "' "   \
                  PCMK_XA_VALUE "='999'/>"                          \
            "</" PCMK_XE_INSTANCE_ATTRIBUTES ">"                    \
          "</" PCMK__XE_TRANSIENT_ATTRIBUTES ">"                    \
        "</" PCMK__XE_NODE_STATE ">"                                \
      "</" PCMK_XE_STATUS ">"                                       \
    "</" PCMK_XE_CIB ">"

static void
null_args(void **state)
{
    xmlNode *xml = pcmk__xml_parse(CIB_XML);

    assert_non_null(xml);
    assert_null(pcmk_cib_node_shutdown(NULL, NULL));
    assert_null(pcmk_cib_node_shutdown(xml, NULL));
    assert_null(pcmk_cib_node_shutdown(NULL, "node1"));
    free_xml(xml);
}

static void
shutdown_absent(void **state)
{
    xmlNode *xml = pcmk__xml_parse(CIB_XML);

    assert_non_null(xml);
    assert_null(pcmk_cib_node_shutdown(xml, "node"));
    assert_null(pcmk_cib_node_shutdown(xml, "node10"));
    free_xml(xml);
}

static void
shutdown_present(void **state)
{
    xmlNode *xml = pcmk__xml_parse(CIB_XML);

    assert_non_null(xml);
    assert_string_equal(pcmk_cib_node_shutdown(xml, "node1"), "999");
    free_xml(xml);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_args),
                cmocka_unit_test(shutdown_absent),
                cmocka_unit_test(shutdown_present))

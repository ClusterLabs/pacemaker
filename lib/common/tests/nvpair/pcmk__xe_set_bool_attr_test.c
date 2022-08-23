/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/msg_xml.h>

static void
set_attr(void **state)
{
    xmlNode *node = string2xml("<node/>");

    pcmk__xe_set_bool_attr(node, "a", true);
    pcmk__xe_set_bool_attr(node, "b", false);

    assert_string_equal(crm_element_value(node, "a"), XML_BOOLEAN_TRUE);
    assert_string_equal(crm_element_value(node, "b"), XML_BOOLEAN_FALSE);

    free_xml(node);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(set_attr))

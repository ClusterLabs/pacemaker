/*
 * Copyright 2021-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>
#include <crm/common/xml.h>

static void
set_attr(void **state)
{
    xmlNode *node = pcmk__xml_parse("<node/>");

    pcmk__xe_set_bool_attr(node, "a", true);
    pcmk__xe_set_bool_attr(node, "b", false);

    assert_string_equal(pcmk__xe_get(node, "a"), PCMK_VALUE_TRUE);
    assert_string_equal(pcmk__xe_get(node, "b"), PCMK_VALUE_FALSE);

    pcmk__xml_free(node);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(set_attr))

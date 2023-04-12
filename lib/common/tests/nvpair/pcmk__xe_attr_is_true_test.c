/*
 * Copyright 2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static void
empty_input(void **state)
{
    xmlNode *node = string2xml("<node/>");

    assert_false(pcmk__xe_attr_is_true(NULL, NULL));
    assert_false(pcmk__xe_attr_is_true(NULL, "whatever"));
    assert_false(pcmk__xe_attr_is_true(node, NULL));

    free_xml(node);
}

static void
attr_missing(void **state)
{
    xmlNode *node = string2xml("<node a=\"true\" b=\"false\"/>");

    assert_false(pcmk__xe_attr_is_true(node, "c"));
    free_xml(node);
}

static void
attr_present(void **state)
{
    xmlNode *node = string2xml("<node a=\"true\" b=\"false\"/>");

    assert_true(pcmk__xe_attr_is_true(node, "a"));
    assert_false(pcmk__xe_attr_is_true(node, "b"));

    free_xml(node);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input),
                cmocka_unit_test(attr_missing),
                cmocka_unit_test(attr_present))

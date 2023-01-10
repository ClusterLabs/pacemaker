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
    bool value;

    assert_int_equal(pcmk__xe_get_bool_attr(NULL, NULL, &value), ENODATA);
    assert_int_equal(pcmk__xe_get_bool_attr(NULL, "whatever", &value), ENODATA);
    assert_int_equal(pcmk__xe_get_bool_attr(node, NULL, &value), EINVAL);
    assert_int_equal(pcmk__xe_get_bool_attr(node, "whatever", NULL), EINVAL);

    free_xml(node);
}

static void
attr_missing(void **state)
{
    xmlNode *node = string2xml("<node a=\"true\" b=\"false\"/>");
    bool value;

    assert_int_equal(pcmk__xe_get_bool_attr(node, "c", &value), ENODATA);
    free_xml(node);
}

static void
attr_present(void **state)
{
    xmlNode *node = string2xml("<node a=\"true\" b=\"false\" c=\"blah\"/>");
    bool value;

    value = false;
    assert_int_equal(pcmk__xe_get_bool_attr(node, "a", &value), pcmk_rc_ok);
    assert_true(value);
    value = true;
    assert_int_equal(pcmk__xe_get_bool_attr(node, "b", &value), pcmk_rc_ok);
    assert_false(value);
    assert_int_equal(pcmk__xe_get_bool_attr(node, "c", &value), pcmk_rc_unknown_format);

    free_xml(node);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_input),
                cmocka_unit_test(attr_missing),
                cmocka_unit_test(attr_present))

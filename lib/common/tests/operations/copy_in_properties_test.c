 /*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

static void
target_is_NULL(void **state)
{
    xmlNode *test_xml_1 = create_xml_node(NULL, "test_xml_1");
    xmlNode *test_xml_2 = NULL;

    pcmk__xe_set_props(test_xml_1, "test_prop", "test_value", NULL);

    copy_in_properties(test_xml_2, test_xml_1);

    assert_ptr_equal(test_xml_2, NULL);
}

static void
src_is_NULL(void **state)
{
    xmlNode *test_xml_1 = NULL;
    xmlNode *test_xml_2 = create_xml_node(NULL, "test_xml_2");

    copy_in_properties(test_xml_2, test_xml_1);

    assert_ptr_equal(test_xml_2->properties, NULL);
}

static void
copying_is_successful(void **state)
{
    const char *xml_1_value;
    const char *xml_2_value;

    xmlNode *test_xml_1 = create_xml_node(NULL, "test_xml_1");
    xmlNode *test_xml_2 = create_xml_node(NULL, "test_xml_2");

    pcmk__xe_set_props(test_xml_1, "test_prop", "test_value", NULL);

    copy_in_properties(test_xml_2, test_xml_1);

    xml_1_value = crm_element_value(test_xml_1, "test_prop");
    xml_2_value = crm_element_value(test_xml_2, "test_prop");

    assert_string_equal(xml_1_value, xml_2_value);
}

int main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(target_is_NULL),
        cmocka_unit_test(src_is_NULL),
        cmocka_unit_test(copying_is_successful),
    };

    cmocka_set_message_output(CM_OUTPUT_TAP);
    return cmocka_run_group_tests(tests, NULL, NULL);
}

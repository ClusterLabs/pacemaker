/*
 * Copyright 2022-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>
#include <crm/common/xml_internal.h>

static int compare_name_handler(xmlNode *xml, void *userdata) {
    function_called();
    assert_string_equal((char *) userdata, crm_element_name(xml));
    return pcmk_rc_ok;
}

const char *str1 =
    "<xml>\n"
    "  <!-- This is a level 1 node -->\n"
    "  <level1>\n"
    "    content\n"
    "  </level1>\n"
    "  <!-- This is a level 1 node -->\n"
    "  <level1>\n"
    "    content\n"
    "  </level1>\n"
    "  <!-- This is a level 1 node -->\n"
    "  <level1>\n"
    "    content\n"
    "  </level1>\n"
    "</xml>";

static void
bad_input(void **state) {
    xmlNode *xml = string2xml(str1);

    pcmk__assert_asserts(pcmk__xe_foreach_child(xml, NULL, NULL, NULL));

    free_xml(xml);
}

static void
name_given_test(void **state) {
    xmlNode *xml = string2xml(str1);

    /* The handler should be called once for every <level1> node. */
    expect_function_call(compare_name_handler);
    expect_function_call(compare_name_handler);
    expect_function_call(compare_name_handler);

    pcmk__xe_foreach_child(xml, "level1", compare_name_handler, (void *) "level1");
    free_xml(xml);
}

static void
no_name_given_test(void **state) {
    xmlNode *xml = string2xml(str1);

    /* The handler should be called once for every <level1> node. */
    expect_function_call(compare_name_handler);
    expect_function_call(compare_name_handler);
    expect_function_call(compare_name_handler);

    pcmk__xe_foreach_child(xml, NULL, compare_name_handler, (void *) "level1");
    free_xml(xml);
}

static void
name_doesnt_exist_test(void **state) {
    xmlNode *xml = string2xml(str1);
    pcmk__xe_foreach_child(xml, "xxx", compare_name_handler, NULL);
    free_xml(xml);
}

const char *str2 =
    "<xml>\n"
    "  <level1>\n"
    "    <!-- Inside a level 1 node -->\n"
    "    <level2>\n"
    "      <!-- Inside a level 2 node -->\n"
    "    </level2>\n"
    "  </level1>\n"
    "  <level1>\n"
    "    <!-- Inside a level 1 node -->\n"
    "    <level2>\n"
    "      <!-- Inside a level 2 node -->\n"
    "      <level3>\n"
    "        <!-- Inside a level 3 node -->\n"
    "      </level3>\n"
    "    </level2>\n"
    "    <level2>\n"
    "      <!-- Inside a level 2 node -->\n"
    "    </level2>\n"
    "  </level1>\n"
    "</xml>";

static void
multiple_levels_test(void **state) {
    xmlNode *xml = string2xml(str2);

    /* The handler should be called once for every <level1> node. */
    expect_function_call(compare_name_handler);
    expect_function_call(compare_name_handler);

    pcmk__xe_foreach_child(xml, "level1", compare_name_handler, (void *) "level1");
    free_xml(xml);
}

static void
multiple_levels_no_name_test(void **state) {
    xmlNode *xml = string2xml(str2);

    /* The handler should be called once for every <level1> node. */
    expect_function_call(compare_name_handler);
    expect_function_call(compare_name_handler);

    pcmk__xe_foreach_child(xml, NULL, compare_name_handler, (void *) "level1");
    free_xml(xml);
}

const char *str3 =
    "<xml>\n"
    "  <!-- This is node #1 -->\n"
    "  <node1>\n"
    "    content\n"
    "  </node1>\n"
    "  <!-- This is node #2 -->\n"
    "  <node2>\n"
    "    content\n"
    "  </node2>\n"
    "  <!-- This is node #3 -->\n"
    "  <node3>\n"
    "    content\n"
    "  </node3>\n"
    "</xml>";

static int any_of_handler(xmlNode *xml, void *userdata) {
    function_called();
    assert_true(pcmk__str_any_of(crm_element_name(xml), "node1", "node2", "node3", NULL));
    return pcmk_rc_ok;
}

static void
any_of_test(void **state) {
    xmlNode *xml = string2xml(str3);

    /* The handler should be called once for every <nodeX> node. */
    expect_function_call(any_of_handler);
    expect_function_call(any_of_handler);
    expect_function_call(any_of_handler);

    pcmk__xe_foreach_child(xml, NULL, any_of_handler, NULL);
    free_xml(xml);
}

static int stops_on_first_handler(xmlNode *xml, void *userdata) {
    function_called();

    if (pcmk__xe_is(xml, "node1")) {
        return pcmk_rc_error;
    } else {
        return pcmk_rc_ok;
    }
}

static int stops_on_second_handler(xmlNode *xml, void *userdata) {
    function_called();

    if (pcmk__xe_is(xml, "node2")) {
        return pcmk_rc_error;
    } else {
        return pcmk_rc_ok;
    }
}

static int stops_on_third_handler(xmlNode *xml, void *userdata) {
    function_called();

    if (pcmk__xe_is(xml, "node3")) {
        return pcmk_rc_error;
    } else {
        return pcmk_rc_ok;
    }
}

static void
one_of_test(void **state) {
    xmlNode *xml = string2xml(str3);

    /* The handler should be called once. */
    expect_function_call(stops_on_first_handler);
    assert_int_equal(pcmk__xe_foreach_child(xml, "node1", stops_on_first_handler, NULL), pcmk_rc_error);

    expect_function_call(stops_on_second_handler);
    assert_int_equal(pcmk__xe_foreach_child(xml, "node2", stops_on_second_handler, NULL), pcmk_rc_error);

    expect_function_call(stops_on_third_handler);
    assert_int_equal(pcmk__xe_foreach_child(xml, "node3", stops_on_third_handler, NULL), pcmk_rc_error);

    free_xml(xml);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(bad_input),
                cmocka_unit_test(name_given_test),
                cmocka_unit_test(no_name_given_test),
                cmocka_unit_test(name_doesnt_exist_test),
                cmocka_unit_test(multiple_levels_test),
                cmocka_unit_test(multiple_levels_no_name_test),
                cmocka_unit_test(any_of_test),
                cmocka_unit_test(one_of_test))

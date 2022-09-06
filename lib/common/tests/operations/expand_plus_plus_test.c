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
value_is_name_plus_plus(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "6");
}

static void
value_is_name_plus_equals_integer(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X+=2");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "7");
}

// NULL input

static void
target_is_NULL(void **state)
{

    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(NULL, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "5");
}

static void
name_is_NULL(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, NULL, "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "5");
}

static void
value_is_NULL(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", NULL);
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "5");
}

// the value input doesn't start with the name input

static void
value_is_wrong_name(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "Y++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "Y++");
}

static void
value_is_only_an_integer(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "2");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "2");
}

// non-integers

static void
variable_is_initialized_to_be_NULL(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", NULL);
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "X++");
}

static void
variable_is_initialized_to_be_non_numeric(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "hello");
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "1");
}

static void
variable_is_initialized_to_be_non_numeric_2(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "hello");
    expand_plus_plus(test_xml, "X", "X+=2");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "2");
}

static void
variable_is_initialized_to_be_numeric_and_decimal_point_containing(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5.01");
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "6");
}

static void
variable_is_initialized_to_be_numeric_and_decimal_point_containing_2(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5.50");
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "6");
}

static void
variable_is_initialized_to_be_numeric_and_decimal_point_containing_3(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5.99");
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "6");
}

static void
value_is_non_numeric(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X+=hello");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "5");
}

static void
value_is_numeric_and_decimal_point_containing(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X+=2.01");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "7");
}

static void
value_is_numeric_and_decimal_point_containing_2(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X+=1.50");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "6");
}

static void
value_is_numeric_and_decimal_point_containing_3(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X+=1.99");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "6");
}

// undefined input

static void
name_is_undefined(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "Y", "5");
    expand_plus_plus(test_xml, "X", "X++");
    new_value = crm_element_value(test_xml, "X");
    assert_string_equal(new_value, "X++");
}

// large input

static void
assignment_result_is_too_large(void **state)
{
    const char *new_value;
    xmlNode *test_xml = create_xml_node(NULL, "test_xml");
    crm_xml_add(test_xml, "X", "5");
    expand_plus_plus(test_xml, "X", "X+=100000000000");
    new_value = crm_element_value(test_xml, "X");
    printf("assignment result is too large %s\n", new_value);
    assert_string_equal(new_value, "1000000");
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(value_is_name_plus_plus),
                cmocka_unit_test(value_is_name_plus_equals_integer),
                cmocka_unit_test(target_is_NULL),
                cmocka_unit_test(name_is_NULL),
                cmocka_unit_test(value_is_NULL),
                cmocka_unit_test(value_is_wrong_name),
                cmocka_unit_test(value_is_only_an_integer),
                cmocka_unit_test(variable_is_initialized_to_be_NULL),
                cmocka_unit_test(variable_is_initialized_to_be_non_numeric),
                cmocka_unit_test(variable_is_initialized_to_be_non_numeric_2),
                cmocka_unit_test(variable_is_initialized_to_be_numeric_and_decimal_point_containing),
                cmocka_unit_test(variable_is_initialized_to_be_numeric_and_decimal_point_containing_2),
                cmocka_unit_test(variable_is_initialized_to_be_numeric_and_decimal_point_containing_3),
                cmocka_unit_test(value_is_non_numeric),
                cmocka_unit_test(value_is_numeric_and_decimal_point_containing),
                cmocka_unit_test(value_is_numeric_and_decimal_point_containing_2),
                cmocka_unit_test(value_is_numeric_and_decimal_point_containing_3),
                cmocka_unit_test(name_is_undefined),
                cmocka_unit_test(assignment_result_is_too_large))

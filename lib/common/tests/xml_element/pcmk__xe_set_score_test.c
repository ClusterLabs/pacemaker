/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <glib.h>

#include "crmcommon_private.h"  // pcmk__xe_set_score()

#define ATTR_NAME "test_attr"

/*!
 * \internal
 * \brief Update an XML attribute value and check it against a reference value
 *
 * The attribute name is hard-coded as \c ATTR_NAME.
 *
 * \param[in] initial        Initial value
 * \param[in] new            Value to set
 * \param[in] reference_val  Expected attribute value after update
 * \param[in] reference_rc   Expected return code from \c pcmk__xe_set_score()
 */
static void
assert_set_score(const char *initial, const char *new,
                 const char *reference_val, int reference_rc)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test_xml");

    pcmk__xe_set(test_xml, ATTR_NAME, initial);
    assert_int_equal(pcmk__xe_set_score(test_xml, ATTR_NAME, new), reference_rc);
    assert_string_equal(pcmk__xe_get(test_xml, ATTR_NAME), reference_val);

    pcmk__xml_free(test_xml);
}

static void
new_value_name_plus_plus(void **state)
{
    assert_set_score("5", ATTR_NAME "++", "6", pcmk_rc_ok);
}

static void
new_value_name_plus_equals_integer(void **state)
{
    assert_set_score("5", ATTR_NAME "+=2", "7", pcmk_rc_ok);
}

// NULL input

static void
null_target(void **state)
{
    // Dumps core via CRM_CHECK()
    assert_int_equal(pcmk__xe_set_score(NULL, ATTR_NAME, ATTR_NAME "++"),
                     EINVAL);
}

static void
null_name(void **state)
{
    xmlNode *test_xml = pcmk__xe_create(NULL, "test_xml");

    pcmk__xe_set(test_xml, ATTR_NAME, "5");

    // Dumps core via CRM_CHECK()
    assert_int_equal(pcmk__xe_set_score(test_xml, NULL, ATTR_NAME "++"),
                     EINVAL);
    assert_string_equal(pcmk__xe_get(test_xml, ATTR_NAME), "5");

    pcmk__xml_free(test_xml);
}

static void
null_new_value(void **state)
{
    assert_set_score("5", NULL, "5", pcmk_rc_ok);
}

// the value input doesn't start with the name input

static void
new_value_wrong_name(void **state)
{
    assert_set_score("5", "garbage" ATTR_NAME "++", "garbage" ATTR_NAME "++",
                     pcmk_rc_ok);
}

static void
new_value_bare_integer(void **state)
{
    assert_set_score("5", "2", "2", pcmk_rc_ok);
}

// non-integers

static void
initial_value_non_numeric(void **state)
{
    assert_set_score("hello", ATTR_NAME "++", "1", pcmk_rc_ok);
    assert_set_score("hello", ATTR_NAME "+=2", "2", pcmk_rc_ok);
}

static void
initial_value_decimal(void **state)
{
    assert_set_score("5.01", ATTR_NAME "++", "6", pcmk_rc_ok);
    assert_set_score("5.50", ATTR_NAME "++", "6", pcmk_rc_ok);
    assert_set_score("5.99", ATTR_NAME "++", "6", pcmk_rc_ok);
}

static void
new_value_non_numeric(void **state)
{
    assert_set_score("5", ATTR_NAME "+=hello", "5", pcmk_rc_ok);
}

static void
new_value_decimal(void **state)
{
    assert_set_score("5", ATTR_NAME "+=2.01", "7", pcmk_rc_ok);
    assert_set_score("5", ATTR_NAME "+=1.50", "6", pcmk_rc_ok);
    assert_set_score("5", ATTR_NAME "+=1.99", "6", pcmk_rc_ok);
}

static void
initial_value_unset(void **state)
{
    assert_set_score(NULL, ATTR_NAME "++", ATTR_NAME "++", pcmk_rc_ok);
}

// https://gcc.gnu.org/onlinedocs/gcc-15.2.0/cpp/Stringizing.html
#define xstr(s) str(s)
#define str(s) #s

static void
new_value_overflows(void **state)
{
    assert_set_score("5", ATTR_NAME "+=100000000000", xstr(PCMK_SCORE_INFINITY),
                     pcmk_rc_ok);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(new_value_name_plus_plus),
                cmocka_unit_test(new_value_name_plus_equals_integer),
                cmocka_unit_test(null_target),
                cmocka_unit_test(null_name),
                cmocka_unit_test(null_new_value),
                cmocka_unit_test(new_value_wrong_name),
                cmocka_unit_test(new_value_bare_integer),
                cmocka_unit_test(initial_value_non_numeric),
                cmocka_unit_test(initial_value_decimal),
                cmocka_unit_test(new_value_non_numeric),
                cmocka_unit_test(new_value_decimal),
                cmocka_unit_test(initial_value_unset),
                cmocka_unit_test(new_value_overflows))

/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <glib.h>

#include <crm/common/xml.h>
#include <crm/common/rules_internal.h>
#include <crm/common/unittest_internal.h>

/*
 * Shared data
 */

static pcmk_rule_input_t rule_input = {
    .rsc_standard = PCMK_RESOURCE_CLASS_OCF,
    .rsc_provider = "heartbeat",
    .rsc_agent = "IPaddr2",
    .op_name = PCMK_ACTION_MONITOR,
    .op_interval_ms = 10000,
};


/*
 * Test invalid arguments
 */

#define EXPR_ATTRIBUTE                                  \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' />"

static void
null_invalid(void **state)
{
#if 0
    xmlNode *xml = NULL;
#endif
    crm_time_t *next_change = crm_time_new_undefined();

    assert_int_equal(pcmk__evaluate_condition(NULL, NULL, next_change),
                     pcmk_rc_unpack_error);

#if 0 // currently segfaults
    xml = pcmk__xml_parse(EXPR_ATTRIBUTE);
    assert_int_equal(pcmk__evaluate_condition(xml, NULL, next_change), EINVAL);
    free_xml(xml);
#endif

    assert_int_equal(pcmk__evaluate_condition(NULL, &rule_input, next_change),
                     pcmk_rc_unpack_error);

    crm_time_free(next_change);
}


#define EXPR_INVALID "<not_an_expression " PCMK_XA_ID "='e' />"

static void
invalid_expression(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_INVALID);
    crm_time_t *next_change = crm_time_new_undefined();

    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, next_change),
                     pcmk_rc_unpack_error);

    crm_time_free(next_change);
    free_xml(xml);
}


/* Each expression type function already has unit tests, so we just need to test
 * that they are called correctly (essentially, one of each one's own tests).
 */

static void
attribute_expression(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_ATTRIBUTE);

    rule_input.node_attrs = pcmk__strkey_table(free, free);
    pcmk__insert_dup(rule_input.node_attrs, "foo", "bar");

    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, NULL),
                     pcmk_rc_ok);

    g_hash_table_destroy(rule_input.node_attrs);
    rule_input.node_attrs = NULL;
    free_xml(xml);
}

#define EXPR_LOCATION                                   \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='" CRM_ATTR_UNAME "' "      \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='node1' />"

static void
location_expression(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_LOCATION);

    rule_input.node_attrs = pcmk__strkey_table(free, free);
    pcmk__insert_dup(rule_input.node_attrs, CRM_ATTR_UNAME, "node1");

    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, NULL),
                     pcmk_rc_ok);

    g_hash_table_destroy(rule_input.node_attrs);
    rule_input.node_attrs = NULL;
    free_xml(xml);
}

#define EXPR_DATE                                       \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00' "             \
    PCMK_XA_END "='2024-02-01 15:00:00' />"

static void
date_expression(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_DATE);
    crm_time_t *now = crm_time_new("2024-02-01 11:59:59");
    crm_time_t *next_change = crm_time_new("2024-02-01 14:00:00");
    crm_time_t *reference = crm_time_new("2024-02-01 12:00:00");

    rule_input.now = now;
    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, next_change),
                     pcmk_rc_before_range);
    assert_int_equal(crm_time_compare(next_change, reference), 0);
    rule_input.now = NULL;

    crm_time_free(reference);
    crm_time_free(next_change);
    crm_time_free(now);
}

#define EXPR_RESOURCE                                       \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_TYPE "='IPaddr2' />"

static void
resource_expression(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_RESOURCE);

    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, NULL),
                     pcmk_rc_ok);
    free_xml(xml);
}

#define EXPR_OP                                             \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "          \
        PCMK_XA_INTERVAL "='10s' />"

static void
op_expression(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_OP);

    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, NULL),
                     pcmk_rc_ok);
    free_xml(xml);
}

#define EXPR_SUBRULE                                        \
        "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "             \
        "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "  \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "          \
        PCMK_XA_INTERVAL "='10s' /> />"

static void
subrule(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_SUBRULE);
    assert_int_equal(pcmk__evaluate_condition(xml, &rule_input, NULL),
                     pcmk_rc_ok);
    free_xml(xml);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(invalid_expression),
                cmocka_unit_test(attribute_expression),
                cmocka_unit_test(location_expression),
                cmocka_unit_test(date_expression),
                cmocka_unit_test(resource_expression),
                cmocka_unit_test(op_expression),
                cmocka_unit_test(subrule))

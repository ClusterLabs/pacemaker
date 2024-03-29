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

#define RULE_OP                                         \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' > "           \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "  \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "    \
          PCMK_XA_INTERVAL "='10s' />"                  \
    "</" PCMK_XE_RULE ">"

static void
null_invalid(void **state)
{
    xmlNode *xml = NULL;
    crm_time_t *next_change = crm_time_new_undefined();

    assert_int_equal(pcmk_evaluate_rule(NULL, NULL, next_change),
                     EINVAL);

    xml = pcmk__xml_parse(RULE_OP);
    assert_int_equal(pcmk_evaluate_rule(xml, NULL, next_change), EINVAL);
    pcmk__xml_free(xml);

    assert_int_equal(pcmk_evaluate_rule(NULL, &rule_input, next_change),
                     EINVAL);

    crm_time_free(next_change);
}

#define RULE_OP_MISSING_ID                              \
    "<" PCMK_XE_RULE "> "                               \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "  \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "    \
          PCMK_XA_INTERVAL "='10s' />"                  \
    "</" PCMK_XE_RULE ">"

static void
id_missing(void **state)
{
    // Currently acceptable
    xmlNode *xml = pcmk__xml_parse(RULE_OP_MISSING_ID);
    crm_time_t *next_change = crm_time_new_undefined();

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, next_change),
                     pcmk_rc_ok);

    crm_time_free(next_change);
    pcmk__xml_free(xml);
}

#define RULE_IDREF_PARENT "<" PCMK_XE_CIB ">" RULE_OP "</" PCMK_XE_CIB ">"

static void
good_idref(void **state)
{
    xmlNode *parent_xml = pcmk__xml_parse(RULE_IDREF_PARENT);
    xmlNode *rule_xml = pcmk__xe_create(parent_xml, PCMK_XE_RULE);
    crm_time_t *next_change = crm_time_new_undefined();

    crm_xml_add(rule_xml, PCMK_XA_ID_REF, "r");
    assert_int_equal(pcmk_evaluate_rule(rule_xml, &rule_input, next_change),
                     pcmk_rc_ok);

    crm_time_free(next_change);
    pcmk__xml_free(parent_xml);
}

static void
bad_idref(void **state)
{
    xmlNode *parent_xml = pcmk__xml_parse(RULE_IDREF_PARENT);
    xmlNode *rule_xml = pcmk__xe_create(parent_xml, PCMK_XE_RULE);
    crm_time_t *next_change = crm_time_new_undefined();

    crm_xml_add(rule_xml, PCMK_XA_ID_REF, "x");
    assert_int_equal(pcmk_evaluate_rule(rule_xml, &rule_input, next_change),
                     pcmk_rc_unpack_error);

    crm_time_free(next_change);
    pcmk__xml_free(parent_xml);
}

#define RULE_EMPTY "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' />"

static void
empty_default(void **state)
{
    // Currently acceptable
    xmlNode *xml = pcmk__xml_parse(RULE_EMPTY);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_EMPTY_AND                                  \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "             \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_AND "' />"

static void
empty_and(void **state)
{
    // Currently acceptable
    xmlNode *xml = pcmk__xml_parse(RULE_EMPTY_AND);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_EMPTY_OR                                   \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "             \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_OR "' />"

static void
empty_or(void **state)
{
    // Currently treated as unsatisfied
    xmlNode *xml = pcmk__xml_parse(RULE_EMPTY_OR);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_op_unsatisfied);

    pcmk__xml_free(xml);
}

#define RULE_DEFAULT_BOOLEAN_OP                             \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' >"                \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='Dummy' />"                        \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
default_boolean_op(void **state)
{
    // Defaults to PCMK_VALUE_AND
    xmlNode *xml = pcmk__xml_parse(RULE_DEFAULT_BOOLEAN_OP);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_op_unsatisfied);

    pcmk__xml_free(xml);
}

#define RULE_INVALID_BOOLEAN_OP                             \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='not-an-op' >"                 \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='Dummy' />"                        \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
invalid_boolean_op(void **state)
{
    // Currently defaults to PCMK_VALUE_AND
    xmlNode *xml = pcmk__xml_parse(RULE_INVALID_BOOLEAN_OP);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_op_unsatisfied);

    pcmk__xml_free(xml);
}

#define RULE_AND_PASSES                                     \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_AND "' >"        \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='IPaddr2' />"                      \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
and_passes(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_AND_PASSES);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL), pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_LONELY_AND                                     \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_AND "' >"        \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='IPaddr2' />"                      \
    "</" PCMK_XE_RULE ">"

static void
lonely_and_passes(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_LONELY_AND);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL), pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_AND_ONE_FAILS                                  \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_AND "' >"        \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='Dummy' />"                        \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
and_one_fails(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_AND_ONE_FAILS);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_op_unsatisfied);

    pcmk__xml_free(xml);
}

#define RULE_AND_TWO_FAIL                                   \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_AND "' >"        \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='Dummy' />"                        \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='9s' />"                       \
    "</" PCMK_XE_RULE ">"

static void
and_two_fail(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_AND_TWO_FAIL);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_op_unsatisfied);

    pcmk__xml_free(xml);
}

#define RULE_OR_ONE_PASSES                                  \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_OR "' >"         \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='Dummy' />"                        \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
or_one_passes(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_OR_ONE_PASSES);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL), pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_OR_TWO_PASS                                    \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_OR "' >"         \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='IPAddr2' />"                      \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
or_two_pass(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_OR_TWO_PASS);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL), pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_LONELY_OR                                      \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_OR "' >"         \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='10s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
lonely_or_passes(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_LONELY_OR);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL), pcmk_rc_ok);

    pcmk__xml_free(xml);
}

#define RULE_OR_FAILS                                       \
    "<" PCMK_XE_RULE " " PCMK_XA_ID "='r' "                 \
        PCMK_XA_BOOLEAN_OP "='" PCMK_VALUE_OR "' >"         \
    "  <" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e1' "    \
          PCMK_XA_TYPE "='Dummy' />"                        \
    "  <" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e2' "     \
          PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "        \
          PCMK_XA_INTERVAL "='20s' />"                      \
    "</" PCMK_XE_RULE ">"

static void
or_fails(void **state)
{
    xmlNode *xml = pcmk__xml_parse(RULE_OR_FAILS);

    assert_int_equal(pcmk_evaluate_rule(xml, &rule_input, NULL),
                     pcmk_rc_op_unsatisfied);

    pcmk__xml_free(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(id_missing),
                cmocka_unit_test(good_idref),
                cmocka_unit_test(bad_idref),
                cmocka_unit_test(empty_default),
                cmocka_unit_test(empty_and),
                cmocka_unit_test(empty_or),
                cmocka_unit_test(default_boolean_op),
                cmocka_unit_test(invalid_boolean_op),
                cmocka_unit_test(and_passes),
                cmocka_unit_test(lonely_and_passes),
                cmocka_unit_test(and_one_fails),
                cmocka_unit_test(and_two_fail),
                cmocka_unit_test(or_one_passes),
                cmocka_unit_test(or_two_pass),
                cmocka_unit_test(lonely_or_passes),
                cmocka_unit_test(or_fails))

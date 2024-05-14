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
#include "crmcommon_private.h"

/*
 * Shared data
 */

static pcmk_rule_input_t rule_input = {
    // These are the only members used to evaluate resource expressions
    .rsc_standard = PCMK_RESOURCE_CLASS_OCF,
    .rsc_provider = "heartbeat",
    .rsc_agent = "IPaddr2",
};

/*!
 * \internal
 * \brief Run one test, comparing return value
 *
 * \param[in] xml_string    Resource expression XML as string
 * \param[in] reference_rc  Assert that evaluation result equals this
 */
static void
assert_rsc_expression(const char *xml_string, int reference_rc)
{
    xmlNode *xml = pcmk__xml_parse(xml_string);

    assert_int_equal(pcmk__evaluate_rsc_expression(xml, &rule_input),
                     reference_rc);
    free_xml(xml);
}


/*
 * Invalid arguments
 */

#define EXPR_ALL_MATCH                                      \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='heartbeat' "                    \
        PCMK_XA_TYPE "='IPaddr2' />"

static void
null_invalid(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk__evaluate_rsc_expression(NULL, NULL), EINVAL);

    xml = pcmk__xml_parse(EXPR_ALL_MATCH);
    assert_int_equal(pcmk__evaluate_rsc_expression(xml, NULL), EINVAL);
    free_xml(xml);

    assert_rsc_expression(NULL, EINVAL);
}


/*
 * Test PCMK_XA_ID
 */

#define EXPR_ID_MISSING                                 \
        "<" PCMK_XE_RSC_EXPRESSION " "                  \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' " \
        PCMK_XA_PROVIDER "='heartbeat' "                \
        PCMK_XA_TYPE "='IPaddr2' />"

#define EXPR_ID_EMPTY                                       \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='' "    \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='heartbeat' "                    \
        PCMK_XA_TYPE "='IPaddr2' />"

static void
id_missing(void **state)
{
    // Currently acceptable
    assert_rsc_expression(EXPR_ID_MISSING, pcmk_rc_ok);
    assert_rsc_expression(EXPR_ID_EMPTY, pcmk_rc_ok);
}


/*
 * Test standard, provider, and agent
 */

#define EXPR_FAIL_STANDARD                                  \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_LSB "' />"

#define EXPR_EMPTY_STANDARD                                 \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='' />"

static void
fail_standard(void **state)
{
    assert_rsc_expression(EXPR_FAIL_STANDARD, pcmk_rc_op_unsatisfied);
    assert_rsc_expression(EXPR_EMPTY_STANDARD, pcmk_rc_op_unsatisfied);

    rule_input.rsc_standard = NULL;
    assert_rsc_expression(EXPR_FAIL_STANDARD, pcmk_rc_op_unsatisfied);
    assert_rsc_expression(EXPR_EMPTY_STANDARD, pcmk_rc_op_unsatisfied);
    rule_input.rsc_standard = PCMK_RESOURCE_CLASS_OCF;
}

#define EXPR_FAIL_PROVIDER                                  \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='pacemaker' "                    \
        PCMK_XA_TYPE "='IPaddr2' />"

#define EXPR_EMPTY_PROVIDER                                 \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='' " PCMK_XA_TYPE "='IPaddr2' />"

static void
fail_provider(void **state)
{
    assert_rsc_expression(EXPR_FAIL_PROVIDER, pcmk_rc_op_unsatisfied);
    assert_rsc_expression(EXPR_EMPTY_PROVIDER, pcmk_rc_op_unsatisfied);

    rule_input.rsc_provider = NULL;
    assert_rsc_expression(EXPR_FAIL_PROVIDER, pcmk_rc_op_unsatisfied);
    assert_rsc_expression(EXPR_EMPTY_PROVIDER, pcmk_rc_op_unsatisfied);
    rule_input.rsc_provider = "heartbeat";
}

#define EXPR_FAIL_AGENT                                     \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='heartbeat' "                    \
        PCMK_XA_TYPE "='IPaddr3' />"

#define EXPR_EMPTY_AGENT                                    \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='heartbeat' " PCMK_XA_TYPE "='' />"

static void
fail_agent(void **state)
{
    assert_rsc_expression(EXPR_FAIL_AGENT, pcmk_rc_op_unsatisfied);
    assert_rsc_expression(EXPR_EMPTY_AGENT, pcmk_rc_op_unsatisfied);

    rule_input.rsc_agent = NULL;
    assert_rsc_expression(EXPR_FAIL_AGENT, pcmk_rc_op_unsatisfied);
    assert_rsc_expression(EXPR_EMPTY_AGENT, pcmk_rc_op_unsatisfied);
    rule_input.rsc_agent = "IPaddr2";
}

#define EXPR_NO_STANDARD_MATCHES                            \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_PROVIDER "='heartbeat' "                    \
        PCMK_XA_TYPE "='IPaddr2' />"

static void
no_standard_matches(void **state)
{
    assert_rsc_expression(EXPR_NO_STANDARD_MATCHES, pcmk_rc_ok);
}

#define EXPR_NO_PROVIDER_MATCHES                            \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_TYPE "='IPaddr2' />"

static void
no_provider_matches(void **state)
{
    assert_rsc_expression(EXPR_NO_PROVIDER_MATCHES, pcmk_rc_ok);
}

#define EXPR_NO_AGENT_MATCHES                               \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_CLASS "='" PCMK_RESOURCE_CLASS_OCF "' "     \
        PCMK_XA_PROVIDER "='heartbeat' />"

static void
no_agent_matches(void **state)
{
    assert_rsc_expression(EXPR_NO_AGENT_MATCHES, pcmk_rc_ok);
}

#define EXPR_NO_CRITERIA_MATCHES    \
        "<" PCMK_XE_RSC_EXPRESSION " " PCMK_XA_ID "='e' />"

static void
no_criteria_matches(void **state)
{
    assert_rsc_expression(EXPR_NO_CRITERIA_MATCHES, pcmk_rc_ok);
}

static void
all_match(void **state)
{
    assert_rsc_expression(EXPR_ALL_MATCH, pcmk_rc_ok);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(id_missing),
                cmocka_unit_test(fail_standard),
                cmocka_unit_test(fail_provider),
                cmocka_unit_test(fail_agent),
                cmocka_unit_test(no_standard_matches),
                cmocka_unit_test(no_provider_matches),
                cmocka_unit_test(no_agent_matches),
                cmocka_unit_test(no_criteria_matches),
                cmocka_unit_test(all_match))

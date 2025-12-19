/*
 * Copyright 2024-2025 the Pacemaker project contributors
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
#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

/*
 * Shared data
 */

static pcmk_rule_input_t rule_input = {
    // These are the only members used to evaluate operation expressions
    .op_name = PCMK_ACTION_MONITOR,
    .op_interval_ms = 10000,
};

/*!
 * \internal
 * \brief Run one test, checking return value
 *
 * \param[in] xml_string   Operation expression XML (<tt>const char *</tt>)
 * \param[in] expected_rc  Assert that evaluation result equals this (\c int)
 */
#define assert_op_expression(xml_string, expected_rc)                       \
    do {                                                                    \
        xmlNode *xml = pcmk__xml_parse(xml_string);                         \
                                                                            \
        assert_int_equal(pcmk__evaluate_op_expression(xml, &rule_input),    \
                         expected_rc);                                      \
        pcmk__xml_free(xml);                                                \
    } while (0)


/*
 * Invalid arguments
 */

#define EXPR_FAIL_BOTH                                      \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_START "' "            \
        PCMK_XA_INTERVAL "='0' />"

static void
null_invalid(void **state)
{
    xmlNode *xml = NULL;

    assert_int_equal(pcmk__evaluate_op_expression(NULL, NULL), EINVAL);

    xml = pcmk__xml_parse(EXPR_FAIL_BOTH);
    assert_int_equal(pcmk__evaluate_op_expression(xml, NULL), EINVAL);
    pcmk__xml_free(xml);

    assert_op_expression(NULL, EINVAL);
}


/*
 * Test PCMK_XA_ID
 */

#define EXPR_ID_MISSING                                 \
        "<" PCMK_XE_OP_EXPRESSION " "                   \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "      \
        PCMK_XA_INTERVAL "='10s' />"

#define EXPR_ID_EMPTY                                   \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='' " \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "      \
        PCMK_XA_INTERVAL "='10s' />"

static void
id_missing(void **state)
{
    assert_op_expression(EXPR_ID_MISSING, pcmk_rc_unpack_error);
    assert_op_expression(EXPR_ID_EMPTY, pcmk_rc_unpack_error);
}


/*
 * Test PCMK_XA_NAME
 */

#define EXPR_NAME_MISSING                                   \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_INTERVAL "='10s' />"

static void
name_missing(void **state)
{
    assert_op_expression(EXPR_NAME_MISSING, pcmk_rc_unpack_error);
}

#define EXPR_MATCH_BOTH                                     \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "          \
        PCMK_XA_INTERVAL "='10s' />"

#define EXPR_EMPTY_NAME                                     \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='' " PCMK_XA_INTERVAL "='10s' />"

static void
input_name_missing(void **state)
{
    rule_input.op_name = NULL;
    assert_op_expression(EXPR_MATCH_BOTH, pcmk_rc_op_unsatisfied);
    assert_op_expression(EXPR_EMPTY_NAME, pcmk_rc_op_unsatisfied);
    rule_input.op_name = PCMK_ACTION_MONITOR;
}

#define EXPR_FAIL_NAME                                      \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_START "' "            \
        PCMK_XA_INTERVAL "='10s' />"

static void
fail_name(void **state)
{
    assert_op_expression(EXPR_FAIL_NAME, pcmk_rc_op_unsatisfied);

    // An empty name is meaningless but accepted, so not an unpack error
    assert_op_expression(EXPR_EMPTY_NAME, pcmk_rc_op_unsatisfied);
}


/*
 * Test PCMK_XA_INTERVAL
 */

#define EXPR_EMPTY_INTERVAL                                 \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "          \
        PCMK_XA_INTERVAL "='' />"

#define EXPR_INVALID_INTERVAL                               \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "          \
        PCMK_XA_INTERVAL "='not-an-interval' />"

static void
invalid_interval(void **state)
{
    assert_op_expression(EXPR_EMPTY_INTERVAL, pcmk_rc_unpack_error);
    assert_op_expression(EXPR_INVALID_INTERVAL, pcmk_rc_unpack_error);
}

#define EXPR_DEFAULT_INTERVAL                               \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' />"

static void
default_interval(void **state)
{
    assert_op_expression(EXPR_DEFAULT_INTERVAL, pcmk_rc_ok);
}

#define EXPR_FAIL_INTERVAL                                  \
        "<" PCMK_XE_OP_EXPRESSION " " PCMK_XA_ID "='e' "    \
        PCMK_XA_NAME "='" PCMK_ACTION_MONITOR "' "          \
        PCMK_XA_INTERVAL "='9s' />"

static void
fail_interval(void **state)
{
    assert_op_expression(EXPR_FAIL_INTERVAL, pcmk_rc_op_unsatisfied);
}


static void
match_both(void **state)
{
    assert_op_expression(EXPR_MATCH_BOTH, pcmk_rc_ok);
}

static void
fail_both(void **state)
{
    assert_op_expression(EXPR_FAIL_BOTH, pcmk_rc_op_unsatisfied);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(id_missing),
                cmocka_unit_test(name_missing),
                cmocka_unit_test(input_name_missing),
                cmocka_unit_test(fail_name),
                cmocka_unit_test(invalid_interval),
                cmocka_unit_test(default_interval),
                cmocka_unit_test(fail_interval),
                cmocka_unit_test(match_both),
                cmocka_unit_test(fail_both))

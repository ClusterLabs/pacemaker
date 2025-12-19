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

#define MATCHED_STRING "server-north"

static const regmatch_t submatches[] = {
    { .rm_so = 0, .rm_eo = 12 }, // %0 = Entire string
    { .rm_so = 7, .rm_eo = 12 }, // %1 = "north"
};

static pcmk_rule_input_t rule_input = {
    // These are the only members used to evaluate attribute expressions

    // Used to replace submatches in attribute name
    .rsc_id = MATCHED_STRING,
    .rsc_id_submatches = submatches,
    .rsc_id_nmatches = 2,

    // Used when source is instance attributes
    .rsc_params = NULL,

    // Used when source is meta-attributes
    .rsc_meta = NULL,

    // Used to get actual value of node attribute
    .node_attrs = NULL,
};

static int
setup(void **state)
{
    rule_input.rsc_params = pcmk__strkey_table(free, free);
    pcmk__insert_dup(rule_input.rsc_params, "foo-param", "bar");
    pcmk__insert_dup(rule_input.rsc_params, "myparam", "different");

    rule_input.rsc_meta = pcmk__strkey_table(free, free);
    pcmk__insert_dup(rule_input.rsc_meta, "foo-meta", "bar");
    pcmk__insert_dup(rule_input.rsc_params, "mymeta", "different");

    rule_input.node_attrs = pcmk__strkey_table(free, free);
    pcmk__insert_dup(rule_input.node_attrs, "foo", "bar");
    pcmk__insert_dup(rule_input.node_attrs, "num", "10");
    pcmk__insert_dup(rule_input.node_attrs, "ver", "3.5.0");
    pcmk__insert_dup(rule_input.node_attrs, "prefer-north", "100");
    pcmk__insert_dup(rule_input.node_attrs, "empty", "");

    return 0;
}

static int
teardown(void **state)
{
    g_hash_table_destroy(rule_input.rsc_params);
    g_hash_table_destroy(rule_input.rsc_meta);
    g_hash_table_destroy(rule_input.node_attrs);
    return 0;
}

/*!
 * \internal
 * \brief Run one test, comparing return value
 *
 * \param[in] xml_string   Node attribute expression XML as string
 *                         (<tt>const char *</tt>)
 * \param[in] expected_rc  Assert that evaluation result equals this (\c int)
 */
#define assert_attr_expression(xml_string, expected_rc)                     \
    do {                                                                    \
        xmlNode *xml = pcmk__xml_parse(xml_string);                         \
                                                                            \
        assert_int_equal(pcmk__evaluate_attr_expression(xml, &rule_input),  \
                         expected_rc);                                      \
        pcmk__xml_free(xml);                                                \
    } while (0)


/*
 * Invalid arguments
 */

#define EXPR_SOURCE_LITERAL_PASSES                      \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' "                         \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_LITERAL "' />"

static void
null_invalid(void **state)
{
    xmlNode *xml = pcmk__xml_parse(EXPR_SOURCE_LITERAL_PASSES);

    assert_int_equal(pcmk__evaluate_attr_expression(NULL, NULL), EINVAL);
    assert_int_equal(pcmk__evaluate_attr_expression(xml, NULL), EINVAL);
    assert_int_equal(pcmk__evaluate_attr_expression(NULL, &rule_input), EINVAL);

    pcmk__xml_free(xml);
}


/*
 * Test PCMK_XA_ID
 */

#define EXPR_ID_MISSING                                 \
        "<" PCMK_XE_EXPRESSION " "                      \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' />"

static void
id_missing(void **state)
{
    assert_attr_expression(EXPR_ID_MISSING, pcmk_rc_unpack_error);
}


/*
 * Test PCMK_XA_ATTRIBUTE
 */

#define EXPR_ATTR_MISSING                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' />"

static void
attr_missing(void **state)
{
    assert_attr_expression(EXPR_ATTR_MISSING, pcmk_rc_unpack_error);
}

#define EXPR_ATTR_SUBMATCH_PASSES                       \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='prefer-%1' "               \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
attr_with_submatch_passes(void **state)
{
    assert_attr_expression(EXPR_ATTR_SUBMATCH_PASSES, pcmk_rc_ok);
}

#define EXPR_ATTR_SUBMATCH_FAILS                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='undefined-%1' "            \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
attr_with_submatch_fails(void **state)
{
    assert_attr_expression(EXPR_ATTR_SUBMATCH_FAILS, pcmk_rc_op_unsatisfied);
}


/*
 * Test PCMK_XA_VALUE_SOURCE
 */

#define EXPR_SOURCE_MISSING                             \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_VALUE "='bar' />"

static void
source_missing(void **state)
{
    // Defaults to literal
    assert_attr_expression(EXPR_SOURCE_MISSING, pcmk_rc_ok);
}

#define EXPR_SOURCE_INVALID                             \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' "                         \
        PCMK_XA_VALUE_SOURCE "='not-a-source' />"

static void
source_invalid(void **state)
{
    assert_attr_expression(EXPR_SOURCE_INVALID, pcmk_rc_unpack_error);
}

static void
source_literal_passes(void **state)
{
    assert_attr_expression(EXPR_SOURCE_LITERAL_PASSES, pcmk_rc_ok);
}

#define EXPR_SOURCE_LITERAL_VALUE_FAILS                 \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='wrong-value' "                 \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_LITERAL "' />"

static void
source_literal_value_fails(void **state)
{
    assert_attr_expression(EXPR_SOURCE_LITERAL_VALUE_FAILS,
                           pcmk_rc_op_unsatisfied);
}

#define EXPR_SOURCE_LITERAL_ATTR_FAILS                  \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='not-an-attribute' "        \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' "                         \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_LITERAL "' />"

static void
source_literal_attr_fails(void **state)
{
    assert_attr_expression(EXPR_SOURCE_LITERAL_ATTR_FAILS,
                           pcmk_rc_op_unsatisfied);
}

#define EXPR_SOURCE_PARAM_MISSING                       \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='not-a-param' "                 \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_PARAM "' />"

static void
source_params_missing(void **state)
{
    assert_attr_expression(EXPR_SOURCE_PARAM_MISSING, pcmk_rc_op_unsatisfied);
}

#define EXPR_SOURCE_PARAM_PASSES                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='foo-param' "                   \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_PARAM "' />"

static void
source_params_passes(void **state)
{
    assert_attr_expression(EXPR_SOURCE_PARAM_PASSES, pcmk_rc_ok);
}

#define EXPR_SOURCE_PARAM_FAILS                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='myparam' "                     \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_PARAM "' />"

static void
source_params_fails(void **state)
{
    assert_attr_expression(EXPR_SOURCE_PARAM_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_SOURCE_META_MISSING                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='not-a-meta' "                  \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_META "' />"

static void
source_meta_missing(void **state)
{
    assert_attr_expression(EXPR_SOURCE_META_MISSING, pcmk_rc_op_unsatisfied);
}

#define EXPR_SOURCE_META_PASSES                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='foo-meta' "                    \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_META "' />"

static void
source_meta_passes(void **state)
{
    assert_attr_expression(EXPR_SOURCE_META_PASSES, pcmk_rc_ok);
}

#define EXPR_SOURCE_META_FAILS                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='mymeta' "                      \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_META "' />"

static void
source_meta_fails(void **state)
{
    assert_attr_expression(EXPR_SOURCE_META_FAILS, pcmk_rc_op_unsatisfied);
}


/*
 * Test PCMK_XA_TYPE
 */

#define EXPR_TYPE_DEFAULT_NUMBER                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='2.5' />"

static void
type_default_number(void **state)
{
    // Defaults to number for "gt" if either value contains a decimal point
    assert_attr_expression(EXPR_TYPE_DEFAULT_NUMBER, pcmk_rc_ok);
}

#define EXPR_TYPE_DEFAULT_INT                           \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='2' />"

static void
type_default_int(void **state)
{
    // Defaults to integer for "gt" if neither value contains a decimal point
    assert_attr_expression(EXPR_TYPE_DEFAULT_INT, pcmk_rc_ok);
}

#define EXPR_TYPE_INVALID                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='not-a-value' "                  \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_VALUE "='bar' />"

static void
type_invalid(void **state)
{
    assert_attr_expression(EXPR_TYPE_INVALID, pcmk_rc_unpack_error);
}

#define EXPR_TYPE_STRING_PASSES                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_STRING "' "        \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_VALUE "='bar' />"

static void
type_string_passes(void **state)
{
    assert_attr_expression(EXPR_TYPE_STRING_PASSES, pcmk_rc_ok);
}

#define EXPR_TYPE_STRING_FAILS                          \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_STRING "' "        \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_VALUE "='bat' />"

static void
type_string_fails(void **state)
{
    assert_attr_expression(EXPR_TYPE_STRING_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_TYPE_INTEGER_PASSES                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10' />"

static void
type_integer_passes(void **state)
{
    assert_attr_expression(EXPR_TYPE_INTEGER_PASSES, pcmk_rc_ok);
}

#define EXPR_TYPE_INTEGER_FAILS                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='11' />"

static void
type_integer_fails(void **state)
{
    assert_attr_expression(EXPR_TYPE_INTEGER_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_TYPE_INTEGER_TRUNCATION                    \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10.5' />"

static void
type_integer_truncation(void **state)
{
    assert_attr_expression(EXPR_TYPE_INTEGER_TRUNCATION, pcmk_rc_ok);
}

#define EXPR_TYPE_NUMBER_PASSES                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_NUMBER "' "        \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10.0' />"

static void
type_number_passes(void **state)
{
    assert_attr_expression(EXPR_TYPE_NUMBER_PASSES, pcmk_rc_ok);
}

#define EXPR_TYPE_NUMBER_FAILS                          \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_NUMBER "' "        \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10.1' />"

static void
type_number_fails(void **state)
{
    assert_attr_expression(EXPR_TYPE_NUMBER_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_TYPE_VERSION_PASSES                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_VERSION "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "       \
        PCMK_XA_ATTRIBUTE "='ver' "                     \
        PCMK_XA_VALUE "='3.4.9' />"

static void
type_version_passes(void **state)
{
    assert_attr_expression(EXPR_TYPE_VERSION_PASSES, pcmk_rc_ok);
}

#define EXPR_TYPE_VERSION_EQUALITY                      \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_VERSION "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='ver' "                     \
        PCMK_XA_VALUE "='3.5' />"

static void
type_version_equality(void **state)
{
    assert_attr_expression(EXPR_TYPE_VERSION_EQUALITY, pcmk_rc_ok);
}

#define EXPR_TYPE_VERSION_FAILS                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_VERSION "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GTE "' "      \
        PCMK_XA_ATTRIBUTE "='ver' "                     \
        PCMK_XA_VALUE "='4.0' />"

static void
type_version_fails(void **state)
{
    assert_attr_expression(EXPR_TYPE_VERSION_FAILS, pcmk_rc_before_range);
}

/*
 * Test PCMK_XA_OPERATION
 */

#define EXPR_OP_MISSING                                 \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_VALUE "='bar' />"

static void
op_missing(void **state)
{
    assert_attr_expression(EXPR_OP_MISSING, pcmk_rc_unpack_error);
}

#define EXPR_OP_INVALID                                 \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='not-an-operation' "        \
        PCMK_XA_VALUE "='bar' />"

static void
op_invalid(void **state)
{
    assert_attr_expression(EXPR_OP_INVALID, pcmk_rc_unpack_error);
}

#define EXPR_OP_LT_PASSES                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='20' />"

static void
op_lt_passes(void **state)
{
    assert_attr_expression(EXPR_OP_LT_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_LT_FAILS                                \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='2' />"

static void
op_lt_fails(void **state)
{
    assert_attr_expression(EXPR_OP_LT_FAILS, pcmk_rc_after_range);
}

#define EXPR_OP_GT_PASSES                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='2' />"

static void
op_gt_passes(void **state)
{
    assert_attr_expression(EXPR_OP_GT_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_GT_FAILS                                \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='20' />"

static void
op_gt_fails(void **state)
{
    assert_attr_expression(EXPR_OP_GT_FAILS, pcmk_rc_before_range);
}

#define EXPR_OP_LTE_LT_PASSES                           \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LTE "' "      \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='20' />"

static void
op_lte_lt_passes(void **state)
{
    assert_attr_expression(EXPR_OP_LTE_LT_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_LTE_EQ_PASSES                           \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LTE "' "      \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10' />"

static void
op_lte_eq_passes(void **state)
{
    assert_attr_expression(EXPR_OP_LTE_EQ_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_LTE_FAILS                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LTE "' "      \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='9' />"

static void
op_lte_fails(void **state)
{
    assert_attr_expression(EXPR_OP_LTE_FAILS, pcmk_rc_after_range);
}

#define EXPR_OP_GTE_GT_PASSES                           \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GTE "' "      \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='1' />"

static void
op_gte_gt_passes(void **state)
{
    assert_attr_expression(EXPR_OP_GTE_GT_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_GTE_EQ_PASSES                           \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GTE "' "      \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10' />"

static void
op_gte_eq_passes(void **state)
{
    assert_attr_expression(EXPR_OP_GTE_EQ_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_GTE_FAILS                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_GTE "' "      \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='11' />"

static void
op_gte_fails(void **state)
{
    assert_attr_expression(EXPR_OP_GTE_FAILS, pcmk_rc_before_range);
}

// This also tests that string is used if values aren't parseable as numbers
#define EXPR_OP_EQ_PASSES                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_NUMBER "' "        \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='bar' "                         \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_LITERAL "' />"

static void
op_eq_passes(void **state)
{
    assert_attr_expression(EXPR_OP_EQ_PASSES, pcmk_rc_ok);
}

#define EXPR_EQ_EMPTY_VS_EMPTY_PASSES                   \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='empty' "                   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='' />"

static void
op_eq_empty_vs_empty_passes(void **state)
{
    assert_attr_expression(EXPR_EQ_EMPTY_VS_EMPTY_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_EQ_FAILS                                \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='bar' />"

static void
op_eq_fails(void **state)
{
    assert_attr_expression(EXPR_OP_EQ_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_EQ_UNDEFINED_VS_EMPTY_FAILS                \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='boo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' "       \
        PCMK_XA_VALUE "='' />"

static void
op_eq_undefined_vs_empty_fails(void **state)
{
    assert_attr_expression(EXPR_EQ_UNDEFINED_VS_EMPTY_FAILS,
                           pcmk_rc_op_unsatisfied);
}

#define EXPR_OP_NE_PASSES                               \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_STRING "' "        \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_NE "' "       \
        PCMK_XA_VALUE "='bat' "                         \
        PCMK_XA_VALUE_SOURCE "='" PCMK_VALUE_LITERAL "' />"

static void
op_ne_passes(void **state)
{
    assert_attr_expression(EXPR_OP_NE_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_NE_FAILS                                \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_TYPE "='" PCMK_VALUE_INTEGER "' "       \
        PCMK_XA_OPERATION "='" PCMK_VALUE_NE "' "       \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_VALUE "='10' />"

static void
op_ne_fails(void **state)
{
    assert_attr_expression(EXPR_OP_NE_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_OP_DEFINED_PASSES                          \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
op_defined_passes(void **state)
{
    assert_attr_expression(EXPR_OP_DEFINED_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_DEFINED_EMPTY_PASSES                    \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='empty' "                   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
op_defined_empty_passes(void **state)
{
    assert_attr_expression(EXPR_OP_DEFINED_EMPTY_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_DEFINED_FAILS                           \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='boo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
op_defined_fails(void **state)
{
    assert_attr_expression(EXPR_OP_DEFINED_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_OP_DEFINED_WITH_VALUE                      \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_VALUE "='bar' "                         \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
op_defined_with_value(void **state)
{
    assert_attr_expression(EXPR_OP_DEFINED_WITH_VALUE, pcmk_rc_unpack_error);
}

#define EXPR_OP_UNDEFINED_PASSES                        \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='boo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_NOT_DEFINED "' />"

static void
op_undefined_passes(void **state)
{
    assert_attr_expression(EXPR_OP_UNDEFINED_PASSES, pcmk_rc_ok);
}

#define EXPR_OP_UNDEFINED_FAILS                         \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='foo' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_NOT_DEFINED "' />"

static void
op_undefined_fails(void **state)
{
    assert_attr_expression(EXPR_OP_UNDEFINED_FAILS, pcmk_rc_op_unsatisfied);
}

#define EXPR_OP_UNDEFINED_EMPTY_FAILS                   \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='empty' "                   \
        PCMK_XA_OPERATION "='" PCMK_VALUE_NOT_DEFINED "' />"

static void
op_undefined_empty_fails(void **state)
{
    assert_attr_expression(EXPR_OP_UNDEFINED_EMPTY_FAILS,
                           pcmk_rc_op_unsatisfied);
}


/*
 * Test PCMK_XA_VALUE
 */

#define EXPR_VALUE_MISSING_DEFINED_OK                   \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='num' "                     \
        PCMK_XA_OPERATION "='" PCMK_VALUE_DEFINED "' />"

static void
value_missing_defined_ok(void **state)
{
    assert_attr_expression(EXPR_VALUE_MISSING_DEFINED_OK, pcmk_rc_ok);
}

#define EXPR_VALUE_MISSING_EQ_FAILS                     \
        "<" PCMK_XE_EXPRESSION " " PCMK_XA_ID "='e' "   \
        PCMK_XA_ATTRIBUTE "='not-an-attr' "             \
        PCMK_XA_OPERATION "='" PCMK_VALUE_EQ "' />"

static void
value_missing_eq_fails(void **state)
{
    assert_attr_expression(EXPR_VALUE_MISSING_EQ_FAILS, pcmk_rc_unpack_error);
}


#define expr_test(f) cmocka_unit_test_setup_teardown(f, setup, teardown)

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_invalid),
                expr_test(id_missing),
                expr_test(attr_missing),
                expr_test(attr_with_submatch_passes),
                expr_test(attr_with_submatch_fails),
                expr_test(source_missing),
                expr_test(source_invalid),
                expr_test(source_literal_passes),
                expr_test(source_literal_value_fails),
                expr_test(source_literal_attr_fails),
                expr_test(source_params_missing),
                expr_test(source_params_passes),
                expr_test(source_params_fails),
                expr_test(source_meta_missing),
                expr_test(source_meta_passes),
                expr_test(source_meta_fails),
                expr_test(type_default_number),
                expr_test(type_default_int),
                expr_test(type_invalid),
                expr_test(type_string_passes),
                expr_test(type_string_fails),
                expr_test(type_integer_passes),
                expr_test(type_integer_fails),
                expr_test(type_integer_truncation),
                expr_test(type_number_passes),
                expr_test(type_number_fails),
                expr_test(type_version_passes),
                expr_test(type_version_equality),
                expr_test(type_version_fails),
                expr_test(op_missing),
                expr_test(op_invalid),
                expr_test(op_lt_passes),
                expr_test(op_lt_fails),
                expr_test(op_gt_passes),
                expr_test(op_gt_fails),
                expr_test(op_lte_lt_passes),
                expr_test(op_lte_eq_passes),
                expr_test(op_lte_fails),
                expr_test(op_gte_gt_passes),
                expr_test(op_gte_eq_passes),
                expr_test(op_gte_fails),
                expr_test(op_eq_passes),
                expr_test(op_eq_empty_vs_empty_passes),
                expr_test(op_eq_fails),
                expr_test(op_eq_undefined_vs_empty_fails),
                expr_test(op_ne_passes),
                expr_test(op_ne_fails),
                expr_test(op_defined_passes),
                expr_test(op_defined_empty_passes),
                expr_test(op_defined_fails),
                expr_test(op_defined_with_value),
                expr_test(op_undefined_passes),
                expr_test(op_undefined_fails),
                expr_test(op_undefined_empty_fails),
                expr_test(value_missing_defined_ok),
                expr_test(value_missing_eq_fails))

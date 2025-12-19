/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <glib.h>

#include <crm/common/xml.h>
#include <crm/common/unittest_internal.h>
#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Run one test, checking return value
 *
 * \param[in] xml          Date expression XML
 * \param[in] now_s        Time to evaluate expression with
 * \param[in] expected_rc  Assert that evaluation result equals this
 */
static void
assert_date_expr(const xmlNode *xml, const char *now_s, int expected_rc)
{
    crm_time_t *now = crm_time_new(now_s);

    assert_int_equal(pcmk__evaluate_date_expression(xml, now, NULL),
                     expected_rc);
    crm_time_free(now);
}

/*!
 * \internal
 * \brief Run one test, checking return value and output argument
 *
 * \param[in] xml            Date expression XML
 * \param[in] now_s          Time to evaluate expression with
 * \param[in] next_change_s  Initialize next change time with this time
 * \param[in] expected_s     Time that next change should be after expression
 *                           evaluation
 * \param[in] expected_rc    Assert that evaluation result equals this
 */
static void
assert_date_expr_change(const xmlNode *xml, const char *now_s,
                        const char *next_change_s, const char *expected_s,
                        int expected_rc)
{
    crm_time_t *now = crm_time_new(now_s);
    crm_time_t *next_change = crm_time_new(next_change_s);
    crm_time_t *expected = crm_time_new(expected_s);

    assert_int_equal(pcmk__evaluate_date_expression(xml, now, next_change),
                     expected_rc);

    assert_int_equal(crm_time_compare(next_change, expected), 0);

    crm_time_free(now);
    crm_time_free(next_change);
    crm_time_free(expected);
}

#define EXPR_LT_VALID                                   \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' "       \
        PCMK_XA_END "='2024-02-01 15:00:00' />"

static void
null_invalid(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_LT_VALID);
    crm_time_t *t = crm_time_new("2024-02-01");

    assert_int_equal(pcmk__evaluate_date_expression(NULL, NULL, NULL), EINVAL);
    assert_int_equal(pcmk__evaluate_date_expression(xml, NULL, NULL), EINVAL);
    assert_int_equal(pcmk__evaluate_date_expression(NULL, t, NULL), EINVAL);

    crm_time_free(t);
    pcmk__xml_free(xml);
}

static void
null_next_change_ok(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_LT_VALID);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_within_range);
    pcmk__xml_free(xml);
}

#define EXPR_ID_MISSING                             \
    "<" PCMK_XE_DATE_EXPRESSION " "                 \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' "   \
        PCMK_XA_END "='2024-02-01 15:00:00' />"

static void
id_missing(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_ID_MISSING);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_OP_INVALID                                 \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
        PCMK_XA_OPERATION "='not-a-choice' />"

static void
op_invalid(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_OP_INVALID);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_LT_MISSING_END                             \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
        PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' />"

static void
lt_missing_end(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_LT_MISSING_END);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_LT_INVALID_END                             \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_LT "' "           \
    PCMK_XA_END "='not-a-datetime' />"

static void
lt_invalid_end(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_LT_INVALID_END);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

static void
lt_valid(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_LT_VALID);

    // Now and next change are both before end
    assert_date_expr_change(xml, "2023-01-01 05:00:00", "2024-02-01 10:00:00",
                            "2024-02-01 10:00:00", pcmk_rc_within_range);

    // Now is before end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 14:59:59", "2024-02-01 18:00:00",
                            "2024-02-01 15:00:00", pcmk_rc_within_range);

    // Now is equal to end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 15:00:00", "2024-02-01 20:00:00",
                            "2024-02-01 20:00:00", pcmk_rc_after_range);

    // Now and next change are both after end
    assert_date_expr_change(xml, "2024-03-01 12:00:00", "2024-02-01 20:00:00",
                            "2024-02-01 20:00:00", pcmk_rc_after_range);

    pcmk__xml_free(xml);
}

#define EXPR_GT_MISSING_START                           \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' />"

static void
gt_missing_start(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_GT_MISSING_START);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_GT_INVALID_START                           \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "           \
    PCMK_XA_START "='not-a-datetime' />"

static void
gt_invalid_start(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_GT_INVALID_START);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_GT_VALID                                   \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_GT "' "           \
    PCMK_XA_START "='2024-02-01 12:00:00' />"

static void
gt_valid(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_GT_VALID);

    // Now and next change are both before start
    assert_date_expr_change(xml, "2024-01-01 04:30:05", "2024-01-01 11:00:00",
                            "2024-01-01 11:00:00", pcmk_rc_before_range);

    // Now is before start, next change is after start
    assert_date_expr_change(xml, "2024-02-01 11:59:59", "2024-02-01 18:00:00",
                            "2024-02-01 12:00:01", pcmk_rc_before_range);

    // Now is equal to start, next change is after start
    assert_date_expr_change(xml, "2024-02-01 12:00:00", "2024-02-01 18:00:00",
                            "2024-02-01 12:00:01", pcmk_rc_before_range);

    // Now is one second after start, next change is after start
    assert_date_expr_change(xml, "2024-02-01 12:00:01", "2024-02-01 18:00:00",
                            "2024-02-01 18:00:00", pcmk_rc_within_range);

    // t is after start, next change is after start
    assert_date_expr_change(xml, "2024-03-01 05:03:11", "2024-04-04 04:04:04",
                            "2024-04-04 04:04:04", pcmk_rc_within_range);

    pcmk__xml_free(xml);
}

#define EXPR_RANGE_MISSING                              \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' />"

static void
range_missing(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_MISSING);
    crm_time_t *t = crm_time_new("2024-01-01");

    assert_int_equal(pcmk__evaluate_date_expression(xml, t, NULL),
                     pcmk_rc_unpack_error);

    crm_time_free(t);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_INVALID_START_INVALID_END            \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='not-a-date' "                      \
    PCMK_XA_END "='not-a-date' />"

static void
range_invalid_start_invalid_end(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_INVALID_START_INVALID_END);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_INVALID_START_ONLY                   \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='not-a-date' />"

static void
range_invalid_start_only(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_INVALID_START_ONLY);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_START_ONLY                     \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00' />"

static void
range_valid_start_only(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_VALID_START_ONLY);

    // Now and next change are before start
    assert_date_expr_change(xml, "2024-01-01 04:30:05", "2024-01-01 11:00:00",
                            "2024-01-01 11:00:00", pcmk_rc_before_range);

    // Now is before start, next change is after start
    assert_date_expr_change(xml, "2024-02-01 11:59:59", "2024-02-01 18:00:00",
                            "2024-02-01 12:00:00", pcmk_rc_before_range);

    // Now is equal to start, next change is after start
    assert_date_expr_change(xml, "2024-02-01 12:00:00", "2024-02-01 18:00:00",
                            "2024-02-01 18:00:00", pcmk_rc_within_range);

    // Now and next change are after start
    assert_date_expr_change(xml, "2024-03-01 05:03:11", "2024-04-04 04:04:04",
                            "2024-04-04 04:04:04", pcmk_rc_within_range);

    pcmk__xml_free(xml);
}

#define EXPR_RANGE_INVALID_END_ONLY                   \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_END "='not-a-date' />"

static void
range_invalid_end_only(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_INVALID_END_ONLY);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_END_ONLY                     \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_END "='2024-02-01 15:00:00' />"

static void
range_valid_end_only(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_VALID_END_ONLY);

    // Now and next change are before end
    assert_date_expr_change(xml, "2024-01-01 04:30:05", "2024-01-01 11:00:00",
                            "2024-01-01 11:00:00", pcmk_rc_within_range);

    // Now is before end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 14:59:59", "2024-02-01 18:00:00",
                            "2024-02-01 15:00:01", pcmk_rc_within_range);

    // Now is equal to end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 15:00:00", "2024-02-01 18:00:00",
                            "2024-02-01 15:00:01", pcmk_rc_within_range);

    // Now and next change are after end
    assert_date_expr_change(xml, "2024-02-01 15:00:01", "2024-04-04 04:04:04",
                            "2024-04-04 04:04:04", pcmk_rc_after_range);

    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_START_INVALID_END              \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00' "             \
    PCMK_XA_END "='not-a-date' />"

static void
range_valid_start_invalid_end(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_VALID_START_INVALID_END);

    assert_date_expr(xml, "2024-01-01 04:30:05", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_INVALID_START_VALID_END              \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='not-a-date' "                      \
    PCMK_XA_END "='2024-02-01 15:00:00' />"

static void
range_invalid_start_valid_end(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_INVALID_START_VALID_END);

    assert_date_expr(xml, "2024-01-01 04:30:05", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_START_VALID_END                \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00' "             \
    PCMK_XA_END "='2024-02-01 15:00:00' />"

static void
range_valid_start_valid_end(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_VALID_START_VALID_END);

    // Now and next change are before start
    assert_date_expr_change(xml, "2024-01-01 04:30:05", "2024-01-01 11:00:00",
                            "2024-01-01 11:00:00", pcmk_rc_before_range);

    // Now is before start, next change is between start and end
    assert_date_expr_change(xml, "2024-02-01 11:59:59", "2024-02-01 14:00:00",
                            "2024-02-01 12:00:00", pcmk_rc_before_range);

    // Now is equal to start, next change is between start and end
    assert_date_expr_change(xml, "2024-02-01 12:00:00", "2024-02-01 14:30:00",
                            "2024-02-01 14:30:00", pcmk_rc_within_range);

    // Now is between start and end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 14:03:11", "2024-04-04 04:04:04",
                            "2024-02-01 15:00:01", pcmk_rc_within_range);

    // Now is equal to end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 15:00:00", "2028-04-04 04:04:04",
                            "2024-02-01 15:00:01", pcmk_rc_within_range);

    // Now and next change are after end
    assert_date_expr_change(xml, "2024-02-01 15:00:01", "2028-04-04 04:04:04",
                            "2028-04-04 04:04:04", pcmk_rc_after_range);

    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_START_INVALID_DURATION         \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00'>"             \
    "<" PCMK_XE_DURATION " " PCMK_XA_ID "='d' "         \
    PCMK_XA_HOURS "='not-a-number' />"                  \
    "</" PCMK_XE_DATE_EXPRESSION ">"

static void
range_valid_start_invalid_duration(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_VALID_START_INVALID_DURATION);

    assert_date_expr(xml, "2024-02-01 04:30:05", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_START_VALID_DURATION           \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00'>"             \
    "<" PCMK_XE_DURATION " " PCMK_XA_ID "='d' "         \
    PCMK_XA_HOURS "='3' />"                             \
    "</" PCMK_XE_DATE_EXPRESSION ">"

static void
range_valid_start_valid_duration(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_RANGE_VALID_START_VALID_DURATION);

    // Now and next change are before start
    assert_date_expr_change(xml, "2024-01-01 04:30:05", "2024-01-01 11:00:00",
                            "2024-01-01 11:00:00", pcmk_rc_before_range);

    // Now is before start, next change is between start and end
    assert_date_expr_change(xml, "2024-02-01 11:59:59", "2024-02-01 14:00:00",
                            "2024-02-01 12:00:00", pcmk_rc_before_range);

    // Now is equal to start, next change is between start and end
    assert_date_expr_change(xml, "2024-02-01 12:00:00", "2024-02-01 14:30:00",
                            "2024-02-01 14:30:00", pcmk_rc_within_range);

    // Now is between start and end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 14:03:11", "2024-04-04 04:04:04",
                            "2024-02-01 15:00:01", pcmk_rc_within_range);

    // Now is equal to end, next change is after end
    assert_date_expr_change(xml, "2024-02-01 15:00:00", "2028-04-04 04:04:04",
                            "2024-02-01 15:00:01", pcmk_rc_within_range);

    // Now and next change are after end
    assert_date_expr_change(xml, "2024-02-01 15:00:01", "2028-04-04 04:04:04",
                            "2028-04-04 04:04:04", pcmk_rc_after_range);

    pcmk__xml_free(xml);
}

#define EXPR_RANGE_VALID_START_DURATION_MISSING_ID      \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='d' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_IN_RANGE "' "     \
    PCMK_XA_START "='2024-02-01 12:00:00'>"             \
    "<" PCMK_XE_DURATION " " PCMK_XA_HOURS "='3' />"    \
    "</" PCMK_XE_DATE_EXPRESSION ">"

static void
range_valid_start_duration_missing_id(void **state)
{
    xmlNodePtr xml = NULL;

    xml = pcmk__xml_parse(EXPR_RANGE_VALID_START_DURATION_MISSING_ID);

    assert_date_expr(xml, "2024-02-01 04:30:05", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_SPEC_MISSING                               \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_DATE_SPEC "' />"

static void
spec_missing(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_SPEC_MISSING);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_SPEC_INVALID                               \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_DATE_SPEC "'>"    \
    "<" PCMK_XE_DATE_SPEC " " PCMK_XA_ID "='s' "        \
    PCMK_XA_MONTHS "='not-a-number'/>"                  \
    "</" PCMK_XE_DATE_EXPRESSION ">"

static void
spec_invalid(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_SPEC_INVALID);

    assert_date_expr(xml, "2024-01-01", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

#define EXPR_SPEC_VALID                                 \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_DATE_SPEC "'>"    \
    "<" PCMK_XE_DATE_SPEC " " PCMK_XA_ID "='s' "        \
    PCMK_XA_MONTHS "='2'/>"                             \
    "</" PCMK_XE_DATE_EXPRESSION ">"

static void
spec_valid(void **state)
{
    // date_spec does not currently support next_change
    xmlNodePtr xml = pcmk__xml_parse(EXPR_SPEC_VALID);

    // Now is just before spec start
    assert_date_expr(xml, "2024-01-01 23:59:59", pcmk_rc_before_range);

    // Now matches spec start
    assert_date_expr(xml, "2024-02-01 00:00:00", pcmk_rc_ok);

    // Now is within spec range
    assert_date_expr(xml, "2024-02-22 22:22:22", pcmk_rc_ok);

    // Now matches spec end
    assert_date_expr(xml, "2024-02-29 23:59:59", pcmk_rc_ok);

    // Now is just past spec end
    assert_date_expr(xml, "2024-03-01 00:00:00", pcmk_rc_after_range);

    pcmk__xml_free(xml);
}

#define EXPR_SPEC_MISSING_ID                            \
    "<" PCMK_XE_DATE_EXPRESSION " " PCMK_XA_ID "='e' "  \
    PCMK_XA_OPERATION "='" PCMK_VALUE_DATE_SPEC "'>"    \
    "<" PCMK_XE_DATE_SPEC " "                           \
    PCMK_XA_MONTHS "='2'/>"                             \
    "</" PCMK_XE_DATE_EXPRESSION ">"

static void
spec_missing_id(void **state)
{
    xmlNodePtr xml = pcmk__xml_parse(EXPR_SPEC_MISSING_ID);

    assert_date_expr(xml, "2024-01-01 23:59:59", pcmk_rc_unpack_error);
    pcmk__xml_free(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, pcmk__xml_test_teardown_group,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(null_next_change_ok),
                cmocka_unit_test(id_missing),
                cmocka_unit_test(op_invalid),
                cmocka_unit_test(lt_missing_end),
                cmocka_unit_test(lt_invalid_end),
                cmocka_unit_test(lt_valid),
                cmocka_unit_test(gt_missing_start),
                cmocka_unit_test(gt_invalid_start),
                cmocka_unit_test(gt_valid),
                cmocka_unit_test(range_missing),
                cmocka_unit_test(range_invalid_start_invalid_end),
                cmocka_unit_test(range_invalid_start_only),
                cmocka_unit_test(range_valid_start_only),
                cmocka_unit_test(range_invalid_end_only),
                cmocka_unit_test(range_valid_end_only),
                cmocka_unit_test(range_valid_start_invalid_end),
                cmocka_unit_test(range_invalid_start_valid_end),
                cmocka_unit_test(range_valid_start_valid_end),
                cmocka_unit_test(range_valid_start_invalid_duration),
                cmocka_unit_test(range_valid_start_valid_duration),
                cmocka_unit_test(range_valid_start_duration_missing_id),
                cmocka_unit_test(spec_missing),
                cmocka_unit_test(spec_invalid),
                cmocka_unit_test(spec_valid),
                cmocka_unit_test(spec_missing_id))

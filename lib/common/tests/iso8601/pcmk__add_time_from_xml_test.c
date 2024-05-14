/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libxml/tree.h>    // xmlNode

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>
#include <crm/common/iso8601_internal.h>
#include <crm/common/xml.h>
#include "../../crmcommon_private.h"

#define ALL_VALID "<duration id=\"duration1\" years=\"1\" months=\"2\" "   \
                   "weeks=\"3\" days=\"-1\" hours=\"1\" minutes=\"1\" "      \
                   "seconds=\"1\" />"

#define YEARS_INVALID "<duration id=\"duration1\" years=\"not-a-number\" />"

#define YEARS_TOO_BIG "<duration id=\"duration1\" years=\"2222222222\" />"

#define YEARS_TOO_SMALL "<duration id=\"duration1\" years=\"-2222222222\" />"

static void
null_time_invalid(void **state)
{
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(NULL, pcmk__time_years, xml),
                     EINVAL);
    free_xml(xml);
}

static void
null_xml_ok(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = pcmk_copy_time(t);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_years, NULL),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
}

static void
invalid_component(void **state)
{
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(NULL, pcmk__time_unknown, xml),
                     EINVAL);
    free_xml(xml);
}

static void
missing_attr(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = pcmk_copy_time(t);
    xmlNode *xml = pcmk__xml_parse(YEARS_INVALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_months, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
invalid_attr(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = pcmk_copy_time(t);
    xmlNode *xml = pcmk__xml_parse(YEARS_INVALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_years, xml),
                     pcmk_rc_unpack_error);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
out_of_range_attr(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = pcmk_copy_time(t);
    xmlNode *xml = NULL;

    xml = pcmk__xml_parse(YEARS_TOO_BIG);
    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_years, xml), ERANGE);
    assert_int_equal(crm_time_compare(t, reference), 0);
    free_xml(xml);

    xml = pcmk__xml_parse(YEARS_TOO_SMALL);
    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_years, xml), ERANGE);
    assert_int_equal(crm_time_compare(t, reference), 0);
    free_xml(xml);

    crm_time_free(t);
    crm_time_free(reference);
}

static void
add_years(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2025-01-01 15:00:00");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_years, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
add_months(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2024-03-01 15:00:00");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_months, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
add_weeks(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2024-01-22 15:00:00");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_weeks, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
add_days(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2023-12-31 15:00:00");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_days, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
add_hours(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2024-01-01 16:00:00");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_hours, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
add_minutes(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2024-01-01 15:01:00");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_minutes, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

static void
add_seconds(void **state)
{
    crm_time_t *t = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *reference = crm_time_new("2024-01-01 15:00:01");
    xmlNode *xml = pcmk__xml_parse(ALL_VALID);

    assert_int_equal(pcmk__add_time_from_xml(t, pcmk__time_seconds, xml),
                     pcmk_rc_ok);
    assert_int_equal(crm_time_compare(t, reference), 0);

    crm_time_free(t);
    crm_time_free(reference);
    free_xml(xml);
}

PCMK__UNIT_TEST(pcmk__xml_test_setup_group, NULL,
                cmocka_unit_test(null_time_invalid),
                cmocka_unit_test(null_xml_ok),
                cmocka_unit_test(invalid_component),
                cmocka_unit_test(missing_attr),
                cmocka_unit_test(invalid_attr),
                cmocka_unit_test(out_of_range_attr),
                cmocka_unit_test(add_years),
                cmocka_unit_test(add_months),
                cmocka_unit_test(add_weeks),
                cmocka_unit_test(add_days),
                cmocka_unit_test(add_hours),
                cmocka_unit_test(add_minutes),
                cmocka_unit_test(add_seconds));

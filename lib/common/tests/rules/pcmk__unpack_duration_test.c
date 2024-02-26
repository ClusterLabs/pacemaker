/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>
#include <crm/common/xml.h>
#include "../../crmcommon_private.h"

#define MONTHS_TO_SECONDS "months=\"2\" weeks=\"3\" days=\"-1\" "           \
                          "hours=\"1\" minutes=\"1\" seconds=\"1\" />"

#define ALL_VALID "<duration id=\"duration1\" years=\"1\" " MONTHS_TO_SECONDS

#define NO_ID     "<duration years=\"1\" " MONTHS_TO_SECONDS

#define YEARS_INVALID "<duration id=\"duration1\" years=\"not-a-number\" "  \
                      MONTHS_TO_SECONDS

static void
null_invalid(void **state)
{
    xmlNode *duration = string2xml(ALL_VALID);
    crm_time_t *start = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *end = NULL;

    assert_int_equal(pcmk__unpack_duration(NULL, NULL, NULL), EINVAL);
    assert_int_equal(pcmk__unpack_duration(duration, NULL, NULL), EINVAL);
    assert_int_equal(pcmk__unpack_duration(duration, start, NULL), EINVAL);
    assert_int_equal(pcmk__unpack_duration(duration, NULL, &end), EINVAL);
    assert_int_equal(pcmk__unpack_duration(NULL, start, NULL), EINVAL);
    assert_int_equal(pcmk__unpack_duration(NULL, start, &end), EINVAL);
    assert_int_equal(pcmk__unpack_duration(NULL, NULL, &end), EINVAL);

    crm_time_free(start);
    free_xml(duration);
}

static void
nonnull_end_invalid(void **state)
{
    xmlNode *duration = string2xml(ALL_VALID);
    crm_time_t *start = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *end = crm_time_new("2024-01-01 15:00:01");

    assert_int_equal(pcmk__unpack_duration(duration, start, &end), EINVAL);

    crm_time_free(start);
    crm_time_free(end);
    free_xml(duration);
}

static void
no_id(void **state)
{
    xmlNode *duration = string2xml(NO_ID);
    crm_time_t *start = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *end = NULL;
    crm_time_t *reference = crm_time_new("2025-03-21 16:01:01");

    assert_int_equal(pcmk__unpack_duration(duration, start, &end), pcmk_rc_ok);
    assert_int_equal(crm_time_compare(end, reference), 0);

    crm_time_free(start);
    crm_time_free(end);
    crm_time_free(reference);
    free_xml(duration);
}

static void
years_invalid(void **state)
{
    xmlNode *duration = string2xml(YEARS_INVALID);
    crm_time_t *start = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *end = NULL;
    crm_time_t *reference = crm_time_new("2024-03-21 16:01:01");

    assert_int_equal(pcmk__unpack_duration(duration, start, &end),
                     pcmk_rc_unpack_error);
    assert_int_equal(crm_time_compare(end, reference), 0);

    crm_time_free(start);
    crm_time_free(end);
    crm_time_free(reference);
    free_xml(duration);
}

static void
all_valid(void **state)
{
    xmlNode *duration = string2xml(ALL_VALID);
    crm_time_t *start = crm_time_new("2024-01-01 15:00:00");
    crm_time_t *end = NULL;
    crm_time_t *reference = crm_time_new("2025-03-21 16:01:01");

    assert_int_equal(pcmk__unpack_duration(duration, start, &end), pcmk_rc_ok);
    assert_int_equal(crm_time_compare(end, reference), 0);

    crm_time_free(start);
    crm_time_free(end);
    crm_time_free(reference);
    free_xml(duration);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_invalid),
                cmocka_unit_test(nonnull_end_invalid),
                cmocka_unit_test(no_id),
                cmocka_unit_test(years_invalid),
                cmocka_unit_test(all_valid))

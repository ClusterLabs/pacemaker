/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/unittest_internal.h>

#include <crm/common/iso8601.h>
#include "crmcommon_private.h"

static void
empty_arg(void **state)
{
    assert_null(crm_time_parse_duration(NULL));
    assert_null(crm_time_parse_duration(""));
}

static void
invalid_arg(void **state)
{
    // Valid except doesn't start with P
    assert_null(crm_time_parse_duration("X3Y6M4DT12H30M5S"));

    // Illegal character after P
    assert_null(crm_time_parse_duration("P"));
    assert_null(crm_time_parse_duration("P 3Y6M4DT12H30M5S"));
    assert_null(crm_time_parse_duration("PX3Y6M4DT12H30M5S"));

    // Integer overflow
    assert_null(crm_time_parse_duration("P2147483648Y6M4DT12H30M5S"));
    assert_null(crm_time_parse_duration("P3Y2147483648M4DT12H30M5S"));
    assert_null(crm_time_parse_duration("P3Y6M2147483648DT12H30M5S"));
    assert_null(crm_time_parse_duration("P3Y6M4DT2147483648H30M5S"));
    assert_null(crm_time_parse_duration("P3Y6M4DT12H2147483648M5S"));
    assert_null(crm_time_parse_duration("P3Y6M4DT12H30MP2147483648S"));

    // Missing or invalid units
    assert_null(crm_time_parse_duration("P3Y6M4DT12H30M5"));
    assert_null(crm_time_parse_duration("P3Y6M4DT12H30M5X"));
    assert_null(crm_time_parse_duration("P3X6M4DT12H30M5S"));
    assert_null(crm_time_parse_duration("PT"));
    assert_null(crm_time_parse_duration("P/"));

#if 0
    // @TODO The current implementation treats these as valid

    // Units out of order
    assert_null(crm_time_parse_duration("P6M3Y4DT12H30M5S"));
    assert_null(crm_time_parse_duration("P6M3DT12HY430M5S"));

    // Same unit specified multiple times
    assert_null(crm_time_parse_duration("P6Y4M3D1MT12H30M5S"));

    // Weeks mixed with other units
    assert_null(crm_time_parse_duration("P6Y4M3W3D1MT12H30M5S"));
    assert_null(crm_time_parse_duration("P3WT12H30M5S"));
#endif
}

static void
valid_arg(void **state)
{
    // @TODO Check result value
    assert_non_null(crm_time_parse_duration("P3Y6M4DT12H30M5S"));
    assert_non_null(crm_time_parse_duration("P3Y6M4DT12H30M"));
    assert_non_null(crm_time_parse_duration("P3Y6M4D"));
    assert_non_null(crm_time_parse_duration("P1M"));  // 1 month
    assert_non_null(crm_time_parse_duration("PT1M")); // 1 minute
    assert_non_null(crm_time_parse_duration("P7W"));

#if 0
    // @TODO Current implementation can't handle these cases

    // Fractional value for last unit
    assert_non_null(crm_time_parse_duration("P3Y6M4DT12H30.5M"));
    assert_non_null(crm_time_parse_duration("P3Y6M4DT12H30,5M"));

    // P<YYYY>-<MM>-<DD>T<hh>:<mm>:<ss> format
    assert_non_null(crm_time_parse_duration("P0003-02-01T11:10:09");
#endif
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(empty_arg),
                cmocka_unit_test(invalid_arg),
                cmocka_unit_test(valid_arg));

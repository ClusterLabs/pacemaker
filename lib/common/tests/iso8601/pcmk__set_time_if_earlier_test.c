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
#include "../../crmcommon_private.h"

static void
null_ok(void **state)
{
    crm_time_t *target = crm_time_new("2024-01-01 00:30:00 +01:00");
    crm_time_t *target_copy = pcmk_copy_time(target);

    // Should do nothing (just checking it doesn't assert or crash)
    pcmk__set_time_if_earlier(NULL, NULL);
    pcmk__set_time_if_earlier(NULL, target);

    // Shouldn't assert, crash, or change target
    pcmk__set_time_if_earlier(target, NULL);
    assert_int_equal(crm_time_compare(target, target_copy), 0);

    crm_time_free(target);
    crm_time_free(target_copy);
}

static void
target_undefined(void **state)
{
    crm_time_t *source = crm_time_new("2024-01-01 00:29:59 +01:00");
    crm_time_t *target = crm_time_new_undefined();

    pcmk__set_time_if_earlier(target, source);
    assert_int_equal(crm_time_compare(target, source), 0);

    crm_time_free(source);
    crm_time_free(target);
}

static void
source_earlier(void **state)
{
    crm_time_t *source = crm_time_new("2024-01-01 00:29:59 +01:00");
    crm_time_t *target = crm_time_new("2024-01-01 00:30:00 +01:00");

    pcmk__set_time_if_earlier(target, source);
    assert_int_equal(crm_time_compare(target, source), 0);

    crm_time_free(source);
    crm_time_free(target);
}

static void
source_later(void **state)
{
    crm_time_t *source = crm_time_new("2024-01-01 00:31:00 +01:00");
    crm_time_t *target = crm_time_new("2024-01-01 00:30:00 +01:00");
    crm_time_t *target_copy = pcmk_copy_time(target);

    pcmk__set_time_if_earlier(target, source);
    assert_int_equal(crm_time_compare(target, target_copy), 0);

    crm_time_free(source);
    crm_time_free(target);
    crm_time_free(target_copy);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_ok),
                cmocka_unit_test(target_undefined),
                cmocka_unit_test(source_earlier),
                cmocka_unit_test(source_later))

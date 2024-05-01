/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scheduler.h>
#include <crm/common/unittest_internal.h>

static void
null_scheduler(void **state)
{
    assert_null(pcmk_get_dc(NULL));
}

static void
null_dc(void **state)
{
    pcmk_scheduler_t scheduler = {
        .dc_node = NULL,
    };

    assert_null(pcmk_get_dc(&scheduler));
}

static void
valid_dc(void **state)
{
    pcmk_node_t dc = {
        .weight = 1,
    };
    pcmk_scheduler_t scheduler = {
        .dc_node = &dc,
    };

    assert_ptr_equal(&dc, pcmk_get_dc(&scheduler));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_scheduler),
                cmocka_unit_test(null_dc),
                cmocka_unit_test(valid_dc))

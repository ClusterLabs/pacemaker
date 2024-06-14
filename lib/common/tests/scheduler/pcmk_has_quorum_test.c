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
    assert_false(pcmk_has_quorum(NULL));
}

static void
valid_scheduler(void **state)
{
    pcmk_scheduler_t scheduler = {
        .flags = pcmk_sched_quorate,
    };

    assert_true(pcmk_has_quorum(&scheduler));

    scheduler.flags = pcmk_sched_none;
    assert_false(pcmk_has_quorum(&scheduler));
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_scheduler),
                cmocka_unit_test(valid_scheduler))

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
    assert_int_equal(pcmk_get_no_quorum_policy(NULL), pcmk_no_quorum_stop);
}

static void
valid_no_quorum_policy(void **state)
{
    pcmk_scheduler_t scheduler = {
        .no_quorum_policy = pcmk_no_quorum_fence,
    };

    assert_int_equal(pcmk_get_no_quorum_policy(&scheduler),
                     pcmk_no_quorum_fence);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_scheduler),
                cmocka_unit_test(valid_no_quorum_policy))

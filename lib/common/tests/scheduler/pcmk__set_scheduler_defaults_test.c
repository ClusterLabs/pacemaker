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

#include <crm/common/scheduler.h>
#include <crm/pengine/internal.h>
#include <crm/pengine/status.h>

#include "mock_private.h"

static void
null_scheduler(void **state)
{
    pcmk__assert_asserts(pcmk__set_scheduler_defaults(NULL));
}

static void
check_defaults(void **state)
{
    uint32_t flags = 0U;
    pcmk_scheduler_t *scheduler = NULL;

    scheduler = pcmk__assert_alloc(1, sizeof(pcmk_scheduler_t));
    scheduler->priv = pcmk__assert_alloc(1, sizeof(pcmk__scheduler_private_t));
    pcmk__set_scheduler_defaults(scheduler);

    flags = pcmk__sched_symmetric_cluster
#if PCMK__CONCURRENT_FENCING_DEFAULT_TRUE
            |pcmk__sched_concurrent_fencing
#endif
            |pcmk__sched_stop_removed_resources
            |pcmk__sched_cancel_removed_actions;

    assert_null(scheduler->priv->out);
    assert_int_equal(scheduler->priv->next_ordering_id, 1);
    assert_int_equal(scheduler->priv->next_action_id, 1);
    assert_int_equal(scheduler->no_quorum_policy, pcmk_no_quorum_stop);
    assert_int_equal(scheduler->flags, flags);

    free(scheduler->priv);
    free(scheduler);
}

PCMK__UNIT_TEST(NULL, NULL,
                cmocka_unit_test(null_scheduler),
                cmocka_unit_test(check_defaults))

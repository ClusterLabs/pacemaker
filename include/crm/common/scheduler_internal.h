/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H
#  define PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H

#include <crm/common/action_relation_internal.h>
#include <crm/common/clone_internal.h>
#include <crm/common/failcounts_internal.h>
#include <crm/common/group_internal.h>
#include <crm/common/roles_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Some warnings are too noisy when logged every time a give function is called
 * (for example, using a deprecated feature). As an alternative, we allow
 * warnings to be logged once per scheduler sequence (transition). Each of those
 * warnings needs a flag defined here.
 */
enum pcmk__sched_warnings {
    pcmk__wo_blind          = (1 << 0),
    pcmk__wo_restart_type   = (1 << 1),
    pcmk__wo_role_after     = (1 << 2),
    pcmk__wo_poweroff       = (1 << 3),
    pcmk__wo_require_all    = (1 << 4),
    pcmk__wo_order_score    = (1 << 5),
    pcmk__wo_neg_threshold  = (1 << 6),
    pcmk__wo_remove_after   = (1 << 7),
    pcmk__wo_ping_node      = (1 << 8),
    pcmk__wo_order_inst     = (1 << 9),
    pcmk__wo_coloc_inst     = (1 << 10),
    pcmk__wo_group_order    = (1 << 11),
    pcmk__wo_group_coloc    = (1 << 12),
    pcmk__wo_upstart        = (1 << 13),
    pcmk__wo_nagios         = (1 << 14),
    pcmk__wo_set_ordering   = (1 << 15),
};

enum pcmk__check_parameters {
    /* Clear fail count if parameters changed for un-expired start or monitor
     * last_failure.
     */
    pcmk__check_last_failure,

    /* Clear fail count if parameters changed for start, monitor, promote, or
     * migrate_from actions for active resources.
     */
    pcmk__check_active,
};

// Group of enum pcmk__sched_warnings flags for warnings we want to log once
extern uint32_t pcmk__warnings;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H

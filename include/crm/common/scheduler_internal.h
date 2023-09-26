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
#include <crm/common/roles_internal.h>

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H

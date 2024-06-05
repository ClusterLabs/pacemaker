/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H
#define PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H

#include <crm/common/action_relation_internal.h>
#include <crm/common/actions_internal.h>
#include <crm/common/attrs_internal.h>
#include <crm/common/bundles_internal.h>
#include <crm/common/clone_internal.h>
#include <crm/common/digest_internal.h>
#include <crm/common/failcounts_internal.h>
#include <crm/common/group_internal.h>
#include <crm/common/history_internal.h>
#include <crm/common/location_internal.h>
#include <crm/common/nodes_internal.h>
#include <crm/common/primitive_internal.h>
#include <crm/common/remote_internal.h>
#include <crm/common/resources_internal.h>
#include <crm/common/roles_internal.h>
#include <crm/common/rules_internal.h>

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

// Group of enum pcmk__warnings flags for warnings we want to log once
extern uint32_t pcmk__warnings;

/*!
 * \internal
 * \brief Log a resource-tagged message at info severity
 *
 * \param[in] rsc       Tag message with this resource's ID
 * \param[in] fmt...    printf(3)-style format and arguments
 */
#define pcmk__rsc_info(rsc, fmt, args...)   \
    crm_log_tag(LOG_INFO, ((rsc) == NULL)? "<NULL>" : (rsc)->id, (fmt), ##args)

/*!
 * \internal
 * \brief Log a resource-tagged message at debug severity
 *
 * \param[in] rsc       Tag message with this resource's ID
 * \param[in] fmt...    printf(3)-style format and arguments
 */
#define pcmk__rsc_debug(rsc, fmt, args...)  \
    crm_log_tag(LOG_DEBUG, ((rsc) == NULL)? "<NULL>" : (rsc)->id, (fmt), ##args)

/*!
 * \internal
 * \brief Log a resource-tagged message at trace severity
 *
 * \param[in] rsc       Tag message with this resource's ID
 * \param[in] fmt...    printf(3)-style format and arguments
 */
#define pcmk__rsc_trace(rsc, fmt, args...)  \
    crm_log_tag(LOG_TRACE, ((rsc) == NULL)? "<NULL>" : (rsc)->id, (fmt), ##args)

/*!
 * \internal
 * \brief Log an error and remember that current scheduler input has errors
 *
 * \param[in] fmt...  printf(3)-style format and arguments
 */
#define pcmk__sched_err(fmt...) do {    \
        was_processing_error = TRUE;    \
        crm_err(fmt);                   \
    } while (0)

/*!
 * \internal
 * \brief Log a warning and remember that current scheduler input has warnings
 *
 * \param[in] fmt...  printf(3)-style format and arguments
 */
#define pcmk__sched_warn(fmt...) do {   \
        was_processing_warning = TRUE;  \
        crm_warn(fmt);                  \
    } while (0)

/*!
 * \internal
 * \brief Set scheduler flags
 *
 * \param[in,out] scheduler     Scheduler data
 * \param[in]     flags_to_set  Group of enum pcmk_scheduler_flags to set
 */
#define pcmk__set_scheduler_flags(scheduler, flags_to_set) do {             \
        (scheduler)->flags = pcmk__set_flags_as(__func__, __LINE__,         \
            LOG_TRACE, "Scheduler", crm_system_name,                        \
            (scheduler)->flags, (flags_to_set), #flags_to_set);             \
    } while (0)

/*!
 * \internal
 * \brief Clear scheduler flags
 *
 * \param[in,out] scheduler       Scheduler data
 * \param[in]     flags_to_clear  Group of enum pcmk_scheduler_flags to clear
 */
#define pcmk__clear_scheduler_flags(scheduler, flags_to_clear) do {         \
        (scheduler)->flags = pcmk__clear_flags_as(__func__, __LINE__,       \
            LOG_TRACE, "Scheduler", crm_system_name,                        \
            (scheduler)->flags, (flags_to_clear), #flags_to_clear);         \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEDULER_INTERNAL__H

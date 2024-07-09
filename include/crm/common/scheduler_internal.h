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
#include <crm/common/tickets_internal.h>

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

// Scheduling options and conditions
enum pcmk__scheduler_flags {
    // No scheduler flags set (compare with equality rather than bit set)
    pcmk__sched_none                    = 0ULL,

    /* These flags are dynamically determined conditions */

    // Whether partition has quorum (via \c PCMK_XA_HAVE_QUORUM attribute)
    //! \deprecated Call pcmk_has_quorum() to check quorum instead
    pcmk__sched_quorate                 = (1ULL << 0),

    // Whether cluster is symmetric (via symmetric-cluster property)
    pcmk__sched_symmetric_cluster       = (1ULL << 1),

    // Whether scheduling encountered a non-configuration error
    pcmk__sched_processing_error        = (1ULL << 2),

    // Whether cluster is in maintenance mode (via maintenance-mode property)
    pcmk__sched_in_maintenance          = (1ULL << 3),

    // Whether fencing is enabled (via stonith-enabled property)
    pcmk__sched_fencing_enabled         = (1ULL << 4),

    // Whether cluster has a fencing resource (via CIB resources)
    /*! \deprecated To indicate the cluster has a fencing resource, add either a
     * fencing resource configuration or the have-watchdog cluster option to the
     * input CIB
     */
    pcmk__sched_have_fencing            = (1ULL << 5),

    // Whether any resource provides or requires unfencing (via CIB resources)
    pcmk__sched_enable_unfencing        = (1ULL << 6),

    // Whether concurrent fencing is allowed (via concurrent-fencing property)
    pcmk__sched_concurrent_fencing      = (1ULL << 7),

    /*
     * Whether resources removed from the configuration should be stopped (via
     * stop-orphan-resources property)
     */
    pcmk__sched_stop_removed_resources  = (1ULL << 8),

    /*
     * Whether recurring actions removed from the configuration should be
     * cancelled (via stop-orphan-actions property)
     */
    pcmk__sched_cancel_removed_actions  = (1ULL << 9),

    // Whether to stop all resources (via stop-all-resources property)
    pcmk__sched_stop_all                = (1ULL << 10),

    // Whether scheduler processing encountered a warning
    pcmk__sched_processing_warning      = (1ULL << 11),

    /*
     * Whether start failure should be treated as if
     * \c PCMK_META_MIGRATION_THRESHOLD is 1 (via
     * \c PCMK_OPT_START_FAILURE_IS_FATAL property)
     */
    pcmk__sched_start_failure_fatal     = (1ULL << 12),

    // Unused
    pcmk__sched_remove_after_stop       = (1ULL << 13),

    // Whether unseen nodes should be fenced (via startup-fencing property)
    pcmk__sched_startup_fencing         = (1ULL << 14),

    /*
     * Whether resources should be left stopped when their node shuts down
     * cleanly (via shutdown-lock property)
     */
    pcmk__sched_shutdown_lock           = (1ULL << 15),

    /*
     * Whether resources' current state should be probed (when unknown) before
     * scheduling any other actions (via the enable-startup-probes property)
     */
    pcmk__sched_probe_resources         = (1ULL << 16),

    // Whether the CIB status section has been parsed yet
    pcmk__sched_have_status             = (1ULL << 17),

    // Whether the cluster includes any Pacemaker Remote nodes (via CIB)
    pcmk__sched_have_remote_nodes       = (1ULL << 18),


    /* The remaining flags are scheduling options that must be set explicitly */

    /*
     * Whether to skip unpacking the CIB status section and stop the scheduling
     * sequence after applying node-specific location criteria (skipping
     * assignment, ordering, actions, etc.).
     */
    pcmk__sched_location_only           = (1ULL << 20),

    // Whether sensitive resource attributes have been masked
    pcmk__sched_sanitized               = (1ULL << 21),

    // Skip counting of total, disabled, and blocked resource instances
    pcmk__sched_no_counts               = (1ULL << 23),

    // Whether node scores should be output instead of logged
    pcmk__sched_output_scores           = (1ULL << 25),

    // Whether to show node and resource utilization (in log or output)
    pcmk__sched_show_utilization        = (1ULL << 26),

    /*
     * Whether to stop the scheduling sequence after unpacking the CIB,
     * calculating cluster status, and applying node health (skipping
     * applying node-specific location criteria, assignment, etc.)
     */
    pcmk__sched_validate_only           = (1ULL << 27),
};

// Implementation of pcmk__scheduler_private_t
struct pcmk__scheduler_private {
    // Be careful about when each piece of information is available and final

    char *local_node_name;          // Name of node running scheduler (if known)
    crm_time_t *now;                // Time to use when evaluating rules
    pcmk__output_t *out;            // Output object for displaying messages
    GHashTable *options;            // Cluster options
    const char *fence_action;       // Default fencing action
    int fence_timeout_ms;           // Value of stonith-timeout property in ms
    const char *placement_strategy; // Value of placement-strategy property
    xmlNode *rsc_defaults;          // Configured resource defaults
    xmlNode *op_defaults;           // Configured operation defaults
    GList *resources;               // Resources in cluster
    GHashTable *templates;          // Key = template ID, value = resource list
    GHashTable *tags;               // Key = tag ID, value = element list
    GList *actions;                 // All scheduled actions
    GHashTable *singletons;         // Scheduled non-resource actions
    int next_action_id;             // Counter used as ID for actions
    xmlNode *failed;                // History entries of failed actions
    GList *param_check;             // History entries that need to be checked
    GList *stop_needed;             // Containers that need stop actions
    GList *location_constraints;    // Location constraints
    GList *colocation_constraints;  // Colocation constraints
    GList *ordering_constraints;    // Ordering constraints
    GHashTable *ticket_constraints; // Key = ticket ID, value = pcmk__ticket_t
    int next_ordering_id;           // Counter used as ID for orderings
    int blocked_resources;          // Number of blocked resources in cluster
    int disabled_resources;         // Number of disabled resources in cluster
    xmlNode *graph;                 // Transition graph
    int synapse_count;              // Number of transition graph synapses
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
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     fmt...     printf(3)-style format and arguments
 */
#define pcmk__sched_err(scheduler, fmt...) do {                     \
        pcmk__set_scheduler_flags((scheduler),                      \
                                  pcmk__sched_processing_error);    \
        crm_err(fmt);                                               \
    } while (0)

/*!
 * \internal
 * \brief Log a warning and remember that current scheduler input has warnings
 *
 * \param[in,out] scheduler  Scheduler data
 * \param[in]     fmt...     printf(3)-style format and arguments
 */
#define pcmk__sched_warn(scheduler, fmt...) do {                    \
        pcmk__set_scheduler_flags((scheduler),                      \
                                  pcmk__sched_processing_warning);  \
        crm_warn(fmt);                                              \
    } while (0)

/*!
 * \internal
 * \brief Set scheduler flags
 *
 * \param[in,out] scheduler     Scheduler data
 * \param[in]     flags_to_set  Group of enum pcmk__scheduler_flags to set
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
 * \param[in]     flags_to_clear  Group of enum pcmk__scheduler_flags to clear
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

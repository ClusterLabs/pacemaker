/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_SCHEDULER__H
#define PCMK__CRM_COMMON_SCHEDULER__H

#include <sys/types.h>                  // time_t
#include <libxml/tree.h>                // xmlNode
#include <glib.h>                       // guint, GList, GHashTable

#include <crm/common/iso8601.h>         // crm_time_t

#include <crm/common/actions.h>
#include <crm/common/nodes.h>
#include <crm/common/resources.h>
#include <crm/common/roles.h>
#include <crm/common/rules.h>
#include <crm/common/scheduler_types.h>
#include <crm/common/tags.h>
#include <crm/common/tickets.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API
 * \ingroup core
 */

// NOTE: sbd (as of at least 1.5.2) uses this enum
//! Possible responses to loss of quorum
enum pe_quorum_policy {
    pcmk_no_quorum_freeze,  //<! Do not recover resources from outside partition
    pcmk_no_quorum_stop,    //<! Stop all resources in partition
    pcmk_no_quorum_ignore,  //<! Act as if partition still holds quorum
    pcmk_no_quorum_fence,   //<! Fence all nodes in partition
    pcmk_no_quorum_demote,  //<! Demote promotable resources and stop all others

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    // NOTE: sbd (as of at least 1.5.2) uses this value
    //! \deprecated Use pcmk_no_quorum_freeze instead
    no_quorum_freeze    = pcmk_no_quorum_freeze,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    //! \deprecated Use pcmk_no_quorum_stop instead
    no_quorum_stop      = pcmk_no_quorum_stop,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    //! \deprecated Use pcmk_no_quorum_ignore instead
    no_quorum_ignore    = pcmk_no_quorum_ignore,

    //! \deprecated Use pcmk_no_quorum_fence instead
    no_quorum_suicide   = pcmk_no_quorum_fence,

    // NOTE: sbd (as of at least 1.5.2) uses this value
    //! \deprecated Use pcmk_no_quorum_demote instead
    no_quorum_demote    = pcmk_no_quorum_demote,
#endif
};

// Scheduling options and conditions
//!@{
//! \deprecated Do not use
enum pcmk_scheduler_flags {
    // No scheduler flags set (compare with equality rather than bit set)
    pcmk_sched_none                     = 0ULL,

    /* These flags are dynamically determined conditions */

    // Whether partition has quorum (via \c PCMK_XA_HAVE_QUORUM attribute)
    //! \deprecated Call pcmk_has_quorum() to check quorum instead
    pcmk_sched_quorate                  = (1ULL << 0),

    // Whether cluster is symmetric (via symmetric-cluster property)
    pcmk_sched_symmetric_cluster        = (1ULL << 1),

    // Whether cluster is in maintenance mode (via maintenance-mode property)
    pcmk_sched_in_maintenance           = (1ULL << 3),

    // Whether fencing is enabled (via stonith-enabled property)
    pcmk_sched_fencing_enabled          = (1ULL << 4),

    // Whether cluster has a fencing resource (via CIB resources)
    /*! \deprecated To indicate the cluster has a fencing resource, add either a
     * fencing resource configuration or the have-watchdog cluster option to the
     * input CIB
     */
    pcmk_sched_have_fencing             = (1ULL << 5),

    // Whether any resource provides or requires unfencing (via CIB resources)
    pcmk_sched_enable_unfencing         = (1ULL << 6),

    // Whether concurrent fencing is allowed (via concurrent-fencing property)
    pcmk_sched_concurrent_fencing       = (1ULL << 7),

    /*
     * Whether resources removed from the configuration should be stopped (via
     * stop-orphan-resources property)
     */
    pcmk_sched_stop_removed_resources   = (1ULL << 8),

    /*
     * Whether recurring actions removed from the configuration should be
     * cancelled (via stop-orphan-actions property)
     */
    pcmk_sched_cancel_removed_actions   = (1ULL << 9),

    // Whether to stop all resources (via stop-all-resources property)
    pcmk_sched_stop_all                 = (1ULL << 10),

    /*
     * Whether start failure should be treated as if
     * \c PCMK_META_MIGRATION_THRESHOLD is 1 (via
     * \c PCMK_OPT_START_FAILURE_IS_FATAL property)
     */
    pcmk_sched_start_failure_fatal      = (1ULL << 12),

    // Unused
    pcmk_sched_remove_after_stop        = (1ULL << 13),

    // Whether unseen nodes should be fenced (via startup-fencing property)
    pcmk_sched_startup_fencing          = (1ULL << 14),

    /*
     * Whether resources should be left stopped when their node shuts down
     * cleanly (via shutdown-lock property)
     */
    pcmk_sched_shutdown_lock            = (1ULL << 15),

    /*
     * Whether resources' current state should be probed (when unknown) before
     * scheduling any other actions (via the enable-startup-probes property)
     */
    pcmk_sched_probe_resources          = (1ULL << 16),

    // Whether the CIB status section has been parsed yet
    pcmk_sched_have_status              = (1ULL << 17),

    // Whether the cluster includes any Pacemaker Remote nodes (via CIB)
    pcmk_sched_have_remote_nodes        = (1ULL << 18),


    /* The remaining flags are scheduling options that must be set explicitly */

    /*
     * Whether to skip unpacking the CIB status section and stop the scheduling
     * sequence after applying node-specific location criteria (skipping
     * assignment, ordering, actions, etc.).
     */
    pcmk_sched_location_only            = (1ULL << 20),

    // Whether sensitive resource attributes have been masked
    pcmk_sched_sanitized                = (1ULL << 21),

    // Skip counting of total, disabled, and blocked resource instances
    pcmk_sched_no_counts                = (1ULL << 23),

    /*
     * Skip deprecated code kept solely for backward API compatibility
     * (internal code should always set this)
     */
    pcmk_sched_no_compat                = (1ULL << 24),

    // Whether node scores should be output instead of logged
    pcmk_sched_output_scores            = (1ULL << 25),

    // Whether to show node and resource utilization (in log or output)
    pcmk_sched_show_utilization         = (1ULL << 26),

    /*
     * Whether to stop the scheduling sequence after unpacking the CIB,
     * calculating cluster status, and applying node health (skipping
     * applying node-specific location criteria, assignment, etc.)
     */
    pcmk_sched_validate_only            = (1ULL << 27),
};
//!@}

// Implementation of pcmk_scheduler_t
// @COMPAT Make contents internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pe_working_set_s {
    // Be careful about when each piece of information is available and final

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated To set scheduler iput, use pcmk_set_scheduler_cib() instead
    xmlNode *input;                 // CIB XML

    crm_time_t *now;                // Current time for evaluation purposes
    char *dc_uuid;                  // Node ID of designated controller

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_get_dc() instead
    pcmk_node_t *dc_node;           // Node object for DC

    const char *stonith_action;     // Default fencing action
    const char *placement_strategy; // Value of placement-strategy property

    // NOTE: sbd (as of at least 1.5.2) uses this
    // @COMPAT Change to uint64_t at a compatibility break
    //! \deprecated Call pcmk_has_quorum() to check quorum
    unsigned long long flags;       // Group of enum pcmk_scheduler_flags

    int stonith_timeout;            // Value of stonith-timeout property

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_get_no_quorum_policy() to get no-quorum policy
    enum pe_quorum_policy no_quorum_policy; // Response to loss of quorum

    GHashTable *config_hash;        // Cluster properties

    // Ticket constraints unpacked from ticket state
    GHashTable *tickets;

    // Actions for which there can be only one (such as "fence node X")
    GHashTable *singletons;

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_find_node() to find a node instead
    GList *nodes;                   // Nodes in cluster

    GList *resources;               // Resources in cluster
    GList *placement_constraints;   // Location constraints
    GList *ordering_constraints;    // Ordering constraints
    GList *colocation_constraints;  // Colocation constraints

    // Ticket constraints unpacked by libpacemaker
    GList *ticket_constraints;

    GList *actions;                 // Scheduled actions
    xmlNode *failed;                // History entries of failed actions
    xmlNode *op_defaults;           // Configured operation defaults
    xmlNode *rsc_defaults;          // Configured resource defaults
    int num_synapse;                // Number of transition graph synapses
    int max_valid_nodes;            // \deprecated Do not use
    int order_id;                   // ID to use for next created ordering
    int action_id;                  // ID to use for next created action
    xmlNode *graph;                 // Transition graph
    GHashTable *template_rsc_sets;  // Mappings of template ID to resource ID

    // @COMPAT Replace this with a fencer variable (only place it's used)
    const char *localhost;          // \deprecated Do not use

    GHashTable *tags;               // Configuration tags (ID -> pcmk_tag_t *)
    int blocked_resources;          // Number of blocked resources in cluster
    int disabled_resources;         // Number of disabled resources in cluster
    GList *param_check;             // History entries that need to be checked
    GList *stop_needed;             // Containers that need stop actions
    time_t recheck_by;              // Hint to controller when to reschedule
    int ninstances;                 // Total number of resource instances
    guint shutdown_lock;            // How long to lock resources (seconds)
    int priority_fencing_delay;     // Priority fencing delay

    // pcmk__output_t *
    void *priv;                     // For Pacemaker use only

    guint node_pending_timeout;     // Pending join times out after this (ms)
};
//!@}

/* Whether the scheduler input currently being processed has warnings or errors
 *
 * @COMPAT When we can break API compatibility, we should make these
 * internal-only. Ideally they would be converted to pcmk_scheduler_flags
 * values, but everywhere they're needed doesn't currently have access to the
 * scheduler data.
 */
//!@{
//! \deprecated Do not use
extern gboolean was_processing_error;
extern gboolean was_processing_warning;
//!@}

pcmk_node_t *pcmk_get_dc(const pcmk_scheduler_t *scheduler);
enum pe_quorum_policy pcmk_get_no_quorum_policy(const pcmk_scheduler_t
                                                *scheduler);

int pcmk_set_scheduler_cib(pcmk_scheduler_t *scheduler, xmlNode *cib);

bool pcmk_has_quorum(const pcmk_scheduler_t *scheduler);
pcmk_node_t *pcmk_find_node(const pcmk_scheduler_t *scheduler,
                            const char *node_name);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_SCHEDULER__H

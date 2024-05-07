/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H
#  define PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

#include <crm/common/scheduler.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker scheduler API
 * \ingroup pengine
 * \deprecated Do not include this header directly. The scheduler APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
#define pe_rsc_orphan                   pcmk_rsc_removed

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_rsc_managed                  pcmk_rsc_managed

//! \deprecated Do not use
#define pe_rsc_block                    pcmk_rsc_blocked

//! \deprecated Do not use
#define pe_rsc_orphan_container_filler  pcmk_rsc_removed_filler

//! \deprecated Do not use
#define pe_rsc_notify                   pcmk_rsc_notify

//! \deprecated Do not use
#define pe_rsc_unique                   pcmk_rsc_unique

//! \deprecated Do not use
#define pe_rsc_fence_device             pcmk_rsc_fence_device

//! \deprecated Do not use
#define pe_rsc_promotable               pcmk_rsc_promotable

//! \deprecated Do not use
#define pe_rsc_provisional              pcmk_rsc_unassigned

//! \deprecated Do not use
#define pe_rsc_allocating               pcmk_rsc_assigning

//! \deprecated Do not use
#define pe_rsc_merging                  pcmk_rsc_updating_nodes

//! \deprecated Do not use
#define pe_rsc_restarting               pcmk_rsc_restarting

//! \deprecated Do not use
#define pe_rsc_stop                     pcmk_rsc_stop_if_failed

//! \deprecated Do not use
#define pe_rsc_reload                   pcmk_rsc_reload

//! \deprecated Do not use
#define pe_rsc_allow_remote_remotes     pcmk_rsc_remote_nesting_allowed

//! \deprecated Do not use
#define pe_rsc_critical                 pcmk_rsc_critical

//! \deprecated Do not use
#define pe_rsc_failed                   pcmk_rsc_failed

//! \deprecated Do not use
#define pe_rsc_detect_loop              pcmk_rsc_detect_loop

//! \deprecated Do not use
#define pe_rsc_runnable                 pcmk_rsc_runnable

//! \deprecated Do not use
#define pe_rsc_start_pending            pcmk_rsc_start_pending

//!< \deprecated Do not use
#define pe_rsc_starting                 pcmk_rsc_starting

//!< \deprecated Do not use
#define pe_rsc_stopping                 pcmk_rsc_stopping

//! \deprecated Do not use
#define pe_rsc_stop_unexpected          pcmk_rsc_stop_unexpected

//! \deprecated Do not use
#define pe_rsc_allow_migrate            pcmk_rsc_migratable

//! \deprecated Do not use
#define pe_rsc_failure_ignored          pcmk_rsc_ignore_failure

//! \deprecated Do not use
#define pe_rsc_replica_container        pcmk_rsc_replica_container

//! \deprecated Do not use
#define pe_rsc_maintenance              pcmk_rsc_maintenance

//! \deprecated Do not use
#define pe_rsc_is_container             pcmk_rsc_has_filler

//! \deprecated Do not use
#define pe_rsc_needs_quorum             pcmk_rsc_needs_quorum

//! \deprecated Do not use
#define pe_rsc_needs_fencing            pcmk_rsc_needs_fencing

//! \deprecated Do not use
#define pe_rsc_needs_unfencing          pcmk_rsc_needs_unfencing

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_flag_have_quorum             pcmk_sched_quorate

//! \deprecated Do not use
#define pe_flag_symmetric_cluster       pcmk_sched_symmetric_cluster

//! \deprecated Do not use
#define pe_flag_maintenance_mode        pcmk_sched_in_maintenance

//! \deprecated Do not use
#define pe_flag_stonith_enabled         pcmk_sched_fencing_enabled

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_flag_have_stonith_resource   pcmk_sched_have_fencing

//! \deprecated Do not use
#define pe_flag_enable_unfencing        pcmk_sched_enable_unfencing

//! \deprecated Do not use
#define pe_flag_concurrent_fencing      pcmk_sched_concurrent_fencing

//! \deprecated Do not use
#define pe_flag_stop_rsc_orphans        pcmk_sched_stop_removed_resources

//! \deprecated Do not use
#define pe_flag_stop_action_orphans     pcmk_sched_cancel_removed_actions

//! \deprecated Do not use
#define pe_flag_stop_everything         pcmk_sched_stop_all

//! \deprecated Do not use
#define pe_flag_start_failure_fatal     pcmk_sched_start_failure_fatal

//! \deprecated Do not use
#define pe_flag_remove_after_stop       pcmk_sched_remove_after_stop

//! \deprecated Do not use
#define pe_flag_startup_fencing         pcmk_sched_startup_fencing

//! \deprecated Do not use
#define pe_flag_shutdown_lock           pcmk_sched_shutdown_lock

//! \deprecated Do not use
#define pe_flag_startup_probes          pcmk_sched_probe_resources

//! \deprecated Do not use
#define pe_flag_have_status             pcmk_sched_have_status

//! \deprecated Do not use
#define pe_flag_have_remote_nodes       pcmk_sched_have_remote_nodes

//! \deprecated Do not use
#define pe_flag_quick_location          pcmk_sched_location_only

//! \deprecated Do not use
#define pe_flag_sanitized               pcmk_sched_sanitized

//! \deprecated Do not use
#define pe_flag_stdout                  (1ULL << 22)

//! \deprecated Do not use
#define pe_flag_no_counts               pcmk_sched_no_counts

//! \deprecated Do not use
#define pe_flag_no_compat               pcmk_sched_no_compat

//! \deprecated Do not use
#define pe_flag_show_scores             pcmk_sched_output_scores

//! \deprecated Do not use
#define pe_flag_show_utilization        pcmk_sched_show_utilization

//! \deprecated Do not use
#define pe_flag_check_config            pcmk_sched_validate_only

//!@{
//! \deprecated Do not use (unused by Pacemaker)
enum pe_graph_flags {
    pe_graph_none = 0x00000,
    pe_graph_updated_first = 0x00001,
    pe_graph_updated_then = 0x00002,
    pe_graph_disable = 0x00004,
};
//!@}

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_node_t instead
typedef struct pe_node_s node_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated use pcmk_resource_t instead
typedef struct pe_resource_s resource_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_scheduler_t instead
typedef struct pe_working_set_s pe_working_set_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

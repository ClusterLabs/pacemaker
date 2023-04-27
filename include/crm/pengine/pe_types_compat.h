/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H
#  define PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

#include <crm/pengine/pe_types.h>

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

//! \deprecated Use pcmk_sched_quorate instead
#define pe_flag_have_quorum             pcmk_sched_quorate

//! \deprecated Use pcmk_sched_symmetric_cluster instead
#define pe_flag_symmetric_cluster       pcmk_sched_symmetric_cluster

//! \deprecated Use pcmk_sched_in_maintenance instead
#define pe_flag_maintenance_mode        pcmk_sched_in_maintenance

//! \deprecated Use pcmk_sched_fencing_enabled instead
#define pe_flag_stonith_enabled         pcmk_sched_fencing_enabled

//! \deprecated Use pcmk_sched_have_fencing instead
#define pe_flag_have_stonith_resource   pcmk_sched_have_fencing

//! \deprecated Use pcmk_sched_enable_unfencing instead
#define pe_flag_enable_unfencing        pcmk_sched_enable_unfencing

//! \deprecated Use pcmk_sched_concurrent_fencing instead
#define pe_flag_concurrent_fencing      pcmk_sched_concurrent_fencing

//! \deprecated Use pcmk_sched_stop_removed_resources instead
#define pe_flag_stop_rsc_orphans        pcmk_sched_stop_removed_resources

//! \deprecated Use pcmk_sched_cancel_removed_actions instead
#define pe_flag_stop_action_orphans     pcmk_sched_cancel_removed_actions

//! \deprecated Use pcmk_sched_stop_all instead
#define pe_flag_stop_everything         pcmk_sched_stop_all

//! \deprecated Use pcmk_sched_start_failure_fatal instead
#define pe_flag_start_failure_fatal     pcmk_sched_start_failure_fatal

//! \deprecated Do not use
#define pe_flag_remove_after_stop       pcmk_sched_remove_after_stop

//! \deprecated Use pcmk_sched_startup_fencing instead
#define pe_flag_startup_fencing         pcmk_sched_startup_fencing

//! \deprecated Use pcmk_sched_shutdown_lock instead
#define pe_flag_shutdown_lock           pcmk_sched_shutdown_lock

//! \deprecated Use pcmk_sched_probe_resources instead
#define pe_flag_startup_probes          pcmk_sched_probe_resources

//! \deprecated Use pcmk_sched_have_status instead
#define pe_flag_have_status             pcmk_sched_have_status

//! \deprecated Use pcmk_sched_have_remote_nodes instead
#define pe_flag_have_remote_nodes       pcmk_sched_have_remote_nodes

//! \deprecated Use pcmk_sched_location_only instead
#define pe_flag_quick_location          pcmk_sched_location_only

//!@{
//! \deprecated Do not use (unused by Pacemaker)
enum pe_graph_flags {
    pe_graph_none = 0x00000,
    pe_graph_updated_first = 0x00001,
    pe_graph_updated_then = 0x00002,
    pe_graph_disable = 0x00004,
};
//!@}

//!@{
//! \deprecated Do not use
enum pe_check_parameters {
    pe_check_last_failure,
    pe_check_active,
};
//!@}

//!< \deprecated Use pe_action_t instead
typedef struct pe_action_s action_t;

//!< \deprecated Use pe_action_wrapper_t instead
typedef struct pe_action_wrapper_s action_wrapper_t;

//!< \deprecated Use pe_node_t instead
typedef struct pe_node_s node_t;

//!< \deprecated Use enum pe_quorum_policy instead
typedef enum pe_quorum_policy no_quorum_policy_t;

//!< \deprecated use pe_resource_t instead
typedef struct pe_resource_s resource_t;

//!< \deprecated Use pe_tag_t instead
typedef struct pe_tag_s tag_t;

//!< \deprecated Use pe_ticket_t instead
typedef struct pe_ticket_s ticket_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

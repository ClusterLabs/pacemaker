/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES__H
#define PCMK__CRM_COMMON_RESOURCES__H

#include <stdbool.h>                    // bool
#include <sys/types.h>                  // time_t
#include <libxml/tree.h>                // xmlNode
#include <glib.h>                       // gboolean, guint, GList, GHashTable

#include <crm/common/roles.h>           // enum rsc_role_e
#include <crm/common/scheduler_types.h> // pcmk_resource_t, etc.

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for resources
 * \ingroup core
 */

//!@{
//! \deprecated Do not use

// What resource needs before it can be recovered from a failed node
enum rsc_start_requirement {
    pcmk_requires_nothing   = 0,    // Resource can be recovered immediately
    pcmk_requires_quorum    = 1,    // Resource can be recovered if quorate
    pcmk_requires_fencing   = 2,    // Resource can be recovered after fencing

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    rsc_req_nothing         = pcmk_requires_nothing,
    rsc_req_quorum          = pcmk_requires_quorum,
    rsc_req_stonith         = pcmk_requires_fencing,
#endif
};

// Resource scheduling flags
enum pcmk_rsc_flags {
    // No resource flags set (compare with equality rather than bit set)
    pcmk_no_rsc_flags               = 0ULL,

    // Whether resource has been removed from the configuration
    pcmk_rsc_removed                = (1ULL << 0),

    // Whether resource is managed
    pcmk_rsc_managed                = (1ULL << 1),

    // Whether resource is blocked from further action
    pcmk_rsc_blocked                = (1ULL << 2),

    // Whether resource has been removed but has a container
    pcmk_rsc_removed_filler         = (1ULL << 3),

    // Whether resource has clone notifications enabled
    pcmk_rsc_notify                 = (1ULL << 4),

    // Whether resource is not an anonymous clone instance
    pcmk_rsc_unique                 = (1ULL << 5),

    // Whether resource's class is "stonith"
    pcmk_rsc_fence_device           = (1ULL << 6),

    // Whether resource can be promoted and demoted
    pcmk_rsc_promotable             = (1ULL << 7),

    // Whether resource has not yet been assigned to a node
    pcmk_rsc_unassigned             = (1ULL << 8),

    // Whether resource is in the process of being assigned to a node
    pcmk_rsc_assigning              = (1ULL << 9),

    // Whether resource is in the process of modifying allowed node scores
    pcmk_rsc_updating_nodes         = (1ULL << 10),

    // Whether resource is in the process of scheduling actions to restart
    pcmk_rsc_restarting             = (1ULL << 11),

    // Whether resource must be stopped (instead of demoted) if it is failed
    pcmk_rsc_stop_if_failed         = (1ULL << 12),

    // Whether a reload action has been scheduled for resource
    pcmk_rsc_reload                 = (1ULL << 13),

    // Whether resource is a remote connection allowed to run on a remote node
    pcmk_rsc_remote_nesting_allowed = (1ULL << 14),

    // Whether resource has \c PCMK_META_CRITICAL meta-attribute enabled
    pcmk_rsc_critical               = (1ULL << 15),

    // Whether resource is considered failed
    pcmk_rsc_failed                 = (1ULL << 16),

    // Flag for non-scheduler code to use to detect recursion loops
    pcmk_rsc_detect_loop            = (1ULL << 17),

    // \deprecated Do not use
    pcmk_rsc_runnable               = (1ULL << 18),

    // Whether resource has pending start action in history
    pcmk_rsc_start_pending          = (1ULL << 19),

    // \deprecated Do not use
    pcmk_rsc_starting               = (1ULL << 20),

    // \deprecated Do not use
    pcmk_rsc_stopping               = (1ULL << 21),

    /*
     * Whether resource is multiply active with recovery set to
     * \c PCMK_VALUE_STOP_UNEXPECTED
     */
    pcmk_rsc_stop_unexpected        = (1ULL << 22),

    // Whether resource is allowed to live-migrate
    pcmk_rsc_migratable             = (1ULL << 23),

    // Whether resource has an ignorable failure
    pcmk_rsc_ignore_failure         = (1ULL << 24),

    // Whether resource is an implicit container resource for a bundle replica
    pcmk_rsc_replica_container      = (1ULL << 25),

    // Whether resource, its node, or entire cluster is in maintenance mode
    pcmk_rsc_maintenance            = (1ULL << 26),

    // \deprecated Do not use
    pcmk_rsc_has_filler             = (1ULL << 27),

    // Whether resource can be started or promoted only on quorate nodes
    pcmk_rsc_needs_quorum           = (1ULL << 28),

    // Whether resource requires fencing before recovery if on unclean node
    pcmk_rsc_needs_fencing          = (1ULL << 29),

    // Whether resource can be started or promoted only on unfenced nodes
    pcmk_rsc_needs_unfencing        = (1ULL << 30),
};
//!@}

//! Search options for resources (exact resource ID always matches)
enum pe_find {
    //! Also match clone instance ID from resource history
    pcmk_rsc_match_history          = (1 << 0),

    //! Also match anonymous clone instances by base name
    pcmk_rsc_match_anon_basename    = (1 << 1),

    //! Match only clones and their instances, by either clone or instance ID
    pcmk_rsc_match_clone_only       = (1 << 2),

    //! If matching by node, compare current node instead of assigned node
    pcmk_rsc_match_current_node     = (1 << 3),

    //! \deprecated Do not use
    pe_find_inactive                = (1 << 4),

    //! Match clone instances (even unique) by base name as well as exact ID
    pcmk_rsc_match_basename         = (1 << 5),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_rsc_match_history instead
    pe_find_renamed     = pcmk_rsc_match_history,

    //! \deprecated Use pcmk_rsc_match_anon_basename instead
    pe_find_anon        = pcmk_rsc_match_anon_basename,

    //! \deprecated Use pcmk_rsc_match_clone_only instead
    pe_find_clone       = pcmk_rsc_match_clone_only,

    //! \deprecated Use pcmk_rsc_match_current_node instead
    pe_find_current     = pcmk_rsc_match_current_node,

    //! \deprecated Use pcmk_rsc_match_basename instead
    pe_find_any         = pcmk_rsc_match_basename,
#endif
};

//! \internal Do not use
typedef struct pcmk__resource_private pcmk__resource_private_t;

// Implementation of pcmk_resource_t
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pe_resource_s {
    /* @COMPAT Once all members are moved to pcmk__resource_private_t,
     * We can make that the pcmk_resource_t implementation and drop this
     * struct altogether, leaving pcmk_resource_t as an opaque public type.
     */
    pcmk__resource_private_t *private;

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_resource_id() instead
    char *id;                           // Resource ID in configuration

    int priority;                   // Configured priority
    int stickiness;                 // Extra preference for current node
    int sort_index;                 // Promotion score on assigned node
    int failure_timeout;            // Failure timeout
    int migration_threshold;        // Migration threshold
    guint remote_reconnect_ms;      // Retry interval for remote connections
    char *pending_task;             // Pending action in history, if any

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_resource_is_managed() instead
    unsigned long long flags;       // Group of enum pcmk_rsc_flags

    // @TODO Merge these into flags
    gboolean is_remote_node;        // Whether this is a remote connection
    gboolean exclusive_discover;    // Whether exclusive probing is enabled

    /* Pay special attention to whether you want to use rsc_cons_lhs and
     * rsc_cons directly, which include only colocations explicitly involving
     * this resource, or call libpacemaker's pcmk__with_this_colocations() and
     * pcmk__this_with_colocations() functions, which may return relevant
     * colocations involving the resource's ancestors as well.
     */

    GList *rsc_cons_lhs;      // Colocations of other resources with this one
    GList *rsc_cons;          // Colocations of this resource with others
    GList *rsc_location;      // Location constraints for resource
    GList *actions;           // Actions scheduled for resource
    GList *rsc_tickets;       // Ticket constraints for resource

    pcmk_node_t *allocated_to;  // Node resource is assigned to

    // The destination node, if migrate_to completed but migrate_from has not
    pcmk_node_t *partial_migration_target;

    // The source node, if migrate_to completed but migrate_from has not
    pcmk_node_t *partial_migration_source;

    // Nodes where resource may be active
    GList *running_on;

    // Nodes where resource has been probed (key is node ID, not name)
    GHashTable *known_on;

    // Nodes where resource may run (key is node ID, not name)
    GHashTable *allowed_nodes;

    enum rsc_role_e role;           // Resource's current role
    enum rsc_role_e next_role;      // Resource's scheduled next role

    GHashTable *meta;               // Resource's meta-attributes
    GHashTable *parameters;         // \deprecated Use pe_rsc_params() instead
    GHashTable *utilization;        // Resource's utilization attributes

    GList *children;                // Resource's child resources, if any

    // Source nodes where stop is needed after migrate_from and migrate_to
    GList *dangling_migrations;

    pcmk_resource_t *container;     // Resource containing this one, if any
    GList *fillers;                 // Resources contained by this one, if any

    // @COMPAT These should be made const at next API compatibility break
    pcmk_node_t *pending_node;      // Node on which pending_task is happening
    pcmk_node_t *lock_node;         // Resource shutdown-locked to this node

    time_t lock_time;               // When shutdown lock started

    /*
     * Resource parameters may have node-attribute-based rules, which means the
     * values can vary by node. This table has node names as keys and parameter
     * name/value tables as values. Use pe_rsc_params() to get the table for a
     * given node rather than use this directly.
     */
    GHashTable *parameter_cache;
};
//!@}

const char *pcmk_resource_id(const pcmk_resource_t *rsc);
bool pcmk_resource_is_managed(const pcmk_resource_t *rsc);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES__H

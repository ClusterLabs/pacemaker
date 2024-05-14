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

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_resource_is_managed() instead
    unsigned long long flags;       // Group of enum pcmk__rsc_flags

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
    pcmk_node_t *pending_node;      // Node on which pending_action is happening
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

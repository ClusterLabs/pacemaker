/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES__H
#  define PCMK__CRM_COMMON_RESOURCES__H

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

//! Resource variants supported by Pacemaker
enum pe_obj_types {
    // Order matters: some code compares greater or lesser than
    pcmk_rsc_variant_unknown    = -1,   //!< Unknown resource variant
    pcmk_rsc_variant_primitive  = 0,    //!< Primitive resource
    pcmk_rsc_variant_group      = 1,    //!< Group resource
    pcmk_rsc_variant_clone      = 2,    //!< Clone resource
    pcmk_rsc_variant_bundle     = 3,    //!< Bundle resource

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_rsc_variant_unknown instead
    pe_unknown      = pcmk_rsc_variant_unknown,

    //! \deprecated Use pcmk_rsc_variant_primitive instead
    pe_native       = pcmk_rsc_variant_primitive,

    //! \deprecated Use pcmk_rsc_variant_group instead
    pe_group        = pcmk_rsc_variant_group,

    //! \deprecated Use pcmk_rsc_variant_clone instead
    pe_clone        = pcmk_rsc_variant_clone,

    //! \deprecated Use pcmk_rsc_variant_bundle instead
    pe_container    = pcmk_rsc_variant_bundle,
#endif
};

//! What resource needs before it can be recovered from a failed node
enum rsc_start_requirement {
    pcmk_requires_nothing   = 0,    //!< Resource can be recovered immediately
    pcmk_requires_quorum    = 1,    //!< Resource can be recovered if quorate
    pcmk_requires_fencing   = 2,    //!< Resource can be recovered after fencing

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_requires_nothing instead
    rsc_req_nothing         = pcmk_requires_nothing,

    //! \deprecated Use pcmk_requires_quorum instead
    rsc_req_quorum          = pcmk_requires_quorum,

    //! \deprecated Use pcmk_requires_fencing instead
    rsc_req_stonith         = pcmk_requires_fencing,
#endif
};

//! How to recover a resource that is incorrectly active on multiple nodes
enum rsc_recovery_type {
    pcmk_multiply_active_restart    = 0,    //!< Stop on all, start on desired
    pcmk_multiply_active_stop       = 1,    //!< Stop on all and leave stopped
    pcmk_multiply_active_block      = 2,    //!< Do nothing to resource
    pcmk_multiply_active_unexpected = 3,    //!< Stop unexpected instances

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_multiply_active_restart instead
    recovery_stop_start             = pcmk_multiply_active_restart,

    //! \deprecated Use pcmk_multiply_active_stop instead
    recovery_stop_only              = pcmk_multiply_active_stop,

    //! \deprecated Use pcmk_multiply_active_block instead
    recovery_block                  = pcmk_multiply_active_block,

    //! \deprecated Use pcmk_multiply_active_unexpected instead
    recovery_stop_unexpected        = pcmk_multiply_active_unexpected,
#endif
};

//! Resource scheduling flags
enum pcmk_rsc_flags {
    //! No resource flags set (compare with equality rather than bit set)
    pcmk_no_rsc_flags               = 0ULL,

    //! Whether resource has been removed from the configuration
    pcmk_rsc_removed                = (1ULL << 0),

    //! Whether resource is managed
    pcmk_rsc_managed                = (1ULL << 1),

    //! Whether resource is blocked from further action
    pcmk_rsc_blocked                = (1ULL << 2),

    //! Whether resource has been removed but has a container
    pcmk_rsc_removed_filler         = (1ULL << 3),

    //! Whether resource has clone notifications enabled
    pcmk_rsc_notify                 = (1ULL << 4),

    //! Whether resource is not an anonymous clone instance
    pcmk_rsc_unique                 = (1ULL << 5),

    //! Whether resource's class is "stonith"
    pcmk_rsc_fence_device           = (1ULL << 6),

    //! Whether resource can be promoted and demoted
    pcmk_rsc_promotable             = (1ULL << 7),

    //! Whether resource has not yet been assigned to a node
    pcmk_rsc_unassigned             = (1ULL << 8),

    //! Whether resource is in the process of being assigned to a node
    pcmk_rsc_assigning              = (1ULL << 9),

    //! Whether resource is in the process of modifying allowed node scores
    pcmk_rsc_updating_nodes         = (1ULL << 10),

    //! Whether resource is in the process of scheduling actions to restart
    pcmk_rsc_restarting             = (1ULL << 11),

    //! Whether resource must be stopped (instead of demoted) if it is failed
    pcmk_rsc_stop_if_failed         = (1ULL << 12),

    //! Whether a reload action has been scheduled for resource
    pcmk_rsc_reload                 = (1ULL << 13),

    //! Whether resource is a remote connection allowed to run on a remote node
    pcmk_rsc_remote_nesting_allowed = (1ULL << 14),

    //! Whether resource has \c PCMK_META_CRITICAL meta-attribute enabled
    pcmk_rsc_critical               = (1ULL << 15),

    //! Whether resource is considered failed
    pcmk_rsc_failed                 = (1ULL << 16),

    //! Flag for non-scheduler code to use to detect recursion loops
    pcmk_rsc_detect_loop            = (1ULL << 17),

    //! \deprecated Do not use
    pcmk_rsc_runnable               = (1ULL << 18),

    //! Whether resource has pending start action in history
    pcmk_rsc_start_pending          = (1ULL << 19),

    //! \deprecated Do not use
    pcmk_rsc_starting               = (1ULL << 20),

    //! \deprecated Do not use
    pcmk_rsc_stopping               = (1ULL << 21),

    //! Whether resource is multiply active with recovery set to stop_unexpected
    pcmk_rsc_stop_unexpected        = (1ULL << 22),

    //! Whether resource is allowed to live-migrate
    pcmk_rsc_migratable             = (1ULL << 23),

    //! Whether resource has an ignorable failure
    pcmk_rsc_ignore_failure         = (1ULL << 24),

    //! Whether resource is an implicit container resource for a bundle replica
    pcmk_rsc_replica_container      = (1ULL << 25),

    //! Whether resource, its node, or entire cluster is in maintenance mode
    pcmk_rsc_maintenance            = (1ULL << 26),

    //! \deprecated Do not use
    pcmk_rsc_has_filler             = (1ULL << 27),

    //! Whether resource can be started or promoted only on quorate nodes
    pcmk_rsc_needs_quorum           = (1ULL << 28),

    //! Whether resource requires fencing before recovery if on unclean node
    pcmk_rsc_needs_fencing          = (1ULL << 29),

    //! Whether resource can be started or promoted only on unfenced nodes
    pcmk_rsc_needs_unfencing        = (1ULL << 30),
};

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

//!@{
//! \deprecated Do not use
enum pe_restart {
    pe_restart_restart,
    pe_restart_ignore,
};

enum pe_print_options {
    pe_print_log            = (1 << 0),
    pe_print_html           = (1 << 1),
    pe_print_ncurses        = (1 << 2),
    pe_print_printf         = (1 << 3),
    pe_print_dev            = (1 << 4),  // Ignored
    pe_print_details        = (1 << 5),  // Ignored
    pe_print_max_details    = (1 << 6),  // Ignored
    pe_print_rsconly        = (1 << 7),
    pe_print_ops            = (1 << 8),
    pe_print_suppres_nl     = (1 << 9),
    pe_print_xml            = (1 << 10),
    pe_print_brief          = (1 << 11),
    pe_print_pending        = (1 << 12),
    pe_print_clone_details  = (1 << 13),
    pe_print_clone_active   = (1 << 14), // Print clone instances only if active
    pe_print_implicit       = (1 << 15)  // Print implicitly created resources
};
//!@}

// Resource assignment methods (implementation defined by libpacemaker)
//! This type should be considered internal to Pacemaker
typedef struct resource_alloc_functions_s pcmk_assignment_methods_t;

//! Resource object methods
typedef struct resource_object_functions_s {
    /*!
     * \brief Parse variant-specific resource XML from CIB into struct members
     *
     * \param[in,out] rsc        Partially unpacked resource
     * \param[in,out] scheduler  Scheduler data
     *
     * \return TRUE if resource was unpacked successfully, otherwise FALSE
     */
    gboolean (*unpack)(pcmk_resource_t *rsc, pcmk_scheduler_t *scheduler);

    /*!
     * \brief Search for a resource ID in a resource and its children
     *
     * \param[in] rsc      Search this resource and its children
     * \param[in] id       Search for this resource ID
     * \param[in] on_node  If not NULL, limit search to resources on this node
     * \param[in] flags    Group of enum pe_find flags
     *
     * \return Resource that matches search criteria if any, otherwise NULL
     */
    pcmk_resource_t *(*find_rsc)(pcmk_resource_t *rsc, const char *search,
                                 const pcmk_node_t *node, int flags);

    /*!
     * \brief Get value of a resource instance attribute
     *
     * \param[in,out] rsc        Resource to check
     * \param[in]     node       Node to use to evaluate rules
     * \param[in]     create     Ignored
     * \param[in]     name       Name of instance attribute to check
     * \param[in,out] scheduler  Scheduler data
     *
     * \return Value of requested attribute if available, otherwise NULL
     * \note The caller is responsible for freeing the result using free().
     */
    char *(*parameter)(pcmk_resource_t *rsc, pcmk_node_t *node, gboolean create,
                       const char *name, pcmk_scheduler_t *scheduler);

    //! \deprecated Do not use
    void (*print)(pcmk_resource_t *rsc, const char *pre_text, long options,
                  void *print_data);

    /*!
     * \brief Check whether a resource is active
     *
     * \param[in] rsc  Resource to check
     * \param[in] all  If \p rsc is collective, all instances must be active
     *
     * \return TRUE if \p rsc is active, otherwise FALSE
     */
    gboolean (*active)(pcmk_resource_t *rsc, gboolean all);

    /*!
     * \brief Get resource's current or assigned role
     *
     * \param[in] rsc      Resource to check
     * \param[in] current  If TRUE, check current role, otherwise assigned role
     *
     * \return Current or assigned role of \p rsc
     */
    enum rsc_role_e (*state)(const pcmk_resource_t *rsc, gboolean current);

    /*!
     * \brief List nodes where a resource (or any of its children) is
     *
     * \param[in]  rsc      Resource to check
     * \param[out] list     List to add result to
     * \param[in]  current  If 0, list nodes where \p rsc is assigned;
     *                      if 1, where active; if 2, where active or pending
     *
     * \return If list contains only one node, that node, otherwise NULL
     */
    pcmk_node_t *(*location)(const pcmk_resource_t *rsc, GList **list,
                             int current);

    /*!
     * \brief Free all memory used by a resource
     *
     * \param[in,out] rsc  Resource to free
     */
    void (*free)(pcmk_resource_t *rsc);

    /*!
     * \brief Increment cluster's instance counts for a resource
     *
     * Given a resource, increment its cluster's ninstances, disabled_resources,
     * and blocked_resources counts for the resource and its descendants.
     *
     * \param[in,out] rsc  Resource to count
     */
    void (*count)(pcmk_resource_t *rsc);

    /*!
     * \brief Check whether a given resource is in a list of resources
     *
     * \param[in] rsc           Resource ID to check for
     * \param[in] only_rsc      List of resource IDs to check
     * \param[in] check_parent  If TRUE, check top ancestor as well
     *
     * \return TRUE if \p rsc, its top parent if requested, or '*' is in
     *         \p only_rsc, otherwise FALSE
     */
    gboolean (*is_filtered)(const pcmk_resource_t *rsc, GList *only_rsc,
                            gboolean check_parent);

    /*!
     * \brief Find a node (and optionally count all) where resource is active
     *
     * \param[in]  rsc          Resource to check
     * \param[out] count_all    If not NULL, set this to count of active nodes
     * \param[out] count_clean  If not NULL, set this to count of clean nodes
     *
     * \return A node where the resource is active, preferring the source node
     *         if the resource is involved in a partial migration, or a clean,
     *         online node if the resource's \c PCMK_META_REQUIRES is "quorum",
     *         or \c PCMK_VALUE_NOTHING, otherwise \c NULL.
     */
    pcmk_node_t *(*active_node)(const pcmk_resource_t *rsc,
                                unsigned int *count_all,
                                unsigned int *count_clean);

    /*!
     * \brief Get maximum resource instances per node
     *
     * \param[in] rsc  Resource to check
     *
     * \return Maximum number of \p rsc instances that can be active on one node
     */
    unsigned int (*max_per_node)(const pcmk_resource_t *rsc);
} pcmk_rsc_methods_t;

//! Implementation of pcmk_resource_t
struct pe_resource_s {
    char *id;                           //!< Resource ID in configuration
    char *clone_name;                   //!< Resource instance ID in history

    //! Resource configuration (possibly expanded from template)
    xmlNode *xml;

    //! Original resource configuration, if using template
    xmlNode *orig_xml;

    //! Configuration of resource operations (possibly expanded from template)
    xmlNode *ops_xml;

    pcmk_scheduler_t *cluster;          //!< Cluster that resource is part of
    pcmk_resource_t *parent;            //!< Resource's parent resource, if any
    enum pe_obj_types variant;          //!< Resource variant
    void *variant_opaque;               //!< Variant-specific (and private) data
    pcmk_rsc_methods_t *fns;            //!< Resource object methods
    pcmk_assignment_methods_t *cmds;    //!< Resource assignment methods

    enum rsc_recovery_type recovery_type;   //!< How to recover if failed

    enum pe_restart restart_type;   //!< \deprecated Do not use
    int priority;                   //!< Configured priority
    int stickiness;                 //!< Extra preference for current node
    int sort_index;                 //!< Promotion score on assigned node
    int failure_timeout;            //!< Failure timeout
    int migration_threshold;        //!< Migration threshold
    guint remote_reconnect_ms;      //!< Retry interval for remote connections
    char *pending_task;             //!< Pending action in history, if any
    unsigned long long flags;       //!< Group of enum pcmk_rsc_flags

    // @TODO Merge these into flags
    gboolean is_remote_node;        //!< Whether this is a remote connection
    gboolean exclusive_discover;    //!< Whether exclusive probing is enabled

    /* Pay special attention to whether you want to use rsc_cons_lhs and
     * rsc_cons directly, which include only colocations explicitly involving
     * this resource, or call libpacemaker's pcmk__with_this_colocations() and
     * pcmk__this_with_colocations() functions, which may return relevant
     * colocations involving the resource's ancestors as well.
     */

    //!@{
    //! This field should be treated as internal to Pacemaker
    GList *rsc_cons_lhs;      // Colocations of other resources with this one
    GList *rsc_cons;          // Colocations of this resource with others
    GList *rsc_location;      // Location constraints for resource
    GList *actions;           // Actions scheduled for resource
    GList *rsc_tickets;       // Ticket constraints for resource
    //!@}

    pcmk_node_t *allocated_to;  //!< Node resource is assigned to

    //! The destination node, if migrate_to completed but migrate_from has not
    pcmk_node_t *partial_migration_target;

    //! The source node, if migrate_to completed but migrate_from has not
    pcmk_node_t *partial_migration_source;

    //! Nodes where resource may be active
    GList *running_on;

    //! Nodes where resource has been probed (key is node ID, not name)
    GHashTable *known_on;

    //! Nodes where resource may run (key is node ID, not name)
    GHashTable *allowed_nodes;

    enum rsc_role_e role;           //!< Resource's current role
    enum rsc_role_e next_role;      //!< Resource's scheduled next role

    GHashTable *meta;               //!< Resource's meta-attributes
    GHashTable *parameters;         //!< \deprecated Use pe_rsc_params() instead
    GHashTable *utilization;        //!< Resource's utilization attributes

    GList *children;                //!< Resource's child resources, if any

    // Source nodes where stop is needed after migrate_from and migrate_to
    GList *dangling_migrations;

    pcmk_resource_t *container;     //!< Resource containing this one, if any
    GList *fillers;                 //!< Resources contained by this one, if any

    // @COMPAT These should be made const at next API compatibility break
    pcmk_node_t *pending_node;      //!< Node on which pending_task is happening
    pcmk_node_t *lock_node;         //!< Resource shutdown-locked to this node

    time_t lock_time;               //!< When shutdown lock started

    /*!
     * Resource parameters may have node-attribute-based rules, which means the
     * values can vary by node. This table has node names as keys and parameter
     * name/value tables as values. Use pe_rsc_params() to get the table for a
     * given node rather than use this directly.
     */
    GHashTable *parameter_cache;
};

const char *pcmk_multiply_active_text(enum rsc_recovery_type recovery);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES__H

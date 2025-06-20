/*
 * Copyright 2024-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES_INTERNAL__H
#define PCMK__CRM_COMMON_RESOURCES_INTERNAL__H

#include <stdbool.h>                    // bool
#include <stdint.h>                     // uint32_t
#include <glib.h>                       // gboolean, gpointer, guint, etc.
#include <libxml/tree.h>                // xmlNode

#include <crm/common/resources.h>       // pcmk_resource_t
#include <crm/common/roles.h>           // enum rsc_role_e
#include <crm/common/scheduler_types.h> // pcmk_node_t, etc.

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Set resource flags
 *
 * \param[in,out] resource      Resource to set flags for
 * \param[in]     flags_to_set  Group of enum pcmk_rsc_flags to set
 */
#define pcmk__set_rsc_flags(resource, flags_to_set) do {                    \
        (resource)->flags = pcmk__set_flags_as(__func__, __LINE__,          \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_set), #flags_to_set);                                 \
    } while (0)

/*!
 * \internal
 * \brief Clear resource flags
 *
 * \param[in,out] resource        Resource to clear flags for
 * \param[in]     flags_to_clear  Group of enum pcmk_rsc_flags to clear
 */
#define pcmk__clear_rsc_flags(resource, flags_to_clear) do {                \
        (resource)->flags = pcmk__clear_flags_as(__func__, __LINE__,        \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_clear), #flags_to_clear);                             \
    } while (0)

//! Resource variants supported by Pacemaker
enum pcmk__rsc_variant {
    // Order matters: some code compares greater or lesser than
    pcmk__rsc_variant_unknown    = -1,  //!< Unknown resource variant
    pcmk__rsc_variant_primitive  = 0,   //!< Primitive resource
    pcmk__rsc_variant_group      = 1,   //!< Group resource
    pcmk__rsc_variant_clone      = 2,   //!< Clone resource
    pcmk__rsc_variant_bundle     = 3,   //!< Bundle resource
};

//! How to recover a resource that is incorrectly active on multiple nodes
enum pcmk__multiply_active {
    pcmk__multiply_active_restart,      //!< Stop on all, start on desired
    pcmk__multiply_active_stop,         //!< Stop on all and leave stopped
    pcmk__multiply_active_block,        //!< Do nothing to resource
    pcmk__multiply_active_unexpected,   //!< Stop unexpected instances
};

//! Resource scheduling flags
enum pcmk__rsc_flags {
    // No resource flags set (compare with equality rather than bit set)
    pcmk__no_rsc_flags               = 0ULL,

    // Whether resource has been removed from the configuration
    pcmk__rsc_removed                = (1ULL << 0),

    /* NOTE: sbd (at least as of 1.5.2) uses pe_rsc_managed which equates to
     * this value, so the value should not be changed
     */
    // Whether resource is managed
    pcmk__rsc_managed                = (1ULL << 1),

    // Whether resource is blocked from further action
    pcmk__rsc_blocked                = (1ULL << 2),

    // Whether resource has been removed but was launched
    pcmk__rsc_removed_launched       = (1ULL << 3),

    // Whether resource has clone notifications enabled
    pcmk__rsc_notify                 = (1ULL << 4),

    // Whether resource is not an anonymous clone instance
    pcmk__rsc_unique                 = (1ULL << 5),

    // Whether resource's class is "stonith"
    pcmk__rsc_fence_device           = (1ULL << 6),

    // Whether resource can be promoted and demoted
    pcmk__rsc_promotable             = (1ULL << 7),

    // Whether resource has not yet been assigned to a node
    pcmk__rsc_unassigned             = (1ULL << 8),

    // Whether resource is in the process of being assigned to a node
    pcmk__rsc_assigning              = (1ULL << 9),

    // Whether resource is in the process of modifying allowed node scores
    pcmk__rsc_updating_nodes         = (1ULL << 10),

    // Whether resource is in the process of scheduling actions to restart
    pcmk__rsc_restarting             = (1ULL << 11),

    // Whether resource must be stopped (instead of demoted) if it is failed
    pcmk__rsc_stop_if_failed         = (1ULL << 12),

    // Whether a reload action has been scheduled for resource
    pcmk__rsc_reload                 = (1ULL << 13),

    // Whether resource is a remote connection allowed to run on a remote node
    pcmk__rsc_remote_nesting_allowed = (1ULL << 14),

    // Whether resource has \c PCMK_META_CRITICAL meta-attribute enabled
    pcmk__rsc_critical               = (1ULL << 15),

    // Whether resource is considered failed
    pcmk__rsc_failed                 = (1ULL << 16),

    // Flag for non-scheduler code to use to detect recursion loops
    pcmk__rsc_detect_loop            = (1ULL << 17),

    // Whether resource is a Pacemaker Remote connection
    pcmk__rsc_is_remote_connection   = (1ULL << 18),

    // Whether resource has pending start action in history
    pcmk__rsc_start_pending          = (1ULL << 19),

    // Whether resource is probed only on nodes marked exclusive
    pcmk__rsc_exclusive_probes       = (1ULL << 20),

    /*
     * Whether resource is multiply active with recovery set to
     * \c PCMK_VALUE_STOP_UNEXPECTED
     */
    pcmk__rsc_stop_unexpected        = (1ULL << 22),

    // Whether resource is allowed to live-migrate
    pcmk__rsc_migratable             = (1ULL << 23),

    // Whether resource has an ignorable failure
    pcmk__rsc_ignore_failure         = (1ULL << 24),

    // Whether resource is an implicit container resource for a bundle replica
    pcmk__rsc_replica_container      = (1ULL << 25),

    // Whether resource, its node, or entire cluster is in maintenance mode
    pcmk__rsc_maintenance            = (1ULL << 26),

    // Whether resource can be started or promoted only on quorate nodes
    pcmk__rsc_needs_quorum           = (1ULL << 28),

    // Whether resource requires fencing before recovery if on unclean node
    pcmk__rsc_needs_fencing          = (1ULL << 29),

    // Whether resource can be started or promoted only on unfenced nodes
    pcmk__rsc_needs_unfencing        = (1ULL << 30),
};

// Where to look for a resource
enum pcmk__rsc_node {
    pcmk__rsc_node_none     = 0U,           // Nowhere
    pcmk__rsc_node_assigned = (1U << 0),    // Where resource is assigned
    pcmk__rsc_node_current  = (1U << 1),    // Where resource is running
    pcmk__rsc_node_pending  = (1U << 2),    // Where resource is pending
};

//! Resource assignment methods (implementation defined by libpacemaker)
typedef struct pcmk__assignment_methods pcmk__assignment_methods_t;

//! Resource object methods
typedef struct {
    /*!
     * \internal
     * \brief Parse variant-specific resource XML from CIB into struct members
     *
     * \param[in,out] rsc  Partially unpacked resource
     *
     * \return \c true if resource was unpacked successfully, otherwise \c false
     */
    bool (*unpack)(pcmk_resource_t *rsc);

    /*!
     * \internal
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
                                 const pcmk_node_t *node, uint32_t flags);

    /*!
     * \internal
     * \brief Check whether a resource is active
     *
     * \param[in] rsc  Resource to check
     * \param[in] all  If \p rsc is collective, all instances must be active
     *
     * \return TRUE if \p rsc is active, otherwise FALSE
     */
    bool (*active)(const pcmk_resource_t *rsc, bool all);

    /*!
     * \internal
     * \brief Get resource's current or assigned role
     *
     * \param[in] rsc      Resource to check
     * \param[in] current  If \c true, check current role; otherwise, check
     *                     assigned role
     *
     * \return Current or assigned role of \p rsc
     */
    enum rsc_role_e (*state)(const pcmk_resource_t *rsc, bool current);

    /*!
     * \internal
     * \brief List nodes where a resource (or any of its children) is
     *
     * \param[in]  rsc      Resource to check
     * \param[out] list     List to add result to
     * \param[in]  target   Which resource conditions to target (group of
     *                      enum pcmk__rsc_node flags)
     *
     * \return If list contains only one node, that node, otherwise NULL
     */
    pcmk_node_t *(*location)(const pcmk_resource_t *rsc, GList **list,
                             uint32_t target);

    /*!
     * \internal
     * \brief Free all memory used by a resource
     *
     * \param[in,out] rsc  Resource to free
     */
    void (*free)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Increment cluster's instance counts for a resource
     *
     * Given a resource, increment its cluster's ninstances, disabled_resources,
     * and blocked_resources counts for the resource and its descendants.
     *
     * \param[in,out] rsc  Resource to count
     */
    void (*count)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Check whether a given resource is in a list of resources
     *
     * \param[in] rsc           Resource ID to check for
     * \param[in] only_rsc      List of resource IDs to check
     * \param[in] check_parent  If \c true, check top ancestor as well
     *
     * \return \c true if \p rsc, its top parent if requested, or \c "*" is in
     *         \p only_rsc, or \c false otherwise
     */
    bool (*is_filtered)(const pcmk_resource_t *rsc, const GList *only_rsc,
                        bool check_parent);

    /*!
     * \internal
     * \brief Find a node (and optionally count all) where resource is active
     *
     * \param[in]  rsc          Resource to check
     * \param[out] count_all    If not NULL, set this to count of active nodes
     * \param[out] count_clean  If not NULL, set this to count of clean nodes
     *
     * \return A node where the resource is active, preferring the source node
     *         if the resource is involved in a partial migration, or a clean,
     *         online node if the resource's \c PCMK_META_REQUIRES is
     *         \c PCMK_VALUE_QUORUM or \c PCMK_VALUE_NOTHING, otherwise \c NULL.
     */
    pcmk_node_t *(*active_node)(const pcmk_resource_t *rsc,
                                unsigned int *count_all,
                                unsigned int *count_clean);

    /*!
     * \internal
     * \brief Get maximum resource instances per node
     *
     * \param[in] rsc  Resource to check
     *
     * \return Maximum number of \p rsc instances that can be active on one node
     */
    unsigned int (*max_per_node)(const pcmk_resource_t *rsc);
} pcmk__rsc_methods_t;

// Implementation of pcmk__resource_private_t
struct pcmk__resource_private {
    enum pcmk__rsc_variant variant; // Resource variant
    void *variant_opaque;           // Variant-specific data
    char *history_id;               // Resource instance ID in history
    GHashTable *meta;               // Resource meta-attributes
    GHashTable *utilization;        // Resource utilization attributes
    int priority;                   // Priority relative other resources
    int promotion_priority;         // Promotion priority on assigned node
    enum rsc_role_e orig_role;      // Resource's role at start of transition
    enum rsc_role_e next_role;      // Resource's role at end of transition
    int stickiness;                 // Extra preference for current node
    guint failure_expiration_ms;    // Failures expire after this much time
    int ban_after_failures;         // Ban from node after this many failures
    guint remote_reconnect_ms;      // Retry interval for remote connections
    char *pending_action;           // Pending action in history, if any
    const pcmk_node_t *pending_node;// Node on which pending_action is happening
    time_t lock_time;               // When shutdown lock started
    const pcmk_node_t *lock_node;   // Node that resource is shutdown-locked to
    GList *actions;                 // Actions scheduled for resource
    GList *children;                // Resource's child resources, if any
    pcmk_resource_t *parent;        // Resource's parent resource, if any
    pcmk_scheduler_t *scheduler;    // Scheduler data containing resource

    // Resource configuration (possibly expanded from template)
    xmlNode *xml;

    // Original resource configuration, if using template
    xmlNode *orig_xml;

    // Configuration of resource operations (possibly expanded from template)
    xmlNode *ops_xml;

    /*
     * Resource parameters may have node-attribute-based rules, which means the
     * values can vary by node. This table has node names as keys and parameter
     * name/value tables as values. Use pe_rsc_params() to get the table for a
     * given node rather than use this directly.
     */
    GHashTable *parameter_cache;

    /* A "launcher" is defined in one of these ways:
     *
     * - A Pacemaker Remote connection for a guest node or bundle node has its
     *   launcher set to the resource that starts the guest or the bundle
     *   replica's container.
     *
     * - If the user configures the PCMK__META_CONTAINER meta-attribute for this
     *   resource, the launcher is set to that.
     *
     *   If the launcher is a Pacemaker Remote connection resource, this
     *   resource may run only on the node created by that connection.
     *
     *   Otherwise, this resource will be colocated with and ordered after the
     *   launcher, and failures of this resource will cause the launcher to be
     *   recovered instead of this one. This is appropriate for monitoring-only
     *   resources that represent a service launched by the other resource.
     */
    pcmk_resource_t *launcher;

    // Resources launched by this one, if any (pcmk_resource_t *)
    GList *launched;

    // What to do if the resource is incorrectly active on multiple nodes
    enum pcmk__multiply_active multiply_active_policy;

    /* The assigned node (if not NULL) is the one where the resource *should*
     * be active by the end of the current scheduler transition. Only primitive
     * resources have an assigned node. This is a node copy (created by
     * pe__copy_node()) and so must be freed using pcmk__free_node_copy().
     *
     * @TODO This should probably be part of the primitive variant data.
     */
    pcmk_node_t *assigned_node;

    /* The active nodes are ones where the resource is (or might be, if
     * insufficient information is available to be sure) already active at the
     * start of the current scheduler transition.
     *
     * For primitive resources, there should be at most one, but could be more
     * if it is (incorrectly) multiply active. For collective resources, this
     * combines active nodes of all descendants.
     */
    GList *active_nodes;

    /* The next two tables store node copies (created by pe__copy_node()), which
     * share some members with the original node objects and must be freed with
     * pcmk__free_node_copy().
     */

    // Nodes where resource has been probed (key is node ID, not name)
    GHashTable *probed_nodes;

    // Nodes where resource is allowed to run (key is node ID, not name)
    GHashTable *allowed_nodes;

    // The source node, if migrate_to completed but migrate_from has not
    pcmk_node_t *partial_migration_source;

    // The destination node, if migrate_to completed but migrate_from has not
    pcmk_node_t *partial_migration_target;

    // Source nodes where stop is needed after migrate_from and migrate_to
    GList *dangling_migration_sources;

    /* Pay special attention to whether you want to use with_this_colocations
     * and this_with_colocations directly, which include only colocations
     * explicitly involving this resource, or call libpacemaker's
     * pcmk__with_this_colocations() and pcmk__this_with_colocations()
     * functions, which may return relevant colocations involving the resource's
     * ancestors as well.
     */

    // Colocations of other resources with this one
    GList *with_this_colocations;

    // Colocations of this resource with others
    GList *this_with_colocations;

    GList *location_constraints;        // Location constraints for resource
    GList *ticket_constraints;          // Ticket constraints for resource

    const pcmk__rsc_methods_t *fns;         // Resource object methods
    const pcmk__assignment_methods_t *cmds; // Resource assignment methods
};

void pcmk__free_resource(gpointer user_data);
const char *pcmk__multiply_active_text(const pcmk_resource_t *rsc);

/*!
 * \internal
 * \brief Get node where resource is currently active (if any)
 *
 * \param[in] rsc  Resource to check
 *
 * \return Node that \p rsc is active on, if any, otherwise NULL
 */
static inline pcmk_node_t *
pcmk__current_node(const pcmk_resource_t *rsc)
{
    if (rsc == NULL) {
        return NULL;
    }
    return rsc->priv->fns->active_node(rsc, NULL, NULL);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES_INTERNAL__H

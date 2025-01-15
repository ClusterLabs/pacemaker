/*
 * Copyright 2021-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__PACEMAKER_LIBPACEMAKER_PRIVATE__H
#define PCMK__PACEMAKER_LIBPACEMAKER_PRIVATE__H

/* This header is for the sole use of libpacemaker, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#include <stdio.h>                  // NULL
#include <stdint.h>                 // uint32_t
#include <stdbool.h>                // bool, false
#include <glib.h>                   // guint, gpointer, GList, GHashTable
#include <libxml/tree.h>            // xmlNode

#include <crm/common/scheduler.h>   // pcmk_action_t, pcmk_node_t, etc.
#include <crm/common/scheduler_internal.h>  // pcmk__location_t, etc.
#include <crm/cib.h>                // cib_t
#include <crm/lrmd_events.h>        // lrmd_event_data_t
#include <crm/pengine/internal.h>   // pe__const_top_resource(), etc.
#include <pacemaker.h>              // pcmk_injections_t
#include <pacemaker-internal.h>     // pcmk__colocation_t

#ifdef __cplusplus
extern "C" {
#endif

// Colocation flags
enum pcmk__coloc_flags {
    pcmk__coloc_none        = 0U,

    // Primary is affected even if already active
    pcmk__coloc_influence   = (1U << 0),

    // Colocation was explicitly configured in CIB
    pcmk__coloc_explicit    = (1U << 1),
};

// Flags to modify the behavior of add_colocated_node_scores()
enum pcmk__coloc_select {
    // With no other flags, apply all "with this" colocations
    pcmk__coloc_select_default      = 0,

    // Apply "this with" colocations instead of "with this" colocations
    pcmk__coloc_select_this_with    = (1 << 0),

    // Apply only colocations with non-negative scores
    pcmk__coloc_select_nonnegative  = (1 << 1),

    // Apply only colocations with at least one matching node
    pcmk__coloc_select_active       = (1 << 2),
};

// Flags the update_ordered_actions() method can return
enum pcmk__updated {
    pcmk__updated_none      = 0,        // Nothing changed
    pcmk__updated_first     = (1 << 0), // First action was updated
    pcmk__updated_then      = (1 << 1), // Then action was updated
};

#define pcmk__set_updated_flags(au_flags, action, flags_to_set) do {        \
        au_flags = pcmk__set_flags_as(__func__, __LINE__,                   \
                                      LOG_TRACE, "Action update",           \
                                      (action)->uuid, au_flags,             \
                                      (flags_to_set), #flags_to_set);       \
    } while (0)

#define pcmk__clear_updated_flags(au_flags, action, flags_to_clear) do {    \
        au_flags = pcmk__clear_flags_as(__func__, __LINE__,                 \
                                        LOG_TRACE, "Action update",         \
                                        (action)->uuid, au_flags,           \
                                        (flags_to_clear), #flags_to_clear); \
    } while (0)

// Resource assignment methods
struct pcmk__assignment_methods {
    /*!
     * \internal
     * \brief Assign a resource to a node
     *
     * \param[in,out] rsc           Resource to assign to a node
     * \param[in]     prefer        Node to prefer, if all else is equal
     * \param[in]     stop_if_fail  If \c true and \p rsc can't be assigned to a
     *                              node, set next role to stopped and update
     *                              existing actions (if \p rsc is not a
     *                              primitive, this applies to its primitive
     *                              descendants instead)
     *
     * \return Node that \p rsc is assigned to, if assigned entirely to one node
     *
     * \note If \p stop_if_fail is \c false, then \c pcmk__unassign_resource()
     *       can completely undo the assignment. A successful assignment can be
     *       either undone or left alone as final. A failed assignment has the
     *       same effect as calling pcmk__unassign_resource(); there are no side
     *       effects on roles or actions.
     */
    pcmk_node_t *(*assign)(pcmk_resource_t *rsc, const pcmk_node_t *prefer,
                           bool stop_if_fail);

    /*!
     * \internal
     * \brief Create all actions needed for a given resource
     *
     * \param[in,out] rsc  Resource to create actions for
     */
    void (*create_actions)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Schedule any probes needed for a resource on a node
     *
     * \param[in,out] rsc   Resource to create probe for
     * \param[in,out] node  Node to create probe on
     *
     * \return true if any probe was created, otherwise false
     */
    bool (*create_probe)(pcmk_resource_t *rsc, pcmk_node_t *node);

    /*!
     * \internal
     * \brief Create implicit constraints needed for a resource
     *
     * \param[in,out] rsc  Resource to create implicit constraints for
     */
    void (*internal_constraints)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Apply a colocation's score to node scores or resource priority
     *
     * Given a colocation constraint, apply its score to the dependent's
     * allowed node scores (if we are still placing resources) or priority (if
     * we are choosing promotable clone instance roles).
     *
     * \param[in,out] dependent      Dependent resource in colocation
     * \param[in]     primary        Primary resource in colocation
     * \param[in]     colocation     Colocation constraint to apply
     * \param[in]     for_dependent  true if called on behalf of dependent
     *
     * \return The score added to the dependent's priority
     */
    int (*apply_coloc_score)(pcmk_resource_t *dependent,
                             const pcmk_resource_t *primary,
                             const pcmk__colocation_t *colocation,
                             bool for_dependent);

    /*!
     * \internal
     * \brief Create list of all resources in colocations with a given resource
     *
     * Given a resource, create a list of all resources involved in mandatory
     * colocations with it, whether directly or via chained colocations.
     *
     * \param[in]     rsc             Resource to add to colocated list
     * \param[in]     orig_rsc        Resource originally requested
     * \param[in,out] colocated_rscs  Existing list
     *
     * \return List of given resource and all resources involved in colocations
     *
     * \note This function is recursive; top-level callers should pass NULL as
     *       \p colocated_rscs and \p orig_rsc, and the desired resource as
     *       \p rsc. The recursive calls will use other values.
     */
    GList *(*colocated_resources)(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList *colocated_rscs);

    /*!
     * \internal
     * \brief Add colocations affecting a resource as primary to a list
     *
     * Given a resource being assigned (\p orig_rsc) and a resource somewhere in
     * its chain of ancestors (\p rsc, which may be \p orig_rsc), get
     * colocations that affect the ancestor as primary and should affect the
     * resource, and add them to a given list.
     *
     * \param[in]     rsc       Resource whose colocations should be added
     * \param[in]     orig_rsc  Affected resource (\p rsc or a descendant)
     * \param[in,out] list      List of colocations to add to
     *
     * \note All arguments should be non-NULL.
     * \note The pcmk__with_this_colocations() wrapper should usually be used
     *       instead of using this method directly.
     */
    void (*with_this_colocations)(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList **list);

    /*!
     * \internal
     * \brief Add colocations affecting a resource as dependent to a list
     *
     * Given a resource being assigned (\p orig_rsc) and a resource somewhere in
     * its chain of ancestors (\p rsc, which may be \p orig_rsc), get
     * colocations that affect the ancestor as dependent and should affect the
     * resource, and add them to a given list.
     *
     *
     * \param[in]     rsc       Resource whose colocations should be added
     * \param[in]     orig_rsc  Affected resource (\p rsc or a descendant)
     * \param[in,out] list      List of colocations to add to
     *
     * \note All arguments should be non-NULL.
     * \note The pcmk__this_with_colocations() wrapper should usually be used
     *       instead of using this method directly.
     */
    void (*this_with_colocations)(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList **list);

    /*!
     * \internal
     * \brief Update nodes with scores of colocated resources' nodes
     *
     * Given a table of nodes and a resource, update the nodes' scores with the
     * scores of the best nodes matching the attribute used for each of the
     * resource's relevant colocations.
     *
     * \param[in,out] source_rsc  Resource whose node scores to add
     * \param[in]     target_rsc  Resource on whose behalf to update \p *nodes
     * \param[in]     log_id      Resource ID for logs (if \c NULL, use
     *                            \p source_rsc ID)
     * \param[in,out] nodes       Nodes to update (set initial contents to
     *                            \c NULL to copy allowed nodes from
     *                            \p source_rsc)
     * \param[in]     colocation  Original colocation constraint (used to get
     *                            configured primary resource's stickiness, and
     *                            to get colocation node attribute; if \c NULL,
     *                            <tt>source_rsc</tt>'s own matching node scores
     *                            will not be added, and \p *nodes must be
     *                            \c NULL as well)
     * \param[in]     factor      Incorporate scores multiplied by this factor
     * \param[in]     flags       Bitmask of enum pcmk__coloc_select values
     *
     * \note \c NULL \p target_rsc, \c NULL \p *nodes, \c NULL \p colocation,
     *       and the \c pcmk__coloc_select_this_with flag are used together (and
     *       only by \c cmp_resources()).
     * \note The caller remains responsible for freeing \p *nodes.
     */
    void (*add_colocated_node_scores)(pcmk_resource_t *source_rsc,
                                      const pcmk_resource_t *target_rsc,
                                      const char *log_id, GHashTable **nodes,
                                      const pcmk__colocation_t *colocation,
                                      float factor, uint32_t flags);

    /*!
     * \internal
     * \brief Apply a location constraint to a resource's allowed node scores
     *
     * \param[in,out] rsc       Resource to apply constraint to
     * \param[in,out] location  Location constraint to apply
     */
    void (*apply_location)(pcmk_resource_t *rsc, pcmk__location_t *location);

    /*!
     * \internal
     * \brief Return action flags for a given resource action
     *
     * \param[in,out] action  Action to get flags for
     * \param[in]     node    If not NULL, limit effects to this node
     *
     * \return Flags appropriate to \p action on \p node
     * \note For primitives, this will be the same as action->flags regardless
     *       of node. For collective resources, the flags can differ due to
     *       multiple instances possibly being involved.
     */
    uint32_t (*action_flags)(pcmk_action_t *action, const pcmk_node_t *node);

    /*!
     * \internal
     * \brief Update two actions according to an ordering between them
     *
     * Given information about an ordering of two actions, update the actions'
     * flags (and runnable_before members if appropriate) as appropriate for the
     * ordering. Effects may cascade to other orderings involving the actions as
     * well.
     *
     * \param[in,out] first      'First' action in an ordering
     * \param[in,out] then       'Then' action in an ordering
     * \param[in]     node       If not NULL, limit scope of ordering to this
     *                           node (only used when interleaving instances)
     * \param[in]     flags      Action flags for \p first for ordering purposes
     * \param[in]     filter     Action flags to limit scope of certain updates
     *                           (may include pcmk__action_optional to affect
     *                           only mandatory actions and
     *                           pcmk__action_runnable to affect only runnable
     *                           actions)
     * \param[in]     type       Group of enum pcmk__action_relation_flags
     * \param[in,out] scheduler  Scheduler data
     *
     * \return Group of enum pcmk__updated flags indicating what was updated
     */
    uint32_t (*update_ordered_actions)(pcmk_action_t *first,
                                       pcmk_action_t *then,
                                       const pcmk_node_t *node, uint32_t flags,
                                       uint32_t filter, uint32_t type,
                                       pcmk_scheduler_t *scheduler);

    /*!
     * \internal
     * \brief Output a summary of scheduled actions for a resource
     *
     * \param[in,out] rsc  Resource to output actions for
     */
    void (*output_actions)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Add a resource's actions to the transition graph
     *
     * \param[in,out] rsc  Resource whose actions should be added
     */
    void (*add_actions_to_graph)(pcmk_resource_t *rsc);

    /*!
     * \internal
     * \brief Add meta-attributes relevant to transition graph actions to XML
     *
     * If a given resource supports variant-specific meta-attributes that are
     * needed for transition graph actions, add them to a given XML element.
     *
     * \param[in]     rsc  Resource whose meta-attributes should be added
     * \param[in,out] xml  Transition graph action attributes XML to add to
     */
    void (*add_graph_meta)(const pcmk_resource_t *rsc, xmlNode *xml);

    /*!
     * \internal
     * \brief Add a resource's utilization to a table of utilization values
     *
     * This function is used when summing the utilization of a resource and all
     * resources colocated with it, to determine whether a node has sufficient
     * capacity. Given a resource and a table of utilization values, it will add
     * the resource's utilization to the existing values, if the resource has
     * not yet been assigned to a node.
     *
     * \param[in]     rsc          Resource with utilization to add
     * \param[in]     orig_rsc     Resource being assigned (for logging only)
     * \param[in]     all_rscs     List of all resources that will be summed
     * \param[in,out] utilization  Table of utilization values to add to
     */
    void (*add_utilization)(const pcmk_resource_t *rsc,
                            const pcmk_resource_t *orig_rsc, GList *all_rscs,
                            GHashTable *utilization);

    /*!
     * \internal
     * \brief Apply a shutdown lock for a resource, if appropriate
     *
     * \param[in,out] rsc       Resource to check for shutdown lock
     */
    void (*shutdown_lock)(pcmk_resource_t *rsc);
};

// Actions (pcmk_sched_actions.c)

G_GNUC_INTERNAL
void pcmk__update_action_for_orderings(pcmk_action_t *action,
                                       pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
uint32_t pcmk__update_ordered_actions(pcmk_action_t *first, pcmk_action_t *then,
                                      const pcmk_node_t *node, uint32_t flags,
                                      uint32_t filter, uint32_t type,
                                      pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__log_action(const char *pre_text, const pcmk_action_t *action,
                      bool details);

G_GNUC_INTERNAL
pcmk_action_t *pcmk__new_cancel_action(pcmk_resource_t *rsc, const char *name,
                                       guint interval_ms,
                                       const pcmk_node_t *node);

G_GNUC_INTERNAL
pcmk_action_t *pcmk__new_shutdown_action(pcmk_node_t *node);

G_GNUC_INTERNAL
bool pcmk__action_locks_rsc_to_node(const pcmk_action_t *action);

G_GNUC_INTERNAL
void pcmk__deduplicate_action_inputs(pcmk_action_t *action);

G_GNUC_INTERNAL
void pcmk__output_actions(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
bool pcmk__check_action_config(pcmk_resource_t *rsc, pcmk_node_t *node,
                               const xmlNode *xml_op);

G_GNUC_INTERNAL
void pcmk__handle_rsc_config_changes(pcmk_scheduler_t *scheduler);


// Recurring actions (pcmk_sched_recurring.c)

G_GNUC_INTERNAL
void pcmk__create_recurring_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__schedule_cancel(pcmk_resource_t *rsc, const char *call_id,
                           const char *task, guint interval_ms,
                           const pcmk_node_t *node, const char *reason);

G_GNUC_INTERNAL
void pcmk__reschedule_recurring(pcmk_resource_t *rsc, const char *task,
                                guint interval_ms, pcmk_node_t *node);

G_GNUC_INTERNAL
bool pcmk__action_is_recurring(const pcmk_action_t *action);


// Producing transition graphs (pcmk_graph_producer.c)

G_GNUC_INTERNAL
bool pcmk__graph_has_loop(const pcmk_action_t *init_action,
                          const pcmk_action_t *action,
                          pcmk__related_action_t *input);

G_GNUC_INTERNAL
void pcmk__add_rsc_actions_to_graph(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__create_graph(pcmk_scheduler_t *scheduler);


// Fencing (pcmk_sched_fencing.c)

G_GNUC_INTERNAL
void pcmk__order_vs_fence(pcmk_action_t *stonith_op,
                          pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__order_vs_unfence(const pcmk_resource_t *rsc, pcmk_node_t *node,
                            pcmk_action_t *action,
                            enum pcmk__action_relation_flags order);

G_GNUC_INTERNAL
void pcmk__fence_guest(pcmk_node_t *node);

G_GNUC_INTERNAL
bool pcmk__node_unfenced(const pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__order_restart_vs_unfence(gpointer data, gpointer user_data);


// Injected scheduler inputs (pcmk_sched_injections.c)

G_GNUC_INTERNAL
void pcmk__inject_scheduler_input(pcmk_scheduler_t *scheduler, cib_t *cib,
                                  const pcmk_injections_t *injections);


// Constraints of any type (pcmk_sched_constraints.c)

G_GNUC_INTERNAL
pcmk_resource_t *pcmk__find_constraint_resource(GList *rsc_list,
                                                const char *id);

G_GNUC_INTERNAL
int pcmk__parse_constraint_role(const char *id, const char *role_spec,
                                enum rsc_role_e *role);

G_GNUC_INTERNAL
xmlNode *pcmk__expand_tags_in_sets(xmlNode *xml_obj,
                                   const pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
bool pcmk__valid_resource_or_tag(const pcmk_scheduler_t *scheduler,
                                 const char *id, pcmk_resource_t **rsc,
                                 pcmk__idref_t **tag);

G_GNUC_INTERNAL
bool pcmk__tag_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
                      bool convert_rsc, const pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__create_internal_constraints(pcmk_scheduler_t *scheduler);


// Location constraints

G_GNUC_INTERNAL
void pcmk__unpack_location(xmlNode *xml_obj, pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
pcmk__location_t *pcmk__new_location(const char *id, pcmk_resource_t *rsc,
                                     int node_score, const char *discover_mode,
                                     pcmk_node_t *foo_node);

G_GNUC_INTERNAL
void pcmk__apply_locations(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__apply_location(pcmk_resource_t *rsc, pcmk__location_t *constraint);


// Colocation constraints (pcmk_sched_colocation.c)

enum pcmk__coloc_affects {
    pcmk__coloc_affects_nothing = 0,
    pcmk__coloc_affects_location,
    pcmk__coloc_affects_role,
};

G_GNUC_INTERNAL
const char *pcmk__colocation_node_attr(const pcmk_node_t *node,
                                       const char *attr,
                                       const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
enum pcmk__coloc_affects pcmk__colocation_affects(const pcmk_resource_t
                                                    *dependent,
                                                  const pcmk_resource_t
                                                    *primary,
                                                  const pcmk__colocation_t
                                                    *colocation,
                                                  bool preview);

G_GNUC_INTERNAL
void pcmk__apply_coloc_to_scores(pcmk_resource_t *dependent,
                                 const pcmk_resource_t *primary,
                                 const pcmk__colocation_t *colocation);

G_GNUC_INTERNAL
int pcmk__apply_coloc_to_priority(pcmk_resource_t *dependent,
                                  const pcmk_resource_t *primary,
                                  const pcmk__colocation_t *colocation);

G_GNUC_INTERNAL
void pcmk__add_colocated_node_scores(pcmk_resource_t *source_rsc,
                                     const pcmk_resource_t *target_rsc,
                                     const char *log_id, GHashTable **nodes,
                                     const pcmk__colocation_t *colocation,
                                     float factor, uint32_t flags);

G_GNUC_INTERNAL
void pcmk__add_dependent_scores(gpointer data, gpointer user_data);

G_GNUC_INTERNAL
void pcmk__colocation_intersect_nodes(pcmk_resource_t *dependent,
                                      const pcmk_resource_t *primary,
                                      const pcmk__colocation_t *colocation,
                                      const GList *primary_nodes,
                                      bool merge_scores);

G_GNUC_INTERNAL
void pcmk__unpack_colocation(xmlNode *xml_obj, pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__add_this_with(GList **list, const pcmk__colocation_t *colocation,
                         const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__add_this_with_list(GList **list, GList *addition,
                              const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__add_with_this(GList **list, const pcmk__colocation_t *colocation,
                         const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__add_with_this_list(GList **list, GList *addition,
                              const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
GList *pcmk__with_this_colocations(const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
GList *pcmk__this_with_colocations(const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__new_colocation(const char *id, const char *node_attr, int score,
                          pcmk_resource_t *dependent, pcmk_resource_t *primary,
                          const char *dependent_role_spec,
                          const char *primary_role_spec, uint32_t flags);

G_GNUC_INTERNAL
void pcmk__block_colocation_dependents(pcmk_action_t *action);

G_GNUC_INTERNAL
bool pcmk__colocation_has_influence(const pcmk__colocation_t *colocation,
                                    const pcmk_resource_t *rsc);


// Ordering constraints (pcmk_sched_ordering.c)

G_GNUC_INTERNAL
void pcmk__new_ordering(pcmk_resource_t *first_rsc, char *first_task,
                        pcmk_action_t *first_action, pcmk_resource_t *then_rsc,
                        char *then_task, pcmk_action_t *then_action,
                        uint32_t flags, pcmk_scheduler_t *sched);

G_GNUC_INTERNAL
void pcmk__unpack_ordering(xmlNode *xml_obj, pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__disable_invalid_orderings(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
void pcmk__order_stops_before_shutdown(pcmk_node_t *node,
                                       pcmk_action_t *shutdown_op);

G_GNUC_INTERNAL
void pcmk__apply_orderings(pcmk_scheduler_t *sched);

G_GNUC_INTERNAL
void pcmk__order_after_each(pcmk_action_t *after, GList *list);


/*!
 * \internal
 * \brief Create a new ordering between two resource actions
 *
 * \param[in,out] first_rsc   Resource for 'first' action
 * \param[in,out] first_task  Action key for 'first' action
 * \param[in]     then_rsc    Resource for 'then' action
 * \param[in,out] then_task   Action key for 'then' action
 * \param[in]     flags       Group of enum pcmk__action_relation_flags
 */
#define pcmk__order_resource_actions(first_rsc, first_task,                 \
                                     then_rsc, then_task, flags)            \
    pcmk__new_ordering((first_rsc),                                         \
                       pcmk__op_key((first_rsc)->id, (first_task), 0),      \
                       NULL,                                                \
                       (then_rsc),                                          \
                       pcmk__op_key((then_rsc)->id, (then_task), 0),        \
                       NULL, (flags), (first_rsc)->priv->scheduler)

#define pcmk__order_starts(rsc1, rsc2, flags)                \
    pcmk__order_resource_actions((rsc1), PCMK_ACTION_START,  \
                                 (rsc2), PCMK_ACTION_START, (flags))

#define pcmk__order_stops(rsc1, rsc2, flags)                 \
    pcmk__order_resource_actions((rsc1), PCMK_ACTION_STOP,   \
                                 (rsc2), PCMK_ACTION_STOP, (flags))


// Ticket constraints (pcmk_sched_tickets.c)

G_GNUC_INTERNAL
void pcmk__unpack_rsc_ticket(xmlNode *xml_obj, pcmk_scheduler_t *scheduler);


// Promotable clone resources (pcmk_sched_promotable.c)

G_GNUC_INTERNAL
void pcmk__add_promotion_scores(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__require_promotion_tickets(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__set_instance_roles(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__create_promotable_actions(pcmk_resource_t *clone);

G_GNUC_INTERNAL
void pcmk__promotable_restart_ordering(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__order_promotable_instances(pcmk_resource_t *clone);

G_GNUC_INTERNAL
void pcmk__update_dependent_with_promotable(const pcmk_resource_t *primary,
                                            pcmk_resource_t *dependent,
                                            const pcmk__colocation_t
                                                *colocation);

G_GNUC_INTERNAL
int pcmk__update_promotable_dependent_priority(const pcmk_resource_t *primary,
                                               pcmk_resource_t *dependent,
                                               const pcmk__colocation_t
                                                   *colocation);


// Pacemaker Remote nodes (pcmk_sched_remote.c)

G_GNUC_INTERNAL
bool pcmk__is_failed_remote_node(const pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__order_remote_connection_actions(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
bool pcmk__rsc_corresponds_to_guest(const pcmk_resource_t *rsc,
                                    const pcmk_node_t *node);

G_GNUC_INTERNAL
pcmk_node_t *pcmk__connection_host_for_action(const pcmk_action_t *action);

G_GNUC_INTERNAL
void pcmk__substitute_remote_addr(pcmk_resource_t *rsc, GHashTable *params);

G_GNUC_INTERNAL
void pcmk__add_guest_meta_to_xml(xmlNode *args_xml,
                                 const pcmk_action_t *action);


// Primitives (pcmk_sched_primitive.c)

G_GNUC_INTERNAL
pcmk_node_t *pcmk__primitive_assign(pcmk_resource_t *rsc,
                                    const pcmk_node_t *prefer,
                                    bool stop_if_fail);

G_GNUC_INTERNAL
void pcmk__primitive_create_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__primitive_internal_constraints(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
uint32_t pcmk__primitive_action_flags(pcmk_action_t *action,
                                      const pcmk_node_t *node);

G_GNUC_INTERNAL
int pcmk__primitive_apply_coloc_score(pcmk_resource_t *dependent,
                                      const pcmk_resource_t *primary,
                                      const pcmk__colocation_t *colocation,
                                      bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_primitive_colocations(const pcmk_resource_t *rsc,
                                      const pcmk_resource_t *orig_rsc,
                                      GList **list);

G_GNUC_INTERNAL
void pcmk__primitive_with_colocations(const pcmk_resource_t *rsc,
                                      const pcmk_resource_t *orig_rsc,
                                      GList **list);

G_GNUC_INTERNAL
void pcmk__schedule_cleanup(pcmk_resource_t *rsc, const pcmk_node_t *node,
                            bool optional);

G_GNUC_INTERNAL
void pcmk__primitive_add_graph_meta(const pcmk_resource_t *rsc, xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__primitive_add_utilization(const pcmk_resource_t *rsc,
                                     const pcmk_resource_t *orig_rsc,
                                     GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__primitive_shutdown_lock(pcmk_resource_t *rsc);


// Groups (pcmk_sched_group.c)

G_GNUC_INTERNAL
pcmk_node_t *pcmk__group_assign(pcmk_resource_t *rsc, const pcmk_node_t *prefer,
                                bool stop_if_fail);

G_GNUC_INTERNAL
void pcmk__group_create_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__group_internal_constraints(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
int pcmk__group_apply_coloc_score(pcmk_resource_t *dependent,
                                  const pcmk_resource_t *primary,
                                  const pcmk__colocation_t *colocation,
                                  bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_group_colocations(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList **list);

G_GNUC_INTERNAL
void pcmk__group_with_colocations(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList **list);

G_GNUC_INTERNAL
void pcmk__group_add_colocated_node_scores(pcmk_resource_t *source_rsc,
                                           const pcmk_resource_t *target_rsc,
                                           const char *log_id,
                                           GHashTable **nodes,
                                           const pcmk__colocation_t *colocation,
                                           float factor, uint32_t flags);

G_GNUC_INTERNAL
void pcmk__group_apply_location(pcmk_resource_t *rsc,
                                pcmk__location_t *location);

G_GNUC_INTERNAL
uint32_t pcmk__group_action_flags(pcmk_action_t *action,
                                  const pcmk_node_t *node);

G_GNUC_INTERNAL
uint32_t pcmk__group_update_ordered_actions(pcmk_action_t *first,
                                            pcmk_action_t *then,
                                            const pcmk_node_t *node,
                                            uint32_t flags, uint32_t filter,
                                            uint32_t type,
                                            pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
GList *pcmk__group_colocated_resources(const pcmk_resource_t *rsc,
                                       const pcmk_resource_t *orig_rsc,
                                       GList *colocated_rscs);

G_GNUC_INTERNAL
void pcmk__group_add_utilization(const pcmk_resource_t *rsc,
                                 const pcmk_resource_t *orig_rsc,
                                 GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__group_shutdown_lock(pcmk_resource_t *rsc);


// Clones (pcmk_sched_clone.c)

G_GNUC_INTERNAL
pcmk_node_t *pcmk__clone_assign(pcmk_resource_t *rsc, const pcmk_node_t *prefer,
                                bool stop_if_fail);

G_GNUC_INTERNAL
void pcmk__clone_create_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__clone_create_probe(pcmk_resource_t *rsc, pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__clone_internal_constraints(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
int pcmk__clone_apply_coloc_score(pcmk_resource_t *dependent,
                                  const pcmk_resource_t *primary,
                                  const pcmk__colocation_t *colocation,
                                  bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_clone_colocations(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList **list);

G_GNUC_INTERNAL
void pcmk__clone_with_colocations(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList **list);

G_GNUC_INTERNAL
void pcmk__clone_apply_location(pcmk_resource_t *rsc,
                                pcmk__location_t *constraint);

G_GNUC_INTERNAL
uint32_t pcmk__clone_action_flags(pcmk_action_t *action,
                                  const pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__clone_add_actions_to_graph(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__clone_add_graph_meta(const pcmk_resource_t *rsc, xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__clone_add_utilization(const pcmk_resource_t *rsc,
                                 const pcmk_resource_t *orig_rsc,
                                 GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__clone_shutdown_lock(pcmk_resource_t *rsc);

// Bundles (pcmk_sched_bundle.c)

G_GNUC_INTERNAL
pcmk_node_t *pcmk__bundle_assign(pcmk_resource_t *rsc,
                                 const pcmk_node_t *prefer, bool stop_if_fail);

G_GNUC_INTERNAL
void pcmk__bundle_create_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__bundle_create_probe(pcmk_resource_t *rsc, pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__bundle_internal_constraints(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
int pcmk__bundle_apply_coloc_score(pcmk_resource_t *dependent,
                                   const pcmk_resource_t *primary,
                                   const pcmk__colocation_t *colocation,
                                   bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_bundle_colocations(const pcmk_resource_t *rsc,
                                   const pcmk_resource_t *orig_rsc,
                                   GList **list);

G_GNUC_INTERNAL
void pcmk__bundle_with_colocations(const pcmk_resource_t *rsc,
                                   const pcmk_resource_t *orig_rsc,
                                   GList **list);

G_GNUC_INTERNAL
void pcmk__bundle_apply_location(pcmk_resource_t *rsc,
                                 pcmk__location_t *constraint);

G_GNUC_INTERNAL
uint32_t pcmk__bundle_action_flags(pcmk_action_t *action,
                                   const pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__output_bundle_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__bundle_add_actions_to_graph(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__bundle_add_utilization(const pcmk_resource_t *rsc,
                                  const pcmk_resource_t *orig_rsc,
                                  GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__bundle_shutdown_lock(pcmk_resource_t *rsc);


// Clone instances or bundle replica containers (pcmk_sched_instances.c)

G_GNUC_INTERNAL
void pcmk__assign_instances(pcmk_resource_t *collective, GList *instances,
                            int max_total, int max_per_node);

G_GNUC_INTERNAL
void pcmk__create_instance_actions(pcmk_resource_t *rsc, GList *instances);

G_GNUC_INTERNAL
bool pcmk__instance_matches(const pcmk_resource_t *instance,
                            const pcmk_node_t *node, enum rsc_role_e role,
                            bool current);

G_GNUC_INTERNAL
pcmk_resource_t *pcmk__find_compatible_instance(const pcmk_resource_t *match_rsc,
                                                const pcmk_resource_t *rsc,
                                                enum rsc_role_e role,
                                                bool current);

G_GNUC_INTERNAL
uint32_t pcmk__instance_update_ordered_actions(pcmk_action_t *first,
                                               pcmk_action_t *then,
                                               const pcmk_node_t *node,
                                               uint32_t flags, uint32_t filter,
                                               uint32_t type,
                                               pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
uint32_t pcmk__collective_action_flags(pcmk_action_t *action,
                                       const GList *instances,
                                       const pcmk_node_t *node);


// Injections (pcmk_injections.c)

G_GNUC_INTERNAL
xmlNode *pcmk__inject_node(cib_t *cib_conn, const char *node, const char *uuid);

G_GNUC_INTERNAL
xmlNode *pcmk__inject_node_state_change(cib_t *cib_conn, const char *node,
                                        bool up);

G_GNUC_INTERNAL
xmlNode *pcmk__inject_resource_history(pcmk__output_t *out, xmlNode *cib_node,
                                       const char *resource,
                                       const char *lrm_name,
                                       const char *rclass,
                                       const char *rtype,
                                       const char *rprovider);

G_GNUC_INTERNAL
void pcmk__inject_failcount(pcmk__output_t *out, cib_t *cib_conn,
                            xmlNode *cib_node, const char *resource,
                            const char *task, guint interval_ms, int rc,
                            bool infinity);

G_GNUC_INTERNAL
xmlNode *pcmk__inject_action_result(xmlNode *cib_resource,
                                    lrmd_event_data_t *op, const char *node,
                                    int target_rc);


// Nodes (pcmk_sched_nodes.c)

//! Options for checking node availability
enum pcmk__node_availability {
    //! Disallow offline or unclean nodes (always implied)
    pcmk__node_alive                = 0,

    //! Disallow shutting down, standby, and maintenance nodes
    pcmk__node_usable               = (1 << 0),

    //! Disallow nodes with zero score
    pcmk__node_no_zero              = (1 << 1),

    //! Disallow nodes with negative scores
    pcmk__node_no_negative          = (1 << 2),

    //! Disallow nodes with minus infinity scores
    pcmk__node_no_banned            = (1 << 3),

    //! Disallow guest nodes whose guest resource is unrunnable
    pcmk__node_no_unrunnable_guest  = (1 << 4),

    //! Exempt guest nodes from alive and usable checks
    pcmk__node_exempt_guest         = (1 << 5),
};

G_GNUC_INTERNAL
bool pcmk__node_available(const pcmk_node_t *node, uint32_t flags);

G_GNUC_INTERNAL
bool pcmk__any_node_available(GHashTable *nodes, uint32_t flags);

G_GNUC_INTERNAL
GHashTable *pcmk__copy_node_table(GHashTable *nodes);

G_GNUC_INTERNAL
void pcmk__copy_node_tables(const pcmk_resource_t *rsc, GHashTable **copy);

G_GNUC_INTERNAL
void pcmk__restore_node_tables(pcmk_resource_t *rsc, GHashTable *backup);

G_GNUC_INTERNAL
GList *pcmk__sort_nodes(GList *nodes, pcmk_node_t *active_node);

G_GNUC_INTERNAL
void pcmk__apply_node_health(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
pcmk_node_t *pcmk__top_allowed_node(const pcmk_resource_t *rsc,
                                    const pcmk_node_t *node);


// Functions applying to more than one variant (pcmk_sched_resource.c)

G_GNUC_INTERNAL
void pcmk__set_assignment_methods(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
bool pcmk__rsc_agent_changed(pcmk_resource_t *rsc, pcmk_node_t *node,
                             const xmlNode *rsc_entry, bool active_on_node);

G_GNUC_INTERNAL
GList *pcmk__rscs_matching_id(const char *id,
                              const pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
GList *pcmk__colocated_resources(const pcmk_resource_t *rsc,
                                 const pcmk_resource_t *orig_rsc,
                                 GList *colocated_rscs);

G_GNUC_INTERNAL
void pcmk__noop_add_graph_meta(const pcmk_resource_t *rsc, xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__output_resource_actions(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__assign_resource(pcmk_resource_t *rsc, pcmk_node_t *node, bool force,
                           bool stop_if_fail);

G_GNUC_INTERNAL
void pcmk__unassign_resource(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__threshold_reached(pcmk_resource_t *rsc, const pcmk_node_t *node,
                             pcmk_resource_t **failed);

G_GNUC_INTERNAL
void pcmk__sort_resources(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
gint pcmk__cmp_instance(gconstpointer a, gconstpointer b);

G_GNUC_INTERNAL
gint pcmk__cmp_instance_number(gconstpointer a, gconstpointer b);


// Functions related to probes (pcmk_sched_probes.c)

G_GNUC_INTERNAL
bool pcmk__probe_rsc_on_node(pcmk_resource_t *rsc, pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__order_probes(pcmk_scheduler_t *scheduler);

G_GNUC_INTERNAL
bool pcmk__probe_resource_list(GList *rscs, pcmk_node_t *node);

G_GNUC_INTERNAL
void pcmk__schedule_probes(pcmk_scheduler_t *scheduler);


// Functions related to live migration (pcmk_sched_migration.c)

void pcmk__create_migration_actions(pcmk_resource_t *rsc,
                                    const pcmk_node_t *current);

void pcmk__abort_dangling_migration(void *data, void *user_data);

bool pcmk__rsc_can_migrate(const pcmk_resource_t *rsc,
                           const pcmk_node_t *current);

void pcmk__order_migration_equivalents(pcmk__action_relation_t *order);


// Functions related to node utilization (pcmk_sched_utilization.c)

G_GNUC_INTERNAL
int pcmk__compare_node_capacities(const pcmk_node_t *node1,
                                  const pcmk_node_t *node2);

G_GNUC_INTERNAL
void pcmk__consume_node_capacity(GHashTable *current_utilization,
                                 const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__release_node_capacity(GHashTable *current_utilization,
                                 const pcmk_resource_t *rsc);

G_GNUC_INTERNAL
const pcmk_node_t *pcmk__ban_insufficient_capacity(pcmk_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__create_utilization_constraints(pcmk_resource_t *rsc,
                                          const GList *allowed_nodes);

G_GNUC_INTERNAL
void pcmk__show_node_capacities(const char *desc, pcmk_scheduler_t *scheduler);


// Functions related to the scheduler (pcmk_scheduler.c)

G_GNUC_INTERNAL
int pcmk__init_scheduler(pcmk__output_t *out, xmlNodePtr input, const crm_time_t *date,
                         pcmk_scheduler_t **scheduler);


// General setup functions (pcmk_setup.c)

G_GNUC_INTERNAL
int pcmk__setup_output_cib_sched(pcmk__output_t **out, cib_t **cib,
                                 pcmk_scheduler_t **scheduler, xmlNode **xml);

G_GNUC_INTERNAL
int pcmk__setup_output_fencing(pcmk__output_t **out, stonith_t **st, xmlNode **xml);

#ifdef __cplusplus
}
#endif

#endif // PCMK__PACEMAKER_LIBPACEMAKER_PRIVATE__H

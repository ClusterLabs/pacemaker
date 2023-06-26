/*
 * Copyright 2021-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__LIBPACEMAKER_PRIVATE__H
#  define PCMK__LIBPACEMAKER_PRIVATE__H

/* This header is for the sole use of libpacemaker, so that functions can be
 * declared with G_GNUC_INTERNAL for efficiency.
 */

#include <crm/pengine/pe_types.h> // pe_action_t, pe_node_t, pe_working_set_t
#include <crm/pengine/internal.h> // pe__location_t

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
struct resource_alloc_functions_s {
    /*!
     * \internal
     * \brief Assign a resource to a node
     *
     * \param[in,out] rsc     Resource to assign to a node
     * \param[in]     prefer  Node to prefer, if all else is equal
     *
     * \return Node that \p rsc is assigned to, if assigned entirely to one node
     */
    pe_node_t *(*assign)(pe_resource_t *rsc, const pe_node_t *prefer);

    /*!
     * \internal
     * \brief Create all actions needed for a given resource
     *
     * \param[in,out] rsc  Resource to create actions for
     */
    void (*create_actions)(pe_resource_t *rsc);

    /*!
     * \internal
     * \brief Schedule any probes needed for a resource on a node
     *
     * \param[in,out] rsc   Resource to create probe for
     * \param[in,out] node  Node to create probe on
     *
     * \return true if any probe was created, otherwise false
     */
    bool (*create_probe)(pe_resource_t *rsc, pe_node_t *node);

    /*!
     * \internal
     * \brief Create implicit constraints needed for a resource
     *
     * \param[in,out] rsc  Resource to create implicit constraints for
     */
    void (*internal_constraints)(pe_resource_t *rsc);

    /*!
     * \internal
     * \brief Apply a colocation's score to node scores or resource priority
     *
     * Given a colocation constraint, apply its score to the dependent's
     * allowed node scores (if we are still placing resources) or priority (if
     * we are choosing promotable clone instance roles).
     *
     * \param[in,out] dependent      Dependent resource in colocation
     * \param[in,out] primary        Primary resource in colocation
     * \param[in]     colocation     Colocation constraint to apply
     * \param[in]     for_dependent  true if called on behalf of dependent
     */
    void (*apply_coloc_score)(pe_resource_t *dependent, pe_resource_t *primary,
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
    GList *(*colocated_resources)(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc,
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
    void (*with_this_colocations)(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc, GList **list);

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
    void (*this_with_colocations)(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc, GList **list);

    /*!
     * \internal
     * \brief Update nodes with scores of colocated resources' nodes
     *
     * Given a table of nodes and a resource, update the nodes' scores with the
     * scores of the best nodes matching the attribute used for each of the
     * resource's relevant colocations.
     *
     * \param[in,out] rsc         Resource to check colocations for
     * \param[in]     log_id      Resource ID for logs (if NULL, use \p rsc ID)
     * \param[in,out] nodes       Nodes to update (set initial contents to NULL
     *                            to copy \p rsc's allowed nodes)
     * \param[in]     colocation  Original colocation constraint (used to get
     *                            configured primary resource's stickiness, and
     *                            to get colocation node attribute; if NULL,
     *                            \p rsc's own matching node scores will not be
     *                            added, and *nodes must be NULL as well)
     * \param[in]     factor      Incorporate scores multiplied by this factor
     * \param[in]     flags       Bitmask of enum pcmk__coloc_select values
     *
     * \note NULL *nodes, NULL colocation, and the pcmk__coloc_select_this_with
     *       flag are used together (and only by cmp_resources()).
     * \note The caller remains responsible for freeing \p *nodes.
     */
    void (*add_colocated_node_scores)(pe_resource_t *rsc, const char *log_id,
                                      GHashTable **nodes,
                                      pcmk__colocation_t *colocation,
                                      float factor, uint32_t flags);

    /*!
     * \internal
     * \brief Apply a location constraint to a resource's allowed node scores
     *
     * \param[in,out] rsc       Resource to apply constraint to
     * \param[in,out] location  Location constraint to apply
     */
    void (*apply_location)(pe_resource_t *rsc, pe__location_t *location);

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
    uint32_t (*action_flags)(pe_action_t *action, const pe_node_t *node);

    /*!
     * \internal
     * \brief Update two actions according to an ordering between them
     *
     * Given information about an ordering of two actions, update the actions'
     * flags (and runnable_before members if appropriate) as appropriate for the
     * ordering. Effects may cascade to other orderings involving the actions as
     * well.
     *
     * \param[in,out] first     'First' action in an ordering
     * \param[in,out] then      'Then' action in an ordering
     * \param[in]     node      If not NULL, limit scope of ordering to this
     *                          node (only used when interleaving instances)
     * \param[in]     flags     Action flags for \p first for ordering purposes
     * \param[in]     filter    Action flags to limit scope of certain updates
     *                          (may include pe_action_optional to affect only
     *                          mandatory actions, and pe_action_runnable to
     *                          affect only runnable actions)
     * \param[in]     type      Group of enum pe_ordering flags to apply
     * \param[in,out] data_set  Cluster working set
     *
     * \return Group of enum pcmk__updated flags indicating what was updated
     */
    uint32_t (*update_ordered_actions)(pe_action_t *first, pe_action_t *then,
                                       const pe_node_t *node, uint32_t flags,
                                       uint32_t filter, uint32_t type,
                                       pe_working_set_t *data_set);

    /*!
     * \internal
     * \brief Output a summary of scheduled actions for a resource
     *
     * \param[in,out] rsc  Resource to output actions for
     */
    void (*output_actions)(pe_resource_t *rsc);

    /*!
     * \internal
     * \brief Add a resource's actions to the transition graph
     *
     * \param[in,out] rsc  Resource whose actions should be added
     */
    void (*add_actions_to_graph)(pe_resource_t *rsc);

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
    void (*add_graph_meta)(const pe_resource_t *rsc, xmlNode *xml);

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
    void (*add_utilization)(const pe_resource_t *rsc,
                            const pe_resource_t *orig_rsc, GList *all_rscs,
                            GHashTable *utilization);

    /*!
     * \internal
     * \brief Apply a shutdown lock for a resource, if appropriate
     *
     * \param[in,out] rsc       Resource to check for shutdown lock
     */
    void (*shutdown_lock)(pe_resource_t *rsc);
};

// Actions (pcmk_sched_actions.c)

G_GNUC_INTERNAL
void pcmk__update_action_for_orderings(pe_action_t *action,
                                       pe_working_set_t *data_set);

G_GNUC_INTERNAL
uint32_t pcmk__update_ordered_actions(pe_action_t *first, pe_action_t *then,
                                      const pe_node_t *node, uint32_t flags,
                                      uint32_t filter, uint32_t type,
                                      pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__log_action(const char *pre_text, const pe_action_t *action,
                      bool details);

G_GNUC_INTERNAL
pe_action_t *pcmk__new_cancel_action(pe_resource_t *rsc, const char *name,
                                     guint interval_ms, const pe_node_t *node);

G_GNUC_INTERNAL
pe_action_t *pcmk__new_shutdown_action(pe_node_t *node);

G_GNUC_INTERNAL
bool pcmk__action_locks_rsc_to_node(const pe_action_t *action);

G_GNUC_INTERNAL
void pcmk__deduplicate_action_inputs(pe_action_t *action);

G_GNUC_INTERNAL
void pcmk__output_actions(pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__check_action_config(pe_resource_t *rsc, pe_node_t *node,
                               const xmlNode *xml_op);

G_GNUC_INTERNAL
void pcmk__handle_rsc_config_changes(pe_working_set_t *data_set);


// Recurring actions (pcmk_sched_recurring.c)

G_GNUC_INTERNAL
void pcmk__create_recurring_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__schedule_cancel(pe_resource_t *rsc, const char *call_id,
                           const char *task, guint interval_ms,
                           const pe_node_t *node, const char *reason);

G_GNUC_INTERNAL
void pcmk__reschedule_recurring(pe_resource_t *rsc, const char *task,
                                guint interval_ms, pe_node_t *node);

G_GNUC_INTERNAL
bool pcmk__action_is_recurring(const pe_action_t *action);


// Producing transition graphs (pcmk_graph_producer.c)

G_GNUC_INTERNAL
bool pcmk__graph_has_loop(const pe_action_t *init_action,
                          const pe_action_t *action,
                          pe_action_wrapper_t *input);

G_GNUC_INTERNAL
void pcmk__add_rsc_actions_to_graph(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__create_graph(pe_working_set_t *data_set);


// Fencing (pcmk_sched_fencing.c)

G_GNUC_INTERNAL
void pcmk__order_vs_fence(pe_action_t *stonith_op, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__order_vs_unfence(const pe_resource_t *rsc, pe_node_t *node,
                            pe_action_t *action, enum pe_ordering order);

G_GNUC_INTERNAL
void pcmk__fence_guest(pe_node_t *node);

G_GNUC_INTERNAL
bool pcmk__node_unfenced(const pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__order_restart_vs_unfence(gpointer data, gpointer user_data);


// Injected scheduler inputs (pcmk_sched_injections.c)

void pcmk__inject_scheduler_input(pe_working_set_t *data_set, cib_t *cib,
                                  const pcmk_injections_t *injections);


// Constraints of any type (pcmk_sched_constraints.c)

G_GNUC_INTERNAL
pe_resource_t *pcmk__find_constraint_resource(GList *rsc_list, const char *id);

G_GNUC_INTERNAL
xmlNode *pcmk__expand_tags_in_sets(xmlNode *xml_obj,
                                   const pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__valid_resource_or_tag(const pe_working_set_t *data_set,
                                 const char *id, pe_resource_t **rsc,
                                 pe_tag_t **tag);

G_GNUC_INTERNAL
bool pcmk__tag_to_set(xmlNode *xml_obj, xmlNode **rsc_set, const char *attr,
                      bool convert_rsc, const pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__create_internal_constraints(pe_working_set_t *data_set);


// Location constraints

G_GNUC_INTERNAL
void pcmk__unpack_location(xmlNode *xml_obj, pe_working_set_t *data_set);

G_GNUC_INTERNAL
pe__location_t *pcmk__new_location(const char *id, pe_resource_t *rsc,
                                   int node_score, const char *discover_mode,
                                   pe_node_t *foo_node);

G_GNUC_INTERNAL
void pcmk__apply_locations(pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__apply_location(pe_resource_t *rsc, pe__location_t *constraint);


// Colocation constraints (pcmk_sched_colocation.c)

enum pcmk__coloc_affects {
    pcmk__coloc_affects_nothing = 0,
    pcmk__coloc_affects_location,
    pcmk__coloc_affects_role,
};

G_GNUC_INTERNAL
enum pcmk__coloc_affects pcmk__colocation_affects(const pe_resource_t
                                                    *dependent,
                                                  const pe_resource_t *primary,
                                                  const pcmk__colocation_t
                                                    *colocation,
                                                  bool preview);

G_GNUC_INTERNAL
void pcmk__apply_coloc_to_scores(pe_resource_t *dependent,
                                 const pe_resource_t *primary,
                                 const pcmk__colocation_t *colocation);

G_GNUC_INTERNAL
void pcmk__apply_coloc_to_priority(pe_resource_t *dependent,
                                   const pe_resource_t *primary,
                                   const pcmk__colocation_t *colocation);

G_GNUC_INTERNAL
void pcmk__add_colocated_node_scores(pe_resource_t *rsc, const char *log_id,
                                     GHashTable **nodes,
                                     pcmk__colocation_t *colocation,
                                     float factor, uint32_t flags);

G_GNUC_INTERNAL
void pcmk__add_dependent_scores(gpointer data, gpointer user_data);

G_GNUC_INTERNAL
void pcmk__unpack_colocation(xmlNode *xml_obj, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__add_this_with(GList **list, const pcmk__colocation_t *colocation);

G_GNUC_INTERNAL
void pcmk__add_this_with_list(GList **list, GList *addition);

G_GNUC_INTERNAL
void pcmk__add_with_this(GList **list, const pcmk__colocation_t *colocation);

G_GNUC_INTERNAL
void pcmk__add_with_this_list(GList **list, GList *addition);

G_GNUC_INTERNAL
GList *pcmk__with_this_colocations(const pe_resource_t *rsc);

G_GNUC_INTERNAL
GList *pcmk__this_with_colocations(const pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__new_colocation(const char *id, const char *node_attr, int score,
                          pe_resource_t *dependent, pe_resource_t *primary,
                          const char *dependent_role, const char *primary_role,
                          bool influence);

G_GNUC_INTERNAL
void pcmk__block_colocation_dependents(pe_action_t *action);

/*!
 * \internal
 * \brief Check whether colocation's dependent preferences should be considered
 *
 * \param[in] colocation  Colocation constraint
 * \param[in] rsc         Primary instance (normally this will be
 *                        colocation->primary, which NULL will be treated as,
 *                        but for clones or bundles with multiple instances
 *                        this can be a particular instance)
 *
 * \return true if colocation influence should be effective, otherwise false
 */
static inline bool
pcmk__colocation_has_influence(const pcmk__colocation_t *colocation,
                               const pe_resource_t *rsc)
{
    if (rsc == NULL) {
        rsc = colocation->primary;
    }

    /* A bundle replica colocates its remote connection with its container,
     * using a finite score so that the container can run on Pacemaker Remote
     * nodes.
     *
     * Moving a connection is lightweight and does not interrupt the service,
     * while moving a container is heavyweight and does interrupt the service,
     * so don't move a clean, active container based solely on the preferences
     * of its connection.
     *
     * This also avoids problematic scenarios where two containers want to
     * perpetually swap places.
     */
    if (pcmk_is_set(colocation->dependent->flags, pe_rsc_allow_remote_remotes)
        && !pcmk_is_set(rsc->flags, pe_rsc_failed)
        && pcmk__list_of_1(rsc->running_on)) {
        return false;
    }

    /* The dependent in a colocation influences the primary's location
     * if the influence option is true or the primary is not yet active.
     */
    return colocation->influence || (rsc->running_on == NULL);
}


// Ordering constraints (pcmk_sched_ordering.c)

G_GNUC_INTERNAL
void pcmk__new_ordering(pe_resource_t *first_rsc, char *first_task,
                        pe_action_t *first_action, pe_resource_t *then_rsc,
                        char *then_task, pe_action_t *then_action,
                        uint32_t flags, pe_working_set_t *sched);

G_GNUC_INTERNAL
void pcmk__unpack_ordering(xmlNode *xml_obj, pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__disable_invalid_orderings(pe_working_set_t *data_set);

G_GNUC_INTERNAL
void pcmk__order_stops_before_shutdown(pe_node_t *node,
                                       pe_action_t *shutdown_op);

G_GNUC_INTERNAL
void pcmk__apply_orderings(pe_working_set_t *sched);

G_GNUC_INTERNAL
void pcmk__order_after_each(pe_action_t *after, GList *list);


/*!
 * \internal
 * \brief Create a new ordering between two resource actions
 *
 * \param[in,out] first_rsc   Resource for 'first' action
 * \param[in,out] first_task  Action key for 'first' action
 * \param[in]     then_rsc    Resource for 'then' action
 * \param[in,out] then_task   Action key for 'then' action
 * \param[in]     flags       Bitmask of enum pe_ordering flags
 */
#define pcmk__order_resource_actions(first_rsc, first_task,                 \
                                     then_rsc, then_task, flags)            \
    pcmk__new_ordering((first_rsc),                                         \
                       pcmk__op_key((first_rsc)->id, (first_task), 0),      \
                       NULL,                                                \
                       (then_rsc),                                          \
                       pcmk__op_key((then_rsc)->id, (then_task), 0),        \
                       NULL, (flags), (first_rsc)->cluster)

#define pcmk__order_starts(rsc1, rsc2, flags)                \
    pcmk__order_resource_actions((rsc1), CRMD_ACTION_START,  \
                                 (rsc2), CRMD_ACTION_START, (flags))

#define pcmk__order_stops(rsc1, rsc2, flags)                 \
    pcmk__order_resource_actions((rsc1), CRMD_ACTION_STOP,   \
                                 (rsc2), CRMD_ACTION_STOP, (flags))


// Ticket constraints (pcmk_sched_tickets.c)

G_GNUC_INTERNAL
void pcmk__unpack_rsc_ticket(xmlNode *xml_obj, pe_working_set_t *data_set);


// Promotable clone resources (pcmk_sched_promotable.c)

G_GNUC_INTERNAL
void pcmk__add_promotion_scores(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__require_promotion_tickets(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__set_instance_roles(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__create_promotable_actions(pe_resource_t *clone);

G_GNUC_INTERNAL
void pcmk__promotable_restart_ordering(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__order_promotable_instances(pe_resource_t *clone);

G_GNUC_INTERNAL
void pcmk__update_dependent_with_promotable(const pe_resource_t *primary,
                                            pe_resource_t *dependent,
                                            const pcmk__colocation_t
                                                *colocation);

G_GNUC_INTERNAL
void pcmk__update_promotable_dependent_priority(const pe_resource_t *primary,
                                                pe_resource_t *dependent,
                                                const pcmk__colocation_t
                                                    *colocation);


// Pacemaker Remote nodes (pcmk_sched_remote.c)

G_GNUC_INTERNAL
bool pcmk__is_failed_remote_node(const pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__order_remote_connection_actions(pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__rsc_corresponds_to_guest(const pe_resource_t *rsc,
                                    const pe_node_t *node);

G_GNUC_INTERNAL
pe_node_t *pcmk__connection_host_for_action(const pe_action_t *action);

G_GNUC_INTERNAL
void pcmk__substitute_remote_addr(pe_resource_t *rsc, GHashTable *params);

G_GNUC_INTERNAL
void pcmk__add_bundle_meta_to_xml(xmlNode *args_xml, const pe_action_t *action);


// Primitives (pcmk_sched_primitive.c)

G_GNUC_INTERNAL
pe_node_t *pcmk__primitive_assign(pe_resource_t *rsc, const pe_node_t *prefer);

G_GNUC_INTERNAL
void pcmk__primitive_create_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__primitive_internal_constraints(pe_resource_t *rsc);

G_GNUC_INTERNAL
uint32_t pcmk__primitive_action_flags(pe_action_t *action,
                                      const pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__primitive_apply_coloc_score(pe_resource_t *dependent,
                                       pe_resource_t *primary,
                                       const pcmk__colocation_t *colocation,
                                       bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_primitive_colocations(const pe_resource_t *rsc,
                                      const pe_resource_t *orig_rsc,
                                      GList **list);

G_GNUC_INTERNAL
void pcmk__primitive_with_colocations(const pe_resource_t *rsc,
                                      const pe_resource_t *orig_rsc,
                                      GList **list);

G_GNUC_INTERNAL
void pcmk__schedule_cleanup(pe_resource_t *rsc, const pe_node_t *node,
                            bool optional);

G_GNUC_INTERNAL
void pcmk__primitive_add_graph_meta(const pe_resource_t *rsc, xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__primitive_add_utilization(const pe_resource_t *rsc,
                                     const pe_resource_t *orig_rsc,
                                     GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__primitive_shutdown_lock(pe_resource_t *rsc);


// Groups (pcmk_sched_group.c)

G_GNUC_INTERNAL
pe_node_t *pcmk__group_assign(pe_resource_t *rsc, const pe_node_t *prefer);

G_GNUC_INTERNAL
void pcmk__group_create_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__group_internal_constraints(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__group_apply_coloc_score(pe_resource_t *dependent,
                                   pe_resource_t *primary,
                                   const pcmk__colocation_t *colocation,
                                   bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_group_colocations(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc, GList **list);

G_GNUC_INTERNAL
void pcmk__group_with_colocations(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc, GList **list);

G_GNUC_INTERNAL
void pcmk__group_add_colocated_node_scores(pe_resource_t *rsc,
                                           const char *log_id,
                                           GHashTable **nodes,
                                           pcmk__colocation_t *colocation,
                                           float factor, uint32_t flags);

G_GNUC_INTERNAL
void pcmk__group_apply_location(pe_resource_t *rsc, pe__location_t *location);

G_GNUC_INTERNAL
uint32_t pcmk__group_action_flags(pe_action_t *action, const pe_node_t *node);

G_GNUC_INTERNAL
uint32_t pcmk__group_update_ordered_actions(pe_action_t *first,
                                            pe_action_t *then,
                                            const pe_node_t *node,
                                            uint32_t flags, uint32_t filter,
                                            uint32_t type,
                                            pe_working_set_t *data_set);

G_GNUC_INTERNAL
GList *pcmk__group_colocated_resources(const pe_resource_t *rsc,
                                       const pe_resource_t *orig_rsc,
                                       GList *colocated_rscs);

G_GNUC_INTERNAL
void pcmk__group_add_utilization(const pe_resource_t *rsc,
                                 const pe_resource_t *orig_rsc, GList *all_rscs,
                                 GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__group_shutdown_lock(pe_resource_t *rsc);


// Clones (pcmk_sched_clone.c)

G_GNUC_INTERNAL
pe_node_t *pcmk__clone_assign(pe_resource_t *rsc, const pe_node_t *prefer);

G_GNUC_INTERNAL
void pcmk__clone_create_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__clone_create_probe(pe_resource_t *rsc, pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__clone_internal_constraints(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__clone_apply_coloc_score(pe_resource_t *dependent,
                                   pe_resource_t *primary,
                                   const pcmk__colocation_t *colocation,
                                   bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_clone_colocations(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc, GList **list);

G_GNUC_INTERNAL
void pcmk__clone_with_colocations(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc, GList **list);

G_GNUC_INTERNAL
void pcmk__clone_apply_location(pe_resource_t *rsc, pe__location_t *constraint);

G_GNUC_INTERNAL
uint32_t pcmk__clone_action_flags(pe_action_t *action, const pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__clone_add_actions_to_graph(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__clone_add_graph_meta(const pe_resource_t *rsc, xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__clone_add_utilization(const pe_resource_t *rsc,
                                 const pe_resource_t *orig_rsc,
                                 GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__clone_shutdown_lock(pe_resource_t *rsc);

// Bundles (pcmk_sched_bundle.c)

G_GNUC_INTERNAL
pe_node_t *pcmk__bundle_assign(pe_resource_t *rsc, const pe_node_t *prefer);

G_GNUC_INTERNAL
void pcmk__bundle_create_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__bundle_create_probe(pe_resource_t *rsc, pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__bundle_internal_constraints(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__bundle_apply_coloc_score(pe_resource_t *dependent,
                                    pe_resource_t *primary,
                                    const pcmk__colocation_t *colocation,
                                    bool for_dependent);

G_GNUC_INTERNAL
void pcmk__with_bundle_colocations(const pe_resource_t *rsc,
                                   const pe_resource_t *orig_rsc, GList **list);

G_GNUC_INTERNAL
void pcmk__bundle_with_colocations(const pe_resource_t *rsc,
                                   const pe_resource_t *orig_rsc, GList **list);

G_GNUC_INTERNAL
void pcmk__bundle_apply_location(pe_resource_t *rsc,
                                 pe__location_t *constraint);

G_GNUC_INTERNAL
uint32_t pcmk__bundle_action_flags(pe_action_t *action, const pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__output_bundle_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__bundle_add_actions_to_graph(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__bundle_add_utilization(const pe_resource_t *rsc,
                                  const pe_resource_t *orig_rsc,
                                  GList *all_rscs, GHashTable *utilization);

G_GNUC_INTERNAL
void pcmk__bundle_shutdown_lock(pe_resource_t *rsc);


// Clone instances or bundle replica containers (pcmk_sched_instances.c)

G_GNUC_INTERNAL
void pcmk__assign_instances(pe_resource_t *collective, GList *instances,
                            int max_total, int max_per_node);

G_GNUC_INTERNAL
void pcmk__create_instance_actions(pe_resource_t *rsc, GList *instances);

G_GNUC_INTERNAL
bool pcmk__instance_matches(const pe_resource_t *instance,
                            const pe_node_t *node, enum rsc_role_e role,
                            bool current);

G_GNUC_INTERNAL
pe_resource_t *pcmk__find_compatible_instance(const pe_resource_t *match_rsc,
                                              const pe_resource_t *rsc,
                                              enum rsc_role_e role,
                                              bool current);

G_GNUC_INTERNAL
uint32_t pcmk__instance_update_ordered_actions(pe_action_t *first,
                                               pe_action_t *then,
                                               const pe_node_t *node,
                                               uint32_t flags, uint32_t filter,
                                               uint32_t type,
                                               pe_working_set_t *data_set);

G_GNUC_INTERNAL
uint32_t pcmk__collective_action_flags(pe_action_t *action,
                                       const GList *instances,
                                       const pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__add_collective_constraints(GList **list,
                                      const pe_resource_t *instance,
                                      const pe_resource_t *collective,
                                      bool with_this);


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
void pcmk__inject_failcount(pcmk__output_t *out, xmlNode *cib_node,
                            const char *resource, const char *task,
                            guint interval_ms, int rc);

G_GNUC_INTERNAL
xmlNode *pcmk__inject_action_result(xmlNode *cib_resource,
                                    lrmd_event_data_t *op, int target_rc);


// Nodes (pcmk_sched_nodes.c)

G_GNUC_INTERNAL
bool pcmk__node_available(const pe_node_t *node, bool consider_score,
                          bool consider_guest);

G_GNUC_INTERNAL
bool pcmk__any_node_available(GHashTable *nodes);

G_GNUC_INTERNAL
GHashTable *pcmk__copy_node_table(GHashTable *nodes);

G_GNUC_INTERNAL
GList *pcmk__sort_nodes(GList *nodes, pe_node_t *active_node);

G_GNUC_INTERNAL
void pcmk__apply_node_health(pe_working_set_t *data_set);

G_GNUC_INTERNAL
pe_node_t *pcmk__top_allowed_node(const pe_resource_t *rsc,
                                  const pe_node_t *node);


// Functions applying to more than one variant (pcmk_sched_resource.c)

G_GNUC_INTERNAL
void pcmk__set_assignment_methods(pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__rsc_agent_changed(pe_resource_t *rsc, pe_node_t *node,
                             const xmlNode *rsc_entry, bool active_on_node);

G_GNUC_INTERNAL
GList *pcmk__rscs_matching_id(const char *id, const pe_working_set_t *data_set);

G_GNUC_INTERNAL
GList *pcmk__colocated_resources(const pe_resource_t *rsc,
                                 const pe_resource_t *orig_rsc,
                                 GList *colocated_rscs);

G_GNUC_INTERNAL
void pcmk__noop_add_graph_meta(const pe_resource_t *rsc, xmlNode *xml);

G_GNUC_INTERNAL
void pcmk__output_resource_actions(pe_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__assign_resource(pe_resource_t *rsc, pe_node_t *node, bool force);

G_GNUC_INTERNAL
void pcmk__unassign_resource(pe_resource_t *rsc);

G_GNUC_INTERNAL
bool pcmk__threshold_reached(pe_resource_t *rsc, const pe_node_t *node,
                             pe_resource_t **failed);

G_GNUC_INTERNAL
void pcmk__sort_resources(pe_working_set_t *data_set);

G_GNUC_INTERNAL
gint pcmk__cmp_instance(gconstpointer a, gconstpointer b);

G_GNUC_INTERNAL
gint pcmk__cmp_instance_number(gconstpointer a, gconstpointer b);


// Functions related to probes (pcmk_sched_probes.c)

G_GNUC_INTERNAL
bool pcmk__probe_rsc_on_node(pe_resource_t *rsc, pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__order_probes(pe_working_set_t *data_set);

G_GNUC_INTERNAL
bool pcmk__probe_resource_list(GList *rscs, pe_node_t *node);

G_GNUC_INTERNAL
void pcmk__schedule_probes(pe_working_set_t *data_set);


// Functions related to live migration (pcmk_sched_migration.c)

void pcmk__create_migration_actions(pe_resource_t *rsc,
                                    const pe_node_t *current);

void pcmk__abort_dangling_migration(void *data, void *user_data);

bool pcmk__rsc_can_migrate(const pe_resource_t *rsc, const pe_node_t *current);

void pcmk__order_migration_equivalents(pe__ordering_t *order);


// Functions related to node utilization (pcmk_sched_utilization.c)

G_GNUC_INTERNAL
int pcmk__compare_node_capacities(const pe_node_t *node1,
                                  const pe_node_t *node2);

G_GNUC_INTERNAL
void pcmk__consume_node_capacity(GHashTable *current_utilization,
                                 const pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__release_node_capacity(GHashTable *current_utilization,
                                 const pe_resource_t *rsc);

G_GNUC_INTERNAL
const pe_node_t *pcmk__ban_insufficient_capacity(pe_resource_t *rsc);

G_GNUC_INTERNAL
void pcmk__create_utilization_constraints(pe_resource_t *rsc,
                                          const GList *allowed_nodes);

G_GNUC_INTERNAL
void pcmk__show_node_capacities(const char *desc, pe_working_set_t *data_set);

#endif // PCMK__LIBPACEMAKER_PRIVATE__H

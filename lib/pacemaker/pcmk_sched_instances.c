/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

/* This file is intended for code usable with both clone instances and bundle
 * replica containers.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

static void append_parent_colocation(pe_resource_t * rsc, pe_resource_t * child, gboolean all);

/*!
 * \internal
 * \brief Check whether a node is allowed to run an instance
 *
 * \param[in] instance      Clone instance or bundle container to check
 * \param[in] node          Node to check
 * \param[in] max_per_node  Maximum number of instances allowed to run on a node
 *
 * \return true if \p node is allowed to run \p instance, otherwise false
 */
static bool
can_run_instance(const pe_resource_t *instance, const pe_node_t *node,
                 int max_per_node)
{
    pe_node_t *allowed_node = NULL;

    if (pcmk_is_set(instance->flags, pe_rsc_orphan)) {
        pe_rsc_trace(instance, "%s cannot run on %s: orphaned",
                     instance->id, pe__node_name(node));
        return false;
    }

    if (!pcmk__node_available(node, false, false)) {
        pe_rsc_trace(instance,
                     "%s cannot run on %s: node cannot run resources",
                     instance->id, pe__node_name(node));
        return false;
    }

    allowed_node = pcmk__top_allowed_node(instance, node);
    if (allowed_node == NULL) {
        crm_warn("%s cannot run on %s: node not allowed",
                 instance->id, pe__node_name(node));
        return false;
    }

    if (allowed_node->weight < 0) {
        pe_rsc_trace(instance, "%s cannot run on %s: parent score is %s there",
                     instance->id, pe__node_name(node),
                     pcmk_readable_score(allowed_node->weight));
        return false;
    }

    if (allowed_node->count >= max_per_node) {
        pe_rsc_trace(instance,
                     "%s cannot run on %s: node already has %d instance%s",
                     instance->id, pe__node_name(node), max_per_node,
                     pcmk__plural_s(max_per_node));
        return false;
    }

    pe_rsc_trace(instance, "%s can run on %s (%d already running)",
                 instance->id, pe__node_name(node), allowed_node->count);
    return true;
}

/*!
 * \internal
 * \brief Ban a clone instance or bundle replica from unavailable allowed nodes
 *
 * \param[in,out] instance      Clone instance or bundle replica to ban
 * \param[in]     max_per_node  Maximum instances allowed to run on a node
 */
static void
ban_unavailable_allowed_nodes(pe_resource_t *instance, int max_per_node)
{
    if (instance->allowed_nodes != NULL) {
        GHashTableIter iter;
        const pe_node_t *allowed_node = NULL;

        g_hash_table_iter_init(&iter, instance->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **) &allowed_node)) {
            if (!can_run_instance(instance, allowed_node, max_per_node)) {
                // Ban instance (and all its children) from node
                common_update_score(instance, allowed_node->details->id,
                                    -INFINITY);
            }
        }
    }
}

/*!
 * \internal
 * \brief Choose a node for an instance
 *
 * \param[in,out] instance      Clone instance or bundle replica container
 * \param[in]     prefer        If not NULL, attempt early assignment to this
 *                              node, if still the best choice; otherwise,
 *                              perform final assignment
 * \param[in]     all_coloc     If true (indicating that there are more
 *                              available nodes than instances), add all parent
 *                              colocations to instance, otherwise add only
 *                              negative (and for "this with" colocations,
 *                              infinite) colocations to avoid needless
 *                              shuffling of instances among nodes
 * \param[in]     max_per_node  Assign at most this many instances to one node
 *
 * \return true if \p instance could be assigned to a node, otherwise false
 */
static bool
assign_instance(pe_resource_t *instance, const pe_node_t *prefer,
                bool all_coloc, int max_per_node)
{
    pe_node_t *chosen = NULL;
    pe_node_t *allowed = NULL;

    CRM_ASSERT(instance != NULL);
    pe_rsc_trace(instance,
                 "Assigning %s (preferring %s, using %s parent colocations)",
                 instance->id,
                 ((prefer == NULL)? "no node" : prefer->details->uname),
                 (all_coloc? "all" : "essential"));

    if (!pcmk_is_set(instance->flags, pe_rsc_provisional)) {
        // Instance is already assigned
        return instance->fns->location(instance, NULL, FALSE) != NULL;
    }

    if (pcmk_is_set(instance->flags, pe_rsc_allocating)) {
        pe_rsc_debug(instance,
                     "Assignment loop detected involving %s colocations",
                     instance->id);
        return false;
    }

    if (prefer != NULL) { // Possible early assignment to preferred node

        // Get preferred node with instance's scores
        allowed = g_hash_table_lookup(instance->allowed_nodes,
                                      prefer->details->id);

        if ((allowed == NULL) || (allowed->weight < 0)) {
            pe_rsc_trace(instance,
                         "Not assigning %s to preferred node %s: unavailable",
                         instance->id, pe__node_name(prefer));
            return false;
        }
    }

    ban_unavailable_allowed_nodes(instance, max_per_node);

    if (prefer == NULL) { // Final assignment
        chosen = instance->cmds->assign(instance, NULL);

    } else { // Possible early assignment to preferred node
        GHashTable *backup = pcmk__copy_node_table(instance->allowed_nodes);

        chosen = instance->cmds->assign(instance, prefer);

        // Revert nodes if preferred node won't be assigned
        if ((chosen != NULL) && (chosen->details != prefer->details)) {
            crm_info("Not assigning %s to preferred node %s: %s is better",
                     instance->id, pe__node_name(prefer),
                     pe__node_name(chosen));
            g_hash_table_destroy(instance->allowed_nodes);
            instance->allowed_nodes = backup;
            pcmk__unassign_resource(instance);
            chosen = NULL;
        } else if (backup != NULL) {
            g_hash_table_destroy(backup);
        }
    }

    // The parent tracks how many instances have been assigned to each node
    if (chosen != NULL) {
        allowed = pcmk__top_allowed_node(instance, chosen);
        if (allowed == NULL) {
            /* The instance is allowed on the node, but its parent isn't. This
             * shouldn't be possible if the resource is managed, and we won't be
             * able to limit the number of instances assigned to the node.
             */
            CRM_LOG_ASSERT(!pcmk_is_set(instance->flags, pe_rsc_managed));

        } else {
            allowed->count++;
        }
    }
    return chosen != NULL;
}

static void
append_parent_colocation(pe_resource_t * rsc, pe_resource_t * child, gboolean all)
{

    GList *gIter = NULL;

    gIter = rsc->rsc_cons;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) gIter->data;

        if (all || cons->score < 0 || cons->score == INFINITY) {
            pcmk__add_this_with(child, cons);
        }
    }

    gIter = rsc->rsc_cons_lhs;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__colocation_t *cons = (pcmk__colocation_t *) gIter->data;

        if (!pcmk__colocation_has_influence(cons, child)) {
           continue;
        }
        if (all || cons->score < 0) {
            pcmk__add_with_this(child, cons);
        }
    }
}

/*!
 * \internal
 * \brief Reset the node counts of a resource's allowed nodes to zero
 *
 * \param[in,out] rsc  Resource to reset
 *
 * \return Number of nodes that are available to run resources
 */
static unsigned int
reset_allowed_node_counts(pe_resource_t *rsc)
{
    unsigned int available_nodes = 0;
    pe_node_t *node = NULL;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, rsc->allowed_nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        node->count = 0;
        if (pcmk__node_available(node, false, false)) {
            available_nodes++;
        }
    }
    return available_nodes;
}

/*!
 * \internal
 * \brief Check whether an instance has a preferred node
 *
 * \param[in] rsc               Clone or bundle being assigned (for logs only)
 * \param[in] instance          Clone instance or bundle replica container
 * \param[in] optimal_per_node  Optimal number of instances per node
 *
 * \return Instance's current node if still available, otherwise NULL
 */
static const pe_node_t *
preferred_node(const pe_resource_t *rsc, const pe_resource_t *instance,
               int optimal_per_node)
{
    const pe_node_t *node = NULL;
    const pe_node_t *parent_node = NULL;

    // Check whether instance is active, healthy, and not yet assigned
    if ((instance->running_on == NULL)
        || !pcmk_is_set(instance->flags, pe_rsc_provisional)
        || pcmk_is_set(instance->flags, pe_rsc_failed)) {
        return NULL;
    }

    // Check whether instance's current node can run resources
    node = pe__current_node(instance);
    if (!pcmk__node_available(node, true, false)) {
        pe_rsc_trace(rsc, "Not assigning %s to %s early (unavailable)",
                     instance->id, pe__node_name(node));
        return NULL;
    }

    // Check whether node already has optimal number of instances assigned
    parent_node = pcmk__top_allowed_node(instance, node);
    if ((parent_node != NULL) && (parent_node->count >= optimal_per_node)) {
        pe_rsc_trace(rsc,
                     "Not assigning %s to %s early "
                     "(optimal instances already assigned)",
                     instance->id, pe__node_name(node));
        return NULL;
    }

    return node;
}

/*!
 * \internal
 * \brief Assign collective instances to nodes
 *
 * \param[in,out] collective    Clone or bundle resource being assigned
 * \param[in,out] instances     List of clone instances or bundle containers
 * \param[in]     max_total     Maximum instances to assign in total
 * \param[in]     max_per_node  Maximum instances to assign to any one node
 */
void
pcmk__assign_instances(pe_resource_t *collective, GList *instances,
                       int max_total, int max_per_node)
{
    // Reuse node count to track number of assigned instances
    unsigned int available_nodes = reset_allowed_node_counts(collective);

    /* Include finite positive preferences of the collective's
     * colocation dependents only if not every node will get an instance.
     */
    bool all_coloc = (max_total < available_nodes);

    int optimal_per_node = 0;
    int assigned = 0;
    GList *iter = NULL;
    pe_resource_t *instance = NULL;
    const pe_node_t *current = NULL;

    if (available_nodes > 0) {
        optimal_per_node = max_total / available_nodes;
    }
    if (optimal_per_node < 1) {
        optimal_per_node = 1;
    }

    pe_rsc_debug(collective,
                 "Assigning up to %d %s instance%s to up to %d node%s "
                 "(at most %d per host, %d optimal)",
                 max_total, collective->id, pcmk__plural_s(max_total),
                 available_nodes, pcmk__plural_s(available_nodes),
                 max_per_node, optimal_per_node);

    // Assign as many instances as possible to their current location
    for (iter = instances; (iter != NULL) && (assigned < max_total);
         iter = iter->next) {
        instance = (pe_resource_t *) iter->data;

        append_parent_colocation(instance->parent, instance, all_coloc);

        current = preferred_node(collective, instance, optimal_per_node);
        if ((current != NULL)
            && assign_instance(instance, current, all_coloc, max_per_node)) {
            pe_rsc_trace(collective, "Assigned %s to current node %s",
                         instance->id, pe__node_name(current));
            assigned++;
        }
    }

    pe_rsc_trace(collective, "Assigned %d of %d instance%s to current node",
                 assigned, max_total, pcmk__plural_s(max_total));

    for (iter = instances; iter != NULL; iter = iter->next) {
        instance = (pe_resource_t *) iter->data;

        if (!pcmk_is_set(instance->flags, pe_rsc_provisional)) {
            continue; // Already assigned
        }

        if (instance->running_on != NULL) {
            current = pe__current_node(instance);
            if (pcmk__top_allowed_node(instance, current) == NULL) {
                const char *unmanaged = "";

                if (!pcmk_is_set(instance->flags, pe_rsc_managed)) {
                    unmanaged = "Unmanaged resource ";
                }
                crm_notice("%s%s is running on %s which is no longer allowed",
                           unmanaged, instance->id, pe__node_name(current));
            }
        }

        if (assigned >= max_total) {
            pe_rsc_debug(collective,
                         "Not assigning %s because maximum %d instances "
                         "already assigned",
                         instance->id, max_total);
            resource_location(instance, NULL, -INFINITY,
                              "collective_limit_reached", collective->cluster);

        } else if (assign_instance(instance, NULL, all_coloc, max_per_node)) {
            assigned++;
        }
    }

    pe_rsc_debug(collective, "Assigned %d of %d possible instance%s of %s",
                 assigned, max_total, pcmk__plural_s(max_total),
                 collective->id);
}

enum instance_state {
    instance_starting   = (1 << 0),
    instance_stopping   = (1 << 1),
    instance_restarting = (1 << 2),
    instance_active     = (1 << 3),
};

/*!
 * \internal
 * \brief Check whether an instance is active, starting, and/or stopping
 *
 * \param[in]     instance  Clone instance or bundle replica container
 * \param[in,out] state     Whether any instance is starting, stopping, etc.
 */
static void
check_instance_state(const pe_resource_t *instance, uint32_t *state)
{
    const GList *iter = NULL;
    uint32_t instance_state = 0; // State of just this instance

    // If the instance has its own children (a cloned group), check each one
    if (instance->children != NULL) {
        for (iter = instance->children; iter != NULL; iter = iter->next) {
            check_instance_state((const pe_resource_t *) iter->data, state);
        }
        return;
    }

    if (instance->running_on != NULL) {
        instance_state |= instance_active;
    }

    // Check each of the instance's actions for runnable start or stop
    for (iter = instance->actions;
         (iter != NULL) && !pcmk_all_flags_set(instance_state,
                                               instance_starting
                                               |instance_stopping);
         iter = iter->next) {

        const pe_action_t *action = (const pe_action_t *) iter->data;

        if (pcmk__str_eq(RSC_START, action->task, pcmk__str_none)) {
            if (!pcmk_is_set(action->flags, pe_action_optional)
                && pcmk_is_set(action->flags, pe_action_runnable)) {
                pe_rsc_trace(instance, "Instance is starting due to %s",
                             action->uuid);
                instance_state |= instance_starting;
            } else {
                pe_rsc_trace(instance,
                             "%s doesn't affect %s state (unrunnable)",
                             action->uuid, instance->id);
            }

        } else if (pcmk__str_eq(RSC_STOP, action->task, pcmk__str_none)) {
            if (!pcmk_is_set(action->flags, pe_action_optional)
                && pcmk_any_flags_set(action->flags,
                                      // Pseudo-stops are implied by fencing
                                      pe_action_pseudo|pe_action_runnable)) {
                pe_rsc_trace(instance, "Instance is stopping due to %s",
                             action->uuid);
                instance_state |= instance_stopping;
            } else {
                pe_rsc_trace(instance,
                             "%s doesn't affect %s state (unrunnable)",
                             action->uuid, instance->id);
            }
        }
    }

    if (pcmk_all_flags_set(instance_state,
                           instance_starting|instance_stopping)) {
        instance_state |= instance_restarting;
    }
    *state |= instance_state;
}

void
clone_create_pseudo_actions(pe_resource_t *rsc, GList *children,
                            notify_data_t **start_notify,
                            notify_data_t **stop_notify)
{
    uint32_t state = 0;

    pe_action_t *stop = NULL;
    pe_action_t *stopped = NULL;

    pe_action_t *start = NULL;
    pe_action_t *started = NULL;

    pe_rsc_trace(rsc, "Creating actions for %s", rsc->id);

    for (GList *gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        child_rsc->cmds->create_actions(child_rsc);
        check_instance_state(child_rsc, &state);
    }

    /* start */
    start = pe__new_rsc_pseudo_action(rsc, RSC_START,
                                      !pcmk_is_set(state, instance_starting),
                                      true);
    started = pe__new_rsc_pseudo_action(rsc, RSC_STARTED,
                                        !pcmk_is_set(state, instance_starting),
                                        false);
    started->priority = INFINITY;

    if (pcmk_any_flags_set(state, instance_active|instance_starting)) {
        pe__set_action_flags(started, pe_action_runnable);
    }

    if (start_notify != NULL && *start_notify == NULL) {
        *start_notify = pe__clone_notif_pseudo_ops(rsc, RSC_START, start,
                                                   started);
    }

    /* stop */
    stop = pe__new_rsc_pseudo_action(rsc, RSC_STOP,
                                     !pcmk_is_set(state, instance_stopping),
                                     true);
    stopped = pe__new_rsc_pseudo_action(rsc, RSC_STOPPED,
                                        !pcmk_is_set(state, instance_stopping),
                                        true);
    stopped->priority = INFINITY;
    if (!pcmk_is_set(state, instance_restarting)) {
        pe__set_action_flags(stop, pe_action_migrate_runnable);
    }

    if (stop_notify != NULL && *stop_notify == NULL) {
        *stop_notify = pe__clone_notif_pseudo_ops(rsc, RSC_STOP, stop, stopped);

        if (start_notify && *start_notify && *stop_notify) {
            order_actions((*stop_notify)->post_done, (*start_notify)->pre, pe_order_optional);
        }
    }
}

gboolean
is_child_compatible(const pe_resource_t *child_rsc, const pe_node_t *local_node,
                    enum rsc_role_e filter, gboolean current)
{
    pe_node_t *node = NULL;
    enum rsc_role_e next_role = child_rsc->fns->state(child_rsc, current);

    CRM_CHECK(child_rsc && local_node, return FALSE);
    if (is_set_recursive(child_rsc, pe_rsc_block, TRUE) == FALSE) {
        /* We only want instances that haven't failed */
        node = child_rsc->fns->location(child_rsc, NULL, current);
    }

    if (filter != RSC_ROLE_UNKNOWN && next_role != filter) {
        crm_trace("Filtered %s", child_rsc->id);
        return FALSE;
    }

    if (node && (node->details == local_node->details)) {
        return TRUE;

    } else if (node) {
        crm_trace("%s - %s vs %s", child_rsc->id, pe__node_name(node),
                  pe__node_name(local_node));

    } else {
        crm_trace("%s - not allocated %d", child_rsc->id, current);
    }
    return FALSE;
}

pe_resource_t *
find_compatible_child(const pe_resource_t *local_child,
                      const pe_resource_t *rsc, enum rsc_role_e filter,
                      gboolean current)
{
    pe_resource_t *pair = NULL;
    GList *gIter = NULL;
    GList *scratch = NULL;
    pe_node_t *local_node = NULL;

    local_node = local_child->fns->location(local_child, NULL, current);
    if (local_node) {
        return find_compatible_child_by_node(local_child, local_node, rsc, filter, current);
    }

    scratch = g_hash_table_get_values(local_child->allowed_nodes);
    scratch = pcmk__sort_nodes(scratch, NULL);

    gIter = scratch;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        pair = find_compatible_child_by_node(local_child, node, rsc, filter, current);
        if (pair) {
            goto done;
        }
    }

    pe_rsc_debug(rsc, "Can't pair %s with %s", local_child->id, rsc->id);
  done:
    g_list_free(scratch);
    return pair;
}

enum action_tasks
clone_child_action(pe_action_t * action)
{
    enum action_tasks result = no_action;
    pe_resource_t *child = (pe_resource_t *) action->rsc->children->data;

    if (pcmk__strcase_any_of(action->task, "notify", "notified", NULL)) {

        /* Find the action we're notifying about instead */

        int stop = 0;
        char *key = action->uuid;
        int lpc = strlen(key);

        for (; lpc > 0; lpc--) {
            if (key[lpc] == '_' && stop == 0) {
                stop = lpc;

            } else if (key[lpc] == '_') {
                char *task_mutable = NULL;

                lpc++;
                task_mutable = strdup(key + lpc);
                task_mutable[stop - lpc] = 0;

                crm_trace("Extracted action '%s' from '%s'", task_mutable, key);
                result = get_complex_task(child, task_mutable, TRUE);
                free(task_mutable);
                break;
            }
        }

    } else {
        result = get_complex_task(child, action->task, TRUE);
    }
    return result;
}

#define pe__clear_action_summary_flags(flags, action, flag) do {        \
        flags = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                     "Action summary", action->rsc->id, \
                                     flags, flag, #flag);               \
    } while (0)

enum pe_action_flags
summary_action_flags(pe_action_t *action, GList *children,
                     const pe_node_t *node)
{
    GList *gIter = NULL;
    gboolean any_runnable = FALSE;
    gboolean check_runnable = TRUE;
    enum action_tasks task = clone_child_action(action);
    enum pe_action_flags flags = (pe_action_optional | pe_action_runnable | pe_action_pseudo);
    const char *task_s = task2text(task);

    for (gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_action_t *child_action = NULL;
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        child_action = find_first_action(child->actions, NULL, task_s, child->children ? NULL : node);
        pe_rsc_trace(action->rsc, "Checking for %s in %s on %s (%s)", task_s, child->id,
                     pe__node_name(node), child_action?child_action->uuid:"NA");
        if (child_action) {
            enum pe_action_flags child_flags = child->cmds->action_flags(child_action, node);

            if (pcmk_is_set(flags, pe_action_optional)
                && !pcmk_is_set(child_flags, pe_action_optional)) {
                pe_rsc_trace(child, "%s is mandatory because of %s", action->uuid,
                             child_action->uuid);
                pe__clear_action_summary_flags(flags, action, pe_action_optional);
                pe__clear_action_flags(action, pe_action_optional);
            }
            if (pcmk_is_set(child_flags, pe_action_runnable)) {
                any_runnable = TRUE;
            }
        }
    }

    if (check_runnable && any_runnable == FALSE) {
        pe_rsc_trace(action->rsc, "%s is not runnable because no children are", action->uuid);
        pe__clear_action_summary_flags(flags, action, pe_action_runnable);
        if (node == NULL) {
            pe__clear_action_flags(action, pe_action_runnable);
        }
    }

    return flags;
}

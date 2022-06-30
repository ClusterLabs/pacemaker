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
        pe_rsc_trace(instance, "%s cannot run on %s because it is an orphan",
                     instance->id, pe__node_name(node));
        return false;
    }

    if (!pcmk__node_available(node, false, false)) {
        pe_rsc_trace(instance,
                     "%s cannot run on %s because it cannot run resources",
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
                     "%s cannot run on %s because it already has %d instance%s",
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
 * \brief Ban a clone instance from its allowed nodes that are unavailable
 *
 * \param[in,out] rsc           Clone instance
 * \param[in]     max_per_node  Maximum instances allowed to run on a node
 */
static void
ban_unavailable_allowed_nodes(pe_resource_t *instance, int max_per_node)
{
    if (instance->allowed_nodes != NULL) {
        GHashTableIter iter;
        pe_node_t *allowed_node = NULL;

        g_hash_table_iter_init(&iter, instance->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL,
                                      (void **) &allowed_node)) {
            if (!can_run_instance(instance, allowed_node, max_per_node)) {
                // Ban instance (and all its children) from node
                common_update_score(instance, allowed_node->details->id,
                                    -INFINITY);
            }
        }
    }
}

static pe_node_t *
allocate_instance(pe_resource_t *rsc, pe_node_t *prefer, gboolean all_coloc,
                  int limit, pe_working_set_t *data_set)
{
    pe_node_t *chosen = NULL;
    GHashTable *backup = NULL;

    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "Checking allocation of %s (preferring %s, using %s parent colocations)",
                 rsc->id, (prefer? prefer->details->uname: "none"),
                 (all_coloc? "all" : "some"));

    if (!pcmk_is_set(rsc->flags, pe_rsc_provisional)) {
        return rsc->fns->location(rsc, NULL, FALSE);

    } else if (pcmk_is_set(rsc->flags, pe_rsc_allocating)) {
        pe_rsc_debug(rsc, "Dependency loop detected involving %s", rsc->id);
        return NULL;
    }

    /* Only include positive colocation preferences of dependent resources
     * if not every node will get a copy of the clone
     */
    append_parent_colocation(rsc->parent, rsc, all_coloc);

    if (prefer) {
        pe_node_t *local_prefer = g_hash_table_lookup(rsc->allowed_nodes, prefer->details->id);

        if (local_prefer == NULL || local_prefer->weight < 0) {
            pe_rsc_trace(rsc, "Not pre-allocating %s to %s - unavailable", rsc->id,
                         pe__node_name(prefer));
            return NULL;
        }
    }

    ban_unavailable_allowed_nodes(rsc, limit);

    backup = pcmk__copy_node_table(rsc->allowed_nodes);
    pe_rsc_trace(rsc, "Allocating instance %s", rsc->id);
    chosen = rsc->cmds->assign(rsc, prefer);
    if (chosen && prefer && (chosen->details != prefer->details)) {
        crm_info("Not pre-allocating %s to %s because %s is better",
                 rsc->id, pe__node_name(prefer), pe__node_name(chosen));
        g_hash_table_destroy(rsc->allowed_nodes);
        rsc->allowed_nodes = backup;
        pcmk__unassign_resource(rsc);
        chosen = NULL;
        backup = NULL;
    }
    if (chosen) {
        pe_node_t *local_node = pcmk__top_allowed_node(rsc, chosen);

        if (local_node) {
            local_node->count++;

        } else if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            /* what to do? we can't enforce per-node limits in this case */
            pcmk__config_err("%s not found in %s (list of %d)",
                             chosen->details->id, rsc->parent->id,
                             g_hash_table_size(rsc->parent->allowed_nodes));
        }
    }

    if(backup) {
        g_hash_table_destroy(backup);
    }
    return chosen;
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

void
distribute_children(pe_resource_t *rsc, GList *children, GList *nodes,
                    int max, int per_host_max, pe_working_set_t * data_set) 
{
    int loop_max = 0;
    int allocated = 0;
    int available_nodes = 0;
    bool all_coloc = false;

    /* count now tracks the number of clones currently allocated */
    for(GList *nIter = nodes; nIter != NULL; nIter = nIter->next) {
        pe_node_t *node = nIter->data;

        node->count = 0;
        if (pcmk__node_available(node, false, false)) {
            available_nodes++;
        }
    }

    all_coloc = (max < available_nodes) ? true : false;

    if(available_nodes) {
        loop_max = max / available_nodes;
    }
    if (loop_max < 1) {
        loop_max = 1;
    }

    pe_rsc_debug(rsc, "Allocating up to %d %s instances to a possible %d nodes (at most %d per host, %d optimal)",
                 max, rsc->id, available_nodes, per_host_max, loop_max);

    /* Pre-allocate as many instances as we can to their current location */
    for (GList *gIter = children; gIter != NULL && allocated < max; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;
        pe_node_t *child_node = NULL;
        pe_node_t *local_node = NULL;

        if ((child->running_on == NULL)
            || !pcmk_is_set(child->flags, pe_rsc_provisional)
            || pcmk_is_set(child->flags, pe_rsc_failed)) {

            continue;
        }

        child_node = pe__current_node(child);
        local_node = pcmk__top_allowed_node(child, child_node);

        pe_rsc_trace(rsc,
                     "Checking pre-allocation of %s to %s (%d remaining of %d)",
                     child->id, pe__node_name(child_node), max - allocated,
                     max);

        if (!pcmk__node_available(child_node, true, false)) {
            pe_rsc_trace(rsc, "Not pre-allocating because %s can not run %s",
                         pe__node_name(child_node), child->id);
            continue;
        }

        if ((local_node != NULL) && (local_node->count >= loop_max)) {
            pe_rsc_trace(rsc,
                         "Not pre-allocating because %s already allocated "
                         "optimal instances", pe__node_name(child_node));
            continue;
        }

        if (allocate_instance(child, child_node, all_coloc, per_host_max,
                              data_set)) {
            pe_rsc_trace(rsc, "Pre-allocated %s to %s", child->id,
                         pe__node_name(child_node));
            allocated++;
        }
    }

    pe_rsc_trace(rsc, "Done pre-allocating (%d of %d)", allocated, max);

    for (GList *gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child = (pe_resource_t *) gIter->data;

        if (child->running_on != NULL) {
            pe_node_t *child_node = pe__current_node(child);
            pe_node_t *local_node = pcmk__top_allowed_node(child, child_node);

            if (local_node == NULL) {
                crm_err("%s is running on %s which isn't allowed",
                        child->id, pe__node_name(child_node));
            }
        }

        if (!pcmk_is_set(child->flags, pe_rsc_provisional)) {
        } else if (allocated >= max) {
            pe_rsc_debug(rsc, "Child %s not allocated - limit reached %d %d", child->id, allocated, max);
            resource_location(child, NULL, -INFINITY, "clone:limit_reached", data_set);
        } else {
            if (allocate_instance(child, NULL, all_coloc, per_host_max,
                                  data_set)) {
                allocated++;
            }
        }
    }

    pe_rsc_debug(rsc, "Allocated %d %s instances of a possible %d",
                 allocated, rsc->id, max);
}

static void
clone_update_pseudo_status(pe_resource_t * rsc, gboolean * stopping, gboolean * starting,
                           gboolean * active)
{
    GList *gIter = NULL;

    if (rsc->children) {

        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            clone_update_pseudo_status(child, stopping, starting, active);
        }

        return;
    }

    CRM_ASSERT(active != NULL);
    CRM_ASSERT(starting != NULL);
    CRM_ASSERT(stopping != NULL);

    if (rsc->running_on) {
        *active = TRUE;
    }

    gIter = rsc->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (*starting && *stopping) {
            return;

        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            pe_rsc_trace(rsc, "Skipping optional: %s", action->uuid);
            continue;

        } else if (!pcmk_any_flags_set(action->flags,
                                       pe_action_pseudo|pe_action_runnable)) {
            pe_rsc_trace(rsc, "Skipping unrunnable: %s", action->uuid);
            continue;

        } else if (pcmk__str_eq(RSC_STOP, action->task, pcmk__str_casei)) {
            pe_rsc_trace(rsc, "Stopping due to: %s", action->uuid);
            *stopping = TRUE;

        } else if (pcmk__str_eq(RSC_START, action->task, pcmk__str_casei)) {
            if (!pcmk_is_set(action->flags, pe_action_runnable)) {
                pe_rsc_trace(rsc, "Skipping pseudo-op: %s run=%d, pseudo=%d",
                             action->uuid,
                             pcmk_is_set(action->flags, pe_action_runnable),
                             pcmk_is_set(action->flags, pe_action_pseudo));
            } else {
                pe_rsc_trace(rsc, "Starting due to: %s", action->uuid);
                pe_rsc_trace(rsc, "%s run=%d, pseudo=%d",
                             action->uuid,
                             pcmk_is_set(action->flags, pe_action_runnable),
                             pcmk_is_set(action->flags, pe_action_pseudo));
                *starting = TRUE;
            }
        }
    }
}

void
clone_create_pseudo_actions(pe_resource_t *rsc, GList *children,
                            notify_data_t **start_notify,
                            notify_data_t **stop_notify)
{
    gboolean child_active = FALSE;
    gboolean child_starting = FALSE;
    gboolean child_stopping = FALSE;
    gboolean allow_dependent_migrations = TRUE;

    pe_action_t *stop = NULL;
    pe_action_t *stopped = NULL;

    pe_action_t *start = NULL;
    pe_action_t *started = NULL;

    pe_rsc_trace(rsc, "Creating actions for %s", rsc->id);

    for (GList *gIter = children; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;
        gboolean starting = FALSE;
        gboolean stopping = FALSE;

        child_rsc->cmds->create_actions(child_rsc);
        clone_update_pseudo_status(child_rsc, &stopping, &starting, &child_active);
        if (stopping && starting) {
            allow_dependent_migrations = FALSE;
        }

        child_stopping |= stopping;
        child_starting |= starting;
    }

    /* start */
    start = pe__new_rsc_pseudo_action(rsc, RSC_START, !child_starting, true);
    started = pe__new_rsc_pseudo_action(rsc, RSC_STARTED, !child_starting,
                                        false);
    started->priority = INFINITY;

    if (child_active || child_starting) {
        pe__set_action_flags(started, pe_action_runnable);
    }

    if (start_notify != NULL && *start_notify == NULL) {
        *start_notify = pe__clone_notif_pseudo_ops(rsc, RSC_START, start,
                                                   started);
    }

    /* stop */
    stop = pe__new_rsc_pseudo_action(rsc, RSC_STOP, !child_stopping, true);
    stopped = pe__new_rsc_pseudo_action(rsc, RSC_STOPPED, !child_stopping,
                                        true);
    stopped->priority = INFINITY;
    if (allow_dependent_migrations) {
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

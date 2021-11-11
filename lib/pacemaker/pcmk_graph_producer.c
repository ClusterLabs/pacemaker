/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <glib.h>

#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

gboolean rsc_update_action(pe_action_t * first, pe_action_t * then, enum pe_ordering type);

static enum pe_action_flags
get_action_flags(pe_action_t * action, pe_node_t * node)
{
    enum pe_action_flags flags = action->flags;

    if (action->rsc) {
        flags = action->rsc->cmds->action_flags(action, NULL);

        if (pe_rsc_is_clone(action->rsc) && node) {

            /* We only care about activity on $node */
            enum pe_action_flags clone_flags = action->rsc->cmds->action_flags(action, node);

            /* Go to great lengths to ensure the correct value for pe_action_runnable...
             *
             * If we are a clone, then for _ordering_ constraints, it's only relevant
             * if we are runnable _anywhere_.
             *
             * This only applies to _runnable_ though, and only for ordering constraints.
             * If this function is ever used during colocation, then we'll need additional logic
             *
             * Not very satisfying, but it's logical and appears to work well.
             */
            if (!pcmk_is_set(clone_flags, pe_action_runnable)
                && pcmk_is_set(flags, pe_action_runnable)) {

                pe__set_raw_action_flags(clone_flags, action->rsc->id,
                                         pe_action_runnable);
            }
            flags = clone_flags;
        }
    }
    return flags;
}

static char *
convert_non_atomic_uuid(char *old_uuid, pe_resource_t * rsc, gboolean allow_notify,
                        gboolean free_original)
{
    guint interval_ms = 0;
    char *uuid = NULL;
    char *rid = NULL;
    char *raw_task = NULL;
    int task = no_action;

    CRM_ASSERT(rsc);
    pe_rsc_trace(rsc, "Processing %s", old_uuid);
    if (old_uuid == NULL) {
        return NULL;

    } else if (strstr(old_uuid, "notify") != NULL) {
        goto done;              /* no conversion */

    } else if (rsc->variant < pe_group) {
        goto done;              /* no conversion */
    }

    CRM_ASSERT(parse_op_key(old_uuid, &rid, &raw_task, &interval_ms));
    if (interval_ms > 0) {
        goto done;              /* no conversion */
    }

    task = text2task(raw_task);
    switch (task) {
        case stop_rsc:
        case start_rsc:
        case action_notify:
        case action_promote:
        case action_demote:
            break;
        case stopped_rsc:
        case started_rsc:
        case action_notified:
        case action_promoted:
        case action_demoted:
            task--;
            break;
        case monitor_rsc:
        case shutdown_crm:
        case stonith_node:
            task = no_action;
            break;
        default:
            crm_err("Unknown action: %s", raw_task);
            task = no_action;
            break;
    }

    if (task != no_action) {
        if (pcmk_is_set(rsc->flags, pe_rsc_notify) && allow_notify) {
            uuid = pcmk__notify_key(rid, "confirmed-post", task2text(task + 1));

        } else {
            uuid = pcmk__op_key(rid, task2text(task + 1), 0);
        }
        pe_rsc_trace(rsc, "Converted %s -> %s", old_uuid, uuid);
    }

  done:
    if (uuid == NULL) {
        uuid = strdup(old_uuid);
    }

    if (free_original) {
        free(old_uuid);
    }

    free(raw_task);
    free(rid);
    return uuid;
}

static pe_action_t *
rsc_expand_action(pe_action_t * action)
{
    gboolean notify = FALSE;
    pe_action_t *result = action;
    pe_resource_t *rsc = action->rsc;

    if (rsc == NULL) {
        return action;
    }

    if ((rsc->parent == NULL)
        || (pe_rsc_is_clone(rsc) && (rsc->parent->variant == pe_container))) {
        /* Only outermost resources have notification actions.
         * The exception is those in bundles.
         */
        notify = pcmk_is_set(rsc->flags, pe_rsc_notify);
    }

    if (rsc->variant >= pe_group) {
        /* Expand 'start' -> 'started' */
        char *uuid = NULL;

        uuid = convert_non_atomic_uuid(action->uuid, rsc, notify, FALSE);
        if (uuid) {
            pe_rsc_trace(rsc, "Converting %s to %s %d", action->uuid, uuid,
                         pcmk_is_set(rsc->flags, pe_rsc_notify));
            result = find_first_action(rsc->actions, uuid, NULL, NULL);
            if (result == NULL) {
                crm_err("Couldn't expand %s to %s in %s", action->uuid, uuid, rsc->id);
                result = action;
            }
            free(uuid);
        }
    }
    return result;
}

static enum pe_graph_flags
graph_update_action(pe_action_t * first, pe_action_t * then, pe_node_t * node,
                    enum pe_action_flags first_flags, enum pe_action_flags then_flags,
                    pe_action_wrapper_t *order, pe_working_set_t *data_set)
{
    enum pe_graph_flags changed = pe_graph_none;
    enum pe_ordering type = order->type;

    /* TODO: Do as many of these in parallel as possible */

    if (pcmk_is_set(type, pe_order_implies_then_on_node)) {
        /* Normally we want the _whole_ 'then' clone to
         * restart if 'first' is restarted, so then->node is
         * needed.
         *
         * However for unfencing, we want to limit this to
         * instances on the same node as 'first' (the
         * unfencing operation), so first->node is supplied.
         *
         * Swap the node, from then on we can can treat it
         * like any other 'pe_order_implies_then'
         */

        pe__clear_order_flags(type, pe_order_implies_then_on_node);
        pe__set_order_flags(type, pe_order_implies_then);
        node = first->node;
        pe_rsc_trace(then->rsc,
                     "%s then %s: mapped pe_order_implies_then_on_node to "
                     "pe_order_implies_then on %s",
                     first->uuid, then->uuid, node->details->uname);
    }

    if (type & pe_order_implies_then) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags & pe_action_optional, pe_action_optional,
                pe_order_implies_then, data_set);

        } else if (!pcmk_is_set(first_flags, pe_action_optional)
                   && pcmk_is_set(then->flags, pe_action_optional)) {
            pe__clear_action_flags(then, pe_action_optional);
            pe__set_graph_flags(changed, first, pe_graph_updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_implies_then",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if ((type & pe_order_restart) && then->rsc) {
        enum pe_action_flags restart = (pe_action_optional | pe_action_runnable);

        changed |= then->rsc->cmds->update_actions(first, then, node,
                                                   first_flags, restart,
                                                   pe_order_restart, data_set);
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_restart",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_implies_first) {
        if (first->rsc) {
            changed |= first->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional, pe_order_implies_first,
                data_set);

        } else if (!pcmk_is_set(first_flags, pe_action_optional)
                   && pcmk_is_set(first->flags, pe_action_runnable)) {
            pe__clear_action_flags(first, pe_action_runnable);
            pe__set_graph_flags(changed, first, pe_graph_updated_first);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_implies_first",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_promoted_implies_first) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags & pe_action_optional, pe_action_optional,
                pe_order_promoted_implies_first, data_set);
        }
        pe_rsc_trace(then->rsc,
                     "%s then %s: %s after pe_order_promoted_implies_first",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_one_or_more) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_one_or_more,
                data_set);

        } else if (pcmk_is_set(first_flags, pe_action_runnable)) {
            // We have another runnable instance of "first"
            then->runnable_before++;

            /* Mark "then" as runnable if it requires a certain number of
             * "before" instances to be runnable, and they now are.
             */
            if ((then->runnable_before >= then->required_runnable_before)
                && !pcmk_is_set(then->flags, pe_action_runnable)) {

                pe__set_action_flags(then, pe_action_runnable);
                pe__set_graph_flags(changed, first, pe_graph_updated_then);
            }
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_one_or_more",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (then->rsc && pcmk_is_set(type, pe_order_probe)) {
        if (!pcmk_is_set(first_flags, pe_action_runnable)
            && (first->rsc->running_on != NULL)) {

            pe_rsc_trace(then->rsc,
                         "%s then %s: ignoring because first is stopping",
                         first->uuid, then->uuid);
            type = pe_order_none;
            order->type = pe_order_none;

        } else {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_runnable_left,
                data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_probe",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_runnable_left) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_runnable_left,
                data_set);

        } else if (!pcmk_is_set(first_flags, pe_action_runnable)
                   && pcmk_is_set(then->flags, pe_action_runnable)) {

            pe__clear_action_flags(then, pe_action_runnable);
            pe__set_graph_flags(changed, first, pe_graph_updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_runnable_left",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_implies_first_migratable) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional,
                pe_order_implies_first_migratable, data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after "
                     "pe_order_implies_first_migratable",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_pseudo_left) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_optional, pe_order_pseudo_left,
                data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_pseudo_left",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_optional) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_optional, data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_optional",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if (type & pe_order_asymmetrical) {
        if (then->rsc) {
            changed |= then->rsc->cmds->update_actions(first, then, node,
                first_flags, pe_action_runnable, pe_order_asymmetrical,
                data_set);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after pe_order_asymmetrical",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    if ((first->flags & pe_action_runnable) && (type & pe_order_implies_then_printed)
        && (first_flags & pe_action_optional) == 0) {
        pe_rsc_trace(then->rsc, "%s will be in graph because %s is required",
                     then->uuid, first->uuid);
        pe__set_action_flags(then, pe_action_print_always);
        // Don't bother marking 'then' as changed just for this
    }

    if (pcmk_is_set(type, pe_order_implies_first_printed)
        && !pcmk_is_set(then_flags, pe_action_optional)) {

        pe_rsc_trace(then->rsc, "%s will be in graph because %s is required",
                     first->uuid, then->uuid);
        pe__set_action_flags(first, pe_action_print_always);
        // Don't bother marking 'first' as changed just for this
    }

    if ((type & pe_order_implies_then
         || type & pe_order_implies_first
         || type & pe_order_restart)
        && first->rsc
        && pcmk__str_eq(first->task, RSC_STOP, pcmk__str_casei)
        && !pcmk_is_set(first->rsc->flags, pe_rsc_managed)
        && pcmk_is_set(first->rsc->flags, pe_rsc_block)
        && !pcmk_is_set(first->flags, pe_action_runnable)) {

        if (pcmk_is_set(then->flags, pe_action_runnable)) {
            pe__clear_action_flags(then, pe_action_runnable);
            pe__set_graph_flags(changed, first, pe_graph_updated_then);
        }
        pe_rsc_trace(then->rsc, "%s then %s: %s after checking whether first "
                     "is blocked, unmanaged, unrunnable stop",
                     first->uuid, then->uuid,
                     (changed? "changed" : "unchanged"));
    }

    return changed;
}

// Convenience macros for logging action properties

#define action_type_str(flags) \
    (pcmk_is_set((flags), pe_action_pseudo)? "pseudo-action" : "action")

#define action_optional_str(flags) \
    (pcmk_is_set((flags), pe_action_optional)? "optional" : "required")

#define action_runnable_str(flags) \
    (pcmk_is_set((flags), pe_action_runnable)? "runnable" : "unrunnable")

#define action_node_str(a) \
    (((a)->node == NULL)? "no node" : (a)->node->details->uname)

gboolean
update_action(pe_action_t *then, pe_working_set_t *data_set)
{
    GList *lpc = NULL;
    enum pe_graph_flags changed = pe_graph_none;
    int last_flags = then->flags;

    pe_rsc_trace(then->rsc, "Updating %s %s (%s %s) on %s",
                 action_type_str(then->flags), then->uuid,
                 action_optional_str(then->flags),
                 action_runnable_str(then->flags), action_node_str(then));

    if (pcmk_is_set(then->flags, pe_action_requires_any)) {
        /* initialize current known runnable before actions to 0
         * from here as graph_update_action is called for each of
         * then's before actions, this number will increment as
         * runnable 'first' actions are encountered */
        then->runnable_before = 0;

        /* for backwards compatibility with previous options that use
         * the 'requires_any' flag, initialize required to 1 if it is
         * not set. */ 
        if (then->required_runnable_before == 0) {
            then->required_runnable_before = 1;
        }
        pe__clear_action_flags(then, pe_action_runnable);
        /* We are relying on the pe_order_one_or_more clause of
         * graph_update_action(), called as part of the:
         *
         *    'if (first == other->action)'
         *
         * block below, to set this back if appropriate
         */
    }

    for (lpc = then->actions_before; lpc != NULL; lpc = lpc->next) {
        pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc->data;
        pe_action_t *first = other->action;

        pe_node_t *then_node = then->node;
        pe_node_t *first_node = first->node;

        enum pe_action_flags then_flags = 0;
        enum pe_action_flags first_flags = 0;

        if (first->rsc && first->rsc->variant == pe_group && pcmk__str_eq(first->task, RSC_START, pcmk__str_casei)) {
            first_node = first->rsc->fns->location(first->rsc, NULL, FALSE);
            if (first_node) {
                pe_rsc_trace(first->rsc, "Found node %s for 'first' %s",
                             first_node->details->uname, first->uuid);
            }
        }

        if (then->rsc && then->rsc->variant == pe_group && pcmk__str_eq(then->task, RSC_START, pcmk__str_casei)) {
            then_node = then->rsc->fns->location(then->rsc, NULL, FALSE);
            if (then_node) {
                pe_rsc_trace(then->rsc, "Found node %s for 'then' %s",
                             then_node->details->uname, then->uuid);
            }
        }
        /* Disable constraint if it only applies when on same node, but isn't */
        if (pcmk_is_set(other->type, pe_order_same_node)
            && (first_node != NULL) && (then_node != NULL)
            && (first_node->details != then_node->details)) {

            pe_rsc_trace(then->rsc,
                         "Disabled ordering %s on %s then %s on %s: not same node",
                         other->action->uuid, first_node->details->uname,
                         then->uuid, then_node->details->uname);
            other->type = pe_order_none;
            continue;
        }

        pe__clear_graph_flags(changed, then, pe_graph_updated_first);

        if (first->rsc && pcmk_is_set(other->type, pe_order_then_cancels_first)
            && !pcmk_is_set(then->flags, pe_action_optional)) {

            /* 'then' is required, so we must abandon 'first'
             * (e.g. a required stop cancels any agent reload).
             */
            pe__set_action_flags(other->action, pe_action_optional);
            if (!strcmp(first->task, CRMD_ACTION_RELOAD_AGENT)) {
                pe__clear_resource_flags(first->rsc, pe_rsc_reload);
            }
        }

        if (first->rsc && then->rsc && (first->rsc != then->rsc)
            && (is_parent(then->rsc, first->rsc) == FALSE)) {
            first = rsc_expand_action(first);
        }
        if (first != other->action) {
            pe_rsc_trace(then->rsc, "Ordering %s after %s instead of %s",
                         then->uuid, first->uuid, other->action->uuid);
        }

        first_flags = get_action_flags(first, then_node);
        then_flags = get_action_flags(then, first_node);

        pe_rsc_trace(then->rsc,
                     "%s then %s: type=0x%.6x filter=0x%.6x "
                     "(%s %s %s on %s 0x%.6x then 0x%.6x)",
                     first->uuid, then->uuid, other->type, first_flags,
                     action_optional_str(first_flags),
                     action_runnable_str(first_flags),
                     action_type_str(first_flags), action_node_str(first),
                     first->flags, then->flags);

        if (first == other->action) {
            /*
             * 'first' was not expanded (e.g. from 'start' to 'running'), which could mean it:
             * - has no associated resource,
             * - was a primitive,
             * - was pre-expanded (e.g. 'running' instead of 'start')
             *
             * The third argument here to graph_update_action() is a node which is used under two conditions:
             * - Interleaving, in which case first->node and
             *   then->node are equal (and NULL)
             * - If 'then' is a clone, to limit the scope of the
             *   constraint to instances on the supplied node
             *
             */
            pe_node_t *node = then->node;
            changed |= graph_update_action(first, then, node, first_flags,
                                           then_flags, other, data_set);

            /* 'first' was for a complex resource (clone, group, etc),
             * create a new dependency if necessary
             */
        } else if (order_actions(first, then, other->type)) {
            /* This was the first time 'first' and 'then' were associated,
             * start again to get the new actions_before list
             */
            pe__set_graph_flags(changed, then,
                                pe_graph_updated_then|pe_graph_disable);
        }

        if (changed & pe_graph_disable) {
            pe_rsc_trace(then->rsc,
                         "Disabled ordering %s then %s in favor of %s then %s",
                         other->action->uuid, then->uuid, first->uuid,
                         then->uuid);
            pe__clear_graph_flags(changed, then, pe_graph_disable);
            other->type = pe_order_none;
        }

        if (changed & pe_graph_updated_first) {
            GList *lpc2 = NULL;

            crm_trace("Re-processing %s and its 'after' actions since it changed",
                      first->uuid);
            for (lpc2 = first->actions_after; lpc2 != NULL; lpc2 = lpc2->next) {
                pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc2->data;

                update_action(other->action, data_set);
            }
            update_action(first, data_set);
        }
    }

    if (pcmk_is_set(then->flags, pe_action_requires_any)) {
        if (last_flags != then->flags) {
            pe__set_graph_flags(changed, then, pe_graph_updated_then);
        } else {
            pe__clear_graph_flags(changed, then, pe_graph_updated_then);
        }
    }

    if (changed & pe_graph_updated_then) {
        crm_trace("Re-processing %s and its 'after' actions since it changed",
                  then->uuid);
        if (pcmk_is_set(last_flags, pe_action_runnable)
            && !pcmk_is_set(then->flags, pe_action_runnable)) {
            pcmk__block_colocated_starts(then, data_set);
        }
        update_action(then, data_set);
        for (lpc = then->actions_after; lpc != NULL; lpc = lpc->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) lpc->data;

            update_action(other->action, data_set);
        }
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Add an XML node tag for a specified ID
 *
 * \param[in]     id      Node UUID to add
 * \param[in,out] xml     Parent XML tag to add to
 */
static xmlNode*
add_node_to_xml_by_id(const char *id, xmlNode *xml)
{
    xmlNode *node_xml;

    node_xml = create_xml_node(xml, XML_CIB_TAG_NODE);
    crm_xml_add(node_xml, XML_ATTR_UUID, id);

    return node_xml;
}

/*!
 * \internal
 * \brief Add an XML node tag for a specified node
 *
 * \param[in]     node  Node to add
 * \param[in,out] xml   XML to add node to
 */
static void
add_node_to_xml(const pe_node_t *node, void *xml)
{
    add_node_to_xml_by_id(node->details->id, (xmlNode *) xml);
}

/*!
 * \internal
 * \brief Add XML with nodes that need an update of their maintenance state
 *
 * \param[in,out] xml       Parent XML tag to add to
 * \param[in]     data_set  Working set for cluster
 */
static int
add_maintenance_nodes(xmlNode *xml, const pe_working_set_t *data_set)
{
    GList *gIter = NULL;
    xmlNode *maintenance =
        xml?create_xml_node(xml, XML_GRAPH_TAG_MAINTENANCE):NULL;
    int count = 0;

    for (gIter = data_set->nodes; gIter != NULL;
         gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;
        struct pe_node_shared_s *details = node->details;

        if (!pe__is_guest_or_remote_node(node)) {
            continue; /* just remote nodes need to know atm */
        }

        if (details->maintenance != details->remote_maintenance) {
            if (maintenance) {
                crm_xml_add(
                    add_node_to_xml_by_id(node->details->id, maintenance),
                    XML_NODE_IS_MAINTENANCE, details->maintenance?"1":"0");
            }
            count++;
        }
    }
    crm_trace("%s %d nodes to adjust maintenance-mode "
              "to transition", maintenance?"Added":"Counted", count);
    return count;
}

/*!
 * \internal
 * \brief Add pseudo action with nodes needing maintenance state update
 *
 * \param[in,out] data_set  Working set for cluster
 */
void
add_maintenance_update(pe_working_set_t *data_set)
{
    pe_action_t *action = NULL;

    if (add_maintenance_nodes(NULL, data_set)) {
        crm_trace("adding maintenance state update pseudo action");
        action = get_pseudo_op(CRM_OP_MAINTENANCE_NODES, data_set);
        pe__set_action_flags(action, pe_action_print_always);
    }
}

/*!
 * \internal
 * \brief Add XML with nodes that an action is expected to bring down
 *
 * If a specified action is expected to bring any nodes down, add an XML block
 * with their UUIDs. When a node is lost, this allows the controller to
 * determine whether it was expected.
 *
 * \param[in,out] xml       Parent XML tag to add to
 * \param[in]     action    Action to check for downed nodes
 * \param[in]     data_set  Working set for cluster
 */
static void
add_downed_nodes(xmlNode *xml, const pe_action_t *action,
                 const pe_working_set_t *data_set)
{
    CRM_CHECK(xml && action && action->node && data_set, return);

    if (pcmk__str_eq(action->task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {

        /* Shutdown makes the action's node down */
        xmlNode *downed = create_xml_node(xml, XML_GRAPH_TAG_DOWNED);
        add_node_to_xml_by_id(action->node->details->id, downed);

    } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {

        /* Fencing makes the action's node and any hosted guest nodes down */
        const char *fence = g_hash_table_lookup(action->meta, "stonith_action");

        if (pcmk__is_fencing_action(fence)) {
            xmlNode *downed = create_xml_node(xml, XML_GRAPH_TAG_DOWNED);
            add_node_to_xml_by_id(action->node->details->id, downed);
            pe_foreach_guest_node(data_set, action->node, add_node_to_xml, downed);
        }

    } else if (action->rsc && action->rsc->is_remote_node
               && pcmk__str_eq(action->task, CRMD_ACTION_STOP, pcmk__str_casei)) {

        /* Stopping a remote connection resource makes connected node down,
         * unless it's part of a migration
         */
        GList *iter;
        pe_action_t *input;
        gboolean migrating = FALSE;

        for (iter = action->actions_before; iter != NULL; iter = iter->next) {
            input = ((pe_action_wrapper_t *) iter->data)->action;
            if (input->rsc && pcmk__str_eq(action->rsc->id, input->rsc->id, pcmk__str_casei)
                && pcmk__str_eq(input->task, CRMD_ACTION_MIGRATED, pcmk__str_casei)) {
                migrating = TRUE;
                break;
            }
        }
        if (!migrating) {
            xmlNode *downed = create_xml_node(xml, XML_GRAPH_TAG_DOWNED);
            add_node_to_xml_by_id(action->rsc->id, downed);
        }
    }
}

static bool
should_lock_action(pe_action_t *action)
{
    // Only actions taking place on resource's lock node are locked
    if ((action->rsc->lock_node == NULL) || (action->node == NULL)
        || (action->node->details != action->rsc->lock_node->details)) {
        return false;
    }

    /* During shutdown, only stops are locked (otherwise, another action such as
     * a demote would cause the controller to clear the lock)
     */
    if (action->node->details->shutdown && action->task
        && strcmp(action->task, RSC_STOP)) {
        return false;
    }

    return true;
}

static xmlNode *
action2xml(pe_action_t * action, gboolean as_input, pe_working_set_t *data_set)
{
    gboolean needs_node_info = TRUE;
    gboolean needs_maintenance_info = FALSE;
    xmlNode *action_xml = NULL;
    xmlNode *args_xml = NULL;
#if ENABLE_VERSIONED_ATTRS
    pe_rsc_action_details_t *rsc_details = NULL;
#endif

    if (action == NULL) {
        return NULL;
    }

    if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {
        /* All fences need node info; guest node fences are pseudo-events */
        action_xml = create_xml_node(NULL,
                                     pcmk_is_set(action->flags, pe_action_pseudo)?
                                     XML_GRAPH_TAG_PSEUDO_EVENT :
                                     XML_GRAPH_TAG_CRM_EVENT);

    } else if (pcmk__str_eq(action->task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (pcmk__str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT, pcmk__str_casei)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (pcmk__str_eq(action->task, CRM_OP_LRM_REFRESH, pcmk__str_casei)) {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);

    } else if (pcmk__str_eq(action->task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
        // CIB-only clean-up for shutdown locks
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT);
        crm_xml_add(action_xml, PCMK__XA_MODE, XML_TAG_CIB);

/* 	} else if(pcmk__str_eq(action->task, RSC_PROBED, pcmk__str_casei)) { */
/* 		action_xml = create_xml_node(NULL, XML_GRAPH_TAG_CRM_EVENT); */

    } else if (pcmk_is_set(action->flags, pe_action_pseudo)) {
        if (pcmk__str_eq(action->task, CRM_OP_MAINTENANCE_NODES, pcmk__str_casei)) {
            needs_maintenance_info = TRUE;
        }
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_PSEUDO_EVENT);
        needs_node_info = FALSE;

    } else {
        action_xml = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);

#if ENABLE_VERSIONED_ATTRS
        rsc_details = pe_rsc_action_details(action);
#endif
    }

    crm_xml_add_int(action_xml, XML_ATTR_ID, action->id);
    crm_xml_add(action_xml, XML_LRM_ATTR_TASK, action->task);
    if (action->rsc != NULL && action->rsc->clone_name != NULL) {
        char *clone_key = NULL;
        guint interval_ms;

        if (pcmk__guint_from_hash(action->meta,
                                  XML_LRM_ATTR_INTERVAL_MS, 0,
                                  &interval_ms) != pcmk_rc_ok) {
            interval_ms = 0;
        }

        if (pcmk__str_eq(action->task, RSC_NOTIFY, pcmk__str_casei)) {
            const char *n_type = g_hash_table_lookup(action->meta, "notify_type");
            const char *n_task = g_hash_table_lookup(action->meta, "notify_operation");

            CRM_CHECK(n_type != NULL, crm_err("No notify type value found for %s", action->uuid));
            CRM_CHECK(n_task != NULL,
                      crm_err("No notify operation value found for %s", action->uuid));
            clone_key = pcmk__notify_key(action->rsc->clone_name,
                                         n_type, n_task);

        } else if(action->cancel_task) {
            clone_key = pcmk__op_key(action->rsc->clone_name,
                                     action->cancel_task, interval_ms);
        } else {
            clone_key = pcmk__op_key(action->rsc->clone_name,
                                     action->task, interval_ms);
        }

        CRM_CHECK(clone_key != NULL, crm_err("Could not generate a key for %s", action->uuid));
        crm_xml_add(action_xml, XML_LRM_ATTR_TASK_KEY, clone_key);
        crm_xml_add(action_xml, "internal_" XML_LRM_ATTR_TASK_KEY, action->uuid);
        free(clone_key);

    } else {
        crm_xml_add(action_xml, XML_LRM_ATTR_TASK_KEY, action->uuid);
    }

    if (needs_node_info && action->node != NULL) {
        pe_node_t *router_node = pcmk__connection_host_for_action(action);

        crm_xml_add(action_xml, XML_LRM_ATTR_TARGET, action->node->details->uname);
        crm_xml_add(action_xml, XML_LRM_ATTR_TARGET_UUID, action->node->details->id);
        if (router_node) {
            crm_xml_add(action_xml, XML_LRM_ATTR_ROUTER_NODE, router_node->details->uname);
        }

        g_hash_table_insert(action->meta, strdup(XML_LRM_ATTR_TARGET), strdup(action->node->details->uname));
        g_hash_table_insert(action->meta, strdup(XML_LRM_ATTR_TARGET_UUID), strdup(action->node->details->id));
    }

    /* No details if this action is only being listed in the inputs section */
    if (as_input) {
        return action_xml;
    }

    if (action->rsc && !pcmk_is_set(action->flags, pe_action_pseudo)) {
        int lpc = 0;
        xmlNode *rsc_xml = NULL;
        const char *attr_list[] = {
            XML_AGENT_ATTR_CLASS,
            XML_AGENT_ATTR_PROVIDER,
            XML_ATTR_TYPE
        };

        /* If a resource is locked to a node via shutdown-lock, mark its actions
         * so the controller can preserve the lock when the action completes.
         */
        if (should_lock_action(action)) {
            crm_xml_add_ll(action_xml, XML_CONFIG_ATTR_SHUTDOWN_LOCK,
                           (long long) action->rsc->lock_time);
        }

        // List affected resource

        rsc_xml = create_xml_node(action_xml,
                                  crm_element_name(action->rsc->xml));
        if (pcmk_is_set(action->rsc->flags, pe_rsc_orphan)
            && action->rsc->clone_name) {
            /* Do not use the 'instance free' name here as that
             * might interfere with the instance we plan to keep.
             * Ie. if there are more than two named /anonymous/
             * instances on a given node, we need to make sure the
             * command goes to the right one.
             *
             * Keep this block, even when everyone is using
             * 'instance free' anonymous clone names - it means
             * we'll do the right thing if anyone toggles the
             * unique flag to 'off'
             */
            crm_debug("Using orphan clone name %s instead of %s", action->rsc->id,
                      action->rsc->clone_name);
            crm_xml_add(rsc_xml, XML_ATTR_ID, action->rsc->clone_name);
            crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->id);

        } else if (!pcmk_is_set(action->rsc->flags, pe_rsc_unique)) {
            const char *xml_id = ID(action->rsc->xml);

            crm_debug("Using anonymous clone name %s for %s (aka. %s)", xml_id, action->rsc->id,
                      action->rsc->clone_name);

            /* ID is what we'd like client to use
             * ID_LONG is what they might know it as instead
             *
             * ID_LONG is only strictly needed /here/ during the
             * transition period until all nodes in the cluster
             * are running the new software /and/ have rebooted
             * once (meaning that they've only ever spoken to a DC
             * supporting this feature).
             *
             * If anyone toggles the unique flag to 'on', the
             * 'instance free' name will correspond to an orphan
             * and fall into the clause above instead
             */
            crm_xml_add(rsc_xml, XML_ATTR_ID, xml_id);
            if (action->rsc->clone_name && !pcmk__str_eq(xml_id, action->rsc->clone_name, pcmk__str_casei)) {
                crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->clone_name);
            } else {
                crm_xml_add(rsc_xml, XML_ATTR_ID_LONG, action->rsc->id);
            }

        } else {
            CRM_ASSERT(action->rsc->clone_name == NULL);
            crm_xml_add(rsc_xml, XML_ATTR_ID, action->rsc->id);
        }

        for (lpc = 0; lpc < PCMK__NELEM(attr_list); lpc++) {
            crm_xml_add(rsc_xml, attr_list[lpc],
                        g_hash_table_lookup(action->rsc->meta, attr_list[lpc]));
        }
    }

    /* List any attributes in effect */
    args_xml = create_xml_node(NULL, XML_TAG_ATTRS);
    crm_xml_add(args_xml, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    g_hash_table_foreach(action->extra, hash2field, args_xml);
    if (action->rsc != NULL && action->node) {
        // Get the resource instance attributes, evaluated properly for node
        GHashTable *params = pe_rsc_params(action->rsc, action->node, data_set);

        pcmk__substitute_remote_addr(action->rsc, params, data_set);

        g_hash_table_foreach(params, hash2smartfield, args_xml);

#if ENABLE_VERSIONED_ATTRS
        {
            xmlNode *versioned_parameters = create_xml_node(NULL, XML_TAG_RSC_VER_ATTRS);

            pe_get_versioned_attributes(versioned_parameters, action->rsc,
                                        action->node, data_set);
            if (xml_has_children(versioned_parameters)) {
                add_node_copy(action_xml, versioned_parameters);
            }
            free_xml(versioned_parameters);
        }
#endif

    } else if(action->rsc && action->rsc->variant <= pe_native) {
        GHashTable *params = pe_rsc_params(action->rsc, NULL, data_set);

        g_hash_table_foreach(params, hash2smartfield, args_xml);

#if ENABLE_VERSIONED_ATTRS
        if (xml_has_children(action->rsc->versioned_parameters)) {
            add_node_copy(action_xml, action->rsc->versioned_parameters);
        }
#endif
    }

#if ENABLE_VERSIONED_ATTRS
    if (rsc_details) {
        if (xml_has_children(rsc_details->versioned_parameters)) {
            add_node_copy(action_xml, rsc_details->versioned_parameters);
        }

        if (xml_has_children(rsc_details->versioned_meta)) {
            add_node_copy(action_xml, rsc_details->versioned_meta);
        }
    }
#endif

    g_hash_table_foreach(action->meta, hash2metafield, args_xml);
    if (action->rsc != NULL) {
        const char *value = g_hash_table_lookup(action->rsc->meta, "external-ip");
        pe_resource_t *parent = action->rsc;

        while (parent != NULL) {
            parent->cmds->append_meta(parent, args_xml);
            parent = parent->parent;
        }

        if(value) {
            hash2smartfield((gpointer)"pcmk_external_ip", (gpointer)value, (gpointer)args_xml);
        }

        pcmk__add_bundle_meta_to_xml(args_xml, action);

    } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei) && action->node) {
        /* Pass the node's attributes as meta-attributes.
         *
         * @TODO: Determine whether it is still necessary to do this. It was
         * added in 33d99707, probably for the libfence-based implementation in
         * c9a90bd, which is no longer used.
         */
        g_hash_table_foreach(action->node->details->attrs, hash2metafield, args_xml);
    }

    sorted_xml(args_xml, action_xml, FALSE);
    free_xml(args_xml);

    /* List any nodes this action is expected to make down */
    if (needs_node_info && (action->node != NULL)) {
        add_downed_nodes(action_xml, action, data_set);
    }

    if (needs_maintenance_info) {
        add_maintenance_nodes(action_xml, data_set);
    }

    crm_log_xml_trace(action_xml, "dumped action");
    return action_xml;
}

static bool
should_dump_action(pe_action_t *action)
{
    CRM_CHECK(action != NULL, return false);

    if (pcmk_is_set(action->flags, pe_action_dumped)) {
        crm_trace("Action %s (%d) already dumped", action->uuid, action->id);
        return false;

    } else if (pcmk_is_set(action->flags, pe_action_pseudo)
               && pcmk__str_eq(action->task, CRM_OP_PROBED, pcmk__str_casei)) {
        GList *lpc = NULL;

        /* This is a horrible but convenient hack
         *
         * It mimimizes the number of actions with unsatisfied inputs
         * (i.e. not included in the graph)
         *
         * This in turn, means we can be more concise when printing
         * aborted/incomplete graphs.
         *
         * It also makes it obvious which node is preventing
         * probe_complete from running (presumably because it is only
         * partially up)
         *
         * For these reasons we tolerate such perversions
         */

        for (lpc = action->actions_after; lpc != NULL; lpc = lpc->next) {
            pe_action_wrapper_t *wrapper = (pe_action_wrapper_t *) lpc->data;

            if (!pcmk_is_set(wrapper->action->flags, pe_action_runnable)) {
                /* Only interested in runnable operations */
            } else if (!pcmk__str_eq(wrapper->action->task, RSC_START, pcmk__str_casei)) {
                /* Only interested in start operations */
            } else if (pcmk_is_set(wrapper->action->flags, pe_action_dumped)
                       || should_dump_action(wrapper->action)) {
                crm_trace("Action %s (%d) should be dumped: "
                          "dependency of %s (%d)",
                          action->uuid, action->id,
                          wrapper->action->uuid, wrapper->action->id);
                return true;
            }
        }
    }

    if (!pcmk_is_set(action->flags, pe_action_runnable)) {
        crm_trace("Ignoring action %s (%d): unrunnable",
                  action->uuid, action->id);
        return false;

    } else if (pcmk_is_set(action->flags, pe_action_optional)
               && !pcmk_is_set(action->flags, pe_action_print_always)) {
        crm_trace("Ignoring action %s (%d): optional",
                  action->uuid, action->id);
        return false;

    // Monitors should be dumped even for unmanaged resources
    } else if (action->rsc && !pcmk_is_set(action->rsc->flags, pe_rsc_managed)
               && !pcmk__str_eq(action->task, RSC_STATUS, pcmk__str_casei)) {

        const char *interval_ms_s = g_hash_table_lookup(action->meta,
                                                        XML_LRM_ATTR_INTERVAL_MS);

        // Cancellation of recurring monitors should still be dumped
        if (pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches)) {
            crm_trace("Ignoring action %s (%d): for unmanaged resource (%s)",
                      action->uuid, action->id, action->rsc->id);
            return false;
        }
    }

    if (pcmk_is_set(action->flags, pe_action_pseudo) ||
        pcmk__strcase_any_of(action->task, CRM_OP_FENCE, CRM_OP_SHUTDOWN, NULL)) {
        /* skip the next checks */
        return true;
    }

    if (action->node == NULL) {
        pe_err("Skipping action %s (%d) "
               "because it was not allocated to a node (bug?)",
               action->uuid, action->id);
        log_action(LOG_DEBUG, "Unallocated action", action, false);
        return false;

    } else if (pcmk_is_set(action->flags, pe_action_dc)) {
        crm_trace("Action %s (%d) should be dumped: "
                  "can run on DC instead of %s",
                  action->uuid, action->id, action->node->details->uname);

    } else if (pe__is_guest_node(action->node)
               && !action->node->details->remote_requires_reset) {
        crm_trace("Action %s (%d) should be dumped: "
                  "assuming will be runnable on guest node %s",
                  action->uuid, action->id, action->node->details->uname);

    } else if (action->node->details->online == false) {
        pe_err("Skipping action %s (%d) "
               "because it was scheduled for offline node (bug?)",
               action->uuid, action->id);
        log_action(LOG_DEBUG, "Action for offline node", action, FALSE);
        return false;
#if 0
        /* but this would also affect resources that can be safely
         *  migrated before a fencing op
         */
    } else if (action->node->details->unclean == false) {
        pe_err("Skipping action %s (%d) "
               "because it was scheduled for unclean node (bug?)",
               action->uuid, action->id);
        log_action(LOG_DEBUG, "Action for unclean node", action, false);
        return false;
#endif
    }
    return true;
}

/* lowest to highest */
static gint
sort_action_id(gconstpointer a, gconstpointer b)
{
    const pe_action_wrapper_t *action_wrapper2 = (const pe_action_wrapper_t *)a;
    const pe_action_wrapper_t *action_wrapper1 = (const pe_action_wrapper_t *)b;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (action_wrapper1->action->id > action_wrapper2->action->id) {
        return -1;
    }

    if (action_wrapper1->action->id < action_wrapper2->action->id) {
        return 1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Check whether an ordering's flags can change an action
 *
 * \param[in] ordering  Ordering to check
 *
 * \return true if ordering has flags that can change an action, false otherwise
 */
static bool
ordering_can_change_actions(pe_action_wrapper_t *ordering)
{
    return pcmk_any_flags_set(ordering->type, ~(pe_order_implies_first_printed
                                                |pe_order_implies_then_printed
                                                |pe_order_optional));
}

/*!
 * \internal
 * \brief Check whether an action input should be in the transition graph
 *
 * \param[in]     action  Action to check
 * \param[in,out] input   Action input to check
 *
 * \return true if input should be in graph, false otherwise
 * \note This function may not only check an input, but disable it under certian
 *       circumstances (load or anti-colocation orderings that are not needed).
 */
static bool
check_dump_input(pe_action_t *action, pe_action_wrapper_t *input)
{
    if (input->state == pe_link_dumped) {
        return true;
    }

    if (input->type == pe_order_none) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "ordering disabled",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (!pcmk_is_set(input->action->flags, pe_action_runnable)
               && !ordering_can_change_actions(input)
               && !pcmk__str_eq(input->action->uuid, CRM_OP_PROBED, pcmk__str_casei)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "optional and input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (!pcmk_is_set(input->action->flags, pe_action_runnable)
               && pcmk_is_set(input->type, pe_order_one_or_more)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "one-or-more and input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (pcmk_is_set(action->flags, pe_action_pseudo)
               && pcmk_is_set(input->type, pe_order_stonith_stop)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "stonith stop but action is pseudo",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (pcmk_is_set(input->type, pe_order_implies_first_migratable)
               && !pcmk_is_set(input->action->flags, pe_action_runnable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "implies input migratable but input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (pcmk_is_set(input->type, pe_order_apply_first_non_migratable)
               && pcmk_is_set(input->action->flags, pe_action_migrate_runnable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "only if input unmigratable but input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if ((input->type == pe_order_optional)
               && pcmk_is_set(input->action->flags, pe_action_migrate_runnable)
               && pcmk__ends_with(input->action->uuid, "_stop_0")) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "optional but stop in migration",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (input->type == pe_order_load) {
        pe_node_t *input_node = input->action->node;

        // load orderings are relevant only if actions are for same node

        if (action->rsc && pcmk__str_eq(action->task, RSC_MIGRATE, pcmk__str_casei)) {
            pe_node_t *allocated = action->rsc->allocated_to;

            /* For load_stopped -> migrate_to orderings, we care about where it
             * has been allocated to, not where it will be executed.
             */
            if ((input_node == NULL) || (allocated == NULL)
                || (input_node->details != allocated->details)) {
                crm_trace("Ignoring %s (%d) input %s (%d): "
                          "load ordering node mismatch %s vs %s",
                          action->uuid, action->id,
                          input->action->uuid, input->action->id,
                          (allocated? allocated->details->uname : "<none>"),
                          (input_node? input_node->details->uname : "<none>"));
                input->type = pe_order_none;
                return false;
            }

        } else if ((input_node == NULL) || (action->node == NULL)
                   || (input_node->details != action->node->details)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "load ordering node mismatch %s vs %s",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id,
                      (action->node? action->node->details->uname : "<none>"),
                      (input_node? input_node->details->uname : "<none>"));
            input->type = pe_order_none;
            return false;

        } else if (pcmk_is_set(input->action->flags, pe_action_optional)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "load ordering input optional",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id);
            input->type = pe_order_none;
            return false;
        }

    } else if (input->type == pe_order_anti_colocation) {
        if (input->action->node && action->node
            && (input->action->node->details != action->node->details)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "anti-colocation node mismatch %s vs %s",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id,
                      action->node->details->uname,
                      input->action->node->details->uname);
            input->type = pe_order_none;
            return false;

        } else if (pcmk_is_set(input->action->flags, pe_action_optional)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "anti-colocation input optional",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id);
            input->type = pe_order_none;
            return false;
        }

    } else if (input->action->rsc
               && input->action->rsc != action->rsc
               && pcmk_is_set(input->action->rsc->flags, pe_rsc_failed)
               && !pcmk_is_set(input->action->rsc->flags, pe_rsc_managed)
               && pcmk__ends_with(input->action->uuid, "_stop_0")
               && action->rsc && pe_rsc_is_clone(action->rsc)) {
        crm_warn("Ignoring requirement that %s complete before %s:"
                 " unmanaged failed resources cannot prevent clone shutdown",
                 input->action->uuid, action->uuid);
        return false;

    } else if (pcmk_is_set(input->action->flags, pe_action_optional)
               && !pcmk_any_flags_set(input->action->flags,
                                      pe_action_print_always|pe_action_dumped)
               && !should_dump_action(input->action)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "input optional",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;
    }

    crm_trace("%s (%d) input %s %s (%d) on %s should be dumped: %s %s 0x%.6x",
              action->uuid, action->id, action_type_str(input->action->flags),
              input->action->uuid, input->action->id,
              action_node_str(input->action),
              action_runnable_str(input->action->flags),
              action_optional_str(input->action->flags), input->type);
    return true;
}

bool
pcmk__graph_has_loop(pe_action_t *init_action, pe_action_t *action,
                     pe_action_wrapper_t *input)
{
    bool has_loop = false;

    if (pcmk_is_set(input->action->flags, pe_action_tracking)) {
        crm_trace("Breaking tracking loop: %s@%s -> %s@%s (0x%.6x)",
                  input->action->uuid,
                  input->action->node? input->action->node->details->uname : "",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  input->type);
        return false;
    }

    // Don't need to check inputs that won't be used
    if (!check_dump_input(action, input)) {
        return false;
    }

    if (input->action == init_action) {
        crm_debug("Input loop found in %s@%s ->...-> %s@%s",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  init_action->uuid,
                  init_action->node? init_action->node->details->uname : "");
        return true;
    }

    pe__set_action_flags(input->action, pe_action_tracking);

    crm_trace("Checking inputs of action %s@%s input %s@%s (0x%.6x)"
              "for graph loop with %s@%s ",
              action->uuid,
              action->node? action->node->details->uname : "",
              input->action->uuid,
              input->action->node? input->action->node->details->uname : "",
              input->type,
              init_action->uuid,
              init_action->node? init_action->node->details->uname : "");

    // Recursively check input itself for loops
    for (GList *iter = input->action->actions_before;
         iter != NULL; iter = iter->next) {

        if (pcmk__graph_has_loop(init_action, input->action,
                                 (pe_action_wrapper_t *) iter->data)) {
            // Recursive call already logged a debug message
            has_loop = true;
            goto done;
        }
    }

done:
    pe__clear_action_flags(input->action, pe_action_tracking);

    if (!has_loop) {
        crm_trace("No input loop found in %s@%s -> %s@%s (0x%.6x)",
                  input->action->uuid,
                  input->action->node? input->action->node->details->uname : "",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  input->type);
    }
    return has_loop;
}

// Remove duplicate inputs (regardless of flags)
static void
deduplicate_inputs(pe_action_t *action)
{
    GList *item = NULL;
    GList *next = NULL;
    pe_action_wrapper_t *last_input = NULL;

    action->actions_before = g_list_sort(action->actions_before,
                                         sort_action_id);
    for (item = action->actions_before; item != NULL; item = next) {
        pe_action_wrapper_t *input = (pe_action_wrapper_t *) item->data;

        next = item->next;
        if (last_input && (input->action->id == last_input->action->id)) {
            crm_trace("Input %s (%d) duplicate skipped for action %s (%d)",
                      input->action->uuid, input->action->id,
                      action->uuid, action->id);

            /* For the purposes of scheduling, the ordering flags no longer
             * matter, but crm_simulate looks at certain ones when creating a
             * dot graph. Combining the flags is sufficient for that purpose.
             */
            last_input->type |= input->type;
            if (input->state == pe_link_dumped) {
                last_input->state = pe_link_dumped;
            }

            free(item->data);
            action->actions_before = g_list_delete_link(action->actions_before,
                                                        item);
        } else {
            last_input = input;
            input->state = pe_link_not_dumped;
        }
    }
}

/*!
 * \internal
 * \brief Add an action to the transition graph XML if appropriate
 *
 * \param[in] action    Action to possibly add
 * \param[in] data_set  Cluster working set
 *
 * \note This will de-duplicate the action inputs, meaning that the
 *       pe_action_wrapper_t:type flags can no longer be relied on to retain
 *       their original settings. That means this MUST be called after
 *       pcmk__apply_orderings() is complete, and nothing after this should rely
 *       on those type flags. (For example, some code looks for type equal to
 *       some flag rather than whether the flag is set, and some code looks for
 *       particular combinations of flags -- such code must be done before
 *       stage8().)
 */
void
graph_element_from_action(pe_action_t *action, pe_working_set_t *data_set)
{
    GList *lpc = NULL;
    int synapse_priority = 0;
    xmlNode *syn = NULL;
    xmlNode *set = NULL;
    xmlNode *in = NULL;
    xmlNode *xml_action = NULL;
    pe_action_wrapper_t *input = NULL;

    /* If we haven't already, de-duplicate inputs -- even if we won't be dumping
     * the action, so that crm_simulate dot graphs don't have duplicates.
     */
    if (!pcmk_is_set(action->flags, pe_action_dedup)) {
        deduplicate_inputs(action);
        pe__set_action_flags(action, pe_action_dedup);
    }

    if (should_dump_action(action) == FALSE) {
        return;
    }

    pe__set_action_flags(action, pe_action_dumped);

    syn = create_xml_node(data_set->graph, "synapse");
    set = create_xml_node(syn, "action_set");
    in = create_xml_node(syn, "inputs");

    crm_xml_add_int(syn, XML_ATTR_ID, data_set->num_synapse);
    data_set->num_synapse++;

    if (action->rsc != NULL) {
        synapse_priority = action->rsc->priority;
    }
    if (action->priority > synapse_priority) {
        synapse_priority = action->priority;
    }
    if (synapse_priority > 0) {
        crm_xml_add_int(syn, XML_CIB_ATTR_PRIORITY, synapse_priority);
    }

    xml_action = action2xml(action, FALSE, data_set);
    add_node_nocopy(set, crm_element_name(xml_action), xml_action);

    for (lpc = action->actions_before; lpc != NULL; lpc = lpc->next) {
        input = (pe_action_wrapper_t *) lpc->data;
        if (check_dump_input(action, input)) {
            xmlNode *input_xml = create_xml_node(in, "trigger");

            input->state = pe_link_dumped;
            xml_action = action2xml(input->action, TRUE, data_set);
            add_node_nocopy(input_xml, crm_element_name(xml_action), xml_action);
        }
    }
}

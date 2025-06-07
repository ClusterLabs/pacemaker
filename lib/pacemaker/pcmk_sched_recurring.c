/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>
#include <crm/common/scheduler_internal.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

// Information parsed from an operation history entry in the CIB
struct op_history {
    // XML attributes
    const char *id;         // ID of history entry
    const char *name;       // Action name

    // Parsed information
    char *key;              // Operation key for action
    enum rsc_role_e role;   // Action role (or pcmk_role_unknown for default)
    guint interval_ms;      // Action interval
};

/*!
 * \internal
 * \brief Parse an interval from XML
 *
 * \param[in] xml  XML containing an interval attribute
 *
 * \return Interval parsed from XML (or 0 as default)
 */
static guint
xe_interval(const xmlNode *xml)
{
    guint interval_ms = 0U;

    pcmk_parse_interval_spec(crm_element_value(xml, PCMK_META_INTERVAL),
                             &interval_ms);
    return interval_ms;
}

/*!
 * \internal
 * \brief Check whether an operation exists multiple times in resource history
 *
 * \param[in] rsc          Resource with history to search
 * \param[in] name         Name of action to search for
 * \param[in] interval_ms  Interval (in milliseconds) of action to search for
 *
 * \return true if an operation with \p name and \p interval_ms exists more than
 *         once in the operation history of \p rsc, otherwise false
 */
static bool
is_op_dup(const pcmk_resource_t *rsc, const char *name, guint interval_ms)
{
    const char *id = NULL;

    for (xmlNode *op = pcmk__xe_first_child(rsc->priv->ops_xml, PCMK_XE_OP,
                                            NULL, NULL);
         op != NULL; op = pcmk__xe_next(op, PCMK_XE_OP)) {

        // Check whether action name and interval match
        if (!pcmk__str_eq(crm_element_value(op, PCMK_XA_NAME), name,
                          pcmk__str_none)
            || (xe_interval(op) != interval_ms)) {
            continue;
        }

        if (pcmk__xe_id(op) == NULL) {
            continue; // Shouldn't be possible
        }

        if (id == NULL) {
            id = pcmk__xe_id(op); // First matching op
        } else {
            pcmk__config_err("Operation %s is duplicate of %s (do not use "
                             "same name and interval combination more "
                             "than once per resource)", pcmk__xe_id(op), id);
            return true;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether an action name is one that can be recurring
 *
 * \param[in] name  Action name to check
 *
 * \return true if \p name is an action known to be unsuitable as a recurring
 *         operation, otherwise false
 *
 * \note Pacemaker's current philosophy is to allow users to configure recurring
 *       operations except for a short list of actions known not to be suitable
 *       for that (as opposed to allowing only actions known to be suitable,
 *       which includes only monitor). Among other things, this approach allows
 *       users to define their own custom operations and make them recurring,
 *       though that use case is not well tested.
 */
static bool
op_cannot_recur(const char *name)
{
    return pcmk__str_any_of(name, PCMK_ACTION_STOP, PCMK_ACTION_START,
                            PCMK_ACTION_DEMOTE, PCMK_ACTION_PROMOTE,
                            PCMK_ACTION_RELOAD_AGENT,
                            PCMK_ACTION_MIGRATE_TO, PCMK_ACTION_MIGRATE_FROM,
                            NULL);
}

/*!
 * \internal
 * \brief Check whether a resource history entry is for a recurring action
 *
 * \param[in]  rsc          Resource that history entry is for
 * \param[in]  xml          XML of resource history entry to check
 * \param[out] op           Where to store parsed info if recurring
 *
 * \return true if \p xml is for a recurring action, otherwise false
 */
static bool
is_recurring_history(const pcmk_resource_t *rsc, const xmlNode *xml,
                     struct op_history *op)
{
    const char *role = NULL;

    op->interval_ms = xe_interval(xml);
    if (op->interval_ms == 0) {
        return false; // Not recurring
    }

    op->id = pcmk__xe_id(xml);
    if (pcmk__str_empty(op->id)) {
        pcmk__config_err("Ignoring resource history entry without ID");
        return false; // Shouldn't be possible (unless CIB was manually edited)
    }

    op->name = crm_element_value(xml, PCMK_XA_NAME);
    if (op_cannot_recur(op->name)) {
        pcmk__config_err("Ignoring %s because %s action cannot be recurring",
                         op->id, pcmk__s(op->name, "unnamed"));
        return false;
    }

    // There should only be one recurring operation per action/interval
    if (is_op_dup(rsc, op->name, op->interval_ms)) {
        return false;
    }

    // Ensure role is valid if specified
    role = crm_element_value(xml, PCMK_XA_ROLE);
    if (role == NULL) {
        op->role = pcmk_role_unknown;
    } else {
        op->role = pcmk_parse_role(role);
        if (op->role == pcmk_role_unknown) {
            pcmk__config_err("Ignoring %s role because %s is not a valid role",
                             op->id, role);
            return false;
        }
    }

    // Only actions that are still configured and enabled matter
    if (pcmk__find_action_config(rsc, op->name, op->interval_ms,
                                 false) == NULL) {
        pcmk__rsc_trace(rsc,
                        "Ignoring %s (%s-interval %s for %s) because it is "
                        "disabled or no longer in configuration",
                        op->id, pcmk__readable_interval(op->interval_ms),
                        op->name, rsc->id);
        return false;
    }

    op->key = pcmk__op_key(rsc->id, op->name, op->interval_ms);
    return true;
}

/*!
 * \internal
 * \brief Check whether a recurring action for an active role should be optional
 *
 * \param[in]     rsc    Resource that recurring action is for
 * \param[in]     node   Node that \p rsc will be active on (if any)
 * \param[in]     key    Operation key for recurring action to check
 * \param[in,out] start  Start action for \p rsc
 *
 * \return true if recurring action should be optional, otherwise false
 */
static bool
active_recurring_should_be_optional(const pcmk_resource_t *rsc,
                                    const pcmk_node_t *node, const char *key,
                                    pcmk_action_t *start)
{
    GList *possible_matches = NULL;

    if (node == NULL) { // Should only be possible if unmanaged and stopped
        pcmk__rsc_trace(rsc,
                        "%s will be mandatory because resource is unmanaged",
                        key);
        return false;
    }

    if (!pcmk_is_set(rsc->priv->cmds->action_flags(start, NULL),
                     pcmk__action_optional)) {
        pcmk__rsc_trace(rsc, "%s will be mandatory because %s is",
                        key, start->uuid);
        return false;
    }

    possible_matches = find_actions_exact(rsc->priv->actions, key, node);
    if (possible_matches == NULL) {
        pcmk__rsc_trace(rsc,
                        "%s will be mandatory because it is not active on %s",
                        key, pcmk__node_name(node));
        return false;
    }

    for (const GList *iter = possible_matches;
         iter != NULL; iter = iter->next) {

        const pcmk_action_t *op = (const pcmk_action_t *) iter->data;

        if (pcmk_is_set(op->flags, pcmk__action_reschedule)) {
            pcmk__rsc_trace(rsc,
                            "%s will be mandatory because "
                            "it needs to be rescheduled", key);
            g_list_free(possible_matches);
            return false;
        }
    }

    g_list_free(possible_matches);
    return true;
}

/*!
 * \internal
 * \brief Create recurring action from resource history entry for an active role
 *
 * \param[in,out] rsc    Resource that resource history is for
 * \param[in,out] start  Start action for \p rsc on \p node
 * \param[in]     node   Node that resource will be active on (if any)
 * \param[in]     op     Resource history entry
 */
static void
recurring_op_for_active(pcmk_resource_t *rsc, pcmk_action_t *start,
                        const pcmk_node_t *node, const struct op_history *op)
{
    pcmk_action_t *mon = NULL;
    bool is_optional = true;
    bool role_match = false;
    enum rsc_role_e monitor_role = op->role;

    // We're only interested in recurring actions for active roles
    if (monitor_role == pcmk_role_stopped) {
        return;
    }

    is_optional = active_recurring_should_be_optional(rsc, node, op->key,
                                                      start);

    // Check whether monitor's role matches role resource will have
    if (monitor_role == pcmk_role_unknown) {
        monitor_role = pcmk_role_unpromoted;
        role_match = (rsc->priv->next_role != pcmk_role_promoted);
    } else {
        role_match = (rsc->priv->next_role == monitor_role);
    }

    if (!role_match) {
        if (is_optional) { // It's running, so cancel it
            char *after_key = NULL;
            pcmk_action_t *cancel_op = pcmk__new_cancel_action(rsc, op->name,
                                                               op->interval_ms,
                                                               node);

            switch (rsc->priv->orig_role) {
                case pcmk_role_unpromoted:
                case pcmk_role_started:
                    if (rsc->priv->next_role == pcmk_role_promoted) {
                        after_key = promote_key(rsc);

                    } else if (rsc->priv->next_role == pcmk_role_stopped) {
                        after_key = stop_key(rsc);
                    }

                    break;
                case pcmk_role_promoted:
                    after_key = demote_key(rsc);
                    break;
                default:
                    break;
            }

            if (after_key) {
                pcmk__new_ordering(rsc, NULL, cancel_op, rsc, after_key, NULL,
                                   pcmk__ar_unrunnable_first_blocks,
                                   rsc->priv->scheduler);
            }
        }

        do_crm_log((is_optional? LOG_INFO : LOG_TRACE),
                   "%s recurring action %s because %s configured for %s role "
                   "(not %s)",
                   (is_optional? "Cancelling" : "Ignoring"), op->key, op->id,
                   pcmk_role_text(monitor_role),
                   pcmk_role_text(rsc->priv->next_role));
        return;
    }

    pcmk__rsc_trace(rsc,
                    "Creating %s recurring action %s for %s (%s %s on %s)",
                    (is_optional? "optional" : "mandatory"), op->key,
                    op->id, rsc->id, pcmk_role_text(rsc->priv->next_role),
                    pcmk__node_name(node));

    mon = custom_action(rsc, strdup(op->key), op->name, node, is_optional,
                        rsc->priv->scheduler);

    if (!pcmk_is_set(start->flags, pcmk__action_runnable)) {
        pcmk__rsc_trace(rsc, "%s is unrunnable because start is", mon->uuid);
        pcmk__clear_action_flags(mon, pcmk__action_runnable);

    } else if (!pcmk__node_available(node, pcmk__node_alive)) {
        pcmk__rsc_trace(rsc, "%s is unrunnable because no node is available",
                        mon->uuid);
        pcmk__clear_action_flags(mon, pcmk__action_runnable);

    } else if (!pcmk_is_set(mon->flags, pcmk__action_optional)) {
        pcmk__rsc_info(rsc, "Start %s-interval %s for %s on %s",
                       pcmk__readable_interval(op->interval_ms), mon->task,
                       rsc->id, pcmk__node_name(node));
    }

    if (rsc->priv->next_role == pcmk_role_promoted) {
        pe__add_action_expected_result(mon, CRM_EX_PROMOTED);
    }

    // Order monitor relative to other actions
    if ((node == NULL) || pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
        pcmk__new_ordering(rsc, start_key(rsc), NULL,
                           NULL, strdup(mon->uuid), mon,
                           pcmk__ar_first_implies_then
                           |pcmk__ar_unrunnable_first_blocks,
                           rsc->priv->scheduler);

        pcmk__new_ordering(rsc, reload_key(rsc), NULL,
                           NULL, strdup(mon->uuid), mon,
                           pcmk__ar_first_implies_then
                           |pcmk__ar_unrunnable_first_blocks,
                           rsc->priv->scheduler);

        if (rsc->priv->next_role == pcmk_role_promoted) {
            pcmk__new_ordering(rsc, promote_key(rsc), NULL,
                               rsc, NULL, mon,
                               pcmk__ar_ordered
                               |pcmk__ar_unrunnable_first_blocks,
                               rsc->priv->scheduler);

        } else if (rsc->priv->orig_role == pcmk_role_promoted) {
            pcmk__new_ordering(rsc, demote_key(rsc), NULL,
                               rsc, NULL, mon,
                               pcmk__ar_ordered
                               |pcmk__ar_unrunnable_first_blocks,
                               rsc->priv->scheduler);
        }
    }
}

/*!
 * \internal
 * \brief Cancel a recurring action if running on a node
 *
 * \param[in,out] rsc          Resource that action is for
 * \param[in]     node         Node to cancel action on
 * \param[in]     key          Operation key for action
 * \param[in]     name         Action name
 * \param[in]     interval_ms  Action interval (in milliseconds)
 */
static void
cancel_if_running(pcmk_resource_t *rsc, const pcmk_node_t *node,
                  const char *key, const char *name, guint interval_ms)
{
    GList *possible_matches = find_actions_exact(rsc->priv->actions, key,
                                                 node);
    pcmk_action_t *cancel_op = NULL;

    if (possible_matches == NULL) {
        return; // Recurring action isn't running on this node
    }
    g_list_free(possible_matches);

    cancel_op = pcmk__new_cancel_action(rsc, name, interval_ms, node);

    switch (rsc->priv->next_role) {
        case pcmk_role_started:
        case pcmk_role_unpromoted:
            /* Order starts after cancel. If the current role is
             * stopped, this cancels the monitor before the resource
             * starts; if the current role is started, then this cancels
             * the monitor on a migration target before starting there.
             */
            pcmk__new_ordering(rsc, NULL, cancel_op,
                               rsc, start_key(rsc), NULL,
                               pcmk__ar_unrunnable_first_blocks,
                               rsc->priv->scheduler);
            break;
        default:
            break;
    }
    pcmk__rsc_info(rsc,
                   "Cancelling %s-interval %s action for %s on %s because "
                   "configured for " PCMK_ROLE_STOPPED " role (not %s)",
                   pcmk__readable_interval(interval_ms), name, rsc->id,
                   pcmk__node_name(node),
                   pcmk_role_text(rsc->priv->next_role));
}

/*!
 * \internal
 * \brief Order an action after all probes of a resource on a node
 *
 * \param[in,out] rsc     Resource to check for probes
 * \param[in]     node    Node to check for probes of \p rsc
 * \param[in,out] action  Action to order after probes of \p rsc on \p node
 */
static void
order_after_probes(pcmk_resource_t *rsc, const pcmk_node_t *node,
                   pcmk_action_t *action)
{
    GList *probes = pe__resource_actions(rsc, node, PCMK_ACTION_MONITOR, FALSE);

    for (GList *iter = probes; iter != NULL; iter = iter->next) {
        order_actions((pcmk_action_t *) iter->data, action,
                      pcmk__ar_unrunnable_first_blocks);
    }
    g_list_free(probes);
}

/*!
 * \internal
 * \brief Order an action after all stops of a resource on a node
 *
 * \param[in,out] rsc     Resource to check for stops
 * \param[in]     node    Node to check for stops of \p rsc
 * \param[in,out] action  Action to order after stops of \p rsc on \p node
 */
static void
order_after_stops(pcmk_resource_t *rsc, const pcmk_node_t *node,
                  pcmk_action_t *action)
{
    GList *stop_ops = pe__resource_actions(rsc, node, PCMK_ACTION_STOP, TRUE);

    for (GList *iter = stop_ops; iter != NULL; iter = iter->next) {
        pcmk_action_t *stop = (pcmk_action_t *) iter->data;

        if (!pcmk_is_set(stop->flags, pcmk__action_optional)
            && !pcmk_is_set(action->flags, pcmk__action_optional)
            && !pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
            pcmk__rsc_trace(rsc, "%s optional on %s: unmanaged",
                            action->uuid, pcmk__node_name(node));
            pcmk__set_action_flags(action, pcmk__action_optional);
        }

        if (!pcmk_is_set(stop->flags, pcmk__action_runnable)) {
            crm_debug("%s unrunnable on %s: stop is unrunnable",
                      action->uuid, pcmk__node_name(node));
            pcmk__clear_action_flags(action, pcmk__action_runnable);
        }

        if (pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
            pcmk__new_ordering(rsc, stop_key(rsc), stop,
                               NULL, NULL, action,
                               pcmk__ar_first_implies_then
                               |pcmk__ar_unrunnable_first_blocks,
                               rsc->priv->scheduler);
        }
    }
    g_list_free(stop_ops);
}

/*!
 * \internal
 * \brief Create recurring action from resource history entry for inactive role
 *
 * \param[in,out] rsc    Resource that resource history is for
 * \param[in]     node   Node that resource will be active on (if any)
 * \param[in]     op     Resource history entry
 */
static void
recurring_op_for_inactive(pcmk_resource_t *rsc, const pcmk_node_t *node,
                          const struct op_history *op)
{
    GList *possible_matches = NULL;

    // We're only interested in recurring actions for the inactive role
    if (op->role != pcmk_role_stopped) {
        return;
    }

    if (!pcmk_is_set(rsc->flags, pcmk__rsc_unique)) {
        crm_notice("Ignoring %s (recurring monitors for " PCMK_ROLE_STOPPED
                   " role are not supported for anonymous clones)", op->id);
        return; // @TODO add support
    }

    pcmk__rsc_trace(rsc,
                    "Creating recurring action %s for %s on nodes "
                    "where it should not be running", op->id, rsc->id);

    for (GList *iter = rsc->priv->scheduler->nodes;
         iter != NULL; iter = iter->next) {

        pcmk_node_t *stop_node = (pcmk_node_t *) iter->data;

        bool is_optional = true;
        pcmk_action_t *stopped_mon = NULL;

        // Cancel action on node where resource will be active
        if ((node != NULL)
            && pcmk__str_eq(stop_node->priv->name, node->priv->name,
                            pcmk__str_casei)) {
            cancel_if_running(rsc, node, op->key, op->name, op->interval_ms);
            continue;
        }

        // Recurring action on this node is optional if it's already active here
        possible_matches = find_actions_exact(rsc->priv->actions, op->key,
                                              stop_node);
        is_optional = (possible_matches != NULL);
        g_list_free(possible_matches);

        pcmk__rsc_trace(rsc,
                        "Creating %s recurring action %s for %s (%s "
                        PCMK_ROLE_STOPPED " on %s)",
                        (is_optional? "optional" : "mandatory"),
                        op->key, op->id, rsc->id, pcmk__node_name(stop_node));

        stopped_mon = custom_action(rsc, strdup(op->key), op->name, stop_node,
                                    is_optional, rsc->priv->scheduler);

        pe__add_action_expected_result(stopped_mon, CRM_EX_NOT_RUNNING);

        if (pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
            order_after_probes(rsc, stop_node, stopped_mon);
        }

        /* The recurring action is for the inactive role, so it shouldn't be
         * performed until the resource is inactive.
         */
        order_after_stops(rsc, stop_node, stopped_mon);

        if (!pcmk__node_available(stop_node, pcmk__node_alive)) {
            pcmk__rsc_debug(rsc, "%s unrunnable on %s: node unavailable)",
                            stopped_mon->uuid, pcmk__node_name(stop_node));
            pcmk__clear_action_flags(stopped_mon, pcmk__action_runnable);
        }

        if (pcmk_is_set(stopped_mon->flags, pcmk__action_runnable)
            && !pcmk_is_set(stopped_mon->flags, pcmk__action_optional)) {
            crm_notice("Start recurring %s-interval %s for "
                       PCMK_ROLE_STOPPED " %s on %s",
                       pcmk__readable_interval(op->interval_ms),
                       stopped_mon->task, rsc->id, pcmk__node_name(stop_node));
        }
    }
}

/*!
 * \internal
 * \brief Create recurring actions for a resource
 *
 * \param[in,out] rsc  Resource to create recurring actions for
 */
void
pcmk__create_recurring_actions(pcmk_resource_t *rsc)
{
    pcmk_action_t *start = NULL;

    if (pcmk_is_set(rsc->flags, pcmk__rsc_blocked)) {
        pcmk__rsc_trace(rsc,
                        "Skipping recurring actions for blocked resource %s",
                        rsc->id);
        return;
    }

    if (pcmk_is_set(rsc->flags, pcmk__rsc_maintenance)) {
        pcmk__rsc_trace(rsc,
                        "Skipping recurring actions for %s "
                        "in maintenance mode", rsc->id);
        return;
    }

    if (rsc->priv->assigned_node == NULL) {
        // Recurring actions for active roles not needed

    } else if (rsc->priv->assigned_node->details->maintenance) {
        pcmk__rsc_trace(rsc,
                        "Skipping recurring actions for %s on %s "
                        "in maintenance mode",
                        rsc->id, pcmk__node_name(rsc->priv->assigned_node));

    } else if ((rsc->priv->next_role != pcmk_role_stopped)
               || !pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
        // Recurring actions for active roles needed
        start = start_action(rsc, rsc->priv->assigned_node, TRUE);
    }

    pcmk__rsc_trace(rsc, "Creating any recurring actions needed for %s",
                    rsc->id);

    for (xmlNode *op = pcmk__xe_first_child(rsc->priv->ops_xml, PCMK_XE_OP,
                                            NULL, NULL);
         op != NULL; op = pcmk__xe_next(op, PCMK_XE_OP)) {

        struct op_history op_history = { NULL, };

        if (!is_recurring_history(rsc, op, &op_history)) {
            continue;
        }

        if (start != NULL) {
            recurring_op_for_active(rsc, start, rsc->priv->assigned_node,
                                    &op_history);
        }
        recurring_op_for_inactive(rsc, rsc->priv->assigned_node,
                                  &op_history);

        free(op_history.key);
    }
}

/*!
 * \internal
 * \brief Create an executor cancel action
 *
 * \param[in,out] rsc          Resource of action to cancel
 * \param[in]     task         Name of action to cancel
 * \param[in]     interval_ms  Interval of action to cancel
 * \param[in]     node         Node of action to cancel
 *
 * \return Created op
 */
pcmk_action_t *
pcmk__new_cancel_action(pcmk_resource_t *rsc, const char *task,
                        guint interval_ms, const pcmk_node_t *node)
{
    pcmk_action_t *cancel_op = NULL;
    char *key = NULL;
    char *interval_ms_s = NULL;

    pcmk__assert((rsc != NULL) && (task != NULL) && (node != NULL));

    key = pcmk__op_key(rsc->id, task, interval_ms);

    /* This finds an existing action by key, so custom_action() does not change
     * cancel_op->task.
     */
    cancel_op = custom_action(rsc, key, PCMK_ACTION_CANCEL, node, FALSE,
                              rsc->priv->scheduler);

    pcmk__str_update(&(cancel_op->task), PCMK_ACTION_CANCEL);
    pcmk__str_update(&(cancel_op->cancel_task), task);

    interval_ms_s = crm_strdup_printf("%u", interval_ms);
    pcmk__insert_meta(cancel_op, PCMK_XA_OPERATION, task);
    pcmk__insert_meta(cancel_op, PCMK_META_INTERVAL, interval_ms_s);
    free(interval_ms_s);

    return cancel_op;
}

/*!
 * \internal
 * \brief Schedule cancellation of a recurring action
 *
 * \param[in,out] rsc          Resource that action is for
 * \param[in]     call_id      Action's call ID from history
 * \param[in]     task         Action name
 * \param[in]     interval_ms  Action interval
 * \param[in]     node         Node that history entry is for
 * \param[in]     reason       Short description of why action is cancelled
 */
void
pcmk__schedule_cancel(pcmk_resource_t *rsc, const char *call_id,
                      const char *task, guint interval_ms,
                      const pcmk_node_t *node, const char *reason)
{
    pcmk_action_t *cancel = NULL;

    CRM_CHECK((rsc != NULL) && (task != NULL)
              && (node != NULL) && (reason != NULL),
              return);

    crm_info("Recurring %s-interval %s for %s will be stopped on %s: %s",
             pcmk__readable_interval(interval_ms), task, rsc->id,
             pcmk__node_name(node), reason);
    cancel = pcmk__new_cancel_action(rsc, task, interval_ms, node);
    pcmk__insert_meta(cancel, PCMK__XA_CALL_ID, call_id);

    // Cancellations happen after stops
    pcmk__new_ordering(rsc, stop_key(rsc), NULL, rsc, NULL, cancel,
                       pcmk__ar_ordered, rsc->priv->scheduler);
}

/*!
 * \internal
 * \brief Create a recurring action marked as needing rescheduling if active
 *
 * \param[in,out] rsc          Resource that action is for
 * \param[in]     task         Name of action being rescheduled
 * \param[in]     interval_ms  Action interval (in milliseconds)
 * \param[in,out] node         Node where action should be rescheduled
 */
void
pcmk__reschedule_recurring(pcmk_resource_t *rsc, const char *task,
                           guint interval_ms, pcmk_node_t *node)
{
    pcmk_action_t *op = NULL;

    trigger_unfencing(rsc, node, "Device parameters changed (reschedule)",
                      NULL, rsc->priv->scheduler);
    op = custom_action(rsc, pcmk__op_key(rsc->id, task, interval_ms),
                       task, node, TRUE, rsc->priv->scheduler);
    pcmk__set_action_flags(op, pcmk__action_reschedule);
}

/*!
 * \internal
 * \brief Check whether an action is recurring
 *
 * \param[in] action  Action to check
 *
 * \return true if \p action has a nonzero interval, otherwise false
 */
bool
pcmk__action_is_recurring(const pcmk_action_t *action)
{
    guint interval_ms = 0;

    if (pcmk__guint_from_hash(action->meta, PCMK_META_INTERVAL, 0,
                              &interval_ms) != pcmk_rc_ok) {
        return false;
    }
    return (interval_ms > 0);
}

/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/msg_xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

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
    return crm_parse_interval_spec(crm_element_value(xml,
                                                     XML_LRM_ATTR_INTERVAL));
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
is_op_dup(const pe_resource_t *rsc, const char *name, guint interval_ms)
{
    const char *id = NULL;

    for (xmlNode *op = first_named_child(rsc->ops_xml, "op");
         op != NULL; op = crm_next_same_xml(op)) {

        // Check whether action name and interval match
        if (!pcmk__str_eq(crm_element_value(op, "name"),
                          name, pcmk__str_none)
            || (xe_interval(op) != interval_ms)) {
            continue;
        }

        if (ID(op) == NULL) {
            continue; // Shouldn't be possible
        }

        if (id == NULL) {
            id = ID(op); // First matching op
        } else {
            pcmk__config_err("Operation %s is duplicate of %s (do not use "
                             "same name and interval combination more "
                             "than once per resource)", ID(op), id);
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
    return pcmk__str_any_of(name, RSC_STOP, RSC_START, RSC_DEMOTE, RSC_PROMOTE,
                            CRMD_ACTION_RELOAD_AGENT, CRMD_ACTION_MIGRATE,
                            CRMD_ACTION_MIGRATED, NULL);
}

/*!
 * \internal
 * \brief Check whether a resource history entry is for a recurring action
 *
 * \param[in]  rsc          Resource that history entry is for
 * \param[in]  op           Resource history entry to check
 * \param[out] key          Will be set to operation key if recurring
 * \param[out] interval_ms  Will be set to interval from history entry
 */
static bool
is_recurring_history(const pe_resource_t *rsc, const xmlNode *op, char **key,
                     guint *interval_ms)
{
    const char *name = NULL;

    *interval_ms = xe_interval(op);
    if (*interval_ms == 0) {
        return false; // Not recurring
    }

    if (pcmk__str_empty(ID(op))) {
        pcmk__config_err("Ignoring resource history entry without ID");
        return false; // Shouldn't be possible (unless CIB was manually edited)
    }

    name = crm_element_value(op, "name");
    if (op_cannot_recur(name)) {
        pcmk__config_err("Ignoring %s because action '%s' cannot be recurring",
                         ID(op), name);
        return false;
    }

    // There should only be one recurring operation per action/interval
    if (is_op_dup(rsc, name, *interval_ms)) {
        return false;
    }

    // Disabled resources don't get monitored
    *key = pcmk__op_key(rsc->id, name, *interval_ms);
    if (find_rsc_op_entry(rsc, *key) == NULL) {
        crm_trace("Not creating recurring action %s for disabled resource %s",
                  ID(op), rsc->id);
        free(*key);
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Check whether a recurring action for an active role should be optional
 *
 * \param[in] rsc    Resource that recurring action is for
 * \param[in] node   Node that \p rsc will be active on (if any)
 * \param[in] key    Operation key for recurring action to check
 * \param[in] start  Start action for \p rsc
 *
 * \return true if recurring action should be optional, otherwise false
 */
static bool
active_recurring_should_be_optional(const pe_resource_t *rsc,
                                    const pe_node_t *node, const char *key,
                                    pe_action_t *start)
{
    GList *possible_matches = NULL;

    if (node == NULL) { // Should only be possible if unmanaged and stopped
        pe_rsc_trace(rsc, "%s will be mandatory because resource is unmanaged",
                     key);
        return false;
    }

    if (!pcmk_is_set(rsc->cmds->action_flags(start, NULL),
                     pe_action_optional)) {
        pe_rsc_trace(rsc, "%s will be mandatory because %s is",
                     key, start->uuid);
        return false;
    }

    possible_matches = find_actions_exact(rsc->actions, key, node);
    if (possible_matches == NULL) {
        pe_rsc_trace(rsc, "%s will be mandatory because it is not active on %s",
                     key, pe__node_name(node));
        return false;
    }

    for (GList *iter = possible_matches; iter != NULL; iter = iter->next) {
        pe_action_t *op = (pe_action_t *) iter->data;

        if (pcmk_is_set(op->flags, pe_action_reschedule)) {
            pe_rsc_trace(rsc,
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
 * \param[in]     start  Start action for \p rsc on \p node
 * \param[in]     node   Node that resource will be active on (if any)
 * \param[in]     op     Resource history entry
 */
static void
recurring_op_for_active(pe_resource_t *rsc, pe_action_t *start,
                        const pe_node_t *node, const xmlNode *op)
{
    char *key = NULL;
    const char *name = NULL;
    const char *role = NULL;

    guint interval_ms = 0;
    pe_action_t *mon = NULL;
    bool is_optional = true;

    // We're only interested in recurring actions for active roles
    role = crm_element_value(op, "role");
    if ((role != NULL) && (text2role(role) == RSC_ROLE_STOPPED)) {
        return;
    }

    if (!is_recurring_history(rsc, op, &key, &interval_ms)) {
        return;
    }

    name = crm_element_value(op, "name");
    is_optional = active_recurring_should_be_optional(rsc, node, key, start);

    if (((role != NULL) && (rsc->next_role != text2role(role)))
        || ((role == NULL) && (rsc->next_role == RSC_ROLE_PROMOTED))) {
        // Configured monitor role doesn't match role resource will have

        if (is_optional) { // It's running, so cancel it
            char *after_key = NULL;
            pe_action_t *cancel_op = pcmk__new_cancel_action(rsc, name,
                                                             interval_ms, node);

            switch (rsc->role) {
                case RSC_ROLE_UNPROMOTED:
                case RSC_ROLE_STARTED:
                    if (rsc->next_role == RSC_ROLE_PROMOTED) {
                        after_key = promote_key(rsc);

                    } else if (rsc->next_role == RSC_ROLE_STOPPED) {
                        after_key = stop_key(rsc);
                    }

                    break;
                case RSC_ROLE_PROMOTED:
                    after_key = demote_key(rsc);
                    break;
                default:
                    break;
            }

            if (after_key) {
                pcmk__new_ordering(rsc, NULL, cancel_op, rsc, after_key, NULL,
                                   pe_order_runnable_left, rsc->cluster);
            }
        }

        do_crm_log((is_optional? LOG_INFO : LOG_TRACE),
                   "%s recurring action %s because %s configured for %s role "
                   "(not %s)",
                   (is_optional? "Cancelling" : "Ignoring"), key, ID(op),
                   ((role == NULL)? role2text(RSC_ROLE_UNPROMOTED) : role),
                   role2text(rsc->next_role));
        free(key);
        return;
    }

    pe_rsc_trace(rsc,
                 "Creating %s recurring action %s for %s (%s %s on %s)",
                 (is_optional? "optional" : "mandatory"), key,
                 ID(op), rsc->id, role2text(rsc->next_role),
                 pe__node_name(node));

    mon = custom_action(rsc, key, name, node, is_optional, TRUE, rsc->cluster);

    if (!pcmk_is_set(start->flags, pe_action_runnable)) {
        pe_rsc_trace(rsc, "%s is unrunnable because start is", mon->uuid);
        pe__clear_action_flags(mon, pe_action_runnable);

    } else if ((node == NULL) || !node->details->online
               || node->details->unclean) {
        pe_rsc_trace(rsc, "%s is unrunnable because no node is available",
                     mon->uuid);
        pe__clear_action_flags(mon, pe_action_runnable);

    } else if (!pcmk_is_set(mon->flags, pe_action_optional)) {
        pe_rsc_info(rsc, "Start %s-interval %s for %s on %s",
                    pcmk__readable_interval(interval_ms), mon->task, rsc->id,
                    pe__node_name(node));
    }

    if (rsc->next_role == RSC_ROLE_PROMOTED) {
        pe__add_action_expected_result(mon, CRM_EX_PROMOTED);
    }

    // Order monitor relative to other actions
    if ((node == NULL) || pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        pcmk__new_ordering(rsc, start_key(rsc), NULL,
                           NULL, strdup(mon->uuid), mon,
                           pe_order_implies_then|pe_order_runnable_left,
                           rsc->cluster);

        pcmk__new_ordering(rsc, reload_key(rsc), NULL,
                           NULL, strdup(mon->uuid), mon,
                           pe_order_implies_then|pe_order_runnable_left,
                           rsc->cluster);

        if (rsc->next_role == RSC_ROLE_PROMOTED) {
            pcmk__new_ordering(rsc, promote_key(rsc), NULL,
                               rsc, NULL, mon,
                               pe_order_optional|pe_order_runnable_left,
                               rsc->cluster);

        } else if (rsc->role == RSC_ROLE_PROMOTED) {
            pcmk__new_ordering(rsc, demote_key(rsc), NULL,
                               rsc, NULL, mon,
                               pe_order_optional|pe_order_runnable_left,
                               rsc->cluster);
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
cancel_if_running(pe_resource_t *rsc, const pe_node_t *node, const char *key,
                  const char *name, guint interval_ms)
{
    GList *possible_matches = find_actions_exact(rsc->actions, key, node);
    pe_action_t *cancel_op = NULL;

    if (possible_matches == NULL) {
        return; // Recurring action isn't running on this node
    }
    g_list_free(possible_matches);

    cancel_op = pcmk__new_cancel_action(rsc, name, interval_ms, node);

    switch (rsc->next_role) {
        case RSC_ROLE_STARTED:
        case RSC_ROLE_UNPROMOTED:
            /* Order starts after cancel. If the current role is
             * stopped, this cancels the monitor before the resource
             * starts; if the current role is started, then this cancels
             * the monitor on a migration target before starting there.
             */
            pcmk__new_ordering(rsc, NULL, cancel_op,
                               rsc, start_key(rsc), NULL,
                               pe_order_runnable_left, rsc->cluster);
            break;
        default:
            break;
    }
    pe_rsc_info(rsc,
                "Cancelling %s-interval %s action for %s on %s because "
                "configured for " RSC_ROLE_STOPPED_S " role (not %s)",
                pcmk__readable_interval(interval_ms), name, rsc->id,
                pe__node_name(node), role2text(rsc->next_role));
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
order_after_probes(pe_resource_t *rsc, const pe_node_t *node,
                   pe_action_t *action)
{
    GList *probes = pe__resource_actions(rsc, node, RSC_STATUS, FALSE);

    for (GList *iter = probes; iter != NULL; iter = iter->next) {
        order_actions((pe_action_t *) iter->data, action,
                      pe_order_runnable_left);
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
order_after_stops(pe_resource_t *rsc, const pe_node_t *node,
                  pe_action_t *action)
{
    GList *stop_ops = pe__resource_actions(rsc, node, RSC_STOP, TRUE);

    for (GList *iter = stop_ops; iter != NULL; iter = iter->next) {
        pe_action_t *stop = (pe_action_t *) iter->data;

        if (!pcmk_is_set(stop->flags, pe_action_optional)
            && !pcmk_is_set(action->flags, pe_action_optional)
            && !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            pe_rsc_trace(rsc, "%s optional on %s: unmanaged",
                         action->uuid, pe__node_name(node));
            pe__set_action_flags(action, pe_action_optional);
        }

        if (!pcmk_is_set(stop->flags, pe_action_runnable)) {
            crm_debug("%s unrunnable on %s: stop is unrunnable",
                      action->uuid, pe__node_name(node));
            pe__clear_action_flags(action, pe_action_runnable);
        }

        if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            pcmk__new_ordering(rsc, stop_key(rsc), stop,
                               NULL, NULL, action,
                               pe_order_implies_then|pe_order_runnable_left,
                               rsc->cluster);
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
recurring_op_for_inactive(pe_resource_t *rsc, const pe_node_t *node,
                          const xmlNode *op)
{
    char *key = NULL;
    const char *name = NULL;
    const char *role = NULL;
    guint interval_ms = 0;
    GList *possible_matches = NULL;

    // We're only interested in recurring actions for the inactive role
    role = crm_element_value(op, "role");
    if ((role == NULL) || (text2role(role) != RSC_ROLE_STOPPED)) {
        return;
    }

    if (!is_recurring_history(rsc, op, &key, &interval_ms)) {
        return;
    }

    if (!pcmk_is_set(rsc->flags, pe_rsc_unique)) {
        crm_notice("Ignoring %s (recurring monitors for " RSC_ROLE_STOPPED_S
                   " role are not supported for anonymous clones)", ID(op));
        return; // @TODO add support
    }

    name = crm_element_value(op, "name");

    pe_rsc_trace(rsc, "Creating recurring action %s for %s on nodes "
                      "where it should not be running", ID(op), rsc->id);

    for (GList *iter = rsc->cluster->nodes; iter != NULL; iter = iter->next) {
        pe_node_t *stop_node = (pe_node_t *) iter->data;

        bool is_optional = true;
        pe_action_t *stopped_mon = NULL;

        // Cancel action on node where resource will be active
        if ((node != NULL)
            && pcmk__str_eq(stop_node->details->uname, node->details->uname,
                            pcmk__str_casei)) {
            cancel_if_running(rsc, node, key, name, interval_ms);
            continue;
        }

        // Recurring action on this node is optional if it's already active here
        possible_matches = find_actions_exact(rsc->actions, key, stop_node);
        is_optional = (possible_matches != NULL);
        g_list_free(possible_matches);

        pe_rsc_trace(rsc,
                     "Creating %s recurring action %s for %s (%s "
                     RSC_ROLE_STOPPED_S " on %s)",
                     (is_optional? "optional" : "mandatory"),
                     key, ID(op), rsc->id, pe__node_name(stop_node));

        stopped_mon = custom_action(rsc, strdup(key), name, stop_node,
                                    is_optional, TRUE, rsc->cluster);

        pe__add_action_expected_result(stopped_mon, CRM_EX_NOT_RUNNING);

        if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
            order_after_probes(rsc, stop_node, stopped_mon);
        }

        /* The recurring action is for the inactive role, so it shouldn't be
         * performed until the resource is inactive.
         */
        order_after_stops(rsc, stop_node, stopped_mon);

        if (!stop_node->details->online || stop_node->details->unclean) {
            pe_rsc_debug(rsc, "%s unrunnable on %s: node unavailable)",
                         stopped_mon->uuid, pe__node_name(stop_node));
            pe__clear_action_flags(stopped_mon, pe_action_runnable);
        }

        if (pcmk_is_set(stopped_mon->flags, pe_action_runnable)
            && !pcmk_is_set(stopped_mon->flags, pe_action_optional)) {
            crm_notice("Start recurring %s-interval %s for "
                       RSC_ROLE_STOPPED_S " %s on %s",
                       pcmk__readable_interval(interval_ms), stopped_mon->task,
                       rsc->id, pe__node_name(stop_node));
        }
    }
    free(key);
}

/*!
 * \internal
 * \brief Create recurring actions for a resource
 *
 * \param[in,out] rsc  Resource to create recurring actions for
 */
void
pcmk__create_recurring_actions(pe_resource_t *rsc)
{
    pe_action_t *start = NULL;

    if (pcmk_is_set(rsc->flags, pe_rsc_block)) {
        pe_rsc_trace(rsc, "Skipping recurring actions for blocked resource %s",
                     rsc->id);
        return;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_maintenance)) {
        pe_rsc_trace(rsc, "Skipping recurring actions for %s "
                          "in maintenance mode", rsc->id);
        return;
    }

    if (rsc->allocated_to == NULL) {
        // Recurring actions for active roles not needed

    } else if (rsc->allocated_to->details->maintenance) {
        pe_rsc_trace(rsc,
                     "Skipping recurring actions for %s on %s "
                     "in maintenance mode",
                     rsc->id, pe__node_name(rsc->allocated_to));

    } else if ((rsc->next_role != RSC_ROLE_STOPPED)
        || !pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        // Recurring actions for active roles needed
        start = start_action(rsc, rsc->allocated_to, TRUE);
    }

    pe_rsc_trace(rsc, "Creating any recurring actions needed for %s", rsc->id);

    for (xmlNode *op = first_named_child(rsc->ops_xml, "op");
         op != NULL; op = crm_next_same_xml(op)) {

        if (start != NULL) {
            recurring_op_for_active(rsc, start, rsc->allocated_to, op);
        }
        recurring_op_for_inactive(rsc, rsc->allocated_to, op);
    }
}

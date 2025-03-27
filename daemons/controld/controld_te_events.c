/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <libxml/xpath.h>                   // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

#include <crm/common/attrs_internal.h>
#include <crm/common/ipc_attrd_internal.h>

/*!
 * \internal
 * \brief Action numbers of outside events processed in current update diff
 *
 * This table is to be used as a set. It should be empty when the transitioner
 * begins processing a CIB update diff. It ensures that if there are multiple
 * events (for example, "_last_0" and "_last_failure_0") for the same action,
 * only one of them updates the failcount. Events that originate outside the
 * cluster can't be confirmed, since they're not in the transition graph.
 */
static GHashTable *outside_events = NULL;

/*!
 * \internal
 * \brief Empty the hash table containing action numbers of outside events
 */
void
controld_remove_all_outside_events(void)
{
    if (outside_events != NULL) {
        g_hash_table_remove_all(outside_events);
    }
}

/*!
 * \internal
 * \brief Destroy the hash table containing action numbers of outside events
 */
void
controld_destroy_outside_events_table(void)
{
    if (outside_events != NULL) {
        g_hash_table_destroy(outside_events);
        outside_events = NULL;
    }
}

/*!
 * \internal
 * \brief Add an outside event's action number to a set
 *
 * \return Standard Pacemaker return code. Specifically, \p pcmk_rc_ok if the
 *         event was not already in the set, or \p pcmk_rc_already otherwise.
 */
static int
record_outside_event(gint action_num)
{
    if (outside_events == NULL) {
        outside_events = g_hash_table_new(NULL, NULL);
    }

    if (g_hash_table_add(outside_events, GINT_TO_POINTER(action_num))) {
        return pcmk_rc_ok;
    }
    return pcmk_rc_already;
}

gboolean
fail_incompletable_actions(pcmk__graph_t *graph, const char *down_node)
{
    const char *target_uuid = NULL;
    const char *router = NULL;
    const char *router_uuid = NULL;
    xmlNode *last_action = NULL;

    GList *gIter = NULL;
    GList *gIter2 = NULL;

    if (graph == NULL || graph->complete) {
        return FALSE;
    }

    gIter = graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) gIter->data;

        if (pcmk_any_flags_set(synapse->flags, pcmk__synapse_confirmed|pcmk__synapse_failed)) {
            /* We've already been here */
            continue;
        }

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            pcmk__graph_action_t *action = (pcmk__graph_action_t *) gIter2->data;

            if ((action->type == pcmk__pseudo_graph_action)
                || pcmk_is_set(action->flags, pcmk__graph_action_confirmed)) {
                continue;
            } else if (action->type == pcmk__cluster_graph_action) {
                const char *task = pcmk__xe_get(action->xml, PCMK_XA_OPERATION);

                if (pcmk__str_eq(task, PCMK_ACTION_STONITH, pcmk__str_casei)) {
                    continue;
                }
            }

            target_uuid = pcmk__xe_get(action->xml, PCMK__META_ON_NODE_UUID);
            router = pcmk__xe_get(action->xml, PCMK__XA_ROUTER_NODE);
            if (router) {
                const pcmk__node_status_t *node =
                    pcmk__get_node(0, router, NULL,
                                   pcmk__node_search_cluster_member);

                if (node != NULL) {
                    router_uuid = node->xml_id;
                }
            }

            if (pcmk__str_eq(target_uuid, down_node, pcmk__str_casei) || pcmk__str_eq(router_uuid, down_node, pcmk__str_casei)) {
                pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
                pcmk__set_synapse_flags(synapse, pcmk__synapse_failed);
                last_action = action->xml;
                stop_te_timer(action);
                pcmk__update_graph(graph, action);

                if (pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
                    crm_notice("Action %d (%s) was pending on %s (offline)",
                               action->id,
                               pcmk__xe_get(action->xml,
                                            PCMK__XA_OPERATION_KEY),
                               down_node);
                } else {
                    crm_info("Action %d (%s) is scheduled for %s (offline)",
                             action->id,
                             pcmk__xe_get(action->xml, PCMK__XA_OPERATION_KEY),
                             down_node);
                }
            }
        }
    }

    if (last_action != NULL) {
        crm_info("Node %s shutdown resulted in un-runnable actions", down_node);
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Node failure", last_action);
        return TRUE;
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Update failure-related node attributes if warranted
 *
 * \param[in] event            XML describing operation that (maybe) failed
 * \param[in] event_node_uuid  Node that event occurred on
 * \param[in] rc               Actual operation return code
 * \param[in] target_rc        Expected operation return code
 * \param[in] do_update        If TRUE, do update regardless of operation type
 * \param[in] ignore_failures  If TRUE, update last failure but not fail count
 *
 * \return TRUE if this was not a direct nack, success or lrm status refresh
 */
static gboolean
update_failcount(const xmlNode *event, const char *event_node_uuid, int rc,
                 int target_rc, gboolean do_update, gboolean ignore_failures)
{
    guint interval_ms = 0;

    char *task = NULL;
    char *rsc_id = NULL;

    const char *value = NULL;
    const char *id = pcmk__xe_get(event, PCMK__XA_OPERATION_KEY);
    const char *on_uname = pcmk__node_name_from_uuid(event_node_uuid);
    const char *origin = pcmk__xe_get(event, PCMK_XA_CRM_DEBUG_ORIGIN);

    // Nothing needs to be done for success or status refresh
    if (rc == target_rc) {
        return FALSE;
    } else if (pcmk__str_eq(origin, "build_active_RAs", pcmk__str_casei)) {
        crm_debug("No update for %s (rc=%d) on %s: Old failure from lrm status refresh",
                  id, rc, on_uname);
        return FALSE;
    }

    /* Sanity check */
    CRM_CHECK(on_uname != NULL, return TRUE);
    CRM_CHECK(parse_op_key(id, &rsc_id, &task, &interval_ms),
              crm_err("Couldn't parse: %s", pcmk__xe_id(event)); goto bail);

    /* Decide whether update is necessary and what value to use */
    if ((interval_ms > 0)
        || pcmk__str_eq(task, PCMK_ACTION_PROMOTE, pcmk__str_none)
        || pcmk__str_eq(task, PCMK_ACTION_DEMOTE, pcmk__str_none)) {
        do_update = TRUE;

    } else if (pcmk__str_eq(task, PCMK_ACTION_START, pcmk__str_none)) {
        do_update = TRUE;
        value = pcmk__s(controld_globals.transition_graph->failed_start_offset,
                        PCMK_VALUE_INFINITY);

    } else if (pcmk__str_eq(task, PCMK_ACTION_STOP, pcmk__str_none)) {
        do_update = TRUE;
        value = pcmk__s(controld_globals.transition_graph->failed_stop_offset,
                        PCMK_VALUE_INFINITY);
    }

    if (do_update) {
        pcmk__attrd_query_pair_t *fail_pair = NULL;
        pcmk__attrd_query_pair_t *last_pair = NULL;
        char *fail_name = NULL;
        char *last_name = NULL;
        GList *attrs = NULL;

        uint32_t opts = pcmk__node_attr_none;

        char *now = pcmk__ttoa(time(NULL));

        // Fail count will be either incremented or set to infinity
        if (!pcmk_str_is_infinity(value)) {
            value = PCMK_XA_VALUE "++";
        }

        if (g_hash_table_lookup(pcmk__remote_peer_cache, event_node_uuid)) {
            opts |= pcmk__node_attr_remote;
        }

        crm_info("Updating %s for %s on %s after failed %s: rc=%d (update=%s, time=%s)",
                 (ignore_failures? "last failure" : "failcount"),
                 rsc_id, on_uname, task, rc, value, now);

        /* Update the fail count, if we're not ignoring failures */
        if (!ignore_failures) {
            fail_pair = pcmk__assert_alloc(1, sizeof(pcmk__attrd_query_pair_t));

            fail_name = pcmk__failcount_name(rsc_id, task, interval_ms);
            fail_pair->name = fail_name;
            fail_pair->value = value;
            fail_pair->node = on_uname;

            attrs = g_list_prepend(attrs, fail_pair);
        }

        /* Update the last failure time (even if we're ignoring failures,
         * so that failure can still be detected and shown, e.g. by crm_mon)
         */
        last_pair = pcmk__assert_alloc(1, sizeof(pcmk__attrd_query_pair_t));

        last_name = pcmk__lastfailure_name(rsc_id, task, interval_ms);
        last_pair->name = last_name;
        last_pair->value = now;
        last_pair->node = on_uname;

        attrs = g_list_prepend(attrs, last_pair);

        update_attrd_list(attrs, opts);

        free(fail_name);
        free(fail_pair);

        free(last_name);
        free(last_pair);
        g_list_free(attrs);

        free(now);
    }

  bail:
    free(rsc_id);
    free(task);
    return TRUE;
}

pcmk__graph_action_t *
controld_get_action(int id)
{
    for (GList *item = controld_globals.transition_graph->synapses;
         item != NULL; item = item->next) {
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) item->data;

        for (GList *item2 = synapse->actions; item2; item2 = item2->next) {
            pcmk__graph_action_t *action = (pcmk__graph_action_t *) item2->data;

            if (action->id == id) {
                return action;
            }
        }
    }
    return NULL;
}

pcmk__graph_action_t *
get_cancel_action(const char *id, const char *node)
{
    GList *gIter = NULL;
    GList *gIter2 = NULL;

    gIter = controld_globals.transition_graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) gIter->data;

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            const char *task = NULL;
            const char *target = NULL;
            pcmk__graph_action_t *action = (pcmk__graph_action_t *) gIter2->data;

            task = pcmk__xe_get(action->xml, PCMK_XA_OPERATION);
            if (!pcmk__str_eq(PCMK_ACTION_CANCEL, task, pcmk__str_casei)) {
                continue;
            }

            task = pcmk__xe_get(action->xml, PCMK__XA_OPERATION_KEY);
            if (!pcmk__str_eq(task, id, pcmk__str_casei)) {
                continue;
            }

            target = pcmk__xe_get(action->xml, PCMK__META_ON_NODE_UUID);
            if (node && !pcmk__str_eq(target, node, pcmk__str_casei)) {
                crm_trace("Wrong node %s for %s on %s", target, id, node);
                continue;
            }

            crm_trace("Found %s on %s", id, node);
            return action;
        }
    }

    return NULL;
}

bool
confirm_cancel_action(const char *id, const char *node_id)
{
    const char *op_key = NULL;
    const char *node_name = NULL;
    pcmk__graph_action_t *cancel = get_cancel_action(id, node_id);

    if (cancel == NULL) {
        return FALSE;
    }
    op_key = pcmk__xe_get(cancel->xml, PCMK__XA_OPERATION_KEY);
    node_name = pcmk__xe_get(cancel->xml, PCMK__META_ON_NODE);

    stop_te_timer(cancel);
    te_action_confirmed(cancel, controld_globals.transition_graph);

    crm_info("Cancellation of %s on %s confirmed (action %d)",
             op_key, node_name, cancel->id);
    return TRUE;
}

/* downed nodes are listed like: <downed> <node id="UUID1" /> ... </downed> */
#define XPATH_DOWNED "//" PCMK__XE_DOWNED \
                     "/" PCMK_XE_NODE "[@" PCMK_XA_ID "='%s']"

/*!
 * \brief Find a transition event that would have made a specified node down
 *
 * \param[in] target  UUID of node to match
 *
 * \return Matching event if found, NULL otherwise
 */
pcmk__graph_action_t *
match_down_event(const char *target)
{
    pcmk__graph_action_t *match = NULL;
    xmlXPathObject *xpath_ret = NULL;
    GList *gIter, *gIter2;

    char *xpath = crm_strdup_printf(XPATH_DOWNED, target);

    for (gIter = controld_globals.transition_graph->synapses;
         gIter != NULL && match == NULL;
         gIter = gIter->next) {

        for (gIter2 = ((pcmk__graph_synapse_t * ) gIter->data)->actions;
             gIter2 != NULL && match == NULL;
             gIter2 = gIter2->next) {

            match = (pcmk__graph_action_t *) gIter2->data;
            if (pcmk_is_set(match->flags, pcmk__graph_action_executed)) {
                xpath_ret = pcmk__xpath_search(match->xml->doc, xpath);
                if (pcmk__xpath_num_results(xpath_ret) == 0) {
                    match = NULL;
                }
                xmlXPathFreeObject(xpath_ret);
            } else {
                // Only actions that were actually started can match
                match = NULL;
            }
        }
    }

    free(xpath);

    if (match != NULL) {
        crm_debug("Shutdown action %d (%s) found for node %s", match->id,
                  pcmk__xe_get(match->xml, PCMK__XA_OPERATION_KEY), target);
    } else {
        crm_debug("No reason to expect node %s to be down", target);
    }
    return match;
}

void
process_graph_event(xmlNode *event, const char *event_node)
{
    int rc = -1;                // Actual result
    int target_rc = -1;         // Expected result
    int status = -1;            // Executor status
    int callid = -1;            // Executor call ID
    int transition_num = -1;    // Transition number
    int action_num = -1;        // Action number within transition
    char *update_te_uuid = NULL;
    bool ignore_failures = FALSE;
    const char *id = NULL;
    const char *desc = NULL;
    const char *magic = NULL;
    const char *uname = NULL;

    pcmk__assert(event != NULL);

/*
<lrm_rsc_op id="rsc_east-05_last_0" operation_key="rsc_east-05_monitor_0" operation="monitor" crm-debug-origin="do_update_resource" crm_feature_set="3.0.6" transition-key="9:2:7:be2e97d9-05e2-439d-863e-48f7aecab2aa" transition-magic="0:7;9:2:7:be2e97d9-05e2-439d-863e-48f7aecab2aa" call-id="17" rc-code="7" op-status="0" interval="0" last-rc-change="1355361636" exec-time="128" queue-time="0" op-digest="c81f5f40b1c9e859c992e800b1aa6972"/>
*/

    magic = pcmk__xe_get(event, PCMK__XA_TRANSITION_KEY);
    if (magic == NULL) {
        /* non-change */
        return;
    }

    pcmk__xe_get_int(event, PCMK__XA_OP_STATUS, &status);
    if (status == PCMK_EXEC_PENDING) {
        return;
    }

    id = pcmk__xe_get(event, PCMK__XA_OPERATION_KEY);
    pcmk__xe_get_int(event, PCMK__XA_RC_CODE, &rc);
    pcmk__xe_get_int(event, PCMK__XA_CALL_ID, &callid);

    rc = pcmk__effective_rc(rc);

    if (decode_transition_key(magic, &update_te_uuid, &transition_num,
                              &action_num, &target_rc) == FALSE) {
        // decode_transition_key() already logged the bad key
        crm_err("Can't process action %s result: Incompatible versions? "
                QB_XS " call-id=%d", id, callid);
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Bad event", event);
        return;
    }

    if (transition_num == -1) {
        // E.g. crm_resource --fail
        if (record_outside_event(action_num) != pcmk_rc_ok) {
            crm_debug("Outside event with transition key '%s' has already been "
                      "processed", magic);
            goto bail;
        }
        desc = "initiated outside of the cluster";
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Unexpected event", event);

    } else if ((action_num < 0)
               || !pcmk__str_eq(update_te_uuid, controld_globals.te_uuid,
                                pcmk__str_none)) {
        desc = "initiated by a different DC";
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Foreign event", event);

    } else if ((controld_globals.transition_graph->id != transition_num)
               || controld_globals.transition_graph->complete) {

        // Action is not from currently active transition

        guint interval_ms = 0;

        if (parse_op_key(id, NULL, NULL, &interval_ms)
            && (interval_ms != 0)) {
            /* Recurring actions have the transition number they were first
             * scheduled in.
             */

            if (status == PCMK_EXEC_CANCELLED) {
                confirm_cancel_action(id, get_node_id(event));
                goto bail;
            }

            desc = "arrived after initial scheduling";
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Change in recurring result", event);

        } else if (controld_globals.transition_graph->id != transition_num) {
            desc = "arrived really late";
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Old event", event);
        } else {
            desc = "arrived late";
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Inactive graph", event);
        }

    } else {
        // Event is result of an action from currently active transition
        pcmk__graph_action_t *action = controld_get_action(action_num);

        if (action == NULL) {
            // Should never happen
            desc = "unknown";
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Unknown event", event);

        } else if (pcmk_is_set(action->flags, pcmk__graph_action_confirmed)) {
            /* Nothing further needs to be done if the action has already been
             * confirmed. This can happen e.g. when processing both an
             * "xxx_last_0" or "xxx_last_failure_0" record as well as the main
             * history record, which would otherwise result in incorrectly
             * bumping the fail count twice.
             */
            crm_log_xml_debug(event, "Event already confirmed:");
            goto bail;

        } else {
            /* An action result needs to be confirmed.
             * (This is the only case where desc == NULL.)
             */

            if (pcmk__str_eq(crm_meta_value(action->params, PCMK_META_ON_FAIL),
                             PCMK_VALUE_IGNORE, pcmk__str_casei)) {
                ignore_failures = TRUE;

            } else if (rc != target_rc) {
                pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
            }

            stop_te_timer(action);
            te_action_confirmed(action, controld_globals.transition_graph);

            if (pcmk_is_set(action->flags, pcmk__graph_action_failed)) {
                abort_transition(action->synapse->priority + 1,
                                 pcmk__graph_restart, "Event failed", event);
            }
        }
    }

    if (id == NULL) {
        id = "unknown action";
    }
    uname = pcmk__xe_get(event, PCMK__META_ON_NODE);
    if (uname == NULL) {
        uname = "unknown node";
    }

    if (status == PCMK_EXEC_INVALID) {
        // We couldn't attempt the action
        crm_info("Transition %d action %d (%s on %s): %s",
                 transition_num, action_num, id, uname,
                 pcmk_exec_status_str(status));

    } else if (desc && update_failcount(event, event_node, rc, target_rc,
                                        (transition_num == -1), FALSE)) {
        crm_notice("Transition %d action %d (%s on %s): expected '%s' but got '%s' "
                   QB_XS " target-rc=%d rc=%d call-id=%d event='%s'",
                   transition_num, action_num, id, uname,
                   crm_exit_str(target_rc), crm_exit_str(rc),
                   target_rc, rc, callid, desc);

    } else if (desc) {
        crm_info("Transition %d action %d (%s on %s): %s "
                 QB_XS " rc=%d target-rc=%d call-id=%d",
                 transition_num, action_num, id, uname,
                 desc, rc, target_rc, callid);

    } else if (rc == target_rc) {
        crm_info("Transition %d action %d (%s on %s) confirmed: %s "
                 QB_XS " rc=%d call-id=%d",
                 transition_num, action_num, id, uname,
                 crm_exit_str(rc), rc, callid);

    } else {
        update_failcount(event, event_node, rc, target_rc,
                         (transition_num == -1), ignore_failures);
        crm_notice("Transition %d action %d (%s on %s): expected '%s' but got '%s' "
                   QB_XS " target-rc=%d rc=%d call-id=%d",
                   transition_num, action_num, id, uname,
                   crm_exit_str(target_rc), crm_exit_str(rc),
                   target_rc, rc, callid);
    }

  bail:
    free(update_te_uuid);
}

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

#include <pacemaker-controld.h>

char *failed_stop_offset = NULL;
char *failed_start_offset = NULL;

gboolean
fail_incompletable_actions(crm_graph_t * graph, const char *down_node)
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
        synapse_t *synapse = (synapse_t *) gIter->data;

        if (pcmk_any_flags_set(synapse->flags, pcmk__synapse_confirmed|pcmk__synapse_failed)) {
            /* We've already been here */
            continue;
        }

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            crm_action_t *action = (crm_action_t *) gIter2->data;

            if (action->type == action_type_pseudo || action->confirmed) {
                continue;
            } else if (action->type == action_type_crm) {
                const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);

                if (pcmk__str_eq(task, CRM_OP_FENCE, pcmk__str_casei)) {
                    continue;
                }
            }

            target_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
            router = crm_element_value(action->xml, XML_LRM_ATTR_ROUTER_NODE);
            if (router) {
                crm_node_t *node = crm_get_peer(0, router);
                if (node) {
                    router_uuid = node->uuid;
                }
            }

            if (pcmk__str_eq(target_uuid, down_node, pcmk__str_casei) || pcmk__str_eq(router_uuid, down_node, pcmk__str_casei)) {
                action->failed = TRUE;
                pcmk__set_synapse_flags(synapse, pcmk__synapse_failed);
                last_action = action->xml;
                stop_te_timer(action->timer);
                pcmk__update_graph(graph, action);

                if (pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
                    crm_notice("Action %d (%s) was pending on %s (offline)",
                               action->id, crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY), down_node);
                } else {
                    crm_info("Action %d (%s) is scheduled for %s (offline)",
                             action->id, crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY), down_node);
                }
            }
        }
    }

    if (last_action != NULL) {
        crm_info("Node %s shutdown resulted in un-runnable actions", down_node);
        abort_transition(INFINITY, tg_restart, "Node failure", last_action);
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
update_failcount(xmlNode * event, const char *event_node_uuid, int rc,
                 int target_rc, gboolean do_update, gboolean ignore_failures)
{
    guint interval_ms = 0;

    char *task = NULL;
    char *rsc_id = NULL;

    const char *value = NULL;
    const char *id = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    const char *on_uname = crm_peer_uname(event_node_uuid);
    const char *origin = crm_element_value(event, XML_ATTR_ORIGIN);

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
              crm_err("Couldn't parse: %s", ID(event)); goto bail);

    /* Decide whether update is necessary and what value to use */
    if ((interval_ms > 0) || pcmk__str_eq(task, CRMD_ACTION_PROMOTE, pcmk__str_casei)
        || pcmk__str_eq(task, CRMD_ACTION_DEMOTE, pcmk__str_casei)) {
        do_update = TRUE;

    } else if (pcmk__str_eq(task, CRMD_ACTION_START, pcmk__str_casei)) {
        do_update = TRUE;
        if (failed_start_offset == NULL) {
            failed_start_offset = strdup(CRM_INFINITY_S);
        }
        value = failed_start_offset;

    } else if (pcmk__str_eq(task, CRMD_ACTION_STOP, pcmk__str_casei)) {
        do_update = TRUE;
        if (failed_stop_offset == NULL) {
            failed_stop_offset = strdup(CRM_INFINITY_S);
        }
        value = failed_stop_offset;
    }

    /* Fail count will be either incremented or set to infinity */
    if (!pcmk_str_is_infinity(value)) {
        value = XML_NVPAIR_ATTR_VALUE "++";
    }

    if (do_update) {
        char *now = pcmk__ttoa(time(NULL));
        char *attr_name = NULL;
        gboolean is_remote_node = FALSE;

        if (g_hash_table_lookup(crm_remote_peer_cache, event_node_uuid)) {
            is_remote_node = TRUE;
        }

        crm_info("Updating %s for %s on %s after failed %s: rc=%d (update=%s, time=%s)",
                 (ignore_failures? "last failure" : "failcount"),
                 rsc_id, on_uname, task, rc, value, now);

        /* Update the fail count, if we're not ignoring failures */
        if (!ignore_failures) {
            attr_name = pcmk__failcount_name(rsc_id, task, interval_ms);
            update_attrd(on_uname, attr_name, value, NULL, is_remote_node);
            free(attr_name);
        }

        /* Update the last failure time (even if we're ignoring failures,
         * so that failure can still be detected and shown, e.g. by crm_mon)
         */
        attr_name = pcmk__lastfailure_name(rsc_id, task, interval_ms);
        update_attrd(on_uname, attr_name, now, NULL, is_remote_node);
        free(attr_name);

        free(now);
    }

  bail:
    free(rsc_id);
    free(task);
    return TRUE;
}

crm_action_t *
controld_get_action(int id)
{
    for (GList *item = transition_graph->synapses; item; item = item->next) {
        synapse_t *synapse = (synapse_t *) item->data;

        for (GList *item2 = synapse->actions; item2; item2 = item2->next) {
            crm_action_t *action = (crm_action_t *) item2->data;

            if (action->id == id) {
                return action;
            }
        }
    }
    return NULL;
}

crm_action_t *
get_cancel_action(const char *id, const char *node)
{
    GList *gIter = NULL;
    GList *gIter2 = NULL;

    gIter = transition_graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            const char *task = NULL;
            const char *target = NULL;
            crm_action_t *action = (crm_action_t *) gIter2->data;

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
            if (!pcmk__str_eq(CRMD_ACTION_CANCEL, task, pcmk__str_casei)) {
                continue;
            }

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
            if (!pcmk__str_eq(task, id, pcmk__str_casei)) {
                crm_trace("Wrong key %s for %s on %s", task, id, node);
                continue;
            }

            target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
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
    crm_action_t *cancel = get_cancel_action(id, node_id);

    if (cancel == NULL) {
        return FALSE;
    }
    op_key = crm_element_value(cancel->xml, XML_LRM_ATTR_TASK_KEY);
    node_name = crm_element_value(cancel->xml, XML_LRM_ATTR_TARGET);

    stop_te_timer(cancel->timer);
    te_action_confirmed(cancel, transition_graph);

    crm_info("Cancellation of %s on %s confirmed (action %d)",
             op_key, node_name, cancel->id);
    return TRUE;
}

/* downed nodes are listed like: <downed> <node id="UUID1" /> ... </downed> */
#define XPATH_DOWNED "//" XML_GRAPH_TAG_DOWNED \
                     "/" XML_CIB_TAG_NODE "[@" XML_ATTR_UUID "='%s']"

/*!
 * \brief Find a transition event that would have made a specified node down
 *
 * \param[in] target  UUID of node to match
 *
 * \return Matching event if found, NULL otherwise
 */
crm_action_t *
match_down_event(const char *target)
{
    crm_action_t *match = NULL;
    xmlXPathObjectPtr xpath_ret = NULL;
    GList *gIter, *gIter2;

    char *xpath = crm_strdup_printf(XPATH_DOWNED, target);

    for (gIter = transition_graph->synapses;
         gIter != NULL && match == NULL;
         gIter = gIter->next) {

        for (gIter2 = ((synapse_t*)gIter->data)->actions;
             gIter2 != NULL && match == NULL;
             gIter2 = gIter2->next) {

            match = (crm_action_t*)gIter2->data;
            if (match->executed) {
                xpath_ret = xpath_search(match->xml, xpath);
                if (numXpathResults(xpath_ret) < 1) {
                    match = NULL;
                }
                freeXpathObject(xpath_ret);
            } else {
                // Only actions that were actually started can match
                match = NULL;
            }
        }
    }

    free(xpath);

    if (match != NULL) {
        crm_debug("Shutdown action %d (%s) found for node %s", match->id,
                  crm_element_value(match->xml, XML_LRM_ATTR_TASK_KEY), target);
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

    CRM_ASSERT(event != NULL);

/*
<lrm_rsc_op id="rsc_east-05_last_0" operation_key="rsc_east-05_monitor_0" operation="monitor" crm-debug-origin="do_update_resource" crm_feature_set="3.0.6" transition-key="9:2:7:be2e97d9-05e2-439d-863e-48f7aecab2aa" transition-magic="0:7;9:2:7:be2e97d9-05e2-439d-863e-48f7aecab2aa" call-id="17" rc-code="7" op-status="0" interval="0" last-rc-change="1355361636" exec-time="128" queue-time="0" op-digest="c81f5f40b1c9e859c992e800b1aa6972"/>
*/

    magic = crm_element_value(event, XML_ATTR_TRANSITION_KEY);
    if (magic == NULL) {
        /* non-change */
        return;
    }

    crm_element_value_int(event, XML_LRM_ATTR_OPSTATUS, &status);
    if (status == PCMK_EXEC_PENDING) {
        return;
    }

    id = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    crm_element_value_int(event, XML_LRM_ATTR_RC, &rc);
    crm_element_value_int(event, XML_LRM_ATTR_CALLID, &callid);

    rc = pcmk__effective_rc(rc);

    if (decode_transition_key(magic, &update_te_uuid, &transition_num,
                              &action_num, &target_rc) == FALSE) {
        // decode_transition_key() already logged the bad key
        crm_err("Can't process action %s result: Incompatible versions? "
                CRM_XS " call-id=%d", id, callid);
        abort_transition(INFINITY, tg_restart, "Bad event", event);
        return;
    }

    if (transition_num == -1) {
        // E.g. crm_resource --fail
        desc = "initiated outside of the cluster";
        abort_transition(INFINITY, tg_restart, "Unexpected event", event);

    } else if ((action_num < 0) || !pcmk__str_eq(update_te_uuid, te_uuid, pcmk__str_none)) {
        desc = "initiated by a different DC";
        abort_transition(INFINITY, tg_restart, "Foreign event", event);

    } else if ((transition_graph->id != transition_num)
               || (transition_graph->complete)) {

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
            abort_transition(INFINITY, tg_restart, "Change in recurring result",
                             event);

        } else if (transition_graph->id != transition_num) {
            desc = "arrived really late";
            abort_transition(INFINITY, tg_restart, "Old event", event);
        } else {
            desc = "arrived late";
            abort_transition(INFINITY, tg_restart, "Inactive graph", event);
        }

    } else {
        // Event is result of an action from currently active transition
        crm_action_t *action = controld_get_action(action_num);

        if (action == NULL) {
            // Should never happen
            desc = "unknown";
            abort_transition(INFINITY, tg_restart, "Unknown event", event);

        } else if (action->confirmed == TRUE) {
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

            if (pcmk__str_eq(crm_meta_value(action->params, XML_OP_ATTR_ON_FAIL), "ignore", pcmk__str_casei)) {
                ignore_failures = TRUE;

            } else if (rc != target_rc) {
                action->failed = TRUE;
            }

            stop_te_timer(action->timer);
            te_action_confirmed(action, transition_graph);

            if (action->failed) {
                abort_transition(action->synapse->priority + 1, tg_restart,
                                 "Event failed", event);
            }
        }
    }

    if (id == NULL) {
        id = "unknown action";
    }
    uname = crm_element_value(event, XML_LRM_ATTR_TARGET);
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
                   CRM_XS " target-rc=%d rc=%d call-id=%d event='%s'",
                   transition_num, action_num, id, uname,
                   services_ocf_exitcode_str(target_rc),
                   services_ocf_exitcode_str(rc),
                   target_rc, rc, callid, desc);

    } else if (desc) {
        crm_info("Transition %d action %d (%s on %s): %s "
                 CRM_XS " rc=%d target-rc=%d call-id=%d",
                 transition_num, action_num, id, uname,
                 desc, rc, target_rc, callid);

    } else if (rc == target_rc) {
        crm_info("Transition %d action %d (%s on %s) confirmed: %s "
                 CRM_XS " rc=%d call-id=%d",
                 transition_num, action_num, id, uname,
                 services_ocf_exitcode_str(rc), rc, callid);

    } else {
        update_failcount(event, event_node, rc, target_rc,
                         (transition_num == -1), ignore_failures);
        crm_notice("Transition %d action %d (%s on %s): expected '%s' but got '%s' "
                   CRM_XS " target-rc=%d rc=%d call-id=%d",
                   transition_num, action_num, id, uname,
                   services_ocf_exitcode_str(target_rc),
                   services_ocf_exitcode_str(rc),
                   target_rc, rc, callid);
    }

  bail:
    free(update_te_uuid);
}

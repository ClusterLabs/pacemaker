/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>

#include <crm/common/xml.h>
#include <tengine.h>

#include <crmd_fsa.h>

char *failed_stop_offset = NULL;
char *failed_start_offset = NULL;

gboolean
fail_incompletable_actions(crm_graph_t * graph, const char *down_node)
{
    const char *target_uuid = NULL;
    const char *router = NULL;
    const char *router_uuid = NULL;
    xmlNode *last_action = NULL;

    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    if (graph == NULL || graph->complete) {
        return FALSE;
    }

    gIter = graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        if (synapse->confirmed || synapse->failed) {
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

                if (safe_str_eq(task, CRM_OP_FENCE)) {
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

            if (safe_str_eq(target_uuid, down_node) || safe_str_eq(router_uuid, down_node)) {
                action->failed = TRUE;
                synapse->failed = TRUE;
                last_action = action->xml;
                stop_te_timer(action->timer);
                update_graph(graph, action);

                if (synapse->executed) {
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
    int interval = 0;

    char *task = NULL;
    char *rsc_id = NULL;

    const char *value = NULL;
    const char *id = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    const char *on_uname = crm_peer_uname(event_node_uuid);
    const char *origin = crm_element_value(event, XML_ATTR_ORIGIN);

    /* Nothing needs to be done for success, lrm status refresh,
     * or direct nack (internal code for "busy, try again")
     */
    if ((rc == CRM_DIRECT_NACK_RC) || (rc == target_rc)) {
        return FALSE;
    } else if (safe_str_eq(origin, "build_active_RAs")) {
        crm_debug("No update for %s (rc=%d) on %s: Old failure from lrm status refresh",
                  id, rc, on_uname);
        return FALSE;
    }

    /* Sanity check */
    CRM_CHECK(on_uname != NULL, return TRUE);
    CRM_CHECK(parse_op_key(id, &rsc_id, &task, &interval),
              crm_err("Couldn't parse: %s", ID(event)); goto bail);
    CRM_CHECK(task != NULL, goto bail);
    CRM_CHECK(rsc_id != NULL, goto bail);

    /* Decide whether update is necessary and what value to use */
    if ((interval > 0) || safe_str_eq(task, CRMD_ACTION_PROMOTE)
        || safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
        do_update = TRUE;

    } else if (safe_str_eq(task, CRMD_ACTION_START)) {
        do_update = TRUE;
        if (failed_start_offset == NULL) {
            failed_start_offset = strdup(INFINITY_S);
        }
        value = failed_start_offset;

    } else if (safe_str_eq(task, CRMD_ACTION_STOP)) {
        do_update = TRUE;
        if (failed_stop_offset == NULL) {
            failed_stop_offset = strdup(INFINITY_S);
        }
        value = failed_stop_offset;
    }

    /* Fail count will be either incremented or set to infinity */
    if (value == NULL || safe_str_neq(value, INFINITY_S)) {
        value = XML_NVPAIR_ATTR_VALUE "++";
    }

    if (do_update) {
        char *now = crm_itoa(time(NULL));
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
            attr_name = crm_concat("fail-count", rsc_id, '-');
            update_attrd(on_uname, attr_name, value, NULL, is_remote_node);
            free(attr_name);
        }

        /* Update the last failure time (even if we're ignoring failures,
         * so that failure can still be detected and shown, e.g. by crm_mon)
         */
        attr_name = crm_concat("last-failure", rsc_id, '-');
        update_attrd(on_uname, attr_name, now, NULL, is_remote_node);
        free(attr_name);

        free(now);
    }

  bail:
    free(rsc_id);
    free(task);
    return TRUE;
}

/*!
 * \internal
 * \brief Return simplified operation status based on operation return code
 *
 * \param[in] action       CRM action instance of operation
 * \param[in] orig_status  Original reported operation status
 * \param[in] rc           Actual operation return code
 * \param[in] target_rc    Expected operation return code
 *
 * \return PCMK_LRM_OP_DONE if rc equals target_rc, PCMK_LRM_OP_ERROR otherwise
 *
 * \note This assumes that PCMK_LRM_OP_PENDING operations have already been
 *       filtered (otherwise they will get simplified as well).
 */
static int
status_from_rc(crm_action_t * action, int orig_status, int rc, int target_rc)
{
    if (target_rc == rc) {
        crm_trace("Target rc: == %d", rc);
        if (orig_status != PCMK_LRM_OP_DONE) {
            crm_trace("Re-mapping op status to PCMK_LRM_OP_DONE for rc=%d", rc);
        }
        return PCMK_LRM_OP_DONE;
    }

    if (rc != CRM_DIRECT_NACK_RC) {
        const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
        const char *uname = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

        crm_warn("Action %d (%s) on %s failed (target: %d vs. rc: %d): %s",
                 action->id, task, uname, target_rc, rc,
                 services_lrm_status_str(PCMK_LRM_OP_ERROR));
    }
    return PCMK_LRM_OP_ERROR;
}

/*!
 * \internal
 * \brief Confirm action and update transition graph, aborting transition on failures
 *
 * \param[in/out] action           CRM action instance of this operation
 * \param[in]     event            Event instance of this operation
 * \param[in]     orig_status      Original reported operation status
 * \param[in]     op_rc            Actual operation return code
 * \param[in]     target_rc        Expected operation return code
 * \param[in]     ignore_failures  Whether to ignore operation failures
 *
 * \note This assumes that PCMK_LRM_OP_PENDING operations have already been
 *       filtered (otherwise they may be treated as failures).
 */
static void
match_graph_event(crm_action_t *action, xmlNode *event, int op_status,
                  int op_rc, int target_rc, gboolean ignore_failures)
{
    const char *target = NULL;
    const char *this_event = NULL;
    const char *ignore_s = "";

    /* Remap operation status based on return code */
    op_status = status_from_rc(action, op_status, op_rc, target_rc);

    /* Process OP status */
    switch (op_status) {
        case PCMK_LRM_OP_DONE:
            break;
        case PCMK_LRM_OP_ERROR:
        case PCMK_LRM_OP_TIMEOUT:
        case PCMK_LRM_OP_NOTSUPPORTED:
            if (ignore_failures) {
                ignore_s = ", ignoring failure";
            } else {
                action->failed = TRUE;
            }
            break;
        case PCMK_LRM_OP_CANCELLED:
            /* do nothing?? */
            crm_err("Don't know what to do for cancelled ops yet");
            break;
        default:
            /*
             PCMK_LRM_OP_ERROR_HARD,
             PCMK_LRM_OP_ERROR_FATAL,
             PCMK_LRM_OP_NOT_INSTALLED
             */
            action->failed = TRUE;
            crm_err("Unsupported action result: %d", op_status);
    }

    /* stop this event's timer if it had one */
    stop_te_timer(action->timer);
    te_action_confirmed(action);

    update_graph(transition_graph, action);
    trigger_graph();

    if (action->failed) {
        abort_transition(action->synapse->priority + 1, tg_restart, "Event failed", event);
    }

    this_event = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    crm_info("Action %s (%d) confirmed on %s (rc=%d%s)",
             crm_str(this_event), action->id, crm_str(target), op_rc, ignore_s);
}

crm_action_t *
get_action(int id, gboolean confirmed)
{
    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    gIter = transition_graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            crm_action_t *action = (crm_action_t *) gIter2->data;

            if (action->id == id) {
                if (confirmed) {
                    stop_te_timer(action->timer);
                    te_action_confirmed(action);
                }
                return action;
            }
        }
    }

    return NULL;
}

crm_action_t *
get_cancel_action(const char *id, const char *node)
{
    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    gIter = transition_graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            const char *task = NULL;
            const char *target = NULL;
            crm_action_t *action = (crm_action_t *) gIter2->data;

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
            if (safe_str_neq(CRMD_ACTION_CANCEL, task)) {
                continue;
            }

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
            if (safe_str_neq(task, id)) {
                crm_trace("Wrong key %s for %s on %s", task, id, node);
                continue;
            }

            target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
            if (node && safe_str_neq(target, node)) {
                crm_trace("Wrong node %s for %s on %s", target, id, node);
                continue;
            }

            crm_trace("Found %s on %s", id, node);
            return action;
        }
    }

    return NULL;
}

/* downed nodes are listed like: <downed> <node id="UUID1" /> ... </downed> */
#define XPATH_DOWNED "//" XML_GRAPH_TAG_DOWNED \
                     "/" XML_CIB_TAG_NODE "[@" XML_ATTR_UUID "='%s']"

/*!
 * \brief Find a transition event that would have made a specified node down
 *
 * \param[in] target  UUID of node to match
 * \param[in] quiet   If FALSE, log a warning if no match found
 *
 * \return Matching event if found, NULL otherwise
 */
crm_action_t *
match_down_event(const char *target, bool quiet)
{
    crm_action_t *match = NULL;
    xmlXPathObjectPtr xpath_ret = NULL;
    GListPtr gIter, gIter2;

    char *xpath = crm_strdup_printf(XPATH_DOWNED, target);

    for (gIter = transition_graph->synapses;
         gIter != NULL && match == NULL;
         gIter = gIter->next) {

        for (gIter2 = ((synapse_t*)gIter->data)->actions;
             gIter2 != NULL && match == NULL;
             gIter2 = gIter2->next) {

            match = (crm_action_t*)gIter2->data;
            xpath_ret = xpath_search(match->xml, xpath);
            if (numXpathResults(xpath_ret) < 1) {
                match = NULL;
            }
            freeXpathObject(xpath_ret);
        }
    }

    free(xpath);

    if (match != NULL) {
        crm_debug("Shutdown action found for node %s: action %d (%s)",
                  target, match->id,
                  crm_element_value(match->xml, XML_LRM_ATTR_TASK_KEY));

    } else if(quiet == FALSE) {
        crm_warn("No reason to expect node %s to be down", target);
    }

    return match;
}

gboolean
process_graph_event(xmlNode * event, const char *event_node)
{
    int rc = -1;
    int status = -1;
    int callid = -1;

    int action_num = -1;
    crm_action_t *action = NULL;

    int target_rc = -1;
    int transition_num = -1;
    char *update_te_uuid = NULL;

    gboolean stop_early = FALSE;
    gboolean ignore_failures = FALSE;
    const char *id = NULL;
    const char *desc = NULL;
    const char *magic = NULL;

    CRM_ASSERT(event != NULL);

/*
<lrm_rsc_op id="rsc_east-05_last_0" operation_key="rsc_east-05_monitor_0" operation="monitor" crm-debug-origin="do_update_resource" crm_feature_set="3.0.6" transition-key="9:2:7:be2e97d9-05e2-439d-863e-48f7aecab2aa" transition-magic="0:7;9:2:7:be2e97d9-05e2-439d-863e-48f7aecab2aa" call-id="17" rc-code="7" op-status="0" interval="0" last-run="1355361636" last-rc-change="1355361636" exec-time="128" queue-time="0" op-digest="c81f5f40b1c9e859c992e800b1aa6972"/>
*/

    id = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    crm_element_value_int(event, XML_LRM_ATTR_RC, &rc);
    crm_element_value_int(event, XML_LRM_ATTR_OPSTATUS, &status);
    crm_element_value_int(event, XML_LRM_ATTR_CALLID, &callid);

    magic = crm_element_value(event, XML_ATTR_TRANSITION_KEY);
    if (magic == NULL) {
        /* non-change */
        return FALSE;
    }

    if (decode_transition_key(magic, &update_te_uuid, &transition_num,
                              &action_num, &target_rc) == FALSE) {
        crm_err("Invalid event %s.%d detected: %s", id, callid, magic);
        abort_transition(INFINITY, tg_restart, "Bad event", event);
        return FALSE;
    }

    if (status == PCMK_LRM_OP_PENDING) {
        goto bail;
    }

    if (transition_num == -1) {
        desc = "initiated outside of the cluster";
        abort_transition(INFINITY, tg_restart, "Unexpected event", event);

    } else if ((action_num < 0) || (crm_str_eq(update_te_uuid, te_uuid, TRUE) == FALSE)) {
        desc = "initiated by a different node";
        abort_transition(INFINITY, tg_restart, "Foreign event", event);
        stop_early = TRUE;      /* This could be an lrm status refresh */

    } else if (transition_graph->id != transition_num) {
        desc = "arrived really late";
        abort_transition(INFINITY, tg_restart, "Old event", event);
        stop_early = TRUE;      /* This could be an lrm status refresh */

    } else if (transition_graph->complete) {
        desc = "arrived late";
        abort_transition(INFINITY, tg_restart, "Inactive graph", event);

    } else {
        action = get_action(action_num, FALSE);

        if (action == NULL) {
            desc = "unknown";
            abort_transition(INFINITY, tg_restart, "Unknown event", event);

        } else {
            ignore_failures = safe_str_eq(
                crm_meta_value(action->params, XML_OP_ATTR_ON_FAIL), "ignore");
            match_graph_event(action, event, status, rc, target_rc, ignore_failures);
        }
    }

    if (action && (rc == target_rc)) {
        crm_trace("Processed update to %s: %s", id, magic);
    } else {
        if (update_failcount(event, event_node, rc, target_rc,
                             (transition_num == -1), ignore_failures)) {
            /* Turns out this wasn't an lrm status refresh update afterall */
            stop_early = FALSE;
            desc = "failed";
        }
        crm_info("Detected action (%d.%d) %s.%d=%s: %s", transition_num,
                 action_num, id, callid, services_ocf_exitcode_str(rc), desc);
    }

  bail:
    free(update_te_uuid);
    return stop_early;
}

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

#include <lrm/lrm_api.h>
#include <crmd_fsa.h>

char *failed_stop_offset = NULL;
char *failed_start_offset = NULL;

int match_graph_event(int action_id, xmlNode * event, const char *event_node,
                      int op_status, int op_rc, int target_rc);

gboolean
fail_incompletable_actions(crm_graph_t * graph, const char *down_node)
{
    const char *target = NULL;
    xmlNode *last_action = NULL;

    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    if (graph == NULL || graph->complete) {
        return FALSE;
    }

    gIter = graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        if (synapse->confirmed) {
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

            target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
            if (safe_str_eq(target, down_node)) {
                action->failed = TRUE;
                synapse->failed = TRUE;
                last_action = action->xml;
                stop_te_timer(action->timer);
                update_graph(graph, action);

                if (synapse->executed) {
                    crm_notice("Action %d (%s) was pending on %s (offline)",
                               action->id, ID(action->xml), down_node);
                } else {
                    crm_notice("Action %d (%s) is scheduled for %s (offline)",
                               action->id, ID(action->xml), down_node);
                }
            }
        }
    }

    if (last_action != NULL) {
        crm_warn("Node %s shutdown resulted in un-runnable actions", down_node);
        abort_transition(INFINITY, tg_restart, "Node failure", last_action);
        return TRUE;
    }

    return FALSE;
}

static gboolean
update_failcount(xmlNode * event, const char *event_node, int rc, int target_rc, gboolean do_update)
{
    int interval = 0;

    char *task = NULL;
    char *rsc_id = NULL;
    char *attr_name = NULL;

    const char *value = NULL;
    const char *id = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    const char *on_uname = get_uname(event_node);

    if (rc == 99) {
        /* this is an internal code for "we're busy, try again" */
        return FALSE;

    } else if (rc == target_rc) {
        return FALSE;
    }

    if (failed_stop_offset == NULL) {
        failed_stop_offset = crm_strdup(INFINITY_S);
    }

    if (failed_start_offset == NULL) {
        failed_start_offset = crm_strdup(INFINITY_S);
    }

    CRM_CHECK(on_uname != NULL, return TRUE);

    CRM_CHECK(parse_op_key(id, &rsc_id, &task, &interval), crm_err("Couldn't parse: %s", ID(event));
              goto bail);
    CRM_CHECK(task != NULL, goto bail);
    CRM_CHECK(rsc_id != NULL, goto bail);

    if (do_update || interval > 0) {
        do_update = TRUE;

    } else if (safe_str_eq(task, CRMD_ACTION_START)) {
        do_update = TRUE;
        value = failed_start_offset;

    } else if (safe_str_eq(task, CRMD_ACTION_STOP)) {
        do_update = TRUE;
        value = failed_stop_offset;

    } else if (safe_str_eq(task, CRMD_ACTION_STOP)) {
        do_update = TRUE;
        value = failed_stop_offset;

    } else if (safe_str_eq(task, CRMD_ACTION_PROMOTE)) {
        do_update = TRUE;

    } else if (safe_str_eq(task, CRMD_ACTION_DEMOTE)) {
        do_update = TRUE;
    }

    if (value == NULL || safe_str_neq(value, INFINITY_S)) {
        value = XML_NVPAIR_ATTR_VALUE "++";
    }

    if (do_update) {
        char *now = crm_itoa(time(NULL));

        crm_warn("Updating failcount for %s on %s after failed %s:"
                 " rc=%d (update=%s, time=%s)", rsc_id, on_uname, task, rc, value, now);

        attr_name = crm_concat("fail-count", rsc_id, '-');
        update_attrd(on_uname, attr_name, value, NULL);
        free(attr_name);

        attr_name = crm_concat("last-failure", rsc_id, '-');
        update_attrd(on_uname, attr_name, now, NULL);
        free(attr_name);

        free(now);
    }

  bail:
    free(rsc_id);
    free(task);
    return TRUE;
}

static int
status_from_rc(crm_action_t * action, int orig_status, int rc, int target_rc)
{
    int status = orig_status;

    if (target_rc == rc) {
        crm_trace("Target rc: == %d", rc);
        if (status != LRM_OP_DONE) {
            crm_trace("Re-mapping op status to" " LRM_OP_DONE for rc=%d", rc);
            status = LRM_OP_DONE;
        }

    } else {
        status = LRM_OP_ERROR;
    }

    /* 99 is the code we use for direct nack's */
    if (rc != 99 && status != LRM_OP_DONE) {
        const char *task, *uname;

        task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
        uname = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
        crm_warn("Action %d (%s) on %s failed (target: %d vs. rc: %d): %s",
                 action->id, task, uname, target_rc, rc, op_status2text(status));
    }

    return status;
}

/*
 * returns the ID of the action if a match is found
 * returns -1 if a match was not found
 * returns -2 if a match was found but the action failed (and was
 *            not allowed to)
 */
int
match_graph_event(int action_id, xmlNode * event, const char *event_node,
                  int op_status, int op_rc, int target_rc)
{
    const char *target = NULL;
    const char *allow_fail = NULL;
    const char *this_event = NULL;
    crm_action_t *action = NULL;

    action = get_action(action_id, FALSE);
    if (action == NULL) {
        return -1;
    }

    op_status = status_from_rc(action, op_status, op_rc, target_rc);
    if (op_status != LRM_OP_DONE) {
        update_failcount(event, event_node, op_rc, target_rc, FALSE);
    }

    /* Process OP status */
    switch (op_status) {
        case LRM_OP_PENDING:
            crm_debug("Ignoring pending operation");
            return action->id;
            break;
        case LRM_OP_DONE:
            break;
        case LRM_OP_ERROR:
        case LRM_OP_TIMEOUT:
        case LRM_OP_NOTSUPPORTED:
            action->failed = TRUE;
            break;
        case LRM_OP_CANCELLED:
            /* do nothing?? */
            crm_err("Dont know what to do for cancelled ops yet");
            break;
        default:
            action->failed = TRUE;
            crm_err("Unsupported action result: %d", op_status);
    }

    /* stop this event's timer if it had one */
    stop_te_timer(action->timer);
    action->confirmed = TRUE;

    update_graph(transition_graph, action);
    trigger_graph();

    if (action->failed) {
        allow_fail = crm_meta_value(action->params, XML_ATTR_TE_ALLOWFAIL);
        if (crm_is_true(allow_fail)) {
            action->failed = FALSE;
        }
    }

    if (action->failed) {
        abort_transition(action->synapse->priority + 1, tg_restart, "Event failed", event);
    }

    this_event = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    te_log_action(LOG_DEBUG, "Action %s (%d) confirmed on %s (rc=%d)",
                  crm_str(this_event), action->id, crm_str(target), op_status);

    return action->id;
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
                    action->confirmed = TRUE;
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
    const char *task = NULL;
    const char *target = NULL;

    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    gIter = transition_graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            crm_action_t *action = (crm_action_t *) gIter2->data;

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
            if (safe_str_neq(CRMD_ACTION_CANCEL, task)) {
                continue;
            }

            task = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
            if (safe_str_neq(task, id)) {
                continue;
            }

            target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
            if (safe_str_neq(target, node)) {
                continue;
            }

            return action;
        }
    }

    return NULL;
}

crm_action_t *
match_down_event(int id, const char *target, const char *filter)
{
    const char *this_action = NULL;
    const char *this_node = NULL;
    crm_action_t *match = NULL;

    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    gIter = transition_graph->synapses;
    for (; gIter != NULL; gIter = gIter->next) {
        synapse_t *synapse = (synapse_t *) gIter->data;

        /* lookup event */
        gIter2 = synapse->actions;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            crm_action_t *action = (crm_action_t *) gIter2->data;

            if (id > 0 && action->id == id) {
                match = action;
                break;
            }

            this_action = crm_element_value(action->xml, XML_LRM_ATTR_TASK);

            if (action->type != action_type_crm) {
                continue;

            } else if (safe_str_eq(this_action, CRM_OP_LRM_REFRESH)) {
                continue;

            } else if (filter != NULL && safe_str_neq(this_action, filter)) {
                continue;
            }

            this_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

            if (this_node == NULL) {
                crm_log_xml_err(action->xml, "No node uuid");
            }

            if (safe_str_neq(this_node, target)) {
                crm_debug("Action %d : Node mismatch: %s", action->id, this_node);
                continue;
            }

            match = action;
            id = action->id;
            break;
        }

        if (match != NULL) {
            /* stop this event's timer if it had one */
            break;
        }
    }

    if (match != NULL) {
        /* stop this event's timer if it had one */
        crm_debug("Match found for action %d: %s on %s", id,
                  crm_element_value(match->xml, XML_LRM_ATTR_TASK_KEY), target);

    } else if (id > 0) {
        crm_err("No match for action %d", id);

    } else {
        crm_warn("No match for shutdown action on %s", target);
    }

    return match;
}

gboolean
process_graph_event(xmlNode * event, const char *event_node)
{
    int rc = -1;
    int status = -1;

    int action = -1;
    int target_rc = -1;
    int transition_num = -1;
    char *update_te_uuid = NULL;

    gboolean stop_early = FALSE;
    gboolean passed = FALSE;
    const char *id = NULL;
    const char *magic = NULL;

    CRM_ASSERT(event != NULL);

    id = crm_element_value(event, XML_LRM_ATTR_TASK_KEY);
    magic = crm_element_value(event, XML_ATTR_TRANSITION_MAGIC);

    if (magic == NULL) {
        /* non-change */
        return FALSE;
    }

    if(decode_transition_magic(magic, &update_te_uuid, &transition_num, &action,
                               &status, &rc, &target_rc) == FALSE) {
        crm_err("Invalid event %s detected: %s", id, magic);
        abort_transition(INFINITY, tg_restart, "Bad event", event);
        return FALSE;
    }

    if (status == LRM_OP_PENDING) {
        goto bail;
    }

    if (transition_num == -1) {
        crm_err("Action %s (%s) initiated outside of a transition", id, magic);
        abort_transition(INFINITY, tg_restart, "Unexpected event", event);

    } else if (action < 0 || crm_str_eq(update_te_uuid, te_uuid, TRUE) == FALSE) {
        crm_info("Action %s/%d (%s) initiated by a different transitioner", id, action, magic);
        abort_transition(INFINITY, tg_restart, "Foreign event", event);
        stop_early = TRUE;      /* This could be an lrm status refresh */

    } else if (transition_graph->id != transition_num) {
        crm_info("Detected action %s from a different transition:"
                 " %d vs. %d", id, transition_num, transition_graph->id);
        abort_transition(INFINITY, tg_restart, "Old event", event);
        stop_early = TRUE;      /* This could be an lrm status refresh */

    } else if (transition_graph->complete) {
        crm_info("Action %s arrived after a completed transition", id);
        abort_transition(INFINITY, tg_restart, "Inactive graph", event);

    } else if (match_graph_event(action, event, event_node, status, rc, target_rc) < 0) {
        crm_err("Unknown graph action %s", id);
        abort_transition(INFINITY, tg_restart, "Unknown event", event);

    } else {
        passed = TRUE;
        crm_trace("Processed update to %s: %s", id, magic);
    }

    if (passed == FALSE) {
        if (update_failcount(event, event_node, rc, target_rc, transition_num == -1)) {
            /* Turns out this wasn't an lrm status refresh update aferall */
            stop_early = FALSE;
        }
    }

  bail:
    free(update_te_uuid);
    return stop_early;
}

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

#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>


#include <tengine.h>
#include <te_callbacks.h>
#include <crmd_fsa.h>

#include <crm/cluster.h> /* For ONLINESTATUS etc */

void te_update_confirm(const char *event, xmlNode * msg);

extern char *te_uuid;
gboolean shuttingdown = FALSE;
crm_graph_t *transition_graph;
crm_trigger_t *transition_trigger = NULL;

/* #define rsc_op_template "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_CIB_TAG_STATE"[@uname='%s']"//"XML_LRM_TAG_RSC_OP"[@id='%s]" */
#define rsc_op_template "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_LRM_TAG_RSC_OP"[@id='%s']"

static const char *
get_node_id(xmlNode * rsc_op)
{
    xmlNode *node = rsc_op;

    while (node != NULL && safe_str_neq(XML_CIB_TAG_STATE, TYPE(node))) {
        node = node->parent;
    }

    CRM_CHECK(node != NULL, return NULL);
    return ID(node);
}

static void
process_resource_updates(xmlXPathObject * xpathObj)
{
/*
    <status>
       <node_state id="node1" state=CRMD_JOINSTATE_MEMBER exp_state="active">
          <lrm>
             <lrm_resources>
        	<rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/
    int lpc = 0, max = xpathObj->nodesetval->nodeNr;

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *rsc_op = getXpathResult(xpathObj, lpc);
        const char *node = get_node_id(rsc_op);

        process_graph_event(rsc_op, node);
    }
}

void
te_update_diff(const char *event, xmlNode * msg)
{
    int rc = -1;
    const char *op = NULL;

    xmlNode *diff = NULL;
    xmlXPathObject *xpathObj = NULL;

    int diff_add_updates = 0;
    int diff_add_epoch = 0;
    int diff_add_admin_epoch = 0;

    int diff_del_updates = 0;
    int diff_del_epoch = 0;
    int diff_del_admin_epoch = 0;

    CRM_CHECK(msg != NULL, return);
    crm_element_value_int(msg, F_CIB_RC, &rc);

    if (transition_graph == NULL) {
        crm_trace("No graph");
        return;

    } else if (rc < pcmk_ok) {
        crm_trace("Filter rc=%d (%s)", rc, pcmk_strerror(rc));
        return;

    } else if (transition_graph->complete == TRUE
               && fsa_state != S_IDLE
               && fsa_state != S_TRANSITION_ENGINE && fsa_state != S_POLICY_ENGINE) {
        crm_trace("Filter state=%s, complete=%d", fsa_state2string(fsa_state),
                    transition_graph->complete);
        return;
    }

    op = crm_element_value(msg, F_CIB_OPERATION);
    diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    cib_diff_version_details(diff,
                             &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                             &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

    crm_debug("Processing diff (%s): %d.%d.%d -> %d.%d.%d (%s)", op,
              diff_del_admin_epoch, diff_del_epoch, diff_del_updates,
              diff_add_admin_epoch, diff_add_epoch, diff_add_updates, fsa_state2string(fsa_state));
    log_cib_diff(LOG_DEBUG_2, diff, op);

    if (cib_config_changed(NULL, NULL, &diff)) {
        abort_transition(INFINITY, tg_restart, "Non-status change", diff);
        goto bail;              /* configuration changed */
    }

    /* Tickets Attributes - Added/Updated */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_TICKETS);
    if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
        xmlNode *aborted = getXpathResult(xpathObj, 0);

        abort_transition(INFINITY, tg_restart, "Ticket attribute: update", aborted);
        goto bail;

    } else if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    /* Tickets Attributes - Removed */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//" XML_CIB_TAG_TICKETS);
    if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
        xmlNode *aborted = getXpathResult(xpathObj, 0);

        abort_transition(INFINITY, tg_restart, "Ticket attribute: removal", aborted);
        goto bail;

    } else if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    /* Transient Attributes - Added/Updated */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//"
                     XML_TAG_TRANSIENT_NODEATTRS "//" XML_CIB_TAG_NVPAIR);
    if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
        int lpc;

        for (lpc = 0; lpc < xpathObj->nodesetval->nodeNr; lpc++) {
            xmlNode *attr = getXpathResult(xpathObj, lpc);
            const char *name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);
            const char *value = NULL;

            if (safe_str_eq(CRM_OP_PROBED, name)) {
                value = crm_element_value(attr, XML_NVPAIR_ATTR_VALUE);
            }

            if (crm_is_true(value) == FALSE) {
                abort_transition(INFINITY, tg_restart, "Transient attribute: update", attr);
                crm_log_xml_trace(attr, "Abort");
                goto bail;
            }
        }

    } else if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    /* Transient Attributes - Removed */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//"
                     XML_TAG_TRANSIENT_NODEATTRS);
    if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
        xmlNode *aborted = getXpathResult(xpathObj, 0);

        abort_transition(INFINITY, tg_restart, "Transient attribute: removal", aborted);
        goto bail;

    } else if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    /*
     * Check for and fast-track the processing of LRM refreshes
     * In large clusters this can result in _huge_ speedups
     *
     * Unfortunately we can only do so when there are no pending actions
     * Otherwise we could miss updates we're waiting for and stall 
     *
     */
    xpathObj = NULL;
    if (transition_graph->pending == 0) {
        xpathObj =
            xpath_search(diff,
                         "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//"
                         XML_LRM_TAG_RESOURCE);
    }

    if (xpathObj) {
        int updates = xpathObj->nodesetval->nodeNr;

        if (updates > 1) {
            /* Updates by, or in response to, TE actions will never contain updates
             * for more than one resource at a time
             */
            crm_debug("Detected LRM refresh - %d resources updated: Skipping all resource events",
                     updates);
            crm_log_xml_trace(diff, "lrm-refresh");
            abort_transition(INFINITY, tg_restart, "LRM Refresh", NULL);
            goto bail;
        }
        xmlXPathFreeObject(xpathObj);
    }

    /* Process operation updates */
    xpathObj =
        xpath_search(diff,
                     "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_LRM_TAG_RSC_OP);
    if (xpathObj) {
        process_resource_updates(xpathObj);
        xmlXPathFreeObject(xpathObj);
    }

    /* Detect deleted (as opposed to replaced or added) actions - eg. crm_resource -C */
    xpathObj = xpath_search(diff, "//" XML_TAG_DIFF_REMOVED "//" XML_LRM_TAG_RSC_OP);
    if (xpathObj) {
        int lpc = 0, max = xpathObj->nodesetval->nodeNr;

        for (lpc = 0; lpc < max; lpc++) {
            int max = 0;
            const char *op_id = NULL;
            char *rsc_op_xpath = NULL;
            xmlXPathObject *op_match = NULL;
            xmlNode *match = getXpathResult(xpathObj, lpc);

            CRM_CHECK(match != NULL, continue);

            op_id = ID(match);

            max = strlen(rsc_op_template) + strlen(op_id) + 1;
            rsc_op_xpath = calloc(1, max);
            snprintf(rsc_op_xpath, max, rsc_op_template, op_id);

            op_match = xpath_search(diff, rsc_op_xpath);
            if (op_match == NULL || op_match->nodesetval->nodeNr == 0) {
                /* Prevent false positives by matching cancelations too */
                const char *node = get_node_id(match);
                crm_action_t *cancelled = get_cancel_action(op_id, node);

                if (cancelled == NULL) {
                    crm_debug("No match for deleted action %s (%s on %s)", rsc_op_xpath, op_id,
                              node);
                    abort_transition(INFINITY, tg_restart, "Resource op removal", match);
                    if (op_match) {
                        xmlXPathFreeObject(op_match);
                    }
                    free(rsc_op_xpath);
                    goto bail;

                } else {
                    crm_debug("Deleted lrm_rsc_op %s on %s was for graph event %d",
                              op_id, node, cancelled->id);
                }
            }

            if (op_match) {
                xmlXPathFreeObject(op_match);
            }
            free(rsc_op_xpath);
        }
    }

  bail:
    if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }
}

gboolean
process_te_message(xmlNode * msg, xmlNode * xml_data)
{
    const char *from = crm_element_value(msg, F_ORIG);
    const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
    const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);
    const char *ref = crm_element_value(msg, XML_ATTR_REFERENCE);
    const char *op = crm_element_value(msg, F_CRM_TASK);
    const char *type = crm_element_value(msg, F_CRM_MSG_TYPE);

    crm_trace("Processing %s (%s) message", op, ref);
    crm_log_xml_trace(msg, "ipc");

    if (op == NULL) {
        /* error */

    } else if (sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
        crm_trace("Bad sys-to %s", crm_str(sys_to));
        return FALSE;

    } else if (safe_str_eq(op, CRM_OP_INVOKE_LRM)
               && safe_str_eq(sys_from, CRM_SYSTEM_LRMD)
/* 		  && safe_str_eq(type, XML_ATTR_RESPONSE) */
        ) {
        xmlXPathObject *xpathObj = NULL;

        crm_log_xml_trace(msg, "Processing (N)ACK");
        crm_debug("Processing (N)ACK %s from %s", crm_element_value(msg, XML_ATTR_REFERENCE), from);

        xpathObj = xpath_search(xml_data, "//" XML_LRM_TAG_RSC_OP);
        if (xpathObj) {
            process_resource_updates(xpathObj);
            xmlXPathFreeObject(xpathObj);
            xpathObj = NULL;

        } else {
            crm_log_xml_err(msg, "Invalid (N)ACK");
            return FALSE;
        }

    } else {
        crm_err("Unknown command: %s::%s from %s", type, op, sys_from);
    }

    crm_trace("finished processing message");

    return TRUE;
}

GHashTable *stonith_failures = NULL;
struct st_fail_rec 
{
        int count;
};

gboolean too_many_st_failures(void) 
{
    GHashTableIter iter;
    const char *key = NULL;
    struct st_fail_rec *value = NULL;

    if(stonith_failures == NULL) {
        return FALSE;
    }

    g_hash_table_iter_init(&iter, stonith_failures);
    while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
        if(value->count > 10) {
            crm_notice("Too many failures to fence %s (%d), giving up",
                       key, value->count);
            return TRUE;
        }
    }
    return FALSE;
}


void
tengine_stonith_callback(stonith_t * stonith, stonith_callback_data_t *data)
{
    char *uuid = NULL;
    int target_rc = -1;
    int stonith_id = -1;
    int transition_id = -1;
    crm_action_t *action = NULL;
    struct st_fail_rec *rec = NULL;
    int call_id = data->call_id;
    int rc = data->rc;
    char *userdata = data->userdata;

    CRM_CHECK(userdata != NULL, return);
    crm_notice("Stonith operation %d/%s: %s (%d)", call_id, (char *)userdata,
             pcmk_strerror(rc), rc);

    if (AM_I_DC == FALSE) {
        return;
    }

    /* crm_info("call=%d, optype=%d, node_name=%s, result=%d, node_list=%s, action=%s", */
    /*       op->call_id, op->optype, op->node_name, op->op_result, */
    /*       (char *)op->node_list, op->private_data); */

    /* filter out old STONITH actions */
    CRM_CHECK(decode_transition_key(userdata, &uuid, &transition_id, &stonith_id, &target_rc),
              crm_err("Invalid event detected");
              goto bail;
        );

    if (transition_graph->complete || stonith_id < 0 || safe_str_neq(uuid, te_uuid)
        || transition_graph->id != transition_id) {
        crm_info("Ignoring STONITH action initiated outside of the current transition");
        goto bail;
    }

    /* this will mark the event complete if a match is found */
    action = get_action(stonith_id, FALSE);
    if (action == NULL) {
        crm_err("Stonith action not matched");
        goto bail;
    }

    stop_te_timer(action->timer);
    if(stonith_failures == NULL) {
        stonith_failures = g_hash_table_new_full(
            crm_str_hash, g_str_equal, g_hash_destroy_str, free);
    }

    if (rc == pcmk_ok) {
        const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
        const char *uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

        crm_debug("Stonith operation %d for %s passed", call_id, target);
        if (action->confirmed == FALSE) {
            action->confirmed = TRUE;
            send_stonith_update(action, target, uuid);
        }
        rec = g_hash_table_lookup(stonith_failures, target);
        if(rec) {
            rec->count = 0;
        }
        
    } else {
        const char *target = crm_element_value_const(action->xml, XML_LRM_ATTR_TARGET);
        const char *allow_fail = crm_meta_value(action->params, XML_ATTR_TE_ALLOWFAIL);

        action->failed = TRUE;
        if (crm_is_true(allow_fail) == FALSE) {
            crm_notice("Stonith operation %d for %s failed (%s): aborting transition.", call_id, target, pcmk_strerror(rc));
            abort_transition(INFINITY, tg_restart, "Stonith failed", NULL);
        }

        rec = g_hash_table_lookup(stonith_failures, target);
        if(rec) {
            rec->count++;
        } else {
            rec = malloc(sizeof(struct st_fail_rec));
            rec->count = 1;
            g_hash_table_insert(stonith_failures, strdup(target), rec);
        }
    }

    update_graph(transition_graph, action);
    trigger_graph();

  bail:
    free(userdata);
    free(uuid);
    return;
}

void
cib_fencing_updated(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Fencing update %d for %s: failed - %s (%d)",
                call_id, (char *)user_data, pcmk_strerror(rc), rc);
        crm_log_xml_warn(msg, "Failed update");
        abort_transition(INFINITY, tg_shutdown, "CIB update failed", NULL);

    } else {
        crm_info("Fencing update %d for %s: complete", call_id, (char *)user_data);
    }
    free(user_data);
}

void
cib_action_updated(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Update %d FAILED: %s", call_id, pcmk_strerror(rc));
    }
}

void
cib_failcount_updated(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc < pcmk_ok) {
        crm_err("Update %d FAILED: %s", call_id, pcmk_strerror(rc));
    }
}

gboolean
action_timer_callback(gpointer data)
{
    crm_action_timer_t *timer = NULL;

    CRM_CHECK(data != NULL, return FALSE);

    timer = (crm_action_timer_t *) data;
    stop_te_timer(timer);

    crm_warn("Timer popped (timeout=%d, abort_level=%d, complete=%s)",
             timer->timeout,
             transition_graph->abort_priority, transition_graph->complete ? "true" : "false");

    CRM_CHECK(timer->action != NULL, return FALSE);

    if (transition_graph->complete) {
        crm_warn("Ignoring timeout while not in transition");

    } else if (timer->reason == timeout_action_warn) {
        print_action(LOG_WARNING, "Action missed its timeout: ", timer->action);

        /* Don't check the FSA state
         *
         * We might also be in S_INTEGRATION or some other state waiting for this
         * action so we can close the transition and continue
         */

    } else {
        /* fail the action */
        gboolean send_update = TRUE;
        const char *task = crm_element_value(timer->action->xml, XML_LRM_ATTR_TASK);

        print_action(LOG_ERR, "Aborting transition, action lost: ", timer->action);

        timer->action->failed = TRUE;
        timer->action->confirmed = TRUE;
        abort_transition(INFINITY, tg_restart, "Action lost", NULL);

        update_graph(transition_graph, timer->action);
        trigger_graph();

        if (timer->action->type != action_type_rsc) {
            send_update = FALSE;
        } else if (safe_str_eq(task, "cancel")) {
            /* we dont need to update the CIB with these */
            send_update = FALSE;
        }

        if (send_update) {
            /* cib_action_update(timer->action, PCMK_LRM_OP_PENDING, PCMK_EXECRA_STATUS_UNKNOWN); */
            cib_action_update(timer->action, PCMK_LRM_OP_TIMEOUT, PCMK_EXECRA_UNKNOWN_ERROR);
        }
    }

    return FALSE;
}

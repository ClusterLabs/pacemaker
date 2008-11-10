/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <crm_internal.h>

#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <heartbeat.h>

#include <tengine.h>
#include <te_callbacks.h>
#include <crmd_fsa.h>

#include <clplumbing/Gmain_timeout.h>

void te_update_confirm(const char *event, xmlNode *msg);

extern char *te_uuid;
gboolean shuttingdown = FALSE;
crm_graph_t *transition_graph;
GTRIGSource *transition_trigger = NULL;
crm_action_timer_t *transition_timer = NULL;

/* #define rsc_op_template "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_CIB_TAG_STATE"[@uname='%s']"//"XML_LRM_TAG_RSC_OP"[@id='%s]" */
#define rsc_op_template "//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB"//"XML_LRM_TAG_RSC_OP"[@id='%s']"

static const char *get_node_id(xmlNode *rsc_op) 
{
    xmlNode *node = rsc_op;
    while(node != NULL && safe_str_neq(XML_CIB_TAG_STATE, TYPE(node))) {
	node = node->parent;
    }
    
    CRM_CHECK(node != NULL, return NULL);
    return ID(node);
}


static void process_resource_updates(xmlXPathObject *xpathObj) 
{
/*
    <status>
       <node_state id="node1" state=CRMD_STATE_ACTIVE exp_state="active">
          <lrm>
             <lrm_resources>
        	<rsc_state id="" rsc_id="rsc4" node_id="node1" rsc_state="stopped"/>
*/
    int lpc = 0, max = xpathObj->nodesetval->nodeNr;
    for(lpc = 0; lpc < max; lpc++) {
	xmlNode *rsc_op = getXpathResult(xpathObj, lpc);
	const char *node = get_node_id(rsc_op);
	process_graph_event(rsc_op, node);
    }
}

void
te_update_diff(const char *event, xmlNode *msg)
{
	int rc = -1;
	const char *op = NULL;

	xmlNode *diff = NULL;
	xmlNode *cib_top = NULL;
	xmlXPathObject *xpathObj = NULL;

	int diff_add_updates     = 0;
	int diff_add_epoch       = 0;
	int diff_add_admin_epoch = 0;

	int diff_del_updates     = 0;
	int diff_del_epoch       = 0;
	int diff_del_admin_epoch = 0;
	
	CRM_CHECK(msg != NULL, return);
	crm_element_value_int(msg, F_CIB_RC, &rc);	

	if(transition_graph == NULL) {
	    crm_debug_3("No graph");
	    return;

	} else if(rc < cib_ok) {
	    crm_debug_3("Filter rc=%d (%s)", rc, cib_error2string(rc));
	    return;

	} else if(transition_graph->complete == TRUE
		  && fsa_state != S_IDLE
		  && fsa_state != S_TRANSITION_ENGINE
		  && fsa_state != S_POLICY_ENGINE) {
	    crm_debug_2("Filter state=%s, complete=%d", fsa_state2string(fsa_state), transition_graph->complete);
	    return;
	} 	

	op = crm_element_value(msg, F_CIB_OPERATION);
	diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

	cib_diff_version_details(
		diff,
		&diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
		&diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);
	
	crm_debug("Processing diff (%s): %d.%d.%d -> %d.%d.%d (%s)", op,
		  diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
		  diff_add_admin_epoch,diff_add_epoch,diff_add_updates,
		  fsa_state2string(fsa_state));
	log_cib_diff(LOG_DEBUG_2, diff, op);

	/* Process anything that was added */
	cib_top = get_xpath_object("//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_ADDED"//"XML_TAG_CIB, diff, LOG_ERR);
	if(need_abort(cib_top)) {
	    goto bail; /* configuration changed */
	}

	/* Process anything that was removed */
	cib_top = get_xpath_object("//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_REMOVED"//"XML_TAG_CIB, diff, LOG_ERR);
	if(need_abort(cib_top)) {
	    goto bail; /* configuration changed */
	}

	/* Transient Attributes - Added/Updated */
	xpathObj = xpath_search(diff,"//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_ADDED"//"XML_TAG_TRANSIENT_NODEATTRS);
	if(xpathObj && xpathObj->nodesetval->nodeNr > 0) {
	    xmlNode *aborted = getXpathResult(xpathObj, 0);
	    abort_transition(INFINITY, tg_restart, "Transient attribute: update", aborted);
	    goto bail;
	}
	
	/* Transient Attributes - Removed */
	xpathObj = xpath_search(diff,"//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_REMOVED"//"XML_TAG_TRANSIENT_NODEATTRS);
	if(xpathObj && xpathObj->nodesetval->nodeNr > 0) {
	    xmlNode *aborted = getXpathResult(xpathObj, 0);
	    abort_transition(INFINITY, tg_restart, "Transient attribute: removal", aborted);
	    goto bail;
	}

	/* Check for node state updates... possibly from a shutdown we requested */
	xpathObj = xpath_search(diff, "//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_ADDED"//"XML_CIB_TAG_STATE);
	if(xpathObj && xpathObj->nodesetval->nodeNr > 0) {
	    int lpc = 0, max = xpathObj->nodesetval->nodeNr;
	    for(lpc = 0; lpc < max; lpc++) {
		xmlNode *node = getXpathResult(xpathObj, lpc);
		const char *event_node = crm_element_value(node, XML_ATTR_ID);
		const char *ccm_state  = crm_element_value(node, XML_CIB_ATTR_INCCM);
		const char *ha_state   = crm_element_value(node, XML_CIB_ATTR_HASTATE);
		const char *shutdown_s = crm_element_value(node, XML_CIB_ATTR_SHUTDOWN);
		const char *crmd_state = crm_element_value(node, XML_CIB_ATTR_CRMDSTATE);

		if(safe_str_eq(ccm_state, XML_BOOLEAN_FALSE)
		   || safe_str_eq(ha_state, DEADSTATUS)
		   || safe_str_eq(crmd_state, CRMD_JOINSTATE_DOWN)) {
		    crm_action_t *shutdown = NULL;
		    shutdown = match_down_event(0, event_node, NULL);
		    
		    if(shutdown != NULL) {
			update_graph(transition_graph, shutdown);
			trigger_graph();
			
		    } else {
			crm_info("Stonith/shutdown of %s not matched", event_node);
			abort_transition(INFINITY, tg_restart, "Node failure", node);
		    }			
		    fail_incompletable_actions(transition_graph, event_node);
		}
	 
		if(shutdown_s) {
		    int shutdown = crm_parse_int(shutdown_s, NULL);
		    if(shutdown > 0) {
			crm_info("Aborting on "XML_CIB_ATTR_SHUTDOWN" attribute for %s", event_node);
			abort_transition(INFINITY, tg_restart, "Shutdown request", node);
		    }
		}
	    }
	    xmlXPathFreeObject(xpathObj); xpathObj = NULL;
	}

	/*
	 * Check for and fast-track the processing of LRM refreshes
	 * In large clusters this can result in _huge_ speedups
	 */
	xpathObj = xpath_search(diff, "//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_ADDED"//"XML_LRM_TAG_RESOURCE);
	if(xpathObj && xpathObj->nodesetval->nodeNr > 0) {
	    int updates = xpathObj->nodesetval->nodeNr;
	    xmlXPathFreeObject(xpathObj); xpathObj = NULL;
	    crm_info("Detected events for %d lrm resources", updates);
	    
	    if(updates > 1) {
		/* Updates by, or in response to, TE actions will never contain updates
		 * for more than one resource at a time
		 */
		crm_info("Detected LRM refresh: Skipping all resource events");
		abort_transition(INFINITY, tg_restart, "LRM Refresh", diff);
		goto bail;
	    }
	}

	/* Process operation updates */
	xpathObj = xpath_search(diff, "//"F_CIB_UPDATE_RESULT"//"XML_TAG_DIFF_ADDED"//"XML_LRM_TAG_RSC_OP);
	if(xpathObj && xpathObj->nodesetval->nodeNr > 0) {
	    process_resource_updates(xpathObj);
	    xmlXPathFreeObject(xpathObj);
	}

	/* Detect deleted (as opposed to replaced or added) actions - eg. crm_resource -C */ 
	xpathObj = xpath_search(diff, "//"XML_TAG_DIFF_REMOVED"//"XML_LRM_TAG_RSC_OP);
	if(xpathObj) {
	    int lpc = 0, max = xpathObj->nodesetval->nodeNr;
	    
	    for(lpc = 0; lpc < max; lpc++) {
		int max = 0;
		const char *op_id = NULL;
		char *rsc_op_xpath = NULL;
		xmlXPathObject *op_match = NULL;
		xmlNode *match = getXpathResult(xpathObj, lpc);
		CRM_CHECK(match != NULL, continue);

		op_id = ID(match);

		max = strlen(rsc_op_template) + strlen(op_id) + 1;
		crm_malloc0(rsc_op_xpath, max);
		snprintf(rsc_op_xpath, max, rsc_op_template, op_id);
		
		op_match = xpath_search(diff, rsc_op_xpath);
		if(op_match && op_match->nodesetval->nodeNr > 0) {
		    /* XML deletion had a corresponding add */
		    xmlXPathFreeObject(op_match);

		} else {

		    /* Prevent false positives by matching cancelations too */
		    const char *node = get_node_id(match);
		    crm_action_t *cancelled = get_cancel_action(op_id, node);

		    if(cancelled == NULL) {
			crm_info("No match for deleted action %s (%s on %s)", rsc_op_xpath, op_id, node);
			abort_transition(INFINITY, tg_restart, "Resource op removal", match);
			goto bail;

		    } else {
			crm_debug("Deleted lrm_rsc_op %s on %s was for graph event %d",
				  op_id, node, cancelled->id);
		    }
		    
		}
		
		crm_free(rsc_op_xpath);
	    }
	}

  bail:
	if(xpathObj) {
	    xmlXPathFreeObject(xpathObj);
	}
}

gboolean
process_te_message(xmlNode *msg, xmlNode *xml_data)
{
	const char *from     = crm_element_value(msg, F_ORIG);
	const char *sys_to   = crm_element_value(msg, F_CRM_SYS_TO);
	const char *sys_from = crm_element_value(msg, F_CRM_SYS_FROM);
	const char *ref      = crm_element_value(msg, XML_ATTR_REFERENCE);
	const char *op       = crm_element_value(msg, F_CRM_TASK);
	const char *type     = crm_element_value(msg, F_CRM_MSG_TYPE);

	crm_debug_2("Processing %s (%s) message", op, ref);
	crm_log_xml(LOG_DEBUG_3, "ipc", msg);
	
	if(op == NULL){
		/* error */

	} else if(sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
		crm_debug_2("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
	} else if(safe_str_eq(op, CRM_OP_INVOKE_LRM)
		  && safe_str_eq(sys_from, CRM_SYSTEM_LRMD)
/* 		  && safe_str_eq(type, XML_ATTR_RESPONSE) */
		){
	    xmlXPathObject *xpathObj = NULL;
	    crm_log_xml(LOG_DEBUG_2, "Processing (N)ACK", msg);
	    crm_info("Processing (N)ACK %s from %s",
		     crm_element_value(msg, XML_ATTR_REFERENCE), from);
	    
	    xpathObj = xpath_search(xml_data, "//"XML_LRM_TAG_RSC_OP);
	    if(xpathObj) {
		process_resource_updates(xpathObj);
		xmlXPathFreeObject(xpathObj);
		xpathObj = NULL;
		
	    } else {
		crm_log_xml(LOG_ERR, "Invalid (N)ACK", msg);
		return FALSE;
	    }
		
	} else {
		crm_err("Unknown command: %s::%s from %s", type, op, sys_from);
	}

	crm_debug_3("finished processing message");
	
	return TRUE;
}

void
tengine_stonith_callback(stonith_ops_t * op)
{
	const char *allow_fail  = NULL;
	int target_rc = -1;
	int stonith_id = -1;
	int transition_id = -1;
	char *uuid = NULL;
	crm_action_t *stonith_action = NULL;

	if(op == NULL) {
		crm_err("Called with a NULL op!");
		return;
	}
	
	crm_info("call=%d, optype=%d, node_name=%s, result=%d, node_list=%s, action=%s",
		 op->call_id, op->optype, op->node_name, op->op_result,
		 (char *)op->node_list, op->private_data);

	/* restore the orignal transition timeout */
	stonith_op_active--;
	if(stonith_op_active == 0) {
	    crm_info("Restoring transition timeout: %d", active_timeout);
	    transition_graph->transition_timeout = active_timeout;
	}
	
	/* this will mark the event complete if a match is found */
	CRM_CHECK(op->private_data != NULL, return);

	/* filter out old STONITH actions */

	CRM_CHECK(decode_transition_key(
		      op->private_data, &uuid, &transition_id, &stonith_id, &target_rc),
		  crm_err("Invalid event detected");
		  goto bail;
		);
	
	if(transition_graph->complete
	   || stonith_id < 0
	   || safe_str_neq(uuid, te_uuid)
	   || transition_graph->id != transition_id) {
		crm_info("Ignoring STONITH action initiated outside"
			 " of the current transition");
	}

	stonith_action = get_action(stonith_id, TRUE);
	
	if(stonith_action == NULL) {
		crm_err("Stonith action not matched");
		goto bail;
	}

	switch(op->op_result) {
		case STONITH_SUCCEEDED:
			send_stonith_update(op);
			break;
		case STONITH_CANNOT:
		case STONITH_TIMEOUT:
		case STONITH_GENERIC:
			stonith_action->failed = TRUE;
			allow_fail = crm_meta_value(stonith_action->params, XML_ATTR_TE_ALLOWFAIL);

			if(FALSE == crm_is_true(allow_fail)) {
				crm_err("Stonith of %s failed (%d)..."
					" aborting transition.",
					op->node_name, op->op_result);
				abort_transition(INFINITY, tg_restart,
						 "Stonith failed", NULL);
			}
			break;
		default:
			crm_err("Unsupported action result: %d", op->op_result);
			abort_transition(INFINITY, tg_restart,
					 "Unsupport Stonith result", NULL);
	}
	
	update_graph(transition_graph, stonith_action);
	trigger_graph();

  bail:
	crm_free(uuid);
	return;
}

void
cib_fencing_updated(xmlNode *msg, int call_id, int rc,
		    xmlNode *output, void *user_data)
{
    if(rc < cib_ok) {
	crm_err("CIB update failed: %s", cib_error2string(rc));
	crm_log_xml_warn(msg, "Failed update");
    }
    crm_free(user_data);
}

void
cib_action_updated(xmlNode *msg, int call_id, int rc,
		   xmlNode *output, void *user_data)
{
	if(rc < cib_ok) {
		crm_err("Update %d FAILED: %s", call_id, cib_error2string(rc));
	}
}

void
cib_failcount_updated(xmlNode *msg, int call_id, int rc,
		      xmlNode *output, void *user_data)
{
	if(rc < cib_ok) {
		crm_err("Update %d FAILED: %s", call_id, cib_error2string(rc));
	}
}

gboolean
action_timer_callback(gpointer data)
{
	crm_action_timer_t *timer = NULL;
	
	if(data == NULL) {
		crm_err("Timer popped with no data");
		return FALSE;
	}
	
	timer = (crm_action_timer_t*)data;
	stop_te_timer(timer);

	crm_warn("Timer popped (abort_level=%d, complete=%s)",
		 transition_graph->abort_priority,
		 transition_graph->complete?"true":"false");

	CRM_CHECK(timer->action != NULL, return FALSE);

	if(transition_graph->complete) {
		crm_warn("Ignoring timeout while not in transition");
		
	} else if(timer->reason == timeout_action_warn) {
		print_action(
			LOG_WARNING,"Action missed its timeout: ", timer->action);
		
	} else {
		/* fail the action */
	    cib_action_update(timer->action, LRM_OP_TIMEOUT, EXECRA_UNKNOWN_ERROR);
	}

	return FALSE;
}


static int
unconfirmed_actions(gboolean send_updates)
{
	int unconfirmed = 0;
	const char *key = NULL;
	const char *task = NULL;
	const char *node = NULL;
	
	crm_debug_2("Unconfirmed actions...");
	slist_iter(
		synapse, synapse_t, transition_graph->synapses, lpc,

		/* lookup event */
		slist_iter(
			action, crm_action_t, synapse->actions, lpc2,
			if(action->executed == FALSE) {
				continue;
				
			} else if(action->confirmed) {
				continue;
			}
			
			unconfirmed++;
			task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
			node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
			key  = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
			
			crm_info("Action %s %d unconfirmed from %s",
				 key, action->id, node);
			if(action->type != action_type_rsc) {
				continue;
			} else if(send_updates == FALSE) {
				continue;
			} else if(safe_str_eq(task, "cancel")) {
				/* we dont need to update the CIB with these */
				continue;
			} else if(safe_str_eq(task, "stop")) {
				/* *never* update the CIB with these */
				continue;
			}
			cib_action_update(action, LRM_OP_PENDING, EXECRA_STATUS_UNKNOWN);
			);
		);
	if(unconfirmed > 0) {
	    crm_warn("Waiting on %d unconfirmed actions", unconfirmed);
	}
	return unconfirmed;
}

gboolean
global_timer_callback(gpointer data)
{
	crm_action_timer_t *timer = NULL;
	
	if(data == NULL) {
		crm_err("Timer popped with no data");
		return FALSE;
	}
	
	timer = (crm_action_timer_t*)data;
	stop_te_timer(timer);

	if(transition_graph == NULL) {
		crm_err("No current graph");
		return FALSE;
	}
	
	crm_warn("Timer popped (abort_level=%d, complete=%s)",
		 transition_graph->abort_priority,
		 transition_graph->complete?"true":"false");

	CRM_CHECK(timer->action == NULL, return FALSE);
	
	if(fsa_state != S_TRANSITION_ENGINE) {
		crm_err("Discarding transition timeout in state: %s", fsa_state2string(fsa_state));
	    
	} else if(transition_graph->complete) {
		crm_err("Ignoring timeout while not in transition");
		
	} else if(timer->reason == timeout_abort) {
		int unconfirmed = unconfirmed_actions(FALSE);
		crm_warn("Transition abort timeout reached..."
			 " marking transition complete.");

		transition_graph->complete = TRUE;
		abort_transition(INFINITY, tg_restart, "Global Timeout", NULL);

		if(unconfirmed != 0) {
			crm_warn("Writing %d unconfirmed actions to the CIB",
				 unconfirmed);
			unconfirmed_actions(TRUE);
		}
	}
	return FALSE;		
}




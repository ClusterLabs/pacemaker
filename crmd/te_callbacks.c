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
xmlNode *need_abort(xmlNode *update);

extern char *te_uuid;
gboolean shuttingdown = FALSE;
crm_graph_t *transition_graph;
GTRIGSource *transition_trigger = NULL;
crm_action_timer_t *transition_timer = NULL;


void
te_update_diff(const char *event, xmlNode *msg)
{
	int rc = -1;
	const char *op = NULL;
	const char *set_name = NULL;

	xmlNode *diff = NULL;
	xmlNode *aborted = NULL;

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
	
	set_name = "diff-added";
	if(diff != NULL) {
		xmlNode *section = NULL;
		xmlNode *change_set = find_xml_node(diff, set_name, FALSE);
		change_set = find_xml_node(change_set, XML_TAG_CIB, FALSE);

		if(change_set != NULL) {
			crm_debug_2("Checking status changes");
			section=get_object_root(XML_CIB_TAG_STATUS,change_set);
		}
		
		if(section != NULL) {
			extract_event(section);
		}
		crm_debug_2("Checking change set: %s", set_name);
		aborted = need_abort(change_set);
	}
	
	set_name = "diff-removed";
	if(diff != NULL && aborted == NULL) {
		xmlNode *attrs = NULL;
		xmlNode *status = NULL;
		xmlNode *change_set = find_xml_node(diff, set_name, FALSE);
		change_set = find_xml_node(change_set, XML_TAG_CIB, FALSE);

		crm_debug_2("Checking change set: %s", set_name);
		aborted = need_abort(change_set);		

		if(aborted == NULL && change_set != NULL) {
			status = get_object_root(XML_CIB_TAG_STATUS, change_set);
		
			xml_child_iter_filter(
				status, node_state, XML_CIB_TAG_STATE,
				
				attrs = find_xml_node(
					node_state, XML_TAG_TRANSIENT_NODEATTRS, FALSE);
				
				if(attrs != NULL) {
					crm_info("Aborting on "XML_TAG_TRANSIENT_NODEATTRS" deletions");
					abort_transition(INFINITY, tg_restart,
							 XML_TAG_TRANSIENT_NODEATTRS, attrs);
				}
				);
		}
	}
	
	if(aborted != NULL) {
		abort_transition(
			INFINITY, tg_restart, "Non-status change", aborted);
	}
	
	return;
}

gboolean
process_te_message(xmlNode *msg, xmlNode *xml_data)
{
	xmlNode *xml_obj = NULL;
	
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
		xml_obj = xml_data;
		CRM_CHECK(xml_obj != NULL,
			  crm_log_xml(LOG_ERR, "Invalid (N)ACK", msg);
			  return FALSE);
		CRM_CHECK(xml_obj != NULL,
			  crm_log_xml(LOG_ERR, "Invalid (N)ACK", msg);
			  return FALSE);
		xml_obj = get_object_root(XML_CIB_TAG_STATUS, xml_obj);

		CRM_CHECK(xml_obj != NULL,
			  crm_log_xml(LOG_ERR, "Invalid (N)ACK", msg);
			  return FALSE);

		crm_log_xml(LOG_DEBUG_2, "Processing (N)ACK", msg);
		crm_info("Processing (N)ACK %s from %s",
			  crm_element_value(msg, XML_ATTR_REFERENCE), from);
		extract_event(xml_obj);
		
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
			allow_fail = g_hash_table_lookup(
				stonith_action->params,
				crm_meta_name(XML_ATTR_TE_ALLOWFAIL));

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
tengine_stonith_connection_destroy(gpointer user_data)
{
	crm_err("Fencing daemon has left us");
	stonith_src = NULL;
	if(stonith_src == NULL) {
	    G_main_set_trigger(stonith_reconnect);
	}

	/* cbchan will be garbage at this point, arrange for it to be reset */
	set_stonithd_input_IPC_channel_NULL(); 
	return;
}

gboolean
tengine_stonith_dispatch(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;

	while(stonithd_op_result_ready()) {
		if (sender->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if(ST_FAIL == stonithd_receive_ops_result(FALSE)) {
			crm_err("stonithd_receive_ops_result() failed");
		} else {
			lpc++;
		}
	}

	crm_debug_2("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		return FALSE;
	}
	return TRUE;
}

void
cib_fencing_updated(xmlNode *msg, int call_id, int rc,
		    xmlNode *output, void *user_data)
{
    if(rc < cib_ok) {
	crm_err("CIB update failed: %s", cib_error2string(rc));
	crm_log_xml_warn(msg, "Failed update");
    } else {
	erase_status_tag(user_data, XML_CIB_TAG_LRM);
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

	crm_warn("Timer popped (abort_level=%d, complete=%s)",
		 transition_graph->abort_priority,
		 transition_graph->complete?"true":"false");

	CRM_CHECK(timer->action == NULL, return FALSE);
	
	if(transition_graph->complete) {
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




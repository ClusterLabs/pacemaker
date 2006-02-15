/* $Id: callbacks.c,v 1.64 2006/02/15 13:13:58 andrew Exp $ */
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

#include <portability.h>

#include <sys/stat.h>

#include <hb_api.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <heartbeat.h>

#include <tengine.h>
#include <te_callbacks.h>

#include <clplumbing/Gmain_timeout.h>

void te_update_confirm(const char *event, HA_Message *msg);
void te_update_diff(const char *event, HA_Message *msg);
crm_data_t *need_abort(crm_data_t *update);
void cib_fencing_updated(const HA_Message *msg, int call_id, int rc,
			 crm_data_t *output, void *user_data);

extern char *te_uuid;
gboolean shuttingdown = FALSE;
crm_graph_t *transition_graph;
GTRIGSource *transition_trigger = NULL;

void
te_update_diff(const char *event, HA_Message *msg)
{
	int rc = -1;
	const char *op = NULL;
	crm_data_t *diff = NULL;
	crm_data_t *aborted = NULL;
	const char *set_name = NULL;

	int diff_add_updates = 0;
	int diff_add_epoch  = 0;
	int diff_add_admin_epoch = 0;

	int diff_del_updates = 0;
	int diff_del_epoch  = 0;
	int diff_del_admin_epoch = 0;
	
	if(msg == NULL) {
		crm_err("NULL update");
		return;
	}		

	ha_msg_value_int(msg, F_CIB_RC, &rc);	
	op = cl_get_string(msg, F_CIB_OPERATION);

	if(rc < cib_ok) {
		crm_debug_2("Ignoring failed %s operation: %s",
			    op, cib_error2string(rc));
		return;
	} 	

	diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

	cib_diff_version_details(
		diff,
		&diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
		&diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);
	
	crm_info("Processing diff (%s): %d.%d.%d -> %d.%d.%d", op,
		  diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
		  diff_add_admin_epoch,diff_add_epoch,diff_add_updates);
	log_cib_diff(LOG_DEBUG_2, diff, op);

	set_name = "diff-added";
	if(diff != NULL && aborted == NULL) {
		crm_data_t *section = NULL;
		crm_data_t *change_set = find_xml_node(diff, set_name, FALSE);
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
		crm_data_t *change_set = find_xml_node(diff, set_name, FALSE);
		change_set = find_xml_node(change_set, XML_TAG_CIB, FALSE);

		crm_debug_2("Checking change set: %s", set_name);
		aborted = need_abort(change_set);
	}

	if(aborted != NULL) {
		abort_transition(
			INFINITY, tg_restart, "Non-status change", NULL);
	}
	
	free_xml(diff);
	return;
}



gboolean
process_te_message(HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender)
{
	crm_data_t *xml_obj = NULL;
	
	const char *sys_to   = cl_get_string(msg, F_CRM_SYS_TO);
	const char *sys_from = cl_get_string(msg, F_CRM_SYS_FROM);
	const char *ref      = cl_get_string(msg, XML_ATTR_REFERENCE);
	const char *op       = cl_get_string(msg, F_CRM_TASK);
	const char *type     = cl_get_string(msg, F_CRM_MSG_TYPE);

	crm_debug_2("Processing %s (%s) message", op, ref);
	crm_log_message(LOG_DEBUG_3, msg);
	
	if(op == NULL){
		/* error */
	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */

	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
		crm_debug_2("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
	} else if(safe_str_eq(op, CRM_OP_INVOKE_LRM)
		  && safe_str_eq(sys_from, CRM_SYSTEM_LRMD)
/* 		  && safe_str_eq(type, XML_ATTR_RESPONSE) */
		){
#if CRM_DEPRECATED_SINCE_2_0_4
		if(safe_str_eq(crm_element_name(xml_data), XML_TAG_CIB)) {
			xml_obj = xml_data;
		} else {
			xml_obj = find_xml_node(xml_data, XML_TAG_CIB, TRUE);
		}
#else
		xml_obj = xml_data;
		CRM_DEV_ASSERT(safe_str_eq(crm_element_name(xml_obj), XML_TAG_CIB));
#endif
		CRM_DEV_ASSERT(xml_obj != NULL);
		if(xml_obj != NULL) {
			xml_obj = get_object_root(XML_CIB_TAG_STATUS, xml_obj);
			CRM_DEV_ASSERT(xml_obj != NULL);
		}
		if(xml_obj != NULL) {
			crm_log_message_adv(LOG_DEBUG_2, "Processing NACK Reply", msg);
			extract_event(xml_obj);
		} else {
			crm_log_message_adv(LOG_ERR, "Invalid NACK Reply", msg);
		}
		
		
	} else if(safe_str_eq(type, XML_ATTR_RESPONSE)) {
		crm_err("Message was a response not a request.  Discarding");
		return TRUE;

	} else if(strcmp(op, CRM_OP_TRANSITION) == 0) {
		if(transition_graph->complete == FALSE) {
			crm_info("Another transition is already active");
			abort_transition(
				INFINITY,tg_restart,"Transition Active",NULL);

		}  else {
			destroy_graph(transition_graph);
			transition_graph = unpack_graph(xml_data);
			trigger_graph();
			print_graph(LOG_DEBUG, transition_graph);
		}

	} else if(strcmp(op, CRM_OP_TE_HALT) == 0) {
		abort_transition(INFINITY, tg_stop, "Peer Halt", NULL);

	} else if(strcmp(op, CRM_OP_TEABORT) == 0) {
		abort_transition(INFINITY, tg_restart, "Peer Cancelled", NULL);

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
	int stonith_id = -1;
	crm_action_t *stonith_action = NULL;
	char *op_key = NULL;
	char *call_id = NULL;

	if(op == NULL) {
		crm_err("Called with a NULL op!");
		return;
	}
	
	crm_info("call=%d, optype=%d, node_name=%s, result=%d, node_list=%s, action=%s",
		 op->call_id, op->optype, op->node_name, op->op_result,
		 (char *)op->node_list, op->private_data);

	/* this will mark the event complete if a match is found */
	CRM_DEV_ASSERT(op->private_data != NULL);

	/* filter out old STONITH actions */
	decodeNVpair(op->private_data, ';', &call_id, &op_key);
	if(op_key != NULL) {
		char *key = generate_transition_key(
			transition_graph->id, te_uuid);
		gboolean key_matched = safe_str_eq(key, op_key);
		crm_free(key);
		if(key_matched == FALSE) {
			crm_info("Ignoring old STONITH op: %s",
				 op->private_data);
			return;
		}
	}

#if 1
	stonith_id = crm_parse_int(call_id, "-1");
	if(stonith_id < 0) {
		crm_err("Stonith action not matched: %s (%s)",
			call_id, op->private_data);
		return;
	}
#endif
	
 	stonith_action = match_down_event(
		stonith_id, op->node_uuid, CRM_OP_FENCE);
	
	if(stonith_action == NULL) {
		crm_err("Stonith action not matched");
		return;
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
				stonith_action->params, XML_ATTR_TE_ALLOWFAIL);

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
	
	update_graph(transition_graph, stonith_id);
	trigger_graph();
	return;
}

void
tengine_stonith_connection_destroy(gpointer user_data)
{
#if 0
	crm_err("Fencing daemon has left us: Shutting down...NOW");
	/* shutdown properly later */
	CRM_DEV_ASSERT(FALSE/* fencing daemon died */);
#else
	crm_err("Fencing daemon has left us");
#endif
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
cib_fencing_updated(const HA_Message *msg, int call_id, int rc,
		    crm_data_t *output, void *user_data)
{
	if(rc < cib_ok) {
		crm_err("CIB update failed: %s", cib_error2string(rc));
		crm_log_xml_warn(msg, "[Failed Update]");
	}
}

void
cib_action_updated(const HA_Message *msg, int call_id, int rc,
		   crm_data_t *output, void *user_data)
{
	crm_action_t *action = user_data;
	const char *task_uuid = crm_element_value(
		action->xml, XML_LRM_ATTR_TASK_KEY);
	
	CRM_DEV_ASSERT(rc == cib_ok);
	if(rc < cib_ok) {
		crm_err("Update for action %d (%s) FAILED: %s",
			action->id, task_uuid, cib_error2string(rc));
		return;
	}
}


gboolean
timer_callback(gpointer data)
{
	te_timer_t *timer = NULL;
	
	if(data == NULL) {
		crm_err("Timer popped with no data");
		return FALSE;
	}
	
	timer = (te_timer_t*)data;
	if(timer->source_id > 0) {
		Gmain_timeout_remove(timer->source_id);
	}
	timer->source_id = 0;

	crm_warn("Timer popped in state=%d", te_fsa_state);
	if(timer->reason == timeout_abort) {
		crm_err("Transition abort timeout reached..."
			 " marking transition complete.");

		abort_transition(INFINITY, -1, "Global Timeout", NULL);
		return TRUE;
		
	} else if(te_fsa_state != s_in_transition) {
		crm_debug("Ignoring timeout while not in transition");
		return TRUE;
		
	} else if(timer->reason == timeout_timeout) {
		
		/* global timeout - abort the transition */
		crm_warn("Transition timeout reached..."
			 " marking transition complete.");
		
		crm_warn("Some actions may not have been executed.");
			
		abort_transition(INFINITY, -1, "Global Timeout", NULL);
		
		return TRUE;
		
	} else if(timer->action == NULL) {
		crm_err("Action not present!");
		return FALSE;
		
	} else if(timer->reason == timeout_action_warn) {
		print_graph_action(LOG_WARNING, "Action missed its timeout",
			     timer->action);
		return TRUE;
		
	} else {
		/* fail the action
		 * - which may or may not abort the transition
		 */

		/* TODO: send a cancel notice to the LRM */
		/* TODO: use the ack from above to update the CIB */
		return cib_action_update(timer->action, LRM_OP_TIMEOUT);
	}
}


gboolean
te_graph_trigger(gpointer user_data) 
{
	int pending_updates = 0;
	enum transition_status graph_rc = -1;

	if(transition_graph->complete) {
		notify_crmd(transition_graph);
		return TRUE;	
	}
	
	graph_rc = run_graph(transition_graph);
	stop_te_timer(transition_timer);
	print_graph(LOG_DEBUG_2, transition_graph);
	
	if(graph_rc == transition_active) {
		crm_debug_3("Transition not yet complete");
		/* restart the transition timer again */
		start_te_timer(transition_timer);
		return TRUE;	
		
	}

	pending_updates = num_cib_op_callbacks();
	CRM_DEV_ASSERT(pending_updates == 0);

	if(graph_rc != transition_complete) {
		crm_crit("Transition failed: %s", transition_status(graph_rc));
	}

	notify_crmd(transition_graph);

	return TRUE;	
}



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
crm_action_timer_t *transition_timer = NULL;

static gboolean
start_global_timer(crm_action_timer_t *timer, int timeout)
{
	CRM_ASSERT(timer != NULL);
	CRM_CHECK(timer > 0, return FALSE);
	CRM_CHECK(timer->source_id == 0, return FALSE);

	if(timeout <= 0) {
		crm_err("Tried to start timer with period: %d", timeout);

	} else if(timer->source_id == 0) {
		crm_debug_2("Starting abort timer: %dms", timeout);
		timer->timeout = timeout;
		timer->source_id = Gmain_timeout_add(
			timeout, global_timer_callback, (void*)timer);
		CRM_ASSERT(timer->source_id != 0);
		return TRUE;

	} else {
		crm_err("Timer is already active with period: %d", timer->timeout);
	}
	
	return FALSE;		
}

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
	
	crm_debug("Processing diff (%s): %d.%d.%d -> %d.%d.%d", op,
		  diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
		  diff_add_admin_epoch,diff_add_epoch,diff_add_updates);
	log_cib_diff(LOG_DEBUG_2, diff, op);

	set_name = "diff-added";
	if(diff != NULL) {
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
		crm_data_t *attrs = NULL;
		crm_data_t *status = NULL;
		crm_data_t *change_set = find_xml_node(diff, set_name, FALSE);
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
			INFINITY, tg_restart, "Non-status change", NULL);
	}
	
	free_xml(diff);
	return;
}



gboolean
process_te_message(HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender)
{
	crm_data_t *xml_obj = NULL;
	
	const char *from     = cl_get_string(msg, F_ORIG);
	const char *sys_to   = cl_get_string(msg, F_CRM_SYS_TO);
	const char *sys_from = cl_get_string(msg, F_CRM_SYS_FROM);
	const char *ref      = cl_get_string(msg, XML_ATTR_REFERENCE);
	const char *op       = cl_get_string(msg, F_CRM_TASK);
	const char *type     = cl_get_string(msg, F_CRM_MSG_TYPE);

	crm_debug_2("Processing %s (%s) message", op, ref);
	crm_log_message(LOG_DEBUG_3, msg);
	
	if(op == NULL){
		/* error */
	} else if(strcasecmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */

	} else if(sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
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
		CRM_CHECK(xml_obj != NULL,
			  crm_log_message_adv(LOG_ERR, "Invalid (N)ACK", msg);
			  return FALSE);
#endif
		CRM_CHECK(xml_obj != NULL,
			  crm_log_message_adv(LOG_ERR, "Invalid (N)ACK", msg);
			  return FALSE);
		xml_obj = get_object_root(XML_CIB_TAG_STATUS, xml_obj);

		CRM_CHECK(xml_obj != NULL,
			  crm_log_message_adv(LOG_ERR, "Invalid (N)ACK", msg);
			  return FALSE);

		crm_log_message_adv(LOG_DEBUG_2, "Processing (N)ACK", msg);
		crm_info("Processing (N)ACK %s from %s",
			  cl_get_string(msg, XML_ATTR_REFERENCE), from);
		extract_event(xml_obj);
		
	} else if(safe_str_eq(type, XML_ATTR_RESPONSE)) {
		crm_err("Message was a response not a request.  Discarding");
		return TRUE;

	} else if(strcasecmp(op, CRM_OP_TRANSITION) == 0) {
		const char *graph_file = cl_get_string(msg, F_CRM_TGRAPH);
 		const char *graph_input = cl_get_string(msg, F_CRM_TGRAPH_INPUT);
		CRM_CHECK(graph_file != NULL || xml_data != NULL,
			  crm_err("No graph provided");
			  crm_log_message(LOG_WARNING, msg);
			  return TRUE);

		if(transition_graph->complete == FALSE) {
			crm_info("Another transition is already active");
			abort_transition(
				INFINITY, tg_restart, "Transition Active", NULL);

		}  else {
			crm_data_t *graph_data = xml_data;
			crm_debug("Processing graph derived from %s", graph_input);

			if(graph_file != NULL) {
				FILE *graph_fd = fopen(graph_file, "r");

				CRM_CHECK(graph_fd != NULL,
					  cl_perror("Could not open graph file %s", graph_file);
					  return TRUE);

				graph_data = file2xml(graph_fd, FALSE);

				unlink(graph_file);
				fclose(graph_fd);
			}

			destroy_graph(transition_graph);
			transition_graph = unpack_graph(graph_data);				
			start_global_timer(transition_timer,
					   transition_graph->transition_timeout);

			trigger_graph();
			print_graph(LOG_DEBUG_2, transition_graph);

			if(graph_data != xml_data) {
			    free_xml(graph_data);
			}
		}
		
	} else if(strcasecmp(op, CRM_OP_TE_HALT) == 0) {
		abort_transition(INFINITY, tg_stop, "Peer Halt", NULL);

	} else if(strcasecmp(op, CRM_OP_TEABORT) == 0) {
		abort_transition(INFINITY, tg_restart, "Peer Cancelled", NULL);

	} else {
		crm_err("Unknown command: %s::%s from %s", type, op, sys_from);
	}

	crm_debug_3("finished processing message");
	
	return TRUE;
}

#if SUPPORT_HEARTBEAT
void
tengine_stonith_callback(stonith_ops_t * op)
{
	const char *allow_fail  = NULL;
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
			  op->private_data, &uuid, &transition_id, &stonith_id),
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
#endif

void
cib_fencing_updated(const HA_Message *msg, int call_id, int rc,
		    crm_data_t *output, void *user_data)
{
	trigger_graph();

	if(rc < cib_ok) {
		crm_err("CIB update failed: %s", cib_error2string(rc));
		crm_log_xml_warn(msg, "[Failed Update]");
	}
}

void
cib_action_updated(const HA_Message *msg, int call_id, int rc,
		   crm_data_t *output, void *user_data)
{
	trigger_graph();

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
			LOG_WARNING,"Action missed its timeout", timer->action);
		
	} else {
		/* fail the action */
		cib_action_update(timer->action, LRM_OP_TIMEOUT);
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
			cib_action_update(action, LRM_OP_PENDING);
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

gboolean
te_graph_trigger(gpointer user_data) 
{
	int timeout = 0;
	enum transition_status graph_rc = -1;

	if(transition_graph->complete) {
		notify_crmd(transition_graph);
		return TRUE;
	}

	graph_rc = run_graph(transition_graph);
	timeout = transition_graph->transition_timeout;
	print_graph(LOG_DEBUG_3, transition_graph);

	if(graph_rc == transition_active) {
		crm_debug_3("Transition not yet complete");
		stop_te_timer(transition_timer);
		start_global_timer(transition_timer, timeout);
		return TRUE;		

	} else if(graph_rc == transition_pending) {
		crm_debug_3("Transition not yet complete - no actions fired");
		return TRUE;		
	}
	
	if(graph_rc != transition_complete) {
		crm_err("Transition failed: %s", transition_status(graph_rc));
		print_graph(LOG_WARNING, transition_graph);
	}
	
	transition_graph->complete = TRUE;
	notify_crmd(transition_graph);

	return TRUE;	
}



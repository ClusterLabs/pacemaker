/* $Id: callbacks.c,v 1.53 2005/10/31 08:53:04 andrew Exp $ */
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

void te_update_confirm(const char *event, HA_Message *msg);
void te_update_diff(const char *event, HA_Message *msg);
crm_data_t *need_abort(crm_data_t *update);
void cib_fencing_updated(const HA_Message *msg, int call_id, int rc,
			 crm_data_t *output, void *user_data);

extern char *te_uuid;
extern int transition_counter;

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
	if(diff != NULL && aborted == NULL) {
		crm_data_t *section = NULL;
		crm_data_t *change_set = find_xml_node(diff, set_name, FALSE);
		change_set = find_xml_node(change_set, XML_TAG_CIB, FALSE);

		if(change_set != NULL) {
			crm_debug_2("Checking status changes");
			section=get_object_root(XML_CIB_TAG_STATUS,change_set);
		}
		if(section != NULL && extract_event(section) == FALSE) {
			send_complete("Unexpected status update",
				      section, te_update, i_cancel);
			free_xml(diff);
			return;
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
		send_complete("Non-status change", diff, te_update, i_cancel);
		free_xml(diff);
		return;
	}
	
	free_xml(diff);
	return;
}

crm_data_t *
need_abort(crm_data_t *update)
{
	crm_data_t *section_xml = NULL;
	const char *section = NULL;

	if(update == NULL) {
		return NULL;
	}
	
	section = XML_CIB_TAG_NODES;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, NULL,
		       return section_xml;
		);

	section = XML_CIB_TAG_RESOURCES;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, NULL,
		       return section_xml;
		);

	section = XML_CIB_TAG_CONSTRAINTS;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, NULL,
		       return section_xml;
		);

	section = XML_CIB_TAG_CRMCONFIG;
	section_xml = get_object_root(section, update);
	xml_child_iter(section_xml, child, NULL,
		       return section_xml;
		);
	return NULL;
}


void
te_update_confirm(const char *event, HA_Message *msg)
{
	int rc = -1;
	gboolean done = FALSE;
	const char *op = cl_get_string(msg, F_CIB_OPERATION);
	const char *type = cl_get_string(msg, F_CIB_OBJTYPE);
	crm_data_t *update = get_message_xml(msg, F_CIB_UPDATE);

	ha_msg_value_int(msg, F_CIB_RC, &rc);
	crm_debug("Processing %s...", event);
	crm_log_xml_debug_2(update, "Processing update");
	
	if(op == NULL) {
		crm_err("Illegal CIB update, the operation must be specified");
		send_complete("Illegal update", update, te_update, i_cancel);
		done = TRUE;
		
	} else if(te_fsa_state == s_abort_pending) {
		/* take no further actions if an abort is pending */
		crm_debug("Ignoring CIB update while waiting for an abort");
		done = TRUE;
		
	} else if(strcmp(op, CIB_OP_ERASE) == 0) {
		/* these are always unexpected, trigger the PE */
		crm_err("Need to trigger an election here so that"
			" the current state of all nodes is obtained");
		send_complete("Erase event", update, te_update, i_cancel);
		done = TRUE;

	} else if(strcmp(op, CIB_OP_CREATE) == 0
		  || strcmp(op, CIB_OP_DELETE) == 0
		  || strcmp(op, CIB_OP_REPLACE) == 0
		  || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
		
		/* these are always unexpected, trigger the PE */
		send_complete("Non-update change", update, te_update, i_cancel);
		done = TRUE;
		
	} else if(strcmp(op, CIB_OP_UPDATE) != 0) {
		crm_debug_2("Ignoring %s op confirmation", op);
		done = TRUE;
	}

	if(done) {
		free_xml(update);
		return;
	}
	
	if(safe_str_eq(type, XML_CIB_TAG_CRMCONFIG)) {
		/* ignore - for the moment */
		crm_debug("Ignoring changes to the %s section", type);
		
	} else if(safe_str_eq(type, XML_CIB_TAG_NODES)) {
		/* ignore new nodes until they sign up */
		crm_debug("Ignoring changes to the %s section", type);

	} else if(safe_str_eq(type, XML_CIB_TAG_STATUS)) {
		/* this _may_ not be un-expected */
		if(extract_event(update) == FALSE) {
			send_complete("Unexpected status update",
				      update, te_update, i_cancel);
		}

	} else if(safe_str_eq(type, XML_CIB_TAG_NODES)
		|| safe_str_eq(type, XML_CIB_TAG_RESOURCES)
		|| safe_str_eq(type, XML_CIB_TAG_CONSTRAINTS)) {
		/* these are never expected	 */
		crm_debug("Aborting on changes to the %s section", type);
		send_complete("Non-status update", update, te_update, i_cancel);

	} else if(safe_str_eq(type, XML_TAG_CIB)) {
		crm_data_t *section_xml = NULL;
		const char *section = NULL;
		gboolean abort = FALSE;

		section = XML_CIB_TAG_NODES;
		if(abort == FALSE) {
			section_xml = get_object_root(section, update);
			xml_child_iter(section_xml, child, NULL,
				       abort = TRUE;
				       break;
				);
		}
		section = XML_CIB_TAG_RESOURCES;
		if(abort == FALSE) {
			section_xml = get_object_root(section, update);
			xml_child_iter(section_xml, child, NULL,
				       abort = TRUE;
				       break;
				);
		}
		section = XML_CIB_TAG_CONSTRAINTS;
		if(abort == FALSE) {
			section_xml = get_object_root(section, update);
			xml_child_iter(section_xml, child, NULL,
				       abort = TRUE;
				       break;
				);
		}
		section = XML_CIB_TAG_CRMCONFIG;
		if(abort == FALSE) {
			section_xml = get_object_root(section, update);
			xml_child_iter(section_xml, child, NULL,
				       abort = TRUE;
				       break;
				);
		}
		if(abort) {
			send_complete("Non-status update", update,
				      te_update, i_cancel);
		} 

		section = XML_CIB_TAG_STATUS;
		if(abort == FALSE) {
			section_xml = get_object_root(section, update);
			if(extract_event(section_xml) == FALSE) {
				send_complete("Unexpected global status update",
					      section_xml, te_update, i_cancel);
			}
		}
		
	} else {
		crm_err("Ignoring update confirmation for %s object", type);
		crm_log_xml_debug(update, "Ignored update");
	}

	free_xml(update);
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

	crm_log_message(LOG_DEBUG_3, msg);
	crm_debug("Processing %s (%s) message", op, ref);
	
	if(op == NULL){
		/* error */
	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */

	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_TENGINE) != 0) {
		crm_debug_2("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
#ifdef TESTING
	} else if(strcmp(op, CRM_OP_EVENTCC) == 0) {
		crm_debug_4("Processing %s...", op);
		xml_obj = find_xml_node(xml_data, XML_TAG_CIB, TRUE);
		CRM_DEV_ASSERT(xml_obj != NULL);
		if(xml_obj != NULL) {
			xml_obj = get_object_root(XML_CIB_TAG_STATUS, xml_obj);
			CRM_DEV_ASSERT(xml_obj != NULL);
		}
		if(xml_obj != NULL) {
			crm_log_message_adv(LOG_DEBUG, "Processing Loopbacked Action", msg);
			extract_event(xml_obj);
		} else {
			crm_log_message_adv(LOG_ERR, "Invalid Loopbacked Action", msg);
		}
#endif 

	} else if(safe_str_eq(op, CRM_OP_INVOKE_LRM)
		  && safe_str_eq(sys_from, CRM_SYSTEM_LRMD)
/* 		  && safe_str_eq(type, XML_ATTR_RESPONSE) */
		){
		xml_obj = find_xml_node(xml_data, XML_TAG_CIB, TRUE);
		CRM_DEV_ASSERT(xml_obj != NULL);
		if(xml_obj != NULL) {
			xml_obj = get_object_root(XML_CIB_TAG_STATUS, xml_obj);
			CRM_DEV_ASSERT(xml_obj != NULL);
		}
		if(xml_obj != NULL) {
			crm_log_message_adv(LOG_DEBUG, "Processing NACK Reply", msg);
			extract_event(xml_obj);
		} else {
			crm_log_message_adv(LOG_ERR, "Invalid NACK Reply", msg);
		}
		
		
	} else if(safe_str_eq(type, XML_ATTR_RESPONSE)) {
		crm_info("Message was a response not a request.  Discarding");
		return TRUE;

	} else if(strcmp(op, CRM_OP_TRANSITION) == 0) {
		if(te_fsa_state != s_idle) {
			crm_debug("Attempt to start another transition");
			send_complete("Attempt to start another transition",
				      NULL, te_abort, i_cancel);

		} else {
			te_fsa_state = te_state_matrix[i_transition][te_fsa_state];
			CRM_DEV_ASSERT(te_fsa_state == s_in_transition);
			initialize_graph();
			unpack_graph(xml_data);
			
			crm_debug("Initiating transition...");
			if(initiate_transition() == FALSE) {
				/* nothing to be done.. means we're done. */
				crm_info("No actions to be taken..."
					 " transition compelte.");
			}
		}

	} else if(strcmp(op, CRM_OP_TE_HALT) == 0) {
		send_complete(CRM_OP_TE_HALT, NULL, te_halt, i_cancel);

	} else if(strcmp(op, CRM_OP_TEABORT) == 0) {
		send_complete(CRM_OP_TEABORTED, NULL, te_abort, i_cancel);

	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_info("Received quit message, terminating");
		/* wait for pending actions to complete? */
		exit(0);
		
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
	int action_id = -1;
	action_t *stonith_action = NULL;
	char *op_key = NULL;
	char *call_id = NULL;

	if(op == NULL) {
		crm_err("Called with a NULL op!");
		return;
	}
	
	crm_info("optype=%d, node_name=%s, result=%d, node_list=%s, action=%s",
		 op->optype, op->node_name, op->op_result,
		 (char *)op->node_list, op->private_data);

	/* this will mark the event complete if a match is found */
	CRM_DEV_ASSERT(op->private_data != NULL);

	/* filter out old STONITH actions */
	decodeNVpair(op->private_data, ';', &call_id, &op_key);
	if(op_key != NULL) {
		char *key = generate_transition_key(transition_counter,te_uuid);
		gboolean key_matched = safe_str_eq(key, op_key);
		crm_free(key);
		if(key_matched == FALSE) {
			crm_info("Ignoring old STONITH op: %s",
				 op->private_data);
			return;
		}
	}

#if 1
	action_id = crm_parse_int(call_id, "-1");
	if(action_id < 0) {
		crm_err("Stonith action not matched: %s (%s)",
			call_id, op->private_data);
		return;
	}
#endif
	
 	stonith_action = match_down_event(action_id,op->node_uuid,CRM_OP_FENCE);
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
				send_complete("Stonith failed",
					      stonith_action->xml,
					      te_failed, i_cancel);
			}
			break;
		default:
			crm_err("Unsupported action result: %d", op->op_result);
			send_complete("Unsupport Stonith result",
				      stonith_action->xml, te_failed, i_cancel);
	}
	
	process_trigger(action_id);
	check_for_completion();
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

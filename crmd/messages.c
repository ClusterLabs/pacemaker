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

#include <sys/param.h>
#include <crm/crm.h>
#include <string.h>
#include <time.h>
#include <crmd_fsa.h>

#include <lrm/lrm_api.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/common/cluster.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_lrm.h>


GListPtr fsa_message_queue = NULL;
extern void crm_shutdown(int nsig);

enum crmd_fsa_input handle_request(ha_msg_input_t *stored_msg);
enum crmd_fsa_input handle_response(ha_msg_input_t *stored_msg);
enum crmd_fsa_input handle_shutdown_request(HA_Message *stored_msg);

ha_msg_input_t *copy_ha_msg_input(ha_msg_input_t *orig);
gboolean ipc_queue_helper(gpointer key, gpointer value, gpointer user_data);


#ifdef MSG_LOG
#    define ROUTER_RESULT(x)	crm_debug_3("Router result: %s", x);	\
	crm_log_message_adv(LOG_MSG, "router.log", relay_message);
#else
#    define ROUTER_RESULT(x)	crm_debug_3("Router result: %s", x)
#endif
/* debug only, can wrap all it likes */
int last_data_id = 0;

void
register_fsa_error_adv(
	enum crmd_fsa_cause cause, enum crmd_fsa_input input,
	fsa_data_t *cur_data, void *new_data, const char *raised_from)
{
	/* save the current actions if any */
	if(fsa_actions != A_NOTHING) {
		register_fsa_input_adv(
			cur_data?cur_data->fsa_cause:C_FSA_INTERNAL,
			I_NULL, cur_data?cur_data->data:NULL,
			fsa_actions, TRUE, __FUNCTION__);
	}
	
	/* reset the action list */
	fsa_actions = A_NOTHING;

	/* register the error */
	register_fsa_input_adv(
		cause, input, new_data, A_NOTHING, TRUE, raised_from);
}

static gboolean last_was_vote = FALSE;

int
register_fsa_input_adv(
	enum crmd_fsa_cause cause, enum crmd_fsa_input input,
	void *data, long long with_actions,
	gboolean prepend, const char *raised_from)
{
	unsigned  old_len = g_list_length(fsa_message_queue);
	fsa_data_t *fsa_data = NULL;

	last_data_id++;
	CRM_CHECK(raised_from != NULL, raised_from = "<unknown>");
	
	crm_debug("%s %s FSA input %d (%s) (cause=%s) %s data",
		  raised_from, prepend?"prepended":"appended",last_data_id, fsa_input2string(input),
		  fsa_cause2string(cause), data?"with":"without");
	
	if(input == I_WAIT_FOR_EVENT) {
		do_fsa_stall = TRUE;
		crm_debug("Stalling the FSA pending further input: cause=%s",
			  fsa_cause2string(cause));
		if(old_len > 0) {
			crm_warn("%s stalled the FSA with pending inputs",
				raised_from);
			fsa_dump_queue(LOG_DEBUG);
		}
		if(data == NULL) {
			set_bit_inplace(fsa_actions, with_actions);
			with_actions = A_NOTHING;
			return 0;
		}
		crm_err("%s stalled the FSA with data - this may be broken",
			raised_from);
	}

	if(old_len == 0) {
		last_was_vote = FALSE;
	}
	
	if(input == I_NULL && with_actions == A_NOTHING /* && data == NULL */){
		/* no point doing anything */
		crm_err("Cannot add entry to queue: no input and no action");
		return 0;
		
	} else if(data == NULL) {
		last_was_vote = FALSE;

#if 0
	} else if(last_was_vote && cause == C_HA_MESSAGE && input == I_ROUTER) {
		const char *op = cl_get_string(
			((ha_msg_input_t*)data)->msg, F_CRM_TASK);
		if(safe_str_eq(op, CRM_OP_VOTE)) {
			/* It is always safe to treat N successive votes as
			 *    a single one
			 *
			 * If all the discarded votes are more "loosing" than
			 *    the first then the result is accurate
			 *    (win or loose).
			 *
			 * If any of the discarded votes are less "loosing" 
			 *    than the first then we will cast our vote and the
			 *    eventual winner will vote us down again (which
			 *    even in the case that N=2, is no worse than if we
			 *    had not disarded the vote).
			 */
			crm_debug_2("Vote compression: %d", old_len);
			return 0;
		}
#endif
	} else if (cause == C_HA_MESSAGE && input == I_ROUTER) {
		const char *op = cl_get_string(
			((ha_msg_input_t*)data)->msg, F_CRM_TASK);
		if(safe_str_eq(op, CRM_OP_VOTE)) {
			last_was_vote = TRUE;
			crm_debug_3("Added vote: %d", old_len);
		}

	} else {
		last_was_vote = FALSE;
	}

	crm_malloc0(fsa_data, sizeof(fsa_data_t));
	fsa_data->id        = last_data_id;
	fsa_data->fsa_input = input;
	fsa_data->fsa_cause = cause;
	fsa_data->origin    = raised_from;
	fsa_data->data      = NULL;
	fsa_data->data_type = fsa_dt_none;
	fsa_data->actions   = with_actions;

	if(with_actions != A_NOTHING) {
		crm_debug_3("Adding actions %.16llx to input", with_actions);
	}
	
	if(data != NULL) {
		switch(cause) {
			case C_FSA_INTERNAL:
			case C_CRMD_STATUS_CALLBACK:
			case C_IPC_MESSAGE:
			case C_HA_MESSAGE:
				crm_debug_3("Copying %s data from %s as a HA msg",
					  fsa_cause2string(cause),
					  raised_from);
				fsa_data->data = copy_ha_msg_input(data);
				fsa_data->data_type = fsa_dt_ha_msg;
				break;
				
			case C_LRM_OP_CALLBACK:
				crm_debug_3("Copying %s data from %s as lrm_op_t",
					  fsa_cause2string(cause),
					  raised_from);
				fsa_data->data = copy_lrm_op((lrm_op_t*)data);
				fsa_data->data_type = fsa_dt_lrm;
				break;
				
			case C_CCM_CALLBACK:
			case C_SUBSYSTEM_CONNECT:
			case C_LRM_MONITOR_CALLBACK:
			case C_TIMER_POPPED:
			case C_SHUTDOWN:
			case C_HEARTBEAT_FAILED:
			case C_HA_DISCONNECT:
			case C_ILLEGAL:
			case C_UNKNOWN:
			case C_STARTUP:
				crm_err("Copying %s data (from %s)"
					" not yet implemented",
					fsa_cause2string(cause), raised_from);
				exit(1);
				break;
		}
		crm_debug_4("%s data copied",
			  fsa_cause2string(fsa_data->fsa_cause));
	}
	
	/* make sure to free it properly later */
	if(prepend) {
		crm_debug_2("Prepending input");
		fsa_message_queue = g_list_prepend(fsa_message_queue, fsa_data);
	} else {
		fsa_message_queue = g_list_append(fsa_message_queue, fsa_data);
	}
	
	crm_debug_2("Queue len: %d", g_list_length(fsa_message_queue));

	fsa_dump_queue(LOG_DEBUG_2);
	
	if(old_len == g_list_length(fsa_message_queue)){
		crm_err("Couldnt add message to the queue");
	}

	if(fsa_source) {
		crm_debug_3("Triggering FSA: %s", __FUNCTION__);
		G_main_set_trigger(fsa_source);
	}
	return last_data_id;
}

void
fsa_dump_queue(int log_level) 
{
	if(log_level < (int)crm_log_level) {
		return;
	}
	slist_iter(
		data, fsa_data_t, fsa_message_queue, lpc,
		do_crm_log(log_level, 
			   "queue[%d(%d)]: input %s raised by %s()\t(cause=%s)",
			   lpc, data->id, fsa_input2string(data->fsa_input),
			   data->origin, fsa_cause2string(data->fsa_cause));
		);
	
}

ha_msg_input_t *
copy_ha_msg_input(ha_msg_input_t *orig) 
{
	ha_msg_input_t *input_copy = NULL;
	crm_malloc0(input_copy, sizeof(ha_msg_input_t));

	if(orig != NULL) {
		crm_debug_4("Copy msg");
		input_copy->msg = ha_msg_copy(orig->msg);
		if(orig->xml != NULL) {
			crm_debug_4("Copy xml");
			input_copy->xml = copy_xml(orig->xml);
		}
	} else {
		crm_debug_3("No message to copy");
	}
	return input_copy;
}


void
delete_fsa_input(fsa_data_t *fsa_data) 
{
	lrm_op_t *op = NULL;
	crm_data_t *foo = NULL;

	if(fsa_data == NULL) {
		return;
	}
	crm_debug_4("About to free %s data",
		  fsa_cause2string(fsa_data->fsa_cause));
	
	if(fsa_data->data != NULL) {
		switch(fsa_data->data_type) {
			case fsa_dt_ha_msg:
				delete_ha_msg_input(fsa_data->data);
				break;
				
			case fsa_dt_xml:
				foo = fsa_data->data;
				free_xml(foo);
				break;
				
			case fsa_dt_lrm:
				op = (lrm_op_t*)fsa_data->data;

				free_lrm_op(op);

				break;
				
			case fsa_dt_none:
				if(fsa_data->data != NULL) {
					crm_err("Dont know how to free %s data from %s",
						fsa_cause2string(fsa_data->fsa_cause),
						fsa_data->origin);
					exit(1);
				}
				break;
		}
		crm_debug_4("%s data freed",
			  fsa_cause2string(fsa_data->fsa_cause));
	}

	crm_free(fsa_data);
}

/* returns the next message */
fsa_data_t *
get_message(void)
{
	fsa_data_t* message = g_list_nth_data(fsa_message_queue, 0);
	fsa_message_queue = g_list_remove(fsa_message_queue, message);
	crm_debug_2("Processing input %d", message->id);
	return message;
}

/* returns the current head of the FIFO queue */
gboolean
is_message(void)
{
	return (g_list_length(fsa_message_queue) > 0);
}


void *
fsa_typed_data_adv(
	fsa_data_t *fsa_data, enum fsa_data_type a_type, const char *caller)
{
	void *ret_val = NULL;
	if(fsa_data == NULL) {
		do_crm_log(LOG_ERR, "%s: No FSA data available", caller);
		
	} else if(fsa_data->data == NULL) {
		do_crm_log(LOG_ERR, "%s: No message data available", caller);

	} else if(fsa_data->data_type != a_type) {
		do_crm_log(LOG_CRIT,  
			   "%s: Message data was the wrong type! %d vs. requested=%d."
			   "  Origin: %s", caller,
			   fsa_data->data_type, a_type, fsa_data->origin);
		CRM_ASSERT(fsa_data->data_type == a_type);
	} else {
		ret_val = fsa_data->data;
	}
	
	return ret_val;
}


/*	A_MSG_ROUTE	*/
void
do_msg_route(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     fsa_data_t *msg_data)
{
	ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
	route_message(msg_data->fsa_cause, input);
}

void
route_message(enum crmd_fsa_cause cause, ha_msg_input_t *input)
{
	enum crmd_fsa_input result = I_NULL;

	CRM_CHECK(cause == C_IPC_MESSAGE || cause == C_HA_MESSAGE, return);

	/* try passing the buck first */
	crm_debug_4("Attempting to route message");
	if(relay_message(input->msg, cause==C_IPC_MESSAGE)) {
		crm_debug_4("Message routed...");
		input->msg = NULL;
		return;
	}
	
	crm_debug_4("Message wasn't routed... try handling locally");
	
	/* calculate defer */
	result = handle_message(input);
	switch(result) {
		case I_NULL:
			crm_debug_4("Message processed");
			break;
		case I_CIB_OP:
			break;
		case I_ROUTER:
			break;
		case I_NODE_JOIN:
		case I_JOIN_REQUEST:
		case I_JOIN_RESULT:
			break;
		default:
			crm_debug_4("Defering local processing of message");
			register_fsa_input_later(cause, result, input);
			
			result = I_NULL;
			break;
	}

	if(result != I_NULL) {
		/* add to the front of the queue */
		register_fsa_input(cause, result, input);
	}
}


/*
 * This method frees msg
 */
gboolean
send_request(HA_Message *msg, char **msg_reference)
{
	gboolean was_sent = FALSE;

/*	crm_log_xml_debug_3(request, "Final request..."); */

	if(msg_reference != NULL) {
		*msg_reference = crm_strdup(
			cl_get_string(msg, XML_ATTR_REFERENCE));
	}
	
	was_sent = relay_message(msg, TRUE);

	if(was_sent == FALSE) {
		ha_msg_input_t *fsa_input = new_ha_msg_input(msg);
		register_fsa_input(C_IPC_MESSAGE, I_ROUTER, fsa_input);
		delete_ha_msg_input(fsa_input);
		crm_msg_del(msg);
	}
	
	return was_sent;
}

/* unless more processing is required, relay_message is freed */
gboolean
relay_message(HA_Message *relay_message, gboolean originated_locally)
{
	int is_for_dc	= 0;
	int is_for_dcib	= 0;
	int is_for_te	= 0;
	int is_for_crm	= 0;
	int is_for_cib	= 0;
	int is_local    = 0;
	gboolean processing_complete = FALSE;
	const char *host_to = cl_get_string(relay_message, F_CRM_HOST_TO);
	const char *sys_to  = cl_get_string(relay_message, F_CRM_SYS_TO);
	const char *sys_from= cl_get_string(relay_message, F_CRM_SYS_FROM);
	const char *type    = cl_get_string(relay_message, F_TYPE);
	const char *msg_error = NULL;

	crm_debug_3("Routing message %s",
		  cl_get_string(relay_message, XML_ATTR_REFERENCE));

	if(relay_message == NULL) {
		msg_error = "Cannot route empty message";

	} else if(safe_str_eq(CRM_OP_HELLO,
			      cl_get_string(relay_message, F_CRM_TASK))){
		/* quietly ignore */
		processing_complete = TRUE;

	} else if(safe_str_neq(type, T_CRM)) {
		msg_error = "Bad message type";

	} else if(sys_to == NULL) {
		msg_error = "Bad message destination: no subsystem";
	}

	if(msg_error != NULL) {
		processing_complete = TRUE;
		crm_err("%s", msg_error);
		crm_log_message(LOG_WARNING, relay_message);
	}

	if(processing_complete) {
		crm_msg_del(relay_message);
		return TRUE;
	}
	
	processing_complete = TRUE;
	
	is_for_dc   = (strcasecmp(CRM_SYSTEM_DC,   sys_to) == 0);
	is_for_dcib = (strcasecmp(CRM_SYSTEM_DCIB, sys_to) == 0);
	is_for_te   = (strcasecmp(CRM_SYSTEM_TENGINE, sys_to) == 0);
	is_for_cib  = (strcasecmp(CRM_SYSTEM_CIB,  sys_to) == 0);
	is_for_crm  = (strcasecmp(CRM_SYSTEM_CRMD, sys_to) == 0);
		
	is_local = 0;
	if(host_to == NULL || strlen(host_to) == 0) {
		if(is_for_dc || is_for_te) {
			is_local = 0;
				
		} else if(is_for_crm && originated_locally) {
			is_local = 0;
				
		} else {
			is_local = 1;
		}
			
	} else if(safe_str_eq(fsa_our_uname, host_to)) {
		is_local=1;
	}

	if(is_for_dc || is_for_dcib || is_for_te) {
		if(AM_I_DC && is_for_te) {
			ROUTER_RESULT("Message result: Local relay");
			send_msg_via_ipc(relay_message, sys_to);
				
		} else if(AM_I_DC) {
			ROUTER_RESULT("Message result: DC/CRMd process");
			processing_complete = FALSE; /* more to be done by caller */
		} else if(originated_locally
			  && safe_str_neq(sys_from, CRM_SYSTEM_PENGINE)
			  && safe_str_neq(sys_from, CRM_SYSTEM_TENGINE)) {

			/* Neither the TE or PE should be sending messages
			 *   to DC's on other nodes
			 *
			 * By definition, if we are no longer the DC, then
			 *   the PE or TE's data should be discarded
			 */
			
			ROUTER_RESULT("Message result: External relay to DC");
			send_msg_via_ha(relay_message);
				
		} else {
			/* discard */
			ROUTER_RESULT("Message result: Discard, not DC");
			crm_msg_del(relay_message);
		}
			
	} else if(is_local && (is_for_crm || is_for_cib)) {
		ROUTER_RESULT("Message result: CRMd process");
		processing_complete = FALSE; /* more to be done by caller */
			
	} else if(is_local) {
		ROUTER_RESULT("Message result: Local relay");
		send_msg_via_ipc(relay_message, sys_to);
			
	} else {
		ROUTER_RESULT("Message result: External relay");
		send_msg_via_ha(relay_message);
	}
	
	return processing_complete;
}

gboolean
crmd_authorize_message(ha_msg_input_t *client_msg, crmd_client_t *curr_client)
{
	/* check the best case first */
	const char *sys_from = cl_get_string(client_msg->msg, F_CRM_SYS_FROM);
	char *uuid = NULL;
	char *client_name = NULL;
	char *major_version = NULL;
	char *minor_version = NULL;
	const char *filtered_from;
	gpointer table_key = NULL;
	gboolean auth_result = FALSE;
	struct crm_subsystem_s *the_subsystem = NULL;
	gboolean can_reply = FALSE; /* no-one has registered with this id */

	const char *op = cl_get_string(client_msg->msg, F_CRM_TASK);

	if (safe_str_neq(CRM_OP_HELLO, op)) {	

		if(sys_from == NULL) {
			crm_warn("Message [%s] was had no value for %s... discarding",
				 cl_get_string(client_msg->msg, XML_ATTR_REFERENCE),
				 F_CRM_SYS_FROM);
			return FALSE;
		}
		
		filtered_from = sys_from;

		/* The CIB can have two names on the DC */
		if(strcasecmp(sys_from, CRM_SYSTEM_DCIB) == 0)
			filtered_from = CRM_SYSTEM_CIB;
		
		if (g_hash_table_lookup (ipc_clients, filtered_from) != NULL) {
			can_reply = TRUE;  /* reply can be routed */
		}
		
		crm_debug_2("Message reply can%s be routed from %s.",
			   can_reply?"":" not", sys_from);

		if(can_reply == FALSE) {
			crm_warn("Message [%s] not authorized",
				 cl_get_string(client_msg->msg, XML_ATTR_REFERENCE));
		}
		
		return can_reply;
	}
	
	crm_debug_3("received client join msg");
	crm_log_message(LOG_MSG, client_msg->msg);
	auth_result = process_hello_message(
		client_msg->xml, &uuid, &client_name,
		&major_version, &minor_version);

	if (auth_result == TRUE) {
		if(client_name == NULL || uuid == NULL) {
			crm_err("Bad client details (client_name=%s, uuid=%s)",
				crm_str(client_name), crm_str(uuid));
			auth_result = FALSE;
		}
	}

	if (auth_result == TRUE) {
		/* check version */
		int mav = atoi(major_version);
		int miv = atoi(minor_version);
		crm_debug_3("Checking client version number");
		if (mav < 0 || miv < 0) {
			crm_err("Client version (%d:%d) is not acceptable",
				mav, miv);
			auth_result = FALSE;
		}
		crm_free(major_version);
		crm_free(minor_version);
	}

	
	if (safe_str_eq(CRM_SYSTEM_PENGINE, client_name)) {
		the_subsystem = pe_subsystem;
		
	} else if (safe_str_eq(CRM_SYSTEM_TENGINE, client_name)) {
		the_subsystem = te_subsystem;
	}
	
	if (auth_result == TRUE && the_subsystem != NULL) {
		/* if we already have one of those clients
		 * only applies to te, pe etc.  not admin clients
		 */
		crm_debug_3("Checking if %s is required/already connected",
			    client_name);

		table_key = (gpointer)crm_strdup(client_name);
		
		if(is_set(fsa_input_register, the_subsystem->flag_connected)) {
			auth_result = FALSE;
			crm_free(table_key);
			table_key = NULL;
			crm_warn("Bit\t%.16llx set in %.16llx",
				 the_subsystem->flag_connected,
				 fsa_input_register);
			crm_err("Client %s is already connected",
				client_name);
			
		} else if(FALSE == is_set(fsa_input_register,
					  the_subsystem->flag_required)) {
			crm_warn("Bit\t%.16llx not set in %.16llx",
				 the_subsystem->flag_connected,
				 fsa_input_register);
			crm_warn("Client %s joined but we dont need it",
				 client_name);
			stop_subsystem(the_subsystem, TRUE);
			
		} else {
			the_subsystem->ipc = curr_client->client_channel;
			set_bit_inplace(fsa_input_register,
					the_subsystem->flag_connected);
		}

	} else {
		table_key = (gpointer)generate_hash_key(client_name, uuid);
	}
	
	if (auth_result == TRUE) {
		crm_debug_2("Accepted client %s", crm_str(table_key));

		curr_client->table_key = table_key;
		curr_client->sub_sys = crm_strdup(client_name);
		curr_client->uuid = crm_strdup(uuid);
	
		g_hash_table_insert (ipc_clients,
				     table_key, curr_client->client_channel);

		send_hello_message(curr_client->client_channel,
				   "n/a", CRM_SYSTEM_CRMD,
				   "0", "1");

		crm_debug_3("Updated client list with %s", crm_str(table_key));
		
		crm_debug_3("Triggering FSA: %s", __FUNCTION__);
		G_main_set_trigger(fsa_source);

		if(the_subsystem != NULL) {
			CRM_CHECK(the_subsystem->client == NULL,
				  process_client_disconnect(the_subsystem->client));
			the_subsystem->client = curr_client;
		}

	} else {
		crm_free(table_key);
		crm_warn("Rejected client logon request");
		curr_client->client_channel->ch_status = IPC_DISC_PENDING;
	}
	
	if(uuid != NULL) crm_free(uuid);
	if(minor_version != NULL) crm_free(minor_version);
	if(major_version != NULL) crm_free(major_version);
	if(client_name != NULL) crm_free(client_name);

	/* hello messages should never be processed further */
	return FALSE;
}

enum crmd_fsa_input
handle_message(ha_msg_input_t *stored_msg)
{
	enum crmd_fsa_input next_input = I_NULL;
	const char *type = NULL;
	if(stored_msg == NULL || stored_msg->msg == NULL) {
		crm_err("No message to handle");
		return I_NULL;
	}
	type = cl_get_string(stored_msg->msg, F_CRM_MSG_TYPE);

	if(safe_str_eq(type, XML_ATTR_REQUEST)) {
		next_input = handle_request(stored_msg);

	} else if(safe_str_eq(type, XML_ATTR_RESPONSE)) {
		next_input = handle_response(stored_msg);

	} else {
		crm_err("Unknown message type: %s", type);
	}

/* 	crm_debug_2("%s: Next input is %s", __FUNCTION__, */
/* 		   fsa_input2string(next_input)); */
	
	return next_input;
}

#define schedule_pe() do {						\
		next_input = I_PE_CALC;					\
		if(fsa_pe_ref) {					\
			crm_debug("Cancelling %s...", fsa_pe_ref);	\
			crm_free(fsa_pe_ref);				\
			fsa_pe_ref = NULL;				\
		}							\
    } while(0)

enum crmd_fsa_input
handle_request(ha_msg_input_t *stored_msg)
{
	HA_Message *msg = NULL;
	enum crmd_fsa_input next_input = I_NULL;

	const char *op        = cl_get_string(stored_msg->msg, F_CRM_TASK);
	const char *sys_to    = cl_get_string(stored_msg->msg, F_CRM_SYS_TO);
	const char *host_from = cl_get_string(stored_msg->msg, F_CRM_HOST_FROM);

	crm_debug_2("Received %s "XML_ATTR_REQUEST" from %s in state %s",
		    op, host_from, fsa_state2string(fsa_state));
	
	if(op == NULL) {
		crm_err("Bad message");
		crm_log_message(LOG_ERR, stored_msg->msg);

		/*========== common actions ==========*/
	} else if(strcasecmp(op, CRM_OP_NOOP) == 0) {
		crm_debug_2("no-op from %s", crm_str(host_from));

	} else if(strcasecmp(op, CRM_OP_NOVOTE) == 0) {
		register_fsa_input_adv(C_HA_MESSAGE, I_NULL, stored_msg,
				       A_ELECTION_COUNT|A_ELECTION_CHECK, FALSE, __FUNCTION__);

	} else if(strcasecmp(op, CRM_OP_VOTE) == 0) {
		/* count the vote and decide what to do after that */
		register_fsa_input_adv(C_HA_MESSAGE, I_NULL, stored_msg,
				       A_ELECTION_COUNT|A_ELECTION_CHECK, FALSE, __FUNCTION__);

		/* Sometimes we _must_ go into S_ELECTION */
		if(fsa_state == S_HALT) {
			crm_debug("Forcing an election from S_HALT");
			next_input = I_ELECTION;
#if 0
		} else if(AM_I_DC) {
		/* This is the old way of doing things but what is gained? */
			next_input = I_ELECTION;
#endif
		}
		
	} else if(strcasecmp(op, CRM_OP_LOCAL_SHUTDOWN) == 0) {
		
		crm_shutdown(SIGTERM);
		/*next_input = I_SHUTDOWN; */
		next_input = I_NULL;
			
	} else if(strcasecmp(op, CRM_OP_PING) == 0) {
		/* eventually do some stuff to figure out
		 * if we /are/ ok
		 */
		crm_data_t *ping = createPingAnswerFragment(sys_to, "ok");

		crm_xml_add(ping, "crmd_state", fsa_state2string(fsa_state));

		crm_info("Current ping state: %s", fsa_state2string(fsa_state));
		
		msg = create_reply(stored_msg->msg, ping);
		free_xml(ping);
		
		if(relay_message(msg, TRUE) == FALSE) {
			crm_msg_del(msg);
		}
		
		/* probably better to do this via signals on the
		 * local node
		 */
	} else if(strcasecmp(op, CRM_OP_DEBUG_UP) == 0) {
		alter_debug(DEBUG_INC);
		crm_info("Debug set to %d", get_crm_log_level());
		
	} else if(strcasecmp(op, CRM_OP_DEBUG_DOWN) == 0) {
		alter_debug(DEBUG_DEC);
		crm_info("Debug set to %d", get_crm_log_level());

	} else if(strcasecmp(op, CRM_OP_JOIN_OFFER) == 0) {
		next_input = I_JOIN_OFFER;
		crm_debug("Raising I_JOIN_OFFER: join-%s",
			  cl_get_string(stored_msg->msg, F_CRM_JOIN_ID));
				
	} else if(strcasecmp(op, CRM_OP_JOIN_ACKNAK) == 0) {
		next_input = I_JOIN_RESULT;
		crm_debug("Raising I_JOIN_RESULT: join-%s",
			  cl_get_string(stored_msg->msg, F_CRM_JOIN_ID));

	} else if(strcasecmp(op, CRM_OP_LRM_DELETE) == 0
		|| strcasecmp(op, CRM_OP_LRM_FAIL) == 0
		|| strcasecmp(op, CRM_OP_LRM_REFRESH) == 0
		|| strcasecmp(op, CRM_OP_REPROBE) == 0) {
		
		cl_msg_modstring(stored_msg->msg, F_CRM_SYS_TO, CRM_SYSTEM_LRMD);
		next_input = I_ROUTER;
		
		/* this functionality should only be enabled
		 *   if this is a development build
		 */
	} else if(CRM_DEV_BUILD && strcasecmp(op, CRM_OP_DIE) == 0/*constant condition*/) {
		crm_warn("Test-only code: Killing the CRM without mercy");
		crm_warn("Inhibiting respawns");
		exit(100);
		
		/*========== (NOT_DC)-Only Actions ==========*/
	} else if(AM_I_DC == FALSE){

		gboolean dc_match = safe_str_eq(host_from, fsa_our_dc);

		if(dc_match || fsa_our_dc == NULL) {
			if(strcasecmp(op, CRM_OP_HBEAT) == 0) {
				crm_debug_3("Received DC heartbeat from %s",
					  host_from);
				next_input = I_DC_HEARTBEAT;
				
			} else if(fsa_our_dc == NULL) {
				crm_warn("CRMd discarding request: %s"
					" (DC: %s, from: %s)",
					op, crm_str(fsa_our_dc), host_from);

				crm_warn("Ignored Request");
				crm_log_message(LOG_WARNING, stored_msg->msg);
				
			} else if(strcasecmp(op, CRM_OP_SHUTDOWN) == 0) {
				next_input = I_STOP;
				
			} else {
				crm_err("CRMd didnt expect request: %s", op);
				crm_log_message(LOG_ERR, stored_msg->msg);
			}
			
		} else {
			crm_warn("Discarding %s op from %s", op, host_from);
		}

		/*========== DC-Only Actions ==========*/
	} else if(AM_I_DC) {
		const char *message = ha_msg_value(stored_msg->msg, "message");

		/* setting "fsa_pe_ref = NULL" makes sure we ignore any
		 *  PE reply that might be pending or in the queue while
		 *  we ask the CIB for a more up-to-date copy
		 */
		if(safe_str_eq(op, CRM_OP_TEABORT)) {
			crm_debug("Transition cancelled: %s/%s", op, message);
			clear_bit_inplace(fsa_input_register, R_IN_TRANSITION);
			if(need_transition(fsa_state)) {
				schedule_pe();

			} else {	
				crm_debug("Filtering %s op in state %s",
					 op, fsa_state2string(fsa_state));
			}
			
		} else if(strcasecmp(op, CRM_OP_TECOMPLETE) == 0) {
			crm_debug("Transition complete: %s/%s", op, message);
			clear_bit_inplace(fsa_input_register, R_IN_TRANSITION);
 			if(fsa_state == S_TRANSITION_ENGINE) {
				next_input = I_TE_SUCCESS;
 			} else {
				crm_debug("Filtering %s op in state %s",
					  op, fsa_state2string(fsa_state));
			}

		} else if(strcasecmp(op, CRM_OP_JOIN_ANNOUNCE) == 0) {
			next_input = I_NODE_JOIN;
			
		} else if(strcasecmp(op, CRM_OP_JOIN_REQUEST) == 0) {
			next_input = I_JOIN_REQUEST;
			
		} else if(strcasecmp(op, CRM_OP_JOIN_CONFIRM) == 0) {
			next_input = I_JOIN_RESULT;
			
		} else if(strcasecmp(op, CRM_OP_SHUTDOWN) == 0) {
			gboolean dc_match = safe_str_eq(host_from, fsa_our_dc);
			if(dc_match) {
				crm_err("We didnt ask to be shut down yet our"
					" TE is telling us too."
					" Better get out now!");
				next_input = I_TERMINATE;

			} else if(is_set(fsa_input_register, R_SHUTDOWN)) {
				crm_info("Shutting ourselves down (DC)");
				next_input = I_STOP;			

			} else if(fsa_state != S_STOPPING) {
				crm_err("Another node is asking us to shutdown"
					" but we think we're ok.");
				next_input = I_ELECTION;			
			}
			
		} else if(strcasecmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
			/* a slave wants to shut down */
			/* create cib fragment and add to message */
			next_input = handle_shutdown_request(stored_msg->msg);
			
		} else {
			crm_err("Unexpected request (%s) sent to the DC", op);
			crm_log_message(LOG_ERR, stored_msg->msg);
		}		
	}
	return next_input;
}

enum crmd_fsa_input
handle_response(ha_msg_input_t *stored_msg)
{
	enum crmd_fsa_input next_input = I_NULL;

	const char *op        = cl_get_string(stored_msg->msg, F_CRM_TASK);
	const char *sys_from  = cl_get_string(stored_msg->msg, F_CRM_SYS_FROM);
	const char *host_from = cl_get_string(stored_msg->msg, F_CRM_HOST_FROM);
	const char *msg_ref   = cl_get_string(stored_msg->msg, XML_ATTR_REFERENCE);

	crm_debug_2("Received %s "XML_ATTR_RESPONSE" from %s in state %s",
		    op, host_from, fsa_state2string(fsa_state));
	
	if(op == NULL) {
		crm_err("Bad message");
		crm_log_message(LOG_ERR, stored_msg->msg);

 	} else if(AM_I_DC && strcasecmp(op, CRM_OP_PECALC) == 0) {

		crm_debug_2("Processing %s reply %s (fsa=%s)",
			  sys_from, msg_ref, crm_str(fsa_pe_ref));

		if(msg_ref != NULL && safe_str_eq(msg_ref, fsa_pe_ref)) {
			next_input = I_PE_SUCCESS;
			crm_debug_2("Completed: %s...", fsa_pe_ref);
			crm_free(fsa_pe_ref);
			fsa_pe_ref = NULL;
			
		} else {
			crm_debug_2("Skipping superceeded reply from %s",
				  sys_from);
		}
		
	} else if(strcasecmp(op, CRM_OP_VOTE) == 0
		  || strcasecmp(op, CRM_OP_HBEAT) == 0
		  || strcasecmp(op, CRM_OP_SHUTDOWN_REQ) == 0
		  || strcasecmp(op, CRM_OP_SHUTDOWN) == 0) {
		crm_debug_2("Ignoring %s from %s in %s",
			    op, host_from, fsa_state2string(fsa_state));
		next_input = I_NULL;
		
	} else {
		crm_err("Unexpected response (op=%s) sent to the %s",
			op, AM_I_DC?"DC":"CRMd");
		next_input = I_NULL;
	}
	
	return next_input;
		
}

enum crmd_fsa_input
handle_shutdown_request(HA_Message *stored_msg)
{
	/* handle here to avoid potential version issues
	 *   where the shutdown message/proceedure may have
	 *   been changed in later versions.
	 *
	 * This way the DC is always in control of the shutdown
	 */
	
	time_t now = time(NULL);
	crm_data_t *node_state = NULL;
	const char *host_from = cl_get_string(stored_msg, F_CRM_HOST_FROM);

	if(host_from == NULL) {
		/* we're shutting down and the DC */
		host_from = fsa_our_uname;
	}
	
	crm_info("Creating shutdown request for %s",host_from);

	crm_log_message(LOG_MSG, stored_msg);

	node_state = create_node_state(
		host_from, NULL, NULL, NULL, NULL,
		CRMD_STATE_INACTIVE, FALSE, __FUNCTION__);
	crm_xml_add_int(node_state, XML_CIB_ATTR_SHUTDOWN,  (int)now);
	
	fsa_cib_anon_update(XML_CIB_TAG_STATUS,node_state, cib_quorum_override);
	crm_log_xml_debug_2(node_state, "Shutdown update");
	free_xml(node_state);

	/* will be picked up by the TE as long as its running */
	if(need_transition(fsa_state)
	   && is_set(fsa_input_register, R_TE_CONNECTED) == FALSE) {
		register_fsa_action(A_TE_CANCEL);
	}

	return I_NULL;
}

/* frees msg upon completion */
gboolean
send_msg_via_ha(HA_Message *msg)
{
	int log_level        = LOG_DEBUG_3;
	gboolean broadcast   = FALSE;
	gboolean all_is_good = TRUE;

	const char *op       = cl_get_string(msg, F_CRM_TASK);
	const char *sys_to   = cl_get_string(msg, F_CRM_SYS_TO);
	const char *host_to  = cl_get_string(msg, F_CRM_HOST_TO);
	enum crm_ais_msg_types dest = 0;

	if(is_openais_cluster()) {
	    dest = 1;
#if SUPPORT_AIS
	    dest = text2msg_type(sys_to);
#endif
	}
	
	if (msg == NULL) {
		crm_err("Attempt to send NULL Message via HA failed.");
		all_is_good = FALSE;
	} else {
		crm_debug_4("Relaying message to (%s) via HA", host_to); 
	}
	
	if (all_is_good) {
		if (sys_to == NULL || strlen(sys_to) == 0) {
			crm_err("You did not specify a destination sub-system"
				" for this message.");
			all_is_good = FALSE;
		}
	}

	/* There are a number of messages may not need to be ordered.
	 * At a later point perhaps we should detect them and send them
	 *  as unordered messages.
	 */
	if (all_is_good) {
		if (host_to == NULL
		    || strlen(host_to) == 0
		    || safe_str_eq(sys_to, CRM_SYSTEM_DC)) {
		    broadcast = TRUE;
		    all_is_good = send_cluster_message(NULL, dest, msg, FALSE);
		} else {
		    all_is_good = send_cluster_message(host_to, dest, msg, FALSE);
		}
	}
	
	if(all_is_good == FALSE) {
		log_level = LOG_WARNING;
	}	
	
	if(log_level == LOG_WARNING
	   || (safe_str_neq(op, CRM_OP_HBEAT))) {
		do_crm_log(log_level,
			   "Sending %sHA message (ref=%s) to %s@%s %s.",
			   broadcast?"broadcast ":"directed ",
			   cl_get_string(msg, XML_ATTR_REFERENCE),
			   crm_str(sys_to), host_to==NULL?"<all>":host_to,
			   all_is_good?"succeeded":"failed");
	}
	
	crm_msg_del(msg);
	
	return all_is_good;
}


/* msg is deleted by the time this returns */

gboolean
send_msg_via_ipc(HA_Message *msg, const char *sys)
{
	gboolean send_ok = TRUE;
	IPC_Channel *client_channel;
	
	crm_debug_4("relaying msg to sub_sys=%s via IPC", sys);

	client_channel = (IPC_Channel*)g_hash_table_lookup(ipc_clients, sys);

	if(cl_get_string(msg, F_CRM_HOST_FROM) == NULL) {
		ha_msg_add(msg, F_CRM_HOST_FROM, fsa_our_uname);
	}
	
	if (client_channel != NULL) {
		crm_debug_3("Sending message via channel %s.", sys);
		send_ok = send_ipc_message(client_channel, msg);
		
	} else if(sys != NULL && strcasecmp(sys, CRM_SYSTEM_CIB) == 0) {
		crm_err("Sub-system (%s) has been incorporated into the CRMd.",
			sys);
		crm_err("Change the way we handle this CIB message");
		crm_log_message(LOG_ERR, msg);
		send_ok = FALSE;
		
	} else if(sys != NULL && strcasecmp(sys, CRM_SYSTEM_LRMD) == 0) {
		fsa_data_t *fsa_data = NULL;
		ha_msg_input_t *msg_copy = new_ha_msg_input(msg);

		crm_malloc0(fsa_data, sizeof(fsa_data_t));
		fsa_data->fsa_input = I_MESSAGE;
		fsa_data->fsa_cause = C_IPC_MESSAGE;
		fsa_data->data = msg_copy;
		fsa_data->origin = __FUNCTION__;
		fsa_data->data_type = fsa_dt_ha_msg;
		
#ifdef FSA_TRACE
		crm_debug_2("Invoking action %s (%.16llx)",
			    fsa_action2string(A_LRM_INVOKE),
			    A_LRM_INVOKE);
#endif
		do_lrm_invoke(A_LRM_INVOKE, C_IPC_MESSAGE,
					   fsa_state, I_MESSAGE, fsa_data);

		delete_ha_msg_input(msg_copy);
		crm_free(fsa_data);
		
	} else {
		crm_err("Unknown Sub-system (%s)... discarding message.",
			crm_str(sys));
		send_ok = FALSE;
	}    

	crm_msg_del(msg);

	return send_ok;
}	


void
msg_queue_helper(void) 
{
#if SUPPORT_HEARTBEAT
	IPC_Channel *ipc = NULL;
	if(fsa_cluster_conn != NULL) {
		ipc = fsa_cluster_conn->llc_ops->ipcchan(
			fsa_cluster_conn);
	}
	if(ipc != NULL) {
		ipc->ops->resume_io(ipc);
	}
/*  	g_hash_table_foreach_remove(ipc_clients, ipc_queue_helper, NULL); */
#endif
}


gboolean
ipc_queue_helper(gpointer key, gpointer value, gpointer user_data) 
{
	crmd_client_t *ipc_client = value;
	if(ipc_client->client_channel != NULL) {
		ipc_client->client_channel->ops->is_message_pending(ipc_client->client_channel);
	}
	return FALSE;
}

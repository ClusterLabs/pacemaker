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
#include <sys/param.h>
#include <crm/crm.h>
#include <string.h>
#include <crmd_fsa.h>
#include <libxml/tree.h>


#include <hb_api.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>

#include <crm/dmalloc_wrapper.h>

FILE *msg_out_strm = NULL;
FILE *router_strm = NULL;

GListPtr fsa_message_queue = NULL;

extern void crm_shutdown(int nsig);

gboolean relay_message(
	xmlNodePtr xml_relay_message, gboolean originated_locally);


gboolean send_ha_reply(
	ll_cluster_t *hb_cluster,
	xmlNodePtr xml_request, xmlNodePtr xml_response_data);

gboolean send_xmlha_message(ll_cluster_t *hb_fd, xmlNodePtr root);

enum crmd_fsa_input handle_request(xmlNodePtr stored_msg);
enum crmd_fsa_input handle_response(xmlNodePtr stored_msg);
enum crmd_fsa_input handle_shutdown_request(xmlNodePtr stored_msg);


#ifdef MSG_LOG

#    define ROUTER_RESULT(x) char *msg_text = dump_xml_formatted(xml_relay_message);\
	if(router_strm == NULL) {					\
		router_strm = fopen(DEVEL_DIR"/router.log", "w");       \
	}								\
	fprintf(router_strm, "[%d RESULT (%s)]\t%s\t%s\n",		\
		AM_I_DC,						\
		xmlGetProp(xml_relay_message, XML_ATTR_REFERENCE),	\
		x, msg_text);						\
	fflush(router_strm);						\
	crm_free(msg_text);						\
	crm_xml_devel(xml_relay_message, x);
#else
#    define ROUTER_RESULT(x)	crm_xml_devel(xml_relay_message, x);
#endif



/* returns the current head of the FIFO queue */
GListPtr
put_message(xmlNodePtr new_message)
{
	int old_len = g_list_length(fsa_message_queue);

	/* make sure to free it properly later */
	fsa_message_queue = g_list_append(fsa_message_queue,
					   copy_xml_node_recursive(new_message));

	crm_verbose("Queue len: %d -> %d", old_len,
		  g_list_length(fsa_message_queue));

	
	if(old_len == g_list_length(fsa_message_queue)){
		crm_err("Couldnt add message to the queue");
	}
	
	return fsa_message_queue;
}

/* returns the next message */
xmlNodePtr
get_message(void)
{
	xmlNodePtr message = g_list_nth_data(fsa_message_queue, 0);
	fsa_message_queue = g_list_remove(fsa_message_queue, message);
	return message;
}

/* returns the current head of the FIFO queue */
gboolean
is_message(void)
{
	return (g_list_length(fsa_message_queue) > 0);
}


/*	 A_MSG_STORE	*/
enum crmd_fsa_input
do_msg_store(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
/*	xmlNodePtr new_message = (xmlNodePtr)data; */
	

/*	put_message(new_message); */

	return I_NULL;
}


/*	A_MSG_ROUTE	*/
enum crmd_fsa_input
do_msg_route(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
	enum crmd_fsa_input result = I_NULL;
	xmlNodePtr xml_message = (xmlNodePtr)data;
	gboolean routed = FALSE, defer = TRUE, do_process = TRUE;

	

#if 0
/*	if(cause == C_IPC_MESSAGE) { */
		if (crmd_authorize_message(root_xml_node,
					   msg,
					   curr_client) == FALSE) {
			crm_debug("Message not authorized\t%s",
				  dump_xml_formatted(root_xml_node, FALSE));
			do_process = FALSE;
		}
/*	} */
#endif
	if(do_process) {
		/* try passing the buck first */
		routed = relay_message(xml_message, cause==C_IPC_MESSAGE);

		if(routed == FALSE) {

			defer = TRUE;
			/* calculate defer */
			result = handle_message(xml_message);
			switch(result) {
				case I_NULL:
					defer = FALSE;
					break;
				case I_DC_HEARTBEAT:
					defer = FALSE;
					break;
					
					/* what else should go here? */
				default:
					crm_trace("Defering local processing of message");

					put_message(xml_message);
					result = I_REQUEST;
					break;
			}
		} 
	}
	
	return result;
}

/*
 * This method adds a copy of xml_response_data
 */
gboolean
send_request(xmlNodePtr msg_options, xmlNodePtr msg_data,
	     const char *operation, const char *host_to, const char *sys_to,
	     char **msg_reference)
{
	xmlNodePtr local_options = NULL;
	gboolean was_sent = FALSE;
	xmlNodePtr request = NULL;


	if(msg_options == NULL) {
		local_options = create_xml_node(NULL, XML_TAG_OPTIONS);
		msg_options = local_options;
	}

	set_xml_property_copy(msg_options, XML_ATTR_OP, operation);
	
	request = create_request(
		msg_options, msg_data, host_to, sys_to,
		AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD,
		NULL, NULL);

/*	crm_xml_devel(request, "Final request..."); */

	if(msg_reference != NULL) {
		*msg_reference = crm_strdup(xmlGetProp(request, XML_ATTR_REFERENCE));
	}
	
	was_sent = relay_message(request, TRUE);

	if(was_sent == FALSE) {
		put_message(request);
	}
	
	free_xml(request);
	free_xml(local_options);

	return was_sent;
}

/*
 * This method adds a copy of xml_response_data
 */
gboolean
store_request(xmlNodePtr msg_options, xmlNodePtr msg_data,
	      const char *operation, const char *sys_to)
{
	xmlNodePtr request = NULL;
	

	msg_options = set_xml_attr(msg_options, XML_TAG_OPTIONS,
				   XML_ATTR_OP, operation, TRUE);

	crm_verbose("Storing op=%s message for later processing", operation);
	
	request = create_request(msg_options,
				 msg_data,
				 NULL,
				 sys_to,
				 AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD,
				 NULL,
				 NULL);

	put_message(request);
	free_xml(request);
	
	return TRUE;
}

gboolean
relay_message(xmlNodePtr xml_relay_message, gboolean originated_locally)
{
	int is_for_dc	= 0;
	int is_for_dcib	= 0;
	int is_for_crm	= 0;
	int is_for_cib	= 0;
	int is_local    = 0;
	gboolean processing_complete = TRUE;
	const char *host_to = xmlGetProp(xml_relay_message,XML_ATTR_HOSTTO);
	const char *sys_to  = xmlGetProp(xml_relay_message,XML_ATTR_SYSTO);

	crm_debug("Routing message %s",
		  xmlGetProp(xml_relay_message, XML_ATTR_REFERENCE));
	
	if(xml_relay_message == NULL) {
		crm_err("Cannot route empty message");
		return TRUE;
	}

	if(strcmp(CRM_OP_HELLO, xml_relay_message->name) == 0) {
		/* quietly ignore */
		return TRUE;
	}

	if(strcmp(XML_MSG_TAG, xml_relay_message->name) != 0) {
		crm_xml_err(xml_relay_message,
			    "Bad message type, should be crm_message");
		return TRUE;
	}
	
	if(sys_to == NULL) {
		crm_xml_err(xml_relay_message,
			    "Message did not have any value for sys_to");
		return TRUE;
	}
	
	is_for_dc   = (strcmp(CRM_SYSTEM_DC,   sys_to) == 0);
	is_for_dcib = (strcmp(CRM_SYSTEM_DCIB, sys_to) == 0);
	is_for_cib  = (strcmp(CRM_SYSTEM_CIB,  sys_to) == 0);
	is_for_crm  = (strcmp(CRM_SYSTEM_CRMD, sys_to) == 0);
	
	is_local = 0;
	if(host_to == NULL || strlen(host_to) == 0) {
		if(is_for_dc) {
			is_local = 0;

		} else if(is_for_crm && originated_locally) {
			is_local = 0;

		} else {
			is_local = 1;
		}
		
	} else if(strcmp(fsa_our_uname, host_to) == 0) {
		is_local=1;
	}

	crm_trace("is_local    %d", is_local);
	crm_trace("is_for_dcib %d", is_for_dcib);
	crm_trace("is_for_dc   %d", is_for_dc);
	crm_trace("is_for_crm  %d", is_for_crm);
	crm_trace("AM_I_DC     %d", AM_I_DC);
	crm_trace("sys_to      %s", crm_str(sys_to));
	crm_trace("host_to     %s", crm_str(host_to));
	
	if(is_for_dc || is_for_dcib) {
		if(AM_I_DC) {
			ROUTER_RESULT("Message result: DC/CRMd process");
			processing_complete = FALSE; /* more to be done by caller */

		} else if(originated_locally) {
			ROUTER_RESULT("Message result: External relay to DC");
			send_msg_via_ha(xml_relay_message, NULL);

		} else {
			ROUTER_RESULT("Message result: Discard, not DC");
			/* discard */
		}
		
	} else if(is_local && (is_for_crm || is_for_cib)) {
		ROUTER_RESULT("Message result: CRMd process");
		processing_complete = FALSE; /* more to be done by caller */

	} else if(is_local) {
		ROUTER_RESULT("Message result: Local relay");
		send_msg_via_ipc(xml_relay_message, sys_to);
		
	} else {
		ROUTER_RESULT("Message result: External relay");
		send_msg_via_ha(xml_relay_message, host_to);
	}
	
	return processing_complete;
}

gboolean
crmd_authorize_message(
	xmlNodePtr root_xml_node,
	IPC_Message *client_msg, crmd_client_t *curr_client)
{
	/* check the best case first */
	const char *sys_from   = xmlGetProp(root_xml_node,
					    XML_ATTR_SYSFROM);
	char *uuid = NULL;
	char *client_name = NULL;
	char *major_version = NULL;
	char *minor_version = NULL;
	const char *filtered_from;
	gpointer table_key = NULL;
	gboolean result;
	struct crm_subsystem_s *the_subsystem = NULL;
	gboolean can_reply = FALSE; /* no-one has registered with this id */

	const char *op = get_xml_attr(
		root_xml_node, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);
	
	

	if (safe_str_neq(CRM_OP_HELLO, op)) {

		if(sys_from == NULL) {
			crm_warn("Message [%s] was had no value for %s... discarding",
				 xmlGetProp(root_xml_node, XML_ATTR_REFERENCE),
				XML_ATTR_SYSFROM);
			return FALSE;
		}
		
		filtered_from = sys_from;

		/* The CIB can have two names on the DC */
		if(strcmp(sys_from, CRM_SYSTEM_DCIB) == 0)
			filtered_from = CRM_SYSTEM_CIB;
		
		if (g_hash_table_lookup (ipc_clients, filtered_from) != NULL) {
			can_reply = TRUE;  /* reply can be routed */
		}
		
		crm_verbose("Message reply can%s be routed from %s.",
			   can_reply?"":" not", sys_from);

		if(can_reply == FALSE) {
			crm_warn("Message [%s] not authorized",
				 xmlGetProp(root_xml_node, XML_ATTR_REFERENCE));
		}
		
		return can_reply;
	}
	
	crm_debug("received client join msg: %s",
		 (char*)client_msg->msg_body);

	result = process_hello_message(root_xml_node,
				       &uuid,
				       &client_name,
				       &major_version,
				       &minor_version);

	if (result == TRUE) {
		/* check version */
		int mav = atoi(major_version);
		int miv = atoi(minor_version);
		if (mav < 0 || miv < 0) {
			crm_err("Client version (%d:%d) is not acceptable",
				mav, miv);
			result = FALSE;
		}
		crm_free(major_version);
		crm_free(minor_version);
	}

	if (result == TRUE) {
		/* if we already have one of those clients
		 * only applies to te, pe etc.  not admin clients
		 */

		
		if (client_name == NULL) {
			crm_warn("Client had not registered with us yet");

		} else if (strcmp(CRM_SYSTEM_PENGINE, client_name) == 0) {
			the_subsystem = pe_subsystem;
			
		} else if (strcmp(CRM_SYSTEM_TENGINE, client_name) == 0) {
			the_subsystem = te_subsystem;
			
		} else if (strcmp(CRM_SYSTEM_CIB, client_name) == 0) {
			the_subsystem = cib_subsystem;
		}

		if (the_subsystem != NULL) {
			/* do we already have one? */
			result =(fsa_input_register & the_subsystem->flag)==0;
			if(result) {
				the_subsystem->ipc =
					curr_client->client_channel;

			} /* else we didnt ask for the client to start */

		} else if(client_name != NULL && uuid != NULL) {
			table_key = (gpointer)
				generate_hash_key(client_name, uuid);
		} else {
			result = FALSE;
			crm_err("Bad client details (client_name=%s, uuid=%s)",
				crm_str(client_name), uuid);
		}
	}
	
	if(result == TRUE && table_key == NULL) {
		table_key = (gpointer)crm_strdup(client_name);
	}
	
	if (result == TRUE) {
		crm_info("Accepted client %s", (char*)table_key);

		curr_client->table_key = table_key;
		curr_client->sub_sys = crm_strdup(client_name);
		curr_client->uuid = crm_strdup(uuid);
	
		g_hash_table_insert (ipc_clients,
				     table_key,
				     curr_client->client_channel);

		send_hello_message(curr_client->client_channel,
				   "n/a", CRM_SYSTEM_CRMD,
				   "0", "1");

		crm_debug("Updated client list with %s",
		       (char*)table_key);
		
		if(the_subsystem != NULL) {
			set_bit_inplace(
				fsa_input_register, the_subsystem->flag);
		}
		
		s_crmd_fsa(C_SUBSYSTEM_CONNECT, I_NULL, NULL);

	} else {
		crm_err("Rejected client logon request");
		curr_client->client_channel->ch_status = IPC_DISC_PENDING;
	}
	
	if(uuid != NULL) crm_free(uuid);
	if(client_name != NULL) crm_free(client_name);

	/* hello messages should never be processed further */
	return FALSE;
}

enum crmd_fsa_input
handle_message(xmlNodePtr stored_msg)
{
	enum crmd_fsa_input next_input = I_NULL;
	const char *type     = get_xml_attr(
		stored_msg, NULL, XML_ATTR_MSGTYPE,   TRUE);

	if(safe_str_eq(type, XML_ATTR_REQUEST)) {
		next_input = handle_request(stored_msg);

	} else if(safe_str_eq(type, XML_ATTR_RESPONSE)) {
		next_input = handle_response(stored_msg);

	} else {
		crm_err("Unknown message type: %s", type);
	}

/* 	crm_verbose("%s: Next input is %s", __FUNCTION__, */
/* 		   fsa_input2string(next_input)); */
	
	return next_input;
}


enum crmd_fsa_input
handle_request(xmlNodePtr stored_msg)
{
	xmlNodePtr wrapper = NULL;
	enum crmd_fsa_input next_input = I_NULL;

	const char *sys_to   = get_xml_attr(
		stored_msg, NULL, XML_ATTR_SYSTO, TRUE);

	const char *host_from= get_xml_attr(
		stored_msg, NULL, XML_ATTR_HOSTFROM, FALSE);

	const char *op       = get_xml_attr(
		stored_msg, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);

	crm_verbose("Received %s in state %s",
		    op, fsa_state2string(fsa_state));
	
	if(op == NULL) {
		crm_xml_err(stored_msg, "Bad message");

		/*========== common actions ==========*/
	} else if(strcmp(op, CRM_OP_VOTE) == 0) {
		next_input = I_ELECTION;
		
	} else if(strcmp(op, "init_shutdown") == 0) {
		
		crm_shutdown(SIGTERM);
		/*next_input = I_SHUTDOWN; */
		next_input = I_NULL;
			
	} else if(strcmp(op, CRM_OP_QUERY) == 0) {
		
		next_input = I_CIB_OP;

	} else if(strcmp(op, CRM_OP_PING) == 0) {
		/* eventually do some stuff to figure out
		 * if we /are/ ok
		 */
		xmlNodePtr ping = createPingAnswerFragment(sys_to, "ok");

		set_xml_property_copy(ping, "crmd_state",
				      fsa_state2string(fsa_state));
		
		wrapper = create_reply(stored_msg, ping);
		
		relay_message(wrapper, TRUE);
		free_xml(wrapper);

	} else if(strcmp(op, "init_shutdown") == 0) {
		
		crm_shutdown(SIGTERM);
		/*next_input = I_SHUTDOWN; */
		next_input = I_NULL;

#if 0
		/* probably better to do this via signals on the
		 * local node
		 */
	} else if(strcmp(op, "debug_inc") == 0) {
		int level = get_crm_log_level();
		set_crm_log_level(level+1);
		crm_info("Debug set to %d (was %d)",
			 get_crm_log_level(), level);
		
	} else if(strcmp(op, "debug_dec") == 0) {
		int level = get_crm_log_level();
		set_crm_log_level(level-1);
		crm_info("Debug set to %d (was %d)",
			 get_crm_log_level(), level);
#endif		
		/*========== (NOT_DC)-Only Actions ==========*/
	} else if(AM_I_DC == FALSE){

		gboolean dc_match = safe_str_eq(host_from, fsa_our_dc);

		if(dc_match || fsa_our_dc == NULL) {
			if(strcmp(op, CRM_OP_HBEAT) == 0) {
				next_input = I_DC_HEARTBEAT;
			} else if(strcmp(op, CRM_OP_WELCOME) == 0) {
				next_input = I_JOIN_OFFER;
				
			} else if(fsa_our_dc != NULL
				  && strcmp(op, CRM_OP_JOINACK) == 0) {
				next_input = I_JOIN_RESULT;
				
			} else if(fsa_our_dc != NULL
				  && strcmp(op, CRM_OP_REPLACE) == 0) {
				next_input = I_CIB_OP;
			
			} else if(fsa_our_dc != NULL
				  && strcmp(op, CRM_OP_UPDATE) == 0) {
				next_input = I_CIB_OP;
			
			} else if(fsa_our_dc != NULL
				  && strcmp(op, CRM_OP_SHUTDOWN) == 0) {
				next_input = I_TERMINATE;
				
			} else {
				crm_err("%s didnt expect request: %s",
					AM_I_DC?"DC":"CRMd", op);
			}
			
		} else {
			crm_warn("Discarding %s op from %s", op, host_from);
		}

		/*========== DC-Only Actions ==========*/
	} else if(AM_I_DC){
		if(strcmp(op, CRM_OP_TEABORT) == 0) {
			if(fsa_state != S_INTEGRATION) {
				next_input = I_PE_CALC;

			} else {	
				crm_debug("Ignoring %s in state %s."
					"  Waiting for the integration to"
					" complete first.",
					op, fsa_state2string(fsa_state));
			}
				
		} else if(strcmp(op, CRM_OP_TECOMPLETE) == 0) {
			if(fsa_state == S_TRANSITION_ENGINE) {
				next_input = I_SUCCESS;
			} else {
				crm_warn("Op %s is only valid in state %s..."
					 "We are in (%s)",
					 op,
					 fsa_state2string(S_TRANSITION_ENGINE),
					 fsa_state2string(fsa_state));
			}

		} else if(strcmp(op, CRM_OP_CREATE) == 0
			      || strcmp(op, CRM_OP_UPDATE) == 0
			      || strcmp(op, CRM_OP_ERASE) == 0
			      || strcmp(op, CRM_OP_REPLACE) == 0
			      || strcmp(op, CRM_OP_DELETE) == 0) {
			next_input = I_CIB_OP;
				
		} else if(strcmp(op, CRM_OP_ANNOUNCE) == 0) {
			next_input = I_NODE_JOIN;
			
		} else if(strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0) {
			/* a slave wants to shut down */
			/* create cib fragment and add to message */
			next_input = handle_shutdown_request(stored_msg);
			
		} else {
			crm_err("Unexpected request (op=%s) sent to the %s",
				op, AM_I_DC?"DC":"CRMd");
		}		
	}
	return next_input;
}

enum crmd_fsa_input
handle_response(xmlNodePtr stored_msg)
{
	enum crmd_fsa_input next_input = I_NULL;

	const char *sys_from = get_xml_attr(
		stored_msg, NULL, XML_ATTR_SYSFROM,   TRUE);

	const char *msg_ref  = get_xml_attr(
		stored_msg, NULL, XML_ATTR_REFERENCE, TRUE);

	const char *type     = get_xml_attr(
		stored_msg, NULL, XML_ATTR_MSGTYPE,   TRUE);
	
	const char *op       = get_xml_attr(
		stored_msg, XML_TAG_OPTIONS, XML_ATTR_OP, TRUE);

	crm_verbose("Received %s %s in state %s",
		    op, type, fsa_state2string(fsa_state));
	
	if(op == NULL) {
		crm_xml_err(stored_msg, "Bad message");

	} else if(strcmp(op, CRM_OP_WELCOME) == 0) {
			next_input = I_JOIN_REQUEST;
				
	} else if(AM_I_DC && strcmp(op, CRM_OP_JOINACK) == 0) {
		next_input = I_JOIN_RESULT;
				
 	} else if(AM_I_DC && strcmp(op, CRM_OP_RETRIVE_CIB) == 0) {
		next_input = I_CIB_OP;		
		
 	} else if(AM_I_DC && strcmp(op, CRM_OP_PECALC) == 0) {

		if(fsa_state == S_POLICY_ENGINE
		   && safe_str_eq(msg_ref, fsa_pe_ref)) {
			next_input = I_SUCCESS;
		} else if(fsa_state != S_POLICY_ENGINE) {
			crm_err("Reply to %s is only valid in state %s",
				op, fsa_state2string(S_POLICY_ENGINE));
			
		} else {
			crm_verbose("Skipping superceeded reply from %s",
				    sys_from);
		}
		
	} else if(strcmp(op, CRM_OP_VOTE) == 0
		  || strcmp(op, CRM_OP_HBEAT) == 0
		  || strcmp(op, CRM_OP_WELCOME) == 0
		  || strcmp(op, CRM_OP_SHUTDOWN_REQ) == 0
		  || strcmp(op, CRM_OP_SHUTDOWN) == 0
		  || strcmp(op, CRM_OP_ANNOUNCE) == 0) {
		next_input = I_NULL;
		
	} else if(strcmp(op, CRM_OP_CREATE) == 0
		  || strcmp(op, CRM_OP_UPDATE) == 0
		  || strcmp(op, CRM_OP_DELETE) == 0
		  || strcmp(op, CRM_OP_REPLACE) == 0
		  || strcmp(op, CRM_OP_ERASE) == 0) {
		
		/* perhaps we should do somethign with these replies,
		 * especially check that the actions passed
		 */
/* 		fprintf(router_strm, "Message result: CIB Reply\n"); */

	} else {
		crm_err("Unexpected response (op=%s) sent to the %s",
			op, AM_I_DC?"DC":"CRMd");
		next_input = I_NULL;
	}
	
	return next_input;
		
}

enum crmd_fsa_input
handle_shutdown_request(xmlNodePtr stored_msg)
{
	/* handle here to avoid potential version issues
	 *   where the shutdown message/proceedure may have
	 *   been changed in later versions.
	 *
	 * This way the DC is always in control of the shutdown
	 */
	
	xmlNodePtr frag = NULL;
	time_t now = time(NULL);
	char *now_s = crm_itoa((int)now);
	xmlNodePtr node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);
	const char *host_from= get_xml_attr(
		stored_msg, NULL, XML_ATTR_HOSTFROM,  FALSE);
	
	crm_info("Creating shutdown request for %s",host_from);
	
	set_uuid(node_state, XML_ATTR_UUID, host_from);
	set_xml_property_copy(node_state, XML_ATTR_UNAME, host_from);
	set_xml_property_copy(node_state, XML_CIB_ATTR_SHUTDOWN,  now_s);
	set_xml_property_copy(
		node_state, XML_CIB_ATTR_EXPSTATE, CRMD_STATE_INACTIVE);
	
	frag = create_cib_fragment(node_state, NULL);
	
	/* attach it to the original request
	 * and make sure its sent to the CIB
	 */
	xmlAddChild(stored_msg, frag);
	
	/* cleanup intermediate steps */
	free_xml(node_state);
	crm_free(now_s);

	return I_CIB_OP;
}

gboolean
send_xmlha_message(ll_cluster_t *hb_fd, xmlNodePtr root)
{
	int xml_len          = -1;
	int send_result      = -1;
	char *xml_text       = NULL;
	const char *host_to  = NULL;
	const char *sys_to   = NULL;
	struct ha_msg *msg   = NULL;
	gboolean all_is_good = TRUE;
	gboolean broadcast   = FALSE;
	int log_level        = LOG_DEBUG;

	xmlNodePtr opts = find_xml_node(root, XML_TAG_OPTIONS);
	const char *op  = xmlGetProp(opts, XML_ATTR_OP);

#ifdef MSG_LOG
	char *msg_text = NULL;
#endif

	
    
	if (root == NULL) {
		crm_err("Attempt to send NULL Message via HA failed.");
		all_is_good = FALSE;
	}

	host_to = xmlGetProp(root, XML_ATTR_HOSTTO);
	sys_to = xmlGetProp(root, XML_ATTR_SYSTO);
	
	if (all_is_good) {
		msg = ha_msg_new(4); 
		ha_msg_add(msg, F_TYPE, "CRM");
		ha_msg_add(msg, F_COMMENT, "A CRM xml message");
		xml_text = dump_xml_unformatted(root);
		xml_len = strlen(xml_text);
		
		if (xml_text == NULL || xml_len <= 0) {
			crm_err(
			       "Failed sending an invalid XML Message via HA");
			all_is_good = FALSE;
			crm_xml_devel(root, "Bad message was");
			
		} else {
			if(ha_msg_add(msg, "xml", xml_text) == HA_FAIL) {
				crm_err("Could not add xml to HA message");
				all_is_good = FALSE;
			}
		}
	}

	if (all_is_good) {
		if (sys_to == NULL || strlen(sys_to) == 0)
		{
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
		    || strlen(host_to) == 0) {
			broadcast = TRUE;
			send_result=hb_fd->llc_ops->sendclustermsg(hb_fd, msg);
		}
		else {
			send_result = hb_fd->llc_ops->send_ordered_nodemsg(
				hb_fd, msg, host_to);
		}
		
		if(send_result != HA_OK)
			all_is_good = FALSE;
	}
	
	if(all_is_good == FALSE) {
		log_level = LOG_ERR;
	}

	if(log_level == LOG_ERR
	   || (safe_str_neq(op, CRM_OP_HBEAT))) {
		do_crm_log(log_level, __FUNCTION__, 
			   "Sending %sHA message (ref=%s,len=%d) to %s@%s %s.",
			   broadcast?"broadcast ":"directed ",
			   xmlGetProp(root, XML_ATTR_REFERENCE), xml_len,
			   sys_to, host_to==NULL?"<all>":host_to,
			   all_is_good?"succeeded":"failed");
	}
	
#ifdef MSG_LOG
	msg_text = dump_xml_formatted(root);
	if(msg_out_strm == NULL) {
		msg_out_strm = fopen(DEVEL_DIR"/outbound.log", "w");
	}
	fprintf(msg_out_strm, "[%s HA (%s:%d)]\t%s\n",
		all_is_good?"succeeded":"failed",
		xmlGetProp(root, XML_ATTR_REFERENCE),
		send_result,
		msg_text);
	
	fflush(msg_out_strm);
	crm_free(msg_text);
	if(msg != NULL) {
		ha_msg_del(msg);
	}
#endif
		
	return all_is_good;
}
		    


/* required?  or just send to self an let relay_message do its thing? */
/*
 * This method adds a copy of xml_response_data
 */
gboolean
send_ha_reply(ll_cluster_t *hb_cluster,
	      xmlNodePtr xml_request,
	      xmlNodePtr xml_response_data)
{
	gboolean was_sent = FALSE;
	xmlNodePtr reply;

	
	was_sent = FALSE;
	reply = create_reply(xml_request, xml_response_data);
	if (reply != NULL) {
		was_sent = send_xmlha_message(hb_cluster, reply);
		free_xml(reply);
	}
	return was_sent;
}


void
send_msg_via_ha(xmlNodePtr action, const char *dest_node)
{
	
	if (action == NULL) {
		return;

	} else if (validate_crm_message(action, NULL, NULL, NULL) == NULL) {
		crm_err("Relay message to (%s) via HA was invalid, ignoring",
			dest_node);
		return;
	}
/*	crm_verbose("Relaying message to (%s) via HA", dest_node); */
	set_xml_property_copy(action, XML_ATTR_HOSTTO, dest_node);

	send_xmlha_message(fsa_cluster_conn, action);
	return;
}


void
send_msg_via_ipc(xmlNodePtr action, const char *sys)
{
	IPC_Channel *client_channel;
	enum crmd_fsa_input next_input;

	crm_trace("relaying msg to sub_sys=%s via IPC", sys);

	client_channel =
		(IPC_Channel*)g_hash_table_lookup (ipc_clients, sys);

	if(xmlGetProp(action, XML_ATTR_HOSTFROM) == NULL) {
		set_xml_property_copy(
			action, XML_ATTR_HOSTFROM, fsa_our_uname);
	}
	
	if (client_channel != NULL) {
		crm_debug("Sending message via channel %s.", sys);
		
		send_xmlipc_message(client_channel, action);
		
	} else if(sys != NULL && strcmp(sys, CRM_SYSTEM_CIB) == 0) {
		crm_err("Sub-system (%s) has been incorporated into the CRMd.",
			sys);
		crm_xml_err(action, "Change the way we handle");
/*		relay_message(process_cib_message(action, TRUE), TRUE); */
		
	} else if(sys != NULL && strcmp(sys, CRM_SYSTEM_LRMD) == 0) {

#ifdef FSA_TRACE
		crm_verbose("Invoking action %s (%.16llx)",
			    fsa_action2string(A_LRM_INVOKE),
			    A_LRM_INVOKE);
#endif

		next_input =
			do_lrm_invoke(A_LRM_INVOKE, C_IPC_MESSAGE,
				      fsa_state, I_MESSAGE, action);

		/* todo: feed this back in for anything != I_NULL */
		
#ifdef FSA_TRACE
		crm_verbose("Result of action %s was %s",
			    fsa_action2string(A_LRM_INVOKE),
			    fsa_input2string(next_input));
#endif
		
	} else {
		crm_err("Unknown Sub-system (%s)... discarding message.", sys);
	}    
	return;
}	

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
#include <crm/crm.h>
#include <string.h>
#include <crmd_fsa.h>
#include <libxml/tree.h>


#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>
#include <crm/common/msgutils.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>

#include <crm/dmalloc_wrapper.h>

FILE *msg_in_strm = NULL;
FILE *router_strm = NULL;

fsa_message_queue_t fsa_message_queue = NULL;

gboolean relay_message(xmlNodePtr xml_relay_message,
		       gboolean originated_locally);

#ifdef MSG_LOG

#    define ROUTER_RESULT(x) char *msg_text = dump_xml(xml_relay_message);\
	if(router_strm == NULL) {				\
		router_strm = fopen("/tmp/router.log", "w");	\
	}							\
	fprintf(router_strm, "[%d RESULT (%s)]\t%s\t%s\n",	\
		AM_I_DC,					\
		xmlGetProp(xml_relay_message, XML_ATTR_REFERENCE),\
		x, msg_text);					\
	fflush(router_strm);					\
	cl_free(msg_text);
#else
#    define ROUTER_RESULT(x)	CRM_DEBUG(x);
#endif



/* returns the current head of the FIFO queue */
fsa_message_queue_t
put_message(xmlNodePtr new_message)
{
	fsa_message_queue_t next_message = (fsa_message_queue_t)
		cl_malloc(sizeof(struct fsa_message_queue_s));

	CRM_DEBUG("Adding msg to queue");
	
	next_message->message = new_message;
	next_message->next = NULL;
	
	if(fsa_message_queue == NULL) {
		fsa_message_queue = next_message;
	} else {
		fsa_message_queue->next = next_message;
	}

	CRM_DEBUG("Added msg to queue");

	return fsa_message_queue;
}

/* returns the next message */
fsa_message_queue_t
get_message(void)
{
	fsa_message_queue_t next_message = NULL;

	if(fsa_message_queue != NULL) {
		next_message = fsa_message_queue;
		fsa_message_queue = fsa_message_queue->next;
		next_message->next = NULL;
	}
	
	
	return next_message;
}

/* returns the current head of the FIFO queue */
gboolean
is_message(void)
{
	return (fsa_message_queue != NULL
		&& fsa_message_queue->message != NULL);
}


/*	 A_MSG_STORE	*/
enum crmd_fsa_input
do_msg_store(long long action,
	     enum crmd_fsa_cause cause,
	     enum crmd_fsa_state cur_state,
	     enum crmd_fsa_input current_input,
	     void *data)
{
//	xmlNodePtr new_message = (xmlNodePtr)data;
	FNIN();

//	put_message(new_message);

	FNRET(I_NULL);
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

	FNIN();

#if 0
//	if(cause == C_IPC_MESSAGE) {
		if (crmd_authorize_message(root_xml_node,
					   msg,
					   curr_client) == FALSE) {
			CRM_DEBUG("Message not authorized");
			do_process = FALSE;
		}
//	}
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
					CRM_DEBUG("Defering local processing of message");

					put_message(xml_message);
					result = I_REQUEST;
					break;
			}
		} 
	}
	
	FNRET(result);
}


void
crmd_ha_input_callback(const struct ha_msg* msg, void* private_data)
{
	const char *from = ha_msg_value(msg, F_ORIG);
	const char *to = NULL;

	FNIN();

#ifdef MSG_LOG
	
	if(msg_in_strm == NULL) {
		msg_in_strm = fopen("/tmp/inbound.log", "w");
	}
	fprintf(msg_in_strm, "[%s (%s:%s)]\t%s\n",
		from,
		ha_msg_value(msg, F_SEQ),
		ha_msg_value(msg, F_TYPE),
		ha_msg_value(msg, "xml")
		);
	fflush(msg_in_strm);
	
#endif

	if(from == NULL || strcmp(from, fsa_our_uname) == 0) {
#ifdef MSG_LOG
		fprintf(msg_in_strm,
			"Discarded message [F_SEQ=%s] from ourselves.\n",
			ha_msg_value(msg, F_SEQ));
#endif
		FNOUT();
	}

	xmlNodePtr root_xml_node = find_xml_in_hamessage(msg);
	to = xmlGetProp(root_xml_node, XML_ATTR_HOSTTO);

/*
	if(AM_I_DC == FALSE && (to == NULL || strlen(to) == 0)) {
		CRM_DEBUG2("Discarding message [F_SEQ=%s] for the DC.",
			   ha_msg_value(msg, F_SEQ));
		FNOUT();
	}
*/

	if(to != NULL && strlen(to) > 0 && strcmp(to, fsa_our_uname) != 0) {
#ifdef MSG_LOG
		fprintf(msg_in_strm, "Discarding message [F_SEQ=%s] for someone else.",
			   ha_msg_value(msg, F_SEQ));
#endif
		FNOUT();
	}

	set_xml_property_copy(root_xml_node, XML_ATTR_HOSTFROM, from);
	s_crmd_fsa(C_HA_MESSAGE, I_ROUTER, root_xml_node);

	free_xml(root_xml_node);

	FNOUT();
}

/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */
gboolean
crmd_ipc_input_callback(IPC_Channel *client, gpointer user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	IPC_Message *msg = NULL;
	gboolean hack_return_good = TRUE;
	crmd_client_t *curr_client = (crmd_client_t*)user_data;

	FNIN();
	CRM_DEBUG2("Processing IPC message from %s",
		   curr_client->table_key);

	while(client->ops->is_message_pending(client)) {
		if (client->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (client->ops->recv(client, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!hack_return_good);
		}
		if (msg == NULL) {
			CRM_DEBUG("No message this time");
			continue;
		}

		lpc++;
		buffer = (char*)msg->msg_body;
		CRM_DEBUG3("Processing xml from %s [text=%s]",
			   curr_client->table_key, buffer);
	
		xmlNodePtr root_xml_node =
			find_xml_in_ipcmessage(msg, FALSE);
		if (root_xml_node != NULL) {
			if (crmd_authorize_message(root_xml_node,
						   msg,
						   curr_client)) {
				CRM_DEBUG("Message authorized,about to relay");
				s_crmd_fsa(C_IPC_MESSAGE,
					   I_ROUTER,
					   root_xml_node);
				
			} else {
				CRM_DEBUG("Message not authorized");
			}
		} else {
			cl_log(LOG_INFO,
			       "IPC Message was not valid... discarding.");
		}
		free_xml(root_xml_node);
		msg->msg_done(msg);
		
		msg = NULL;
		buffer = NULL;
		root_xml_node = NULL;
	}

	CRM_DEBUG2("Processed %d messages", lpc);
    
	if (client->ch_status == IPC_DISCONNECT)
	{
		cl_log(LOG_INFO,
		       "received HUP from %s",
		       curr_client->table_key);
		if (curr_client != NULL) {
			struct crm_subsystem_s *the_subsystem = NULL;
			
			if (curr_client->sub_sys == NULL)
				CRM_DEBUG("Client had not registered with us yet");
			else if (strcmp(CRM_SYSTEM_PENGINE, curr_client->sub_sys) == 0) 
				the_subsystem = pe_subsystem;
			else if (strcmp(CRM_SYSTEM_TENGINE, curr_client->sub_sys) == 0)
				the_subsystem = te_subsystem;
			else if (strcmp(CRM_SYSTEM_CIB, curr_client->sub_sys) == 0)
				the_subsystem = cib_subsystem;

			if(the_subsystem != NULL) {
				cleanup_subsystem(the_subsystem);
			} // else that was a transient client
			
			if (curr_client->table_key != NULL) {
				/*
				 * Key is destroyed below: curr_client->table_key
				 * Value is cleaned up by G_main_del_IPC_Channel
				 */
				g_hash_table_remove(ipc_clients,
						    curr_client->table_key);
			}


			if(curr_client->client_source != NULL) {
				gboolean det =
					G_main_del_IPC_Channel(curr_client->client_source);
			
				CRM_DEBUG2("crm_client was %s detached",
					   det?"successfully":"not");
			}
			
			cl_free(curr_client->table_key);
			cl_free(curr_client->sub_sys);
			cl_free(curr_client->uuid);
			cl_free(curr_client);
		}
		CRM_DEBUG("this client has now left the building.");
		FNRET(!hack_return_good);
	}
    
	FNRET(hack_return_good);
}


/*
 * This method adds a copy of xml_response_data
 */
gboolean
send_request(xmlNodePtr msg_options, xmlNodePtr msg_data,
	     const char *operation, const char *host_to, const char *sys_to)
{
	gboolean was_sent = FALSE;
	xmlNodePtr request = NULL;
	FNIN();


	msg_options = set_xml_attr(msg_options, XML_TAG_OPTIONS,
				   XML_ATTR_OP, operation, TRUE);
	
	request = create_request(msg_options,
				 msg_data,
				 host_to,
				 sys_to,
				 AM_I_DC?CRM_SYSTEM_DC:CRM_SYSTEM_CRMD,
				 NULL,
				 NULL);

//	xml_message_debug(request, "Final request...");

	was_sent = relay_message(request, TRUE);

	free_xml(request);

	FNRET(was_sent);
}


gboolean
relay_message(xmlNodePtr xml_relay_message, gboolean originated_locally)
{
	int is_for_dc	= 0;
	int is_for_dcib	= 0;
	int is_for_crm	= 0;
	int is_for_cib	= 0;
	int is_local    = 0;
	gboolean dont_cc= TRUE;
	gboolean processing_complete = FALSE;
	const char *host_to = xmlGetProp(xml_relay_message, XML_ATTR_HOSTTO);
	const char *sys_to  = xmlGetProp(xml_relay_message, XML_ATTR_SYSTO);
	const char *sys_cc  = get_xml_attr(xml_relay_message, XML_TAG_OPTIONS,
					   XML_ATTR_SYSCC, FALSE);

	FNIN();

	if(xml_relay_message == NULL) {
		cl_log(LOG_ERR, "Cannot route empty message");
		FNRET(TRUE);
	}

	if(strcmp("hello", xml_relay_message->name) == 0) {
		/* quietly ignore */
		FNRET(TRUE);
	}

	if(strcmp(XML_MSG_TAG, xml_relay_message->name) != 0) {

		xml_message_debug(xml_relay_message,
				  "Bad message type, should be crm_message");
		cl_log(LOG_ERR, "Ignoring message of type %s",
		       xml_relay_message->name);
		FNRET(TRUE);
	}
	

	if(sys_to == NULL) {
		xml_message_debug(xml_relay_message,
				  "Message did not have any value for sys_to");
		cl_log(LOG_ERR, "Message did not have any value for %s",
		       XML_ATTR_SYSTO);
		FNRET(TRUE);
	}
	
	is_for_dc   = (strcmp(CRM_SYSTEM_DC,   sys_to) == 0);
	is_for_dcib = (strcmp(CRM_SYSTEM_DCIB, sys_to) == 0);
	is_for_cib  = (strcmp(CRM_SYSTEM_CIB,  sys_to) == 0);
	is_for_crm  = (strcmp(CRM_SYSTEM_CRMD, sys_to) == 0);
	
	is_local = 0;
	if(host_to == NULL || strlen(host_to) == 0) {
		if(is_for_dc)
			is_local = 0;
		else if(is_for_crm && originated_locally)
			is_local = 0;
		else
			is_local = 1;
		
	} else if(strcmp(fsa_our_uname, host_to) == 0) {
		is_local=1;
	}

#if 0
	CRM_DEBUG2("is_local    %d", is_local);
	CRM_DEBUG2("is_for_dcib %d", is_for_dcib);
	CRM_DEBUG2("is_for_dc   %d", is_for_dc);
	CRM_DEBUG2("is_for_crm  %d", is_for_crm);
	CRM_DEBUG2("AM_I_DC     %d", AM_I_DC);
	CRM_DEBUG2("sys_to      %s", sys_to);
	CRM_DEBUG2("host_to     %s", host_to);
#endif
/*
	if(AM_I_DC && sys_cc != NULL && strcmp(sys_cc, CRM_SYSTEM_DC) == 0) {
		dont_cc = FALSE;
	}
*/
	(void)sys_cc;
	
	if(is_for_dc || is_for_dcib) {
		if(AM_I_DC) {
			ROUTER_RESULT("Message result: DC/CRMd process");
			processing_complete = FALSE; // more to be done by caller

		} else if(originated_locally) {
			ROUTER_RESULT("Message result: External relay to DC");
			send_msg_via_ha(xml_relay_message, NULL);
			processing_complete = TRUE; 

		} else {
			ROUTER_RESULT("Message result: Discard, not DC");
			processing_complete = TRUE; // discard
		}
		
	} else if(is_local && (is_for_crm || is_for_cib)) {
		ROUTER_RESULT("Message result: CRMd process");

	} else if(is_local) {
		if(dont_cc) {
			ROUTER_RESULT("Message result: Local relay");
		} else {
			/* The DC should also get this message */
			ROUTER_RESULT("Message result: Local relay with CC");
		}
		send_msg_via_ipc(xml_relay_message, sys_to);
		processing_complete = TRUE & dont_cc;
		
	} else {
		if(dont_cc) {
			ROUTER_RESULT("Message result: External relay");
		} else {
			/* The DC should also get this message */
			ROUTER_RESULT("Message result: External relay with CC");
		}
		send_msg_via_ha(xml_relay_message, host_to);
		processing_complete = TRUE & dont_cc;
		
	}
	
	FNRET(processing_complete);
}

void
send_msg_via_ha(xmlNodePtr action, const char *dest_node)
{
	FNIN();
	if (action == NULL) FNOUT();

	if (validate_crm_message(action, NULL, NULL, NULL) == NULL)
	{
		cl_log(LOG_ERR,
		       "Relay message to (%s) via HA was invalid, ignoring",
		       dest_node);
		FNOUT();
	}
//	CRM_DEBUG2("Relaying message to (%s) via HA", dest_node);
	set_xml_property_copy(action, XML_ATTR_HOSTTO, dest_node);

	send_xmlha_message(fsa_cluster_conn, action);
	FNOUT();
}


void
send_msg_via_ipc(xmlNodePtr action, const char *sys)
{
	FNIN();
//	cl_log(LOG_DEBUG, "relaying msg to sub_sys=%s via IPC", sys);

	IPC_Channel *client_channel =
		(IPC_Channel*)g_hash_table_lookup (ipc_clients, sys);

	if (client_channel != NULL) {
		cl_log(LOG_DEBUG, "Sending message via channel %s.", sys);
		send_xmlipc_message(client_channel, action);
	} else if(sys != NULL && strcmp(sys, CRM_SYSTEM_CIB) == 0) {
		cl_log(LOG_ERR,
		       "Sub-system (%s) has been incorporated into the CRMd.",
		       sys);
		xml_message_debug(action, "Change the way we handle");
		relay_message(process_cib_message(action, TRUE), TRUE);
		
	} else if(sys != NULL && strcmp(sys, CRM_SYSTEM_LRMD) == 0) {

		do_lrm_invoke(A_LRM_INVOKE, C_IPC_MESSAGE,
			      fsa_state, I_MESSAGE, action);
		
	} else {
		cl_log(LOG_ERR,
		       "Unknown Sub-system (%s)... discarding message.",
		       sys);
	}    
	FNOUT();
}	

gboolean
crmd_authorize_message(xmlNodePtr root_xml_node,
		       IPC_Message *client_msg,
		       crmd_client_t *curr_client)
{
	// check the best case first
	const char *sys_from   = xmlGetProp(root_xml_node,
					    XML_ATTR_SYSFROM);
	char *uuid = NULL;
	char *client_name = NULL;
	char *major_version = NULL;
	char *minor_version = NULL;

	gpointer table_key = NULL;
	
	FNIN();

	if (sys_from != NULL) {
		gboolean can_reply = FALSE; // no-one has registered with this id
		const char *filtered_from = sys_from;

		/* The CIB can have two names on the DC */
		if(strcmp(sys_from, CRM_SYSTEM_DCIB) == 0)
			filtered_from = CRM_SYSTEM_CIB;
		
		if (g_hash_table_lookup (ipc_clients, filtered_from) != NULL)
			can_reply = TRUE;  // reply can be routed
		
		
		CRM_DEBUG3("Message reply can%s be routed from %s.",
			   can_reply?"":" not", sys_from);
		FNRET(can_reply);
	}

	// otherwise, check if it was a hello message

	cl_log(LOG_INFO,
	       "received client join msg: %s",
	       (char*)client_msg->msg_body);

	gboolean result = process_hello_message(client_msg,
						&uuid,
						&client_name,
						&major_version,
						&minor_version);

	if (result == TRUE) {
		// check version
		int mav = atoi(major_version);
		int miv = atoi(minor_version);
		if (mav < 0 || miv < 0) {
			cl_log(LOG_ERR,
			       "Client version (%d:%d) is not acceptable",
			       mav,
			       miv);
			result = FALSE;
		}
		cl_free(major_version);
		cl_free(minor_version);
	}

	if (result == TRUE) {
		/* if we already have one of those clients
		 * only applies to te, pe etc.  not admin clients
		 */

		struct crm_subsystem_s *the_subsystem = NULL;
		
		if (client_name == NULL)
			CRM_DEBUG("Client had not registered with us yet");
		else if (strcmp(CRM_SYSTEM_PENGINE, client_name) == 0) 
			the_subsystem = pe_subsystem;
		else if (strcmp(CRM_SYSTEM_TENGINE, client_name) == 0)
			the_subsystem = te_subsystem;
		else if (strcmp(CRM_SYSTEM_CIB, client_name) == 0)
			the_subsystem = cib_subsystem;

		if (the_subsystem != NULL) {
			// do we already have one?
			result = (fsa_input_register & the_subsystem->flag) == 0;
			set_bit_inplace(&fsa_input_register, the_subsystem->flag);

			if(result) {
				the_subsystem->ipc = curr_client->client_channel;
			} // else we didnt ask for the client to start

		} else if(client_name != NULL && uuid != NULL) {
			table_key = (gpointer)
				generate_hash_key(client_name, uuid);
		} else {
			result = FALSE;
			cl_log(LOG_ERR, "Bad client details (client_name=%s, uuid=%s)",
			       client_name, uuid);
		}
		
	}
	
	if(result == TRUE && table_key == NULL)
		table_key = (gpointer)cl_strdup(client_name);

	if (result == TRUE) {
		cl_log(LOG_INFO, "Accepted client %s", (char*)table_key);

		curr_client->table_key = table_key;
		curr_client->sub_sys = cl_strdup(client_name);
		curr_client->uuid = cl_strdup(uuid);
	
		g_hash_table_insert (ipc_clients,
				     table_key,
				     curr_client->client_channel);

		send_hello_message(curr_client->client_channel,
				   "n/a", CRM_SYSTEM_CRMD,
				   "0", "1");
	} else {
		cl_log(LOG_ERR, "Rejected client logon request");
		curr_client->client_channel->ch_status = IPC_DISC_PENDING;
	}
	
	if(uuid != NULL) cl_free(uuid);
	if(client_name != NULL) cl_free(client_name);

	/* hello messages should never be processed further */
	FNRET(FALSE);
}

enum crmd_fsa_input
handle_message(xmlNodePtr stored_msg)
{
	enum crmd_fsa_input next_input = I_NULL;

	const char *sys_to   = get_xml_attr(stored_msg, NULL,
					    XML_ATTR_SYSTO, TRUE);

	const char *sys_from = get_xml_attr(stored_msg, NULL,
					    XML_ATTR_SYSFROM, TRUE);

	const char *type     = get_xml_attr(stored_msg, NULL,
					    XML_ATTR_MSGTYPE, TRUE);
	
	const char *op       = get_xml_attr(stored_msg, XML_TAG_OPTIONS,
					    XML_ATTR_OP, TRUE);

//	xml_message_debug(stored_msg, "Processing message");

	if(type == NULL || op == NULL) {
		cl_log(LOG_ERR, "Ignoring message (type=%s), (op=%s)",
		       type, op);
		xml_message_debug(stored_msg, "Bad message");
		
	} else if(strcmp(type, XML_ATTR_REQUEST) == 0){
		if(strcmp(op, CRM_OPERATION_VOTE) == 0) {
			next_input = I_ELECTION;
				
		} else if(strcmp(op, CRM_OPERATION_HBEAT) == 0) {
			next_input = I_DC_HEARTBEAT;
				
		} else if(strcmp(op, CRM_OPERATION_WELCOME) == 0) {
			next_input = I_WELCOME;
				
		} else if(strcmp(op, CRM_OPERATION_ANNOUNCE) == 0) {
			next_input = I_NODE_JOIN;
/* admins may want to do this				
		} else if(strcmp(op, CRM_OPERATION_STORE) == 0 && AM_I_DC) {
			next_input = I_RELEASE_DC;
*/
		} else if(strcmp(op, CRM_OPERATION_STORE) == 0
			|| strcmp(op, CRM_OPERATION_ERASE) == 0) {
			next_input = I_CIB_OP;
			fprintf(router_strm, "Message result: CIB Op\n");

		} else if(AM_I_DC
			  && (strcmp(op, CRM_OPERATION_CREATE) == 0
			      || strcmp(op, CRM_OPERATION_UPDATE) == 0
			      || strcmp(op, CRM_OPERATION_DELETE) == 0)) {
			/* updates should only be performed on the DC */
			next_input = I_CIB_OP;
				
		} else if(strcmp(op, CRM_OPERATION_PING) == 0) {
			/* eventually do some stuff to figure out
			 * if we /are/ ok
			 */
			xmlNodePtr ping =
				createPingAnswerFragment(sys_to, "ok");
				
			xmlNodePtr wrapper = create_reply(stored_msg, ping);
			relay_message(wrapper, TRUE);
			free_xml(wrapper);
				
		} else {
			cl_log(LOG_ERR,
			       "Unexpected request (op=%s) sent to the %s",
			       op, AM_I_DC?"DC":"CRMd");
		}
		
	} else if(strcmp(type, XML_ATTR_RESPONSE) == 0) {

		if(strcmp(op, CRM_OPERATION_WELCOME) == 0) {
			next_input = I_WELCOME;
				
		} else if(strcmp(op, CRM_OPERATION_JOINACK) == 0) {
			next_input = I_WELCOME_ACK;
				
		} else if(AM_I_DC
			  && (strcmp(op, CRM_OPERATION_CREATE) == 0
			      || strcmp(op, CRM_OPERATION_UPDATE) == 0
			      || strcmp(op, CRM_OPERATION_DELETE) == 0
			      || strcmp(op, CRM_OPERATION_ERASE) == 0)) {

			// perhaps we should do somethign with these replies
			fprintf(router_strm, "Message result: CIB Reply\n");

			next_input = I_CIB_UPDATE;
			
		} else if (AM_I_DC && strcmp(op, CRM_OPERATION_STORE) == 0) {

			/* if there was any result, we need to merge it back
			 * into our (the DC) copy of the CIB
			 */
			xmlNodePtr data =
				find_xml_node(stored_msg, XML_TAG_FRAGMENT);

			const char *status =
				get_xml_attr(stored_msg, XML_TAG_OPTIONS,
					     XML_ATTR_RESULT, TRUE);

			if(status != NULL
			   && strcmp(status, "ok") == 0
			   && data != NULL) {

				CRM_DEBUG("Updating the CIB with the results of a store");
				
				/* do a replace or an update? */
				xmlNodePtr resp = process_cib_request(
					CRM_OPERATION_UPDATE, NULL, data);

				// TODO: check the return status

				next_input = I_CIB_UPDATE;
				
				free_xml(resp);
				

			} else if(data != NULL) {
				cl_log(LOG_ERR,
				       "Store failed with response [%s]",
				       status);
				
			} else {
				CRM_DEBUG3("Status=%s, data=%p",
					  status, data);
			}
			


		} else if(AM_I_DC
			  && strcmp(sys_from, CRM_SYSTEM_CIB) == 0
			  && strcmp(op, CRM_OPERATION_FORWARD) == 0) {
				
			/* this is a reply to our earlier command
			 * Send it to the relevant node(s)
			 */
			const char *uname =
				get_xml_attr(stored_msg, XML_TAG_OPTIONS,
					     "forward_to", FALSE);

			xmlNodePtr data = find_xml_node(stored_msg,
							XML_TAG_FRAGMENT);

			xmlNodePtr local_options = NULL;
			
			/* If this is part of join request processing,
			 * ask for the status section, otherwise just blast
			 * it down to them.
			 */
			if(uname != NULL) {
				local_options = set_xml_attr(NULL,
							     XML_TAG_OPTIONS,
							     XML_ATTR_VERBOSE,
							     "true",
							     TRUE);
			}
			
			send_request(local_options, data, CRM_OPERATION_STORE,
				     uname, CRM_SYSTEM_CRMD);

			free_xml(local_options);
			
		} else {
			cl_log(LOG_ERR,
			       "Unexpected response (op=%s) sent to the %s",
			       op, AM_I_DC?"DC":"CRMd");
		}
	} else {
		cl_log(LOG_ERR, "Unexpected message type %s", type);
			
	}

/* 	CRM_DEBUG3("%s: Next input is %s", __FUNCTION__, */
/* 		   fsa_input2string(next_input)); */
	
		
	return next_input;
		
}


void lrm_op_callback (lrm_op_t* op)
{
	CRM_DEBUG("In lrm_op_callback()");

	s_crmd_fsa(C_LRM_OP_CALLBACK, I_LRM_EVENT, op);
}

void lrm_monitor_callback (lrm_mon_t* monitor)
{
	CRM_DEBUG("In lrm_monitor_callback()");
	s_crmd_fsa(C_LRM_MONITOR_CALLBACK, I_LRM_EVENT, monitor);
}


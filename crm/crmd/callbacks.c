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

#include <heartbeat.h>

#include <hb_api.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <crm/cib.h>

#include <crmd.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <crm/dmalloc_wrapper.h>

#ifdef MSG_LOG
FILE *msg_in_strm = NULL;
FILE *msg_ipc_strm = NULL;
#endif

xmlNodePtr find_xml_in_hamessage(const HA_Message * msg);
void crmd_ha_connection_destroy(gpointer user_data);

void
crmd_ha_msg_callback(const HA_Message * msg, void* private_data)
{
	ha_msg_input_t *new_input = NULL;

	const char *from = ha_msg_value(msg, F_ORIG);
	const char *seq  = ha_msg_value(msg, F_SEQ);
	const char *op   = ha_msg_value(msg, F_CRM_TASK);

	const char *sys_to   = ha_msg_value(msg, F_CRM_SYS_TO);
	const char *sys_from = ha_msg_value(msg, F_CRM_SYS_FROM);

#ifdef MSG_LOG
	if(msg_in_strm == NULL) {
		msg_in_strm = fopen(DEVEL_DIR"/inbound.log", "w");
	}
#endif

	CRM_ASSERT(from != NULL);
	
#ifdef MSG_LOG
/* 	xml_text = dump_xml_formatted(root_xml_node); */
/* 	fprintf(msg_in_strm, "[%s (%s:%s)]\t%s\n", crm_str(from), */
/* 		seq, ha_msg_value(msg, F_TYPE), xml_text); */
/* 	fflush(msg_in_strm); */
/* 	crm_free(xml_text); */
#endif

	if(AM_I_DC
	   && safe_str_eq(sys_from, CRM_SYSTEM_DC)
	   && safe_str_neq(from, fsa_our_uname)) {
		crm_err("Another DC detected");
		crm_log_message(LOG_ERR, msg);
		new_input = new_ha_msg_input(msg);
		register_fsa_input(C_HA_MESSAGE, I_ELECTION, new_input);

	} else if(safe_str_eq(sys_to, CRM_SYSTEM_DC) && AM_I_DC == FALSE) {
		crm_verbose("Ignoring message for the DC [F_SEQ=%s]", seq);
#ifdef MSG_LOG
		fprintf(msg_in_strm,
			"Ignoring message for the DC [F_SEQ=%s]", seq);
#endif
		return;

	} else if(safe_str_eq(from, fsa_our_uname)
		  && safe_str_eq(op, CRM_OP_VOTE)) {
		crm_verbose("Ignoring our own vote [F_SEQ=%s]", seq);
#ifdef MSG_LOG
		fprintf(msg_in_strm,
			"Ignoring our own heartbeat [F_SEQ=%s]", seq);
#endif
		return;
		
	} else if(AM_I_DC && safe_str_eq(op, CRM_OP_HBEAT)) {
		crm_verbose("Ignoring our own heartbeat [F_SEQ=%s]", seq);
#ifdef MSG_LOG
		fprintf(msg_in_strm,
			"Ignoring our own heartbeat [F_SEQ=%s]", seq);
#endif
		return;

	} else {
		crm_debug("Processing message");
		crm_log_message(LOG_MSG, msg);
		new_input = new_ha_msg_input(msg);
		register_fsa_input(C_HA_MESSAGE, I_ROUTER, new_input);
	}

	
#if 0
	if(ha_msg_value(msg, XML_ATTR_REFERENCE) == NULL) {
		ha_msg_add(new_input->msg, XML_ATTR_REFERENCE, seq);
	}
#endif

	delete_ha_msg_input(new_input);
	s_crmd_fsa(C_HA_MESSAGE);

	return;
}

/*
 * Apparently returning TRUE means "stay connected, keep doing stuff".
 * Returning FALSE means "we're all done, close the connection"
 */
gboolean
crmd_ipc_msg_callback(IPC_Channel *client, gpointer user_data)
{
	int lpc = 0;
	IPC_Message *msg = NULL;
	ha_msg_input_t *new_input = NULL;
	gboolean hack_return_good = TRUE;
	crmd_client_t *curr_client = (crmd_client_t*)user_data;

	crm_verbose("Processing IPC message from %s",
		   curr_client->table_key);

#ifdef MSG_LOG
	if(msg_ipc_strm == NULL) {
		msg_ipc_strm = fopen(DEVEL_DIR"/inbound.ipc.log", "w");
	}
#endif

	while(client->ops->is_message_pending(client)) {
		if (client->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (client->ops->recv(client, &msg) != IPC_OK) {
			perror("Receive failure:");
#ifdef MSG_LOG
			fprintf(msg_ipc_strm, "[%s] [receive failure]\n",
				curr_client->table_key);
			fflush(msg_in_strm);
#endif
			return !hack_return_good;
		}
		if (msg == NULL) {
#ifdef MSG_LOG
			fprintf(msg_ipc_strm, "[%s] [__nothing__]\n",
				curr_client->table_key);
			fflush(msg_in_strm);
#endif
			crm_err("No message this time");
			continue;
		}

		lpc++;
		new_input = new_ipc_msg_input(msg);
		msg->msg_done(msg);
		
		crm_verbose("Processing msg from %s", curr_client->table_key);
		crm_log_message(LOG_MSG, new_input->msg);
	
#ifdef MSG_LOG
		{
			char *buffer = NULL;
			fprintf(msg_ipc_strm, "[%s] [text=%s]\n",
				curr_client->table_key, buffer);
			fflush(msg_in_strm);
		}
#endif
		crmd_authorize_message(new_input, curr_client);
		delete_ha_msg_input(new_input);
		
		msg = NULL;
		new_input = NULL;
	}

	crm_verbose("Processed %d messages", lpc);
    
	if (client->ch_status == IPC_DISCONNECT) {
		crm_info("received HUP from %s",
			 curr_client->table_key);
		if (curr_client != NULL) {
			struct crm_subsystem_s *the_subsystem = NULL;
			
			if (curr_client->sub_sys == NULL) {
				crm_warn("Client hadn't registered with us yet");

			} else if (strcmp(CRM_SYSTEM_PENGINE,
					  curr_client->sub_sys) == 0) {
				the_subsystem = pe_subsystem;

			} else if (strcmp(CRM_SYSTEM_TENGINE,
					  curr_client->sub_sys) == 0) {
				the_subsystem = te_subsystem;

			} else if (strcmp(CRM_SYSTEM_CIB,
					  curr_client->sub_sys) == 0){
				the_subsystem = cib_subsystem;
			}
			
			if(the_subsystem != NULL) {
				cleanup_subsystem(the_subsystem);
			} /* else that was a transient client */
			
			if (curr_client->table_key != NULL) {
				/*
				 * Key is destroyed below:
				 *	curr_client->table_key
				 * Value is cleaned up by:
				 *	G_main_del_IPC_Channel
				 */
				g_hash_table_remove(
					ipc_clients, curr_client->table_key);
			}


			if(curr_client->client_source != NULL) {
				gboolean det = G_main_del_IPC_Channel(
					curr_client->client_source);
			
				crm_verbose("crm_client was %s detached",
					   det?"successfully":"not");
			}
			
			crm_free(curr_client->table_key);
			crm_free(curr_client->sub_sys);
			crm_free(curr_client->uuid);
			crm_free(curr_client);
		}
		return !hack_return_good;
	}
    
	return hack_return_good;
}


void
lrm_op_callback(lrm_op_t* op)
{
	/* todo: free op->rsc */
	crm_debug("received callback");
	register_fsa_input(C_LRM_OP_CALLBACK, I_LRM_EVENT, op);
	s_crmd_fsa(C_LRM_OP_CALLBACK);
}

void
crmd_ha_status_callback(
	const char *node, const char * status,	void* private_data)
{
	xmlNodePtr update      = NULL;

	crm_debug("received callback");
	crm_notice("Status update: Node %s now has status [%s]\n",node,status);

	if(AM_I_DC == FALSE) {
		crm_debug("Got nstatus callback in non-DC mode");
		return;
		
	} else if(safe_str_neq(status, DEADSTATUS)) {
		crm_debug("nstatus callback was not for a dead node");
		return;
	}

	/* this node is taost */
	update = create_node_state(
		node, node, status, NULL, NULL, NULL, NULL);
	
	set_xml_property_copy(
		update, XML_CIB_ATTR_CLEAR_SHUTDOWN, XML_BOOLEAN_TRUE);
	
	update_local_cib(create_cib_fragment(update, NULL));
	s_crmd_fsa(C_FSA_INTERNAL);
	free_xml(update);
}


void
crmd_client_status_callback(const char * node, const char * client,
		 const char * status, void * private)
{
	const char    *join = NULL;
	const char   *extra = NULL;
	xmlNodePtr   update = NULL;

	crm_debug("received callback");

	set_bit_inplace(fsa_input_register, R_PEER_DATA);
	
	if(safe_str_eq(status, JOINSTATUS)){
		status = ONLINESTATUS;
		extra  = XML_CIB_ATTR_CLEAR_SHUTDOWN;

	} else if(safe_str_eq(status, LEAVESTATUS)){
		status = OFFLINESTATUS;
		join   = CRMD_JOINSTATE_DOWN;
		extra  = XML_CIB_ATTR_CLEAR_SHUTDOWN;
	}
	
	crm_notice("Status update: Client %s/%s now has status [%s]\n",
		   node, client, status);

	if(AM_I_DC == FALSE) {
		crm_debug("Got client status callback in non-DC mode");
		return;
		
	}
	
	update = create_node_state(
		node, node, NULL, NULL, status, join, NULL);
	
	set_xml_property_copy(update, extra, XML_BOOLEAN_TRUE);
	
	update_local_cib(create_cib_fragment(update, NULL));

	s_crmd_fsa(C_CRMD_STATUS_CALLBACK);
	free_xml(update);
}


xmlNodePtr
find_xml_in_hamessage(const HA_Message * msg)
{
	const char *xml;
   	xmlDocPtr doc;
	xmlNodePtr root;

	
	if (msg == NULL) {
		crm_info("**** ha_crm_msg_callback called on a NULL message");
		return NULL;
	}

#if 0
	crm_debug("[F_TYPE=%s]", ha_msg_value(msg, F_TYPE));
	crm_debug("[F_ORIG=%s]", ha_msg_value(msg, F_ORIG));
	crm_debug("[F_TO=%s]",   ha_msg_value(msg, F_TO));
	crm_debug("[F_COMMENT=%s]", ha_msg_value(msg, F_COMMENT));
	crm_debug("[F_XML=%s]",  ha_msg_value(msg, F_CRM_DATA));
/*    crm_debug("[F_=%s]", ha_msg_value(ha_msg, F_)); */
#endif
	
	if (strcmp(T_CRM, ha_msg_value(msg, F_TYPE)) != 0) {
		crm_info("Received a (%s) message by mistake.",
		       ha_msg_value(msg, F_TYPE));
		return NULL;
	}
	xml = ha_msg_value(msg, F_CRM_DATA);
	if (xml == NULL) {
		crm_info("No XML attached to this message.");
		return NULL;
	}
	doc = xmlParseMemory(xml, strlen(xml));
	if (doc == NULL) {
		crm_info("XML Buffer was not valid.");
		return NULL;
	}

	root = xmlDocGetRootElement(doc);
	if (root == NULL) {
		crm_info("Root node was NULL.");
		return NULL;
	}
	return root;
}

gboolean lrm_dispatch(int fd, gpointer user_data)
{
	int rc = 0;
	ll_lrm_t *lrm = (ll_lrm_t*)user_data;
	crm_debug("received callback");
	rc = lrm->lrm_ops->rcvmsg(lrm, FALSE);
	if(rc != HA_OK) {
		return FALSE;
	}
	return TRUE;
}

/* #define MAX_EMPTY_CALLBACKS 20 */
/* int empty_callbacks = 0; */

gboolean
crmd_ha_msg_dispatch(IPC_Channel *channel, gpointer user_data)
{
	int lpc = 0;
	ll_cluster_t *hb_cluster = (ll_cluster_t*)user_data;

	while(hb_cluster->llc_ops->msgready(hb_cluster)) {
 		lpc++; 
		/* invoke the callbacks but dont block */
		hb_cluster->llc_ops->rcvmsg(hb_cluster, 0);
	}

	crm_trace("%d HA messages dispatched", lpc);

	if (channel && (channel->ch_status == IPC_DISCONNECT)) {
		crm_crit("Lost connection to heartbeat service.");
		return FALSE;
	}
    
	return TRUE;
}

void
crmd_ha_connection_destroy(gpointer user_data)
{
	crm_crit("Heartbeat has left us");
	/* this is always an error */
	/* feed this back into the FSA */
	register_fsa_input(C_HA_DISCONNECT, I_ERROR, NULL);
	s_crmd_fsa(C_HA_DISCONNECT);
}


gboolean
crmd_client_connect(IPC_Channel *client_channel, gpointer user_data)
{
	if (client_channel == NULL) {
		crm_err("Channel was NULL");

	} else if (client_channel->ch_status == IPC_DISCONNECT) {
		crm_err("Channel was disconnected");

	} else {
		crmd_client_t *blank_client = NULL;
		crm_debug("Channel connected");
		crm_malloc(blank_client, sizeof(crmd_client_t));
	
		if (blank_client == NULL) {
			return FALSE;
		}
		
		client_channel->ops->set_recv_qlen(client_channel, 100);
		client_channel->ops->set_send_qlen(client_channel, 100);
	
		blank_client->client_channel = client_channel;
		blank_client->sub_sys   = NULL;
		blank_client->uuid      = NULL;
		blank_client->table_key = NULL;
	
		blank_client->client_source =
			G_main_add_IPC_Channel(
				G_PRIORITY_LOW, client_channel,
				FALSE,  crmd_ipc_msg_callback,
				blank_client, default_ipc_connection_destroy);
	}
    
	return TRUE;
}


gboolean ccm_dispatch(int fd, gpointer user_data)
{
	int rc = 0;
	oc_ev_t *ccm_token = (oc_ev_t*)user_data;
	crm_debug("received callback");	
	rc = oc_ev_handle_event(ccm_token);
	if(0 == rc) {
		return TRUE;

	} else {
		crm_err("CCM connection appears to have failed: rc=%d.", rc);
		register_fsa_input(C_CCM_CALLBACK, I_ERROR, NULL);
		s_crmd_fsa(C_CCM_CALLBACK);
		return FALSE;
	}
}


void 
crmd_ccm_msg_callback(
	oc_ed_t event, void *cookie, size_t size, const void *data)
{
	struct crmd_ccm_data_s *event_data = NULL;
	crm_debug("received callback");
	
	if(data != NULL) {
		crm_malloc(event_data, sizeof(struct crmd_ccm_data_s));

		if(event_data != NULL) {
			event_data->event = &event;
			event_data->oc = copy_ccm_oc_data(
				(const oc_ev_membership_t *)data);

			crm_debug("Sending callback to the FSA");
			register_fsa_input(
				C_CCM_CALLBACK, I_CCM_EVENT,
				(void*)event_data);

			s_crmd_fsa(C_CCM_CALLBACK);
			
			event_data->event = NULL;
			event_data->oc = NULL;

			crm_free(event_data);
		}

	} else {
		crm_info("CCM Callback with NULL data... "
		       "I dont /think/ this is bad");
	}
	
	oc_ev_callback_done(cookie);
	
	return;
}

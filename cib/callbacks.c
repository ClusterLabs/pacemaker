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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <clplumbing/uids.h>
#include <clplumbing/cl_uuid.h>
#include <clplumbing/Gmain_timeout.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>
#include <crm/common/ctrl.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <cibio.h>
#include <callbacks.h>
#include <cibmessages.h>
#include <notify.h>
#include <heartbeat.h>
#include "common.h"

extern GMainLoop*  mainloop;
extern gboolean cib_shutdown_flag;
extern gboolean stand_alone;
extern const char* cib_root;
#if SUPPORT_HEARTBEAT
extern ll_cluster_t *hb_conn;
#endif

extern void cib_ha_connection_destroy(gpointer user_data);

extern enum cib_errors cib_update_counter(
	xmlNode *xml_obj, const char *field, gboolean reset);

extern void GHFunc_count_peers(
	gpointer key, gpointer value, gpointer user_data);

void initiate_exit(void);
void terminate_cib(const char *caller);
gint cib_GCompareFunc(gconstpointer a, gconstpointer b);
gboolean can_write(int flags);
void send_cib_replace(const xmlNode *sync_request, const char *host);
void cib_process_request(
	xmlNode *request, gboolean privileged, gboolean force_synchronous,
	gboolean from_peer, cib_client_t *cib_client);
void cib_common_callback_worker(xmlNode *op_request, cib_client_t *cib_client,
				gboolean force_synchronous, gboolean privileged);

extern GHashTable *client_list;

int        next_client_id  = 0;
extern const char *cib_our_uname;
extern unsigned long cib_num_ops, cib_num_local, cib_num_updates, cib_num_fail;
extern unsigned long cib_bad_connects, cib_num_timeouts;
extern longclock_t cib_call_time;
extern enum cib_errors cib_status;


int send_via_callback_channel(xmlNode *msg, const char *token);

enum cib_errors cib_process_command(
	xmlNode *request, xmlNode **reply,
	xmlNode **cib_diff, gboolean privileged);

gboolean cib_common_callback(IPC_Channel *channel, cib_client_t *cib_client,
			     gboolean force_synchronous, gboolean privileged);

gboolean cib_process_disconnect(IPC_Channel *channel, cib_client_t *cib_client);
int num_clients = 0;

static void
cib_ipc_connection_destroy(gpointer user_data)
{
	cib_client_t *cib_client = user_data;
	
	/* cib_process_disconnect */

	if(cib_client == NULL) {
		crm_debug_4("Destroying %p", user_data);
		return;
	}

	if(cib_client->source != NULL) {
		crm_debug_4("Deleting %s (%p) from mainloop",
			    cib_client->name, cib_client->source);
		G_main_del_IPC_Channel(cib_client->source); 
		cib_client->source = NULL;
	}
	
	crm_debug_3("Destroying %s (%p)", cib_client->name, user_data);
	num_clients--;
	crm_debug_2("Num unfree'd clients: %d", num_clients);
	crm_free(cib_client->name);
	crm_free(cib_client->callback_id);
	crm_free(cib_client->id);
	crm_free(cib_client);
	crm_debug_4("Freed the cib client");

	return;
}

gboolean
cib_client_connect(IPC_Channel *channel, gpointer user_data)
{
	cl_uuid_t client_id;
	xmlNode *reg_msg = NULL;
	cib_client_t *new_client = NULL;
	char uuid_str[UU_UNPARSE_SIZEOF];
	const char *channel_name = user_data;
	gboolean (*callback)(IPC_Channel *channel, gpointer user_data);
	
	crm_debug_3("Connecting channel");

	if (channel == NULL) {
		crm_err("Channel was NULL");
		cib_bad_connects++;
		return FALSE;

	} else if (channel->ch_status != IPC_CONNECT) {
		crm_err("Channel was disconnected");
		cib_bad_connects++;
		return FALSE;
		
	} else if(channel_name == NULL) {
		crm_err("user_data must contain channel name");
		cib_bad_connects++;
		return FALSE;
		
	} else if(cib_shutdown_flag) {
		crm_info("Ignoring new client [%d] during shutdown",
			channel->farside_pid);
		return FALSE;		
	}

	callback = cib_ro_callback;
	if(safe_str_eq(channel_name, cib_channel_rw)) {
		callback = cib_rw_callback;
	}
	
	crm_malloc0(new_client, sizeof(cib_client_t));
	num_clients++;
	new_client->channel = channel;
	new_client->channel_name = channel_name;
	
	crm_debug_3("Created channel %p for channel %s",
		    new_client, new_client->channel_name);
	
	channel->ops->set_recv_qlen(channel, 1024);
	channel->ops->set_send_qlen(channel, 1024);
	
	new_client->source = G_main_add_IPC_Channel(
	    G_PRIORITY_DEFAULT, channel, FALSE, callback,
	    new_client, cib_ipc_connection_destroy);
	
	crm_debug_3("Channel %s connected for client %s",
		    new_client->channel_name, new_client->id);
	
	cl_uuid_generate(&client_id);
	cl_uuid_unparse(&client_id, uuid_str);

	CRM_CHECK(new_client->id == NULL, crm_free(new_client->id));
	new_client->id = crm_strdup(uuid_str);
	
	/* make sure we can find ourselves later for sync calls
	 * redirected to the master instance
	 */
	g_hash_table_insert(client_list, new_client->id, new_client);
	
	reg_msg = create_xml_node(NULL, "callback");
	crm_xml_add(reg_msg, F_CIB_OPERATION, CRM_OP_REGISTER);
	crm_xml_add(reg_msg, F_CIB_CLIENTID,  new_client->id);
	
	send_ipc_message(channel, reg_msg);		
	free_xml(reg_msg);
	
	return TRUE;
}

gboolean
cib_rw_callback(IPC_Channel *channel, gpointer user_data)
{
	gboolean result = FALSE;
	result = cib_common_callback(channel, user_data, FALSE, TRUE);
	return result;
}

gboolean
cib_ro_callback(IPC_Channel *channel, gpointer user_data)
{
	gboolean result = FALSE;
	result = cib_common_callback(channel, user_data, FALSE, FALSE);
	return result;
}

void
cib_common_callback_worker(xmlNode *op_request, cib_client_t *cib_client,
			   gboolean force_synchronous, gboolean privileged)
{
	longclock_t call_stop = 0;
	longclock_t call_start = 0;
	
	const char *op = crm_element_value(op_request, F_CIB_OPERATION);

	if(crm_str_eq(op, CRM_OP_REGISTER, TRUE)) {
	    return;
	    
	} else if(crm_str_eq(op, T_CIB_NOTIFY, TRUE)) {
	    /* Update the notify filters for this client */
	    int on_off = 0;
	    const char *type = crm_element_value(op_request, F_CIB_NOTIFY_TYPE);;
	    crm_element_value_int(op_request, F_CIB_NOTIFY_ACTIVATE, &on_off);
	    
	    crm_debug("Setting %s callbacks for %s (%s): %s",
		     type, cib_client->name, cib_client->id, on_off?"on":"off");
	    
	    if(safe_str_eq(type, T_CIB_POST_NOTIFY)) {
		cib_client->post_notify = on_off;
		
	    } else if(safe_str_eq(type, T_CIB_PRE_NOTIFY)) {
		cib_client->pre_notify = on_off;
		
	    } else if(safe_str_eq(type, T_CIB_UPDATE_CONFIRM)) {
		cib_client->confirmations = on_off;
		
	    } else if(safe_str_eq(type, T_CIB_DIFF_NOTIFY)) {
		cib_client->diffs = on_off;
		
	    } else if(safe_str_eq(type, T_CIB_REPLACE_NOTIFY)) {
		cib_client->replace = on_off;
	    }
	    return;
	}
	
	cib_client->num_calls++;
	call_start = time_longclock();
	cib_process_request(
	    op_request, force_synchronous, privileged, FALSE, cib_client);

	call_stop = time_longclock();
	cib_call_time += (call_stop - call_start);
}

gboolean
cib_common_callback(IPC_Channel *channel, cib_client_t *cib_client,
		    gboolean force_synchronous, gboolean privileged)
{
	int lpc = 0;
	const char *value = NULL;
	xmlNode *op_request = NULL;
	gboolean keep_channel = TRUE;

	CRM_CHECK(cib_client != NULL, crm_err("Invalid client"); return FALSE);
	CRM_CHECK(cib_client->id != NULL, crm_err("Invalid client: %p", cib_client); return FALSE);

	/*
	 * Do enough work to make entering worthwhile
	 * But don't allow a single client to monopolize the CIB
	 */
	while(lpc < 5
	      && IPC_ISRCONN(channel)
	      && channel->ops->is_message_pending(channel)) {

		lpc++;
		op_request = xmlfromIPC(channel, MAX_IPC_DELAY);
		if (op_request == NULL) {
			break;
		}

		if(cib_client->name == NULL) {
		    value = crm_element_value(op_request, F_CIB_CLIENTNAME);
		    if(value == NULL) {
			cib_client->name = crm_itoa(channel->farside_pid);
		    } else {
			cib_client->name = crm_strdup(value);
		    }
		}

		crm_xml_add(op_request, F_CIB_CLIENTID, cib_client->id);
		crm_xml_add(op_request, F_CIB_CLIENTNAME, cib_client->name);
		/* crm_log_xml(LOG_MSG, "Client[inbound]", op_request); */

		if(cib_client->callback_id == NULL) {
		    value = crm_element_value(op_request, F_CIB_CALLBACK_TOKEN);
		    if(value != NULL) {
			cib_client->callback_id = crm_strdup(value);

		    } else {
			cib_client->callback_id = crm_strdup(cib_client->id);			
		    }
		}
		
		cib_common_callback_worker(
			op_request, cib_client, force_synchronous, privileged);

		free_xml(op_request);
	}

	if(channel->ch_status != IPC_CONNECT) {
		crm_debug_2("Client disconnected");
		keep_channel = cib_process_disconnect(channel, cib_client);	
	}

	return keep_channel;
}

extern void cib_send_remote_msg(void *session, xmlNode *msg);

static void
do_local_notify(xmlNode *notify_src, const char *client_id,
		gboolean sync_reply, gboolean from_peer) 
{
	/* send callback to originating child */
	cib_client_t *client_obj = NULL;
	enum cib_errors local_rc = cib_ok;

	crm_debug_2("Performing notification");

	if(client_id != NULL) {
		client_obj = g_hash_table_lookup(client_list, client_id);
	} else {
		crm_debug_2("No client to sent the response to."
			    "  F_CIB_CLIENTID not set.");
	}
	
	crm_debug_3("Sending callback to request originator");
	if(client_obj == NULL) {
		local_rc = cib_reply_failed;
		
	} else {
		const char *client_id = client_obj->callback_id;
		crm_debug_2("Sending %ssync response to %s %s",
			    sync_reply?"":"an a-",
			    client_obj->name,
			    from_peer?"(originator of delegated request)":"");
		
		if(sync_reply) {
			client_id = client_obj->id;
		}
		local_rc = send_via_callback_channel(notify_src, client_id);
	} 
	
	if(local_rc != cib_ok && client_obj != NULL) {
		crm_warn("%sSync reply to %s failed: %s",
			 sync_reply?"":"A-",
			 client_obj?client_obj->name:"<unknown>", cib_error2string(local_rc));
	}
}

static void
parse_local_options(
	cib_client_t *cib_client, int call_type, int call_options, const char *host, const char *op, 
	gboolean *local_notify, gboolean *needs_reply, gboolean *process, gboolean *needs_forward) 
{
	if(cib_op_modifies(call_type)
	   && !(call_options & cib_inhibit_bcast)) {
		/* we need to send an update anyway */
		*needs_reply = TRUE;
	} else {
		*needs_reply = FALSE;
	}
	
	if(host == NULL && (call_options & cib_scope_local)) {
		crm_debug_2("Processing locally scoped %s op from %s",
			    op, cib_client->name);
		*local_notify = TRUE;
		
	} else if(host == NULL && cib_is_master) {
		crm_debug_2("Processing master %s op locally from %s",
			    op, cib_client->name);
		*local_notify = TRUE;
		
	} else if(safe_str_eq(host, cib_our_uname)) {
		crm_debug_2("Processing locally addressed %s op from %s",
			    op, cib_client->name);
		*local_notify = TRUE;

	} else if(stand_alone) {
		*needs_forward = FALSE;
		*local_notify = TRUE;
		*process = TRUE;
		
	} else {
		crm_debug_2("%s op from %s needs to be forwarded to %s",
			    op, cib_client->name,
			    host?host:"the master instance");
		*needs_forward = TRUE;
		*process = FALSE;
	}		
}

static gboolean
parse_peer_options(
	int call_type, xmlNode *request, 
	gboolean *local_notify, gboolean *needs_reply, gboolean *process, gboolean *needs_forward) 
{
	const char *op         = crm_element_value(request, F_CIB_OPERATION);
	const char *originator = crm_element_value(request, F_ORIG);
	const char *host       = crm_element_value(request, F_CIB_HOST);
	const char *reply_to   = crm_element_value(request, F_CIB_ISREPLY);
	const char *update     = crm_element_value(request, F_CIB_GLOBAL_UPDATE);
	const char *delegated  = crm_element_value(request, F_CIB_DELEGATED);

	if(safe_str_eq(op, "cib_shutdown_req")) {
		if(reply_to != NULL) {
			crm_debug("Processing %s from %s", op, host);
			*needs_reply = FALSE;
			
		} else {
			crm_debug("Processing %s reply from %s", op, host);
		}
		return TRUE;
		
	} else if(crm_is_true(update) && safe_str_eq(reply_to, cib_our_uname)) {
		crm_debug_2("Processing global/peer update from %s"
			    " that originated from us", originator);
		*needs_reply = FALSE;
		if(crm_element_value(request, F_CIB_CLIENTID) != NULL) {
			*local_notify = TRUE;
		}
		return TRUE;
		
	} else if(crm_is_true(update)) {
		crm_debug_2("Processing global/peer update from %s", originator);
		*needs_reply = FALSE;
		return TRUE;

	} else if(host != NULL && safe_str_eq(host, cib_our_uname)) {
		crm_debug_2("Processing request sent to us from %s", originator);
		return TRUE;

	} else if(delegated != NULL && cib_is_master == TRUE) {
		crm_debug_2("Processing request sent to master instance from %s",
			originator);
		return TRUE;

	} else if(reply_to != NULL && safe_str_eq(reply_to, cib_our_uname)) {
		crm_debug_2("Forward reply sent from %s to local clients",
			  originator);
		*process = FALSE;
		*needs_reply = FALSE;
		*local_notify = TRUE;
		return TRUE;

	} else if(delegated != NULL) {
		crm_debug_2("Ignoring msg for master instance");

	} else if(host != NULL) {
		/* this is for a specific instance and we're not it */
		crm_debug_2("Ignoring msg for instance on %s", crm_str(host));
		
	} else if(reply_to == NULL && cib_is_master == FALSE) {
		/* this is for the master instance and we're not it */
		crm_debug_2("Ignoring reply to %s", crm_str(reply_to));
		
	} else {
		crm_err("Nothing for us to do?");
		crm_log_xml(LOG_ERR, "Peer[inbound]", request);
	}

	return FALSE;
}

		
static void
forward_request(xmlNode *request, cib_client_t *cib_client, int call_options)
{
	xmlNode *forward_msg = NULL;
	const char *op         = crm_element_value(request, F_CIB_OPERATION);
	const char *host       = crm_element_value(request, F_CIB_HOST);

	forward_msg = cib_msg_copy(request, TRUE);
	crm_xml_add(forward_msg, F_CIB_DELEGATED, cib_our_uname);
	
	if(host != NULL) {
		crm_debug_2("Forwarding %s op to %s", op, host);
		send_cluster_message(host, crm_msg_cib, forward_msg, FALSE);
		
	} else {
		crm_debug_2("Forwarding %s op to master instance", op);
		send_cluster_message(NULL, crm_msg_cib, forward_msg, FALSE);
	}
	
	if(call_options & cib_discard_reply) {
		crm_debug_2("Client not interested in reply");
	} 
	free_xml(forward_msg);
}

static void
send_peer_reply(
	xmlNode *msg, xmlNode *result_diff, const char *originator, gboolean broadcast)
{
	xmlNode *reply_copy = NULL;

	CRM_ASSERT(msg != NULL);

 	reply_copy = cib_msg_copy(msg, TRUE);
	
	if(broadcast) {
		/* this (successful) call modified the CIB _and_ the
		 * change needs to be broadcast...
		 *   send via HA to other nodes
		 */
		int diff_add_updates = 0;
		int diff_add_epoch   = 0;
		int diff_add_admin_epoch = 0;
		
		int diff_del_updates = 0;
		int diff_del_epoch   = 0;
		int diff_del_admin_epoch = 0;

		char *digest = NULL;
		
		cib_diff_version_details(
			result_diff,
			&diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates, 
			&diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

		crm_debug_2("Sending update diff %d.%d.%d -> %d.%d.%d",
			    diff_del_admin_epoch,diff_del_epoch,diff_del_updates,
			    diff_add_admin_epoch,diff_add_epoch,diff_add_updates);

		crm_xml_add(reply_copy, F_CIB_ISREPLY, originator);
		crm_xml_add(reply_copy, F_CIB_GLOBAL_UPDATE, XML_BOOLEAN_TRUE);
		crm_xml_add(reply_copy, F_CIB_OPERATION, CIB_OP_APPLY_DIFF);

		digest = calculate_xml_digest(the_cib, FALSE, TRUE);
		crm_xml_add(result_diff, XML_ATTR_DIGEST, digest);
/* 		crm_log_xml_debug(the_cib, digest); */
		crm_free(digest);
		
 		add_message_xml(reply_copy, F_CIB_UPDATE_DIFF, result_diff);
		crm_log_xml(LOG_DEBUG_3, "copy", reply_copy);
		send_cluster_message(NULL, crm_msg_cib, reply_copy, TRUE);
		
	} else if(originator != NULL) {
		/* send reply via HA to originating node */
		crm_debug_2("Sending request result to originator only");
		crm_xml_add(reply_copy, F_CIB_ISREPLY, originator);
		send_cluster_message(originator, crm_msg_cib, reply_copy, FALSE);
	}
	
	free_xml(reply_copy);
}
	
void
cib_process_request(
	xmlNode *request, gboolean force_synchronous, gboolean privileged,
	gboolean from_peer, cib_client_t *cib_client) 
{
	int call_type    = 0;
	int call_options = 0;

	gboolean process = TRUE;		
	gboolean is_update = TRUE;
	gboolean needs_reply = TRUE;
	gboolean local_notify = FALSE;
	gboolean needs_forward = FALSE;
	gboolean global_update = crm_is_true(crm_element_value(request, F_CIB_GLOBAL_UPDATE));
	
	xmlNode *op_reply = NULL;
	xmlNode *result_diff = NULL;

	enum cib_errors rc = cib_ok;
	const char *op         = crm_element_value(request, F_CIB_OPERATION);
	const char *originator = crm_element_value(request, F_ORIG);
	const char *host       = crm_element_value(request, F_CIB_HOST);

	crm_debug_4("%s Processing msg %s",
		  cib_our_uname, crm_element_value(request, F_SEQ));

	cib_num_ops++;
	if(cib_num_ops == 0) {
		cib_num_fail = 0;
		cib_num_local = 0;
		cib_num_updates = 0;
		crm_info("Stats wrapped around");
	}
	
	if(host != NULL && strlen(host) == 0) {
		host = NULL;
	}	

	crm_element_value_int(request, F_CIB_CALLOPTS, &call_options);
	if(force_synchronous) {
		call_options |= cib_sync_call;
	}
	
	crm_debug_2("Processing %s message (%s) for %s...",
		    from_peer?"peer":"local",
		    from_peer?originator:cib_our_uname, host?host:"master");

	rc = cib_get_operation_id(op, &call_type);
	if(rc != cib_ok) {
		/* TODO: construct error reply? */
		crm_err("Pre-processing of command failed: %s", cib_error2string(rc));
		return;
	}
	
	is_update = cib_op_modifies(call_type);
	if(is_update) {
		cib_num_updates++;
	}
	
	if(from_peer == FALSE) {
		parse_local_options(cib_client, call_type, call_options, host, op,
				    &local_notify, &needs_reply, &process, &needs_forward);
		
	} else if(parse_peer_options(call_type, request, &local_notify,
				     &needs_reply, &process, &needs_forward) == FALSE) {
		return;
	}
	crm_debug_3("Finished determining processing actions");

	if(call_options & cib_discard_reply) {
		needs_reply = is_update;
		local_notify = FALSE;
	}
	
	if(needs_forward) {
		forward_request(request, cib_client, call_options);
		return;
	}

	if(cib_status != cib_ok) {
	    rc = cib_status;
	    crm_err("Operation ignored, cluster configuration is invalid."
		    " Please repair and restart: %s",
		    cib_error2string(cib_status));
	    op_reply = cib_construct_reply(request, the_cib, cib_status);

	} else if(process) {
		int level = LOG_INFO;
		const char *section = crm_element_value(request, F_CIB_SECTION);
		
		cib_num_local++;
		rc = cib_process_command(
			request, &op_reply, &result_diff, privileged);

		if(global_update) {
		    switch(rc) {
			case cib_ok:
			case cib_old_data:
			case cib_diff_resync:
			case cib_diff_failed:
			    level = LOG_DEBUG_2;
			    break;
			default:
			    level = LOG_ERR;
		    }

		} else if(safe_str_eq(op, CIB_OP_QUERY)) {
		    level = LOG_DEBUG_2;

		} else if(rc != cib_ok) {
		    cib_num_fail++;
		    level = LOG_WARNING;

		} else if(safe_str_eq(op, CIB_OP_QUERY)) {
		    level = LOG_DEBUG_2;

		} else if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {
		    level = LOG_DEBUG_2;
		}
		
		do_crm_log(level, "Operation complete: op %s for section %s (origin=%s/%s/%s): %s (rc=%d)",
			   op, section?section:"'all'", originator?originator:"local",
			   crm_element_value(request, F_CIB_CLIENTNAME),
			   crm_element_value(request, F_CIB_CALLID),
			   cib_error2string(rc), rc);

		if(op_reply == NULL && (needs_reply || local_notify)) {
			crm_err("Unexpected NULL reply to message");
			crm_log_xml(LOG_ERR, "null reply", request);
			needs_reply = FALSE;
			local_notify = FALSE;
		}		
	}
	crm_debug_3("processing response cases");
	
	if(local_notify) {
		const char *client_id = crm_element_value(request, F_CIB_CLIENTID);
		if(process == FALSE) {
			do_local_notify(request, client_id, call_options & cib_sync_call, from_peer);
		} else {
			do_local_notify(op_reply, client_id, call_options & cib_sync_call, from_peer);
		}
	}

	/* from now on we are the server */ 
	if(needs_reply == FALSE || stand_alone) {
		/* nothing more to do...
		 * this was a non-originating slave update
		 */
		crm_debug_2("Completed slave update");

	} else if(rc == cib_ok
		  && result_diff != NULL
		  && !(call_options & cib_inhibit_bcast)) {
		send_peer_reply(request, result_diff, originator, TRUE);
		
	} else if(call_options & cib_discard_reply) {
		crm_debug_4("Caller isn't interested in reply");
		
	} else if (from_peer) {		
		if(is_update == FALSE || result_diff == NULL) {
			crm_debug_3("Request not broadcast: R/O call");

		} else if(call_options & cib_inhibit_bcast) {
			crm_debug_3("Request not broadcast: inhibited");

		} else if(rc != cib_ok) {
			crm_debug_3("Request not broadcast: call failed: %s",
				    cib_error2string(rc));
		} else {
		    crm_debug_2("Directing reply to %s", originator);
		}

		send_peer_reply(op_reply, result_diff, originator, FALSE);
	}
	
	free_xml(op_reply);
	free_xml(result_diff);

	return;	
}

xmlNode *
cib_construct_reply(xmlNode *request, xmlNode *output, int rc) 
{
	int lpc = 0;
	xmlNode *reply = NULL;
	
	const char *name = NULL;
	const char *value = NULL;
	const char *names[] = {
		F_CIB_OPERATION,
		F_CIB_CALLID,
		F_CIB_CLIENTID,
		F_CIB_CALLOPTS
	};

	crm_debug_4("Creating a basic reply");
	reply = create_xml_node(NULL, "cib-reply");
	crm_xml_add(reply, F_TYPE, T_CIB);

	for(lpc = 0; lpc < DIMOF(names); lpc++) {
		name = names[lpc];
		value = crm_element_value(request, name);
		crm_xml_add(reply, name, value);
	}

	crm_xml_add_int(reply, F_CIB_RC, rc);

	if(output != NULL) {
		crm_debug_4("Attaching reply output");
		add_message_xml(reply, F_CIB_CALLDATA, output);
	}
	return reply;
}

enum cib_errors
cib_process_command(xmlNode *request, xmlNode **reply,
		    xmlNode **cib_diff, gboolean privileged)
{
    xmlNode *input       = NULL;
    xmlNode *output      = NULL;
    xmlNode *result_cib  = NULL;
    xmlNode *current_cib = NULL;
	
    int call_type    = 0;
    int call_options = 0;
    int log_level    = LOG_DEBUG_4;

    const char *op = NULL;
    const char *section = NULL;

    enum cib_errors rc = cib_ok;
    enum cib_errors rc2 = cib_ok;
	
    gboolean send_r_notify = FALSE;
    gboolean global_update = FALSE;
    gboolean config_changed = FALSE;
    gboolean manage_counters = TRUE;
	
    CRM_ASSERT(cib_status == cib_ok);

    *reply = NULL;
    *cib_diff = NULL;
    current_cib = the_cib;
	
    /* Start processing the request... */
    op = crm_element_value(request, F_CIB_OPERATION);
    crm_element_value_int(request, F_CIB_CALLOPTS, &call_options);
    rc = cib_get_operation_id(op, &call_type);
	
    if(rc == cib_ok) {
	rc = cib_op_can_run(call_type, call_options, privileged, global_update);
    }
	
    rc2 = cib_op_prepare(call_type, request, &input, &section);
    if(rc == cib_ok) {
	rc = rc2;
    }
	
    if(rc != cib_ok) {
	crm_debug_2("Call setup failed: %s", cib_error2string(rc));
	goto done;
		
    } else if(cib_op_modifies(call_type) == FALSE) {
	rc = cib_perform_op(op, call_options, cib_op_func(call_type), TRUE,
			    section, request, input, FALSE, &config_changed,
			    current_cib, &result_cib, NULL, &output);

	CRM_CHECK(result_cib == NULL, free_xml(result_cib));
	goto done;
    }	

    /* Handle a valid write action */
    global_update = crm_is_true(crm_element_value(request, F_CIB_GLOBAL_UPDATE));
    if(global_update) {
	manage_counters = FALSE;
	call_options |= cib_force_diff;		

	CRM_CHECK(call_type == 3 || call_type == 4,
		  crm_err("Call type: %d", call_type);
		  crm_log_xml(LOG_ERR, "bad op", request));
    }
#ifdef SUPPORT_PRENOTIFY
    if((call_options & cib_inhibit_notify) == 0) {
	cib_pre_notify(call_options, op, the_cib, input);
    }
#endif
    
    if(rc == cib_ok) {
	if(call_options & cib_inhibit_bcast) {
	    /* skip */
	    crm_debug_2("Skipping update: inhibit broadcast");
	    manage_counters = FALSE;
	}	
	    
	rc = cib_perform_op(op, call_options, cib_op_func(call_type), FALSE,
			    section, request, input, manage_counters, &config_changed,
			    current_cib, &result_cib, cib_diff, &output);

	if(manage_counters == FALSE) {
	    *cib_diff = diff_cib_object(current_cib, result_cib, FALSE);
	    config_changed = cib_config_changed(*cib_diff);
	}
    }    
    
    if(rc == cib_ok) {
	rc = activateCibXml(result_cib, config_changed, op);
	
	if(crm_str_eq(CIB_OP_REPLACE, op, TRUE)) {
	    if(section == NULL) {
		send_r_notify = TRUE;
		
	    } else if(safe_str_eq(section, XML_TAG_CIB)) {
		send_r_notify = TRUE;
		
	    } else if(safe_str_eq(section, XML_CIB_TAG_NODES)) {
		send_r_notify = TRUE;
		
	    } else if(safe_str_eq(section, XML_CIB_TAG_STATUS)) {
		send_r_notify = TRUE;
	    }

	} else if(crm_str_eq(CIB_OP_ERASE, op, TRUE)) {
	    send_r_notify = TRUE;
	}

    } else {
	free_xml(result_cib);    
    }
    
    if((call_options & cib_inhibit_notify) == 0) {
	const char *call_id = crm_element_value(request, F_CIB_CALLID);
	const char *client = crm_element_value(request, F_CIB_CLIENTNAME);

#ifdef SUPPORT_POSTNOTIFY
	cib_post_notify(call_options, op, input, rc, the_cib);
#endif
	cib_diff_notify(call_options, client, call_id, op, input, rc, *cib_diff);
    }

    if(send_r_notify) {
	const char *origin = crm_element_value(request, F_ORIG);
	cib_replace_notify(origin, the_cib, rc, *cib_diff);
    }	
    
    if(rc != cib_ok) {
	log_level = LOG_DEBUG_4;
	if(rc == cib_dtd_validation && global_update) {
	    log_level = LOG_WARNING;
	    crm_log_xml_info(input, "cib:global_update");
	}
	
    } else if(config_changed) {
	log_level = LOG_DEBUG_3;
	if(cib_is_master) {
	    log_level = LOG_INFO;
	}
	
    } else if(cib_is_master) {
	log_level = LOG_DEBUG_2;
    }
	
    log_xml_diff(log_level, *cib_diff, "cib:diff");

  done:
    if((call_options & cib_discard_reply) == 0) {
	*reply = cib_construct_reply(request, output, rc);
	/* crm_log_xml_info(*reply, "cib:reply"); */
    }

    if(call_type >= 0) {
	cib_op_cleanup(call_type, call_options, &input, &output);
    }
    return rc;
}

int
send_via_callback_channel(xmlNode *msg, const char *token) 
{
	cib_client_t *hash_client = NULL;
	enum cib_errors rc = cib_ok;
	
	crm_debug_3("Delivering msg %p to client %s", msg, token);

	if(token == NULL) {
		crm_err("No client id token, cant send message");
		if(rc == cib_ok) {
			rc = cib_missing;
		}

	} else if(msg == NULL) {
		crm_err("No message to send");
		rc = cib_reply_failed;
	    
	} else {
		/* A client that left before we could reply is not really
		 * _our_ error.  Warn instead.
		 */
		hash_client = g_hash_table_lookup(client_list, token);
		if(hash_client == NULL) {
			crm_warn("Cannot find client for token %s", token);
			rc = cib_client_gone;
			
		} else if (crm_str_eq(hash_client->channel_name, "remote", FALSE)) {
		    /* just hope it's alive */
		    
		} else if(hash_client->channel == NULL) {
			crm_err("Cannot find channel for client %s", token);
			rc = cib_client_corrupt;
		}
	}

	if(rc == cib_ok) {
	    crm_debug_3("Delivering reply to client %s (%s)",
			token, hash_client->channel_name);
	    if (crm_str_eq(hash_client->channel_name, "remote", FALSE)) {
		cib_send_remote_msg(hash_client->channel, msg);
		
	    } else if(send_ipc_message(hash_client->channel, msg) == FALSE) {
		crm_warn("Delivery of reply to client %s/%s failed",
			 hash_client->name, token);
		rc = cib_reply_failed;
	    }
	}
	
	return rc;
}

gint cib_GCompareFunc(gconstpointer a, gconstpointer b)
{
	const xmlNode *a_msg = a;
	const xmlNode *b_msg = b;

	int msg_a_id = 0;
	int msg_b_id = 0;
	const char *value = NULL;
	
	value = crm_element_value_const(a_msg, F_CIB_CALLID);
	msg_a_id = crm_parse_int(value, NULL);

	value = crm_element_value_const(b_msg, F_CIB_CALLID);
	msg_b_id = crm_parse_int(value, NULL);
	
	if(msg_a_id == msg_b_id) {
		return 0;
	} else if(msg_a_id < msg_b_id) {
		return -1;
	}
	return 1;
}

gboolean
cib_process_disconnect(IPC_Channel *channel, cib_client_t *cib_client)
{
	if (channel == NULL) {
		CRM_DEV_ASSERT(cib_client == NULL);
		
	} else if (cib_client == NULL) {
		crm_err("No client");
		
	} else {
		CRM_DEV_ASSERT(channel->ch_status != IPC_CONNECT);
		crm_debug_2("Cleaning up after client disconnect: %s/%s/%s",
			    crm_str(cib_client->name),
			    cib_client->channel_name,
			    cib_client->id);
		
		if(cib_client->id != NULL) {
			if(!g_hash_table_remove(client_list, cib_client->id)) {
				crm_err("Client %s not found in the hashtable",
					cib_client->name);
			}
		}		
	}

	if(cib_shutdown_flag && g_hash_table_size(client_list) == 0) {
		crm_info("All clients disconnected...");
		initiate_exit();
	}
	
	return FALSE;
}

void
cib_ha_peer_callback(HA_Message * msg, void* private_data)
{
    xmlNode *xml = convert_ha_message(NULL, msg, __FUNCTION__);
    cib_peer_callback(xml, private_data);
}

void
cib_peer_callback(xmlNode * msg, void* private_data)
{
    crm_node_t *node = NULL;
    const char *reason = NULL;
    const char *originator = crm_element_value(msg, F_ORIG);
    
    if(originator == NULL || crm_str_eq(originator, cib_our_uname, TRUE)) {
	/* message is from ourselves */
	return;
	
    } else if(crm_peer_cache == NULL) {
	reason = "membership not established";
	goto bail;
    }

    node = crm_get_peer(0, originator);
    if(node == NULL || crm_is_member_active(node) == FALSE) {
	reason = "not in our membership";
	goto bail;
    }
    
    if(crm_element_value(msg, F_CIB_CLIENTNAME) == NULL) {
	crm_xml_add(msg, F_CIB_CLIENTNAME, originator);
    }
    
    /* crm_log_xml(LOG_MSG, "Peer[inbound]", msg); */
    cib_process_request(msg, FALSE, TRUE, TRUE, NULL);
    return;
    
  bail:
    if(reason) {
	const char *seq = crm_element_value(msg, F_SEQ);
	const char *op  = crm_element_value(msg, F_CIB_OPERATION);
	crm_warn("Discarding %s message (%s) from %s: %s", op, seq, originator, reason);
    }
}

void
cib_client_status_callback(const char * node, const char * client,
			   const char * status, void * private)
{
    crm_node_t *member = NULL;
    if(safe_str_eq(client, CRM_SYSTEM_CIB)) {
	crm_info("Status update: Client %s/%s now has status [%s]",
		 node, client, status);
	
	if(safe_str_eq(status, JOINSTATUS)){
		    status = ONLINESTATUS;
		    
	} else if(safe_str_eq(status, LEAVESTATUS)){
	    status = OFFLINESTATUS;
	}

	member = crm_get_peer(0, node);
	if(member == NULL) {
	    /* Make sure it gets created */
	    const char *uuid = get_uuid(node);
	    member = crm_update_peer(0, 0, 0, -1, 0, uuid, node, NULL, NULL);
	}
	
	crm_update_peer_proc(node, crm_proc_cib, status);
    }
    return;
}

#if SUPPORT_HEARTBEAT
extern oc_ev_t *cib_ev_token;

gboolean cib_ccm_dispatch(int fd, gpointer user_data)
{
	int rc = 0;
	oc_ev_t *ccm_token = (oc_ev_t*)user_data;
	crm_debug_2("received callback");	
	rc = oc_ev_handle_event(ccm_token);
	if(0 == rc) {
		return TRUE;

	}

	crm_err("CCM connection appears to have failed: rc=%d.", rc);

	/* eventually it might be nice to recover and reconnect... but until then... */
	crm_err("Exiting to recover from CCM connection failure");
	exit(2);
	
	return FALSE;
}

int current_instance = 0;
void 
cib_ccm_msg_callback(
	oc_ed_t event, void *cookie, size_t size, const void *data)
{
	gboolean update_id = FALSE;
	const oc_ev_membership_t *membership = data;

	CRM_ASSERT(membership != NULL);

	crm_info("Processing CCM event=%s (id=%d)",
		 ccm_event_name(event), membership->m_instance);

	if(current_instance > membership->m_instance) {
		crm_err("Membership instance ID went backwards! %d->%d",
			current_instance, membership->m_instance);
		CRM_ASSERT(current_instance <= membership->m_instance);
	}
	
	switch(event) {
		case OC_EV_MS_NEW_MEMBERSHIP:
		case OC_EV_MS_INVALID:
			update_id = TRUE;
			break;
		case OC_EV_MS_PRIMARY_RESTORED:
			update_id = TRUE;
			break;
		case OC_EV_MS_NOT_PRIMARY:
			crm_debug_2("Ignoring transitional CCM event: %s",
				    ccm_event_name(event));
			break;
		case OC_EV_MS_EVICTED:
			crm_err("Evicted from CCM: %s", ccm_event_name(event));
			break;
		default:
			crm_err("Unknown CCM event: %d", event);
	}
	
	if(update_id) {
		unsigned int lpc = 0;
		CRM_CHECK(membership != NULL, return);
	
		current_instance = membership->m_instance;

		for(lpc=0; lpc < membership->m_n_out; lpc++) {
		    crm_update_ccm_node(
			membership, lpc+membership->m_out_idx, CRM_NODE_LOST, current_instance);
		}
		
		for(lpc=0; lpc < membership->m_n_member; lpc++) {
		    crm_update_ccm_node(
			membership, lpc+membership->m_memb_idx,CRM_NODE_ACTIVE, current_instance);
		}
	}
	
	oc_ev_callback_done(cookie);
	return;
}
#endif

gboolean
can_write(int flags)
{
	return TRUE;
}

static gboolean
cib_force_exit(gpointer data)
{
	crm_notice("Forcing exit!");
	terminate_cib(__FUNCTION__);
	return FALSE;
}

void
initiate_exit(void)
{
	int active = 0;
	xmlNode *leaving = NULL;

	active = crm_active_peers(crm_proc_cib);
	if(active < 2) {
		terminate_cib(__FUNCTION__);
		return;
	} 

	crm_info("Sending disconnect notification to %d peers...", active);

	leaving = create_xml_node(NULL, "exit-notification");	
	crm_xml_add(leaving, F_TYPE, "cib");
	crm_xml_add(leaving, F_CIB_OPERATION, "cib_shutdown_req");
	
	send_cluster_message(NULL, crm_msg_cib, leaving, TRUE);
	free_xml(leaving);
	
	g_timeout_add(crm_get_msec("5s"), cib_force_exit, NULL);
}

extern int remote_fd;

void
terminate_cib(const char *caller) 
{
    if(remote_fd > 0) {
	close(remote_fd);
    }
    
#if SUPPORT_AIS
    if(is_openais_cluster()) {
	cib_ha_connection_destroy(NULL);
	return;
    } 
#endif
#if SUPPORT_HEARTBEAT
    if(hb_conn != NULL) {
	crm_info("%s: Disconnecting heartbeat", caller);
	hb_conn->llc_ops->signoff(hb_conn, FALSE);

    } else {
	crm_err("%s: No heartbeat connection", caller);
    }
#endif
		
    uninitializeCib();
     
    crm_info("Exiting...");
    
    if (mainloop != NULL && g_main_is_running(mainloop)) {
	g_main_quit(mainloop);
	
    } else {
	exit(LSB_EXIT_OK);
    }

}

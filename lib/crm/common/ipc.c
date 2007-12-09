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

#include <hb_config.h>

#include <sys/param.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <crm/common/ipc.h>
#include <crm/msg_xml.h>
#include <ha_msg.h>



gboolean 
send_ha_message(ll_cluster_t *hb_conn, HA_Message *msg, const char *node, gboolean force_ordered)
{
	gboolean all_is_good = TRUE;

	if (msg == NULL) {
		crm_err("cant send NULL message");
		all_is_good = FALSE;

	} else if(hb_conn == NULL) {
		crm_err("No heartbeat connection specified");
		all_is_good = FALSE;

	} else if(hb_conn->llc_ops->chan_is_connected(hb_conn) == FALSE) {
		crm_err("Not connected to Heartbeat");
		all_is_good = FALSE;
		
	} else if(node != NULL) {
		if(hb_conn->llc_ops->send_ordered_nodemsg(
			   hb_conn, msg, node) != HA_OK) {
			all_is_good = FALSE;
			crm_err("Send failed");
			
		} else {
			crm_debug_2("Message sent...");
		}

	} else if(force_ordered) {
		if(hb_conn->llc_ops->send_ordered_clustermsg(hb_conn, msg) != HA_OK) {
			all_is_good = FALSE;
			crm_err("Broadcast Send failed");
		} else {
			crm_debug_2("Broadcast message sent...");
		}
	} else {
		if(hb_conn->llc_ops->sendclustermsg(hb_conn, msg) != HA_OK) {
			all_is_good = FALSE;
			crm_err("Broadcast Send failed");

		} else {
			crm_debug_2("Broadcast message sent...");
		}
	}

	if(all_is_good == FALSE && hb_conn != NULL) {
		IPC_Channel *ipc = NULL;
		IPC_Queue *send_q = NULL;
		
		if(hb_conn->llc_ops->chan_is_connected(hb_conn) != HA_OK) {
			ipc = hb_conn->llc_ops->ipcchan(hb_conn);
		}
		if(ipc != NULL) {
/* 			ipc->ops->resume_io(ipc); */
			send_q = ipc->send_queue;
		}
		if(send_q != NULL) {
			CRM_CHECK(send_q->current_qlen < send_q->max_qlen, ;);
		}
	}
	
	crm_log_message_adv(all_is_good?LOG_MSG:LOG_WARNING,"HA[outbound]",msg);
	return all_is_good;
}

/* frees msg */
gboolean 
send_ipc_message(IPC_Channel *ipc_client, HA_Message *msg)
{
	gboolean all_is_good = TRUE;
	int fail_level = LOG_WARNING;

	if(ipc_client != NULL && ipc_client->conntype == IPC_CLIENT) {
		fail_level = LOG_ERR;
	}

	if (msg == NULL) {
		crm_err("cant send NULL message");
		all_is_good = FALSE;

	} else if (ipc_client == NULL) {
		crm_err("cant send message without an IPC Channel");
		all_is_good = FALSE;

	} else if(ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
		do_crm_log(fail_level, "IPC Channel to %d is not connected",
			      (int)ipc_client->farside_pid);
		all_is_good = FALSE;
	}

	if(all_is_good && msg2ipcchan(msg, ipc_client) != HA_OK) {
		do_crm_log(fail_level, "Could not send IPC message to %d",
			(int)ipc_client->farside_pid);
		all_is_good = FALSE;

		if(ipc_client->ops->get_chan_status(ipc_client) != IPC_CONNECT) {
			do_crm_log(fail_level,
				      "IPC Channel to %d is no longer connected",
				      (int)ipc_client->farside_pid);

		} else if(ipc_client->conntype == IPC_CLIENT) {
			if(ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
				crm_err("Send queue to %d (size=%d) full.",
					ipc_client->farside_pid,
					(int)ipc_client->send_queue->max_qlen);
			}
		}
	}
/* 	ipc_client->ops->resume_io(ipc_client); */
	
	crm_log_message_adv(all_is_good?LOG_MSG:LOG_WARNING,"IPC[outbound]",msg);
	
	return all_is_good;
}

void
default_ipc_connection_destroy(gpointer user_data)
{
	return;
}

int
init_server_ipc_comms(
	char *channel_name,
	gboolean (*channel_client_connect)(IPC_Channel *newclient,gpointer user_data),
	void (*channel_connection_destroy)(gpointer user_data))
{
	/* the clients wait channel is the other source of events.
	 * This source delivers the clients connection events.
	 * listen to this source at a relatively lower priority.
	 */
    
	char    commpath[SOCKET_LEN];
	IPC_WaitConnection *wait_ch;
	
	sprintf(commpath, CRM_SOCK_DIR "/%s", channel_name);

	wait_ch = wait_channel_init(commpath);

	if (wait_ch == NULL) {
		return 1;
	}
	
	G_main_add_IPC_WaitConnection(
		G_PRIORITY_LOW, wait_ch, NULL, FALSE,
		channel_client_connect, channel_name,
		channel_connection_destroy);

	crm_debug_3("Listening on: %s", commpath);

	return 0;
}

GCHSource*
init_client_ipc_comms(const char *channel_name,
		      gboolean (*dispatch)(
			      IPC_Channel* source_data, gpointer user_data),
		      void *client_data, IPC_Channel **ch)
{
	IPC_Channel *a_ch = NULL;
	GCHSource *the_source = NULL;
	void *callback_data = client_data;

	a_ch = init_client_ipc_comms_nodispatch(channel_name);
	if(ch != NULL) {
		*ch = a_ch;
		if(callback_data == NULL) {
			callback_data = a_ch;
		}
	}

	if(a_ch == NULL) {
		crm_warn("Setup of client connection failed,"
			 " not adding channel to mainloop");
		
		return NULL;
	}

	if(dispatch == NULL) {
		crm_warn("No dispatch method specified..."
			 "maybe you meant init_client_ipc_comms_nodispatch()?");
	} else {
		crm_debug_3("Adding dispatch method to channel");

		the_source = G_main_add_IPC_Channel(
			G_PRIORITY_HIGH, a_ch, FALSE, dispatch, callback_data, 
			default_ipc_connection_destroy);
	}
	
	return the_source;
}

IPC_Channel *
init_client_ipc_comms_nodispatch(const char *channel_name)
{
	IPC_Channel *ch;
	GHashTable  *attrs;
	static char  path[] = IPC_PATH_ATTR;

	char *commpath = NULL;
	int local_socket_len = 2; /* 2 = '/' + '\0' */

	local_socket_len += strlen(channel_name);
	local_socket_len += strlen(CRM_SOCK_DIR);

	crm_malloc0(commpath, local_socket_len);
	if(commpath != NULL) {
		sprintf(commpath, CRM_SOCK_DIR "/%s", channel_name);
		commpath[local_socket_len - 1] = '\0';
		crm_debug_3("Attempting to talk on: %s", commpath);
	}
	
	attrs = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(attrs, path, commpath);

	ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
	g_hash_table_destroy(attrs);

	if (ch == NULL) {
		crm_err("Could not access channel on: %s", commpath);
		crm_free(commpath);
		return NULL;
		
	} else if (ch->ops->initiate_connection(ch) != IPC_OK) {
		crm_debug("Could not init comms on: %s", commpath);
		ch->ops->destroy(ch);
		crm_free(commpath);
		return NULL;
	}

	ch->ops->set_recv_qlen(ch, 512);
	ch->ops->set_send_qlen(ch, 512);
 	ch->should_send_block = TRUE;

	crm_debug_3("Processing of %s complete", commpath);

	crm_free(commpath);
	return ch;
}

IPC_WaitConnection *
wait_channel_init(char daemonsocket[])
{
	IPC_WaitConnection *wait_ch;
	mode_t mask;
	char path[] = IPC_PATH_ATTR;
	GHashTable * attrs;

	
	attrs = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(attrs, path, daemonsocket);
    
	mask = umask(0);
	wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
	if (wait_ch == NULL) {
		cl_perror("Can't create wait channel of type %s",
			  IPC_ANYTYPE);
		exit(1);
	}
	mask = umask(mask);
    
	g_hash_table_destroy(attrs);
    
	return wait_ch;
}

longclock_t ipc_call_start = 0;
longclock_t ipc_call_stop = 0;
longclock_t ipc_call_diff = 0;

gboolean
subsystem_msg_dispatch(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;
	HA_Message *msg = NULL;
	ha_msg_input_t *new_input = NULL;
	gboolean all_is_well = TRUE;
	const char *sys_to;
	const char *task;

	while(IPC_ISRCONN(sender)) {
		gboolean process = FALSE;
		if(sender->ops->is_message_pending(sender) == 0) {
			break;
		}

		msg = msgfromIPC_noauth(sender);
		if (msg == NULL) {
			crm_err("No message from %d this time",
				sender->farside_pid);
			continue;
		}

		lpc++;
		new_input = new_ha_msg_input(msg);
		crm_msg_del(msg);
		msg = NULL;
		
		crm_log_message(LOG_MSG, new_input->msg);

		sys_to = cl_get_string(new_input->msg, F_CRM_SYS_TO);
		task   = cl_get_string(new_input->msg, F_CRM_TASK);

		if(safe_str_eq(task, CRM_OP_HELLO)) {
			process = TRUE;

		} else if(sys_to == NULL) {
			crm_err("Value of %s was NULL!!", F_CRM_SYS_TO);
			
		} else if(task == NULL) {
			crm_err("Value of %s was NULL!!", F_CRM_TASK);
			
		} else {
			process = TRUE;
		}

		if(process){
			gboolean (*process_function)
				(HA_Message *msg, crm_data_t *data, IPC_Channel *sender) = NULL;
			process_function = user_data;
#ifdef MSG_LOG
			crm_log_message_adv(
				LOG_MSG, __FUNCTION__, new_input->msg);
#endif
			if(ipc_call_diff_max_ms > 0) {
				ipc_call_start = time_longclock();
			}
			if(FALSE == process_function(
				   new_input->msg, new_input->xml, sender)) {
				crm_warn("Received a message destined for %s"
					 " by mistake", sys_to);
			}
			if(ipc_call_diff_max_ms > 0) {
				unsigned int ipc_call_diff_ms = 0;
				ipc_call_stop = time_longclock();
				ipc_call_diff = sub_longclock(
					ipc_call_stop, ipc_call_start);
				ipc_call_diff_ms = longclockto_ms(
					ipc_call_diff);
				if(ipc_call_diff_ms > ipc_call_diff_max_ms) {
					crm_err("%s took %dms to complete",
						sys_to, ipc_call_diff_ms);
				}
			}
		} else {
#ifdef MSG_LOG
			crm_log_message_adv(
				LOG_ERR, NULL, new_input->msg);
#endif
		}
		
		delete_ha_msg_input(new_input);
		new_input = NULL;

		if(sender->ch_status == IPC_CONNECT) {
			break;
		}
	}

	crm_debug_2("Processed %d messages", lpc);
	if (sender->ch_status != IPC_CONNECT) {
		crm_err("The server %d has left us: Shutting down...NOW",
			sender->farside_pid);

		exit(1); /* shutdown properly later */
		
		return !all_is_well;
	}
	return all_is_well;
}

gboolean
is_ipc_empty(IPC_Channel *ch)
{
	if(ch == NULL) {
		return TRUE;

	} else if(ch->send_queue->current_qlen == 0
		  && ch->recv_queue->current_qlen == 0) {
		return TRUE;
	}	
	return FALSE;
}

/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
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
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/cluster.h>

#include <crm/common/xml.h>
#include <crm/common/msg.h>

#define F_STONITH_OP "st_op"
#define F_STONITH_CLIENTID "st_client_id"
#define F_STONITH_CLIENTNAME "st_client_name"
#define F_STONITH_CALLBACK_TOKEN "st_token"

char *channel1 = NULL;
char *stonith_our_uname = NULL;

GMainLoop *mainloop = NULL;
GHashTable *client_list = NULL;

gboolean stonith_shutdown_flag = FALSE;

typedef struct stonith_client_s 
{
	char  *id;
	char  *name;
	char  *callback_id;

	const char  *channel_name;

	IPC_Channel *channel;
	GCHSource   *source;

	long long flags;

} stonith_client_t;

static gboolean
stonith_client_disconnect(
    IPC_Channel *channel, stonith_client_t *stonith_client)
{
    if (channel == NULL) {
	CRM_DEV_ASSERT(stonith_client == NULL);
		
    } else if (stonith_client == NULL) {
	crm_err("No client");
		
    } else {
	CRM_DEV_ASSERT(channel->ch_status != IPC_CONNECT);
	crm_debug_2("Cleaning up after client disconnect: %s/%s/%s",
		    crm_str(stonith_client->name),
		    stonith_client->channel_name,
		    stonith_client->id);
		
	if(stonith_client->id != NULL) {
	    if(!g_hash_table_remove(client_list, stonith_client->id)) {
		crm_err("Client %s not found in the hashtable",
			stonith_client->name);
	    }
	}		
    }
	
    return FALSE;
}

static gboolean
stonith_client_callback(IPC_Channel *channel, gpointer user_data)
{
    int lpc = 0;
    const char *value = NULL;
    xmlNode *op_request = NULL;
    gboolean keep_channel = TRUE;
    stonith_client_t *stonith_client = user_data;
    
    CRM_CHECK(stonith_client != NULL, crm_err("Invalid client"); return FALSE);
    CRM_CHECK(stonith_client->id != NULL,
	      crm_err("Invalid client: %p", stonith_client); return FALSE);

    if(IPC_ISRCONN(channel) && channel->ops->is_message_pending(channel)) {

	lpc++;
	op_request = xmlfromIPC(channel, MAX_IPC_DELAY);
	if (op_request == NULL) {
	    goto bail;
	}

	if(stonith_client->name == NULL) {
	    value = crm_element_value(op_request, F_STONITH_CLIENTNAME);
	    if(value == NULL) {
		stonith_client->name = crm_itoa(channel->farside_pid);
	    } else {
		stonith_client->name = crm_strdup(value);
	    }
	}

	crm_xml_add(op_request, F_STONITH_CLIENTID, stonith_client->id);
	crm_xml_add(op_request, F_STONITH_CLIENTNAME, stonith_client->name);

	if(stonith_client->callback_id == NULL) {
	    value = crm_element_value(op_request, F_STONITH_CALLBACK_TOKEN);
	    if(value != NULL) {
		stonith_client->callback_id = crm_strdup(value);

	    } else {
		stonith_client->callback_id = crm_strdup(stonith_client->id);
	    }
	}

	crm_log_xml(LOG_MSG, "Client[inbound]", op_request);
	
	free_xml(op_request);
    }
    
  bail:
    if(channel->ch_status != IPC_CONNECT) {
	crm_debug_2("Client disconnected");
	keep_channel = stonith_client_disconnect(channel, stonith_client);	
    }

    return keep_channel;
}

static void
stonith_client_destroy(gpointer user_data)
{
    stonith_client_t *stonith_client = user_data;
	
    if(stonith_client == NULL) {
	crm_debug_4("Destroying %p", user_data);
	return;
    }

    if(stonith_client->source != NULL) {
	crm_debug_4("Deleting %s (%p) from mainloop",
		    stonith_client->name, stonith_client->source);
	G_main_del_IPC_Channel(stonith_client->source); 
	stonith_client->source = NULL;
    }
	
    crm_debug_3("Destroying %s (%p)", stonith_client->name, user_data);
    crm_free(stonith_client->name);
    crm_free(stonith_client->callback_id);
    crm_free(stonith_client->id);
    crm_free(stonith_client);
    crm_debug_4("Freed the cib client");

    return;
}

static gboolean
stonith_client_connect(IPC_Channel *channel, gpointer user_data)
{
    cl_uuid_t client_id;
    xmlNode *reg_msg = NULL;
    stonith_client_t *new_client = NULL;
    char uuid_str[UU_UNPARSE_SIZEOF];
    const char *channel_name = user_data;

    crm_debug_3("Connecting channel");
    CRM_CHECK(channel_name != NULL, return FALSE);
	
    if (channel == NULL) {
	crm_err("Channel was NULL");
	return FALSE;

    } else if (channel->ch_status != IPC_CONNECT) {
	crm_err("Channel was disconnected");
	return FALSE;
		
    } else if(stonith_shutdown_flag) {
	crm_info("Ignoring new client [%d] during shutdown",
		 channel->farside_pid);
	return FALSE;		
    }

    crm_malloc0(new_client, sizeof(stonith_client_t));
    new_client->channel = channel;
    new_client->channel_name = channel_name;
	
    crm_debug_3("Created channel %p for channel %s",
		new_client, new_client->channel_name);
	
    channel->ops->set_recv_qlen(channel, 1024);
    channel->ops->set_send_qlen(channel, 1024);
	
    new_client->source = G_main_add_IPC_Channel(
	G_PRIORITY_DEFAULT, channel, FALSE, stonith_client_callback,
	new_client, stonith_client_destroy);
	
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
    crm_xml_add(reg_msg, F_STONITH_OP, CRM_OP_REGISTER);
    crm_xml_add(reg_msg, F_STONITH_CALLBACK_TOKEN,  new_client->id);
	
    send_ipc_message(channel, reg_msg);		
    free_xml(reg_msg);
	
    return TRUE;
}

static void
stonith_peer_callback(xmlNode * msg, void* private_data)
{
}

static void
stonith_peer_hb_callback(HA_Message * msg, void* private_data)
{
    xmlNode *xml = convert_ha_message(NULL, msg, __FUNCTION__);
    stonith_peer_callback(xml, private_data);
    free_xml(xml);
}


#if SUPPORT_AIS	
static gboolean stonith_peer_ais_callback(
    AIS_Message *wrapper, char *data, int sender) 
{
    xmlNode *xml = NULL;

    if(wrapper->header.id == crm_class_cluster) {
	xml = string2xml(data);
	if(xml == NULL) {
	    goto bail;
	}
	crm_xml_add(xml, F_ORIG, wrapper->sender.uname);
	crm_xml_add_int(xml, F_SEQ, wrapper->id);
	stonith_peer_callback(xml, NULL);
    }

    free_xml(xml);
    return TRUE;

  bail:
    crm_err("Invalid XML: '%.120s'", data);
    return TRUE;

}

static void
stonith_peer_ais_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_sync = -1;
    exit(1);
}
#endif

static void
stonith_peer_hb_destroy(gpointer user_data)
{
    if(stonith_shutdown_flag) {
	crm_info("Heartbeat disconnection complete... exiting");
    } else {
	crm_err("Heartbeat connection lost!  Exiting.");
    }
		
    crm_info("Exiting...");
    if (mainloop != NULL && g_main_is_running(mainloop)) {
	g_main_quit(mainloop);
		
    } else {
	exit(LSB_EXIT_OK);
    }
}

static void
stonith_shutdown(int nsig)
{
    stonith_shutdown_flag = TRUE;
    crm_info("Terminating with  %d clients", g_hash_table_size(client_list));
    stonith_client_disconnect(NULL, NULL);
}

static void
stonith_cleanup(void) 
{
    crm_peer_destroy();	
    g_hash_table_destroy(client_list);
    crm_free(stonith_our_uname);
#if HAVE_LIBXML2
    xmlCleanupParser();
#endif
    crm_free(channel1);
}

static struct crm_option long_options[] = {
    {"stand-alone", 0, 0, 's'},
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},
    
    {0, 0, 0, 0}
};

int
main(int argc, char ** argv)
{
    int flag;
    int rc = 0;
    int argerr = 0;
    int option_index = 0;
    gboolean stand_alone = FALSE;

    crm_log_init("stonith-ng", LOG_INFO, TRUE, TRUE, argc, argv);
    crm_set_options("V?s$", "mode [options]", long_options,
		    "Provides a summary of cluster's current state."
		    "\n\nOutputs varying levels of detail in a number of different formats.\n");

    mainloop_add_signal(SIGTERM, stonith_shutdown);
	
    /* EnableProcLogging(); */
    set_sigchld_proctrack(G_PRIORITY_HIGH,DEFAULT_MAXDISPATCHTIME);

    crm_peer_init();
    client_list = g_hash_table_new(g_str_hash, g_str_equal);
	
    while (1) {
	flag = crm_get_option(argc, argv, &option_index);
	if (flag == -1)
	    break;
		
	switch(flag) {
	    case 'V':
		alter_debug(DEBUG_INC);
		cl_log_enable_stderr(1);
		break;
	    case 's':
		stand_alone = TRUE;
		cl_log_enable_stderr(1);
		break;
	    case '$':
	    case '?':
		crm_help(flag, LSB_EXIT_OK);
		break;
	    default:
		++argerr;
		break;
	}
    }

    if (optind > argc) {
	++argerr;
    }
    
    if (argerr) {
	crm_help('?', LSB_EXIT_GENERIC);
    }

    if(stand_alone == FALSE) {
	void *dispatch = stonith_peer_hb_callback;
	void *destroy = stonith_peer_hb_destroy;
	    
	if(is_openais_cluster()) {
#if SUPPORT_AIS
	    destroy = stonith_peer_ais_destroy;
	    dispatch = stonith_peer_ais_callback;
#endif
	}
	    
	if(crm_cluster_connect(&stonith_our_uname, NULL, dispatch, destroy,
#if SUPPORT_HEARTBEAT
			       &hb_conn
#else
			       NULL
#endif
	       ) == FALSE){
	    crm_crit("Cannot sign in to the cluster... terminating");
	    exit(100);
	}
	
    } else {
	stonith_our_uname = crm_strdup("localhost");
    }

    channel1 = crm_strdup("stonith-ng");
    rc = init_server_ipc_comms(
	channel1, stonith_client_connect,
	default_ipc_connection_destroy);

    if(rc == 0) {
	/* Create the mainloop and run it... */
	mainloop = g_main_new(FALSE);
	crm_info("Starting %s mainloop", crm_system_name);

	g_main_run(mainloop);

    } else {
	crm_err("Couldnt start all communication channels, exiting.");
    }
	
    stonith_cleanup();

#if SUPPORT_HEARTBEAT
    if(hb_conn) {
	hb_conn->llc_ops->delete(hb_conn);
    }
#endif
	
    crm_info("Done");
    return rc;
}

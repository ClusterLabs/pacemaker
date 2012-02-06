/* 
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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

#include <crm/stonith-ng.h>
#include <crm/stonith-ng-internal.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <crm/cib.h>

#include <internal.h>

char *channel1 = NULL;
char *channel2 = NULL;
char *stonith_our_uname = NULL;

GMainLoop *mainloop = NULL;
GHashTable *client_list = NULL;

gboolean stand_alone = FALSE;
gboolean stonith_shutdown_flag = FALSE;

#if SUPPORT_HEARTBEAT
ll_cluster_t *hb_conn = NULL;
#endif

static gboolean
stonith_client_disconnect(
    IPC_Channel *channel, stonith_client_t *stonith_client)
{
    if (channel == NULL) {
	CRM_LOG_ASSERT(stonith_client == NULL);
		
    } else if (stonith_client == NULL) {
	crm_err("No client");
		
    } else {
	CRM_LOG_ASSERT(channel->ch_status != IPC_CONNECT);
	crm_trace("Cleaning up after client disconnect: %s/%s/%s",
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
    xmlNode *request = NULL;
    gboolean keep_channel = TRUE;
    stonith_client_t *stonith_client = user_data;
    
    CRM_CHECK(stonith_client != NULL, crm_err("Invalid client"); return FALSE);
    CRM_CHECK(stonith_client->id != NULL,
	      crm_err("Invalid client: %p", stonith_client); return FALSE);

    if(IPC_ISRCONN(channel) && channel->ops->is_message_pending(channel)) {

	lpc++;
	request = xmlfromIPC(channel, MAX_IPC_DELAY);
	if (request == NULL) {
	    goto bail;
	}

	if(stonith_client->name == NULL) {
	    value = crm_element_value(request, F_STONITH_CLIENTNAME);
	    if(value == NULL) {
		stonith_client->name = crm_itoa(channel->farside_pid);
	    } else {
		stonith_client->name = crm_strdup(value);
	    }
	}

	crm_xml_add(request, F_STONITH_CLIENTID, stonith_client->id);
	crm_xml_add(request, F_STONITH_CLIENTNAME, stonith_client->name);

	if(stonith_client->callback_id == NULL) {
	    value = crm_element_value(request, F_STONITH_CALLBACK_TOKEN);
	    if(value != NULL) {
		stonith_client->callback_id = crm_strdup(value);

	    } else {
		stonith_client->callback_id = crm_strdup(stonith_client->id);
	    }
	}

	crm_log_xml_trace(request, "Client[inbound]");
	stonith_command(stonith_client, request, NULL);

	free_xml(request);
    }
    
  bail:
    if(channel->ch_status != IPC_CONNECT) {
	crm_trace("Client disconnected");
	keep_channel = stonith_client_disconnect(channel, stonith_client);	
    }

    return keep_channel;
}

static void
stonith_client_destroy(gpointer user_data)
{
    stonith_client_t *stonith_client = user_data;
	
    if(stonith_client == NULL) {
	crm_trace("Destroying %p", user_data);
	return;
    }

    if(stonith_client->source != NULL) {
	crm_trace("Deleting %s (%p) from mainloop",
		    stonith_client->name, stonith_client->source);
	G_main_del_IPC_Channel(stonith_client->source); 
	stonith_client->source = NULL;
    }
	
    crm_trace("Destroying %s (%p)", stonith_client->name, user_data);
    crm_free(stonith_client->name);
    crm_free(stonith_client->callback_id);
    crm_free(stonith_client->id);
    crm_free(stonith_client);
    crm_trace("Freed the cib client");

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

    crm_trace("Connecting channel");
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
	
    crm_trace("Created channel %p for channel %s",
		new_client, new_client->channel_name);
	
    channel->ops->set_recv_qlen(channel, 1024);
    channel->ops->set_send_qlen(channel, 1024);
	
    new_client->source = G_main_add_IPC_Channel(
	G_PRIORITY_DEFAULT, channel, FALSE, stonith_client_callback,
	new_client, stonith_client_destroy);
	
    crm_trace("Channel %s connected for client %s",
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
    crm_xml_add(reg_msg, F_STONITH_OPERATION, CRM_OP_REGISTER);
    crm_xml_add(reg_msg, F_STONITH_CLIENTID,  new_client->id);
	
    send_ipc_message(channel, reg_msg);		
    free_xml(reg_msg);
	
    return TRUE;
}

static void
stonith_peer_callback(xmlNode * msg, void* private_data)
{
    const char *remote = crm_element_value(msg, F_ORIG);
    crm_log_xml_trace(msg, "Peer[inbound]");
    stonith_command(NULL, msg, remote);
}

static void
stonith_peer_hb_callback(HA_Message * msg, void* private_data)
{
    xmlNode *xml = convert_ha_message(NULL, msg, __FUNCTION__);
    stonith_peer_callback(xml, private_data);
    free_xml(xml);
}


#if SUPPORT_COROSYNC	
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

static int
send_via_callback_channel(xmlNode *msg, const char *token) 
{
    stonith_client_t *hash_client = NULL;
    enum stonith_errors rc = stonith_ok;
	
    crm_trace("Delivering msg %p to client %s", msg, token);

    if(token == NULL) {
	crm_err("No client id token, cant send message");
	if(rc == stonith_ok) {
	    rc = -1;
	}

    } else if(msg == NULL) {
	crm_err("No message to send");
	rc = -1;
	    
    } else {
	/* A client that left before we could reply is not really
	 * _our_ error.  Warn instead.
	 */
	hash_client = g_hash_table_lookup(client_list, token);
	if(hash_client == NULL) {
	    crm_warn("Cannot find client for token %s", token);
	    rc = -1;
			
	} else if (crm_str_eq(hash_client->channel_name, "remote", FALSE)) {
	    /* just hope it's alive */
		    
	} else if(hash_client->channel == NULL) {
	    crm_err("Cannot find channel for client %s", token);
	    rc = -1;
	}
    }

    if(rc == stonith_ok) {
	crm_trace("Delivering reply to client %s (%s)",
		    token, hash_client->channel_name);
	if(send_ipc_message(hash_client->channel, msg) == FALSE) {
	    crm_warn("Delivery of reply to client %s/%s failed",
		     hash_client->name, token);
	    rc = -1;
	}
    }
	
    return rc;
}

void do_local_reply(xmlNode *notify_src, const char *client_id,
		     gboolean sync_reply, gboolean from_peer)
{
    /* send callback to originating child */
    stonith_client_t *client_obj = NULL;
    enum stonith_errors local_rc = stonith_ok;

    crm_trace("Sending response");

    if(client_id != NULL) {
	client_obj = g_hash_table_lookup(client_list, client_id);
    } else {
	crm_trace("No client to sent the response to."
		    "  F_STONITH_CLIENTID not set.");
    }
	
    crm_trace("Sending callback to request originator");
    if(client_obj == NULL) {
	local_rc = -1;
		
    } else {
	const char *client_id = client_obj->callback_id;
	crm_trace("Sending %ssync response to %s %s",
		    sync_reply?"":"an a-",
		    client_obj->name,
		    from_peer?"(originator of delegated request)":"");
		
	if(sync_reply) {
	    client_id = client_obj->id;
	}
	local_rc = send_via_callback_channel(notify_src, client_id);
    } 
	
    if(local_rc != stonith_ok && client_obj != NULL) {
	crm_warn("%sSync reply to %s failed: %s",
		 sync_reply?"":"A-",
		 client_obj?client_obj->name:"<unknown>", stonith_error2string(local_rc));
    }
}

long long get_stonith_flag(const char *name) 
{
    if(safe_str_eq(name, STONITH_OP_FENCE)) {
	return 0x01;
		
    } else if(safe_str_eq(name, STONITH_OP_DEVICE_ADD)) {
	return 0x04; 

    } else if(safe_str_eq(name, STONITH_OP_DEVICE_DEL)) {
	return 0x10;
   }
    return 0;
}

static void
stonith_notify_client(gpointer key, gpointer value, gpointer user_data)
{

    IPC_Channel *ipc_client = NULL;
    xmlNode *update_msg = user_data;
    stonith_client_t *client = value;
    const char *type = NULL;

    CRM_CHECK(client != NULL, return);
    CRM_CHECK(update_msg != NULL, return);

    type = crm_element_value(update_msg, F_SUBTYPE);
    CRM_CHECK(type != NULL, crm_log_xml_err(update_msg, "notify"); return);

    if(client == NULL) {
	crm_trace("Skipping NULL client");
	return;

    } else if(client->channel == NULL) {
	crm_trace("Skipping client with NULL channel");
	return;

    } else if(client->name == NULL) {
	crm_trace("Skipping unnammed client / comamnd channel");
	return;
    }

    ipc_client = client->channel;
    if(client->flags & get_stonith_flag(type)) {
	crm_trace("Sending %s-notification to client %s/%s", type, client->name, client->id);
	if(ipc_client->send_queue->current_qlen >= ipc_client->send_queue->max_qlen) {
	    /* We never want the STONITH to exit because our client is slow */
	    crm_debug("%s-notification of client %s/%s failed - queue saturated",
		     type, client->name, client->id);
			
	} else if(send_ipc_message(ipc_client, update_msg) == FALSE) {
	    crm_warn("%s-Notification of client %s/%s failed",
		     type, client->name, client->id);
	}
    }
}

void
do_stonith_notify(
    int options, const char *type, enum stonith_errors result, xmlNode *data,
    const char *remote) 
{
    /* TODO: Standardize the contents of data */
    xmlNode *update_msg = create_xml_node(NULL, "notify");

    CRM_CHECK(type != NULL, ;);
    
    crm_xml_add(update_msg, F_TYPE, T_STONITH_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, type);
    crm_xml_add(update_msg, F_STONITH_OPERATION, type);
    crm_xml_add_int(update_msg, F_STONITH_RC, result);
	
    if(data != NULL) {
	add_message_xml(update_msg, F_STONITH_CALLDATA, data);
    }

    crm_trace("Notifying clients");
    g_hash_table_foreach(client_list, stonith_notify_client, update_msg);
    free_xml(update_msg);
    crm_trace("Notify complete");
}

static stonith_key_value_t *parse_device_list(const char *devices) 
{
    int lpc = 0;
    int max = 0;
    int last = 0;
    stonith_key_value_t *output = NULL;

    if(devices == NULL) {
	return output;
    }

    max = strlen(devices);
    for(lpc = 0; lpc <= max; lpc++) {
        if(devices[lpc] == ',' || devices[lpc] == 0) {
	    char *line = NULL;

            crm_malloc0(line, 2 + lpc - last);
            snprintf(line, 1 + lpc - last, "%s", devices+last);
            output = stonith_key_value_add(output, NULL, line);
            crm_free(line);

            last = lpc + 1;
        }
    }

    return output;
}

static void topology_remove_helper(const char *node, int level) 
{
    xmlNode *data = create_xml_node(NULL, F_STONITH_LEVEL);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add_int(data, XML_ATTR_ID, level);
    crm_xml_add(data, F_STONITH_TARGET, node);
    stonith_level_remove(data);
    free_xml(data);
}

static void topology_register_helper(const char *node, int level, stonith_key_value_t *device_list) 
{
    xmlNode *data = create_xml_node(NULL, F_STONITH_LEVEL);
    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add_int(data, XML_ATTR_ID, level);
    crm_xml_add(data, F_STONITH_TARGET, node);

    for (; device_list; device_list = device_list->next) {
        xmlNode *dev = create_xml_node(data, F_STONITH_DEVICE);
        crm_xml_add(dev, XML_ATTR_ID, device_list->value);
    }

    stonith_level_register(data);
    free_xml(data);
}

static void remove_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = 0, lpc = 0;

    if(xpathObj && xpathObj->nodesetval) {
        max = xpathObj->nodesetval->nodeNr;
    }

    for(lpc = 0; lpc < max; lpc++) {
        xmlNode *match = getXpathResult(xpathObj, lpc);
        CRM_CHECK(match != NULL, continue);

        if(crm_element_value(match, XML_DIFF_MARKER)) {
            /* Deletion */
            int index = 0;
            const char *target = crm_element_value(match, XML_ATTR_STONITH_TARGET);

            crm_element_value_int(match, XML_ATTR_STONITH_INDEX, &index);
            if(target == NULL) {
                crm_err("Invalid fencing target in element %s", ID(match));

            } else if(index <= 0) {
                crm_err("Invalid level for %s in element %s", target, ID(match));

            } else {
                topology_remove_helper(target, index);
            }
     /* } else { Deal with modifications during the 'addition' stage */
        }
    }
}


static void register_fencing_topology(xmlXPathObjectPtr xpathObj, gboolean force)
{
    int max = 0, lpc = 0;

    if(xpathObj && xpathObj->nodesetval) {
        max = xpathObj->nodesetval->nodeNr;
    }

    for(lpc = 0; lpc < max; lpc++) {
        int index = 0;
        const char *target;
        const char *dev_list;
        stonith_key_value_t *devices = NULL;
        xmlNode *match = getXpathResult(xpathObj, lpc);
        CRM_CHECK(match != NULL, continue);

        crm_element_value_int(match, XML_ATTR_STONITH_INDEX, &index);
        target = crm_element_value(match, XML_ATTR_STONITH_TARGET);
        dev_list = crm_element_value(match, XML_ATTR_STONITH_DEVICES);
        devices = parse_device_list(dev_list);

        crm_trace("Updating %s[%d] (%s) to %s", target, index, ID(match), dev_list);

        if(target == NULL) {
            crm_err("Invalid fencing target in element %s", ID(match));

        } else if(index <= 0) {
            crm_err("Invalid level for %s in element %s", target, ID(match));

        } else if(force == FALSE && crm_element_value(match, XML_DIFF_MARKER)) {
            /* Addition */
            topology_register_helper(target, index, devices);

        } else { /* Modification */
            /* Remove then re-add */
            topology_remove_helper(target, index);
            topology_register_helper(target, index, devices);
        }

        stonith_key_value_freeall(devices, 1, 1);
    }
}

/* Fencing 
<diff crm_feature_set="3.0.6">
  <diff-removed>
    <fencing-topology>
      <fencing-level id="f-p1.1" target="pcmk-1" index="1" devices="poison-pill" __crm_diff_marker__="removed:top"/>
      <fencing-level id="f-p1.2" target="pcmk-1" index="2" devices="power" __crm_diff_marker__="removed:top"/>
      <fencing-level devices="disk,network" id="f-p2.1"/>
    </fencing-topology>
  </diff-removed>
  <diff-added>
    <fencing-topology>
      <fencing-level id="f-p.1" target="pcmk-1" index="1" devices="poison-pill" __crm_diff_marker__="added:top"/>
      <fencing-level id="f-p2.1" target="pcmk-2" index="1" devices="disk,something"/>
      <fencing-level id="f-p3.1" target="pcmk-2" index="2" devices="power" __crm_diff_marker__="added:top"/>
    </fencing-topology>
  </diff-added>
</diff>
*/

static void
fencing_topology_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    xmlXPathObjectPtr xpathObj = NULL;
    const char *xpath = "//" XML_TAG_FENCING_LEVEL;

    crm_trace("Pushing in stonith topology");

    /* Grab everything */
    xpathObj = xpath_search(msg, xpath);

    register_fencing_topology(xpathObj, TRUE);

    if(xpathObj) {
	xmlXPathFreeObject(xpathObj);
    }
}

static void
update_fencing_topology(const char *event, xmlNode * msg)
{
    const char *xpath;
    xmlXPathObjectPtr xpathObj = NULL;

    /* Process deletions (only) */
    xpath = "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//" XML_TAG_FENCING_LEVEL;
    xpathObj = xpath_search(msg, xpath);

    remove_fencing_topology(xpathObj);

    if(xpathObj) {
	xmlXPathFreeObject(xpathObj);
    }

    /* Process additions and changes */
    xpath = "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_TAG_FENCING_LEVEL;
    xpathObj = xpath_search(msg, xpath);

    register_fencing_topology(xpathObj, FALSE);

    if(xpathObj) {
	xmlXPathFreeObject(xpathObj);
    }
}

static void
stonith_shutdown(int nsig)
{
    stonith_shutdown_flag = TRUE;
    crm_info("Terminating with  %d clients", g_hash_table_size(client_list));
    stonith_client_disconnect(NULL, NULL);
    exit(0);
}

static void
stonith_cleanup(void) 
{
    crm_peer_destroy();	
    g_hash_table_destroy(client_list);
    crm_free(stonith_our_uname);
#if HAVE_LIBXML2
    crm_xml_cleanup();
#endif
    crm_free(channel1);
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"stand-alone", 0, 0, 's'},
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},
    
    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static void
setup_cib(void)
{
    static void *cib_library = NULL;
    static cib_t *(*cib_new_fn)(void) = NULL;
    static const char *(*cib_err_fn)(enum cib_errors) = NULL;

    int rc, retries = 0;
    cib_t *cib = NULL;

    if(cib_library == NULL) {
        cib_library = dlopen(CIB_LIBRARY, RTLD_LAZY);
    }
    if(cib_library && cib_new_fn == NULL) {
        cib_new_fn = dlsym(cib_library, "cib_new");
    }
    if(cib_library && cib_err_fn == NULL) {
        cib_err_fn = dlsym(cib_library, "cib_error2string");
    }
    if(cib_new_fn != NULL) {
        cib = (*cib_new_fn)();
    }
    
    if(cib == NULL) {
        crm_err("No connection to the CIB");
        return;
    }

    do {
        sleep(retries);
        rc = cib->cmds->signon(cib, CRM_SYSTEM_CRMD, cib_command);
    } while(rc == cib_connection && ++retries < 5);
    
    if (rc != cib_ok) {
        crm_err("Could not connect to the CIB service: %s", (*cib_err_fn)(rc));
        
    } else if (cib_ok != cib->cmds->add_notify_callback(
                   cib, T_CIB_DIFF_NOTIFY, update_fencing_topology)) {
        crm_err("Could not set CIB notification callback");
        
    } else {
        rc = cib->cmds->query(cib, NULL, NULL, cib_scope_local);
        add_cib_op_callback(cib, rc, FALSE, NULL, fencing_topology_callback);
        crm_notice("Watching for stonith topology changes");
    }
    
}

int
main(int argc, char ** argv)
{
    int flag;
    int rc = 0;
    int lpc = 0;
    int argerr = 0;
    int option_index = 0;
    const char *actions[] = { "reboot", "poweroff", "list", "monitor", "status" };

    crm_log_init("stonith-ng", LOG_INFO, TRUE, FALSE, argc, argv);
    crm_set_options(NULL, "mode [options]", long_options,
		    "Provides a summary of cluster's current state."
		    "\n\nOutputs varying levels of detail in a number of different formats.\n");

    while (1) {
	flag = crm_get_option(argc, argv, &option_index);
	if (flag == -1)
	    break;
		
	switch(flag) {
	    case 'V':
		crm_bump_log_level();
		break;
	    case 's':
		stand_alone = TRUE;
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

    if(argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
	printf("<?xml version=\"1.0\"?><!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n");
	printf("<resource-agent name=\"stonithd\">\n");
	printf(" <version>1.0</version>\n");
	printf(" <longdesc lang=\"en\">This is a fake resource that details the instance attributes handled by stonithd.</longdesc>\n");
	printf(" <shortdesc lang=\"en\">Options available for all stonith resources</shortdesc>\n");
	printf(" <parameters>\n");

	printf("  <parameter name=\"stonith-timeout\" unique=\"0\">\n");
	printf("    <shortdesc lang=\"en\">How long to wait for the STONITH action to complete.</shortdesc>\n");
	printf("    <longdesc lang=\"en\">Overrides the stonith-timeout cluster property</longdesc>\n");
	printf("    <content type=\"time\" default=\"60s\"/>\n");
	printf("  </parameter>\n");

	printf("  <parameter name=\"priority\" unique=\"0\">\n");
	printf("    <shortdesc lang=\"en\">The priority of the stonith resource. The lower the number, the higher the priority.</shortdesc>\n");
	printf("    <content type=\"integer\" default=\"0\"/>\n");
	printf("  </parameter>\n");

	printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTARG);
	printf("    <shortdesc lang=\"en\">Advanced use only: An alternate parameter to supply instead of 'port'</shortdesc>\n");
	printf("    <longdesc lang=\"en\">Some devices do not support the standard 'port' parameter or may provide additional ones.\n"
	       "Use this to specify an alternate, device-specific, parameter that should indicate the machine to be fenced.\n"
	       "A value of 'none' can be used to tell the cluster not to supply any additional parameters.\n"
	       "     </longdesc>\n");
	printf("    <content type=\"string\" default=\"port\"/>\n");
	printf("  </parameter>\n");

	printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTMAP);
	printf("    <shortdesc lang=\"en\">A mapping of host names to ports numbers for devices that do not support host names.</shortdesc>\n");
	printf("    <longdesc lang=\"en\">Eg. node1:1;node2:2,3 would tell the cluster to use port 1 for node1 and ports 2 and 3 for node2</longdesc>\n");
	printf("    <content type=\"string\" default=\"\"/>\n");
	printf("  </parameter>\n");

	printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTLIST);
	printf("    <shortdesc lang=\"en\">A list of machines controlled by this device (Optional unless %s=static-list).</shortdesc>\n", STONITH_ATTR_HOSTCHECK);
	printf("    <content type=\"string\" default=\"\"/>\n");
	printf("  </parameter>\n");

	printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTCHECK);
	printf("    <shortdesc lang=\"en\">How to determin which machines are controlled by the device.</shortdesc>\n");
	printf("    <longdesc lang=\"en\">Allowed values: dynamic-list (query the device), static-list (check the %s attribute), none (assume every device can fence every machine)</longdesc>\n", STONITH_ATTR_HOSTLIST);
	printf("    <content type=\"string\" default=\"dynamic-list\"/>\n");
	printf("  </parameter>\n");

	for(lpc = 0; lpc < DIMOF(actions); lpc++) {
	    printf("  <parameter name=\"pcmk_%s_action\" unique=\"0\">\n", actions[lpc]);
	    printf("    <shortdesc lang=\"en\">Advanced use only: An alternate command to run instead of '%s'</shortdesc>\n", actions[lpc]);
	    printf("    <longdesc lang=\"en\">Some devices do not support the standard commands or may provide additional ones.\n"
		   "Use this to specify an alternate, device-specific, command that implements the '%s' action.</longdesc>\n", actions[lpc]);
	    printf("    <content type=\"string\" default=\"%s\"/>\n", actions[lpc]);
	    printf("  </parameter>\n");
	}
	
	printf(" </parameters>\n");
	printf("</resource-agent>\n");
	return 0;
    }

    if (optind != argc) {
	++argerr;
    }
    
    if (argerr) {
	crm_help('?', LSB_EXIT_GENERIC);
    }

    mainloop_add_signal(SIGTERM, stonith_shutdown);
	
    /* EnableProcLogging(); */
    set_sigchld_proctrack(G_PRIORITY_HIGH,DEFAULT_MAXDISPATCHTIME);

    crm_peer_init();
    client_list = g_hash_table_new(crm_str_hash, g_str_equal);
	
    if(stand_alone == FALSE) {
	void *dispatch = stonith_peer_hb_callback;
	void *destroy = stonith_peer_hb_destroy;

	if(is_openais_cluster()) {
#if SUPPORT_COROSYNC
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

        setup_cib();

    } else {
	stonith_our_uname = crm_strdup("localhost");
    }

    device_list = g_hash_table_new_full(
        crm_str_hash, g_str_equal, NULL, free_device);

    topology = g_hash_table_new_full(
        crm_str_hash, g_str_equal, NULL, free_topology_entry);

    channel1 = crm_strdup(stonith_channel);
    rc = init_server_ipc_comms(
	channel1, stonith_client_connect,
	default_ipc_connection_destroy);

    channel2 = crm_strdup(stonith_channel_callback);
    rc = init_server_ipc_comms(
	channel2, stonith_client_connect,
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


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
#include <sys/stat.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <heartbeat.h>
#include <clplumbing/cl_misc.h>
#include <clplumbing/uids.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/Gmain_timeout.h>

/* #include <crm_internal.h> */
#include <ocf/oc_event.h>
/* #include <ocf/oc_membership.h> */

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ctrl.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <attrd.h>

#define OPTARGS	"hV"

GMainLoop*  mainloop = NULL;
const char *attrd_uname = NULL;
char *attrd_uuid = NULL;
ll_cluster_t	*attrd_cluster_conn;
gboolean need_shutdown = FALSE;

GHashTable *attr_hash = NULL;
cib_t *cib_conn = NULL;

typedef struct attr_hash_entry_s 
{
		char *id;
		char *set;
		char *section;

		char *value;
		char *last_value;

		int  timeout;
		char *dampen;
		guint  timer_id;
		
} attr_hash_entry_t;


static void
free_hash_entry(gpointer data)
{
	attr_hash_entry_t *entry = data;
	if (entry == NULL) {
		return;
	}	
	crm_free(entry->id);
	crm_free(entry->set);
	crm_free(entry->dampen);
	crm_free(entry->section);
	if(entry->value != entry->last_value) {
		crm_free(entry->value);
		crm_free(entry->last_value);
	} else {
		crm_free(entry->value);
	}
	crm_free(entry);
}

void attrd_ha_callback(HA_Message * msg, void* private_data);
void attrd_local_callback(HA_Message * msg);
gboolean attrd_timer_callback(void *user_data);
gboolean attrd_trigger_update(attr_hash_entry_t *hash_entry);
void attrd_perform_update(attr_hash_entry_t *hash_entry);

static gboolean
attrd_shutdown(int nsig, gpointer unused)
{
	need_shutdown = TRUE;
	crm_info("Exiting");
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		exit(0);
	}
	return FALSE;
}

static void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-srkh] [-c configure file]\n", cmd);
/* 	fprintf(stream, "\t-d\tsets debug level\n"); */
/* 	fprintf(stream, "\t-s\tgets daemon status\n"); */
/* 	fprintf(stream, "\t-r\trestarts daemon\n"); */
/* 	fprintf(stream, "\t-k\tstops daemon\n"); */
/* 	fprintf(stream, "\t-h\thelp message\n"); */
	fflush(stream);

	exit(exit_status);
}

typedef struct attrd_client_s 
{
		char  *id;
		char  *name;
		
		IPC_Channel *channel;
		GCHSource   *source;
} attrd_client_t;

static void
stop_attrd_timer(attr_hash_entry_t *hash_entry) 
{
	if(hash_entry != NULL && hash_entry->timer_id != 0) {
		crm_debug_2("Stopping %s timer", hash_entry->id);
		Gmain_timeout_remove(hash_entry->timer_id);
		hash_entry->timer_id = 0;
	}
}

static gboolean
attrd_ipc_callback(IPC_Channel *client, gpointer user_data)
{
	int lpc = 0;
	HA_Message *msg = NULL;
	attrd_client_t *curr_client = (attrd_client_t*)user_data;
	gboolean stay_connected = TRUE;
	
	crm_debug_2("Invoked: %s", curr_client->id);

	while(IPC_ISRCONN(client)) {
		if(client->ops->is_message_pending(client) == 0) {
			break;
		}
		
		msg = msgfromIPC_noauth(client);
		if (msg == NULL) {
			crm_debug("%s: no message this time", curr_client->id);
			continue;
		}

		lpc++;
		
		crm_debug_2("Processing msg from %s", curr_client->id);
		crm_log_message_adv(LOG_DEBUG_3, __PRETTY_FUNCTION__, msg);
		
		attrd_local_callback(msg);

		crm_msg_del(msg);
		msg = NULL;

		if(client->ch_status != IPC_CONNECT) {
			break;
		}
	}
	
	crm_debug_2("Processed %d messages", lpc);
	if (client->ch_status != IPC_CONNECT) {
		stay_connected = FALSE;
	}

	return stay_connected;
}

static void
attrd_connection_destroy(gpointer user_data)
{
	attrd_client_t *client = user_data;
	
	/* cib_process_disconnect */

	if(client == NULL) {
		return;
	}

	if(client->source != NULL) {
		crm_debug_4("Deleting %s (%p) from mainloop",
			    client->name, client->source);
		G_main_del_IPC_Channel(client->source); 
		client->source = NULL;
	}
	
	crm_debug_3("Destroying %s (%p)", client->name, client);
	crm_free(client->name);
	crm_free(client->id);
	crm_free(client);
	crm_debug_4("Freed the cib client");

	return;
}

static gboolean
attrd_connect(IPC_Channel *channel, gpointer user_data)
{
	attrd_client_t *new_client = NULL;
	crm_debug_3("Connecting channel");

	if(channel == NULL) {
		crm_err("Channel was NULL");
		return FALSE;

	} else if(channel->ch_status != IPC_CONNECT) {
		crm_err("Channel was disconnected");
		return FALSE;		
	} else if(need_shutdown) {
		crm_info("Ignoring connection request during shutdown");
		return FALSE;		
	}
	

	crm_malloc0(new_client, sizeof(attrd_client_t));
	new_client->channel = channel;
	
	crm_debug_3("Created channel %p for channel %s",
		    new_client, new_client->id);
	
/* 		channel->ops->set_recv_qlen(channel, 100); */
/* 		channel->ops->set_send_qlen(channel, 400); */
	
	new_client->source = G_main_add_IPC_Channel(
		G_PRIORITY_DEFAULT, channel, FALSE, attrd_ipc_callback,
		new_client, attrd_connection_destroy);
	
	crm_debug_3("Client %s connected", new_client->id);
	
	return TRUE;
}

static gboolean
attrd_ha_dispatch(IPC_Channel *channel, gpointer user_data)
{
	gboolean stay_connected = TRUE;

	crm_debug_2("Invoked");

	while(attrd_cluster_conn != NULL && IPC_ISRCONN(channel)) {
		if(attrd_cluster_conn->llc_ops->msgready(attrd_cluster_conn) == 0) {
			crm_debug_2("no message ready yet");
			break;
		}
		/* invoke the callbacks but dont block */
		attrd_cluster_conn->llc_ops->rcvmsg(attrd_cluster_conn, 0);
	}
	
	if (attrd_cluster_conn == NULL || channel->ch_status != IPC_CONNECT) {
		if(need_shutdown == FALSE) {
			crm_crit("Lost connection to heartbeat service.");
		} else {
			crm_info("Lost connection to heartbeat service.");
		}
		stay_connected = FALSE;
	}
    
	return stay_connected;
}

static void
attrd_ha_connection_destroy(gpointer user_data)
{
	crm_debug_3("Invoked");
	if(need_shutdown) {
		/* we signed out, so this is expected */
		crm_info("Heartbeat disconnection complete");
		return;
	}

	crm_crit("Lost connection to heartbeat service!");
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
		return;
	}
	exit(LSB_EXIT_OK);	
}


static gboolean
register_with_ha(void) 
{
	const char *const_attrd_uuid = NULL;
	if(attrd_cluster_conn == NULL) {
		attrd_cluster_conn = ll_cluster_new("heartbeat");
	}
	if(attrd_cluster_conn == NULL) {
		crm_err("Cannot create heartbeat object");
		return FALSE;
	}
	
	crm_debug("Signing in with Heartbeat");
	if (attrd_cluster_conn->llc_ops->signon(attrd_cluster_conn, T_ATTRD)!= HA_OK) {

		crm_err("Cannot sign on with heartbeat: %s",
			attrd_cluster_conn->llc_ops->errmsg(attrd_cluster_conn));
		return FALSE;
	}

	crm_debug_3("Be informed of CRM messages");
	if (HA_OK != attrd_cluster_conn->llc_ops->set_msg_callback(
		    attrd_cluster_conn, T_ATTRD, attrd_ha_callback,
		    attrd_cluster_conn)) {
		
		crm_err("Cannot set msg callback: %s",
			attrd_cluster_conn->llc_ops->errmsg(attrd_cluster_conn));
		return FALSE;
	}

	crm_debug_3("Adding channel to mainloop");
	G_main_add_IPC_Channel(
		G_PRIORITY_HIGH, attrd_cluster_conn->llc_ops->ipcchan(
			attrd_cluster_conn),
		FALSE, attrd_ha_dispatch, attrd_cluster_conn /* userdata  */,  
		attrd_ha_connection_destroy);

	crm_debug_3("Finding our node name");
	attrd_uname = attrd_cluster_conn->llc_ops->get_mynodeid(
		attrd_cluster_conn);
	if (attrd_uname == NULL) {
		crm_err("get_mynodeid() failed");
		return FALSE;
	}
	crm_info("Hostname: %s", attrd_uname);

	crm_debug_3("Finding our node uuid");
	const_attrd_uuid = get_uuid(attrd_cluster_conn, attrd_uname);
	if(const_attrd_uuid == NULL) {
		crm_err("get_uuid_by_name() failed");
		return FALSE;
	}
	/* copy it so that unget_uuid() doesn't trash the value on us */
	attrd_uuid = crm_strdup(const_attrd_uuid);
	crm_info("UUID: %s", attrd_uuid);

	return TRUE;
}

static void
attrd_cib_connection_destroy(gpointer user_data)
{
	if(need_shutdown) {
	    crm_info("Connection to the CIB terminated...");

	} else {
	    /* eventually this will trigger a reconnect, not a shutdown */ 
	    crm_err("Connection to the CIB terminated...");
	    exit(1);
	}
	
	return;
}

int
main(int argc, char ** argv)
{
	int flag;
	int argerr = 0;
	gboolean was_err = FALSE;
	char *channel_name = crm_strdup(attrd_channel);
	
	crm_log_init(T_ATTRD, LOG_INFO, TRUE, FALSE, 0, NULL);
	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, attrd_shutdown, NULL, NULL);
	
	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				cl_log_enable_stderr(1);
				alter_debug(DEBUG_INC);
				break;
			case 'h':		/* Help message */
				usage(T_ATTRD, LSB_EXIT_OK);
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
		usage(T_ATTRD, LSB_EXIT_GENERIC);
	}

	if(register_with_ha() == FALSE) {
		crm_err("HA Signon failed");
		was_err = TRUE;
	}

	if(was_err == FALSE) {
		int lpc = 0;
		int max_retry = 20;
		enum cib_errors rc = cib_not_connected;
		cib_conn = cib_new();
		for(lpc = 0; lpc < max_retry && rc != cib_ok; lpc++) {
			crm_debug("CIB signon attempt %d", lpc);
			rc = cib_conn->cmds->signon(
				cib_conn, T_ATTRD, cib_command);
			sleep(5);
		}
		if(rc != cib_ok) {
			crm_err("Signon to CIB failed: %s",
				cib_error2string(rc));
			was_err = TRUE;
		}
	}

	if(was_err == FALSE) {
	    enum cib_errors rc = cib_conn->cmds->set_connection_dnotify(
		cib_conn, attrd_cib_connection_destroy);
	    if(rc != cib_ok) {
		crm_err("Could not set dnotify callback");
		was_err = TRUE;
	    }
	}
	
	if(was_err == FALSE) {
		int rc = init_server_ipc_comms(
			channel_name, attrd_connect,
			default_ipc_connection_destroy);
		
		if(rc != 0) {
			crm_err("Could not start IPC server");
			was_err = TRUE;
		}
	}

	if(was_err) {
		crm_err("Aborting startup");
		return 100;
	}

	attr_hash = g_hash_table_new_full(
		g_str_hash, g_str_equal, NULL, free_hash_entry);

	crm_info("Starting mainloop...");
	mainloop = g_main_new(FALSE);
	g_main_run(mainloop);
	crm_info("Exiting...");

	attrd_cluster_conn->llc_ops->signoff(attrd_cluster_conn, TRUE);
	attrd_cluster_conn->llc_ops->delete(attrd_cluster_conn);
	
	cib_conn->cmds->signoff(cib_conn);
	cib_delete(cib_conn);

	g_hash_table_destroy(attr_hash);
	crm_free(channel_name);
	crm_free(attrd_uuid);
	empty_uuid_cache();

	return 0;
}

static void
attrd_cib_callback(const HA_Message *msg, int call_id, int rc,
		   crm_data_t *output, void *user_data)
{
	char *attr = user_data;
	if(rc == cib_NOTEXISTS) {
		rc = cib_ok;
	}
	if(rc < cib_ok) {
		crm_err("Update %d for %s failed: %s", call_id, attr, cib_error2string(rc));
	} else {
		crm_debug("Update %d for %s passed", call_id, attr);
	}
	crm_free(attr);
}

static void
log_hash_entry(int level, attr_hash_entry_t *entry, const char *text) 
{
	do_crm_log(level, "%s", text);
	do_crm_log(level, "Set:     %s", entry->section);
	do_crm_log(level, "Name:    %s", entry->id);
	do_crm_log(level, "Value:   %s", entry->value);
	do_crm_log(level, "Timeout: %s", entry->dampen);
}

static attr_hash_entry_t *
find_hash_entry(HA_Message * msg) 
{
	const char *value = NULL;
	const char *attr  = ha_msg_value(msg, F_ATTRD_ATTRIBUTE);
	attr_hash_entry_t *hash_entry = NULL;

	if(attr == NULL) {
		crm_info("Ignoring message with no attribute name");
		return NULL;
	}
	
	hash_entry = g_hash_table_lookup(attr_hash, attr);

	if(hash_entry == NULL) {	
		/* create one and add it */
		crm_info("Creating hash entry for %s", attr);
		crm_malloc0(hash_entry, sizeof(attr_hash_entry_t));
		hash_entry->id = crm_strdup(attr);

		g_hash_table_insert(attr_hash, hash_entry->id, hash_entry);
		hash_entry = g_hash_table_lookup(attr_hash, attr);
		CRM_CHECK(hash_entry != NULL, return NULL);
	}

	value = ha_msg_value(msg, F_ATTRD_SET);
	if(value != NULL) {
		crm_free(hash_entry->set);
		hash_entry->set = crm_strdup(value);
		crm_debug("\t%s->set: %s", attr, value);
	}
	
	value = ha_msg_value(msg, F_ATTRD_SECTION);
	if(value == NULL) {
		value = XML_CIB_TAG_STATUS;
	}
	crm_free(hash_entry->section);
	hash_entry->section = crm_strdup(value);
	crm_debug("\t%s->section: %s", attr, value);
	
	value = ha_msg_value(msg, F_ATTRD_DAMPEN);
	if(value != NULL) {
		crm_free(hash_entry->dampen);
		hash_entry->dampen = crm_strdup(value);

		hash_entry->timeout = crm_get_msec(value);
		crm_debug("\t%s->timeout: %s", attr, value);
	}

	log_hash_entry(LOG_DEBUG_2, hash_entry, "Found (and updated) entry:");
	return hash_entry;
}

void
attrd_ha_callback(HA_Message * msg, void* private_data)
{
	attr_hash_entry_t *hash_entry = NULL;
	const char *from   = ha_msg_value(msg, F_ORIG);
	const char *op     = ha_msg_value(msg, F_ATTRD_TASK);
	const char *ignore = ha_msg_value(msg, F_ATTRD_IGNORE_LOCALLY);

	if(ignore == NULL || safe_str_neq(from, attrd_uname)) {
		crm_info("%s message from %s", op, from);
		hash_entry = find_hash_entry(msg);
		stop_attrd_timer(hash_entry);
		attrd_perform_update(hash_entry);
	}
}

void
attrd_perform_update(attr_hash_entry_t *hash_entry)
{
	int rc = cib_ok;

	if(hash_entry == NULL) {
	    return;
	    
	} else if(hash_entry->value == NULL) {
		/* delete the attr */
		rc = delete_attr(cib_conn, cib_none, hash_entry->section, attrd_uuid,
				 hash_entry->set, NULL, hash_entry->id, NULL, FALSE);
		crm_info("Sent delete %d: %s %s %s",
			 rc, hash_entry->id, hash_entry->set, hash_entry->section);
		
	} else {
		/* send update */
		rc = update_attr(cib_conn, cib_none, hash_entry->section,
 				 attrd_uuid, hash_entry->set, NULL,
 				 hash_entry->id, hash_entry->value, FALSE);
		crm_info("Sent update %d: %s=%s", rc, hash_entry->id, hash_entry->value);
	}

	add_cib_op_callback(rc, FALSE, crm_strdup(hash_entry->id), attrd_cib_callback);
	
	return;
}

static void
update_for_hash_entry(gpointer key, gpointer value, gpointer user_data)
{
	attrd_timer_callback(value);
}


void
attrd_local_callback(HA_Message * msg)
{
	attr_hash_entry_t *hash_entry = NULL;
	const char *from  = ha_msg_value(msg, F_ORIG);
	const char *op    = ha_msg_value(msg, F_ATTRD_TASK);
	const char *attr  = ha_msg_value(msg, F_ATTRD_ATTRIBUTE);
	const char *value = ha_msg_value(msg, F_ATTRD_VALUE);

	if(safe_str_eq(op, "refresh")) {
		crm_info("Sending full refresh");
		g_hash_table_foreach(attr_hash, update_for_hash_entry, NULL);
		return;
	}

	crm_debug("%s message from %s: %s=%s", op, from, attr, crm_str(value));
	hash_entry = find_hash_entry(msg);
	if(hash_entry == NULL) {
	    return;
	}
	
	crm_free(hash_entry->last_value);
	hash_entry->last_value = hash_entry->value;

	if(value != NULL) {
		hash_entry->value = crm_strdup(value);

	} else {
		hash_entry->value = NULL;
	}
	
	if(safe_str_eq(hash_entry->value, hash_entry->last_value)) {
		crm_debug_2("Ignoring non-change");
		return;
	}

	stop_attrd_timer(hash_entry);
	
	if(hash_entry->timeout > 0) {
		hash_entry->timer_id = Gmain_timeout_add(
			hash_entry->timeout, attrd_timer_callback, hash_entry);
	} else {
		attrd_trigger_update(hash_entry);
	}
	
	return;
}

gboolean
attrd_timer_callback(void *user_data)
{
 	stop_attrd_timer(user_data);
	attrd_trigger_update(user_data);
	return TRUE;
}

gboolean
attrd_trigger_update(attr_hash_entry_t *hash_entry)
{
	HA_Message *msg = NULL;

	/* send HA message to everyone */
	crm_info("Sending flush op to all hosts for: %s", hash_entry->id);
 	log_hash_entry(LOG_DEBUG_2, hash_entry, "Sending flush op to all hosts for:");

	msg = ha_msg_new(8);
	ha_msg_add(msg, F_TYPE, T_ATTRD);
	ha_msg_add(msg, F_ORIG, attrd_uname);
	ha_msg_add(msg, F_ATTRD_TASK, "flush");
	ha_msg_add(msg, F_ATTRD_ATTRIBUTE, hash_entry->id);
	ha_msg_add(msg, F_ATTRD_SET, hash_entry->set);
	ha_msg_add(msg, F_ATTRD_SECTION, hash_entry->section);
	ha_msg_add(msg, F_ATTRD_DAMPEN, hash_entry->dampen);
	ha_msg_add(msg, F_ATTRD_VALUE, hash_entry->value);

	if(hash_entry->timeout <= 0) {
		ha_msg_add(msg, F_ATTRD_IGNORE_LOCALLY, hash_entry->value);
		attrd_perform_update(hash_entry);
	}

	send_ha_message(attrd_cluster_conn, msg, NULL, FALSE);
	crm_msg_del(msg);
	
	return TRUE;
}

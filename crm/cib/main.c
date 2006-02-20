/* $Id: main.c,v 1.39 2006/02/20 11:39:46 andrew Exp $ */
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

/* #include <portability.h> */
#include <ocf/oc_event.h>
/* #include <ocf/oc_membership.h> */

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ctrl.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <cibio.h>
#include <callbacks.h>

#include <crm/dmalloc_wrapper.h>

gboolean cib_shutdown_flag = FALSE;
unsigned int cib_diff_loglevel = LOG_INFO;

extern void oc_ev_special(const oc_ev_t *, oc_ev_class_t , int );

GMainLoop*  mainloop = NULL;
const char* crm_system_name = CRM_SYSTEM_CIB;
char *cib_our_uname = NULL;
oc_ev_t *cib_ev_token;
gboolean cib_writes_enabled = TRUE;

void usage(const char* cmd, int exit_status);
int init_start(void);
gboolean cib_register_ha(ll_cluster_t *hb_cluster, const char *client_name);
gboolean cib_shutdown(int nsig, gpointer unused);
void cib_ha_connection_destroy(gpointer user_data);
gboolean startCib(const char *filename);
extern gboolean cib_msg_timeout(gpointer data);
extern int write_cib_contents(gpointer p);

ll_cluster_t *hb_conn = NULL;
GTRIGSource *cib_writer = NULL;

#define OPTARGS	"hV"

int
main(int argc, char ** argv)
{
	int flag;
	int argerr = 0;
	char *param_val = NULL;
	const char *param_name = NULL;

	crm_log_init(crm_system_name);
	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, cib_shutdown, NULL, NULL);
	
	cib_writer = G_main_add_tempproc_trigger(			
		G_PRIORITY_LOW, write_cib_contents, "write_cib_contents",
		NULL, NULL, NULL);

	EnableProcLogging();
	set_sigchld_proctrack(G_PRIORITY_HIGH);

	client_list = g_hash_table_new(g_str_hash, g_str_equal);
	peer_hash = g_hash_table_new(g_str_hash, g_str_equal);
	
	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				cl_log_enable_stderr(1);
				alter_debug(DEBUG_INC);
				break;
			case 'h':		/* Help message */
				usage(crm_system_name, LSB_EXIT_OK);
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
		usage(crm_system_name,LSB_EXIT_GENERIC);
	}
    
	/* apparently we're not allowed to free the result of getenv */
	param_name = ENV_PREFIX "" KEY_CONFIG_WRITES_ENABLED;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	if(param_val != NULL) {
		cl_str_to_boolean(param_val, &cib_writes_enabled);
		param_val = NULL;
	}
	crm_info("Disk writes to %s: %s", CIB_FILENAME,
		 cib_writes_enabled?"enabled":"DISABLED");

	param_name = ENV_PREFIX "" KEY_LOG_CONFIG_CHANGES;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	cib_diff_loglevel = crm_log_level;
	if(param_val != NULL) {
		int do_log = 0;
		cl_str_to_boolean(param_val, &do_log);
		if(do_log == FALSE) {
			cib_diff_loglevel = crm_log_level + 1;
		}
		param_val = NULL;
	}
	crm_info("Configuration changes logged at: debug %d",
		 cib_diff_loglevel - LOG_INFO);

	/* read local config file */
	return init_start();
}

unsigned long cib_num_ops = 0;
const char *cib_stat_interval = "10min";
unsigned long cib_num_local = 0, cib_num_updates = 0, cib_num_fail = 0;
unsigned long cib_bad_connects = 0, cib_num_timeouts = 0;
longclock_t cib_call_time = 0;

gboolean cib_stats(gpointer data);

gboolean
cib_stats(gpointer data)
{
	int local_log_level = LOG_DEBUG;
	static unsigned long last_stat = 0;
	unsigned int cib_calls_ms = 0;
	static unsigned long cib_stat_interval_ms = 0;

	if(cib_stat_interval_ms == 0) {
		cib_stat_interval_ms = crm_get_msec(cib_stat_interval);
	}
	
	cib_calls_ms = longclockto_ms(cib_call_time);

	if((cib_num_ops - last_stat) > 0) {
		unsigned long calls_diff = cib_num_ops - last_stat;
		double stat_1 = (1000*cib_calls_ms)/calls_diff;
		
		local_log_level = LOG_INFO;
		crm_log_maybe(local_log_level,
			      "Processed %lu operations"
			      " (%.2fus average, %lu%% utilization) in the last %s",
			      calls_diff, stat_1, 
			      (100*cib_calls_ms)/cib_stat_interval_ms,
			      cib_stat_interval);
	}
	
	crm_log_maybe(local_log_level+1,
		      "\tDetail: %lu operations (%ums total)"
		      " (%lu local, %lu updates, %lu failures,"
		      " %lu timeouts, %lu bad connects)",
		      cib_num_ops, cib_calls_ms, cib_num_local, cib_num_updates,
		      cib_num_fail, cib_bad_connects, cib_num_timeouts);

	last_stat = cib_num_ops;
	cib_call_time = 0;
	return TRUE;
}

int
init_start(void)
{
	gboolean was_error = FALSE;

	hb_conn = ll_cluster_new("heartbeat");
	if(cib_register_ha(hb_conn, CRM_SYSTEM_CIB) == FALSE) {
		crm_crit("Cannot sign in to heartbeat... terminating");
		fprintf(stderr, "Cannot sign in to heartbeat... terminating");
		exit(1);
	}

	if(startCib(CIB_FILENAME) == FALSE){
		crm_crit("Cannot start CIB... terminating");
		exit(1);
	}
	
	was_error = init_server_ipc_comms(
		crm_strdup(cib_channel_callback), cib_client_connect_null,
		default_ipc_connection_destroy);

	was_error = was_error || init_server_ipc_comms(
		crm_strdup(cib_channel_ro), cib_client_connect_rw_ro,
		default_ipc_connection_destroy);

	was_error = was_error || init_server_ipc_comms(
		crm_strdup(cib_channel_rw), cib_client_connect_rw_ro,
		default_ipc_connection_destroy);

	was_error = was_error || init_server_ipc_comms(
		crm_strdup(cib_channel_rw_synchronous), cib_client_connect_rw_synch,
		default_ipc_connection_destroy);

	was_error = was_error || init_server_ipc_comms(
		crm_strdup(cib_channel_ro_synchronous), cib_client_connect_ro_synch,
		default_ipc_connection_destroy);
	
	if(was_error == FALSE) {
		crm_debug_3("Be informed of CRM Client Status changes");
		if (HA_OK != hb_conn->llc_ops->set_cstatus_callback(
			    hb_conn, cib_client_status_callback, hb_conn)) {
			
			crm_err("Cannot set cstatus callback: %s",
				hb_conn->llc_ops->errmsg(hb_conn));
			was_error = TRUE;
		} else {
			crm_debug_3("Client Status callback set");
		}
	}

	if(was_error == FALSE) {
		gboolean did_fail = TRUE;
		int num_ccm_fails = 0;
		int max_ccm_fails = 30;
		int ret;
		int cib_ev_fd;
		
		while(did_fail && was_error == FALSE) {
			did_fail = FALSE;
			crm_debug_3("Registering with CCM");
			ret = oc_ev_register(&cib_ev_token);
			if (ret != 0) {
				crm_warn("CCM registration failed");
				did_fail = TRUE;
			}
			
			if(did_fail == FALSE) {
				crm_debug_3("Setting up CCM callbacks");
				ret = oc_ev_set_callback(
					cib_ev_token, OC_EV_MEMB_CLASS,
					cib_ccm_msg_callback, NULL);
				if (ret != 0) {
					crm_warn("CCM callback not set");
					did_fail = TRUE;
				}
			}
			if(did_fail == FALSE) {
				oc_ev_special(cib_ev_token, OC_EV_MEMB_CLASS, 0);
				
				crm_debug_3("Activating CCM token");
				ret = oc_ev_activate(cib_ev_token, &cib_ev_fd);
				if (ret != 0){
					crm_warn("CCM Activation failed");
					did_fail = TRUE;
				}
			}
			
			if(did_fail) {
				num_ccm_fails++;
				oc_ev_unregister(cib_ev_token);
				
				if(num_ccm_fails < max_ccm_fails){
					crm_warn("CCM Connection failed"
						 " %d times (%d max)",
						 num_ccm_fails, max_ccm_fails);
					sleep(1);
					
				} else {
					crm_err("CCM Activation failed"
						" %d (max) times",
						num_ccm_fails);
					was_error = TRUE;
					
				}
			}
		}

		crm_debug_3("CCM Activation passed... all set to go!");
		G_main_add_fd(G_PRIORITY_HIGH, cib_ev_fd, FALSE,
			      cib_ccm_dispatch, cib_ev_token,
			      default_ipc_connection_destroy);
	}

	if(was_error == FALSE) {
		/* Async get client status information in the cluster */
		crm_debug_3("Requesting an initial dump of CIB client_status");
		hb_conn->llc_ops->client_status(
			hb_conn, NULL, CRM_SYSTEM_CIB, -1);

		/* Create the mainloop and run it... */
		mainloop = g_main_new(FALSE);
		crm_info("Starting %s mainloop", crm_system_name);

		Gmain_timeout_add(crm_get_msec("10s"), cib_msg_timeout, NULL);
		Gmain_timeout_add(
			crm_get_msec(cib_stat_interval), cib_stats, NULL); 
		
		g_main_run(mainloop);
		return_to_orig_privs();

	} else {
		crm_err("Couldnt start all communication channels, exiting.");
	}
	
	return 0;
}

void
usage(const char* cmd, int exit_status)
{
	FILE* stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-srkh]"
		"[-c configure file]\n", cmd);
/* 	fprintf(stream, "\t-d\tsets debug level\n"); */
/* 	fprintf(stream, "\t-s\tgets daemon status\n"); */
/* 	fprintf(stream, "\t-r\trestarts daemon\n"); */
/* 	fprintf(stream, "\t-k\tstops daemon\n"); */
/* 	fprintf(stream, "\t-h\thelp message\n"); */
	fflush(stream);

	exit(exit_status);
}


gboolean
cib_register_ha(ll_cluster_t *hb_cluster, const char *client_name)
{
	const char *uname = NULL;
	
	crm_info("Signing in with Heartbeat");
	if (hb_cluster->llc_ops->signon(hb_cluster, client_name)!= HA_OK) {
		crm_err("Cannot sign on with heartbeat: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_set_ha_options(hb_cluster);
	
	crm_debug_3("Be informed of CIB messages");
	if (HA_OK != hb_cluster->llc_ops->set_msg_callback(
		    hb_cluster, T_CIB, cib_peer_callback, hb_cluster)){
		
		crm_err("Cannot set msg callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_debug_3("Finding our node name");
	if ((uname = hb_cluster->llc_ops->get_mynodeid(hb_cluster)) == NULL) {
		crm_err("get_mynodeid() failed");
		return FALSE;
	}
	
	cib_our_uname = crm_strdup(uname);
	crm_info("FSA Hostname: %s", cib_our_uname);

	crm_debug_3("Adding channel to mainloop");
	G_main_add_IPC_Channel(
		G_PRIORITY_DEFAULT, hb_cluster->llc_ops->ipcchan(hb_cluster),
		FALSE, cib_ha_dispatch, hb_cluster /* userdata  */,  
		cib_ha_connection_destroy);

	return TRUE;
    
}

void
cib_ha_connection_destroy(gpointer user_data)
{
	if(cib_shutdown_flag) {
		crm_info("Heartbeat disconnection complete... exiting");
	} else {
		crm_err("Heartbeat connection lost!  Exiting.");
	}
		
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
		
	} else {
		exit(LSB_EXIT_OK);
	}
}


static void
disconnect_cib_client(gpointer key, gpointer value, gpointer user_data) 
{
	cib_client_t *a_client = value;
	crm_debug_2("Processing client %s/%s... send=%d, recv=%d",
		  a_client->name, a_client->channel_name,
		  (int)a_client->channel->send_queue->current_qlen,
		  (int)a_client->channel->recv_queue->current_qlen);

	if(a_client->channel->ch_status == IPC_CONNECT) {
		a_client->channel->ops->resume_io(a_client->channel);
		if(a_client->channel->send_queue->current_qlen != 0
		   || a_client->channel->recv_queue->current_qlen != 0) {
			crm_info("Flushed messages to/from %s/%s... send=%d, recv=%d",
				a_client->name, a_client->channel_name,
				(int)a_client->channel->send_queue->current_qlen,
				(int)a_client->channel->recv_queue->current_qlen);
		}
	}

	if(a_client->channel->ch_status == IPC_CONNECT) {
		crm_warn("Disconnecting %s/%s...",
			 a_client->name, a_client->channel_name);
		a_client->channel->ops->disconnect(a_client->channel);
	}
}

extern gboolean cib_process_disconnect(
	IPC_Channel *channel, cib_client_t *cib_client);

gboolean
cib_shutdown(int nsig, gpointer unused)
{
	if(cib_shutdown_flag == FALSE) {
		cib_shutdown_flag = TRUE;
		crm_debug("Disconnecting %d clients",
			 g_hash_table_size(client_list));
		g_hash_table_foreach(client_list, disconnect_cib_client, NULL);
		crm_info("Disconnected %d clients",
			 g_hash_table_size(client_list));
		cib_process_disconnect(NULL, NULL);

	} else {
		crm_info("Waiting for %d clients to disconnect...",
			 g_hash_table_size(client_list));
	}
	
	
	return TRUE;
}

gboolean
startCib(const char *filename)
{
	crm_data_t *cib = readCibXmlFile(filename);

	if(cib == NULL) {
		crm_warn("CIB Initialization failed, "
			 "starting with an empty default.");

		cib = createEmptyCib();
		crm_xml_add(cib, XML_ATTR_GENERATION_ADMIN, "0");
		crm_xml_add(cib, XML_ATTR_GENERATION, "0");
		crm_xml_add(cib, XML_ATTR_NUMUPDATES, "0");
	}
	
	if(activateCibXml(cib, filename) != 0) {
		return FALSE;
	}

	crm_info("CIB Initialization completed successfully");
	return TRUE;
}

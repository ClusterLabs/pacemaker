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

#include <lha_internal.h>

#include <sys/param.h>

#include <heartbeat.h>
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ctrl.h>
#include <crm/pengine/rules.h>
#include <crm/common/cluster.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>

#include <sys/types.h>
#include <sys/stat.h>


char *ipc_server = NULL;

extern void crmd_ha_connection_destroy(gpointer user_data);

gboolean crm_shutdown(int nsig, gpointer unused);
gboolean register_with_ha(ll_cluster_t *hb_cluster, const char *client_name);

gboolean      fsa_has_quorum = FALSE;
GHashTable   *ipc_clients = NULL;
GTRIGSource  *fsa_source = NULL;

/*	 A_HA_CONNECT	*/
#ifdef WITH_NATIVE_AIS	
extern void crmd_ha_msg_filter(HA_Message * msg);

static gboolean crm_ais_dispatch(AIS_Message *wrapper, char *data, int sender) 
{
    crm_data_t *xml = string2xml(data);
    if(xml != NULL) {
	crm_debug_2("Message received: %d:'%.120s'", wrapper->header.id, data);
	ha_msg_add(xml, F_ORIG, wrapper->sender.uname);
	ha_msg_add_int(xml, F_SEQ, wrapper->id);

	switch(wrapper->header.id) {
	    case crm_class_notify:
		break;
	    case crm_class_members:
		do_ccm_update_cache(
		    C_HA_MESSAGE, fsa_state, OC_EV_MS_NEW_MEMBERSHIP, NULL, xml);
		crm_update_quorum(crm_have_quorum);
		break;
	    default:
		crmd_ha_msg_filter(xml);
		break;
	}
	free_xml(xml);
	
    } else {
	crm_err("Invalid message: %s", data);
    }
    return TRUE;
}

static void
crm_ais_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_in = -1;
    exit(1);
}
#endif

void
do_ha_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	gboolean registered = FALSE;
	
	if(action & A_HA_DISCONNECT) {
#ifdef WITH_NATIVE_AIS
		crm_peer_destroy();
#else
		if(fsa_cluster_conn != NULL) {
			set_bit_inplace(fsa_input_register, R_HA_DISCONNECTED);
			fsa_cluster_conn->llc_ops->signoff(
				fsa_cluster_conn, FALSE);
		}
#endif
		crm_info("Disconnected from Heartbeat");
	}
	
	if(action & A_HA_CONNECT) {
#ifdef WITH_NATIVE_AIS
		crm_peer_init();
		registered = init_ais_connection(
		    crm_ais_dispatch, crm_ais_destroy, &fsa_our_uname);
		fsa_our_uuid = crm_strdup(fsa_our_uname);
#else
		if(fsa_cluster_conn == NULL) {
			fsa_cluster_conn = ll_cluster_new("heartbeat");
		}
		
		/* make sure we are disconnected first */
		fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn, FALSE);
		
		registered = register_with_ha(
			fsa_cluster_conn, crm_system_name);
#endif
		if(registered == FALSE) {
			set_bit_inplace(fsa_input_register, R_HA_DISCONNECTED);
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
			return;
		}
		clear_bit_inplace(fsa_input_register, R_HA_DISCONNECTED);
		crm_info("Connected to Heartbeat");
	} 
	
	if(action & ~(A_HA_CONNECT|A_HA_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
}

/*	 A_SHUTDOWN	*/
void
do_shutdown(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	int lpc = 0;
	gboolean continue_shutdown = TRUE;
	struct crm_subsystem_s *subsystems[] = {
		pe_subsystem,
		te_subsystem
	};

	/* just in case */
	set_bit_inplace(fsa_input_register, R_SHUTDOWN);

	for(lpc = 0; lpc < DIMOF(subsystems); lpc++) {
		struct crm_subsystem_s *a_subsystem = subsystems[lpc];
		if(is_set(fsa_input_register, a_subsystem->flag_connected)) {
			crm_info("Terminating the %s", a_subsystem->name);
			if(stop_subsystem(a_subsystem, TRUE) == FALSE) {
				/* its gone... */
				crm_err("Faking %s exit", a_subsystem->name);
				clear_bit_inplace(fsa_input_register,
						  a_subsystem->flag_connected);
			}
			continue_shutdown = FALSE;
		}
	}
    
	if(continue_shutdown == FALSE) {
		crm_info("Waiting for subsystems to exit");
		crmd_fsa_stall(NULL);
	}
	
	crm_info("All subsystems stopped, continuing");
}

/*	 A_SHUTDOWN_REQ	*/
void
do_shutdown_req(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	HA_Message *msg = NULL;
	
	crm_info("Sending shutdown request to DC: %s", crm_str(fsa_our_dc));
	msg = create_request(
		CRM_OP_SHUTDOWN_REQ, NULL, NULL,
		CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

/* 	set_bit_inplace(fsa_input_register, R_STAYDOWN); */
	if(send_request(msg, NULL) == FALSE) {
		if(AM_I_DC) {
			crm_info("Processing shutdown locally");
		} else {
			register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
		}
	}
}

extern char *max_generation_from;
extern crm_data_t *max_generation_xml;
extern GHashTable *meta_hash;
extern GHashTable *resources;
extern GHashTable *voted;

void log_connected_client(gpointer key, gpointer value, gpointer user_data);

void
log_connected_client(gpointer key, gpointer value, gpointer user_data)
{
	crmd_client_t *client = value;
	crm_err("%s is still connected at exit", client->table_key);
}


static void free_mem(fsa_data_t *msg_data) 
{
	if(fsa_cluster_conn) {
		fsa_cluster_conn->llc_ops->delete(fsa_cluster_conn);
		fsa_cluster_conn = NULL;
	}
	
	slist_destroy(fsa_data_t, fsa_data, fsa_message_queue, 
		      crm_info("Dropping %s: [ state=%s cause=%s origin=%s ]",
			       fsa_input2string(fsa_data->fsa_input),
			       fsa_state2string(fsa_state),
			       fsa_cause2string(fsa_data->fsa_cause),
			       fsa_data->origin);
		      delete_fsa_input(fsa_data);
		);
	
	delete_fsa_input(msg_data);

	if(ipc_clients) {
		crm_debug("Number of connected clients: %d",
			  g_hash_table_size(ipc_clients));
/* 		g_hash_table_foreach(ipc_clients, log_connected_client, NULL); */
		g_hash_table_destroy(ipc_clients);
	}
	
	empty_uuid_cache();
	crm_peer_destroy();
	clear_bit_inplace(fsa_input_register, R_CCM_DATA);

	if(te_subsystem->client && te_subsystem->client->client_source) {
		crm_debug("Full destroy: TE");
		G_main_del_IPC_Channel(te_subsystem->client->client_source);
	} else {
		crm_debug("Partial destroy: TE");
		crmd_ipc_connection_destroy(te_subsystem->client);
	}
	crm_free(te_subsystem);
	
	if(pe_subsystem->client && pe_subsystem->client->client_source) {
		crm_debug("Full destroy: PE");
		G_main_del_IPC_Channel(pe_subsystem->client->client_source);
	} else {
		crm_debug("Partial destroy: PE");
		crmd_ipc_connection_destroy(pe_subsystem->client);
	}
	crm_free(pe_subsystem);
	
	crm_free(cib_subsystem);
	
	if(integrated_nodes) {
		g_hash_table_destroy(integrated_nodes);
	}
	if(finalized_nodes) {
		g_hash_table_destroy(finalized_nodes);
	}
	if(confirmed_nodes) {
		g_hash_table_destroy(confirmed_nodes);
	}
	if(meta_hash) {
		g_hash_table_destroy(meta_hash);
	}
	if(resources) {
		g_hash_table_destroy(resources);
	}
	if(voted) {
		g_hash_table_destroy(voted);
	}

	cib_delete(fsa_cib_conn);
	fsa_cib_conn = NULL;

	if(fsa_lrm_conn) {
		fsa_lrm_conn->lrm_ops->delete(fsa_lrm_conn);
	}
	
	crm_free(integration_timer);
	crm_free(finalization_timer);
	crm_free(election_trigger);
	crm_free(election_timeout);
	crm_free(shutdown_escalation_timer);
	crm_free(wait_timer);
	crm_free(recheck_timer);

	crm_free(fsa_our_dc_version);
	crm_free(fsa_our_uuid);
	crm_free(fsa_our_dc);
	crm_free(ipc_server);

 	crm_free(max_generation_from);
 	free_xml(max_generation_xml);
}

/*	 A_EXIT_0, A_EXIT_1	*/
void
do_exit(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	fsa_data_t *msg_data)
{
	int exit_code = 0;
	int log_level = LOG_INFO;
	const char *exit_type = "gracefully";
	
	if(action & A_EXIT_1) {
		exit_code = 1;
		log_level = LOG_ERR;
		exit_type = "forcefully";
	}
	
	verify_stopped(cur_state, LOG_ERR);
	do_crm_log(log_level, "Performing %s - %s exiting the CRMd",
		      fsa_action2string(action), exit_type);
	
	if(is_set(fsa_input_register, R_IN_RECOVERY)) {
		crm_err("Could not recover from internal error");
		exit_code = 2;		
	} 
	if(is_set(fsa_input_register, R_STAYDOWN)) {
		crm_warn("Inhibiting respawn by Heartbeat");
		exit_code = 100;
	}

	free_mem(msg_data);
	
	crm_info("[%s] stopped (%d)", crm_system_name, exit_code);
	cl_flush_logs();
	exit(exit_code);
}

/*	 A_STARTUP	*/
void
do_startup(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   fsa_data_t *msg_data)
{
	int was_error = 0;
	int interval = 1; /* seconds between DC heartbeats */

	crm_debug("Registering Signal Handlers");
	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, crm_shutdown, NULL, NULL);

	fsa_source = G_main_add_TriggerHandler(
		G_PRIORITY_HIGH, crm_fsa_trigger, NULL, NULL);

	ipc_clients = g_hash_table_new(g_str_hash, g_str_equal);
	
	crm_debug("Creating CIB and LRM objects");
	fsa_cib_conn = cib_new();
	fsa_lrm_conn = ll_lrm_new(XML_CIB_TAG_LRM);	
	
	crm_debug("Init server comms");
	if(ipc_server == NULL) {
		ipc_server = crm_strdup(CRM_SYSTEM_CRMD);
	}

	was_error = init_server_ipc_comms(ipc_server, crmd_client_connect,
					  default_ipc_connection_destroy);

	/* set up the timers */
	crm_malloc0(integration_timer, sizeof(fsa_timer_t));
	crm_malloc0(finalization_timer, sizeof(fsa_timer_t));
	crm_malloc0(election_trigger, sizeof(fsa_timer_t));
	crm_malloc0(election_timeout, sizeof(fsa_timer_t));
	crm_malloc0(shutdown_escalation_timer, sizeof(fsa_timer_t));
	crm_malloc0(wait_timer, sizeof(fsa_timer_t));
	crm_malloc0(recheck_timer, sizeof(fsa_timer_t));

	interval = interval * 1000;

	if(election_trigger != NULL) {
		election_trigger->source_id = 0;
		election_trigger->period_ms = -1;
		election_trigger->fsa_input = I_DC_TIMEOUT;
		election_trigger->callback = crm_timer_popped;
		election_trigger->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(election_timeout != NULL) {
		election_timeout->source_id = 0;
		election_timeout->period_ms = -1;
		election_timeout->fsa_input = I_ELECTION_DC;
		election_timeout->callback = crm_timer_popped;
		election_timeout->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(integration_timer != NULL) {
		integration_timer->source_id = 0;
		integration_timer->period_ms = -1;
		integration_timer->fsa_input = I_INTEGRATED;
		integration_timer->callback = crm_timer_popped;
		integration_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(finalization_timer != NULL) {
		finalization_timer->source_id = 0;
		finalization_timer->period_ms = -1;
		finalization_timer->fsa_input = I_FINALIZED;
		finalization_timer->callback = crm_timer_popped;
		finalization_timer->repeat = FALSE;
		/* for possible enabling... a bug in the join protocol left
		 *    a slave in S_PENDING while we think its in S_NOT_DC
		 *
		 * raising I_FINALIZED put us into a transition loop which is
		 *    never resolved.
		 * in this loop we continually send probes which the node
		 *    NACK's because its in S_PENDING
		 *
		 * if we have nodes where heartbeat is active but the
		 *    CRM is not... then this will be handled in the
		 *    integration phase
		 */
		finalization_timer->fsa_input = I_ELECTION;

	} else {
		was_error = TRUE;
	}
	
	if(shutdown_escalation_timer != NULL) {
		shutdown_escalation_timer->source_id = 0;
		shutdown_escalation_timer->period_ms = -1;
		shutdown_escalation_timer->fsa_input = I_STOP;
		shutdown_escalation_timer->callback = crm_timer_popped;
		shutdown_escalation_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(wait_timer != NULL) {
		wait_timer->source_id = 0;
		wait_timer->period_ms = 2000;
		wait_timer->fsa_input = I_NULL;
		wait_timer->callback = crm_timer_popped;
		wait_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}

	if(recheck_timer != NULL) {
		recheck_timer->source_id = 0;
		recheck_timer->period_ms = -1;
		recheck_timer->fsa_input = I_PE_CALC;
		recheck_timer->callback = crm_timer_popped;
		recheck_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	/* set up the sub systems */
	crm_malloc0(cib_subsystem, sizeof(struct crm_subsystem_s));
	crm_malloc0(te_subsystem,  sizeof(struct crm_subsystem_s));
	crm_malloc0(pe_subsystem,  sizeof(struct crm_subsystem_s));

	if(cib_subsystem != NULL) {
		cib_subsystem->pid      = -1;	
		cib_subsystem->path     = BIN_DIR;
		cib_subsystem->name     = CRM_SYSTEM_CIB;
		cib_subsystem->command  = BIN_DIR"/"CRM_SYSTEM_CIB;
		cib_subsystem->args     = "-VVc";
		cib_subsystem->flag_connected = R_CIB_CONNECTED;	
		cib_subsystem->flag_required  = R_CIB_REQUIRED;	

	} else {
		was_error = TRUE;
	}
	
	if(te_subsystem != NULL) {
		te_subsystem->pid      = -1;	
		te_subsystem->path     = BIN_DIR;
		te_subsystem->name     = CRM_SYSTEM_TENGINE;
		te_subsystem->command  = BIN_DIR"/"CRM_SYSTEM_TENGINE;
		te_subsystem->args     = NULL;
		te_subsystem->flag_connected = R_TE_CONNECTED;	
		te_subsystem->flag_required  = R_TE_REQUIRED;	
		
	} else {
		was_error = TRUE;
	}
	
	if(pe_subsystem != NULL) {
		pe_subsystem->pid      = -1;	
		pe_subsystem->path     = BIN_DIR;
		pe_subsystem->name     = CRM_SYSTEM_PENGINE;
		pe_subsystem->command  = BIN_DIR"/"CRM_SYSTEM_PENGINE;
		pe_subsystem->args     = NULL;
		pe_subsystem->flag_connected = R_PE_CONNECTED;	
		pe_subsystem->flag_required  = R_PE_REQUIRED;	
		
	} else {
		was_error = TRUE;
	}

	if(was_error) {
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}
	
	welcomed_nodes = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	integrated_nodes = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	finalized_nodes = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	confirmed_nodes = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);

	set_sigchld_proctrack(G_PRIORITY_HIGH,DEFAULT_MAXDISPATCHTIME);
}

/*	 A_STOP	*/
void
do_stop(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	fsa_data_t *msg_data)
{
    register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

/*	 A_STARTED	*/
void
do_started(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   fsa_data_t *msg_data)
{
	if(cur_state != S_STARTING) {
	    crm_err("Start cancelled...");
	    return;
	    
	} else if(is_set(fsa_input_register, R_CCM_DATA) == FALSE) {
		crm_info("Delaying start, CCM (%.16llx) not connected",
			 R_CCM_DATA);

		crmd_fsa_stall(NULL);
		return;

	} else if(is_set(fsa_input_register, R_LRM_CONNECTED) == FALSE) {
		crm_info("Delaying start, LRM (%.16llx) not connected",
			 R_LRM_CONNECTED);

		crmd_fsa_stall(NULL);
		return;

	} else if(is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {
		crm_info("Delaying start, CIB (%.16llx) not connected",
			 R_CIB_CONNECTED);

		crmd_fsa_stall(NULL);
		return;

	} else if(is_set(fsa_input_register, R_READ_CONFIG) == FALSE) {
		crm_info("Delaying start, Config not read (%.16llx)",
			 R_READ_CONFIG);

		crmd_fsa_stall(NULL);
		return;

	} else if(is_set(fsa_input_register, R_PEER_DATA) == FALSE) {
		HA_Message *	msg = NULL;

		/* try reading from HA */
		crm_info("Delaying start, Peer data (%.16llx) not recieved",
			 R_PEER_DATA);

		crm_debug_3("Looking for a HA message");
#ifndef WITH_NATIVE_AIS
		msg = fsa_cluster_conn->llc_ops->readmsg(fsa_cluster_conn, 0);
#endif
		if(msg != NULL) {
			crm_debug_3("There was a HA message");
 			crm_msg_del(msg);
		}
		/* this should no longer be required */
/* 		crm_timer_start(wait_timer); */
		crmd_fsa_stall(NULL);
		return;
	}

	crm_info("The local CRM is operational");
	clear_bit_inplace(fsa_input_register, R_STARTING);
	register_fsa_input(msg_data->fsa_cause, I_PENDING, NULL);
}

/*	 A_RECOVER	*/
void
do_recover(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   fsa_data_t *msg_data)
{
	set_bit_inplace(fsa_input_register, R_IN_RECOVERY);
	crm_err("Action %s (%.16llx) not supported",
	       fsa_action2string(action), action);

	register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

pe_cluster_option crmd_opts[] = {
	/* name, old-name, validate, default, description */
	{ XML_CONFIG_ATTR_DC_DEADTIME, NULL, "time", NULL, "10s", &check_time, "How long to wait for a response from other nodes during startup.", "The \"correct\" value will depend on the speed and load of your network." },
	{ XML_CONFIG_ATTR_RECHECK, NULL, "time", "Zero disables polling.  Positive values are an interval in seconds (unless other SI units are specified. eg. 5min)", "0", &check_timer, "Polling interval for time based changes to options, resource parameters and constraints.", "The Cluster is primarily event driven, however the configuration can have elements that change based on time.  To ensure these changes take effect, we can optionally poll the cluster's status for changes." },
	{ XML_CONFIG_ATTR_ELECTION_FAIL, NULL, "time", NULL, "2min", &check_timer, "*** Advanced Use Only ***.", "If need to adjust this value, it probably indicates the presence of a bug." },
	{ XML_CONFIG_ATTR_FORCE_QUIT, NULL, "time", NULL, "20min", &check_timer, "*** Advanced Use Only ***.", "If need to adjust this value, it probably indicates the presence of a bug." },
	{ "crmd-integration-timeout", NULL, "time", NULL, "3min", &check_timer, "*** Advanced Use Only ***.", "If need to adjust this value, it probably indicates the presence of a bug." },
	{ "crmd-finalization-timeout", NULL, "time", NULL, "30min", &check_timer, "*** Advanced Use Only ***.", "If you need to adjust this value, it probably indicates the presence of a bug." },
};

void
crmd_metadata(void)
{
	config_metadata("CRM Daemon", "1.0",
			"CRM Daemon Options",
			"This is a fake resource that details the options that can be configured for the CRM Daemon.",
			crmd_opts, DIMOF(crmd_opts));
}

static void
verify_crmd_options(GHashTable *options)
{
	verify_all_options(options, crmd_opts, DIMOF(crmd_opts));
}

static const char *
crmd_pref(GHashTable *options, const char *name)
{
	return get_cluster_pref(options, crmd_opts, DIMOF(crmd_opts), name);
}

static void
config_query_callback(const HA_Message *msg, int call_id, int rc,
		      crm_data_t *output, void *user_data) 
{
	const char *value = NULL;
	GHashTable *config_hash = NULL;

	if(rc != cib_ok) {
		fsa_data_t *msg_data = NULL;
		crm_err("Local CIB query resulted in an error: %s",
			cib_error2string(rc));
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);

		if(rc == cib_bad_permissions
		   || rc == cib_bad_digest
		   || rc == cib_bad_config) {
			crm_err("The cluster is mis-configured - shutting down and staying down");
			set_bit_inplace(fsa_input_register, R_STAYDOWN);
		}
		return;
	}

	crm_debug("Call %d : Parsing CIB options", call_id);
	config_hash = g_hash_table_new_full(
		g_str_hash,g_str_equal, g_hash_destroy_str,g_hash_destroy_str);

	unpack_instance_attributes(
		output, XML_CIB_TAG_PROPSET, NULL, config_hash,
		CIB_OPTIONS_FIRST, NULL);
	
	value = g_hash_table_lookup(config_hash, XML_CONFIG_ATTR_DC_DEADTIME);
	if(value == NULL) {
		/* apparently we're not allowed to free the result of getenv */
		char *param_val = getenv(ENV_PREFIX "" KEY_INITDEAD);

		value = crmd_pref(config_hash, XML_CONFIG_ATTR_DC_DEADTIME);
		if(param_val != NULL) {
			int from_env = crm_get_msec(param_val) / 2;
			int from_defaults = crm_get_msec(value);
			if(from_env > from_defaults) {
				g_hash_table_replace(
					config_hash, crm_strdup(XML_CONFIG_ATTR_DC_DEADTIME),
					crm_strdup(param_val));
			}
		}
	}

	verify_crmd_options(config_hash);

	value = crmd_pref(config_hash, XML_CONFIG_ATTR_DC_DEADTIME);
	election_trigger->period_ms = crm_get_msec(value);
	
	value = crmd_pref(config_hash, XML_CONFIG_ATTR_FORCE_QUIT);
	shutdown_escalation_timer->period_ms = crm_get_msec(value);

	value = crmd_pref(config_hash, XML_CONFIG_ATTR_ELECTION_FAIL);
	election_timeout->period_ms = crm_get_msec(value);
	
	value = crmd_pref(config_hash, XML_CONFIG_ATTR_RECHECK);
	recheck_timer->period_ms = crm_get_msec(value);

	value = crmd_pref(config_hash, "crmd-integration-timeout");
	integration_timer->period_ms  = crm_get_msec(value);

	value = crmd_pref(config_hash, "crmd-finalization-timeout");
	finalization_timer->period_ms = crm_get_msec(value);

	set_bit_inplace(fsa_input_register, R_READ_CONFIG);
	crm_debug_3("Triggering FSA: %s", __FUNCTION__);
	G_main_set_trigger(fsa_source);
	
	g_hash_table_destroy(config_hash);
}

/*	 A_READCONFIG	*/
void
do_read_config(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	int call_id = fsa_cib_conn->cmds->query(
 		fsa_cib_conn, XML_CIB_TAG_CRMCONFIG, NULL, cib_scope_local);

	add_cib_op_callback(call_id, FALSE, NULL, config_query_callback);
	crm_debug_2("Querying the CIB... call %d", call_id);
}


gboolean
crm_shutdown(int nsig, gpointer unused)
{
	if (crmd_mainloop != NULL && g_main_is_running(crmd_mainloop)) {
		if(is_set(fsa_input_register, R_SHUTDOWN)) {
			crm_err("Escalating the shutdown");
			register_fsa_input_before(C_SHUTDOWN, I_ERROR, NULL);

		} else {
			crm_info("Requesting shutdown");
			set_bit_inplace(fsa_input_register, R_SHUTDOWN);
			register_fsa_input(C_SHUTDOWN,I_SHUTDOWN,NULL);

			if(shutdown_escalation_timer->period_ms < 1) {
				GHashTable *config_hash = g_hash_table_new_full(
					g_str_hash, g_str_equal,
					g_hash_destroy_str, g_hash_destroy_str);
				const char *value = crmd_pref(
					config_hash, XML_CONFIG_ATTR_FORCE_QUIT);
				int msec = crm_get_msec(value);
				crm_info("Using default shutdown escalation: %dms", msec);
				shutdown_escalation_timer->period_ms = msec;
				g_hash_table_destroy(config_hash);
			}

			/* cant rely on this... */
			crm_timer_start(shutdown_escalation_timer);
		}
		
	} else {
		crm_info("exit from shutdown");
		exit(LSB_EXIT_OK);
	    
	}
	return TRUE;
}

static void
default_cib_update_callback(const HA_Message *msg, int call_id, int rc,
		     crm_data_t *output, void *user_data) 
{
	if(rc != cib_ok) {
		fsa_data_t *msg_data = NULL;
		crm_err("CIB Update failed: %s", cib_error2string(rc));
		crm_log_xml_warn(output, "update:failed");
		
		register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
	}
}

static void
populate_cib_nodes_ha(gboolean with_client_status)
{
	int call_id = 0;
	const char *ha_node = NULL;
	crm_data_t *cib_node_list = NULL;
	
	/* Async get client status information in the cluster */
	crm_debug_2("Invoked");
	if(with_client_status) {
		crm_debug_3("Requesting an initial dump of CRMD client_status");
		fsa_cluster_conn->llc_ops->client_status(
			fsa_cluster_conn, NULL, CRM_SYSTEM_CRMD, -1);
	}
	
	crm_info("Requesting the list of configured nodes");
	fsa_cluster_conn->llc_ops->init_nodewalk(fsa_cluster_conn);

	cib_node_list = create_xml_node(NULL, XML_CIB_TAG_NODES);
	do {
		const char *ha_node_type = NULL;
		const char *ha_node_uuid = NULL;
		crm_data_t *cib_new_node = NULL;

		ha_node = fsa_cluster_conn->llc_ops->nextnode(fsa_cluster_conn);
		if(ha_node == NULL) {
			continue;
		}
		
		ha_node_type = fsa_cluster_conn->llc_ops->node_type(
			fsa_cluster_conn, ha_node);
		if(safe_str_neq(NORMALNODE, ha_node_type)) {
			crm_debug("Node %s: skipping '%s'",
				  ha_node, ha_node_type);
			continue;
		}

		ha_node_uuid = get_uuid(fsa_cluster_conn, ha_node);
		if(ha_node_uuid == NULL) {
			crm_warn("Node %s: no uuid found", ha_node);
			continue;	
		}
		
		crm_notice("Node: %s (uuid: %s)", ha_node, ha_node_uuid);
		cib_new_node = create_xml_node(cib_node_list, XML_CIB_TAG_NODE);
		crm_xml_add(cib_new_node, XML_ATTR_ID,    ha_node_uuid);
		crm_xml_add(cib_new_node, XML_ATTR_UNAME, ha_node);
		crm_xml_add(cib_new_node, XML_ATTR_TYPE,  ha_node_type);

	} while(ha_node != NULL);

	fsa_cluster_conn->llc_ops->end_nodewalk(fsa_cluster_conn);
	
	/* Now update the CIB with the list of nodes */
	fsa_cib_update(
		XML_CIB_TAG_NODES, cib_node_list,
		cib_scope_local|cib_quorum_override|cib_inhibit_bcast, call_id);
	add_cib_op_callback(call_id, FALSE, NULL, default_cib_update_callback);

	free_xml(cib_node_list);
	crm_debug_2("Complete");
}

static void create_cib_node_definition(
    gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    crm_data_t *cib_nodes = user_data;
    crm_data_t *cib_new_node = NULL;
    
    crm_notice("Node: %s (uuid: %s)", node->uname, node->uuid);
    cib_new_node = create_xml_node(cib_nodes, XML_CIB_TAG_NODE);
    crm_xml_add(cib_new_node, XML_ATTR_ID,    node->uuid);
    crm_xml_add(cib_new_node, XML_ATTR_UNAME, node->uname);
    crm_xml_add(cib_new_node, XML_ATTR_TYPE,  NORMALNODE);
}

void
populate_cib_nodes(gboolean with_client_status)
{
    int call_id = 0;
    crm_data_t *cib_node_list = NULL;
    if(fsa_cluster_conn) {
	populate_cib_nodes_ha(with_client_status);
	return;
    }

    if(with_client_status) {
	crm_info("Requesting the list of configured nodes");
	send_ais_text(crm_class_members, __FUNCTION__, TRUE, NULL, crm_msg_ais);
    }
    
    cib_node_list = create_xml_node(NULL, XML_CIB_TAG_NODES);
    g_hash_table_foreach(
	crm_peer_cache, create_cib_node_definition, cib_node_list);    
    
    fsa_cib_update(
	XML_CIB_TAG_NODES, cib_node_list,
	cib_scope_local|cib_quorum_override|cib_inhibit_bcast, call_id);
    add_cib_op_callback(call_id, FALSE, NULL, default_cib_update_callback);
    
    free_xml(cib_node_list);
    crm_debug_2("Complete");
}

gboolean
register_with_ha(ll_cluster_t *hb_cluster, const char *client_name)
{
	const char *const_uname = NULL;
	const char *const_uuid = NULL;
	crm_debug("Signing in with Heartbeat");
	if (hb_cluster->llc_ops->signon(hb_cluster, client_name)!= HA_OK) {

		crm_err("Cannot sign on with heartbeat: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_debug_3("Be informed of CRM messages");
	if (HA_OK != hb_cluster->llc_ops->set_msg_callback(
		    hb_cluster, T_CRM, crmd_ha_msg_callback, hb_cluster)){
		
		crm_err("Cannot set msg callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_debug_3("Be informed of Node Status changes");
	if (HA_OK != hb_cluster->llc_ops->set_nstatus_callback(
		    hb_cluster, crmd_ha_status_callback, hb_cluster)){
		
		crm_err("Cannot set nstatus callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}
	
	crm_debug_3("Be informed of CRM Client Status changes");
	if (HA_OK != hb_cluster->llc_ops->set_cstatus_callback(
		    hb_cluster, crmd_client_status_callback, hb_cluster)) {

		crm_err("Cannot set cstatus callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_debug_3("Adding channel to mainloop");
	G_main_add_ll_cluster(
		G_PRIORITY_HIGH, hb_cluster,
		FALSE, crmd_ha_msg_dispatch, hb_cluster /* userdata  */,  
		crmd_ha_connection_destroy);

	crm_debug_3("Finding our node name");
	if ((const_uname =
	     hb_cluster->llc_ops->get_mynodeid(hb_cluster)) == NULL) {
		crm_err("get_mynodeid() failed");
		return FALSE;
	}
	fsa_our_uname = crm_strdup(const_uname);
	crm_info("Hostname: %s", fsa_our_uname);

	crm_debug_3("Finding our node uuid");
	const_uuid = get_uuid(fsa_cluster_conn, fsa_our_uname);
	if(const_uuid == NULL) {
		crm_err("get_uuid_by_name() failed");
		return FALSE;
	}
	/* copy it so that unget_uuid() doesn't trash the value on us */
	fsa_our_uuid = crm_strdup(const_uuid);
	crm_info("UUID: %s", fsa_our_uuid);
		
	populate_cib_nodes(TRUE);
	
	return TRUE;
}

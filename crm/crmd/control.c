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

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ctrl.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <crm/dmalloc_wrapper.h>

extern void crmd_ha_connection_destroy(gpointer user_data);
extern gboolean stop_all_resources(void);

gboolean crm_shutdown(int nsig, gpointer unused);
gboolean register_with_ha(ll_cluster_t *hb_cluster, const char *client_name);


GHashTable   *ipc_clients = NULL;
GTRIGSource  *fsa_source = NULL;

/*	 A_HA_CONNECT	*/
enum crmd_fsa_input
do_ha_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	gboolean registered = FALSE;
	
	if(action & A_HA_DISCONNECT) {
		if(fsa_cluster_conn != NULL) {
			fsa_cluster_conn->llc_ops->signoff(
				fsa_cluster_conn, FALSE);
		}
		
	}
	
	if(action & A_HA_CONNECT) {
		if(fsa_cluster_conn == NULL) {
			fsa_cluster_conn = ll_cluster_new("heartbeat");
		}
		
		/* make sure we are disconnected first */
		fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn, FALSE);
		
		registered = register_with_ha(
			fsa_cluster_conn, crm_system_name);
		
		if(registered == FALSE) {
			register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
			return I_NULL;
		}
	} 
	
	if(action & ~(A_HA_CONNECT|A_HA_DISCONNECT)) {
		crm_err("Unexpected action %s in %s",
		       fsa_action2string(action), __FUNCTION__);
	}
	
	
	return I_NULL;
}

/*	 A_SHUTDOWN	*/
enum crmd_fsa_input
do_shutdown(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	enum crmd_fsa_input next_input = I_NULL;
	enum crmd_fsa_input tmp = I_NULL;

	/* just in case */
	set_bit_inplace(fsa_input_register, R_SHUTDOWN);
	
	/* last attempt to shut these down */
	if(is_set(fsa_input_register, R_PE_CONNECTED)) {
		crm_warn("Last attempt to shutdown the PolicyEngine");
		tmp = do_pe_control(A_PE_STOP, cause, cur_state,
				    current_input, msg_data);
		if(tmp != I_NULL) {
			next_input = I_ERROR;
			crm_err("Failed to shutdown the PolicyEngine");
		}
	}

	if(is_set(fsa_input_register, R_TE_CONNECTED)) {
		crm_warn("Last attempt to shutdown the Transitioner");
		tmp = do_pe_control(A_TE_STOP, cause, cur_state,
				    current_input, msg_data);
		if(tmp != I_NULL) {
			next_input = I_ERROR;
			crm_err("Failed to shutdown the Transitioner");
		}
	}

	crm_info("Stopping all remaining local resources");
	if(is_set(fsa_input_register, R_LRM_CONNECTED)) {
		stop_all_resources();
	} else {
		crm_err("Exiting with no LRM connection..."
			" resources may be active!");
		register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
	}
	
	return next_input;
}

/*	 A_SHUTDOWN_REQ	*/
enum crmd_fsa_input
do_shutdown_req(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    fsa_data_t *msg_data)
{
	enum crmd_fsa_input next_input = I_NULL;
	HA_Message *msg = NULL;
	
	crm_info("Sending shutdown request to DC: %s", crm_str(fsa_our_dc));
	msg = create_request(
		CRM_OP_SHUTDOWN_REQ, NULL, NULL,
		CRM_SYSTEM_DC, CRM_SYSTEM_CRMD, NULL);

/* 	set_bit_inplace(fsa_input_register, R_STAYDOWN); */
	
	if(send_request(msg, NULL) == FALSE) {
		next_input = I_ERROR;
#if 0
		/* this shouldnt be required */
	} else {
		crm_timer_start(shutdown_timer);
#endif
	}

	return next_input;
}

/*	 A_EXIT_0, A_EXIT_1	*/
enum crmd_fsa_input
do_exit(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	fsa_data_t *msg_data)
{
	int exit_code = 0;
	gboolean do_exit = FALSE;
	
	if(action & A_EXIT_0) {
		if(is_set(fsa_input_register, R_PE_CONNECTED)) {
			crm_info("Waiting for the PE to disconnect");
			crmd_fsa_stall(NULL);
			
		} else if(is_set(fsa_input_register, R_TE_CONNECTED)) {
			crm_info("Waiting for the TE to disconnect");
			crmd_fsa_stall(NULL);
		} else {
			do_exit = TRUE;
			crm_info("Performing %s - gracefully exiting the CRMd",
				 fsa_action2string(action));
		}
		
	} else {
		do_exit = TRUE;
		exit_code = 1;
		crm_warn("Performing %s - forcefully exiting the CRMd... now!",
			 fsa_action2string(action));
	}

	if(do_exit) {
		if(is_set(fsa_input_register, R_IN_RECOVERY)) {
			crm_info("Could not recover from internal error");
			exit_code = 2;			
			
		} else if(is_set(fsa_input_register, R_STAYDOWN)) {
			crm_info("Inhibiting respawn by Heartbeat");
			exit_code = 100;
		}
		crm_info("[%s] stopped (%d)", crm_system_name, exit_code);
		exit(exit_code);
	}
	
	return I_NULL;
}


/*	 A_STARTUP	*/
enum crmd_fsa_input
do_startup(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   fsa_data_t *msg_data)
{
	int was_error = 0;
	int interval = 1; /* seconds between DC heartbeats */

	crm_info("Register Signal Handler");
	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, crm_shutdown, NULL, NULL);

	fsa_source = G_main_add_TriggerHandler(
		G_PRIORITY_HIGH, crm_fsa_trigger, NULL, NULL);

	ipc_clients = g_hash_table_new(g_str_hash, g_str_equal);
	
	if(was_error == 0) {
		crm_info("Init server comms");
		was_error = init_server_ipc_comms(
			crm_strdup(CRM_SYSTEM_CRMD), crmd_client_connect,
			default_ipc_connection_destroy);
	}	

	if(was_error == 0) {
		crm_info("Creating CIB object");
		fsa_cib_conn = cib_new();
	}
	
	/* set up the timers */
	crm_malloc0(dc_heartbeat, sizeof(fsa_timer_t));
	crm_malloc0(integration_timer, sizeof(fsa_timer_t));
	crm_malloc0(finalization_timer, sizeof(fsa_timer_t));
	crm_malloc0(election_trigger, sizeof(fsa_timer_t));
	crm_malloc0(election_timeout, sizeof(fsa_timer_t));
	crm_malloc0(shutdown_escalation_timer, sizeof(fsa_timer_t));
	crm_malloc0(wait_timer, sizeof(fsa_timer_t));
	crm_malloc0(shutdown_timer, sizeof(fsa_timer_t));

	interval = interval * 1000;

	if(election_trigger != NULL) {
		election_trigger->source_id = -1;
		election_trigger->period_ms = -1;
		election_trigger->fsa_input = I_DC_TIMEOUT;
		election_trigger->callback = crm_timer_popped;
		election_trigger->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(dc_heartbeat != NULL) {
		dc_heartbeat->source_id = -1;
		dc_heartbeat->period_ms = -1;
		dc_heartbeat->fsa_input = I_NULL;
		dc_heartbeat->callback = do_dc_heartbeat;
		dc_heartbeat->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(election_timeout != NULL) {
		election_timeout->source_id = -1;
		election_timeout->period_ms = -1;
		election_timeout->fsa_input = I_ELECTION_DC;
		election_timeout->callback = crm_timer_popped;
		election_timeout->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(integration_timer != NULL) {
		integration_timer->source_id = -1;
		integration_timer->period_ms = -1;
		integration_timer->fsa_input = I_INTEGRATED;
		integration_timer->callback = crm_timer_popped;
		integration_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(finalization_timer != NULL) {
		finalization_timer->source_id = -1;
		finalization_timer->period_ms = -1;
		finalization_timer->fsa_input = I_FINALIZED;
		finalization_timer->callback = crm_timer_popped;
		finalization_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(shutdown_escalation_timer != NULL) {
		shutdown_escalation_timer->source_id = -1;
		shutdown_escalation_timer->period_ms = -1;
		shutdown_escalation_timer->fsa_input = I_STOP;
		shutdown_escalation_timer->callback = crm_timer_popped;
		shutdown_escalation_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}
	
	if(wait_timer != NULL) {
		wait_timer->source_id = -1;
		wait_timer->period_ms = 500;
		wait_timer->fsa_input = I_NULL;
		wait_timer->callback = crm_timer_popped;
		wait_timer->repeat = FALSE;
	} else {
		was_error = TRUE;
	}

	if(shutdown_timer != NULL) {
		shutdown_timer->source_id = -1;
		shutdown_timer->period_ms = -1;
		shutdown_timer->fsa_input = I_SHUTDOWN;
		shutdown_timer->callback = crm_timer_popped;
		shutdown_timer->repeat = TRUE;
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
	crmd_peer_state = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);

	set_sigchld_proctrack(G_PRIORITY_HIGH);
	
	return I_NULL;
}

extern GHashTable *shutdown_ops;

/*	 A_STOP	*/
enum crmd_fsa_input
do_stop(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	fsa_data_t *msg_data)
{
	if(g_hash_table_size(shutdown_ops) > 0) {
		crm_err("%d stop operations outstanding at exit",
			g_hash_table_size(shutdown_ops));
	}
	
	return I_NULL;
}

/*	 A_STARTED	*/
enum crmd_fsa_input
do_started(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   fsa_data_t *msg_data)
{
	if(is_set(fsa_input_register, R_CCM_DATA) == FALSE) {
		crm_info("Delaying start, CCM (%.16llx) not connected",
			 R_CCM_DATA);

		crmd_fsa_stall(NULL);
		return I_NULL;

	} else if(is_set(fsa_input_register, R_LRM_CONNECTED) == FALSE) {
		crm_info("Delaying start, LRM (%.16llx) not connected",
			 R_LRM_CONNECTED);

		crmd_fsa_stall(NULL);
		return I_NULL;

	} else if(is_set(fsa_input_register, R_CIB_CONNECTED) == FALSE) {
		crm_info("Delaying start, CIB (%.16llx) not connected",
			 R_CIB_CONNECTED);

		crmd_fsa_stall(NULL);
		return I_NULL;

	} else if(is_set(fsa_input_register, R_PEER_DATA) == FALSE) {
		HA_Message *	msg = NULL;

		/* try reading from HA */
		crm_info("Delaying start, Peer data (%.16llx) not recieved",
			 R_PEER_DATA);

		crm_debug_3("Looking for a HA message");
		msg = fsa_cluster_conn->llc_ops->readmsg(fsa_cluster_conn, 0);
		if(msg != NULL) {
			crm_debug_3("There was a HA message");
 			crm_msg_del(msg);
		}
		
		crm_timer_start(wait_timer);
		crmd_fsa_stall(NULL);
		return I_NULL;
	}

	crm_info("The local CRM is operational");
	clear_bit_inplace(fsa_input_register, R_STARTING);
	register_fsa_input(msg_data->fsa_cause, I_PENDING, NULL);
	
	return I_NULL;
}

/*	 A_RECOVER	*/
enum crmd_fsa_input
do_recover(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   fsa_data_t *msg_data)
{
	set_bit_inplace(fsa_input_register, R_IN_RECOVERY);
	crm_err("Action %s (%.16llx) not supported",
	       fsa_action2string(action), action);

	register_fsa_input(C_FSA_INTERNAL, I_STOP, NULL);

	return I_NULL;
}

/*	 A_READCONFIG	*/
enum crmd_fsa_input
do_read_config(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	/* this one probably is worthwhile blocking on */
	crm_data_t *cib_copy = get_cib_copy(fsa_cib_conn);
	crm_data_t *config   = get_object_root(XML_CIB_TAG_CRMCONFIG, cib_copy);

	dc_heartbeat->period_ms = 0;
	
	xml_child_iter(
		config, iter, XML_CIB_TAG_NVPAIR,

		const char *name  = crm_element_value(iter, XML_NVPAIR_ATTR_NAME);
		const char *value = crm_element_value(iter, XML_NVPAIR_ATTR_VALUE);

		if(name == NULL || value == NULL) {
			continue;
			
		} else if(safe_str_eq(name, XML_CONFIG_ATTR_DC_BEAT)) {
			dc_heartbeat->period_ms = atoi(value);
			
		} else if(safe_str_eq(name, XML_CONFIG_ATTR_DC_DEADTIME)) {
			election_trigger->period_ms = atoi(value);

		} else if(safe_str_eq(name, XML_CONFIG_ATTR_FORCE_QUIT)) {
			shutdown_escalation_timer->period_ms = atoi(value);

		}
		);
		
	if(dc_heartbeat->period_ms < 1) {
		/* sensible default */
		dc_heartbeat->period_ms = crm_get_msec(
			getenv("HA_"KEY_KEEPALIVE));
	}
	
	election_timeout->period_ms   = dc_heartbeat->period_ms * 6;
	integration_timer->period_ms  = dc_heartbeat->period_ms * 6;
	finalization_timer->period_ms = dc_heartbeat->period_ms * 6;
	integration_timer->period_ms  = crm_get_msec("5min");
	finalization_timer->period_ms = crm_get_msec("5min");
	
	if(election_trigger->period_ms < 1
	   || election_trigger->period_ms > election_timeout->period_ms) {
		/* sensible default */
		election_trigger->period_ms = election_timeout->period_ms * 2;
	}
	
	if(shutdown_escalation_timer->period_ms < 1
	   || election_timeout->period_ms > shutdown_escalation_timer->period_ms) {
		/* sensible default - 32 election cycles */
		shutdown_escalation_timer->period_ms
			= (election_timeout->period_ms + election_trigger->period_ms) * 32;
	}
	shutdown_timer->period_ms = election_trigger->period_ms;
	

	return I_NULL;
}


gboolean
crm_shutdown(int nsig, gpointer unused)
{
	if (crmd_mainloop != NULL && g_main_is_running(crmd_mainloop)) {
		if(is_set(fsa_input_register, R_SHUTDOWN)) {
			crm_err("Escalating the shutdown");
			register_fsa_input_before(C_SHUTDOWN, I_ERROR, NULL);

		} else {
			set_bit_inplace(fsa_input_register, R_SHUTDOWN);
/* 			set_bit_inplace(fsa_input_register, R_STAYDOWN); */

			/* if we ever win an election we're the last man standing */
			election_timeout->fsa_input = I_STOP;

			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				/* cant rely on this... */
				crm_timer_start(shutdown_escalation_timer);
				register_fsa_input(C_SHUTDOWN,I_SHUTDOWN,NULL);

			} else {
				crm_err("Could not set R_SHUTDOWN");
				exit(LSB_EXIT_ENOTSUPPORTED);
			}
		}
		
	} else {
		crm_info("exit from shutdown");
		exit(LSB_EXIT_OK);
	    
	}
	return TRUE;
}


gboolean
register_with_ha(ll_cluster_t *hb_cluster, const char *client_name)
{
	crm_debug("Signing in with Heartbeat");
	if (hb_cluster->llc_ops->signon(hb_cluster, client_name)!= HA_OK) {

		crm_err("Cannot sign on with heartbeat: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_set_ha_options(hb_cluster);
	
	crm_debug_3("Be informed of CRM messages");
	if (HA_OK != hb_cluster->llc_ops->set_msg_callback(
		    hb_cluster, T_CRM, crmd_ha_msg_callback, hb_cluster)){
		
		crm_err("Cannot set msg callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

#if 0
	crm_debug_3("Be informed of Node Status changes");
	if (HA_OK != hb_cluster->llc_ops->set_nstatus_callback(
		    hb_cluster, crmd_ha_status_callback, hb_cluster)){
		
		crm_err("Cannot set nstatus callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}
#endif
	
	crm_debug_3("Be informed of CRM Client Status changes");
	if (HA_OK != hb_cluster->llc_ops->set_cstatus_callback(
		    hb_cluster, crmd_client_status_callback, hb_cluster)) {

		crm_err("Cannot set cstatus callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_debug_3("Adding channel to mainloop");
	G_main_add_IPC_Channel(
		G_PRIORITY_HIGH, hb_cluster->llc_ops->ipcchan(hb_cluster),
		FALSE, crmd_ha_msg_dispatch, hb_cluster /* userdata  */,  
		crmd_ha_connection_destroy);

	crm_debug_3("Finding our node name");
	if ((fsa_our_uname =
	     hb_cluster->llc_ops->get_mynodeid(hb_cluster)) == NULL) {
		crm_err("get_mynodeid() failed");
		return FALSE;
	}
	crm_info("FSA Hostname: %s", fsa_our_uname);

	/* Async get client status information in the cluster */
	crm_debug_3("Requesting an initial dump of CRMD client_status");
	fsa_cluster_conn->llc_ops->client_status(
		fsa_cluster_conn, NULL, CRM_SYSTEM_CRMD, -1);

	
	return TRUE;
    
}

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

void crm_shutdown(int nsig);
/* IPC_WaitConnection *wait_channel_init(char daemonsocket[]); */
gboolean register_with_ha(ll_cluster_t *hb_cluster, const char *client_name);


GHashTable   *ipc_clients = NULL;

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
			fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn);
		}
		
	}
	
	if(action & A_HA_CONNECT) {
		if(fsa_cluster_conn == NULL)
			fsa_cluster_conn = ll_cluster_new("heartbeat");

		/* make sure we are disconnected first */
		fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn);
		
		registered = register_with_ha(
			fsa_cluster_conn, crm_system_name);
		
		if(registered == FALSE) {
			return I_FAIL;
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
	stop_all_resources();
	
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
	
	crm_debug("Sending shutdown request to DC");
	if(send_request(NULL, NULL, CRM_OP_SHUTDOWN_REQ,
			NULL, CRM_SYSTEM_DC, NULL) == FALSE){
		next_input = I_ERROR;
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
	if(action & A_EXIT_0) {
		crm_info("Performing %s - gracefully exiting the CRMd\n",
			fsa_action2string(action));

		g_main_quit(crmd_mainloop);
	} else {
		crm_warn("Performing %s - forcefully exiting the CRMd\n",
			fsa_action2string(action));
		exit(1);
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

	crm_info("Register PID");
	register_pid(PID_FILE, FALSE, crm_shutdown);
	
	ipc_clients = g_hash_table_new(&g_str_hash, &g_str_equal);
	
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
	crm_malloc(dc_heartbeat, sizeof(fsa_timer_t));
	crm_malloc(integration_timer, sizeof(fsa_timer_t));
	crm_malloc(finalization_timer, sizeof(fsa_timer_t));
	crm_malloc(election_trigger, sizeof(fsa_timer_t));
	crm_malloc(election_timeout, sizeof(fsa_timer_t));
	crm_malloc(shutdown_escalation_timer, sizeof(fsa_timer_t));
	crm_malloc(wait_timer, sizeof(fsa_timer_t));

	interval = interval * 1000;

	if(election_trigger != NULL) {
		election_trigger->source_id = -1;
		election_trigger->period_ms = -1;
		election_trigger->fsa_input = I_DC_TIMEOUT;
		election_trigger->callback = timer_popped;
	} else {
		was_error = TRUE;
	}
	
	if(dc_heartbeat != NULL) {
		dc_heartbeat->source_id = -1;
		dc_heartbeat->period_ms = -1;
		dc_heartbeat->fsa_input = I_NULL;
		dc_heartbeat->callback = do_dc_heartbeat;
	} else {
		was_error = TRUE;
	}
	
	if(election_timeout != NULL) {
		election_timeout->source_id = -1;
		election_timeout->period_ms = -1;
		election_timeout->fsa_input = I_ELECTION_DC;
		election_timeout->callback = timer_popped;
	} else {
		was_error = TRUE;
	}
	
	if(integration_timer != NULL) {
		integration_timer->source_id = -1;
		integration_timer->period_ms = -1;
		integration_timer->fsa_input = I_INTEGRATED;
		integration_timer->callback = timer_popped;
	} else {
		was_error = TRUE;
	}
	
	if(finalization_timer != NULL) {
		finalization_timer->source_id = -1;
		finalization_timer->period_ms = -1;
		finalization_timer->fsa_input = I_FINALIZED;
		finalization_timer->callback = timer_popped;
	} else {
		was_error = TRUE;
	}
	
	if(shutdown_escalation_timer != NULL) {
		shutdown_escalation_timer->source_id = -1;
		shutdown_escalation_timer->period_ms = -1;
		shutdown_escalation_timer->fsa_input = I_TERMINATE;
		shutdown_escalation_timer->callback = timer_popped;
	} else {
		was_error = TRUE;
	}
	
	if(wait_timer != NULL) {
		wait_timer->source_id = -1;
		wait_timer->period_ms = 3*1000;
		wait_timer->fsa_input = I_NULL;
		wait_timer->callback = timer_popped;
	} else {
		was_error = TRUE;
	}
	
	/* set up the sub systems */
	crm_malloc(cib_subsystem, sizeof(struct crm_subsystem_s));
	crm_malloc(te_subsystem,  sizeof(struct crm_subsystem_s));
	crm_malloc(pe_subsystem,  sizeof(struct crm_subsystem_s));

	if(cib_subsystem != NULL) {
		cib_subsystem->pid      = -1;	
		cib_subsystem->flag     = R_CIB_CONNECTED;	
		cib_subsystem->path     = BIN_DIR;
		cib_subsystem->name     = CRM_SYSTEM_CIB;
		cib_subsystem->command  = BIN_DIR"/"CRM_SYSTEM_CIB;
		cib_subsystem->args     = "-VVc";

	} else {
		was_error = TRUE;
	}
	
	if(te_subsystem != NULL) {
		te_subsystem->pid      = -1;	
		te_subsystem->flag     = R_TE_CONNECTED;	
		te_subsystem->path     = BIN_DIR;
		te_subsystem->name     = CRM_SYSTEM_TENGINE;
		te_subsystem->command  = BIN_DIR"/"CRM_SYSTEM_TENGINE;
		te_subsystem->args     = "-VVc";
		
	} else {
		was_error = TRUE;
	}
	
	if(pe_subsystem != NULL) {
		pe_subsystem->pid      = -1;	
		pe_subsystem->flag     = R_PE_CONNECTED;	
		pe_subsystem->path     = BIN_DIR;
		pe_subsystem->name     = CRM_SYSTEM_PENGINE;
		pe_subsystem->command  = BIN_DIR"/"CRM_SYSTEM_PENGINE;
		pe_subsystem->args     = "-VVc";
		
	} else {
		was_error = TRUE;
	}

	if(was_error)
		return I_FAIL;
	
	return I_NULL;
}


/*	 A_STOP	*/
enum crmd_fsa_input
do_stop(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	fsa_data_t *msg_data)
{
	/* nothing to do yet */

	/* todo: shut down any remaining CRM resources */
	
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
	if(is_set(fsa_input_register, R_CCM_DATA) == FALSE
/* 	   || is_set(fsa_input_register, R_PE_CONNECTED) == FALSE */
/* 	   || is_set(fsa_input_register, R_TE_CONNECTED) == FALSE */
	   || is_set(fsa_input_register, R_LRM_CONNECTED) == FALSE
		) {
		crm_info("Delaying start, some systems not connected %.16llx (%.16llx)",
			 fsa_input_register, (long long)R_CCM_DATA|R_LRM_CONNECTED);

		crmd_fsa_stall();
		return I_NULL;

	} else if(is_set(fsa_input_register, R_PEER_DATA) == FALSE) {
		struct ha_msg*	msg = NULL;

		/* try reading from HA */
		crm_info("Delaying start, some systems not connected %.16llx (%.16llx)",
			 fsa_input_register, (long long)R_PEER_DATA);

		crm_debug("Looking for a HA message");
		msg = fsa_cluster_conn->llc_ops->readmsg(fsa_cluster_conn, 0);
		if(msg != NULL) {
			crm_debug("There was a HA message");
			ha_msg_del(msg);
		}
		
		startTimer(wait_timer);
		crmd_fsa_stall();
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
	

	crm_err("Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);

	return I_SHUTDOWN;
}

/*	 A_READCONFIG	*/
enum crmd_fsa_input
do_read_config(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       fsa_data_t *msg_data)
{
	xmlNodePtr cib_copy = get_cib_copy(fsa_cib_conn);
	xmlNodePtr config   = get_object_root(XML_CIB_TAG_CRMCONFIG, cib_copy);

	xml_child_iter(
		config, iter, XML_CIB_TAG_NVPAIR,

		const char *name  = xmlGetProp(iter, XML_NVPAIR_ATTR_NAME);
		const char *value = xmlGetProp(iter, XML_NVPAIR_ATTR_VALUE);

		if(name == NULL || value == NULL) {
			continue;
			
		} else if(safe_str_eq(name, XML_CONFIG_ATTR_DC_BEAT)) {
			dc_heartbeat->period_ms = atoi(value);
			
		} else if(safe_str_eq(name, XML_CONFIG_ATTR_DC_DEADTIME)) {
			election_trigger->period_ms = atoi(value);

		} else if(safe_str_eq(name, XML_CONFIG_ATTR_FORCE_QUIT)) {
			shutdown_escalation_timer->period_ms = atoi(value);

		} else if(safe_str_eq(name, XML_CONFIG_ATTR_REANNOUNCE)) {
			fsa_join_reannouce = atoi(value);

		}
		);
		
	if(dc_heartbeat->period_ms < 1) {
		/* sensible default */
		dc_heartbeat->period_ms = 1000;
		
	}
	if(election_trigger->period_ms < 1) {
		/* sensible default */
		election_trigger->period_ms = dc_heartbeat->period_ms * 4;
		
	}
	if(shutdown_escalation_timer->period_ms < 1) {
		/* sensible default */
		shutdown_escalation_timer->period_ms
			= election_trigger->period_ms * 3 * 100;
	}
	if(fsa_join_reannouce < 0) {
		fsa_join_reannouce = 100; /* how many times should we let
					   * go by before reannoucning
					   * ourselves to the DC
					   */
	}
	
	election_timeout->period_ms   = dc_heartbeat->period_ms * 6;
	integration_timer->period_ms  = dc_heartbeat->period_ms * 6;
	finalization_timer->period_ms = dc_heartbeat->period_ms * 6;

	return I_NULL;
}


void
crm_shutdown(int nsig)
{
	CL_SIGNAL(nsig, crm_shutdown);
    
	if (crmd_mainloop != NULL && g_main_is_running(crmd_mainloop)) {
		if(is_set(fsa_input_register, R_SHUTDOWN)) {
			crm_err("Escalating the shutdown");
			register_fsa_input(C_SHUTDOWN, I_ERROR, NULL);
			s_crmd_fsa(C_SHUTDOWN);

		} else {
			set_bit_inplace(fsa_input_register, R_SHUTDOWN);

			/* fast track the case where no-one else is out there */
			if(AM_I_DC) {
				election_timeout->fsa_input = I_TERMINATE;
			}

			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				/* cant rely on this... */
				startTimer(shutdown_escalation_timer);
				register_fsa_input(C_SHUTDOWN, I_SHUTDOWN, NULL);
				s_crmd_fsa(C_SHUTDOWN);

			} else {
				crm_err("Could not set R_SHUTDOWN");
				exit(LSB_EXIT_ENOTSUPPORTED);
			}
		}
		
	} else {
		crm_info("exit from shutdown");
		exit(LSB_EXIT_OK);
	    
	}
	return;
}


gboolean
register_with_ha(ll_cluster_t *hb_cluster, const char *client_name)
{
	int facility;
	
	if(safe_val3(NULL, hb_cluster, llc_ops, errmsg) == NULL) {
		crm_crit("cluster errmsg function unavailable");
	}
	
	crm_info("Signing in with Heartbeat");
	if (hb_cluster->llc_ops->signon(hb_cluster, client_name)!= HA_OK) {

		crm_err("Cannot sign on with heartbeat: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	/* change the logging facility to the one used by heartbeat daemon */
	crm_info("Switching to Heartbeat logger");
	if (( facility =
	      hb_cluster->llc_ops->get_logfacility(hb_cluster)) > 0) {
		cl_log_set_facility(facility);
 	}	
	crm_verbose("Facility: %d", facility);	
  
	crm_debug("Be informed of CRM messages");
	if (HA_OK != hb_cluster->llc_ops->set_msg_callback(
		    hb_cluster, T_CRM, crmd_ha_msg_callback, hb_cluster)){
		
		crm_err("Cannot set msg callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

#if 0
	crm_debug("Be informed of Node Status changes");
	if (HA_OK != hb_cluster->llc_ops->set_nstatus_callback(
		    hb_cluster, crmd_ha_status_callback, hb_cluster)){
		
		crm_err("Cannot set nstatus callback: %s",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}
#endif
	
	crm_debug("Be informed of CRM Client Status changes");
	if (HA_OK != hb_cluster->llc_ops->set_cstatus_callback(
		    hb_cluster, crmd_client_status_callback, hb_cluster)) {

		crm_err("Cannot set cstatus callback: %s\n",
			hb_cluster->llc_ops->errmsg(hb_cluster));
		return FALSE;
	}

	crm_info("beekhof: Client Status callback set");

	crm_debug("Adding channel to mainloop");
	G_main_add_IPC_Channel(
		G_PRIORITY_HIGH, hb_cluster->llc_ops->ipcchan(hb_cluster),
		FALSE, crmd_ha_msg_dispatch, hb_cluster /* userdata  */,  
		crmd_ha_connection_destroy);

	crm_debug("Finding our node name");
	if ((fsa_our_uname =
	     hb_cluster->llc_ops->get_mynodeid(hb_cluster)) == NULL) {
		crm_err("get_mynodeid() failed");
		return FALSE;
	}
	crm_info("FSA Hostname: %s", fsa_our_uname);

	/* Async get client status information in the cluster */
	crm_debug("Requesting an initial dump of CRMD client_status");
	crm_info("beekhof: Requesting Client Status");
	fsa_cluster_conn->llc_ops->client_status(
		fsa_cluster_conn, NULL, CRM_SYSTEM_CRMD, -1);

	
	return TRUE;
    
}

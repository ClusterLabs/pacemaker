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

#include <crm/crm.h>
#include <crmd_fsa.h>
#include <fsa_proto.h>
#include <crmd.h>
#include <crm/common/ipcutils.h>
#include <crm/common/crmutils.h>

#include <clplumbing/Gmain_timeout.h>

#include <crm/dmalloc_wrapper.h>

#define PID_FILE     WORKING_DIR"/crm.pid"
#define DAEMON_LOG   LOG_DIR"/crm.log"
#define DAEMON_DEBUG LOG_DIR"/crm.debug"

gboolean crmd_ha_input_dispatch(int fd, gpointer user_data);
void crmd_ha_input_destroy(gpointer user_data);
void shutdown(int nsig);

GHashTable   *ipc_clients = NULL;

/*	 A_HA_CONNECT	*/
enum crmd_fsa_input
do_ha_register(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
{
	gboolean registered = FALSE;
	
	FNIN();

	if(fsa_cluster_connection == NULL)
		fsa_cluster_connection = ll_cluster_new("heartbeat");

	// make sure we are disconnected first
	fsa_cluster_connection->llc_ops->signoff(fsa_cluster_connection);
	
	registered = register_with_ha(fsa_cluster_connection,
				      crm_system_name,
				      crmd_ha_input_dispatch,
				      crmd_ha_input_callback,
				      crmd_ha_input_destroy);

	if(registered)
		FNRET(I_NULL);
	
	FNRET(I_FAIL);
}

/*	 A_SHUTDOWN	*/
enum crmd_fsa_input
do_shutdown(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	enum crmd_fsa_input next_input = I_NULL;
	enum crmd_fsa_input tmp = I_NULL;
	
	FNIN();

	tmp = do_pe_control(A_PE_STOP, cause, cur_state, current_input, data);
	if(tmp != I_NULL)
		next_input = I_FAIL;
	tmp = do_te_control(A_TE_STOP, cause, cur_state, current_input, data);
	if(tmp != I_NULL)
		next_input = I_FAIL;
	tmp = do_cib_control(A_CIB_STOP, cause, cur_state, current_input, data);
	if(tmp != I_NULL)
		next_input = I_FAIL;
	
	FNRET(next_input);
}

gboolean
crmd_ha_input_dispatch(int fd, gpointer user_data)
{
	FNIN();

	ll_cluster_t*	hb_cluster = (ll_cluster_t*)user_data;
    
	while(hb_cluster->llc_ops->msgready(hb_cluster))
	{
		// invoke the callbacks but dont block
		hb_cluster->llc_ops->rcvmsg(hb_cluster, 0);
	}
    
	FNRET(TRUE);
}

void
crmd_ha_input_destroy(gpointer user_data)
{
	cl_log(LOG_INFO, "in my hb_input_destroy");
}

/*	 A_LRM_CONNECT	*/
enum crmd_fsa_input
do_lrm_register(long long action,
		enum crmd_fsa_cause cause,
		enum crmd_fsa_state cur_state,
		enum crmd_fsa_input current_input,
		void *data)
{
	FNIN();

	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n", fsa_action2string(action), action);

	FNRET(I_NULL);
}

/*	 A_EXIT_0, A_EXIT_1	*/
enum crmd_fsa_input
do_exit(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	void *data)
{
	FNIN();

	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n", fsa_action2string(action), action);

	if(action & A_EXIT_0) {
		g_main_quit(crmd_mainloop);
	} else {
		exit(1);
	}
	
	FNRET(I_NULL);
}


/*	 A_STARTUP	*/
enum crmd_fsa_input
do_startup(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   void *data)
{
	FNIN();

	fsa_input_register = 0; // zero out the regester
	
	cl_log(LOG_INFO, "Register PID");
	register_pid(PID_FILE, FALSE, shutdown);
	
	cl_log_set_logfile(DAEMON_LOG);
/*	if (crm_debug()) { */
	cl_log_set_debugfile(DAEMON_DEBUG);
/*  		cl_log_enable_stderr(FALSE); 
		} */
	
	ipc_clients = g_hash_table_new(&g_str_hash, &g_str_equal);
	
	/* change the logging facility to the one used by heartbeat daemon */
	fsa_cluster_connection = ll_cluster_new("heartbeat");
	
	int facility;
	cl_log(LOG_INFO, "Switching to Heartbeat logger");
	if ((facility =
	     fsa_cluster_connection->llc_ops->get_logfacility(
		     fsa_cluster_connection)) > 0) {
		cl_log_set_facility(facility);
	}
	
	int was_error = 0;

	CRM_DEBUG2("Facility: %d", facility);
	
	if(was_error == 0) {
		CRM_DEBUG("Init server comms");
		was_error = init_server_ipc_comms(CRM_SYSTEM_CRMD,
						  crmd_client_connect,
						  default_ipc_input_destroy);
	}
	
	if (was_error == 0) {
		CRM_DEBUG("Finding our node name");
		fsa_our_uname = fsa_cluster_connection->llc_ops->get_mynodeid(
			fsa_cluster_connection);
		
		if (fsa_our_uname == NULL) {
			cl_log(LOG_ERR, "get_mynodeid() failed");
			was_error = 1;
		}
		cl_log(LOG_INFO, "Hostname: %s", fsa_our_uname);
	}

	/* set up the timers */
	dc_heartbeat     = (fsa_timer_t *)ha_malloc(sizeof(fsa_timer_t));
	integration_timer= (fsa_timer_t *)ha_malloc(sizeof(fsa_timer_t));
	election_trigger = (fsa_timer_t *)ha_malloc(sizeof(fsa_timer_t));
	election_timeout = (fsa_timer_t *)ha_malloc(sizeof(fsa_timer_t));
	shutdown_escalation_timmer = (fsa_timer_t *)
		ha_malloc(sizeof(fsa_timer_t));


	int interval = 1; // seconds between DC heartbeats

	interval = interval * 1000;
	
	election_trigger->source_id = -1;
	election_trigger->period_ms = interval*4;
	election_trigger->fsa_input = I_DC_TIMEOUT;
	election_trigger->callback = timer_popped;

	dc_heartbeat->source_id = -1;
	dc_heartbeat->period_ms = interval;
	dc_heartbeat->fsa_input = I_NULL;
	dc_heartbeat->callback = do_dc_heartbeat;
		
	election_timeout->source_id = -1;
	election_timeout->period_ms = interval*6;
	election_timeout->fsa_input = I_ELECTION_DC;
	election_timeout->callback = timer_popped;

	integration_timer->source_id = -1;
	integration_timer->period_ms = interval*6;
	integration_timer->fsa_input = I_INTEGRATION_TIMEOUT;
	integration_timer->callback = timer_popped;
	
	shutdown_escalation_timmer->source_id = -1;
	shutdown_escalation_timmer->period_ms = interval*13;
	shutdown_escalation_timmer->fsa_input = I_ERROR;
	shutdown_escalation_timmer->callback = timer_popped;
	
	/* set up the sub systems */
	cib_subsystem = (struct crm_subsystem_s*)
		ha_malloc(sizeof(struct crm_subsystem_s));
	
	cib_subsystem->pid = 0;	
	cib_subsystem->respawn = 1;	
	cib_subsystem->path = ha_strdup(BIN_DIR);
	cib_subsystem->name = ha_strdup(CRM_SYSTEM_CIB);
	cib_subsystem->command = BIN_DIR"/cib";
	cib_subsystem->flag = R_CIB_CONNECTED;	

	te_subsystem = (struct crm_subsystem_s*)
		ha_malloc(sizeof(struct crm_subsystem_s));
	
	te_subsystem->pid = 0;	
	te_subsystem->respawn = 1;	
	te_subsystem->path = ha_strdup(BIN_DIR);
	cib_subsystem->name = ha_strdup(CRM_SYSTEM_TENGINE);
	te_subsystem->command = BIN_DIR"/tengine";
	te_subsystem->flag = R_TE_CONNECTED;	

	pe_subsystem = (struct crm_subsystem_s*)
		ha_malloc(sizeof(struct crm_subsystem_s));
	
	pe_subsystem->pid = 0;	
	pe_subsystem->respawn = 1;	
	pe_subsystem->path = ha_strdup(BIN_DIR);
	cib_subsystem->name = ha_strdup(CRM_SYSTEM_PENGINE);
	pe_subsystem->command = BIN_DIR"/pengine";
	pe_subsystem->flag = R_PE_CONNECTED;	


	if(was_error)
		FNRET(I_FAIL);
	
	FNRET(I_NULL);
}


/*	 A_STOP	*/
enum crmd_fsa_input
do_stop(long long action,
	enum crmd_fsa_cause cause,
	enum crmd_fsa_state cur_state,
	enum crmd_fsa_input current_input,
	void *data)
{
	FNIN();

	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);

	FNRET(I_NULL);
}

/*	 A_STARTED	*/
enum crmd_fsa_input
do_started(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   void *data)
{
	FNIN();

	clear_bit_inplace(&fsa_input_register, R_STARTING);
	
	FNRET(I_NULL);
}

/*	 A_RECOVER	*/
enum crmd_fsa_input
do_recover(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   void *data)
{
	FNIN();

	cl_log(LOG_ERR, "Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);

	FNRET(I_SHUTDOWN);
}

void
shutdown(int nsig)
{
	FNIN();
    
	CL_SIGNAL(nsig, shutdown);

    
	if (crmd_mainloop != NULL && g_main_is_running(crmd_mainloop)) {

		if(is_set(fsa_input_register, R_SHUTDOWN)) {
			CRM_DEBUG("Escalating the shutdown");
			s_crmd_fsa(C_SHUTDOWN, I_ERROR, NULL);

		} else {
			set_bit_inplace(&fsa_input_register, R_SHUTDOWN);

			// cant rely on this...
			startTimer(shutdown_escalation_timmer);

			s_crmd_fsa(C_SHUTDOWN, I_SHUTDOWN, NULL);
		}
		
	} else {
		CRM_DEBUG("exit from shutdown");
		exit(LSB_EXIT_OK);
	    
	}
	FNOUT();
}

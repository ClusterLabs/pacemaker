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

extern gboolean crmd_ha_input_dispatch(int fd, gpointer user_data);
extern void crmd_ha_input_destroy(gpointer user_data);

void crm_shutdown(int nsig);

IPC_WaitConnection *wait_channel_init(char daemonsocket[]);

int init_server_ipc_comms(
	const char *child,
	gboolean (*channel_client_connect)(IPC_Channel *newclient,
					   gpointer user_data),
	void (*channel_input_destroy)(gpointer user_data));


gboolean
register_with_ha(ll_cluster_t *hb_cluster, const char *client_name,
		 gboolean (*dispatch_method)(int fd, gpointer user_data),
		 void (*message_callback)(const struct ha_msg* msg,
					  void* private_data),
		 GDestroyNotify cleanup_method);

GHashTable   *ipc_clients = NULL;

/*	 A_HA_CONNECT	*/
enum crmd_fsa_input
do_ha_control(long long action,
	       enum crmd_fsa_cause cause,
	       enum crmd_fsa_state cur_state,
	       enum crmd_fsa_input current_input,
	       void *data)
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

		// make sure we are disconnected first
		fsa_cluster_conn->llc_ops->signoff(fsa_cluster_conn);
		
		registered = register_with_ha(fsa_cluster_conn,
					      crm_system_name,
					      crmd_ha_input_dispatch,
					      crmd_ha_input_callback,
					      crmd_ha_input_destroy);
		
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
	    void *data)
{
	enum crmd_fsa_input next_input = I_NULL;
	enum crmd_fsa_input tmp = I_NULL;
	
	

	/* last attempt to shut these down */
	if(is_set(fsa_input_register, R_PE_CONNECTED)) {
		crm_warn("Last attempt to shutdown the PolicyEngine");
		tmp = do_pe_control(A_PE_STOP, cause, cur_state,
				    current_input, data);
		if(tmp != I_NULL) {
			next_input = I_ERROR;
			crm_err("Failed to shutdown the PolicyEngine");
		}
	}

	if(is_set(fsa_input_register, R_TE_CONNECTED)) {
		crm_warn("Last attempt to shutdown the Transitioner");
		tmp = do_pe_control(A_TE_STOP, cause, cur_state,
				    current_input, data);
		if(tmp != I_NULL) {
			next_input = I_ERROR;
			crm_err("Failed to shutdown the Transitioner");
		}
		
	}

	/* TODO: shutdown all remaining resources? */
	
	return next_input;
}

/*	 A_SHUTDOWN_REQ	*/
enum crmd_fsa_input
do_shutdown_req(long long action,
	    enum crmd_fsa_cause cause,
	    enum crmd_fsa_state cur_state,
	    enum crmd_fsa_input current_input,
	    void *data)
{
	enum crmd_fsa_input next_input = I_NULL;
	

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
	void *data)
{
	

	crm_err("Action %s (%.16llx) not supported\n",
		fsa_action2string(action), action);

	if(action & A_EXIT_0) {
		g_main_quit(crmd_mainloop);
	} else {
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
	   void *data)
{
	int facility;
	int was_error = 0;
	int interval = 1; // seconds between DC heartbeats

	fsa_input_register = 0; // zero out the regester
	
	crm_info("Register PID");
	register_pid(PID_FILE, FALSE, crm_shutdown);
	
	ipc_clients = g_hash_table_new(&g_str_hash, &g_str_equal);
	
	/* change the logging facility to the one used by heartbeat daemon */
	fsa_cluster_conn = ll_cluster_new("heartbeat");
	
	crm_info("Switching to Heartbeat logger");
	if ((facility =
	     fsa_cluster_conn->llc_ops->get_logfacility(
		     fsa_cluster_conn)) > 0) {
		cl_log_set_facility(facility);
	}
	
	crm_verbose("Facility: %d", facility);
	
	if(was_error == 0) {
		crm_info("Init server comms");
		was_error = init_server_ipc_comms(
			CRM_SYSTEM_CRMD, crmd_client_connect,
			default_ipc_input_destroy);
	}
	
	if (was_error == 0) {
		fsa_our_uname = fsa_cluster_conn->llc_ops->get_mynodeid(
			fsa_cluster_conn);
		
		if (fsa_our_uname == NULL) {
			crm_err("get_mynodeid() failed");
			was_error = 1;
		}
		crm_info("FSA Hostname: %s", fsa_our_uname);
	}

	/* set up the timers */
	dc_heartbeat     = (fsa_timer_t *)crm_malloc(sizeof(fsa_timer_t));
	integration_timer= (fsa_timer_t *)crm_malloc(sizeof(fsa_timer_t));
	election_trigger = (fsa_timer_t *)crm_malloc(sizeof(fsa_timer_t));
	election_timeout = (fsa_timer_t *)crm_malloc(sizeof(fsa_timer_t));
	shutdown_escalation_timmer = (fsa_timer_t *)
		crm_malloc(sizeof(fsa_timer_t));


	interval = interval * 1000;
	
	election_trigger->source_id = -1;
	election_trigger->period_ms = -1;
	election_trigger->fsa_input = I_DC_TIMEOUT;
	election_trigger->callback = timer_popped;

	dc_heartbeat->source_id = -1;
	dc_heartbeat->period_ms = -1;
	dc_heartbeat->fsa_input = I_NULL;
	dc_heartbeat->callback = do_dc_heartbeat;
		
	election_timeout->source_id = -1;
	election_timeout->period_ms = -1;
	election_timeout->fsa_input = I_ELECTION_DC;
	election_timeout->callback = timer_popped;

	integration_timer->source_id = -1;
	integration_timer->period_ms = -1;
	integration_timer->fsa_input = I_INTEGRATION_TIMEOUT;
	integration_timer->callback = timer_popped;
	
	shutdown_escalation_timmer->source_id = -1;
	shutdown_escalation_timmer->period_ms = -1;
	shutdown_escalation_timmer->fsa_input = I_TERMINATE;
	shutdown_escalation_timmer->callback = timer_popped;
	
	/* set up the sub systems */
	cib_subsystem = (struct crm_subsystem_s*)
		crm_malloc(sizeof(struct crm_subsystem_s));
	
	cib_subsystem->pid = 0;	
	cib_subsystem->respawn = 1;	
	cib_subsystem->path = crm_strdup(BIN_DIR);
	cib_subsystem->name = crm_strdup(CRM_SYSTEM_CIB);
	cib_subsystem->command = BIN_DIR"/cib";
	cib_subsystem->flag = R_CIB_CONNECTED;	

	te_subsystem = (struct crm_subsystem_s*)
		crm_malloc(sizeof(struct crm_subsystem_s));
	
	te_subsystem->pid = 0;	
	te_subsystem->respawn = 1;	
	te_subsystem->path = crm_strdup(BIN_DIR);
	te_subsystem->name = crm_strdup(CRM_SYSTEM_TENGINE);
	te_subsystem->command = BIN_DIR"/tengine";
	te_subsystem->flag = R_TE_CONNECTED;	

	pe_subsystem = (struct crm_subsystem_s*)
		crm_malloc(sizeof(struct crm_subsystem_s));
	
	pe_subsystem->pid = 0;	
	pe_subsystem->respawn = 1;	
	pe_subsystem->path = crm_strdup(BIN_DIR);
	pe_subsystem->name = crm_strdup(CRM_SYSTEM_PENGINE);
	pe_subsystem->command = BIN_DIR"/pengine";
	pe_subsystem->flag = R_PE_CONNECTED;	


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
	void *data)
{
	

	crm_err("Action %s (%.16llx) not supported\n",
	       fsa_action2string(action), action);

	return I_NULL;
}

/*	 A_STARTED	*/
enum crmd_fsa_input
do_started(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   void *data)
{
	

	clear_bit_inplace(&fsa_input_register, R_STARTING);
	
	return I_NULL;
}

/*	 A_RECOVER	*/
enum crmd_fsa_input
do_recover(long long action,
	   enum crmd_fsa_cause cause,
	   enum crmd_fsa_state cur_state,
	   enum crmd_fsa_input current_input,
	   void *data)
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
	       void *data)
{
	xmlNodePtr cib_copy = get_cib_copy();
	xmlNodePtr config   = get_object_root(XML_CIB_TAG_CRMCONFIG, cib_copy);
	xmlNodePtr iter = config->children;
	while(iter != NULL) {
		const char *name  = xmlGetProp(iter, XML_NVPAIR_ATTR_NAME);
		const char *value = xmlGetProp(iter, XML_NVPAIR_ATTR_VALUE);
		iter = iter->next;
		
		if(name == NULL || value == NULL) {
			continue;
			
		} else if(safe_str_eq(name, "dc_heartbeat")) {
			dc_heartbeat->period_ms = atoi(value);
			
		} else if(safe_str_eq(name, "dc_deadtime")) {
			election_trigger->period_ms = atoi(value);

		} else if(safe_str_eq(name, "shutdown_escalation")) {
			shutdown_escalation_timmer->period_ms = atoi(value);

		}
	}
	
	if(dc_heartbeat->period_ms < 1) {
		// sensible default
		dc_heartbeat->period_ms = 1000;
		
	}
	if(election_trigger->period_ms < 1) {
		// sensible default
		election_trigger->period_ms = dc_heartbeat->period_ms * 4;
		
	}
	if(shutdown_escalation_timmer->period_ms < 1) {
		// sensible default
		shutdown_escalation_timmer->period_ms
			= election_trigger->period_ms * 3 *10;// 10 for testing
	}
	
	election_timeout->period_ms  = dc_heartbeat->period_ms * 6;
	integration_timer->period_ms = dc_heartbeat->period_ms * 6;

	return I_NULL;
}


void
crm_shutdown(int nsig)
{
	CL_SIGNAL(nsig, crm_shutdown);
    
	if (crmd_mainloop != NULL && g_main_is_running(crmd_mainloop)) {

		if(is_set(fsa_input_register, R_SHUTDOWN)) {
			crm_err("Escalating the shutdown");
			s_crmd_fsa(C_SHUTDOWN, I_ERROR, NULL);

		} else {
			set_bit_inplace(&fsa_input_register, R_SHUTDOWN);

			if(is_set(fsa_input_register, R_SHUTDOWN)) {
				// cant rely on this...
				startTimer(shutdown_escalation_timmer);
				
				s_crmd_fsa(C_SHUTDOWN, I_SHUTDOWN, NULL);
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

int
init_server_ipc_comms(
	const char *child,
	gboolean (*channel_client_connect)(IPC_Channel *newclient,
					   gpointer user_data),
	void (*channel_input_destroy)(gpointer user_data))
{
	/* the clients wait channel is the other source of events.
	 * This source delivers the clients connection events.
	 * listen to this source at a relatively lower priority.
	 */
    
	char    commpath[SOCKET_LEN];
	IPC_WaitConnection *wait_ch;

	
	sprintf(commpath, WORKING_DIR "/%s", child);

	wait_ch = wait_channel_init(commpath);

	if (wait_ch == NULL) return 1;
	G_main_add_IPC_WaitConnection(G_PRIORITY_LOW,
				      wait_ch,
				      NULL,
				      FALSE,
				      channel_client_connect,
				      wait_ch, // user data passed to ??
				      channel_input_destroy);

	crm_debug("Listening on: %s", commpath);

	return 0;
}

#define safe_val3(def, t,u,v)       (t?t->u?t->u->v:def:def)

gboolean
register_with_ha(ll_cluster_t *hb_cluster, const char *client_name,
		 gboolean (*dispatch_method)(int fd, gpointer user_data),
		 void (*message_callback)(const struct ha_msg* msg,
					  void* private_data),
		 GDestroyNotify cleanup_method)
{
	const char* ournode = NULL;
	if(safe_val3(NULL, hb_cluster, llc_ops, errmsg) == NULL) {
	  crm_crit("cluster errmsg function unavailable");
	}
	crm_info("Signing in with Heartbeat");
	if (hb_cluster->llc_ops->signon(hb_cluster, client_name)!= HA_OK) {
		crm_err("Cannot sign on with heartbeat");
		if(safe_val3(NULL, hb_cluster, llc_ops, errmsg) == NULL) {
			crm_crit("cluster errmsg function unavailable");
		} else {
			crm_err("REASON: %s",
				hb_cluster->llc_ops->errmsg(hb_cluster));
		}
		return FALSE;
	}
  
	crm_debug("Finding our node name");
	if ((ournode =
	     hb_cluster->llc_ops->get_mynodeid(hb_cluster)) == NULL) {
		crm_err("get_mynodeid() failed");
		return FALSE;
	}
	crm_info("hostname: %s", ournode);
	
	crm_debug("Be informed of CRM messages");
	if (hb_cluster->llc_ops->set_msg_callback(hb_cluster,
						  "CRM",
						  message_callback,
						  hb_cluster)
	    !=HA_OK){
		crm_err("Cannot set CRM message callback");
		if(safe_val3(NULL, hb_cluster, llc_ops, errmsg) == NULL) {
			crm_crit("cluster errmsg function unavailable");
		} else {
			crm_err("REASON: %s",
				hb_cluster->llc_ops->errmsg(hb_cluster));
		}
		return FALSE;
	}

	G_main_add_fd(G_PRIORITY_HIGH, 
		      hb_cluster->llc_ops->inputfd(hb_cluster),
		      FALSE, 
		      dispatch_method, 
		      hb_cluster,  // usrdata 
		      cleanup_method);

	return TRUE;
    
}

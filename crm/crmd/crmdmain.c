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
#include <crm/common/crm.h>

#include <portability.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <apphb.h>

#include <clplumbing/ipc.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/uids.h>
#include <clplumbing/realtime.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_poll.h>

#include <ocf/oc_event.h>
#include <libxml/tree.h>

GMainLoop*  mainloop = NULL;
const char* daemon_name = "crmd";

#include <crm/common/crmutils.h>
#include <crm/common/ipcutils.h>
#include <crm/common/xmlvalues.h>
#include <crmd.h>

#define PID_FILE     "/var/lib/heartbeat/crm/crm.pid"
#define DAEMON_LOG   "crm.log"
#define DAEMON_DEBUG "crm.debug"
#define OPTARGS	"skrh"

void usage(const char* cmd, int exit_status);
int init_start(void);
void register_with_apphb(void);
ll_cluster_t * ha_register(void);
int register_with_ccm(ll_cluster_t *hb_cluster);
gboolean crmd_ha_input_dispatch(int fd, gpointer user_data);
void crmd_ha_input_destroy(gpointer user_data);
void shutdown(int nsig);
void crmd_hamsg_callback(const struct ha_msg* msg, void* private_data);

int
main(int argc, char ** argv)
{

    cl_log_set_entity(daemon_name);
    cl_log_enable_stderr(TRUE);
    cl_log_set_facility(LOG_USER);
    
    int	req_restart = FALSE;
    int	req_status = FALSE;
    int	req_stop = FALSE;
    int	argerr = 0;
    int flag;
    
    
    while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
	switch(flag) {
	    case 's':		/* Status */
		req_status = TRUE;
		break;
	    case 'k':		/* Stop (kill) */
		req_stop = TRUE;
		break;
	    case 'r':		/* Restart */
		req_restart = TRUE;
		break;
	    case 'h':		/* Help message */
		usage(daemon_name, LSB_EXIT_OK);
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
	usage(daemon_name,LSB_EXIT_GENERIC);
    }
    
    // read local config file
    
    if (req_status){
	FNRET(init_status(PID_FILE, daemon_name));
    }
  
    if (req_stop){
	FNRET(init_stop(PID_FILE, mainloop));
    }
  
    if (req_restart) { 
	init_stop(PID_FILE, mainloop);
    }

    FNRET(init_start());
}


int
init_start(void)
{
    long pid;

    if ((pid = get_running_pid(PID_FILE, NULL)) > 0) {
	cl_log(LOG_CRIT, "already running: [pid %ld].", pid);
	exit(LSB_EXIT_OK);
    }
    cl_log(LOG_INFO, "Register PID");
    register_pid(PID_FILE, TRUE, shutdown);
  
    cl_log_set_logfile(DAEMON_LOG);
//    if (crm_debug()) {
    cl_log_set_debugfile(DAEMON_DEBUG);
//    }

    xmlInitParser();
    pending_remote_replies = g_hash_table_new(&g_str_hash, &g_str_equal);
    ipc_clients = g_hash_table_new(&g_str_hash, &g_str_equal);
		    
    /* change the logging facility to the one used by heartbeat daemon */
    hb_cluster = ll_cluster_new("heartbeat");
  
    //	(void)_heartbeat_h_Id;
    (void)_ha_msg_h_Id;

    int facility;
    cl_log(LOG_INFO, "Switching to Heartbeat logger");
    if ((facility = hb_cluster->llc_ops->get_logfacility(hb_cluster))>0) {
	cl_log_set_facility(facility);
    }
    

    int was_error = 0;

    CRM_DEBUG("Init server comms");
    was_error = init_server_ipc_comms(CRM_SYSTEM_CRMD, crmd_client_connect, default_ipc_input_destroy);
    
    if(was_error == 0)
    {
	CRM_DEBUG("Signon with the CIB");
	IPC_Channel *cib_channel = init_client_ipc_comms("cib", crmd_ipc_input_callback);
	if(cib_channel != NULL)
	    g_hash_table_insert (ipc_clients, strdup("cib"), (gpointer)cib_channel);
	else
	    was_error = 1;
    }
    if(was_error == 0)
    {
	CRM_DEBUG("Registering with HA");
	was_error = (register_with_ha(hb_cluster,
				      daemon_name,
				      crmd_ha_input_dispatch,
				      crmd_ha_input_callback,
				      crmd_ha_input_destroy) == FALSE);
    }
    if(was_error == 0)
    {
	CRM_DEBUG("Registering with CCM");
	was_error = register_with_ccm(hb_cluster);
    }
    
    if(was_error == 0)
    {
	CRM_DEBUG("Finding our node name");
	our_uname = hb_cluster->llc_ops->get_mynodeid(hb_cluster);
	if(our_uname == NULL)
	{
	    cl_log(LOG_ERR, "get_mynodeid() failed");
	    was_error = 1;
	}
	cl_log(LOG_INFO, "Hostname: %s", our_uname);
    }

    if(was_error == 0)
    {
	/* Create the mainloop and run it... */
	mainloop = g_main_new(FALSE);
	cl_log(LOG_INFO, "Starting %s", daemon_name);
	
#ifdef REALTIME_SUPPORT
	static int  crm_realtime = 1;
	if (crm_realtime == 1){
	    cl_enable_realtime();
	}else if (crm_realtime == 0){
	    cl_disable_realtime();
	}
	cl_make_realtime(SCHED_RR, 5, 64, 64);
#endif
	
	g_main_run(mainloop);
	return_to_orig_privs();
    }
    
    if (unlink(PID_FILE) == 0) {
	cl_log(LOG_INFO, "[%s] stopped", daemon_name);
    }
    FNRET(was_error);
}

gboolean
crmd_ha_input_dispatch(int fd, gpointer user_data)
{
    cl_log(LOG_DEBUG, "input_dispatch...");
    
    ll_cluster_t*	hb_cluster = (ll_cluster_t*)user_data;
    
    while(hb_cluster->llc_ops->msgready(hb_cluster))
    {
	cl_log(LOG_DEBUG, "there was another message...");
	hb_cluster->llc_ops->rcvmsg(hb_cluster, 0);  // invoke the callbacks but dont block
    }
    
    FNRET(TRUE);
}

void
crmd_ha_input_destroy(gpointer user_data)
{
    cl_log(LOG_INFO, "in my hb_input_destroy");
}

int
register_with_ccm(ll_cluster_t *hb_cluster)
{
    int ret;
    fd_set rset;
    
    cl_log(LOG_INFO, "Registering with CCM");
    oc_ev_register(&ev_token);
    
    cl_log(LOG_INFO, "Setting up CCM callbacks");
    oc_ev_set_callback(ev_token, OC_EV_MEMB_CLASS, crmd_ccm_input_callback, NULL);
    oc_ev_special(ev_token, OC_EV_MEMB_CLASS, 0/*don't care*/);
    
    cl_log(LOG_INFO, "Activating CCM taken");
    ret = oc_ev_activate(ev_token, &my_ev_fd);
    if(ret){
	cl_log(LOG_INFO, "CCM Activation failed... unregistering");
	oc_ev_unregister(ev_token);
	return(1);
    }
    cl_log(LOG_INFO, "CCM Activation passed... all set to go!");
    
    FD_ZERO(&rset);
    FD_SET(my_ev_fd, &rset);
    
    if(oc_ev_handle_event(ev_token)){
	cl_log(LOG_ERR,"CCM Activation: terminating");
	return(1);
    }
    
    cl_log(LOG_INFO, "Sign up for \"ccmjoin\" messages");
    if (hb_cluster->llc_ops->set_msg_callback(hb_cluster, "ccmjoin",
					      msg_ccm_join, hb_cluster) != HA_OK)
    {
	cl_log(LOG_ERR, "Cannot set msg_ipfail_join callback");
    }
    
    FNRET(0);
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

void
shutdown(int nsig)
{
    static int	shuttingdown = 0;
    CL_SIGNAL(nsig, shutdown);
  
    if (!shuttingdown) {
	shuttingdown = 1;
    }
    if (mainloop != NULL && g_main_is_running(mainloop)) {
	g_main_quit(mainloop);
    }else{
	exit(LSB_EXIT_OK);
    }
}


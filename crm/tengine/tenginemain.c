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

#include <crm/common/ipcutils.h>
#include <crm/common/crmutils.h>
#include <crm/common/xmlvalues.h>
#include <crm/common/msgutils.h>

#include <crm/dmalloc_wrapper.h>

#define OPTARGS	"skrh"
#define PID_FILE     WORKING_DIR "/transitioner.pid"
#define DAEMON_LOG   "/var/log/transitioner.log"
#define DAEMON_DEBUG "/var/log/transitioner.debug"

GMainLoop*  mainloop = NULL;
const char* crm_system_name = "transitioner";


void usage(const char* cmd, int exit_status);
int init_start(void);
void shutdown(int nsig);

int
main(int argc, char ** argv)
{

    cl_log_set_entity(crm_system_name);
    cl_log_enable_stderr(TRUE);
    cl_log_set_facility(LOG_USER);
    
    int	req_restart = FALSE;
    int	req_status = FALSE;
    int	req_stop = FALSE;
    int	argerr = 0;
    int flag;

    if (0)
    {
	send_ipc_message(NULL, NULL);
    }
    
    
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
    
    // read local config file
    
    if (req_status){
	return init_status(PID_FILE, crm_system_name);
    }
  
    if (req_stop){
	return init_stop(PID_FILE, mainloop);
    }
  
    if (req_restart) { 
	init_stop(PID_FILE, mainloop);
    }

    return init_start();

}


int
init_start(void)
{
    long pid;

    if ((pid = get_running_pid(PID_FILE, NULL)) > 0) {
	cl_log(LOG_CRIT, "already running: [pid %ld].", pid);
	exit(LSB_EXIT_OK);
    }
  
    cl_log_set_logfile(DAEMON_LOG);
//    if (crm_debug()) {
    cl_log_set_debugfile(DAEMON_DEBUG);
//    }

    (void)_ha_msg_h_Id;
    
    /* change the logging facility to the one used by heartbeat daemon */
    ll_cluster_t*	hb_fd = ll_cluster_new("heartbeat");
    
    //	(void)_heartbeat_h_Id;
    
    int facility;
    cl_log(LOG_INFO, "Switching to Heartbeat logger");
    if ((facility = hb_fd->llc_ops->get_logfacility(hb_fd))>0) {
	cl_log_set_facility(facility);
    }
    
    cl_log(LOG_INFO, "Register PID");
    register_pid(PID_FILE, TRUE, shutdown);

    IPC_Channel *crm_ch = init_client_ipc_comms("crmd", default_ipc_input_dispatch);
    send_hello_message(crm_ch, "1234", CRM_SYSTEM_TENGINE, "0", "1");

    /* Create the mainloop and run it... */
    mainloop = g_main_new(FALSE);
    cl_log(LOG_INFO, "Starting %s", crm_system_name);

    G_main_add_IPC_Channel(G_PRIORITY_LOW,
			   crm_ch,
			   FALSE, 
			   default_ipc_input_dispatch,
			   crm_ch, 
			   default_ipc_input_destroy);

    
    
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
  
    if (unlink(PID_FILE) == 0) {
	cl_log(LOG_INFO, "[%s] stopped", crm_system_name);
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

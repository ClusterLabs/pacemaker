/* $Id: cibmain.c,v 1.24 2004/07/09 15:35:57 msoffen Exp $ */
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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/uids.h>

//#include <ocf/oc_event.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ctrl.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <cibio.h>

#include <crm/dmalloc_wrapper.h>

/* #define REALTIME_SUPPORT 0 */
#define PID_FILE     WORKING_DIR"/cib.pid"
#define DAEMON_LOG   LOG_DIR"/cib.log"
#define DAEMON_DEBUG LOG_DIR"/cib.debug"

GMainLoop*  mainloop = NULL;
const char* crm_system_name = CRM_SYSTEM_CIB;

void usage(const char* cmd, int exit_status);
int init_start(void);
void cib_shutdown(int nsig);
gboolean cib_msg_callback(IPC_Channel *client, gpointer user_data);
gboolean process_maincib_message(xmlNodePtr msg, IPC_Channel *sender);

#define OPTARGS	"skrh"

int
main(int argc, char ** argv)
{

	int	req_comms_restart = FALSE;
	int	req_restart = FALSE;
	int	req_status = FALSE;
	int	req_stop = FALSE;
	int	argerr = 0;
	int flag;
    
	cl_log_set_entity(crm_system_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);
    
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
			case 'c':		/* Restart */
				req_comms_restart = TRUE;
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
		return init_stop(PID_FILE);
	}
  
	if (req_restart) { 
		init_stop(PID_FILE);
	}

	return init_start();
}


int
init_start(void)
{
	long pid;
	ll_cluster_t *hb_fd;
	int facility;
	IPC_Channel *crm_ch = NULL;
#ifdef REALTIME_SUPPORT
	static int  crm_realtime = 1;
#endif

	if ((pid = get_running_pid(PID_FILE, NULL)) > 0) {
		crm_crit("already running: [pid %ld].", pid);
		exit(LSB_EXIT_OK);
	}

	crm_info("Register PID");
	register_pid(PID_FILE, FALSE, cib_shutdown);

	cl_log_set_logfile(DAEMON_LOG);
//    if (crm_verbose()) {
	cl_log_set_debugfile(DAEMON_DEBUG);
//    }
  
	hb_fd = ll_cluster_new("heartbeat");

	crm_info("Switching to Heartbeat logger");
	if ((facility = hb_fd->llc_ops->get_logfacility(hb_fd))>0) {
		cl_log_set_facility(facility);
	}    

	if(startCib(CIB_FILENAME) == FALSE){
		crm_crit("Cannot start CIB... terminating");
		exit(1);
	}
	
	crm_ch = init_client_ipc_comms(CRM_SYSTEM_CRMD,
				       subsystem_input_dispatch,
				       (void*)process_maincib_message);

	if(crm_ch != NULL) {
		send_hello_message(crm_ch, "-", CRM_SYSTEM_CIB, "0", "1");

	/* Create the mainloop and run it... */
		mainloop = g_main_new(FALSE);
		crm_info("Starting %s", crm_system_name);
	
#ifdef REALTIME_SUPPORT
		if (crm_realtime == 1) {
			cl_enable_realtime();
		} else if (crm_realtime == 0) {
			cl_disable_realtime();
		}
		cl_make_realtime(SCHED_RR, 5, 64, 64);
#endif
		
		g_main_run(mainloop);
		return_to_orig_privs();
	} else {
		crm_err("Connection to CRM not valid, exiting.");
	}
	
	
	if (unlink(PID_FILE) == 0) {
		crm_info("[%s] stopped", crm_system_name);
	}
	return 0;
}

gboolean
process_maincib_message(xmlNodePtr msg, IPC_Channel *sender)
{
	const char *op = get_xml_attr (msg, XML_TAG_OPTIONS,
				       XML_ATTR_OP, FALSE);

	const char *sys_to = xmlGetProp(msg, XML_ATTR_SYSTO);

	crm_debug("Processing %s message", op);

	if(safe_str_eq(xmlGetProp(msg, XML_ATTR_MSGTYPE), XML_ATTR_REQUEST)) {
		crm_info("Message was a response not a request."
			 "  Discarding");

	} else if (strcmp(sys_to, CRM_SYSTEM_CIB) == 0
		   || strcmp(sys_to, CRM_SYSTEM_DCIB) == 0) {
		
		xmlNodePtr answer = process_cib_message(msg, TRUE);
		if (send_xmlipc_message(sender, answer)==FALSE)
			crm_warn("Cib answer could not be sent");
		free_xml(answer);

	} else {
		crm_warn("Received a message destined for %s by mistake",
			 sys_to);
		return FALSE;
	}
		
	return TRUE;
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
cib_shutdown(int nsig)
{
	static int	shuttingdown = 0;
	CL_SIGNAL(nsig, cib_shutdown);
  
	if (!shuttingdown) {
		shuttingdown = 1;
	}
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	} else {
		exit(LSB_EXIT_OK);
	}
}

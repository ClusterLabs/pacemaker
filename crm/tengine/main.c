/* $Id: main.c,v 1.10 2004/12/15 10:11:34 andrew Exp $ */
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
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/uids.h>
#include <clplumbing/coredumps.h>

#include <crm/common/ctrl.h>
#include <crm/common/ipc.h>

#include <tengine.h>

#include <crm/dmalloc_wrapper.h>

#define SYS_NAME     CRM_SYSTEM_TENGINE
#define OPTARGS      "skrhVc"
#define PID_FILE     WORKING_DIR "/" SYS_NAME ".pid"
#define DAEMON_LOG   DEVEL_DIR"/"SYS_NAME".log"
#define DAEMON_DEBUG DEVEL_DIR"/"SYS_NAME".debug"

GMainLoop*  mainloop = NULL;
const char* crm_system_name = SYS_NAME;
extern cib_t *te_cib_conn;

void usage(const char* cmd, int exit_status);
int init_start(void);
void tengine_shutdown(int nsig);
extern void te_update_confirm(const char *event, struct ha_msg *msg);

int
main(int argc, char ** argv)
{
	gboolean allow_cores = TRUE;
	int req_restart = FALSE;
	int req_status = FALSE;
	int req_stop = FALSE;
	int argerr = 0;
	int flag;

	/* Redirect messages from glib functions to our handler */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);
	/* and for good measure... */
	g_log_set_always_fatal((GLogLevelFlags)0);    
    
	cl_log_set_entity(crm_system_name);
	cl_log_set_facility(LOG_LOCAL7);

	cl_log_set_logfile(DAEMON_LOG);
	cl_log_set_debugfile(DAEMON_DEBUG);

	CL_SIGNAL(SIGTERM, tengine_shutdown);

/* 	set_crm_log_level(LOG_TRACE); */
	crm_debug("Begining option processing");

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				alter_debug(DEBUG_INC);
				break;
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
			case 'c':
				allow_cores = TRUE;
				break;
    
			default:
				++argerr;
				break;
		}
	}
    
	crm_debug("Option processing complete");

	if (optind > argc) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name,LSB_EXIT_GENERIC);
	}
    
	/* read local config file */

	if(allow_cores) {
		crm_info("Enabling coredumps");
		cl_set_corerootdir(DEVEL_DIR);	    
		cl_enable_coredumps(1);
		cl_cdtocoredir();
		crm_debug("Coredump processing complete");
	}
    
	if (req_status){
		return init_status(PID_FILE, crm_system_name);
	}
  
	if (req_stop){
		return init_stop(PID_FILE);
	}
  
	if (req_restart) { 
		init_stop(PID_FILE);
	}

	crm_debug("Starting...");
	return init_start();

}


int
init_start(void)
{
	int init_ok = TRUE;
	
	init_client_ipc_comms(
		CRM_SYSTEM_CRMD, subsystem_msg_dispatch,
		(void*)process_te_message, &crm_ch);

	if(crm_ch != NULL) {
		send_hello_message(crm_ch, "1234", CRM_SYSTEM_TENGINE, "0", "1");
	} else {
		init_ok = FALSE;
		crm_err("Could not connect to the CRMd");
	}

	if(init_ok) {
		crm_trace("Creating CIB connection");
		te_cib_conn = cib_new();
		if(te_cib_conn == NULL) {
			init_ok = FALSE;
		}
	}
	
	if(init_ok) {
		crm_trace("Connecting to the CIB");
		if(te_cib_conn->cmds->signon(
			   te_cib_conn, cib_command) != cib_ok) {
			init_ok = FALSE;
		}
	}

	if(init_ok) {
		crm_trace("Setting CIB notification callback");
		if(te_cib_conn->cmds->add_notify_callback(
			   te_cib_conn, T_CIB_UPDATE_CONFIRM,
			   te_update_confirm) != cib_ok) {
			init_ok = FALSE;
		}
	}

	if(init_ok) {
		/* Create the mainloop and run it... */
		crm_info("Starting %s", crm_system_name);

		mainloop = g_main_new(FALSE);
		g_main_run(mainloop);
		return_to_orig_privs();

		crm_info("Exiting %s", crm_system_name);
		
	} else {
		crm_warn("Initialization errors, %s not starting.",
			 crm_system_name);
	}

	if(init_ok) {
		return 0;
	}
	return 1;
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
tengine_shutdown(int nsig)
{
	static int	shuttingdown = 0;
	CL_SIGNAL(nsig, tengine_shutdown);
  
	if (!shuttingdown) {
		shuttingdown = 1;
	}
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	}else{
		exit(LSB_EXIT_OK);
	}
}

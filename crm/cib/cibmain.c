/* $Id: cibmain.c,v 1.12 2004/03/24 09:59:04 andrew Exp $ */
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

#include <crm/common/ipcutils.h>
#include <crm/common/crmutils.h>
#include <crm/common/xmlutils.h>
#include <crm/common/xmltags.h>
#include <crm/common/xmlvalues.h>
#include <cibio.h>
#include <crm/cib.h>
#include <crm/common/msgutils.h>

#include <crm/dmalloc_wrapper.h>

/* #define REALTIME_SUPPORT 0 */
#define PID_FILE     WORKING_DIR"/cib.pid"
#define DAEMON_LOG   LOG_DIR"/cib.log"
#define DAEMON_DEBUG LOG_DIR"/cib.debug"

GMainLoop*  mainloop = NULL;
const char* crm_system_name = CRM_SYSTEM_CIB;

void usage(const char* cmd, int exit_status);
int init_start(void);
void shutdown(int nsig);
gboolean cib_msg_callback(IPC_Channel *client, gpointer user_data);

#define OPTARGS	"skrh"

int
main(int argc, char ** argv)
{

	cl_log_set_entity(crm_system_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);
    
	int	req_comms_restart = FALSE;
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
		FNRET(init_status(PID_FILE, crm_system_name));
	}
  
	if (req_stop){
		FNRET(init_stop(PID_FILE));
	}
  
	if (req_restart) { 
		init_stop(PID_FILE);
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
	register_pid(PID_FILE, FALSE, shutdown);

	xmlInitParser();  // only do this once

	cl_log_set_logfile(DAEMON_LOG);
//    if (crm_debug()) {
	cl_log_set_debugfile(DAEMON_DEBUG);
//    }
  
	ll_cluster_t *hb_fd = ll_cluster_new("heartbeat");

	int facility;
	cl_log(LOG_INFO, "Switching to Heartbeat logger");
	if ((facility = hb_fd->llc_ops->get_logfacility(hb_fd))>0) {
		cl_log_set_facility(facility);
	}    

	if(startCib(CIB_FILENAME) == FALSE){
		cl_log(LOG_CRIT, "Cannot start CIB... terminating");
		exit(1);
	}
	
    
	IPC_Channel *crm_ch = init_client_ipc_comms(CRM_SYSTEM_CRMD,
						    cib_msg_callback,
						    NULL);

	if(crm_ch != NULL) {
		send_hello_message(crm_ch, "-", CRM_SYSTEM_CIB, "0", "1");

	/* Create the mainloop and run it... */
		mainloop = g_main_new(FALSE);
		cl_log(LOG_INFO, "Starting %s", crm_system_name);
		
/* 		G_main_add_IPC_Channel(G_PRIORITY_LOW, */
/* 				       crm_ch, */
/* 				       FALSE,  */
/* 				       cib_msg_callback, */
/* 				       crm_ch,  */
/* 				       default_ipc_input_destroy); */
	
	
#ifdef REALTIME_SUPPORT
		static int  crm_realtime = 1;
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
		cl_log(LOG_ERR, "Connection to CRM not valid, exiting.");
	}
	
	
	if (unlink(PID_FILE) == 0) {
		cl_log(LOG_INFO, "[%s] stopped", crm_system_name);
	}
	FNRET(0);
}


gboolean
cib_msg_callback(IPC_Channel *sender, void *user_data)
{
	int lpc = 0;
	char *buffer = NULL;
	xmlDocPtr doc = NULL;
	IPC_Message *msg = NULL;
	gboolean all_is_well = TRUE;
	xmlNodePtr answer = NULL, root_xml_node = NULL;
	
	FNIN();

	while(sender->ops->is_message_pending(sender)) {
		if (sender->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
		}
		if (sender->ops->recv(sender, &msg) != IPC_OK) {
			perror("Receive failure:");
			FNRET(!all_is_well);
		}
		if (msg == NULL) {
			cl_log(LOG_ERR, "No message this time");
			continue;
		}

		lpc++;

		/* the docs say only do this once, but in their code
		 * they do it every time!
		 */
//		xmlInitParser();

		buffer = (char*)msg->msg_body;
		cl_log(LOG_DEBUG, "Message %d [text=%s]", lpc, buffer);
		doc = xmlParseMemory(ha_strdup(buffer), strlen(buffer));

		if(doc == NULL) {
			cl_log(LOG_INFO,
			       "XML Buffer was not valid...\n Buffer: (%s)",
			       buffer);
		}

		root_xml_node = xmlDocGetRootElement(doc);

		const char *sys_to= xmlGetProp(root_xml_node, XML_ATTR_SYSTO);
		const char *type  = xmlGetProp(root_xml_node, XML_ATTR_MSGTYPE);
		if (root_xml_node == NULL) {
			cl_log(LOG_ERR, "Root node was NULL!!");

		} else if(sys_to == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_SYSTO);
			
		} else if(type == NULL) {
			cl_log(LOG_ERR, "Value of %s was NULL!!",
			       XML_ATTR_MSGTYPE);
			
		} else if(strcmp(type, XML_ATTR_REQUEST) != 0) {
			cl_log(LOG_INFO,
			       "Message was a response not a request."
			       "  Discarding");
		} else if (strcmp(sys_to, CRM_SYSTEM_CIB) == 0
			|| strcmp(sys_to, CRM_SYSTEM_DCIB) == 0) {

			answer = process_cib_message(root_xml_node, TRUE);
			if (send_xmlipc_message(sender, answer)==FALSE)
				cl_log(LOG_WARNING,
				       "Cib answer could not be sent");
		} else {
			cl_log(LOG_WARNING,
			       "Received a message destined for %s by mistake",
			       sys_to);
		}
		
		if(answer != NULL)
			free_xml(answer);
		
		msg->msg_done(msg);
		msg = NULL;
	}

	// clean up after a break
	if(msg != NULL)
		msg->msg_done(msg);

	if(root_xml_node != NULL)
		free_xml(root_xml_node);

	CRM_DEBUG2("Processed %d messages", lpc);
	if (sender->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "The server has left us: Shutting down...NOW");

		exit(1); // shutdown properly later
		
		FNRET(!all_is_well);
	}
	FNRET(all_is_well);
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
	} else {
		exit(LSB_EXIT_OK);
	}
}

/* $Id: main.c,v 1.18 2005/05/20 09:58:43 andrew Exp $ */
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

#include <crm/crm.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <clplumbing/uids.h>
#include <clplumbing/coredumps.h>

#include <crm/common/ipc.h>
#include <crm/common/ctrl.h>

#include <crm/dmalloc_wrapper.h>

#define SYS_NAME CRM_SYSTEM_PENGINE
#define OPTARGS	"hVc"


GMainLoop*  mainloop = NULL;
const char* crm_system_name = SYS_NAME;

void usage(const char* cmd, int exit_status);
int init_start(void);
gboolean pengine_shutdown(int nsig, gpointer unused);
extern gboolean process_pe_message(crm_data_t * msg, IPC_Channel *sender);

int
main(int argc, char ** argv)
{
	gboolean allow_cores = TRUE;
	int	argerr = 0;
	int flag;
    
	crm_log_init(crm_system_name);
	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, pengine_shutdown, NULL, NULL);

	while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
		switch(flag) {
			case 'V':
				alter_debug(DEBUG_INC);
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
    
	if (optind > argc) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name,LSB_EXIT_GENERIC);
	}
    
	/* read local config file */
	crm_debug_4("do start");
	return init_start();
}


int
init_start(void)
{
	IPC_Channel *crm_ch = NULL;

	crm_debug_4("initialize comms");
	init_client_ipc_comms(
		CRM_SYSTEM_CRMD, subsystem_msg_dispatch,
		(void*)process_pe_message, &crm_ch);

	if(crm_ch != NULL) {
		crm_debug_4("sending hello message");
		send_hello_message(
			crm_ch, "1234", CRM_SYSTEM_PENGINE, "0", "1");

		/* Create the mainloop and run it... */
		crm_info("Starting %s", crm_system_name);

		mainloop = g_main_new(FALSE);
		g_main_run(mainloop);
		return_to_orig_privs();

		crm_info("Exiting %s", crm_system_name);
		return 0;
	}

	crm_err("Could not connect to the CRMd");
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

gboolean
pengine_shutdown(int nsig, gpointer unused)
{
#if 0
	static int shuttingdown = 0;
  
	if (!shuttingdown) {
		shuttingdown = 1;
	}
	if (mainloop != NULL && g_main_is_running(mainloop)) {
		g_main_quit(mainloop);
	}else{
		exit(LSB_EXIT_OK);
	}
	return TRUE;
#else
	return FALSE;
#endif
}


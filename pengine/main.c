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

#include <crm_internal.h>

#include <crm/crm.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <hb_api.h>
#include <heartbeat.h>
#include <clplumbing/uids.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/cl_misc.h>

#include <crm/common/ipc.h>
#include <crm/common/ctrl.h>
#include <crm/pengine/common.h>

#if HAVE_LIBXML2
#  include <libxml/parser.h>
#endif

#define OPTARGS	"hVc"

GMainLoop*  mainloop = NULL;

void usage(const char* cmd, int exit_status);
int pe_init(void);
gboolean pengine_shutdown(int nsig, gpointer unused);
extern gboolean process_pe_message(crm_data_t * msg, IPC_Channel *sender);
extern unsigned int pengine_input_loglevel;

int
main(int argc, char ** argv)
{
	int flag;
	int argerr = 0;
	char *param_val = NULL;
	gboolean allow_cores = TRUE;
	const char *param_name = NULL;
    
	crm_log_init(CRM_SYSTEM_PENGINE, LOG_INFO, TRUE, FALSE, 0, NULL);
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

	if(argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
		pe_metadata();
		return 0;
	}
	
	if (optind > argc) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name,LSB_EXIT_GENERIC);
	}

	param_name = ENV_PREFIX "" KEY_LOG_PENGINE_INPUTS;
	param_val = getenv(param_name);
	crm_debug("%s = %s", param_name, param_val);
	pengine_input_loglevel = crm_log_level;
	if(param_val != NULL) {
		int do_log = 0;
		cl_str_to_boolean(param_val, &do_log);
		if(do_log == FALSE) {
			pengine_input_loglevel = crm_log_level + 1;
		}
		param_val = NULL;
	}
	
	/* read local config file */
	crm_debug_4("do start");
	return pe_init();
}


int
pe_init(void)
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

#if HAVE_LIBXML2
		xmlCleanupParser();
#endif
		
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
	crm_info("Exiting PEngine (SIGTERM)");
	exit(LSB_EXIT_OK);
}


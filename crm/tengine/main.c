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

#include <hb_config.h>

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


#define SYS_NAME     CRM_SYSTEM_TENGINE
#define OPTARGS      "hVc"

GMainLoop*  mainloop = NULL;
const char* crm_system_name = SYS_NAME;
cib_t *te_cib_conn = NULL;

void usage(const char* cmd, int exit_status);
int te_init(void);
gboolean tengine_shutdown(int nsig, gpointer unused);
extern void te_update_confirm(const char *event, HA_Message *msg);
extern void te_update_diff(const char *event, HA_Message *msg);
extern crm_graph_functions_t te_graph_fns;

int
main(int argc, char ** argv)
{
	int flag;
	int rc = 0;
	int dummy = 0;
	int argerr = 0;
	gboolean allow_cores = TRUE;
	
	crm_log_init(crm_system_name, LOG_INFO, TRUE, FALSE, 0, NULL);
	G_main_add_SignalHandler(
		G_PRIORITY_HIGH, SIGTERM, tengine_shutdown, NULL, NULL);

	transition_trigger = G_main_add_TriggerHandler(
		G_PRIORITY_LOW, te_graph_trigger, NULL, NULL);

	stonith_reconnect = G_main_add_TriggerHandler(
		G_PRIORITY_LOW, te_connect_stonith, &dummy, NULL);
	
	crm_debug_3("Begining option processing");

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
    
	crm_debug_3("Option processing complete");

	if (optind > argc) {
		++argerr;
	}
    
	if (argerr) {
		usage(crm_system_name,LSB_EXIT_GENERIC);
	}
    
	/* read local config file */    
	crm_debug_3("Starting...");
	rc = te_init();
	return rc;
}

int
te_init(void)
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
		crm_debug_4("Creating CIB connection");
		te_cib_conn = cib_new();
		if(te_cib_conn == NULL) {
			init_ok = FALSE;
		}
	}
	
	if(init_ok) {
		crm_debug_4("Connecting to the CIB");
		if(cib_ok != te_cib_conn->cmds->signon(
			   te_cib_conn, crm_system_name, cib_command)) {
			crm_err("Could not connect to the CIB");
			init_ok = FALSE;
		}
	}

	if(init_ok) {
		crm_debug_4("Setting CIB notification callback");
		if(cib_ok != te_cib_conn->cmds->add_notify_callback(
			   te_cib_conn, T_CIB_DIFF_NOTIFY, te_update_diff)) {
			crm_err("Could not set CIB notification callback");
			init_ok = FALSE;
		}
	}

	if(init_ok) {
	    G_main_set_trigger(stonith_reconnect);
	}

	if(init_ok) {
                cl_uuid_t new_uuid;
                char uuid_str[UU_UNPARSE_SIZEOF];
                
                cl_uuid_generate(&new_uuid);
                cl_uuid_unparse(&new_uuid, uuid_str);
                te_uuid = crm_strdup(uuid_str);
                crm_info("Registering TE UUID: %s", te_uuid);
		set_graph_functions(&te_graph_fns);

		/* create a blank one */
		transition_graph = unpack_graph(NULL);
		transition_graph->complete = TRUE;
		transition_graph->abort_reason = "DC Takeover";
		transition_graph->completion_action = tg_restart;

		crm_malloc0(transition_timer, sizeof(crm_action_timer_t));
		transition_timer->source_id = 0;
		transition_timer->reason    = timeout_abort;
		transition_timer->action    = NULL;
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

	destroy_graph(transition_graph);
	crm_free(transition_timer);
	
	te_cib_conn->cmds->signoff(te_cib_conn);
	cib_delete(te_cib_conn);
	te_cib_conn = NULL;

	stonithd_signoff();
	
	crm_free(te_uuid);
	
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

gboolean shuttingdown;
gboolean
tengine_shutdown(int nsig, gpointer unused)
{  
	shuttingdown = TRUE;
	abort_transition(INFINITY, tg_shutdown, "Shutdown", NULL);
	return TRUE;
}

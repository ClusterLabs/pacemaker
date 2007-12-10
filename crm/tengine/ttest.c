
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

#include <sys/param.h>
#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#define OPTARGS	"V?X:"

#include <glib.h>
#include <tengine.h>
#include <clplumbing/GSource.h>

GMainLoop*  mainloop = NULL;
crm_graph_t *transition_graph = NULL;
cib_t *te_cib_conn = NULL;

static gboolean
ttest_pseudo_command(crm_graph_t *graph, crm_action_t *pseudo) 
{
	crm_debug("Event handler: action %d executed", pseudo->id);
	pseudo->confirmed = TRUE;
	update_graph(graph, pseudo);
	trigger_graph();
	return TRUE;
}

static gboolean
ttest_rsc_command(crm_graph_t *graph, crm_action_t *pseudo)
{
/* 	send_rsc_command(action); */
	return TRUE;
}

crm_graph_functions_t ttest_graph_fns = {
	ttest_pseudo_command,
	ttest_rsc_command,
	ttest_pseudo_command,
	ttest_pseudo_command,
};

int
main(int argc, char **argv)
{
	int flag;
	int argerr = 0;
	const char *xml_file = NULL;
	crm_data_t *xml_graph = NULL;
  
	set_crm_log_level(0);
/* 	crm_log_init("ttest"); */
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);

	/* and for good measure... - this enum is a bit field (!) */
	g_log_set_always_fatal((GLogLevelFlags)0); /*value out of range*/
	set_crm_log_level(LOG_WARNING);

	transition_trigger = G_main_add_TriggerHandler(
		G_PRIORITY_LOW, te_graph_trigger, NULL, NULL);

	set_graph_functions(&ttest_graph_fns);

	while (1) {
		flag = getopt(argc, argv, OPTARGS);
		if (flag == -1)
			break;
    
		switch(flag) {
			case 'X':
				xml_file = crm_strdup(optarg);
				break;

			case 'V':
				cl_log_enable_stderr(TRUE);
				alter_debug(DEBUG_INC);
				break;
			default:
				printf("?? getopt returned character code 0%o ??\n", flag);
				++argerr;
				break;
		}
	}
  
	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
	}
  
	if (optind > argc) {
		++argerr;
	}
  
	if (argerr) {
		crm_err("%d errors in option parsing", argerr);
	}
  
	crm_debug("=#=#=#=#= Getting XML =#=#=#=#=");
	if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		if(xml_strm) {
			xml_graph = file2xml(xml_strm, FALSE);
			fclose(xml_strm);
			
		} else {
			cl_perror("Could not open %s for reading", xml_file);
			xml_file = NULL;
		}
		
	}
	if(xml_file == NULL) {
		xml_graph = stdin2xml();
	}

#ifdef MTRACE  
	mtrace();
#endif

	transition_graph = unpack_graph(xml_graph);
	trigger_graph();
	print_graph(LOG_DEBUG, transition_graph);
	transition_graph->completion_action = tg_shutdown;

	mainloop = g_main_new(FALSE);
	
	g_main_run(mainloop);
	
	crm_info("Exiting ttest");
	
#ifdef MTRACE  
	muntrace();
#endif
	crm_debug_4("Transition complete...");

	return 0;
}


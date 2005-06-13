/* $Id: ttest.c,v 1.20 2005/06/13 13:32:09 andrew Exp $ */

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

extern gboolean unpack_graph(crm_data_t *xml_graph);
extern gboolean initiate_transition(void);
extern gboolean initialize_graph(void);

GMainLoop*  mainloop = NULL;

int
main(int argc, char **argv)
{
	int flag;
	int argerr = 0;
	crm_data_t *xml_graph = NULL;
	HA_Message *cmd = NULL;
	
	const char *xml_file = NULL;
	
	IPC_Channel* channels[2];
  
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
  
	crm_debug_4("Initializing graph...");
	initialize_graph();
	
	crm_debug("=#=#=#=#= Getting XML =#=#=#=#=");
	if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		if(xml_strm) {
			xml_graph = file2xml(xml_strm);
		} else {
			crm_err("Could not open %s for reading", xml_file);
			xml_file = NULL;
		}
		
	}
	if(xml_file == NULL) {
		xml_graph = stdin2xml();
	}
  
#ifdef MTRACE  
	mtrace();
#endif
	if (ipc_channel_pair(channels) != IPC_OK) {
		cl_perror("Can't create ipc channel pair");
		exit(1);
	}
	crm_ch = channels[0];

/* 	fcntl(channels[0]->ops->get_send_select_fd(channels[0]), F_SETFL, O_NONBLOCK); */
/* 	fcntl(channels[0]->ops->get_recv_select_fd(channels[0]), F_SETFL, O_NONBLOCK); */
/* 	fcntl(channels[1]->ops->get_send_select_fd(channels[0]), F_SETFL, O_NONBLOCK); */
/* 	fcntl(channels[1]->ops->get_recv_select_fd(channels[0]), F_SETFL, O_NONBLOCK); */
	
	G_main_add_IPC_Channel(G_PRIORITY_HIGH,
			       channels[1], FALSE,
			       subsystem_msg_dispatch,
			       (void*)process_te_message, 
			       default_ipc_connection_destroy);

	/* send transition graph over IPC instead */
	cmd = create_request(CRM_OP_TRANSITION, xml_graph, NULL,
			     CRM_SYSTEM_TENGINE, CRM_SYSTEM_TENGINE, NULL);


	
	send_ipc_message(channels[0], cmd);
	free_xml(xml_graph);

    /* Create the mainloop and run it... */
	mainloop = g_main_new(FALSE);
	crm_debug("Starting mainloop");
	g_main_run(mainloop);

	initialize_graph();
	
#ifdef MTRACE  
	muntrace();
#endif
	crm_debug_4("Transition complete...");

	return 0;
}


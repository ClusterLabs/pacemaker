/* $Id: ttest.c,v 1.14 2004/11/12 17:12:51 andrew Exp $ */

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

#include <getopt.h>
#include <glib.h>
#include <tengine.h>
#include <clplumbing/GSource.h>

extern gboolean unpack_graph(xmlNodePtr xml_graph);
extern gboolean initiate_transition(void);
extern gboolean initialize_graph(void);

GMainLoop*  mainloop = NULL;

int
main(int argc, char **argv)
{
	int flag;
	int argerr = 0;
	xmlNodePtr xml_graph = NULL;
	xmlNodePtr options = NULL;
	
	const char *xml_file = NULL;
	
	IPC_Channel* channels[2];
  
	cl_log_set_entity("ttest");
	cl_log_set_facility(LOG_USER);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{"daemon", 0, 0, 0},
      
			{0, 0, 0, 0}
		};
    
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
		if (flag == -1)
			break;
    
		switch(flag) {
			case 0:
				printf("option %s", long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
    
				break;
      
				/* a sample test for multiple instance
				   if (digit_optind != 0 && digit_optind != this_option_optind)
				   printf ("digits occur in two different argv-elements.\n");
				   digit_optind = this_option_optind;
				   printf ("option %c\n", c);
				*/
      
			case 'X':
				xml_file = crm_strdup(optarg);
				break;

			case 'V':
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
  
	crm_trace("Initializing graph...");
	initialize_graph();
	
	crm_debug("=#=#=#=#= Getting XML =#=#=#=#=");
	if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		xml_graph = file2xml(xml_strm);
		
	} else {
		xml_graph = file2xml(stdin);
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
	
	G_main_add_IPC_Channel(G_PRIORITY_LOW,
			       channels[1], FALSE,
			       subsystem_msg_dispatch,
			       (void*)process_te_message, 
			       default_ipc_connection_destroy);

	/* send transition graph over IPC instead */
	options = create_xml_node(NULL, XML_TAG_OPTIONS);
	set_xml_property_copy(options, XML_ATTR_OP, CRM_OP_TRANSITION);
	send_ipc_request(channels[0], options, xml_graph,
			 NULL, CRM_SYSTEM_TENGINE, CRM_SYSTEM_TENGINE,
			 NULL, NULL);
	
	free_xml(options);
	free_xml(xml_graph);

    /* Create the mainloop and run it... */
	mainloop = g_main_new(FALSE);
	crm_debug("Starting mainloop");
	g_main_run(mainloop);

	initialize_graph();
	
#ifdef MTRACE  
	muntrace();
#endif
	crm_trace("Transition complete...");

	return 0;
}


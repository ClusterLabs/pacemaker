/* $Id: ttest.c,v 1.2 2004/05/23 19:54:04 andrew Exp $ */

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

#include <crm/common/xmlutils.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#define OPTARGS	"V?i:o:D:C:S:HA:U:M:I:EWRFt:m:a:d:w:c:r:p:s:"

#include <getopt.h>
#include <glib.h>
#include <tengine.h>

extern gboolean unpack_graph(xmlNodePtr xml_graph);
extern gboolean initiate_transition(void);
extern gboolean initialize_graph(void);

int
main(int argc, char **argv)
{
	int argerr = 0;
	int flag;
  
	cl_log_set_entity("ttest");
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			// Top-level Options
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
      
			case 'V':
				printf("option %d", flag);
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
		cl_log(LOG_ERR, "%d errors in option parsing", argerr);
	}
  
	cl_log(LOG_INFO, "=#=#=#=#= Getting XML =#=#=#=#=");
  
  
	mtrace();

	CRM_DEBUG("Initializing graph...");
	initialize_graph();
	
	xmlNodePtr xml_graph = file2xml(stdin);

	CRM_DEBUG("Unpacking graph...");
	unpack_graph(xml_graph);
	CRM_DEBUG("Initiating transition...");

	if(initiate_transition() == FALSE) {
		// nothing to be done.. means we're done.
		cl_log(LOG_INFO, "No actions to be taken..."
		       " transition compelte.");
	}

	initialize_graph();
	free_xml(xml_graph);
	muntrace();

	CRM_DEBUG("Transition complete...");

	return 0;
}

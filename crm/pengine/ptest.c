/* $Id: ptest.c,v 1.51 2005/05/20 14:58:09 andrew Exp $ */

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

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>

#include <crm/cib.h>

#define OPTARGS	"V?X:w"

#include <getopt.h>
#include <glib.h>
#include <pengine.h>
#include <pe_utils.h>

gboolean inhibit_exit = FALSE;
extern crm_data_t * do_calculations(crm_data_t *cib_object);
extern cl_mem_stats_t *mem_stats;

int
main(int argc, char **argv)
{
	crm_data_t * cib_object = NULL;
	int argerr = 0;
	int flag;
		
	crm_data_t * graph = NULL;
	char *msg_buffer = NULL;

	const char *xml_file = NULL;
	
	cl_log_set_entity("ptest");
	cl_log_set_facility(LOG_USER);
	set_crm_log_level(LOG_WARNING);
	
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{F_CRM_DATA,  1, 0, 'X'},
			{"help", 0, 0, 0},
      
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
      
			case 'w':
				inhibit_exit = TRUE;
				break;
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
		while (optind < argc) {
			printf("%s ", argv[optind++]);
		}
		printf("\n");
	}
  
	if (optind > argc) {
		++argerr;
	}
  
	if (argerr) {
		crm_err("%d errors in option parsing", argerr);
	}
  
	crm_info("=#=#=#=#= Getting XML =#=#=#=#=");
  
	
	if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		cib_object = file2xml(xml_strm);
	} else {
		cib_object = stdin2xml();
	}

#ifdef MCHECK
	mtrace();
#endif
	crm_malloc0(mem_stats, sizeof(cl_mem_stats_t));
	crm_zero_mem_stats(mem_stats);

	graph = do_calculations(cib_object);

	msg_buffer = dump_xml_formatted(graph);
	fprintf(stdout, "%s\n", msg_buffer);
	fflush(stdout);
	crm_free(msg_buffer);
	
	free_xml(graph);

	crm_mem_stats(mem_stats);
	cl_malloc_setstats(NULL);
	crm_free(mem_stats);

#ifdef MCHECK
	muntrace();
#endif
	
	free_xml(cib_object);

	/* required for MallocDebug.app */
	if(inhibit_exit) {
		GMainLoop*  mainloop = g_main_new(FALSE);
		g_main_run(mainloop);		
	}
	
	return 0;
}

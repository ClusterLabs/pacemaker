/* $Id: crm_verify.c,v 1.1 2005/10/14 06:24:03 andrew Exp $ */

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
#include <libgen.h>

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/msg_xml.h>
#include <clplumbing/cl_signal.h>

#include <crm/cib.h>

#define OPTARGS	"V?X:wD:"

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif
#include <glib.h>
#include <crm/pengine/pengine.h>
#include <crm/pengine/pe_utils.h>

extern crm_data_t * do_calculations(
	pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now);
extern void cleanup_calculations(pe_working_set_t *data_set);

int
main(int argc, char **argv)
{
	crm_data_t * cib_object = NULL;
	int argerr = 0;
	int flag;
		
	pe_working_set_t data_set;
	
	const char *xml_file = NULL;
	
	g_log_set_handler(NULL,
			  G_LOG_LEVEL_ERROR      | G_LOG_LEVEL_CRITICAL
			  | G_LOG_LEVEL_WARNING  | G_LOG_LEVEL_MESSAGE
			  | G_LOG_LEVEL_INFO     | G_LOG_LEVEL_DEBUG
			  | G_LOG_FLAG_RECURSION | G_LOG_FLAG_FATAL,
			  cl_glib_msg_handler, NULL);

	/* and for good measure... - this enum is a bit field (!) */
	g_log_set_always_fatal((GLogLevelFlags)0); /*value out of range*/
	
	cl_log_set_entity(basename(argv[0]));
	cl_log_set_facility(LOG_LOCAL7);
	cl_log_enable_stderr(TRUE);
	set_crm_log_level(LOG_ERR);
	
	CL_SIGNAL(DEBUG_INC, alter_debug);
	CL_SIGNAL(DEBUG_DEC, alter_debug);
	
	while (1) {
#ifdef HAVE_GETOPT_H
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
			{F_CRM_DATA,  1, 0, 'X'},
			{"help", 0, 0, 0},
      
			{0, 0, 0, 0}
		};
#endif
    
#ifdef HAVE_GETOPT_H
		flag = getopt_long(argc, argv, OPTARGS,
				   long_options, &option_index);
#else
		flag = getopt(argc, argv, OPTARGS);
#endif
		if (flag == -1)
			break;
    
		switch(flag) {
#ifdef HAVE_GETOPT_H
			case 0:
				printf("option %s", long_options[option_index].name);
				if (optarg)
					printf(" with arg %s", optarg);
				printf("\n");
    
				break;
#endif
      
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
  
	
	crm_zero_mem_stats(NULL);

	if(xml_file != NULL) {
		FILE *xml_strm = fopen(xml_file, "r");
		crm_info("Reading %s", xml_file);
		cib_object = file2xml(xml_strm);
	} else {
		cib_object = stdin2xml();
	}

 	CRM_DEV_ASSERT(cib_object != NULL);
#if 0
	status = get_object_root(XML_CIB_TAG_STATUS, cib_object);
	xml_child_iter(status, node_state, XML_CIB_TAG_STATE,
		       xml_remove_prop(node_state, XML_CIB_TAG_LRM);
		);
#endif	
	crm_notice("Required feature set: %s", feature_set(cib_object));
 	do_id_check(cib_object, NULL);
	
	do_calculations(&data_set, cib_object, NULL);
	cleanup_calculations(&data_set);

	free_xml(cib_object);

	crm_mem_stats(NULL);
 	CRM_DEV_ASSERT(crm_mem_stats(NULL) == FALSE);

	if(was_processing_error) {
		fprintf(stderr, "Errors found during procesing: config not valid");
		
		return 2;
	} else if(was_processing_warning) {
		fprintf(stderr, "Wanrings found during procesing: config may not be valid");
		return 1;
	}

	return 0;
}

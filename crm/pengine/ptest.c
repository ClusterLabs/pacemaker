/* $Id: ptest.c,v 1.45 2005/04/11 15:32:35 andrew Exp $ */

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

#define OPTARGS	"V?X:"

#include <getopt.h>
#include <glib.h>
#include <pengine.h>
#include <pe_utils.h>


int
main(int argc, char **argv)
{
	crm_data_t * cib_object = NULL;
	int argerr = 0;
	int flag;
		
	GListPtr resources = NULL;
	GListPtr nodes = NULL;
	GListPtr placement_constraints = NULL;
	GListPtr actions = NULL;
	GListPtr ordering_constraints = NULL;
	GListPtr stonith_list = NULL;
	GListPtr shutdown_list = NULL;
	GListPtr colors = NULL;
	GListPtr action_sets = NULL;
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
	crm_debug("=#=#=#=#= Stage 0 =#=#=#=#=");

#ifdef MCHECK
	mtrace();
#endif

	stage0(cib_object,
	       &resources,
	       &nodes,  &placement_constraints,
	       &actions,  &ordering_constraints,
	       &stonith_list, &shutdown_list);
	
	crm_debug("========= Nodes =========");
	slist_iter(node, node_t, nodes, lpc,
		   print_node(NULL, node, TRUE));

	crm_debug("========= Resources =========");
	slist_iter(resource, resource_t, resources, lpc,
		   print_resource(NULL, resource, TRUE));    

	crm_debug("========= Constraints =========");
	slist_iter(constraint, rsc_to_node_t, placement_constraints, lpc,
		   print_rsc_to_node(NULL, constraint, FALSE));
    
	crm_debug("=#=#=#=#= Stage 1 =#=#=#=#=");
	stage1(placement_constraints, nodes, resources);

	crm_debug("========= Nodes =========");
	slist_iter(node, node_t, nodes, lpc,
		   print_node(NULL, node, TRUE));

	crm_debug("========= Resources =========");
	slist_iter(resource, resource_t, resources, lpc,
		   print_resource(NULL, resource, TRUE));

	crm_debug("=#=#=#=#= Stage 2 =#=#=#=#=");
	stage2(resources, nodes, &colors);

	crm_debug("========= Nodes =========");
	slist_iter(node, node_t, nodes, lpc,
		   print_node(NULL, node, TRUE));

	crm_debug("========= Resources =========");
	slist_iter(resource, resource_t, resources, lpc,
		   print_resource(NULL, resource, TRUE));  
  
	crm_debug("========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));
  
	crm_debug("========= Action List =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action(NULL, action, FALSE));

	crm_debug("=#=#=#=#= Stage 3 =#=#=#=#=");
	stage3(colors);
	crm_debug("========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));

	crm_debug("========= Action List =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action(NULL, action, TRUE));

	crm_debug("=#=#=#=#= Stage 4 =#=#=#=#=");
	stage4(colors);
	crm_debug("========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));

	crm_debug("=#=#=#=#= Summary =#=#=#=#=");
	crm_debug("========= Action List =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action(NULL, action, TRUE));
	
	crm_debug("=#=#=#=#= Stage 5 =#=#=#=#=");
	stage5(resources, &ordering_constraints);

	crm_debug("========= All Actions =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action("\t", action, TRUE);
		);

	crm_debug("=#=#=#=#= Stage 6 =#=#=#=#=");
	stage6(&actions, &ordering_constraints, nodes, resources);

	crm_debug("========= Action List =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action(NULL, action, TRUE));
	
	crm_debug("=#=#=#=#= Stage 7 =#=#=#=#=");
	stage7(resources, actions, ordering_constraints);

	crm_debug("=#=#=#=#= Summary =#=#=#=#=");
	crm_debug("========= All Actions =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action("\t", action, TRUE);
		);

	crm_debug("========= Stonith List =========");
	slist_iter(node, node_t, stonith_list, lpc,
		   print_node(NULL, node, FALSE));
  
	crm_debug("========= Shutdown List =========");
	slist_iter(node, node_t, shutdown_list, lpc,
		   print_node(NULL, node, FALSE));

	crm_debug("=#=#=#=#= Stage 8 =#=#=#=#=");
	stage8(resources, actions, &graph);


	crm_verbose("deleting node cons");
	while(placement_constraints) {
		pe_free_rsc_to_node((rsc_to_node_t*)placement_constraints->data);
		placement_constraints = placement_constraints->next;
	}
	if(placement_constraints != NULL) {
		g_list_free(placement_constraints);
	}
	
	crm_verbose("deleting order cons");
	pe_free_shallow(ordering_constraints);

	crm_verbose("deleting action sets");
	slist_iter(action_set, GList, action_sets, lpc,
		   pe_free_shallow_adv(action_set, FALSE);
		);
	pe_free_shallow_adv(action_sets, FALSE);
	
	crm_verbose("deleting actions");
	pe_free_actions(actions);

/*	GListPtr action_sets = NULL; */

	crm_verbose("deleting resources");
	pe_free_resources(resources); 
	
	crm_verbose("deleting colors");
	pe_free_colors(colors);

	crm_free(no_color->details);
	crm_free(no_color);
	
	crm_verbose("deleting nodes");
	pe_free_nodes(nodes);
	
	if(shutdown_list != NULL) {
		g_list_free(shutdown_list);
	}
	if(stonith_list != NULL) {
		g_list_free(stonith_list);
	}

#ifdef MCHECK
	muntrace();
#endif

	msg_buffer = dump_xml_formatted(graph);
	fprintf(stdout, "%s\n", msg_buffer);
	fflush(stdout);
	crm_free(msg_buffer);

	free_xml(graph);
	free_xml(cib_object);

	return 0;
}

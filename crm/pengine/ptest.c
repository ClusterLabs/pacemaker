/* $Id: ptest.c,v 1.34 2004/09/17 13:03:10 andrew Exp $ */

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

#define OPTARGS	"V?i:o:D:C:S:HA:U:M:I:EWRFt:m:a:d:w:c:r:p:s:"

#include <getopt.h>
#include <glib.h>
#include <pengine.h>
#include <pe_utils.h>


int
main(int argc, char **argv)
{
	xmlNodePtr cib_object = NULL;
	int lpc = 0;
	int argerr = 0;
	int flag;
		
	GListPtr resources = NULL;
	GListPtr nodes = NULL;
	GListPtr node_constraints = NULL;
	GListPtr actions = NULL;
	GListPtr action_constraints = NULL;
	GListPtr stonith_list = NULL;
	GListPtr shutdown_list = NULL;
	GListPtr colors = NULL;
	GListPtr action_sets = NULL;
	xmlNodePtr graph = NULL;
	char *msg_buffer = NULL;

	cl_log_set_entity("ptest");
	cl_log_set_facility(LOG_USER);
	
	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			/* Top-level Options */
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
  
	crm_info("=#=#=#=#= Getting XML =#=#=#=#=");
  
	cib_object = file2xml(stdin);
  
	crm_info("=#=#=#=#= Stage 0 =#=#=#=#=");


#ifdef MCHECK
	mtrace();
#endif

	stage0(cib_object,
	       &resources,
	       &nodes,  &node_constraints,
	       &actions,  &action_constraints,
	       &stonith_list, &shutdown_list);
	
	crm_debug("========= Nodes =========");
	slist_iter(node, node_t, nodes, lpc,
		   print_node(NULL, node, TRUE));

	crm_debug("========= Resources =========");
	slist_iter(resource, resource_t, resources, lpc,
		   print_resource(NULL, resource, TRUE));    

	crm_debug("========= Constraints =========");
	slist_iter(constraint, rsc_to_node_t, node_constraints, lpc,
		   print_rsc_to_node(NULL, constraint, FALSE));
    
	crm_debug("=#=#=#=#= Stage 1 =#=#=#=#=");
	stage1(node_constraints, nodes, resources);

	crm_debug("========= Nodes =========");
	slist_iter(node, node_t, nodes, lpc,
		   print_node(NULL, node, TRUE));

	crm_debug("========= Resources =========");
	slist_iter(resource, resource_t, resources, lpc,
		   print_resource(NULL, resource, TRUE));

	crm_debug("=#=#=#=#= Stage 2 =#=#=#=#=");
/*	pe_debug_on(); */
	stage2(resources, nodes, &colors);
/*	pe_debug_off(); */

	crm_debug("========= Nodes =========");
	slist_iter(node, node_t, nodes, lpc,
		   print_node(NULL, node, TRUE));

	crm_debug("========= Resources =========");
	slist_iter(resource, resource_t, resources, lpc,
		   print_resource(NULL, resource, TRUE));  
  
	crm_debug("========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));
  
	crm_debug("=#=#=#=#= Stage 3 =#=#=#=#=");
	stage3(colors);
	crm_debug("========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));

	crm_debug("=#=#=#=#= Stage 4 =#=#=#=#=");
	stage4(colors);
	crm_debug("========= Colors =========");
	slist_iter(color, color_t, colors, lpc,
		   print_color(NULL, color, FALSE));

	crm_debug("=#=#=#=#= Summary =#=#=#=#=");
	summary(resources);
	crm_debug("========= Action List =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action(NULL, action, FALSE));
	
	crm_debug("=#=#=#=#= Stage 5 =#=#=#=#=");
	stage5(resources);

	crm_debug("=#=#=#=#= Stage 6 =#=#=#=#=");
	stage6(&actions, &action_constraints, nodes, resources);

	crm_debug("========= Action List =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action(NULL, action, TRUE));
	
	crm_debug("=#=#=#=#= Stage 7 =#=#=#=#=");
	stage7(resources, actions, action_constraints, &action_sets);

	crm_debug("=#=#=#=#= Summary =#=#=#=#=");
	summary(resources);

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
	stage8(actions, &graph);


	crm_verbose("deleting node cons");
	while(node_constraints) {
		pe_free_rsc_to_node((rsc_to_node_t*)node_constraints->data);
		node_constraints = node_constraints->next;
	}
	if(node_constraints != NULL) {
		g_list_free(node_constraints);
	}
	
	crm_verbose("deleting order cons");
	pe_free_shallow(action_constraints);

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
	
	g_list_free(shutdown_list);
	g_list_free(stonith_list);

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

/* $Id: pengine.c,v 1.72 2005/05/24 12:54:39 andrew Exp $ */
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
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>

#include <pengine.h>
#include <pe_utils.h>

extern GListPtr global_action_list;

crm_data_t * do_calculations(crm_data_t *cib_object);
void cleanup_calculations(
	GListPtr resources, GListPtr nodes, GListPtr placement_constraints,
	GListPtr actions, GListPtr ordering_constraints, GListPtr stonith_list,
	GListPtr shutdown_list, GListPtr colors, GListPtr action_sets);

int num_synapse = 0;
gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;
cl_mem_stats_t *mem_stats = NULL;

gboolean
process_pe_message(HA_Message *msg, crm_data_t * xml_data, IPC_Channel *sender)
{
	const char *sys_to = cl_get_string(msg, F_CRM_SYS_TO);
	const char *op = cl_get_string(msg, F_CRM_TASK);
	const char *ref = cl_get_string(msg, XML_ATTR_REFERENCE);

	crm_debug_3("Processing %s op (ref=%s)...", op, ref);
	
	if(op == NULL){
		/* error */

	} else if(strcmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */
		
	} else if(safe_str_eq(cl_get_string(msg, F_CRM_MSG_TYPE),
			      XML_ATTR_RESPONSE)) {
		/* ignore */
		
	} else if(sys_to == NULL || strcmp(sys_to, CRM_SYSTEM_PENGINE) != 0) {
		crm_debug_3("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
	} else if(strcmp(op, CRM_OP_PECALC) == 0) {
		crm_data_t *generation = create_xml_node(NULL, XML_TAG_CIB);
		crm_data_t *status     = get_object_root(
			XML_CIB_TAG_STATUS, xml_data);
		crm_data_t *log_input  = status;
		crm_data_t *output     = NULL;
		log_input  = xml_data;


		copy_in_properties(generation, xml_data);
		crm_log_xml_info(generation, "[generation]");

#if 0
		char *xml_buffer = NULL;
		char *xml_buffer_ptr = NULL;
		int max_xml = MAXLINE - 8;
		
		xml_buffer = dump_xml_unformatted(generation);
		LogToCircularBuffer(input_buffer, LOG_INFO,
				    "Generation: %s", xml_buffer);
		crm_free(xml_buffer);

		xml_buffer = dump_xml_unformatted(status);
		xml_buffer_ptr = xml_buffer;

		while(xml_buffer_ptr != NULL) {
			LogToCircularBuffer(input_buffer, LOG_INFO,
					    "PE xml: %s", xml_buffer_ptr);
			if(strlen(xml_buffer_ptr) > max_xml) {
				xml_buffer_ptr = xml_buffer_ptr + max_xml;
			} else {
				xml_buffer_ptr = NULL;;
			}
		}
		crm_free(xml_buffer);
#endif
		was_processing_error = FALSE;
		was_processing_warning = FALSE;

		crm_malloc0(mem_stats, sizeof(cl_mem_stats_t));
		crm_zero_mem_stats(mem_stats);

		output = do_calculations(xml_data);
		crm_log_xml_debug_3(output, "[out]");

		if (send_ipc_reply(sender, msg, output) ==FALSE) {
			crm_err("Answer could not be sent");
		}

		free_xml(output);
		
		if(mem_stats->nbytes_alloc != 0) {
			crm_mem_stats(mem_stats);
			pe_warn("Unfree'd memory");
		}
		cl_malloc_setstats(NULL);
		crm_free(mem_stats);
	
		if(was_processing_error) {
			crm_info("ERRORs found during PE processing."
			       "  Input follows:");
			crm_log_xml_info(log_input, "[input]");

		} else if(was_processing_warning) {
			crm_debug_2("WARNINGs found during PE processing."
				"  Input follows:");
			crm_log_xml_debug(log_input, "[input]");

		} else {
			crm_log_xml_debug_2(log_input, "[input]");
		}

		free_xml(generation);

		
	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_warn("Received quit message, terminating");
		exit(0);
	}
	
	return TRUE;
}

#define MEMCHECK_STAGE_5 0

crm_data_t *
do_calculations(crm_data_t * cib_object)
{
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

/*	pe_debug_on(); */
	
	crm_debug_5("unpack");		  
	stage0(cib_object,
	       &resources,
	       &nodes,  &placement_constraints,
	       &actions,  &ordering_constraints,
	       &stonith_list, &shutdown_list);
	
#if MEMCHECK_STAGE_0
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	crm_debug_5("apply placement constraints");
	stage1(placement_constraints, nodes, resources);
	
#if MEMCHECK_STAGE_1
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	crm_debug_5("color resources");
	stage2(resources, nodes, &colors);

#if MEMCHECK_STAGE_2
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	/* unused */
	stage3(colors);
	
	crm_debug_5("assign nodes to colors");
	stage4(colors);	
	
#if MEMCHECK_STAGE_4
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	crm_debug_5("creating actions and internal ording constraints");
	stage5(resources, &ordering_constraints);

#if MEMCHECK_STAGE_5
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	crm_debug_5("processing fencing and shutdown cases");
	stage6(&actions, &ordering_constraints, nodes, resources);
	
#if MEMCHECK_STAGE_6
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	crm_debug_5("applying ordering constraints");
	stage7(resources, actions, ordering_constraints);

#if MEMCHECK_STAGE_7
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);

	free_xml(graph);
	crm_mem_stats(mem_stats);
	crm_err("Exiting");
	exit(1);
#endif

	crm_debug_2("=#=#=#=#= Summary =#=#=#=#=");
	crm_debug_2("========= All Actions =========");
	slist_iter(action, action_t, actions, lpc,
		   print_action("\t", action, TRUE);
		);
	
	crm_debug_2("\t========= Set %d (Un-runnable) =========", -1);
	crm_action_debug_2(
		slist_iter(action, action_t, actions, lpc,
			   if(action->optional == FALSE
			      && action->runnable == FALSE) {
				   log_action(LOG_DEBUG_2, "\t", action, TRUE);
			   }
			)
		);
	
	crm_debug_2("========= Stonith List =========");
	crm_action_debug_3(
		slist_iter(node, node_t, stonith_list, lpc,
			   print_node(NULL, node, FALSE);
			)
		);
	
	crm_debug_2("========= Shutdown List =========");
	crm_action_debug_3(
		slist_iter(node, node_t, shutdown_list, lpc,
			   print_node(NULL, node, FALSE);
			)
		);
	
	crm_debug_5("creating transition graph");
	stage8(resources, actions, &graph);
	
	cleanup_calculations(
		resources, nodes, placement_constraints, actions,
		ordering_constraints, stonith_list, shutdown_list,
		colors, action_sets);
	
	return graph;
}

/* 	cleanup_calculations(resources, nodes, placement_constraints, actions, ordering_constraints, stonith_list, shutdown_list, colors, action_sets); */

void
cleanup_calculations(GListPtr resources,
		     GListPtr nodes,
		     GListPtr placement_constraints,
		     GListPtr actions,
		     GListPtr ordering_constraints,
		     GListPtr stonith_list,
		     GListPtr shutdown_list,
		     GListPtr colors,
		     GListPtr action_sets)
{
	GListPtr iterator = NULL;
	
	crm_free(dc_uuid);
	dc_uuid = NULL;	
	
	crm_debug_3("deleting order cons");
	pe_free_ordering(ordering_constraints); 

	crm_debug_3("deleting action sets");
	slist_iter(action_set, GList, action_sets, lpc,
		   pe_free_shallow_adv(action_set, FALSE);
		);
	pe_free_shallow_adv(action_sets, FALSE);
	
	crm_debug_3("deleting global actions");
	pe_free_actions(global_action_list);
	global_action_list = NULL;

/* 	crm_debug_3("deleting actions"); */
/* 	pe_free_actions(actions); */

	crm_debug_3("deleting resources");
	pe_free_resources(resources); 
	
	crm_debug_3("deleting nodes");
	pe_free_nodes(nodes);
	
	crm_debug_3("deleting colors");
	pe_free_colors(colors);

	crm_debug_3("deleting node cons");
	iterator = placement_constraints;
	while(iterator) {
		pe_free_rsc_to_node((rsc_to_node_t*)iterator->data);
		iterator = iterator->next;
	}
	if(placement_constraints != NULL) {
		g_list_free(placement_constraints);
	}
	
	if(no_color != NULL) {
		crm_free(no_color->details);
		crm_free(no_color);
	}
	
	pe_free_shallow(shutdown_list);
	pe_free_shallow(stonith_list);
}

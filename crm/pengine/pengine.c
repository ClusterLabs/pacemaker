/* $Id: pengine.c,v 1.91 2005/09/15 17:13:08 andrew Exp $ */
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

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>

#include <pengine.h>
#include <pe_utils.h>

crm_data_t * do_calculations(
	pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now);

gboolean was_processing_error = FALSE;
gboolean was_processing_warning = FALSE;

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
		pe_working_set_t data_set;
		crm_data_t *generation = create_xml_node(NULL, XML_TAG_CIB);
		crm_data_t *status     = get_object_root(
			XML_CIB_TAG_STATUS, xml_data);
		crm_data_t *log_input  = status;
		log_input  = xml_data;


		copy_in_properties(generation, xml_data);
		crm_log_xml_info(generation, "[generation]");
		crm_log_xml_debug(status, "[status]");

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

		crm_zero_mem_stats(NULL);

		
		do_calculations(&data_set, xml_data, NULL);
		crm_log_xml_debug_3(data_set.graph, "[out]");

		if (send_ipc_reply(sender, msg, data_set.graph) ==FALSE) {
			crm_err("Answer could not be sent");
		}

		cleanup_calculations(&data_set);
		
		if(is_ipc_empty(sender) && crm_mem_stats(NULL)) {
			pe_warn("Unfree'd memory");
		}
	
		if(was_processing_error) {
			crm_info("ERRORs found during PE processing."
			       "  Input follows:");
			crm_log_xml_info(log_input, "[input]");

		} else if(was_processing_warning) {
			crm_debug("WARNINGs found during PE processing."
				"  Input follows:");
			crm_log_xml_debug(log_input, "[input]");

		} else if(crm_log_level > LOG_DEBUG) {
			crm_log_xml_debug_2(log_input, "[input]");
		}

		free_xml(generation);

		
	} else if(strcmp(op, CRM_OP_QUIT) == 0) {
		crm_warn("Received quit message, terminating");
		exit(0);
	}
	
	return TRUE;
}

#define MEMCHECK_STAGE_0 0


crm_data_t *
do_calculations(pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now)
{
	
/*	pe_debug_on(); */
	set_working_set_defaults(data_set);
	data_set->input = copy_xml(xml_input);
	data_set->now = now;
	if(data_set->now == NULL) {
		data_set->now = new_ha_date(TRUE);
	}
	
	crm_debug_5("unpack");		  
	stage0(data_set);
	
#if MEMCHECK_STAGE_0
	check_and_exit(0);
#endif

	crm_debug_5("apply placement constraints");
	stage1(data_set);
	
#if MEMCHECK_STAGE_1
	check_and_exit(1);
#endif

	crm_debug_5("color resources");
	stage2(data_set);

#if MEMCHECK_STAGE_2
	check_and_exit(2);
#endif

	/* unused */
	stage3(data_set);

#if MEMCHECK_STAGE_3
	check_and_exit(3);
#endif
	
	crm_debug_5("assign nodes to colors");
	stage4(data_set);	
	
#if MEMCHECK_STAGE_4
	check_and_exit(4);
#endif

	crm_debug_5("creating actions and internal ording constraints");
	stage5(data_set);

#if MEMCHECK_STAGE_5
	check_and_exit(5);
#endif

	crm_debug_5("processing fencing and shutdown cases");
	stage6(data_set);
	
#if MEMCHECK_STAGE_6
	check_and_exit(6);
#endif

	crm_debug_5("applying ordering constraints");
	stage7(data_set);

#if MEMCHECK_STAGE_7
	check_and_exit(7);
#endif

	crm_debug_5("creating transition graph");
	stage8(data_set);

#if MEMCHECK_STAGE_8
	check_and_exit(8);
#endif

	crm_debug_2("=#=#=#=#= Summary =#=#=#=#=");
	crm_debug_2("========= All Actions =========");
	slist_iter(action, action_t, data_set->actions, lpc,
		   log_action(LOG_DEBUG_2, "\t", action, TRUE)
		);
	
	crm_debug_2("\t========= Set %d (Un-runnable) =========", -1);
	crm_action_debug_2(
		slist_iter(action, action_t, data_set->actions, lpc,
			   if(action->optional == FALSE
			      && action->runnable == FALSE
			      && action->pseudo == FALSE) {
				   log_action(LOG_DEBUG_2, "\t", action, TRUE);
			   }
			)
		);
	
	return data_set->graph;
}

void
cleanup_calculations(pe_working_set_t *data_set)
{
	GListPtr iterator = NULL;

	if(data_set == NULL) {
		return;
	}
	
	crm_free(data_set->dc_uuid);
	crm_free(data_set->transition_idle_timeout);
	
	crm_debug_3("deleting order cons");
	pe_free_ordering(data_set->ordering_constraints); 

	crm_debug_3("deleting actions");
	pe_free_actions(data_set->actions);

	crm_debug_3("deleting resources");
	pe_free_resources(data_set->resources); 
	
	crm_debug_3("deleting nodes");
	pe_free_nodes(data_set->nodes);
	
	crm_debug_3("deleting colors");
	pe_free_colors(data_set->colors);

	crm_debug_3("deleting node cons");
	iterator = data_set->placement_constraints;
	while(iterator) {
		pe_free_rsc_to_node(iterator->data);
		iterator = iterator->next;
	}
	if(data_set->placement_constraints != NULL) {
		g_list_free(data_set->placement_constraints);
	}
	free_xml(data_set->graph);
	free_ha_date(data_set->now);
	free_xml(data_set->input);
}


void
set_working_set_defaults(pe_working_set_t *data_set) 
{
	data_set->input = NULL;
	data_set->now = NULL;
	data_set->graph = NULL;
	
	data_set->transition_idle_timeout = crm_strdup("60s");
	data_set->dc_uuid           = NULL;
	data_set->dc_node           = NULL;
	data_set->have_quorum       = FALSE;
	data_set->stonith_enabled   = FALSE;
	data_set->symmetric_cluster = TRUE;
	data_set->no_quorum_policy  = no_quorum_freeze;
	
	data_set->stop_action_orphans = FALSE;
	data_set->stop_rsc_orphans = FALSE;
	data_set->remove_on_stop = TRUE;
	
	data_set->nodes     = NULL;
	data_set->resources = NULL;
	data_set->ordering_constraints  = NULL;
	data_set->placement_constraints = NULL;

	data_set->no_color = NULL;
	data_set->colors   = NULL;
	data_set->actions  = NULL;	

	data_set->num_synapse = 0;
	data_set->max_valid_nodes = 0;
	data_set->order_id = 1;
	data_set->action_id = 1;
	data_set->color_id = 0;

}

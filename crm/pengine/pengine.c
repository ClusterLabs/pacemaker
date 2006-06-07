/* $Id: pengine.c,v 1.114 2006/06/07 12:46:59 andrew Exp $ */
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

#include <crm/pengine/status.h>
#include <lib/crm/pengine/pengine.h>
#include <lib/crm/pengine/utils.h>

crm_data_t * do_calculations(
	pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now);

#define PE_WORKING_DIR	HA_VARLIBDIR"/heartbeat/pengine"


extern int transition_id;

#define get_series() 	was_processing_error?1:was_processing_warning?2:3

typedef struct series_s 
{
	int id;
	const char *name;
	const char *param;
	int wrap;
} series_t;

series_t series[] = {
	{ 0, "pe-unknown", "_dont_match_anything_", -1 },
	{ 0, "pe-error",   "pe-error-series-max", -1 },
	{ 0, "pe-warn",    "pe-warn-series-max", 200 },
	{ 0, "pe-input",   "pe-input-series-max", 400 },
};


gboolean
process_pe_message(HA_Message *msg, crm_data_t * xml_data, IPC_Channel *sender)
{
	const char *sys_to = cl_get_string(msg, F_CRM_SYS_TO);
	const char *op = cl_get_string(msg, F_CRM_TASK);
	const char *ref = cl_get_string(msg, XML_ATTR_REFERENCE);

	crm_debug_3("Processing %s op (ref=%s)...", op, ref);
	
	if(op == NULL){
		/* error */

	} else if(strcasecmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */
		
	} else if(safe_str_eq(cl_get_string(msg, F_CRM_MSG_TYPE),
			      XML_ATTR_RESPONSE)) {
		/* ignore */
		
	} else if(sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_PENGINE) != 0) {
		crm_debug_3("Bad sys-to %s", crm_str(sys_to));
		return FALSE;
		
	} else if(strcasecmp(op, CRM_OP_PECALC) == 0) {
		int seq = -1;
		int series_id = 0;
		int series_wrap = 0;
		char *filename = NULL;
		const char *value = NULL;
		pe_working_set_t data_set;
		crm_data_t *generation = create_xml_node(NULL, XML_TAG_CIB);
		crm_data_t *log_input  = copy_xml(xml_data);
#if HAVE_BZLIB_H
		gboolean compress = TRUE;
#else
		gboolean compress = FALSE;
#endif
		
		
		copy_in_properties(generation, xml_data);
		crm_log_xml_info(generation, "[generation]");

		was_processing_error = FALSE;
		was_processing_warning = FALSE;

		crm_zero_mem_stats(NULL);

		do_calculations(&data_set, xml_data, NULL);
		crm_log_xml_debug_3(data_set.graph, "[out]");

		if(send_ipc_reply(sender, msg, data_set.graph) == FALSE) {
			crm_err("Answer could not be sent");
		}

		series_id = get_series();
		series_wrap = series[series_id].wrap;
		value = g_hash_table_lookup(
			data_set.config_hash, series[series_id].param);

		if(value != NULL) {
			series_wrap = crm_int_helper(value, NULL);
			if(errno != 0) {
				series_wrap = series[series_id].wrap;
			}

		} else {
			pe_config_warn("No value specified for cluster"
				       " preference: %s",
				       series[series_id].param);
		}   
		
		data_set.input = NULL;
		cleanup_calculations(&data_set);
		
		if(is_ipc_empty(sender) && crm_mem_stats(NULL)) {
			pe_warn("Unfree'd memory");
		}

		seq = get_last_sequence(PE_WORKING_DIR, series[series_id].name);
	
		filename = generate_series_filename(
			PE_WORKING_DIR, series[series_id].name, seq, compress);
		write_xml_file(log_input, filename, compress);

		write_last_sequence(PE_WORKING_DIR, series[series_id].name,
				    seq+1, series_wrap);
		
		if(was_processing_error) {
			crm_err("Transition %d:"
				" ERRORs found during PE processing."
				" PEngine Input stored in: %s",
				transition_id, filename);

		} else if(was_processing_warning) {
			crm_warn("Transition %d:"
				 " WARNINGs found during PE processing."
				 " PEngine Input stored in: %s",
				 transition_id, filename);

		} else {
			crm_info("Transition %d: PEngine Input stored in: %s",
				 transition_id, filename);
		}

		if(was_config_error) {
			crm_info("Configuration ERRORs found during PE processing."
			       "  Please run \"crm_verify -L\" to identify issues.");

		} else if(was_processing_warning) {
			crm_info("Configuration WARNINGs found during PE processing."
				 "  Please run \"crm_verify -L\" to identify issues.");
		}

		free_xml(generation);
		free_xml(log_input);
		crm_free(filename);
		
	} else if(strcasecmp(op, CRM_OP_QUIT) == 0) {
		crm_warn("Received quit message, terminating");
		exit(0);
	}
	
	return TRUE;
}

#define MEMCHECK_STAGE_0 0

#define check_and_exit(stage) 	cleanup_calculations(data_set);		\
	crm_mem_stats(NULL);						\
	crm_err("Exiting: stage %d", stage);				\
	exit(1);

crm_data_t *
do_calculations(pe_working_set_t *data_set, crm_data_t *xml_input, ha_time_t *now)
{
	int rsc_log_level = LOG_INFO;
/*	pe_debug_on(); */
	set_working_set_defaults(data_set);
	data_set->input = xml_input;
	data_set->now = now;
	if(data_set->now == NULL) {
		data_set->now = new_ha_date(TRUE);
	}

#if MEMCHECK_STAGE_SETUP
	check_and_exit(-1);
#endif
	
	crm_debug_5("unpack constraints");		  
	stage0(data_set);
	
#if MEMCHECK_STAGE_0
	check_and_exit(0);
#endif

	slist_iter(rsc, resource_t, data_set->resources, lpc,
		   rsc->fns->print(rsc, NULL, pe_print_log, &rsc_log_level);
		);

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

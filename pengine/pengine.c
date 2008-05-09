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

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pengine.h>
#include <allocate.h>
#include <lib/crm/pengine/utils.h>
#include <utils.h>

xmlNode * do_calculations(
	pe_working_set_t *data_set, xmlNode *xml_input, ha_time_t *now);

#define PE_WORKING_DIR	HA_VARLIBDIR"/heartbeat/pengine"

int scores_log_level = LOG_DEBUG_2;
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
process_pe_message(xmlNode *msg, xmlNode * xml_data, IPC_Channel *sender)
{
	gboolean send_via_disk = FALSE;
	const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
	const char *op = crm_element_value(msg, F_CRM_TASK);
	const char *ref = crm_element_value(msg, XML_ATTR_REFERENCE);

	crm_debug_3("Processing %s op (ref=%s)...", op, ref);
	
	if(op == NULL){
		/* error */

	} else if(strcasecmp(op, CRM_OP_HELLO) == 0) {
		/* ignore */
		
	} else if(safe_str_eq(crm_element_value(msg, F_CRM_MSG_TYPE),
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
		char *graph_file = NULL;
		const char *value = NULL;
		pe_working_set_t data_set;
		xmlNode *converted = NULL;
		xmlNode *reply = NULL;
		gboolean process = TRUE;
#if HAVE_BZLIB_H
		gboolean compress = TRUE;
#else
		gboolean compress = FALSE;
#endif

		crm_config_error = FALSE;
		crm_config_warning = FALSE;	
		
		was_processing_error = FALSE;
		was_processing_warning = FALSE;

		graph_file = crm_strdup(WORKING_DIR"/graph.XXXXXX");
		graph_file = mktemp(graph_file);

		value = crm_element_value(xml_data, XML_ATTR_VALIDATION);
		if(safe_str_neq(value, LATEST_SCHEMA_VERSION)) {
		    int schema_version = 0;
		    int max_version = get_schema_version(LATEST_SCHEMA_VERSION);
		    int min_version = get_schema_version(MINIMUM_SCHEMA_VERSION);

		    crm_config_warn("Your current configuration only conforms to %s", value);
		    crm_config_warn("Please use XXX to upgrade %s", LATEST_SCHEMA_VERSION);
		    
		    converted = copy_xml(xml_data);
		    schema_version = update_validation(&converted, FALSE, FALSE);

		    value = crm_element_value(xml_data, XML_ATTR_VALIDATION);
		    if(schema_version < min_version) {
			crm_config_err("Your current configuration could only be upgraded to %s... "
				       "the minimum requirement is %s.", value, MINIMUM_SCHEMA_VERSION);

			data_set.graph = create_xml_node(NULL, XML_TAG_GRAPH);
			crm_xml_add_int(data_set.graph, "transition_id", 0);
			process = FALSE;

		    } else if(schema_version < max_version) {
			crm_config_warn("Your configuration was internally updated to %s... "
					"which is acceptable but not the most recent", value);
		    } else {
			crm_config_warn("Your configuration was internally updated to %s", value);
		    }

		    xml_data = converted;
		}

		if(process) {
		    do_calculations(&data_set, xml_data, NULL);
		}
		
		series_id = get_series();
		series_wrap = series[series_id].wrap;
		value = pe_pref(data_set.config_hash, series[series_id].param);

		if(value != NULL) {
			series_wrap = crm_int_helper(value, NULL);
			if(errno != 0) {
				series_wrap = series[series_id].wrap;
			}

		} else {
			crm_config_warn("No value specified for cluster"
					" preference: %s",
					series[series_id].param);
		}		

		seq = get_last_sequence(PE_WORKING_DIR, series[series_id].name);	
		
		data_set.input = NULL;
		reply = create_reply(msg, data_set.graph);
		CRM_ASSERT(reply != NULL);

		filename = generate_series_filename(
			PE_WORKING_DIR, series[series_id].name, seq, compress);
		crm_xml_add(reply, F_CRM_TGRAPH_INPUT, filename);
		crm_free(filename); filename = NULL;

		if(send_ipc_message(sender, reply) == FALSE) {
			send_via_disk = TRUE;
			crm_err("Answer could not be sent via IPC, send via the disk instead");	           
			crm_info("Writing the TE graph to %s", graph_file);
			if(write_xml_file(data_set.graph, graph_file, FALSE) < 0) {
				crm_err("TE graph could not be written to disk");
			}
		}
		free_xml(reply);
		
		cleanup_alloc_calculations(&data_set);

		filename = generate_series_filename(
			PE_WORKING_DIR, series[series_id].name, seq, compress);

		write_xml_file(xml_data, filename, compress);
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

		if(crm_config_error) {
			crm_info("Configuration ERRORs found during PE processing."
			       "  Please run \"crm_verify -L\" to identify issues.");

		} else if(crm_config_warning) {
			crm_info("Configuration WARNINGs found during PE processing."
				 "  Please run \"crm_verify -L\" to identify issues.");
		}

		if(send_via_disk) {
			reply = create_reply(msg, NULL);
			crm_xml_add(reply, F_CRM_TGRAPH, graph_file);
			crm_xml_add(reply, F_CRM_TGRAPH_INPUT, filename);
			CRM_ASSERT(reply != NULL);
			if(send_ipc_message(sender, reply) == FALSE) {
				crm_err("Answer could not be sent");
			}
			free_xml(reply);
		}

		free_xml(converted);
		crm_free(graph_file);
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

xmlNode *
do_calculations(pe_working_set_t *data_set, xmlNode *xml_input, ha_time_t *now)
{
	int rsc_log_level = LOG_NOTICE;
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
		   if(is_set(rsc->flags, pe_rsc_orphan)
		      && rsc->role == RSC_ROLE_STOPPED) {
			   continue;
		   }
		   rsc->fns->print(rsc, NULL, pe_print_log, &rsc_log_level);
		);

	
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
	crm_debug_2("\t========= Set %d (Un-runnable) =========", -1);
	if(crm_log_level > LOG_DEBUG) {
		slist_iter(action, action_t, data_set->actions, lpc,
			   if(action->optional == FALSE
			      && action->runnable == FALSE
			      && action->pseudo == FALSE) {
				   log_action(LOG_DEBUG_2, "\t", action, TRUE);
			   }
			);
	}
	
	return data_set->graph;
}

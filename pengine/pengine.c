/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>


#include <glib.h>

#include <crm/pengine/status.h>
#include <pengine.h>
#include <allocate.h>
#include <utils.h>

xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now);

gboolean show_scores = FALSE;
int scores_log_level = LOG_DEBUG_2;
gboolean show_utilization = FALSE;
int utilization_log_level = LOG_DEBUG_2;
extern int transition_id;

#define get_series() 	was_processing_error?1:was_processing_warning?2:3

typedef struct series_s {
    const char *name;
    const char *param;
    int wrap;
} series_t;

series_t series[] = {
    {"pe-unknown", "_dont_match_anything_", -1},
    {"pe-error", "pe-error-series-max", -1},
    {"pe-warn", "pe-warn-series-max", 200},
    {"pe-input", "pe-input-series-max", 400},
};

gboolean process_pe_message(xmlNode * msg, xmlNode * xml_data, qb_ipcs_connection_t* sender);

gboolean
process_pe_message(xmlNode * msg, xmlNode * xml_data, qb_ipcs_connection_t* sender)
{
    static char *last_digest = NULL;

    const char *sys_to = crm_element_value(msg, F_CRM_SYS_TO);
    const char *op = crm_element_value(msg, F_CRM_TASK);
    const char *ref = crm_element_value(msg, XML_ATTR_REFERENCE);

    crm_trace("Processing %s op (ref=%s)...", op, ref);

    if (op == NULL) {
        /* error */

    } else if (strcasecmp(op, CRM_OP_HELLO) == 0) {
        /* ignore */

    } else if (safe_str_eq(crm_element_value(msg, F_CRM_MSG_TYPE), XML_ATTR_RESPONSE)) {
        /* ignore */

    } else if (sys_to == NULL || strcasecmp(sys_to, CRM_SYSTEM_PENGINE) != 0) {
        crm_trace("Bad sys-to %s", crm_str(sys_to));
        return FALSE;

    } else if (strcasecmp(op, CRM_OP_PECALC) == 0) {
        int seq = -1;
        int series_id = 0;
        int series_wrap = 0;
        char *digest = NULL;
        char *graph_file = NULL;
        const char *value = NULL;
        pe_working_set_t data_set;
        xmlNode *converted = NULL;
        xmlNode *reply = NULL;
        gboolean is_repoke = FALSE;
        gboolean process = TRUE;
        char *filename = NULL;

        crm_config_error = FALSE;
        crm_config_warning = FALSE;

        was_processing_error = FALSE;
        was_processing_warning = FALSE;

        graph_file = strdup(CRM_STATE_DIR "/graph.XXXXXX");
        graph_file = mktemp(graph_file);

        set_working_set_defaults(&data_set);

        digest = calculate_xml_versioned_digest(xml_data, FALSE, FALSE, CRM_FEATURE_SET);
        converted = copy_xml(xml_data);
        if (cli_config_update(&converted, NULL, TRUE) == FALSE) {
            data_set.graph = create_xml_node(NULL, XML_TAG_GRAPH);
            crm_xml_add_int(data_set.graph, "transition_id", 0);
            crm_xml_add_int(data_set.graph, "cluster-delay", 0);
            process = FALSE;

        } else if (safe_str_eq(digest, last_digest)) {
            crm_info("Input has not changed since last time, not saving to disk");
            is_repoke = TRUE;

        } else {
            free(last_digest);
            last_digest = digest;
        }

        if (process) {
            do_calculations(&data_set, converted, NULL);
        }

        series_id = get_series();
        series_wrap = series[series_id].wrap;
        value = pe_pref(data_set.config_hash, series[series_id].param);

        if (value != NULL) {
            series_wrap = crm_int_helper(value, NULL);
            if (errno != 0) {
                series_wrap = series[series_id].wrap;
            }

        } else {
            crm_config_warn("No value specified for cluster"
                            " preference: %s", series[series_id].param);
        }

        seq = get_last_sequence(PE_STATE_DIR, series[series_id].name);
        crm_trace("Series %s: wrap=%d, seq=%d, pref=%s",
                  series[series_id].name, series_wrap, seq, value);

        data_set.input = NULL;
        reply = create_reply(msg, data_set.graph);
        CRM_ASSERT(reply != NULL);

        if (is_repoke == FALSE) {
            filename = generate_series_filename(PE_STATE_DIR, series[series_id].name, seq, HAVE_BZLIB_H);
        }

        crm_xml_add(reply, F_CRM_TGRAPH_INPUT, filename);
        crm_xml_add_int(reply, "graph-errors", was_processing_error);
        crm_xml_add_int(reply, "graph-warnings", was_processing_warning);
        crm_xml_add_int(reply, "config-errors", crm_config_error);
        crm_xml_add_int(reply, "config-warnings", crm_config_warning);

        if (crm_ipcs_send(sender, 0, reply, TRUE) == FALSE) {
            crm_err("Couldn't send transition graph to peer, discarding");
        }

        free_xml(reply);
        cleanup_alloc_calculations(&data_set);

        if (was_processing_error) {
            crm_err("Calculated Transition %d: %s",
                    transition_id, filename);

        } else if (was_processing_warning) {
            crm_warn("Calculated Transition %d: %s",
                     transition_id, filename);

        } else {
            crm_notice("Calculated Transition %d: %s",
                       transition_id, filename);
        }

        if (crm_config_error) {
            crm_notice("Configuration ERRORs found during PE processing."
                       "  Please run \"crm_verify -L\" to identify issues.");
        }

        if (is_repoke == FALSE && series_wrap != 0) {
            write_xml_file(xml_data, filename, HAVE_BZLIB_H);
            write_last_sequence(PE_STATE_DIR, series[series_id].name,
                                seq + 1, series_wrap);
        } else {
            crm_trace("Not writing out %s: %d & %d",
                      filename, is_repoke, series_wrap);
        }

        free_xml(converted);
        free(graph_file);
        free(filename);

    } else if (strcasecmp(op, CRM_OP_QUIT) == 0) {
        crm_warn("Received quit message, terminating");
        exit(0);
    }

    return TRUE;
}

xmlNode *
do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now)
{
    GListPtr gIter = NULL;
    int rsc_log_level = LOG_INFO;

/*	pe_debug_on(); */

    CRM_ASSERT(xml_input || is_set(data_set->flags, pe_flag_have_status));

    if (is_set(data_set->flags, pe_flag_have_status) == FALSE) {
        set_working_set_defaults(data_set);
        data_set->input = xml_input;
        data_set->now = now;
        if (data_set->now == NULL) {
            data_set->now = crm_time_new(NULL);
        }
    } else {
        crm_trace("Already have status - reusing");
    }

    crm_trace("Calculate cluster status");
    stage0(data_set);

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        if (is_set(rsc->flags, pe_rsc_orphan) && rsc->role == RSC_ROLE_STOPPED) {
            continue;
        }
        rsc->fns->print(rsc, NULL, pe_print_log, &rsc_log_level);
    }

    crm_trace("Applying placement constraints");
    stage2(data_set);

    crm_trace("Create internal constraints");
    stage3(data_set);

    crm_trace("Check actions");
    stage4(data_set);

    crm_trace("Allocate resources");
    stage5(data_set);

    crm_trace("Processing fencing and shutdown cases");
    stage6(data_set);

    crm_trace("Applying ordering constraints");
    stage7(data_set);

    crm_trace("Create transition graph");
    stage8(data_set);

    crm_trace("=#=#=#=#= Summary =#=#=#=#=");
    crm_trace("\t========= Set %d (Un-runnable) =========", -1);
    if (get_crm_log_level() >= LOG_TRACE) {
        gIter = data_set->actions;
        for (; gIter != NULL; gIter = gIter->next) {
            action_t *action = (action_t *) gIter->data;

            if (is_set(action->flags, pe_action_optional) == FALSE
                && is_set(action->flags, pe_action_runnable) == FALSE
                && is_set(action->flags, pe_action_pseudo) == FALSE) {
                log_action(LOG_TRACE, "\t", action, TRUE);
            }
        }
    }

    return data_set->graph;
}

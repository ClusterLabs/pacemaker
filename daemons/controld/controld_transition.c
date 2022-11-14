/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

extern pcmk__graph_functions_t te_graph_fns;

static void
global_cib_callback(const xmlNode * msg, int callid, int rc, xmlNode * output)
{
}

static pcmk__graph_t *
create_blank_graph(void)
{
    pcmk__graph_t *a_graph = pcmk__unpack_graph(NULL, NULL);

    a_graph->complete = true;
    a_graph->abort_reason = "DC Takeover";
    a_graph->completion_action = pcmk__graph_restart;
    return a_graph;
}

/*	 A_TE_START, A_TE_STOP, O_TE_RESTART	*/
void
do_te_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    cib_t *cib_conn = controld_globals.cib_conn;
    gboolean init_ok = TRUE;

    if (pcmk_is_set(action, A_TE_STOP)) {
        if (transition_graph) {
            pcmk__free_graph(transition_graph);
            transition_graph = NULL;
        }

        if (cib_conn != NULL) {
            cib_conn->cmds->del_notify_callback(cib_conn, T_CIB_DIFF_NOTIFY,
                                                te_update_diff);
        }

        controld_clear_fsa_input_flags(R_TE_CONNECTED);
        crm_info("Transitioner is now inactive");
    }

    if ((action & A_TE_START) == 0) {
        return;

    } else if (pcmk_is_set(controld_globals.fsa_input_register,
                           R_TE_CONNECTED)) {
        crm_debug("The transitioner is already active");
        return;

    } else if ((action & A_TE_START) && cur_state == S_STOPPING) {
        crm_info("Ignoring request to start the transitioner while shutting down");
        return;
    }

    if (te_uuid == NULL) {
        te_uuid = crm_generate_uuid();
        crm_info("Registering TE UUID: %s", te_uuid);
    }

    if (cib_conn == NULL) {
        crm_err("Could not set CIB callbacks");
        init_ok = FALSE;

    } else {
        if (cib_conn->cmds->add_notify_callback(cib_conn, T_CIB_DIFF_NOTIFY,
                                                te_update_diff) != pcmk_ok) {
            crm_err("Could not set CIB notification callback");
            init_ok = FALSE;
        }

        if (cib_conn->cmds->set_op_callback(cib_conn,
                                            global_cib_callback) != pcmk_ok) {
            crm_err("Could not set CIB global callback");
            init_ok = FALSE;
        }
    }

    if (init_ok) {
        pcmk__set_graph_functions(&te_graph_fns);

        if (transition_graph) {
            pcmk__free_graph(transition_graph);
        }

        /* create a blank one */
        crm_debug("Transitioner is now active");
        transition_graph = create_blank_graph();
        controld_set_fsa_input_flags(R_TE_CONNECTED);
    }
}

/*	 A_TE_INVOKE, A_TE_CANCEL	*/
void
do_te_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{

    if (!AM_I_DC
        || ((controld_globals.fsa_state != S_TRANSITION_ENGINE)
            && pcmk_is_set(action, A_TE_INVOKE))) {
        crm_notice("No need to invoke the TE (%s) in state %s",
                   fsa_action2string(action),
                   fsa_state2string(controld_globals.fsa_state));
        return;
    }

    if (action & A_TE_CANCEL) {
        crm_debug("Cancelling the transition: %s",
                  transition_graph->complete ? "inactive" : "active");
        abort_transition(INFINITY, pcmk__graph_restart, "Peer Cancelled", NULL);
        if (!transition_graph->complete) {
            crmd_fsa_stall(FALSE);
        }

    } else if (action & A_TE_HALT) {
        abort_transition(INFINITY, pcmk__graph_wait, "Peer Halt", NULL);
        if (!transition_graph->complete) {
            crmd_fsa_stall(FALSE);
        }

    } else if (action & A_TE_INVOKE) {
        const char *value = NULL;
        xmlNode *graph_data = NULL;
        ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
        const char *ref = crm_element_value(input->msg, XML_ATTR_REFERENCE);
        const char *graph_file = crm_element_value(input->msg, F_CRM_TGRAPH);
        const char *graph_input = crm_element_value(input->msg, F_CRM_TGRAPH_INPUT);

        if (graph_file == NULL && input->xml == NULL) {
            crm_log_xml_err(input->msg, "Bad command");
            register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
            return;
        }

        if (!transition_graph->complete) {
            crm_info("Another transition is already active");
            abort_transition(INFINITY, pcmk__graph_restart, "Transition Active",
                             NULL);
            return;
        }

        if ((fsa_pe_ref == NULL)
            || !pcmk__str_eq(fsa_pe_ref, ref, pcmk__str_none)) {
            crm_info("Transition is redundant: %s expected but %s received",
                     pcmk__s(fsa_pe_ref, "no reference"),
                     pcmk__s(ref, "no reference"));
            abort_transition(INFINITY, pcmk__graph_restart,
                             "Transition Redundant", NULL);
        }

        graph_data = input->xml;

        if (graph_data == NULL && graph_file != NULL) {
            graph_data = filename2xml(graph_file);
        }

        if (is_timer_started(transition_timer)) {
            crm_debug("The transitioner wait for a transition timer");
            return;
        }

        CRM_CHECK(graph_data != NULL,
                  crm_err("Input raised by %s is invalid", msg_data->origin);
                  crm_log_xml_err(input->msg, "Bad command");
                  return);

        pcmk__free_graph(transition_graph);
        transition_graph = pcmk__unpack_graph(graph_data, graph_input);
        CRM_CHECK(transition_graph != NULL,
                  transition_graph = create_blank_graph(); return);
        crm_info("Processing graph %d (ref=%s) derived from %s", transition_graph->id, ref,
                 graph_input);

        te_reset_job_counts();
        value = crm_element_value(graph_data, "failed-stop-offset");
        if (value != NULL) {
            pcmk__str_update(&failed_stop_offset, value);
        }

        value = crm_element_value(graph_data, "failed-start-offset");
        if (value != NULL) {
            pcmk__str_update(&failed_start_offset, value);
        }

        if ((crm_element_value_epoch(graph_data, "recheck-by", &recheck_by)
            != pcmk_ok) || (recheck_by < 0)) {
            recheck_by = 0;
        }

        trigger_graph();
        pcmk__log_graph(LOG_TRACE, transition_graph);

        if (graph_data != input->xml) {
            free_xml(graph_data);
        }
    }
}

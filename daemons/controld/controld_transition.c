/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

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
        pcmk__free_graph(controld_globals.transition_graph);
        controld_globals.transition_graph = NULL;

        if (cib_conn != NULL) {
            cib_conn->cmds->del_notify_callback(cib_conn,
                                                PCMK__VALUE_CIB_DIFF_NOTIFY,
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

    if (controld_globals.te_uuid == NULL) {
        controld_globals.te_uuid = crm_generate_uuid();
        crm_info("Registering TE UUID: %s", controld_globals.te_uuid);
    }

    if (cib_conn == NULL) {
        crm_err("Could not set CIB callbacks");
        init_ok = FALSE;

    } else if (cib_conn->cmds->add_notify_callback(cib_conn,
                                                   PCMK__VALUE_CIB_DIFF_NOTIFY,
                                                   te_update_diff) != pcmk_ok) {
        crm_err("Could not set CIB notification callback");
        init_ok = FALSE;
    }

    if (init_ok) {
        controld_register_graph_functions();
        pcmk__free_graph(controld_globals.transition_graph);

        /* create a blank one */
        crm_debug("Transitioner is now active");
        controld_globals.transition_graph = create_blank_graph();
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
        crm_debug("Cancelling the transition: %sactive",
                  controld_globals.transition_graph->complete? "in" : "");
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Peer Cancelled", NULL);
        if (!controld_globals.transition_graph->complete) {
            crmd_fsa_stall(FALSE);
        }

    } else if (action & A_TE_HALT) {
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_wait, "Peer Halt",
                         NULL);
        if (!controld_globals.transition_graph->complete) {
            crmd_fsa_stall(FALSE);
        }

    } else if (action & A_TE_INVOKE) {
        ha_msg_input_t *input = fsa_typed_data(fsa_dt_ha_msg);
        xmlNode *graph_data = input->xml;
        const char *ref = pcmk__xe_get(input->msg, PCMK_XA_REFERENCE);
        const char *graph_input = pcmk__xe_get(input->msg,
                                               PCMK__XA_CRM_TGRAPH_IN);

        if (graph_data == NULL) {
            crm_log_xml_err(input->msg, "Bad command");
            register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
            return;
        }

        if (!controld_globals.transition_graph->complete) {
            crm_info("Another transition is already active");
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Transition Active", NULL);
            return;
        }

        if ((controld_globals.fsa_pe_ref == NULL)
            || !pcmk__str_eq(controld_globals.fsa_pe_ref, ref,
                             pcmk__str_none)) {
            crm_info("Transition is redundant: %s expected but %s received",
                     pcmk__s(controld_globals.fsa_pe_ref, "no reference"),
                     pcmk__s(ref, "no reference"));
            abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                             "Transition Redundant", NULL);
        }

        if (controld_is_started_transition_timer()) {
            crm_debug("The transitioner wait for a transition timer");
            return;
        }

        CRM_CHECK(graph_data != NULL,
                  crm_err("Input raised by %s is invalid", msg_data->origin);
                  crm_log_xml_err(input->msg, "Bad command");
                  return);

        pcmk__free_graph(controld_globals.transition_graph);
        controld_globals.transition_graph = pcmk__unpack_graph(graph_data,
                                                               graph_input);
        CRM_CHECK(controld_globals.transition_graph != NULL,
                  controld_globals.transition_graph = create_blank_graph();
                  return);
        crm_info("Processing graph %d (ref=%s) derived from %s",
                 controld_globals.transition_graph->id, ref, graph_input);

        te_reset_job_counts();

        trigger_graph();
        pcmk__log_graph(LOG_TRACE, controld_globals.transition_graph);

        if (graph_data != input->xml) {
            pcmk__xml_free(graph_data);
        }
    }
}

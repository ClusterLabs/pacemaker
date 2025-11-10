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
    pcmk__graph_t *graph = pcmk__unpack_graph(NULL, NULL);

    graph->complete = true;
    graph->abort_reason = "DC Takeover";
    graph->completion_action = pcmk__graph_restart;
    return graph;
}

// A_TE_START, A_TE_STOP, O_TE_RESTART
void
do_te_control(long long action, enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
              fsa_data_t *msg_data)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    if (pcmk__is_set(action, A_TE_STOP)) {
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

    if (!pcmk__is_set(action, A_TE_START)) {
        return;
    }

    if (pcmk__is_set(controld_globals.fsa_input_register, R_TE_CONNECTED)) {
        crm_debug("The transitioner is already active");
        return;
    }

    if (cur_state == S_STOPPING) {
        crm_info("Ignoring request to start the transitioner while shutting "
                 "down");
        return;
    }

    if ((cib_conn == NULL)
        || (cib_conn->cmds->add_notify_callback(cib_conn,
                                                PCMK__VALUE_CIB_DIFF_NOTIFY,
                                                te_update_diff) != pcmk_ok)) {
        crm_err("Could not set CIB notification callback");
        return;
    }

    if (controld_globals.te_uuid == NULL) {
        controld_globals.te_uuid = pcmk__generate_uuid();
        crm_info("Registering TE UUID: %s", controld_globals.te_uuid);
    }

    controld_register_graph_functions();
    pcmk__free_graph(controld_globals.transition_graph);
    controld_globals.transition_graph = create_blank_graph();
    controld_set_fsa_input_flags(R_TE_CONNECTED);
    crm_debug("Transitioner is now active");
}

// A_TE_INVOKE, A_TE_CANCEL
void
do_te_invoke(long long action, enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
             fsa_data_t *msg_data)
{
    ha_msg_input_t *input = NULL;
    xmlNode *graph_data = NULL;
    const char *ref = NULL;
    const char *graph_input = NULL;

    if (!AM_I_DC) {
        crm_notice("Not invoking the TE because we are not the DC");
        return;
    }

    if (pcmk__is_set(action, A_TE_INVOKE)
        && (controld_globals.fsa_state != S_TRANSITION_ENGINE)) {

        crm_notice("No need to invoke the TE (%s) while in state %s",
                   fsa_action2string(action),
                   fsa_state2string(controld_globals.fsa_state));
        return;
    }

    if (pcmk__is_set(action, A_TE_CANCEL)) {
        crm_debug("Cancelling the transition: %sactive",
                  controld_globals.transition_graph->complete? "in" : "");
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Peer cancelled", NULL);
        if (!controld_globals.transition_graph->complete) {
            controld_fsa_stall(false, action);
        }
        return;
    }

    if (pcmk__is_set(action, A_TE_HALT)) {
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_wait, "Peer halt",
                         NULL);
        if (!controld_globals.transition_graph->complete) {
            controld_fsa_stall(false, action);
        }
        return;
    }

    if (!pcmk__is_set(action, A_TE_INVOKE)) {
        return;
    }

    pcmk__assert((msg_data != NULL) && (msg_data->data != NULL));

    input = msg_data->data;
    graph_data = input->xml;
    if (graph_data == NULL) {
        crm_log_xml_err(input->msg, "Bad command");
        register_fsa_error(I_FAIL, msg_data);
        return;
    }

    if (!controld_globals.transition_graph->complete) {
        crm_info("Another transition is already active");
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Transition active", NULL);
        return;
    }

    ref = pcmk__xe_get(input->msg, PCMK_XA_REFERENCE);

    if ((controld_globals.fsa_pe_ref == NULL)
        || !pcmk__str_eq(controld_globals.fsa_pe_ref, ref,
                         pcmk__str_none)) {
        crm_info("Transition is redundant: %s expected but %s received",
                 pcmk__s(controld_globals.fsa_pe_ref, "no reference"),
                 pcmk__s(ref, "no reference"));
        abort_transition(PCMK_SCORE_INFINITY, pcmk__graph_restart,
                         "Transition redundant", NULL);
    }

    if (controld_is_started_transition_timer()) {
        crm_debug("The transitioner wait for a transition timer");
        return;
    }

    CRM_CHECK(graph_data != NULL,
              crm_err("Input raised by %s is invalid", msg_data->origin);
              crm_log_xml_err(input->msg, "Bad command");
              return);

    graph_input = pcmk__xe_get(input->msg, PCMK__XA_CRM_TGRAPH_IN);
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

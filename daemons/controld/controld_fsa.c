/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>               // PRIx64
#include <sys/param.h>
#include <stdio.h>
#include <stdint.h>                 // uint64_t
#include <string.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/lrmd.h>
#include <crm/cib.h>
#include <crm/common/xml.h>
#include <crm/cluster/election_internal.h>
#include <crm/cluster.h>

#include <pacemaker-controld.h>

//! Triggers an FSA invocation
static crm_trigger_t *fsa_trigger = NULL;

static void do_state_transition(enum crmd_fsa_state cur_state,
                                enum crmd_fsa_state next_state,
                                fsa_data_t *msg_data);

void s_crmd_fsa_actions(fsa_data_t * fsa_data);
void log_fsa_input(fsa_data_t * stored_msg);

static void
do_fsa_action(fsa_data_t * fsa_data, long long an_action,
              void (*function) (long long action,
                                enum crmd_fsa_cause cause,
                                enum crmd_fsa_state cur_state,
                                enum crmd_fsa_input cur_input, fsa_data_t * msg_data))
{
    controld_clear_fsa_action_flags(an_action);
    function(an_action, fsa_data->fsa_cause, controld_globals.fsa_state,
             fsa_data->fsa_input, fsa_data);
}

static const uint64_t startup_actions =
    A_STARTUP | A_CIB_START | A_LRM_CONNECT | A_HA_CONNECT | A_READCONFIG |
    A_STARTED | A_CL_JOIN_QUERY;

// A_LOG, A_WARN, A_ERROR
void
do_log(long long action, enum crmd_fsa_cause cause,
       enum crmd_fsa_state cur_state,
       enum crmd_fsa_input current_input, fsa_data_t *msg_data)
{
    unsigned log_type = LOG_TRACE;

    if (action & A_LOG) {
        log_type = LOG_INFO;
    } else if (action & A_WARN) {
        log_type = LOG_WARNING;
    } else if (action & A_ERROR) {
        log_type = LOG_ERR;
    }

    do_crm_log(log_type, "Input %s received in state %s from %s",
               fsa_input2string(msg_data->fsa_input),
               fsa_state2string(cur_state), msg_data->origin);

    if (msg_data->data_type == fsa_dt_ha_msg) {
        ha_msg_input_t *input = fsa_typed_data(msg_data->data_type);

        crm_log_xml_debug(input->msg, __func__);

    } else if (msg_data->data_type == fsa_dt_xml) {
        xmlNode *input = fsa_typed_data(msg_data->data_type);

        crm_log_xml_debug(input, __func__);

    } else if (msg_data->data_type == fsa_dt_lrm) {
        lrmd_event_data_t *input = fsa_typed_data(msg_data->data_type);

        do_crm_log(log_type,
                   "Resource %s: Call ID %d returned %d (%d)."
                   "  New status if rc=0: %s",
                   input->rsc_id, input->call_id, input->rc,
                   input->op_status, (char *)input->user_data);
    }
}

/*!
 * \internal
 * \brief Initialize the FSA trigger
 */
void
controld_init_fsa_trigger(void)
{
    fsa_trigger = mainloop_add_trigger(G_PRIORITY_HIGH, crm_fsa_trigger, NULL);
}

/*!
 * \internal
 * \brief Destroy the FSA trigger
 */
void
controld_destroy_fsa_trigger(void)
{
    // This basically will not work, since mainloop has a reference to it
    mainloop_destroy_trigger(fsa_trigger);
    fsa_trigger = NULL;
}

/*!
 * \internal
 * \brief Trigger an FSA invocation
 *
 * \param[in] fn    Calling function name
 * \param[in] line  Line number where call occurred
 */
void
controld_trigger_fsa_as(const char *fn, int line)
{
    if (fsa_trigger != NULL) {
        crm_trace("%s:%d - Triggered FSA invocation", fn, line);
        mainloop_set_trigger(fsa_trigger);
    }
}

enum crmd_fsa_state
s_crmd_fsa(enum crmd_fsa_cause cause)
{
    controld_globals_t *globals = &controld_globals;
    fsa_data_t *fsa_data = NULL;
    uint64_t register_copy = controld_globals.fsa_input_register;
    uint64_t new_actions = A_NOTHING;
    enum crmd_fsa_state last_state;

    crm_trace("FSA invoked with Cause: %s\tState: %s",
              fsa_cause2string(cause),
              fsa_state2string(globals->fsa_state));

    fsa_dump_actions(controld_globals.fsa_actions, "Initial");

    controld_clear_global_flags(controld_fsa_is_stalled);
    if ((controld_globals.fsa_message_queue == NULL)
        && (controld_globals.fsa_actions != A_NOTHING)) {
        /* fake the first message so we can get into the loop */
        fsa_data = pcmk__assert_alloc(1, sizeof(fsa_data_t));
        fsa_data->fsa_input = I_NULL;
        fsa_data->fsa_cause = C_FSA_INTERNAL;
        fsa_data->origin = __func__;
        fsa_data->data_type = fsa_dt_none;
        controld_globals.fsa_message_queue
            = g_list_append(controld_globals.fsa_message_queue, fsa_data);
    }
    while ((controld_globals.fsa_message_queue != NULL)
           && !pcmk__is_set(controld_globals.flags, controld_fsa_is_stalled)) {
        crm_trace("Checking messages (%d remaining)",
                  g_list_length(controld_globals.fsa_message_queue));

        fsa_data = get_message();
        if(fsa_data == NULL) {
            continue;
        }

        log_fsa_input(fsa_data);

        /* add any actions back to the queue */
        controld_set_fsa_action_flags(fsa_data->actions);
        fsa_dump_actions(fsa_data->actions, "Restored actions");

        /* get the next batch of actions */
        new_actions = controld_fsa_get_action(fsa_data->fsa_input);
        controld_set_fsa_action_flags(new_actions);
        fsa_dump_actions(new_actions, "New actions");

        if (fsa_data->fsa_input != I_NULL && fsa_data->fsa_input != I_ROUTER) {
            crm_debug("Processing %s: [ state=%s cause=%s origin=%s ]",
                      fsa_input2string(fsa_data->fsa_input),
                      fsa_state2string(globals->fsa_state),
                      fsa_cause2string(fsa_data->fsa_cause), fsa_data->origin);
        }

        /* logging : *before* the state is changed */
        if (pcmk__is_set(controld_globals.fsa_actions, A_ERROR)) {
            do_fsa_action(fsa_data, A_ERROR, do_log);
        }
        if (pcmk__is_set(controld_globals.fsa_actions, A_WARN)) {
            do_fsa_action(fsa_data, A_WARN, do_log);
        }
        if (pcmk__is_set(controld_globals.fsa_actions, A_LOG)) {
            do_fsa_action(fsa_data, A_LOG, do_log);
        }

        /* update state variables */
        last_state = globals->fsa_state;
        globals->fsa_state = controld_fsa_get_next_state(fsa_data->fsa_input);

        /*
         * Remove certain actions during shutdown
         */
        if ((globals->fsa_state == S_STOPPING)
            || pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
            controld_clear_fsa_action_flags(startup_actions);
        }

        /*
         * Hook for change of state.
         * Allows actions to be added or removed when entering a state
         */
        if (last_state != globals->fsa_state) {
            do_state_transition(last_state, globals->fsa_state, fsa_data);
        }

        /* start doing things... */
        s_crmd_fsa_actions(fsa_data);
        delete_fsa_input(fsa_data);
    }

    if ((controld_globals.fsa_message_queue != NULL)
        || (controld_globals.fsa_actions != A_NOTHING)
        || pcmk__is_set(controld_globals.flags, controld_fsa_is_stalled)) {

        crm_debug("Exiting the FSA: queue=%d, fsa_actions=%" PRIx64
                  ", stalled=%s",
                  g_list_length(controld_globals.fsa_message_queue),
                  controld_globals.fsa_actions,
                  pcmk__flag_text(controld_globals.flags,
                                  controld_fsa_is_stalled));
    } else {
        crm_trace("Exiting the FSA");
    }

    /* cleanup inputs? */
    if (register_copy != controld_globals.fsa_input_register) {
        uint64_t same = register_copy & controld_globals.fsa_input_register;

        fsa_dump_inputs(LOG_DEBUG, "Added",
                        controld_globals.fsa_input_register ^ same);
        fsa_dump_inputs(LOG_DEBUG, "Removed", register_copy ^ same);
    }

    fsa_dump_actions(controld_globals.fsa_actions, "Remaining");
    fsa_dump_queue(LOG_DEBUG);

    return globals->fsa_state;
}

void
s_crmd_fsa_actions(fsa_data_t * fsa_data)
{
    /*
     * Process actions in order of priority but do only one
     * action at a time to avoid complicating the ordering.
     */
    CRM_CHECK(fsa_data != NULL, return);
    while ((controld_globals.fsa_actions != A_NOTHING)
           && !pcmk__is_set(controld_globals.flags, controld_fsa_is_stalled)) {

        /* regular action processing in order of action priority
         *
         * Make sure all actions that connect to required systems
         * are performed first
         */
        if (pcmk__is_set(controld_globals.fsa_actions, A_ERROR)) {
            do_fsa_action(fsa_data, A_ERROR, do_log);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_WARN)) {
            do_fsa_action(fsa_data, A_WARN, do_log);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_LOG)) {
            do_fsa_action(fsa_data, A_LOG, do_log);

            /* get out of here NOW! before anything worse happens */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_EXIT_1)) {
            do_fsa_action(fsa_data, A_EXIT_1, do_exit);

            /* sub-system restart */
        } else if (pcmk__all_flags_set(controld_globals.fsa_actions,
                                       O_LRM_RECONNECT)) {
            do_fsa_action(fsa_data, O_LRM_RECONNECT, do_lrm_control);

        } else if (pcmk__all_flags_set(controld_globals.fsa_actions,
                                       O_CIB_RESTART)) {
            do_fsa_action(fsa_data, O_CIB_RESTART, do_cib_control);

        } else if (pcmk__all_flags_set(controld_globals.fsa_actions,
                                       O_PE_RESTART)) {
            do_fsa_action(fsa_data, O_PE_RESTART, do_pe_control);

        } else if (pcmk__all_flags_set(controld_globals.fsa_actions,
                                       O_TE_RESTART)) {
            do_fsa_action(fsa_data, O_TE_RESTART, do_te_control);

            /* essential start tasks */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_STARTUP)) {
            do_fsa_action(fsa_data, A_STARTUP, do_startup);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_CIB_START)) {
            do_fsa_action(fsa_data, A_CIB_START, do_cib_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_HA_CONNECT)) {
            do_fsa_action(fsa_data, A_HA_CONNECT, do_ha_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_READCONFIG)) {
            do_fsa_action(fsa_data, A_READCONFIG, do_read_config);

            /* sub-system start/connect */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_LRM_CONNECT)) {
            do_fsa_action(fsa_data, A_LRM_CONNECT, do_lrm_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_TE_START)) {
            do_fsa_action(fsa_data, A_TE_START, do_te_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_PE_START)) {
            do_fsa_action(fsa_data, A_PE_START, do_pe_control);

            /* Timers */
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_TIMER_STOP)) {
            do_fsa_action(fsa_data, A_DC_TIMER_STOP, do_timer_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_INTEGRATE_TIMER_STOP)) {
            do_fsa_action(fsa_data, A_INTEGRATE_TIMER_STOP, do_timer_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_INTEGRATE_TIMER_START)) {
            do_fsa_action(fsa_data, A_INTEGRATE_TIMER_START, do_timer_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_FINALIZE_TIMER_STOP)) {
            do_fsa_action(fsa_data, A_FINALIZE_TIMER_STOP, do_timer_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_FINALIZE_TIMER_START)) {
            do_fsa_action(fsa_data, A_FINALIZE_TIMER_START, do_timer_control);

            /*
             * Highest priority actions
             */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_MSG_ROUTE)) {
            do_fsa_action(fsa_data, A_MSG_ROUTE, do_msg_route);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_RECOVER)) {
            do_fsa_action(fsa_data, A_RECOVER, do_recover);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_CL_JOIN_RESULT)) {
            do_fsa_action(fsa_data, A_CL_JOIN_RESULT,
                          do_cl_join_finalize_respond);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_CL_JOIN_REQUEST)) {
            do_fsa_action(fsa_data, A_CL_JOIN_REQUEST,
                          do_cl_join_offer_respond);

        } else if (pcmk__is_set(controld_globals.fsa_actions, A_SHUTDOWN_REQ)) {
            do_fsa_action(fsa_data, A_SHUTDOWN_REQ, do_shutdown_req);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_ELECTION_VOTE)) {
            do_fsa_action(fsa_data, A_ELECTION_VOTE, do_election_vote);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_ELECTION_COUNT)) {
            do_fsa_action(fsa_data, A_ELECTION_COUNT, do_election_count_vote);

            /*
             * High priority actions
             */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_STARTED)) {
            do_fsa_action(fsa_data, A_STARTED, do_started);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_CL_JOIN_QUERY)) {
            do_fsa_action(fsa_data, A_CL_JOIN_QUERY, do_cl_join_query);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_TIMER_START)) {
            do_fsa_action(fsa_data, A_DC_TIMER_START, do_timer_control);

            /*
             * Medium priority actions
             * - Membership
             */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_DC_TAKEOVER)) {
            do_fsa_action(fsa_data, A_DC_TAKEOVER, do_dc_takeover);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_DC_RELEASE)) {
            do_fsa_action(fsa_data, A_DC_RELEASE, do_dc_release);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_JOIN_FINAL)) {
            do_fsa_action(fsa_data, A_DC_JOIN_FINAL, do_dc_join_final);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_ELECTION_CHECK)) {
            do_fsa_action(fsa_data, A_ELECTION_CHECK, do_election_check);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_ELECTION_START)) {
            do_fsa_action(fsa_data, A_ELECTION_START, do_election_vote);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_JOIN_OFFER_ALL)) {
            do_fsa_action(fsa_data, A_DC_JOIN_OFFER_ALL, do_dc_join_offer_all);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_JOIN_OFFER_ONE)) {
            do_fsa_action(fsa_data, A_DC_JOIN_OFFER_ONE, do_dc_join_offer_one);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_JOIN_PROCESS_REQ)) {
            do_fsa_action(fsa_data, A_DC_JOIN_PROCESS_REQ,
                          do_dc_join_filter_offer);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_JOIN_PROCESS_ACK)) {
            do_fsa_action(fsa_data, A_DC_JOIN_PROCESS_ACK, do_dc_join_ack);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_DC_JOIN_FINALIZE)) {
            do_fsa_action(fsa_data, A_DC_JOIN_FINALIZE, do_dc_join_finalize);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_CL_JOIN_ANNOUNCE)) {
            do_fsa_action(fsa_data, A_CL_JOIN_ANNOUNCE, do_cl_join_announce);

            /*
             * Low(er) priority actions
             * Make sure the CIB is always updated before invoking the
             * scheduler, and the scheduler before the transition engine.
             */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_TE_HALT)) {
            do_fsa_action(fsa_data, A_TE_HALT, do_te_invoke);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_TE_CANCEL)) {
            do_fsa_action(fsa_data, A_TE_CANCEL, do_te_invoke);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_LRM_INVOKE)) {
            do_fsa_action(fsa_data, A_LRM_INVOKE, do_lrm_invoke);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_PE_INVOKE)) {
            do_fsa_action(fsa_data, A_PE_INVOKE, do_pe_invoke);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_TE_INVOKE)) {
            do_fsa_action(fsa_data, A_TE_INVOKE, do_te_invoke);

            /* Shutdown actions */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_DC_RELEASED)) {
            do_fsa_action(fsa_data, A_DC_RELEASED, do_dc_release);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_PE_STOP)) {
            do_fsa_action(fsa_data, A_PE_STOP, do_pe_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_TE_STOP)) {
            do_fsa_action(fsa_data, A_TE_STOP, do_te_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_SHUTDOWN)) {
            do_fsa_action(fsa_data, A_SHUTDOWN, do_shutdown);
        } else if (pcmk__is_set(controld_globals.fsa_actions,
                               A_LRM_DISCONNECT)) {
            do_fsa_action(fsa_data, A_LRM_DISCONNECT, do_lrm_control);

        } else if (pcmk__is_set(controld_globals.fsa_actions,
                                A_HA_DISCONNECT)) {
            do_fsa_action(fsa_data, A_HA_DISCONNECT, do_ha_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_CIB_STOP)) {
            do_fsa_action(fsa_data, A_CIB_STOP, do_cib_control);
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_STOP)) {
            do_fsa_action(fsa_data, A_STOP, do_stop);

            /* exit gracefully */
        } else if (pcmk__is_set(controld_globals.fsa_actions, A_EXIT_0)) {
            do_fsa_action(fsa_data, A_EXIT_0, do_exit);

            /* Error checking and reporting */
        } else {
            pcmk__err("Action %s not supported " QB_XS " %" PRIx64,
                      fsa_action2string(controld_globals.fsa_actions),
                      controld_globals.fsa_actions);
            register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, fsa_data, NULL,
                                   __func__);
        }
    }
}

void
log_fsa_input(fsa_data_t * stored_msg)
{
    pcmk__assert(stored_msg != NULL);
    crm_trace("Processing queued input %d", stored_msg->id);
    if (stored_msg->fsa_cause == C_LRM_OP_CALLBACK) {
        crm_trace("FSA processing LRM callback from %s", stored_msg->origin);

    } else if (stored_msg->data == NULL) {
        crm_trace("FSA processing input from %s", stored_msg->origin);

    } else {
        ha_msg_input_t *ha_input = fsa_typed_data_adv(stored_msg, fsa_dt_ha_msg,
                                                      __func__);

        crm_trace("FSA processing XML message from %s", stored_msg->origin);
        crm_log_xml_trace(ha_input->xml, "FSA message data");
    }
}

static void
check_join_counts(fsa_data_t *msg_data)
{
    int count;
    guint npeers;

    count = crmd_join_phase_count(controld_join_finalized);
    if (count > 0) {
        pcmk__err("%d cluster node%s failed to confirm join", count,
                  pcmk__plural_s(count));
        crmd_join_phase_log(LOG_NOTICE);
        return;
    }

    npeers = pcmk__cluster_num_active_nodes();
    count = crmd_join_phase_count(controld_join_confirmed);
    if (count == npeers) {
        if (npeers == 1) {
            crm_debug("Sole active cluster node is fully joined");
        } else {
            crm_debug("All %d active cluster nodes are fully joined", count);
        }

    } else if (count > npeers) {
        pcmk__err("New election needed because more nodes confirmed join "
                  "than are in membership (%d > %u)",
                  count, npeers);
        register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);

    } else if (controld_globals.membership_id != controld_globals.peer_seq) {
        crm_info("New join needed because membership changed (%llu -> %llu)",
                 controld_globals.membership_id, controld_globals.peer_seq);
        register_fsa_input_before(C_FSA_INTERNAL, I_NODE_JOIN, NULL);

    } else {
        pcmk__warn("Only %d of %u active cluster nodes fully joined (%d did "
                   "not respond to offer)",
                   count, npeers,
                   crmd_join_phase_count(controld_join_welcomed));
    }
}

static void
do_state_transition(enum crmd_fsa_state cur_state,
                    enum crmd_fsa_state next_state, fsa_data_t *msg_data)
{
    int level = LOG_INFO;
    int count = 0;
    gboolean clear_recovery_bit = TRUE;
#if 0
    uint64_t original_fsa_actions = controld_globals.fsa_actions;
#endif

    enum crmd_fsa_cause cause = msg_data->fsa_cause;
    enum crmd_fsa_input current_input = msg_data->fsa_input;

    const char *state_from = fsa_state2string(cur_state);
    const char *state_to = fsa_state2string(next_state);
    const char *input = fsa_input2string(current_input);

    CRM_LOG_ASSERT(cur_state != next_state);

    if (cur_state == S_IDLE || next_state == S_IDLE) {
        level = LOG_NOTICE;
    } else if (cur_state == S_NOT_DC || next_state == S_NOT_DC) {
        level = LOG_NOTICE;
    } else if (cur_state == S_ELECTION) {
        level = LOG_NOTICE;
    } else if (cur_state == S_STARTING) {
        level = LOG_NOTICE;
    } else if (next_state == S_RECOVERY) {
        level = LOG_WARNING;
    }

    do_crm_log(level, "State transition %s -> %s "
               QB_XS " input=%s cause=%s origin=%s",
               state_from, state_to, input, fsa_cause2string(cause),
               msg_data->origin);

    if (next_state != S_ELECTION && cur_state != S_RELEASE_DC) {
        controld_stop_current_election_timeout();
    }
    if (next_state == S_INTEGRATION) {
        controld_set_fsa_action_flags(A_INTEGRATE_TIMER_START);
    } else {
        controld_set_fsa_action_flags(A_INTEGRATE_TIMER_STOP);
    }

    if (next_state == S_FINALIZE_JOIN) {
        controld_set_fsa_action_flags(A_FINALIZE_TIMER_START);
    } else {
        controld_set_fsa_action_flags(A_FINALIZE_TIMER_STOP);
    }

    if (next_state != S_PENDING) {
        controld_set_fsa_action_flags(A_DC_TIMER_STOP);
    }
    if (next_state != S_IDLE) {
        controld_stop_recheck_timer();
    }

    if (cur_state == S_FINALIZE_JOIN && next_state == S_POLICY_ENGINE) {
        populate_cib_nodes(node_update_quick|node_update_all, __func__);
    }

    switch (next_state) {
        case S_PENDING:
            {
                cib_t *cib_conn = controld_globals.cib_conn;
                cib_conn->cmds->set_secondary(cib_conn, cib_none);
            }
            update_dc(NULL);
            break;

        case S_ELECTION:
            update_dc(NULL);
            break;

        case S_NOT_DC:
            controld_reset_counter_election_timer();
            purge_stonith_cleanup();

            if (pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
                crm_info("(Re)Issuing shutdown request now" " that we have a new DC");
                controld_set_fsa_action_flags(A_SHUTDOWN_REQ);
            }
            CRM_LOG_ASSERT(controld_globals.dc_name != NULL);
            if (controld_globals.dc_name == NULL) {
                pcmk__err("Reached S_NOT_DC without a DC" " being recorded");
            }
            break;

        case S_RECOVERY:
            clear_recovery_bit = FALSE;
            break;

        case S_FINALIZE_JOIN:
            CRM_LOG_ASSERT(AM_I_DC);
            if (cause == C_TIMER_POPPED) {
                pcmk__warn("Progressed to state %s after %s",
                           fsa_state2string(next_state),
                           fsa_cause2string(cause));
            }
            count = crmd_join_phase_count(controld_join_welcomed);
            if (count > 0) {
                pcmk__warn("%d cluster node%s failed to respond to join offer",
                           count, pcmk__plural_s(count));
                crmd_join_phase_log(LOG_NOTICE);

            } else {
                crm_debug("All cluster nodes (%d) responded to join offer",
                          crmd_join_phase_count(controld_join_integrated));
            }
            break;

        case S_POLICY_ENGINE:
            controld_reset_counter_election_timer();
            CRM_LOG_ASSERT(AM_I_DC);
            if (cause == C_TIMER_POPPED) {
                crm_info("Progressed to state %s after %s",
                         fsa_state2string(next_state), fsa_cause2string(cause));
            }
            check_join_counts(msg_data);
            break;

        case S_STOPPING:
        case S_TERMINATE:
            /* possibly redundant */
            controld_set_fsa_input_flags(R_SHUTDOWN);
            break;

        case S_IDLE:
            CRM_LOG_ASSERT(AM_I_DC);
            if (pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
                crm_info("(Re)Issuing shutdown request now" " that we are the DC");
                controld_set_fsa_action_flags(A_SHUTDOWN_REQ);
            }
            controld_start_recheck_timer();
            break;

        default:
            break;
    }

    if (clear_recovery_bit && next_state != S_PENDING) {
        controld_clear_fsa_action_flags(A_RECOVER);
    } else if (clear_recovery_bit == FALSE) {
        controld_set_fsa_action_flags(A_RECOVER);
    }

#if 0
    if (original_fsa_actions != controld_globals.fsa_actions) {
        fsa_dump_actions(original_fsa_actions ^ controld_globals.fsa_actions,
                         "New actions");
    }
#endif
}

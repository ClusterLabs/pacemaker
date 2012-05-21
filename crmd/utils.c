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
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/attrd.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/cluster.h>

#include <crmd_fsa.h>
#include <crmd_utils.h>
#include <crmd_messages.h>

/*	A_DC_TIMER_STOP, A_DC_TIMER_START,
 *	A_FINALIZE_TIMER_STOP, A_FINALIZE_TIMER_START
 *	A_INTEGRATE_TIMER_STOP, A_INTEGRATE_TIMER_START
 */
void
do_timer_control(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean timer_op_ok = TRUE;

    if (action & A_DC_TIMER_STOP) {
        timer_op_ok = crm_timer_stop(election_trigger);

    } else if (action & A_FINALIZE_TIMER_STOP) {
        timer_op_ok = crm_timer_stop(finalization_timer);

    } else if (action & A_INTEGRATE_TIMER_STOP) {
        timer_op_ok = crm_timer_stop(integration_timer);

/* 	} else if(action & A_ELECTION_TIMEOUT_STOP) { */
/* 		timer_op_ok = crm_timer_stop(election_timeout); */
    }

    /* dont start a timer that wasnt already running */
    if (action & A_DC_TIMER_START && timer_op_ok) {
        crm_timer_start(election_trigger);
        if (AM_I_DC) {
            /* there can be only one */
            register_fsa_input(cause, I_ELECTION, NULL);
        }

    } else if (action & A_FINALIZE_TIMER_START) {
        crm_timer_start(finalization_timer);

    } else if (action & A_INTEGRATE_TIMER_START) {
        crm_timer_start(integration_timer);

/* 	} else if(action & A_ELECTION_TIMEOUT_START) { */
/* 		crm_timer_start(election_timeout); */
    }
}

const char *
get_timer_desc(fsa_timer_t * timer)
{
    if (timer == election_trigger) {
        return "Election Trigger";

    } else if (timer == election_timeout) {
        return "Election Timeout";

    } else if (timer == shutdown_escalation_timer) {
        return "Shutdown Escalation";

    } else if (timer == integration_timer) {
        return "Integration Timer";

    } else if (timer == finalization_timer) {
        return "Finalization Timer";

    } else if (timer == transition_timer) {
        return "New Transition Timer";

    } else if (timer == wait_timer) {
        return "Wait Timer";

    } else if (timer == recheck_timer) {
        return "PEngine Recheck Timer";

    }
    return "Unknown Timer";
}

gboolean
crm_timer_popped(gpointer data)
{
    fsa_timer_t *timer = (fsa_timer_t *) data;

    if (timer == wait_timer
        || timer == recheck_timer
        || timer == transition_timer || timer == finalization_timer || timer == election_trigger) {
        crm_info("%s (%s) just popped (%dms)",
                 get_timer_desc(timer), fsa_input2string(timer->fsa_input), timer->period_ms);
        timer->counter++;

    } else {
        crm_err("%s (%s) just popped in state %s! (%dms)",
                get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                fsa_state2string(fsa_state), timer->period_ms);
    }

    if(timer == election_trigger && election_trigger->counter > 5) {
        crm_notice("We appear to be in an election loop, something may be wrong");
        election_trigger->counter = 0;
    }

    if (timer->repeat == FALSE) {
        crm_timer_stop(timer);  /* make it _not_ go off again */
    }

    if (timer->fsa_input == I_INTEGRATED) {
        crm_info("Welcomed: %d, Integrated: %d",
                 g_hash_table_size(welcomed_nodes), g_hash_table_size(integrated_nodes));
        if (g_hash_table_size(welcomed_nodes) == 0) {
            /* If we don't even have ourself, start again */
            register_fsa_error_adv(C_FSA_INTERNAL, I_ELECTION, NULL, NULL, __FUNCTION__);

        } else {
            register_fsa_input_before(C_TIMER_POPPED, timer->fsa_input, NULL);
        }

    } else if (timer == recheck_timer && fsa_state != S_IDLE) {
        crm_debug("Discarding %s event in state: %s",
                  fsa_input2string(timer->fsa_input), fsa_state2string(fsa_state));

    } else if (timer == finalization_timer && fsa_state != S_FINALIZE_JOIN) {
        crm_debug("Discarding %s event in state: %s",
                  fsa_input2string(timer->fsa_input), fsa_state2string(fsa_state));

    } else if (timer->fsa_input != I_NULL) {
        register_fsa_input(C_TIMER_POPPED, timer->fsa_input, NULL);
    }

    crm_trace("Triggering FSA: %s", __FUNCTION__);
    mainloop_set_trigger(fsa_source);

    return TRUE;
}

gboolean
crm_timer_start(fsa_timer_t * timer)
{
    const char *timer_desc = get_timer_desc(timer);

    if (timer->source_id == 0 && timer->period_ms > 0) {
        timer->source_id = g_timeout_add(timer->period_ms, timer->callback, (void *)timer);
        CRM_ASSERT(timer->source_id != 0);
        crm_debug("Started %s (%s:%dms), src=%d",
                  timer_desc, fsa_input2string(timer->fsa_input),
                  timer->period_ms, timer->source_id);

    } else if (timer->period_ms < 0) {
        crm_err("Tried to start %s (%s:%dms) with a -ve period",
                timer_desc, fsa_input2string(timer->fsa_input), timer->period_ms);

    } else {
        crm_debug("%s (%s:%dms) already running: src=%d",
                  timer_desc, fsa_input2string(timer->fsa_input),
                  timer->period_ms, timer->source_id);
        return FALSE;
    }
    return TRUE;
}

gboolean
crm_timer_stop(fsa_timer_t * timer)
{
    const char *timer_desc = get_timer_desc(timer);

    if (timer == NULL) {
        crm_err("Attempted to stop NULL timer");
        return FALSE;

    } else if (timer->source_id != 0) {
        crm_trace("Stopping %s (%s:%dms), src=%d",
                    timer_desc, fsa_input2string(timer->fsa_input),
                    timer->period_ms, timer->source_id);
        g_source_remove(timer->source_id);
        timer->source_id = 0;

    } else {
        crm_trace("%s (%s:%dms) already stopped",
                    timer_desc, fsa_input2string(timer->fsa_input), timer->period_ms);
        return FALSE;
    }
    return TRUE;
}

const char *
fsa_input2string(enum crmd_fsa_input input)
{
    const char *inputAsText = NULL;

    switch (input) {
        case I_NULL:
            inputAsText = "I_NULL";
            break;
        case I_CIB_OP:
            inputAsText = "I_CIB_OP (unused)";
            break;
        case I_CIB_UPDATE:
            inputAsText = "I_CIB_UPDATE";
            break;
        case I_DC_TIMEOUT:
            inputAsText = "I_DC_TIMEOUT";
            break;
        case I_ELECTION:
            inputAsText = "I_ELECTION";
            break;
        case I_PE_CALC:
            inputAsText = "I_PE_CALC";
            break;
        case I_RELEASE_DC:
            inputAsText = "I_RELEASE_DC";
            break;
        case I_ELECTION_DC:
            inputAsText = "I_ELECTION_DC";
            break;
        case I_ERROR:
            inputAsText = "I_ERROR";
            break;
        case I_FAIL:
            inputAsText = "I_FAIL";
            break;
        case I_INTEGRATED:
            inputAsText = "I_INTEGRATED";
            break;
        case I_FINALIZED:
            inputAsText = "I_FINALIZED";
            break;
        case I_NODE_JOIN:
            inputAsText = "I_NODE_JOIN";
            break;
        case I_JOIN_OFFER:
            inputAsText = "I_JOIN_OFFER";
            break;
        case I_JOIN_REQUEST:
            inputAsText = "I_JOIN_REQUEST";
            break;
        case I_JOIN_RESULT:
            inputAsText = "I_JOIN_RESULT";
            break;
        case I_NOT_DC:
            inputAsText = "I_NOT_DC";
            break;
        case I_RECOVERED:
            inputAsText = "I_RECOVERED";
            break;
        case I_RELEASE_FAIL:
            inputAsText = "I_RELEASE_FAIL";
            break;
        case I_RELEASE_SUCCESS:
            inputAsText = "I_RELEASE_SUCCESS";
            break;
        case I_RESTART:
            inputAsText = "I_RESTART";
            break;
        case I_PE_SUCCESS:
            inputAsText = "I_PE_SUCCESS";
            break;
        case I_ROUTER:
            inputAsText = "I_ROUTER";
            break;
        case I_SHUTDOWN:
            inputAsText = "I_SHUTDOWN";
            break;
        case I_STARTUP:
            inputAsText = "I_STARTUP";
            break;
        case I_TE_SUCCESS:
            inputAsText = "I_TE_SUCCESS";
            break;
        case I_STOP:
            inputAsText = "I_STOP";
            break;
        case I_DC_HEARTBEAT:
            inputAsText = "I_DC_HEARTBEAT";
            break;
        case I_WAIT_FOR_EVENT:
            inputAsText = "I_WAIT_FOR_EVENT";
            break;
        case I_LRM_EVENT:
            inputAsText = "I_LRM_EVENT";
            break;
        case I_PENDING:
            inputAsText = "I_PENDING";
            break;
        case I_HALT:
            inputAsText = "I_HALT";
            break;
        case I_TERMINATE:
            inputAsText = "I_TERMINATE";
            break;
        case I_ILLEGAL:
            inputAsText = "I_ILLEGAL";
            break;
    }

    if (inputAsText == NULL) {
        crm_err("Input %d is unknown", input);
        inputAsText = "<UNKNOWN_INPUT>";
    }

    return inputAsText;
}

const char *
fsa_state2string(enum crmd_fsa_state state)
{
    const char *stateAsText = NULL;

    switch (state) {
        case S_IDLE:
            stateAsText = "S_IDLE";
            break;
        case S_ELECTION:
            stateAsText = "S_ELECTION";
            break;
        case S_INTEGRATION:
            stateAsText = "S_INTEGRATION";
            break;
        case S_FINALIZE_JOIN:
            stateAsText = "S_FINALIZE_JOIN";
            break;
        case S_NOT_DC:
            stateAsText = "S_NOT_DC";
            break;
        case S_POLICY_ENGINE:
            stateAsText = "S_POLICY_ENGINE";
            break;
        case S_RECOVERY:
            stateAsText = "S_RECOVERY";
            break;
        case S_RELEASE_DC:
            stateAsText = "S_RELEASE_DC";
            break;
        case S_PENDING:
            stateAsText = "S_PENDING";
            break;
        case S_STOPPING:
            stateAsText = "S_STOPPING";
            break;
        case S_TERMINATE:
            stateAsText = "S_TERMINATE";
            break;
        case S_TRANSITION_ENGINE:
            stateAsText = "S_TRANSITION_ENGINE";
            break;
        case S_STARTING:
            stateAsText = "S_STARTING";
            break;
        case S_HALT:
            stateAsText = "S_HALT";
            break;
        case S_ILLEGAL:
            stateAsText = "S_ILLEGAL";
            break;
    }

    if (stateAsText == NULL) {
        crm_err("State %d is unknown", state);
        stateAsText = "<UNKNOWN_STATE>";
    }

    return stateAsText;
}

const char *
fsa_cause2string(enum crmd_fsa_cause cause)
{
    const char *causeAsText = NULL;

    switch (cause) {
        case C_UNKNOWN:
            causeAsText = "C_UNKNOWN";
            break;
        case C_STARTUP:
            causeAsText = "C_STARTUP";
            break;
        case C_IPC_MESSAGE:
            causeAsText = "C_IPC_MESSAGE";
            break;
        case C_HA_MESSAGE:
            causeAsText = "C_HA_MESSAGE";
            break;
        case C_CCM_CALLBACK:
            causeAsText = "C_CCM_CALLBACK";
            break;
        case C_TIMER_POPPED:
            causeAsText = "C_TIMER_POPPED";
            break;
        case C_SHUTDOWN:
            causeAsText = "C_SHUTDOWN";
            break;
        case C_HEARTBEAT_FAILED:
            causeAsText = "C_HEARTBEAT_FAILED";
            break;
        case C_SUBSYSTEM_CONNECT:
            causeAsText = "C_SUBSYSTEM_CONNECT";
            break;
        case C_LRM_OP_CALLBACK:
            causeAsText = "C_LRM_OP_CALLBACK";
            break;
        case C_LRM_MONITOR_CALLBACK:
            causeAsText = "C_LRM_MONITOR_CALLBACK";
            break;
        case C_CRMD_STATUS_CALLBACK:
            causeAsText = "C_CRMD_STATUS_CALLBACK";
            break;
        case C_HA_DISCONNECT:
            causeAsText = "C_HA_DISCONNECT";
            break;
        case C_FSA_INTERNAL:
            causeAsText = "C_FSA_INTERNAL";
            break;
        case C_ILLEGAL:
            causeAsText = "C_ILLEGAL";
            break;
    }

    if (causeAsText == NULL) {
        crm_err("Cause %d is unknown", cause);
        causeAsText = "<UNKNOWN_CAUSE>";
    }

    return causeAsText;
}

const char *
fsa_action2string(long long action)
{
    const char *actionAsText = NULL;

    switch (action) {

        case A_NOTHING:
            actionAsText = "A_NOTHING";
            break;
        case A_ELECTION_START:
            actionAsText = "A_ELECTION_START";
            break;
        case A_DC_JOIN_FINAL:
            actionAsText = "A_DC_JOIN_FINAL";
            break;
        case A_READCONFIG:
            actionAsText = "A_READCONFIG";
            break;
        case O_RELEASE:
            actionAsText = "O_RELEASE";
            break;
        case A_STARTUP:
            actionAsText = "A_STARTUP";
            break;
        case A_STARTED:
            actionAsText = "A_STARTED";
            break;
        case A_HA_CONNECT:
            actionAsText = "A_HA_CONNECT";
            break;
        case A_HA_DISCONNECT:
            actionAsText = "A_HA_DISCONNECT";
            break;
        case A_LRM_CONNECT:
            actionAsText = "A_LRM_CONNECT";
            break;
        case A_LRM_EVENT:
            actionAsText = "A_LRM_EVENT";
            break;
        case A_LRM_INVOKE:
            actionAsText = "A_LRM_INVOKE";
            break;
        case A_LRM_DISCONNECT:
            actionAsText = "A_LRM_DISCONNECT";
            break;
        case O_LRM_RECONNECT:
            actionAsText = "O_LRM_RECONNECT";
            break;
        case A_CL_JOIN_QUERY:
            actionAsText = "A_CL_JOIN_QUERY";
            break;
        case A_DC_TIMER_STOP:
            actionAsText = "A_DC_TIMER_STOP";
            break;
        case A_DC_TIMER_START:
            actionAsText = "A_DC_TIMER_START";
            break;
        case A_INTEGRATE_TIMER_START:
            actionAsText = "A_INTEGRATE_TIMER_START";
            break;
        case A_INTEGRATE_TIMER_STOP:
            actionAsText = "A_INTEGRATE_TIMER_STOP";
            break;
        case A_FINALIZE_TIMER_START:
            actionAsText = "A_FINALIZE_TIMER_START";
            break;
        case A_FINALIZE_TIMER_STOP:
            actionAsText = "A_FINALIZE_TIMER_STOP";
            break;
        case A_ELECTION_COUNT:
            actionAsText = "A_ELECTION_COUNT";
            break;
        case A_ELECTION_VOTE:
            actionAsText = "A_ELECTION_VOTE";
            break;
        case A_ELECTION_CHECK:
            actionAsText = "A_ELECTION_CHECK";
            break;
        case A_CL_JOIN_ANNOUNCE:
            actionAsText = "A_CL_JOIN_ANNOUNCE";
            break;
        case A_CL_JOIN_REQUEST:
            actionAsText = "A_CL_JOIN_REQUEST";
            break;
        case A_CL_JOIN_RESULT:
            actionAsText = "A_CL_JOIN_RESULT";
            break;
        case A_DC_JOIN_OFFER_ALL:
            actionAsText = "A_DC_JOIN_OFFER_ALL";
            break;
        case A_DC_JOIN_OFFER_ONE:
            actionAsText = "A_DC_JOIN_OFFER_ONE";
            break;
        case A_DC_JOIN_PROCESS_REQ:
            actionAsText = "A_DC_JOIN_PROCESS_REQ";
            break;
        case A_DC_JOIN_PROCESS_ACK:
            actionAsText = "A_DC_JOIN_PROCESS_ACK";
            break;
        case A_DC_JOIN_FINALIZE:
            actionAsText = "A_DC_JOIN_FINALIZE";
            break;
        case A_MSG_PROCESS:
            actionAsText = "A_MSG_PROCESS";
            break;
        case A_MSG_ROUTE:
            actionAsText = "A_MSG_ROUTE";
            break;
        case A_RECOVER:
            actionAsText = "A_RECOVER";
            break;
        case A_DC_RELEASE:
            actionAsText = "A_DC_RELEASE";
            break;
        case A_DC_RELEASED:
            actionAsText = "A_DC_RELEASED";
            break;
        case A_DC_TAKEOVER:
            actionAsText = "A_DC_TAKEOVER";
            break;
        case A_SHUTDOWN:
            actionAsText = "A_SHUTDOWN";
            break;
        case A_SHUTDOWN_REQ:
            actionAsText = "A_SHUTDOWN_REQ";
            break;
        case A_STOP:
            actionAsText = "A_STOP  ";
            break;
        case A_EXIT_0:
            actionAsText = "A_EXIT_0";
            break;
        case A_EXIT_1:
            actionAsText = "A_EXIT_1";
            break;
        case A_CCM_CONNECT:
            actionAsText = "A_CCM_CONNECT";
            break;
        case A_CCM_DISCONNECT:
            actionAsText = "A_CCM_DISCONNECT";
            break;
        case O_CIB_RESTART:
            actionAsText = "O_CIB_RESTART";
            break;
        case A_CIB_START:
            actionAsText = "A_CIB_START";
            break;
        case A_CIB_STOP:
            actionAsText = "A_CIB_STOP";
            break;
        case A_TE_INVOKE:
            actionAsText = "A_TE_INVOKE";
            break;
        case O_TE_RESTART:
            actionAsText = "O_TE_RESTART";
            break;
        case A_TE_START:
            actionAsText = "A_TE_START";
            break;
        case A_TE_STOP:
            actionAsText = "A_TE_STOP";
            break;
        case A_TE_HALT:
            actionAsText = "A_TE_HALT";
            break;
        case A_TE_CANCEL:
            actionAsText = "A_TE_CANCEL";
            break;
        case A_PE_INVOKE:
            actionAsText = "A_PE_INVOKE";
            break;
        case O_PE_RESTART:
            actionAsText = "O_PE_RESTART";
            break;
        case A_PE_START:
            actionAsText = "A_PE_START";
            break;
        case A_PE_STOP:
            actionAsText = "A_PE_STOP";
            break;
        case A_NODE_BLOCK:
            actionAsText = "A_NODE_BLOCK";
            break;
        case A_UPDATE_NODESTATUS:
            actionAsText = "A_UPDATE_NODESTATUS";
            break;
        case A_LOG:
            actionAsText = "A_LOG   ";
            break;
        case A_ERROR:
            actionAsText = "A_ERROR ";
            break;
        case A_WARN:
            actionAsText = "A_WARN  ";
            break;
            /* Composite actions */
        case A_DC_TIMER_START | A_CL_JOIN_QUERY:
            actionAsText = "A_DC_TIMER_START|A_CL_JOIN_QUERY";
            break;
    }

    if (actionAsText == NULL) {
        crm_err("Action %.16llx is unknown", action);
        actionAsText = "<UNKNOWN_ACTION>";
    }

    return actionAsText;
}

void
fsa_dump_inputs(int log_level, const char *text, long long input_register)
{
    if (input_register == A_NOTHING) {
        return;
    }
    if (text == NULL) {
        text = "Input register contents:";
    }

    if (is_set(input_register, R_THE_DC)) {
        crm_trace( "%s %.16llx (R_THE_DC)", text, R_THE_DC);
    }
    if (is_set(input_register, R_STARTING)) {
        crm_trace( "%s %.16llx (R_STARTING)", text, R_STARTING);
    }
    if (is_set(input_register, R_SHUTDOWN)) {
        crm_trace( "%s %.16llx (R_SHUTDOWN)", text, R_SHUTDOWN);
    }
    if (is_set(input_register, R_STAYDOWN)) {
        crm_trace( "%s %.16llx (R_STAYDOWN)", text, R_STAYDOWN);
    }
    if (is_set(input_register, R_JOIN_OK)) {
        crm_trace( "%s %.16llx (R_JOIN_OK)", text, R_JOIN_OK);
    }
    if (is_set(input_register, R_READ_CONFIG)) {
        crm_trace( "%s %.16llx (R_READ_CONFIG)", text, R_READ_CONFIG);
    }
    if (is_set(input_register, R_INVOKE_PE)) {
        crm_trace( "%s %.16llx (R_INVOKE_PE)", text, R_INVOKE_PE);
    }
    if (is_set(input_register, R_CIB_CONNECTED)) {
        crm_trace( "%s %.16llx (R_CIB_CONNECTED)", text, R_CIB_CONNECTED);
    }
    if (is_set(input_register, R_PE_CONNECTED)) {
        crm_trace( "%s %.16llx (R_PE_CONNECTED)", text, R_PE_CONNECTED);
    }
    if (is_set(input_register, R_TE_CONNECTED)) {
        crm_trace( "%s %.16llx (R_TE_CONNECTED)", text, R_TE_CONNECTED);
    }
    if (is_set(input_register, R_LRM_CONNECTED)) {
        crm_trace( "%s %.16llx (R_LRM_CONNECTED)", text, R_LRM_CONNECTED);
    }
    if (is_set(input_register, R_CIB_REQUIRED)) {
        crm_trace( "%s %.16llx (R_CIB_REQUIRED)", text, R_CIB_REQUIRED);
    }
    if (is_set(input_register, R_PE_REQUIRED)) {
        crm_trace( "%s %.16llx (R_PE_REQUIRED)", text, R_PE_REQUIRED);
    }
    if (is_set(input_register, R_TE_REQUIRED)) {
        crm_trace( "%s %.16llx (R_TE_REQUIRED)", text, R_TE_REQUIRED);
    }
    if (is_set(input_register, R_REQ_PEND)) {
        crm_trace( "%s %.16llx (R_REQ_PEND)", text, R_REQ_PEND);
    }
    if (is_set(input_register, R_PE_PEND)) {
        crm_trace( "%s %.16llx (R_PE_PEND)", text, R_PE_PEND);
    }
    if (is_set(input_register, R_TE_PEND)) {
        crm_trace( "%s %.16llx (R_TE_PEND)", text, R_TE_PEND);
    }
    if (is_set(input_register, R_RESP_PEND)) {
        crm_trace( "%s %.16llx (R_RESP_PEND)", text, R_RESP_PEND);
    }
    if (is_set(input_register, R_CIB_DONE)) {
        crm_trace( "%s %.16llx (R_CIB_DONE)", text, R_CIB_DONE);
    }
    if (is_set(input_register, R_HAVE_CIB)) {
        crm_trace( "%s %.16llx (R_HAVE_CIB)", text, R_HAVE_CIB);
    }
    if (is_set(input_register, R_CIB_ASKED)) {
        crm_trace( "%s %.16llx (R_CIB_ASKED)", text, R_CIB_ASKED);
    }
    if (is_set(input_register, R_MEMBERSHIP)) {
        crm_trace( "%s %.16llx (R_MEMBERSHIP)", text, R_MEMBERSHIP);
    }
    if (is_set(input_register, R_PEER_DATA)) {
        crm_trace( "%s %.16llx (R_PEER_DATA)", text, R_PEER_DATA);
    }
    if (is_set(input_register, R_IN_RECOVERY)) {
        crm_trace( "%s %.16llx (R_IN_RECOVERY)", text, R_IN_RECOVERY);
    }
}

void
fsa_dump_actions(long long action, const char *text)
{
    if (is_set(action, A_READCONFIG)) {
        crm_trace( "Action %.16llx (A_READCONFIG) %s", A_READCONFIG, text);
    }
    if (is_set(action, A_STARTUP)) {
        crm_trace( "Action %.16llx (A_STARTUP) %s", A_STARTUP, text);
    }
    if (is_set(action, A_STARTED)) {
        crm_trace( "Action %.16llx (A_STARTED) %s", A_STARTED, text);
    }
    if (is_set(action, A_HA_CONNECT)) {
        crm_trace( "Action %.16llx (A_CONNECT) %s", A_HA_CONNECT, text);
    }
    if (is_set(action, A_HA_DISCONNECT)) {
        crm_trace( "Action %.16llx (A_DISCONNECT) %s", A_HA_DISCONNECT, text);
    }
    if (is_set(action, A_LRM_CONNECT)) {
        crm_trace( "Action %.16llx (A_LRM_CONNECT) %s", A_LRM_CONNECT, text);
    }
    if (is_set(action, A_LRM_EVENT)) {
        crm_trace( "Action %.16llx (A_LRM_EVENT) %s", A_LRM_EVENT, text);
    }
    if (is_set(action, A_LRM_INVOKE)) {
        crm_trace( "Action %.16llx (A_LRM_INVOKE) %s", A_LRM_INVOKE, text);
    }
    if (is_set(action, A_LRM_DISCONNECT)) {
        crm_trace(
                            "Action %.16llx (A_LRM_DISCONNECT) %s", A_LRM_DISCONNECT, text);
    }
    if (is_set(action, A_DC_TIMER_STOP)) {
        crm_trace(
                            "Action %.16llx (A_DC_TIMER_STOP) %s", A_DC_TIMER_STOP, text);
    }
    if (is_set(action, A_DC_TIMER_START)) {
        crm_trace(
                            "Action %.16llx (A_DC_TIMER_START) %s", A_DC_TIMER_START, text);
    }
    if (is_set(action, A_INTEGRATE_TIMER_START)) {
        crm_trace(
                            "Action %.16llx (A_INTEGRATE_TIMER_START) %s",
                            A_INTEGRATE_TIMER_START, text);
    }
    if (is_set(action, A_INTEGRATE_TIMER_STOP)) {
        crm_trace(
                            "Action %.16llx (A_INTEGRATE_TIMER_STOP) %s",
                            A_INTEGRATE_TIMER_STOP, text);
    }
    if (is_set(action, A_FINALIZE_TIMER_START)) {
        crm_trace(
                            "Action %.16llx (A_FINALIZE_TIMER_START) %s",
                            A_FINALIZE_TIMER_START, text);
    }
    if (is_set(action, A_FINALIZE_TIMER_STOP)) {
        crm_trace(
                            "Action %.16llx (A_FINALIZE_TIMER_STOP) %s",
                            A_FINALIZE_TIMER_STOP, text);
    }
    if (is_set(action, A_ELECTION_COUNT)) {
        crm_trace(
                            "Action %.16llx (A_ELECTION_COUNT) %s", A_ELECTION_COUNT, text);
    }
    if (is_set(action, A_ELECTION_VOTE)) {
        crm_trace(
                            "Action %.16llx (A_ELECTION_VOTE) %s", A_ELECTION_VOTE, text);
    }
    if (is_set(action, A_ELECTION_CHECK)) {
        crm_trace(
                            "Action %.16llx (A_ELECTION_CHECK) %s", A_ELECTION_CHECK, text);
    }
    if (is_set(action, A_CL_JOIN_ANNOUNCE)) {
        crm_trace(
                            "Action %.16llx (A_CL_JOIN_ANNOUNCE) %s", A_CL_JOIN_ANNOUNCE, text);
    }
    if (is_set(action, A_CL_JOIN_REQUEST)) {
        crm_trace(
                            "Action %.16llx (A_CL_JOIN_REQUEST) %s", A_CL_JOIN_REQUEST, text);
    }
    if (is_set(action, A_CL_JOIN_RESULT)) {
        crm_trace(
                            "Action %.16llx (A_CL_JOIN_RESULT) %s", A_CL_JOIN_RESULT, text);
    }
    if (is_set(action, A_DC_JOIN_OFFER_ALL)) {
        crm_trace(
                            "Action %.16llx (A_DC_JOIN_OFFER_ALL) %s", A_DC_JOIN_OFFER_ALL, text);
    }
    if (is_set(action, A_DC_JOIN_OFFER_ONE)) {
        crm_trace(
                            "Action %.16llx (A_DC_JOIN_OFFER_ONE) %s", A_DC_JOIN_OFFER_ONE, text);
    }
    if (is_set(action, A_DC_JOIN_PROCESS_REQ)) {
        crm_trace(
                            "Action %.16llx (A_DC_JOIN_PROCESS_REQ) %s",
                            A_DC_JOIN_PROCESS_REQ, text);
    }
    if (is_set(action, A_DC_JOIN_PROCESS_ACK)) {
        crm_trace(
                            "Action %.16llx (A_DC_JOIN_PROCESS_ACK) %s",
                            A_DC_JOIN_PROCESS_ACK, text);
    }
    if (is_set(action, A_DC_JOIN_FINALIZE)) {
        crm_trace(
                            "Action %.16llx (A_DC_JOIN_FINALIZE) %s", A_DC_JOIN_FINALIZE, text);
    }
    if (is_set(action, A_MSG_PROCESS)) {
        crm_trace( "Action %.16llx (A_MSG_PROCESS) %s", A_MSG_PROCESS, text);
    }
    if (is_set(action, A_MSG_ROUTE)) {
        crm_trace( "Action %.16llx (A_MSG_ROUTE) %s", A_MSG_ROUTE, text);
    }
    if (is_set(action, A_RECOVER)) {
        crm_trace( "Action %.16llx (A_RECOVER) %s", A_RECOVER, text);
    }
    if (is_set(action, A_DC_RELEASE)) {
        crm_trace( "Action %.16llx (A_DC_RELEASE) %s", A_DC_RELEASE, text);
    }
    if (is_set(action, A_DC_RELEASED)) {
        crm_trace( "Action %.16llx (A_DC_RELEASED) %s", A_DC_RELEASED, text);
    }
    if (is_set(action, A_DC_TAKEOVER)) {
        crm_trace( "Action %.16llx (A_DC_TAKEOVER) %s", A_DC_TAKEOVER, text);
    }
    if (is_set(action, A_SHUTDOWN)) {
        crm_trace( "Action %.16llx (A_SHUTDOWN) %s", A_SHUTDOWN, text);
    }
    if (is_set(action, A_SHUTDOWN_REQ)) {
        crm_trace( "Action %.16llx (A_SHUTDOWN_REQ) %s", A_SHUTDOWN_REQ, text);
    }
    if (is_set(action, A_STOP)) {
        crm_trace( "Action %.16llx (A_STOP  ) %s", A_STOP, text);
    }
    if (is_set(action, A_EXIT_0)) {
        crm_trace( "Action %.16llx (A_EXIT_0) %s", A_EXIT_0, text);
    }
    if (is_set(action, A_EXIT_1)) {
        crm_trace( "Action %.16llx (A_EXIT_1) %s", A_EXIT_1, text);
    }
    if (is_set(action, A_CCM_CONNECT)) {
        crm_trace( "Action %.16llx (A_CCM_CONNECT) %s", A_CCM_CONNECT, text);
    }
    if (is_set(action, A_CCM_DISCONNECT)) {
        crm_trace(
                            "Action %.16llx (A_CCM_DISCONNECT) %s", A_CCM_DISCONNECT, text);
    }
    if (is_set(action, A_CIB_START)) {
        crm_trace( "Action %.16llx (A_CIB_START) %s", A_CIB_START, text);
    }
    if (is_set(action, A_CIB_STOP)) {
        crm_trace( "Action %.16llx (A_CIB_STOP) %s", A_CIB_STOP, text);
    }
    if (is_set(action, A_TE_INVOKE)) {
        crm_trace( "Action %.16llx (A_TE_INVOKE) %s", A_TE_INVOKE, text);
    }
    if (is_set(action, A_TE_START)) {
        crm_trace( "Action %.16llx (A_TE_START) %s", A_TE_START, text);
    }
    if (is_set(action, A_TE_STOP)) {
        crm_trace( "Action %.16llx (A_TE_STOP) %s", A_TE_STOP, text);
    }
    if (is_set(action, A_TE_CANCEL)) {
        crm_trace( "Action %.16llx (A_TE_CANCEL) %s", A_TE_CANCEL, text);
    }
    if (is_set(action, A_PE_INVOKE)) {
        crm_trace( "Action %.16llx (A_PE_INVOKE) %s", A_PE_INVOKE, text);
    }
    if (is_set(action, A_PE_START)) {
        crm_trace( "Action %.16llx (A_PE_START) %s", A_PE_START, text);
    }
    if (is_set(action, A_PE_STOP)) {
        crm_trace( "Action %.16llx (A_PE_STOP) %s", A_PE_STOP, text);
    }
    if (is_set(action, A_NODE_BLOCK)) {
        crm_trace( "Action %.16llx (A_NODE_BLOCK) %s", A_NODE_BLOCK, text);
    }
    if (is_set(action, A_UPDATE_NODESTATUS)) {
        crm_trace(
                            "Action %.16llx (A_UPDATE_NODESTATUS) %s", A_UPDATE_NODESTATUS, text);
    }
    if (is_set(action, A_LOG)) {
        crm_trace( "Action %.16llx (A_LOG   ) %s", A_LOG, text);
    }
    if (is_set(action, A_ERROR)) {
        crm_trace( "Action %.16llx (A_ERROR ) %s", A_ERROR, text);
    }
    if (is_set(action, A_WARN)) {
        crm_trace( "Action %.16llx (A_WARN  ) %s", A_WARN, text);
    }
}

void
create_node_entry(const char *uuid, const char *uname, const char *type)
{

    /* make sure a node entry exists for the new node
     *
     * this will add anyone except the first ever node in the cluster
     *   since it will also be the DC which doesnt go through the
     *   join process (with itself).  We can include a special case
     *   later if desired.
     */
    xmlNode *tmp1 = create_xml_node(NULL, XML_CIB_TAG_NODE);

    crm_trace("Creating node entry for %s", uname);
    set_uuid(tmp1, XML_ATTR_UUID, uname);

    crm_xml_add(tmp1, XML_ATTR_UNAME, uname);
    crm_xml_add(tmp1, XML_ATTR_TYPE, type);

    fsa_cib_anon_update(XML_CIB_TAG_NODES, tmp1,
                        cib_scope_local | cib_quorum_override | cib_can_create);

    free_xml(tmp1);

}

xmlNode *
create_node_state(const char *uname, const char *ha_state, const char *ccm_state,
                  const char *crmd_state, const char *join_state, const char *exp_state,
                  gboolean clear_shutdown, const char *src)
{
    xmlNode *node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);

    crm_trace("%s Creating node state entry for %s", src, uname);
    set_uuid(node_state, XML_ATTR_UUID, uname);

    if (crm_element_value(node_state, XML_ATTR_UUID) == NULL) {
        crm_debug("Node %s is not a cluster member", uname);
        free_xml(node_state);
        return NULL;
    }

    crm_xml_add(node_state, XML_ATTR_UNAME, uname);
    crm_xml_add(node_state, XML_CIB_ATTR_HASTATE, ha_state);
    crm_xml_add(node_state, XML_CIB_ATTR_INCCM, ccm_state);
    crm_xml_add(node_state, XML_CIB_ATTR_CRMDSTATE, crmd_state);
    crm_xml_add(node_state, XML_CIB_ATTR_JOINSTATE, join_state);
    crm_xml_add(node_state, XML_CIB_ATTR_EXPSTATE, exp_state);
    crm_xml_add(node_state, XML_ATTR_ORIGIN, src);

    if (clear_shutdown) {
        crm_xml_add(node_state, XML_CIB_ATTR_SHUTDOWN, "0");
    }

    crm_log_xml_trace(node_state, "created");

    return node_state;
}

extern GHashTable *ipc_clients;

void
process_client_disconnect(crmd_client_t * curr_client)
{
    struct crm_subsystem_s *the_subsystem = NULL;

    CRM_CHECK(curr_client != NULL, return);
    crm_trace("received HUP from %s", curr_client->table_key);

    if (curr_client->sub_sys == NULL) {
        crm_trace("Client hadn't registered with us yet");

    } else if (strcasecmp(CRM_SYSTEM_PENGINE, curr_client->sub_sys) == 0) {
        the_subsystem = pe_subsystem;

    } else if (strcasecmp(CRM_SYSTEM_TENGINE, curr_client->sub_sys) == 0) {
        the_subsystem = te_subsystem;

    } else if (strcasecmp(CRM_SYSTEM_CIB, curr_client->sub_sys) == 0) {
        the_subsystem = cib_subsystem;
    }

    if (the_subsystem != NULL) {
        the_subsystem->source = NULL;
        the_subsystem->client = NULL;
        crm_info("Received HUP from %s:[%d]", the_subsystem->name, the_subsystem->pid);

    } else {
        /* else that was a transient client */
        crm_trace("Received HUP from transient client");
    }

    if (curr_client->table_key != NULL) {
        /*
         * Key is destroyed below as:
         *      curr_client->table_key
         * Value is cleaned up by:
         *      crmd_ipc_connection_destroy
         *   which will also call:
         *      G_main_del_IPC_Channel
         */
        g_hash_table_remove(ipc_clients, curr_client->table_key);
    }
}

gboolean
update_dc(xmlNode * msg)
{
    char *last_dc = fsa_our_dc;
    const char *dc_version = NULL;
    const char *welcome_from = NULL;

    if (msg != NULL) {
        gboolean invalid = FALSE;

        dc_version = crm_element_value(msg, F_CRM_VERSION);
        welcome_from = crm_element_value(msg, F_CRM_HOST_FROM);

        CRM_CHECK(dc_version != NULL, return FALSE);
        CRM_CHECK(welcome_from != NULL, return FALSE);

        if (AM_I_DC && safe_str_neq(welcome_from, fsa_our_uname)) {
            invalid = TRUE;

        } else if (fsa_our_dc && safe_str_neq(welcome_from, fsa_our_dc)) {
            invalid = TRUE;
        }

        if (invalid) {
            CRM_CHECK(fsa_our_dc != NULL, crm_err("We have no DC"));
            if (AM_I_DC) {
                crm_err("Not updating DC to %s (%s): we are also a DC", welcome_from, dc_version);
            } else {
                crm_warn("New DC %s is not %s", welcome_from, fsa_our_dc);
            }

            register_fsa_action(A_CL_JOIN_QUERY | A_DC_TIMER_START);
            return FALSE;
        }
    }

    crm_free(fsa_our_dc_version);
    fsa_our_dc_version = NULL;

    fsa_our_dc = NULL;          /* Free'd as last_dc */

    if (welcome_from != NULL) {
        fsa_our_dc = crm_strdup(welcome_from);
    }
    if (dc_version != NULL) {
        fsa_our_dc_version = crm_strdup(dc_version);
    }

    if (safe_str_eq(fsa_our_dc, last_dc)) {
        /* do nothing */

    } else if (fsa_our_dc != NULL) {
        crm_info("Set DC to %s (%s)", crm_str(fsa_our_dc), crm_str(fsa_our_dc_version));

    } else if (last_dc != NULL) {
        crm_debug("Unset DC. Was %s", crm_str(last_dc));
    }

    crm_free(last_dc);
    return TRUE;
}

#define STATUS_PATH_MAX 512
static void
erase_xpath_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *xpath = user_data;

    do_crm_log(rc == 0 ? LOG_DEBUG : LOG_NOTICE,
               "Deletion of \"%s\": %s (rc=%d)", xpath, cib_error2string(rc), rc);
    crm_free(xpath);
}

void
erase_status_tag(const char *uname, const char *tag, int options)
{
    int rc = cib_ok;
    char xpath[STATUS_PATH_MAX];
    int cib_opts = cib_quorum_override | cib_xpath | options;

    if (fsa_cib_conn && uname) {
        snprintf(xpath, STATUS_PATH_MAX, "//node_state[@uname='%s']/%s", uname, tag);
        crm_info("Deleting xpath: %s", xpath);
        rc = fsa_cib_conn->cmds->delete(fsa_cib_conn, xpath, NULL, cib_opts);
        add_cib_op_callback(fsa_cib_conn, rc, FALSE, crm_strdup(xpath), erase_xpath_callback);
    }
}

crm_ipc_t *attrd_ipc = NULL;

void
update_attrd(const char *host, const char *name, const char *value, const char *user_name)
{
    gboolean rc;

    if(attrd_ipc == NULL) {
        attrd_ipc = crm_ipc_new(T_ATTRD, 0);
        crm_ipc_connect(attrd_ipc);
    }

    rc = attrd_update_delegate(attrd_ipc, 'U', host, name, value, XML_CIB_TAG_STATUS, NULL, NULL, user_name);
    
    if (rc == FALSE) {
        crm_err("Could not send %s %s %s (%d)", T_ATTRD, name ? "update" : "refresh",
                name?name:"", is_set(fsa_input_register, R_SHUTDOWN));

        if(is_set(fsa_input_register, R_SHUTDOWN)) {
            register_fsa_input(C_FSA_INTERNAL, I_FAIL, NULL);
        }
    }
}

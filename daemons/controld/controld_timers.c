/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdlib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <pacemaker-controld.h>

// Wait before retrying a failed cib or executor connection
fsa_timer_t *wait_timer = NULL;

// Periodically re-run scheduler (for date_spec evaluation and as a failsafe)
fsa_timer_t *recheck_timer = NULL;

// Wait at start-up, or after an election, for DC to make contact
fsa_timer_t *election_trigger = NULL;

// Delay start of new transition with expectation something else might happen
fsa_timer_t *transition_timer = NULL;

// join-integration-timeout
fsa_timer_t *integration_timer = NULL;

// join-finalization-timeout
fsa_timer_t *finalization_timer = NULL;

// Wait for DC to stop all resources and give us the all-clear to shut down
fsa_timer_t *shutdown_escalation_timer = NULL;

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
    }

    /* don't start a timer that wasn't already running */
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
    }
}

const char *
get_timer_desc(fsa_timer_t * timer)
{
    if (timer == election_trigger) {
        return "Election Trigger";

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
        return "Cluster Recheck Timer";

    }
    return "Unknown Timer";
}

gboolean
crm_timer_popped(gpointer data)
{
    fsa_timer_t *timer = (fsa_timer_t *) data;

    if (timer->log_error) {
        crm_err("%s (%s) just popped in state %s! (%dms)",
                get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                fsa_state2string(fsa_state), timer->period_ms);
    } else {
        crm_info("%s (%s) just popped (%dms)",
                 get_timer_desc(timer), fsa_input2string(timer->fsa_input), timer->period_ms);
        timer->counter++;
    }

    if (timer == election_trigger && election_trigger->counter > 5) {
        crm_notice("We appear to be in an election loop, something may be wrong");
        crm_write_blackbox(0, NULL);
        election_trigger->counter = 0;
    }

    crm_timer_stop(timer);  // Make timer _not_ go off again

    if (timer->fsa_input == I_INTEGRATED) {
        crm_info("Welcomed: %d, Integrated: %d",
                 crmd_join_phase_count(crm_join_welcomed),
                 crmd_join_phase_count(crm_join_integrated));
        if (crmd_join_phase_count(crm_join_welcomed) == 0) {
            // If we don't even have ourselves, start again
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
is_timer_started(fsa_timer_t * timer)
{
    if (timer->period_ms > 0) {
        if (timer->source_id == 0) {
            return FALSE;
        } else {
            return TRUE;
        }
    }
    return FALSE;
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
        crm_err("Tried to start %s (%s:%dms) with a negative period",
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

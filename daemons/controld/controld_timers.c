/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <time.h>
#include <stdlib.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <pacemaker-controld.h>

//! FSA mainloop timer type
typedef struct fsa_timer_s {
    guint source_id;                        //!< Timer source ID
    guint period_ms;                        //!< Timer period
    enum crmd_fsa_input fsa_input;          //!< Input to register if timer pops
    gboolean (*callback) (gpointer data);   //!< What do if timer pops
    bool log_error;                         //!< Timer popping indicates error
    int counter;                            //!< For detecting loops
} fsa_timer_t;

//! Wait before retrying a failed cib or executor connection
static fsa_timer_t *wait_timer = NULL;

//! Periodically re-run scheduler (for date_spec evaluation and as a failsafe)
static fsa_timer_t *recheck_timer = NULL;

//! Wait at start-up, or after an election, for DC to make contact
static fsa_timer_t *election_timer = NULL;

//! Delay start of new transition with expectation something else might happen
static fsa_timer_t *transition_timer = NULL;

//! join-integration-timeout
static fsa_timer_t *integration_timer = NULL;

//! join-finalization-timeout
static fsa_timer_t *finalization_timer = NULL;

// Wait for DC to stop all resources and give us the all-clear to shut down
fsa_timer_t *shutdown_escalation_timer = NULL;

//! Cluster recheck interval (from configuration)
static guint recheck_interval_ms = 0;

static const char *
get_timer_desc(fsa_timer_t * timer)
{
    if (timer == election_timer) {
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

/*!
 * \internal
 * \brief Stop an FSA timer
 *
 * \param[in,out] timer  Timer to stop
 *
 * \return true if the timer was running, or false otherwise
 */
static bool
controld_stop_timer(fsa_timer_t *timer)
{
    CRM_CHECK(timer != NULL, return false);

    if (timer->source_id != 0) {
        crm_trace("Stopping %s (would inject %s if popped after %ums, src=%d)",
                  get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                  timer->period_ms, timer->source_id);
        g_source_remove(timer->source_id);
        timer->source_id = 0;

    } else {
        crm_trace("%s already stopped (would inject %s if popped after %ums)",
                  get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                  timer->period_ms);
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Start an FSA timer
 *
 * \param[in,out] timer  Timer to start
 */
static void
controld_start_timer(fsa_timer_t *timer)
{
    if (timer->source_id == 0 && timer->period_ms > 0) {
        timer->source_id = g_timeout_add(timer->period_ms, timer->callback, (void *)timer);
        CRM_ASSERT(timer->source_id != 0);
        crm_debug("Started %s (inject %s if pops after %ums, source=%d)",
                  get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                  timer->period_ms, timer->source_id);
    } else {
        crm_debug("%s already running (inject %s if pops after %ums, source=%d)",
                  get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                  timer->period_ms, timer->source_id);
    }
}

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
        timer_op_ok = controld_stop_timer(election_timer);

    } else if (action & A_FINALIZE_TIMER_STOP) {
        timer_op_ok = controld_stop_timer(finalization_timer);

    } else if (action & A_INTEGRATE_TIMER_STOP) {
        timer_op_ok = controld_stop_timer(integration_timer);
    }

    /* don't start a timer that wasn't already running */
    if (action & A_DC_TIMER_START && timer_op_ok) {
        controld_start_timer(election_timer);
        if (AM_I_DC) {
            /* there can be only one */
            register_fsa_input(cause, I_ELECTION, NULL);
        }

    } else if (action & A_FINALIZE_TIMER_START) {
        controld_start_timer(finalization_timer);

    } else if (action & A_INTEGRATE_TIMER_START) {
        controld_start_timer(integration_timer);
    }
}

static gboolean
crm_timer_popped(gpointer data)
{
    fsa_timer_t *timer = (fsa_timer_t *) data;

    if (timer->log_error) {
        crm_err("%s just popped in state %s! " CRM_XS " input=%s time=%ums",
                get_timer_desc(timer),
                fsa_state2string(controld_globals.fsa_state),
                fsa_input2string(timer->fsa_input), timer->period_ms);
    } else {
        crm_info("%s just popped " CRM_XS " input=%s time=%ums",
                 get_timer_desc(timer), fsa_input2string(timer->fsa_input),
                 timer->period_ms);
        timer->counter++;
    }

    if ((timer == election_timer) && (election_timer->counter > 5)) {
        crm_notice("We appear to be in an election loop, something may be wrong");
        crm_write_blackbox(0, NULL);
        election_timer->counter = 0;
    }

    controld_stop_timer(timer);  // Make timer _not_ go off again

    if (timer->fsa_input == I_INTEGRATED) {
        crm_info("Welcomed: %d, Integrated: %d",
                 crmd_join_phase_count(crm_join_welcomed),
                 crmd_join_phase_count(crm_join_integrated));
        if (crmd_join_phase_count(crm_join_welcomed) == 0) {
            // If we don't even have ourselves, start again
            register_fsa_error_adv(C_FSA_INTERNAL, I_ELECTION, NULL, NULL,
                                   __func__);

        } else {
            register_fsa_input_before(C_TIMER_POPPED, timer->fsa_input, NULL);
        }

    } else if ((timer == recheck_timer)
               && (controld_globals.fsa_state != S_IDLE)) {
        crm_debug("Discarding %s event in state: %s",
                  fsa_input2string(timer->fsa_input),
                  fsa_state2string(controld_globals.fsa_state));

    } else if ((timer == finalization_timer)
               && (controld_globals.fsa_state != S_FINALIZE_JOIN)) {
        crm_debug("Discarding %s event in state: %s",
                  fsa_input2string(timer->fsa_input),
                  fsa_state2string(controld_globals.fsa_state));

    } else if (timer->fsa_input != I_NULL) {
        register_fsa_input(C_TIMER_POPPED, timer->fsa_input, NULL);
    }

    controld_trigger_fsa();

    return TRUE;
}

bool
controld_init_fsa_timers(void)
{
    transition_timer = calloc(1, sizeof(fsa_timer_t));
    if (transition_timer == NULL) {
        return FALSE;
    }

    integration_timer = calloc(1, sizeof(fsa_timer_t));
    if (integration_timer == NULL) {
        return FALSE;
    }

    finalization_timer = calloc(1, sizeof(fsa_timer_t));
    if (finalization_timer == NULL) {
        return FALSE;
    }

    election_timer = calloc(1, sizeof(fsa_timer_t));
    if (election_timer == NULL) {
        return FALSE;
    }

    shutdown_escalation_timer = calloc(1, sizeof(fsa_timer_t));
    if (shutdown_escalation_timer == NULL) {
        return FALSE;
    }

    wait_timer = calloc(1, sizeof(fsa_timer_t));
    if (wait_timer == NULL) {
        return FALSE;
    }

    recheck_timer = calloc(1, sizeof(fsa_timer_t));
    if (recheck_timer == NULL) {
        return FALSE;
    }

    election_timer->source_id = 0;
    election_timer->period_ms = 0;
    election_timer->fsa_input = I_DC_TIMEOUT;
    election_timer->callback = crm_timer_popped;
    election_timer->log_error = FALSE;

    transition_timer->source_id = 0;
    transition_timer->period_ms = 0;
    transition_timer->fsa_input = I_PE_CALC;
    transition_timer->callback = crm_timer_popped;
    transition_timer->log_error = FALSE;

    integration_timer->source_id = 0;
    integration_timer->period_ms = 0;
    integration_timer->fsa_input = I_INTEGRATED;
    integration_timer->callback = crm_timer_popped;
    integration_timer->log_error = TRUE;

    finalization_timer->source_id = 0;
    finalization_timer->period_ms = 0;
    finalization_timer->fsa_input = I_FINALIZED;
    finalization_timer->callback = crm_timer_popped;
    finalization_timer->log_error = FALSE;

    /* We can't use I_FINALIZED here, because that creates a bug in the join
     * process where a joining node can be stuck in S_PENDING while we think it
     * is in S_NOT_DC. This created an infinite transition loop in which we
     * continually send probes which the node NACKs because it's pending.
     *
     * If we have nodes where the cluster layer is active but the controller is
     * not, we can avoid this causing an election/join loop, in the integration
     * phase.
     */
    finalization_timer->fsa_input = I_ELECTION;

    shutdown_escalation_timer->source_id = 0;
    shutdown_escalation_timer->period_ms = 0;
    shutdown_escalation_timer->fsa_input = I_STOP;
    shutdown_escalation_timer->callback = crm_timer_popped;
    shutdown_escalation_timer->log_error = TRUE;

    wait_timer->source_id = 0;
    wait_timer->period_ms = 2000;
    wait_timer->fsa_input = I_NULL;
    wait_timer->callback = crm_timer_popped;
    wait_timer->log_error = FALSE;

    recheck_timer->source_id = 0;
    recheck_timer->period_ms = 0;
    recheck_timer->fsa_input = I_PE_CALC;
    recheck_timer->callback = crm_timer_popped;
    recheck_timer->log_error = FALSE;

    return TRUE;
}

/*!
 * \internal
 * \brief Configure timers based on the CIB
 *
 * \param[in,out] options  Name/value pairs for configured options
 */
void
controld_configure_fsa_timers(GHashTable *options)
{
    const char *value = NULL;

    // Election timer
    value = g_hash_table_lookup(options, XML_CONFIG_ATTR_DC_DEADTIME);
    election_timer->period_ms = crm_parse_interval_spec(value);

    // Integration timer
    value = g_hash_table_lookup(options, "join-integration-timeout");
    integration_timer->period_ms = crm_parse_interval_spec(value);

    // Finalization timer
    value = g_hash_table_lookup(options, "join-finalization-timeout");
    finalization_timer->period_ms = crm_parse_interval_spec(value);

    // Shutdown escalation timer
    value = g_hash_table_lookup(options, XML_CONFIG_ATTR_FORCE_QUIT);
    shutdown_escalation_timer->period_ms = crm_parse_interval_spec(value);
    crm_debug("Shutdown escalation occurs if DC has not responded to request "
              "in %ums", shutdown_escalation_timer->period_ms);

    // Transition timer
    value = g_hash_table_lookup(options, "transition-delay");
    transition_timer->period_ms = crm_parse_interval_spec(value);

    // Recheck interval
    value = g_hash_table_lookup(options, XML_CONFIG_ATTR_RECHECK);
    recheck_interval_ms = crm_parse_interval_spec(value);
    crm_debug("Re-run scheduler after %dms of inactivity", recheck_interval_ms);
}

void
controld_free_fsa_timers(void)
{
    controld_stop_timer(transition_timer);
    controld_stop_timer(integration_timer);
    controld_stop_timer(finalization_timer);
    controld_stop_timer(election_timer);
    controld_stop_timer(shutdown_escalation_timer);
    controld_stop_timer(wait_timer);
    controld_stop_timer(recheck_timer);

    free(transition_timer); transition_timer = NULL;
    free(integration_timer); integration_timer = NULL;
    free(finalization_timer); finalization_timer = NULL;
    free(election_timer); election_timer = NULL;
    free(shutdown_escalation_timer); shutdown_escalation_timer = NULL;
    free(wait_timer); wait_timer = NULL;
    free(recheck_timer); recheck_timer = NULL;
}

/*!
 * \internal
 * \brief Check whether the transition timer is started
 * \return true if the transition timer is started, or false otherwise
 */
bool
controld_is_started_transition_timer(void)
{
    return (transition_timer->period_ms > 0)
           && (transition_timer->source_id != 0);
}

/*!
 * \internal
 * \brief Start the recheck timer
 */
void
controld_start_recheck_timer(void)
{
    // Default to recheck interval configured in CIB (if any)
    guint period_ms = recheck_interval_ms;

    // If scheduler supplied a "recheck by" time, check whether that's sooner
    if (controld_globals.transition_graph->recheck_by > 0) {
        time_t diff_seconds = controld_globals.transition_graph->recheck_by
                              - time(NULL);

        if (diff_seconds < 1) {
            // We're already past the desired time
            period_ms = 500;
        } else {
            period_ms = (guint) diff_seconds * 1000;
        }

        // Use "recheck by" only if it's sooner than interval from CIB
        if (period_ms > recheck_interval_ms) {
            period_ms = recheck_interval_ms;
        }
    }

    if (period_ms > 0) {
        recheck_timer->period_ms = period_ms;
        controld_start_timer(recheck_timer);
    }
}

/*!
 * \internal
 * \brief Start the wait timer
 */
void
controld_start_wait_timer(void)
{
    controld_start_timer(wait_timer);
}

/*!
 * \internal
 * \brief Stop the recheck timer
 *
 * \return true if the recheck timer was running, or false otherwise
 */
bool
controld_stop_recheck_timer(void)
{
    return controld_stop_timer(recheck_timer);
}

/*!
 * \brief Get the transition timer's configured period
 * \return The transition_timer's period
 */
guint
controld_get_period_transition_timer(void)
{
    return transition_timer->period_ms;
}

/*!
 * \internal
 * \brief Reset the election timer's counter to 0
 */
void
controld_reset_counter_election_timer(void)
{
    election_timer->counter = 0;
}

/*!
 * \internal
 * \brief Stop the transition timer
 *
 * \return true if the transition timer was running, or false otherwise
 */
bool
controld_stop_transition_timer(void)
{
    return controld_stop_timer(transition_timer);
}

/*!
 * \internal
 * \brief Start the transition timer
 */
void
controld_start_transition_timer(void)
{
    controld_start_timer(transition_timer);
}

/*!
 * \internal
 * \brief Start the countdown sequence for a shutdown
 *
 * \param[in] default_period_ms  Period to use if the shutdown escalation
 *                               timer's period is 0
 */
void
controld_shutdown_start_countdown(guint default_period_ms)
{
    if (shutdown_escalation_timer->period_ms == 0) {
        shutdown_escalation_timer->period_ms = default_period_ms;
    }

    crm_notice("Initiating controller shutdown sequence " CRM_XS " limit=%ums",
               shutdown_escalation_timer->period_ms);
    controld_start_timer(shutdown_escalation_timer);
}

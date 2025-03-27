/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <crm/common/xml.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include <crm/crm.h>

#include <pacemaker-controld.h>

static void
election_win_cb(pcmk_cluster_t *cluster)
{
    register_fsa_input(C_FSA_INTERNAL, I_ELECTION_DC, NULL);
}

void
controld_election_init(void)
{
    election_init(controld_globals.cluster, election_win_cb);
}

/*!
 * \internal
 * \brief Configure election options based on the CIB
 *
 * \param[in,out] options  Name/value pairs for configured options
 */
void
controld_configure_election(GHashTable *options)
{
    const char *value = g_hash_table_lookup(options, PCMK_OPT_ELECTION_TIMEOUT);
    guint interval_ms = 0U;

    pcmk_parse_interval_spec(value, &interval_ms);
    election_timeout_set_period(controld_globals.cluster, interval_ms);
}

void
controld_remove_voter(const char *uname)
{
    election_remove(controld_globals.cluster, uname);

    if (pcmk__str_eq(uname, controld_globals.dc_name, pcmk__str_casei)) {
        /* Clear any election dampening in effect. Otherwise, if the lost DC had
         * just won, an immediate new election could fizzle out with no new DC.
         */
        election_clear_dampening(controld_globals.cluster);
    }
}

void
controld_stop_current_election_timeout(void)
{
    election_timeout_stop(controld_globals.cluster);
}

/*	A_ELECTION_VOTE	*/
void
do_election_vote(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean not_voting = FALSE;

    /* don't vote if we're in one of these states or wanting to shut down */
    switch (cur_state) {
        case S_STARTING:
        case S_RECOVERY:
        case S_STOPPING:
        case S_TERMINATE:
            crm_warn("Not voting in election, we're in state %s", fsa_state2string(cur_state));
            not_voting = TRUE;
            break;
        case S_ELECTION:
        case S_INTEGRATION:
        case S_RELEASE_DC:
            break;
        default:
            crm_err("Broken? Voting in state %s", fsa_state2string(cur_state));
            break;
    }

    if (not_voting == FALSE) {
        if (pcmk_is_set(controld_globals.fsa_input_register, R_STARTING)) {
            not_voting = TRUE;
        }
    }

    if (not_voting) {
        if (AM_I_DC) {
            register_fsa_input(C_FSA_INTERNAL, I_RELEASE_DC, NULL);

        } else {
            register_fsa_input(C_FSA_INTERNAL, I_PENDING, NULL);
        }
        return;
    }

    election_vote(controld_globals.cluster);
    return;
}

void
do_election_check(long long action,
                  enum crmd_fsa_cause cause,
                  enum crmd_fsa_state cur_state,
                  enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    if (controld_globals.fsa_state == S_ELECTION) {
        election_check(controld_globals.cluster);
    } else {
        crm_debug("Ignoring election check because we are not in an election");
    }
}

/*	A_ELECTION_COUNT	*/
void
do_election_count_vote(long long action,
                       enum crmd_fsa_cause cause,
                       enum crmd_fsa_state cur_state,
                       enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    enum election_result rc = 0;
    ha_msg_input_t *vote = fsa_typed_data(fsa_dt_ha_msg);

    if (pcmk__peer_cache == NULL) {
        if (!pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
            crm_err("Internal error, no peer cache");
        }
        return;
    }

    rc = election_count_vote(controld_globals.cluster, vote->msg,
                             (cur_state != S_STARTING));
    switch(rc) {
        case election_start:
            election_reset(controld_globals.cluster);
            register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
            break;

        case election_lost:
            update_dc(NULL);

            if (pcmk_is_set(controld_globals.fsa_input_register, R_THE_DC)) {
                cib_t *cib_conn = controld_globals.cib_conn;

                register_fsa_input(C_FSA_INTERNAL, I_RELEASE_DC, NULL);
                cib_conn->cmds->set_secondary(cib_conn, cib_none);

            } else if (cur_state != S_STARTING) {
                register_fsa_input(C_FSA_INTERNAL, I_PENDING, NULL);
            }
            break;

        default:
            crm_trace("Election message resulted in state %d", rc);
    }
}

static void
feature_update_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;

        crm_notice("Feature update failed: %s " QB_XS " rc=%d",
                   pcmk_strerror(rc), rc);
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

/*!
 * \internal
 * \brief Update a node attribute in the CIB during a DC takeover
 *
 * \param[in] name   Name of attribute to update
 * \param[in] value  New attribute value
 */
#define dc_takeover_update_attr(name, value) do {                           \
       cib__update_node_attr(controld_globals.logger_out,                   \
                             controld_globals.cib_conn, cib_none,           \
                             PCMK_XE_CRM_CONFIG, NULL, NULL, NULL, NULL,    \
                             name, value, NULL, NULL);                      \
    } while (0)

/*	 A_DC_TAKEOVER	*/
void
do_dc_takeover(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *cib = NULL;
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();
    const char *cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);
    pid_t watchdog = pcmk__locate_sbd();

    crm_info("Taking over DC status for this partition");
    controld_set_fsa_input_flags(R_THE_DC);
    execute_stonith_cleanup();

    election_reset(controld_globals.cluster);
    controld_set_fsa_input_flags(R_JOIN_OK|R_INVOKE_PE);

    controld_globals.cib_conn->cmds->set_primary(controld_globals.cib_conn,
                                                 cib_none);

    cib = pcmk__xe_create(NULL, PCMK_XE_CIB);
    pcmk__xe_set(cib, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    controld_update_cib(PCMK_XE_CIB, cib, cib_none, feature_update_callback);

    dc_takeover_update_attr(PCMK_OPT_HAVE_WATCHDOG, pcmk__btoa(watchdog));
    dc_takeover_update_attr(PCMK_OPT_DC_VERSION,
                            PACEMAKER_VERSION "-" BUILD_VERSION);
    dc_takeover_update_attr(PCMK_OPT_CLUSTER_INFRASTRUCTURE, cluster_layer_s);

#if SUPPORT_COROSYNC
    if ((controld_globals.cluster_name == NULL)
        && (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync)) {

        char *cluster_name = pcmk__corosync_cluster_name();

        if (cluster_name != NULL) {
            dc_takeover_update_attr(PCMK_OPT_CLUSTER_NAME, cluster_name);
        }
        free(cluster_name);
    }
#endif

    controld_trigger_config();
    pcmk__xml_free(cib);
}

/*	 A_DC_RELEASE	*/
void
do_dc_release(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    if (action & A_DC_RELEASE) {
        crm_debug("Releasing the role of DC");
        controld_clear_fsa_input_flags(R_THE_DC);
        controld_expect_sched_reply(NULL);

    } else if (action & A_DC_RELEASED) {
        crm_info("DC role released");
        if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
            xmlNode *update = NULL;
            pcmk__node_status_t *node = controld_get_local_node_status();

            pcmk__update_peer_expected(__func__, node, CRMD_JOINSTATE_DOWN);
            update = create_node_state_update(node, node_update_expected, NULL,
                                              __func__);
            /* Don't need a based response because controld will stop. */
            fsa_cib_anon_update_discard_reply(PCMK_XE_STATUS, update);
            pcmk__xml_free(update);
        }
        register_fsa_input(C_FSA_INTERNAL, I_RELEASE_SUCCESS, NULL);

    } else {
        crm_err("Unknown DC action %s", fsa_action2string(action));
    }

    crm_trace("Am I still the DC? %s", pcmk__btoa(AM_I_DC));
}

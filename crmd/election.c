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

#include <sys/time.h>
#include <sys/resource.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/cluster/internal.h>
#include <crm/crm.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <tengine.h>

#define STORM_INTERVAL   2      /* in seconds */
#define STORM_MULTIPLIER 5      /* multiplied by the number of nodes */

GHashTable *voted = NULL;
uint highest_born_on = -1;
static int current_election_id = 1;

static int
crm_uptime(struct timeval *output)
{
    static time_t expires = 0;
    static struct rusage info;

    time_t tm_now = time(NULL);

    if (expires < tm_now) {
        int rc = getrusage(RUSAGE_SELF, &info);

        output->tv_sec = 0;
        output->tv_usec = 0;

        if (rc < 0) {
            crm_perror(LOG_ERR, "Could not calculate the current uptime");
            expires = 0;
            return -1;
        }

        crm_debug("Current CPU usage is: %lds, %ldus", (long)info.ru_utime.tv_sec,
                  (long)info.ru_utime.tv_usec);
    }

    expires = tm_now + STORM_INTERVAL;  /* N seconds after the last _access_ */
    output->tv_sec = info.ru_utime.tv_sec;
    output->tv_usec = info.ru_utime.tv_usec;
    return 1;
}

static int
crm_compare_age(struct timeval your_age)
{
    struct timeval our_age;

    if (crm_uptime(&our_age) < 0) {
        return -1;
    }

    /* We want these times to be "significantly" different */

    if (our_age.tv_sec > your_age.tv_sec) {
        crm_debug("Win: %ld vs %ld (seconds)", (long)our_age.tv_sec, (long)your_age.tv_sec);
        return 1;
    } else if (our_age.tv_sec < your_age.tv_sec) {
        crm_debug("Loose: %ld vs %ld (seconds)", (long)our_age.tv_sec, (long)your_age.tv_sec);
        return -1;
    } else if (our_age.tv_usec > your_age.tv_usec) {
        crm_debug("Win: %ld.%ld vs %ld.%ld (usec)",
                  (long)our_age.tv_sec, (long)our_age.tv_usec, (long)your_age.tv_sec, (long)your_age.tv_usec);
        return 1;
    } else if (our_age.tv_usec < your_age.tv_usec) {
        crm_debug("Loose: %ld.%ld vs %ld.%ld (usec)",
                  (long)our_age.tv_sec, (long)our_age.tv_usec, (long)your_age.tv_sec, (long)your_age.tv_usec);
        return -1;
    }

    return 0;
}

/*	A_ELECTION_VOTE	*/
void
do_election_vote(long long action,
                 enum crmd_fsa_cause cause,
                 enum crmd_fsa_state cur_state,
                 enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    struct timeval age;
    xmlNode *vote = NULL;
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
        default:
            break;
    }

    if (not_voting == FALSE) {
        if (is_set(fsa_input_register, R_STARTING)) {
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

    vote = create_request(CRM_OP_VOTE, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

    current_election_id++;
    crm_xml_add(vote, F_CRM_ELECTION_OWNER, fsa_our_uuid);
    crm_xml_add_int(vote, F_CRM_ELECTION_ID, current_election_id);

    crm_uptime(&age);
    crm_xml_add_int(vote, F_CRM_ELECTION_AGE_S, age.tv_sec);
    crm_xml_add_int(vote, F_CRM_ELECTION_AGE_US, age.tv_usec);

    send_cluster_message(NULL, crm_msg_crmd, vote, TRUE);
    free_xml(vote);

    crm_debug("Started election %d", current_election_id);
    if (voted) {
        g_hash_table_destroy(voted);
    }
    voted = NULL;

    if (cur_state == S_ELECTION || cur_state == S_RELEASE_DC) {
        crm_timer_start(election_timeout);

    } else if (cur_state != S_INTEGRATION) {
        crm_err("Broken? Voting in state %s", fsa_state2string(cur_state));
    }

    return;
}

char *dc_hb_msg = NULL;
int beat_num = 0;

gboolean
do_dc_heartbeat(gpointer data)
{
    return TRUE;
}

struct election_data_s {
    const char *winning_uname;
    unsigned int winning_bornon;
};

void
do_election_check(long long action,
                  enum crmd_fsa_cause cause,
                  enum crmd_fsa_state cur_state,
                  enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int voted_size = 0;
    int num_members = crm_active_peers();

    if (voted) {
        voted_size = g_hash_table_size(voted);
    }
    /* in the case of #voted > #members, it is better to
     *   wait for the timeout and give the cluster time to
     *   stabilize
     */
    if (fsa_state != S_ELECTION) {
        crm_debug("Ignore election check: we not in an election");

    } else if (voted_size >= num_members) {
        /* we won and everyone has voted */
        crm_timer_stop(election_timeout);
        register_fsa_input(C_FSA_INTERNAL, I_ELECTION_DC, NULL);
        if (voted_size > num_members) {
            GHashTableIter gIter;
            const crm_node_t *node;
            char *key = NULL;

            g_hash_table_iter_init(&gIter, crm_peer_cache);
            while (g_hash_table_iter_next(&gIter, NULL, (gpointer *) & node)) {
                if (crm_is_peer_active(node)) {
                    crm_err("member: %s proc=%.32x", node->uname, node->processes);
                }
            }

            g_hash_table_iter_init(&gIter, voted);
            while (g_hash_table_iter_next(&gIter, (gpointer *) & key, NULL)) {
                crm_err("voted: %s", key);
            }

        }
        crm_debug("Destroying voted hash");
        g_hash_table_destroy(voted);
        voted = NULL;

    } else {
        crm_debug("Still waiting on %d non-votes (%d total)",
                  num_members - voted_size, num_members);
    }

    return;
}

#define loss_dampen 2           /* in seconds */

/*	A_ELECTION_COUNT	*/
void
do_election_count_vote(long long action,
                       enum crmd_fsa_cause cause,
                       enum crmd_fsa_state cur_state,
                       enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int age = 0;
    int election_id = -1;
    int log_level = LOG_INFO;
    gboolean use_born_on = FALSE;
    gboolean done = FALSE;
    gboolean we_loose = FALSE;
    const char *op = NULL;
    const char *vote_from = NULL;
    const char *election_owner = NULL;
    const char *reason = "unknown";
    crm_node_t *our_node = NULL, *your_node = NULL;
    ha_msg_input_t *vote = fsa_typed_data(fsa_dt_ha_msg);

    static int election_wins = 0;

    time_t tm_now = time(NULL);
    static time_t expires = 0;
    static time_t last_election_loss = 0;

    /* if the membership copy is NULL we REALLY shouldnt be voting
     * the question is how we managed to get here.
     */

    CRM_CHECK(msg_data != NULL, return);
    CRM_CHECK(vote != NULL, crm_err("Bogus data from %s", msg_data->origin); return);
    CRM_CHECK(vote->msg != NULL, crm_err("Bogus data from %s", msg_data->origin); return);

    if(crm_peer_cache == NULL) {
        if(is_not_set(fsa_input_register, R_SHUTDOWN)) {
            crm_err("Internal error, no peer cache");
        }
        return;
    }

    op = crm_element_value(vote->msg, F_CRM_TASK);
    vote_from = crm_element_value(vote->msg, F_CRM_HOST_FROM);
    election_owner = crm_element_value(vote->msg, F_CRM_ELECTION_OWNER);
    crm_element_value_int(vote->msg, F_CRM_ELECTION_ID, &election_id);

    CRM_CHECK(vote_from != NULL, vote_from = fsa_our_uname);

    your_node = crm_get_peer(0, vote_from);
    our_node = crm_get_peer(0, fsa_our_uname);

    if (voted == NULL) {
        crm_debug("Created voted hash");
        voted = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                      g_hash_destroy_str, g_hash_destroy_str);
    }

    if (is_heartbeat_cluster()) {
        use_born_on = TRUE;
    } else if (is_classic_ais_cluster()) {
        use_born_on = TRUE;
    }

    if (cur_state == S_STARTING) {
        reason = "Still starting";
        we_loose = TRUE;

    } else if (our_node == NULL || crm_is_peer_active(our_node) == FALSE) {
        reason = "We are not part of the cluster";
        log_level = LOG_ERR;
        we_loose = TRUE;

    } else if (election_id != current_election_id && crm_str_eq(fsa_our_uuid, election_owner, TRUE)) {
        log_level = LOG_DEBUG_2;
        reason = "Superceeded";
        done = TRUE;

    } else if (your_node == NULL || crm_is_peer_active(your_node) == FALSE) {
        /* Possibly we cached the message in the FSA queue at a point that it wasn't */
        reason = "Peer is not part of our cluster";
        log_level = LOG_WARNING;
        done = TRUE;

    } else if (crm_str_eq(op, CRM_OP_NOVOTE, TRUE)) {
        char *op_copy = strdup(op);
        char *uname_copy = strdup(vote_from);

        CRM_ASSERT(crm_str_eq(fsa_our_uuid, election_owner, TRUE));

        /* update the list of nodes that have voted */
        g_hash_table_replace(voted, uname_copy, op_copy);
        reason = "Recorded";
        done = TRUE;

    } else {
        struct timeval your_age;
        const char *your_version = crm_element_value(vote->msg, F_CRM_VERSION);

        your_age.tv_sec = 0;
        your_age.tv_usec = 0;

        crm_element_value_int(vote->msg, F_CRM_ELECTION_AGE_S, (int *)&(your_age.tv_sec));
        crm_element_value_int(vote->msg, F_CRM_ELECTION_AGE_US, (int *)&(your_age.tv_usec));

        age = crm_compare_age(your_age);
        if(your_age.tv_sec == 0 && your_age.tv_usec == 0) {
            crm_log_xml_trace(vote->msg, "bad vote");
            crm_write_blackbox(0, NULL);
        }

        if (crm_str_eq(vote_from, fsa_our_uname, TRUE)) {
            char *op_copy = strdup(op);
            char *uname_copy = strdup(vote_from);

            CRM_ASSERT(crm_str_eq(fsa_our_uuid, election_owner, TRUE));

            /* update ourselves in the list of nodes that have voted */
            g_hash_table_replace(voted, uname_copy, op_copy);
            reason = "Recorded";
            done = TRUE;

        } else if (compare_version(your_version, CRM_FEATURE_SET) < 0) {
            reason = "Version";
            we_loose = TRUE;

        } else if (compare_version(your_version, CRM_FEATURE_SET) > 0) {
            reason = "Version";

        } else if (age < 0) {
            reason = "Uptime";
            we_loose = TRUE;

        } else if (age > 0) {
            reason = "Uptime";

            /* TODO: Check for y(our) born < 0 */
        } else if (use_born_on && your_node->born < our_node->born) {
            reason = "Born";
            we_loose = TRUE;

        } else if (use_born_on && your_node->born > our_node->born) {
            reason = "Born";

        } else if (fsa_our_uname == NULL) {
            reason = "Unknown host name";
            we_loose = TRUE;

        } else if (strcasecmp(fsa_our_uname, vote_from) > 0) {
            reason = "Host name";
            we_loose = TRUE;

        } else {
            reason = "Host name";
            CRM_ASSERT(strcasecmp(fsa_our_uname, vote_from) < 0);
/* cant happen...
 *	} else if(strcasecmp(fsa_our_uname, vote_from) == 0) {
 *
 */
        }
    }

    if (expires < tm_now) {
        election_wins = 0;
        expires = tm_now + STORM_INTERVAL;

    } else if (done == FALSE && we_loose == FALSE) {
        int peers = 1 + g_hash_table_size(crm_peer_cache);

        /* If every node has to vote down every other node, thats N*(N-1) total elections
         * Allow some leway before _really_ complaining
         */
        election_wins++;
        if (election_wins > (peers * peers)) {
            crm_warn("Election storm detected: %d elections in %d seconds", election_wins,
                     STORM_INTERVAL);
            election_wins = 0;
            expires = tm_now + STORM_INTERVAL;
            crm_write_blackbox(0, NULL);
        }
    }

    if (done) {
        do_crm_log(log_level + 1, "Election %d (current: %d, owner: %s): Processed %s from %s (%s)",
                   election_id, current_election_id, election_owner, op, vote_from, reason);

    } else if (we_loose) {
        xmlNode *novote = create_request(CRM_OP_NOVOTE, NULL, vote_from,
                                         CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

        do_crm_log(log_level, "Election %d (owner: %s) lost: %s from %s (%s)",
                   election_id, election_owner, op, vote_from, reason);
        update_dc(NULL);

        crm_timer_stop(election_timeout);
        if (fsa_input_register & R_THE_DC) {
            crm_trace("Give up the DC to %s", vote_from);
            register_fsa_input(C_FSA_INTERNAL, I_RELEASE_DC, NULL);
            fsa_cib_conn->cmds->set_slave(fsa_cib_conn, cib_scope_local);

        } else if (cur_state != S_STARTING) {
            crm_trace("We werent the DC anyway");
            register_fsa_input(C_FSA_INTERNAL, I_PENDING, NULL);
        }

        crm_xml_add(novote, F_CRM_ELECTION_OWNER, election_owner);
        crm_xml_add_int(novote, F_CRM_ELECTION_ID, election_id);

        send_cluster_message(crm_get_peer(0, vote_from), crm_msg_crmd, novote, TRUE);
        free_xml(novote);

        last_election_loss = tm_now;

    } else {
        do_crm_log(log_level, "Election %d (owner: %s) pass: %s from %s (%s)",
                   election_id, election_owner, op, vote_from, reason);

        if (last_election_loss) {

            if (tm_now - last_election_loss < (time_t) loss_dampen) {
                crm_info("Election %d ignore: We already lost an election less than %ds ago (%s)",
                         election_id, loss_dampen, ctime(&last_election_loss));
                update_dc(NULL);
                return;
            }
            last_election_loss = 0;
        }

        register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
        g_hash_table_destroy(voted);
        voted = NULL;
    }
}

/*	A_ELECT_TIMER_START, A_ELECTION_TIMEOUT 	*/
/* we won */
void
do_election_timer_ctrl(long long action,
                       enum crmd_fsa_cause cause,
                       enum crmd_fsa_state cur_state,
                       enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
}

static void
feature_update_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;

        crm_notice("Update failed: %s (%d)", pcmk_strerror(rc), rc);
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

/*	 A_DC_TAKEOVER	*/
void
do_dc_takeover(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    int rc = pcmk_ok;
    xmlNode *cib = NULL;
    GListPtr gIter = NULL;
    const char *cluster_type = name_for_cluster_type(get_cluster_type());

    crm_info("Taking over DC status for this partition");
    set_bit(fsa_input_register, R_THE_DC);

    for (gIter = stonith_cleanup_list; gIter != NULL; gIter = gIter->next) {
        char *target = gIter->data;
        crm_node_t *target_node = crm_get_peer(0, target);
        const char *uuid = get_uuid(target_node);

        crm_notice("Marking %s, target of a previous stonith action, as clean", target);
        send_stonith_update(NULL, target, uuid);
        free(target);
    }
    g_list_free(stonith_cleanup_list);
    stonith_cleanup_list = NULL;

#if SUPPORT_COROSYNC
    if (is_classic_ais_cluster()) {
        send_ais_text(crm_class_quorum, NULL, TRUE, NULL, crm_msg_ais);
    }
#endif

    if (voted != NULL) {
        crm_trace("Destroying voted hash");
        g_hash_table_destroy(voted);
        voted = NULL;
    }

    set_bit(fsa_input_register, R_JOIN_OK);
    set_bit(fsa_input_register, R_INVOKE_PE);

    fsa_cib_conn->cmds->set_master(fsa_cib_conn, cib_scope_local);

    cib = create_xml_node(NULL, XML_TAG_CIB);
    crm_xml_add(cib, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
    fsa_cib_update(XML_TAG_CIB, cib, cib_quorum_override, rc, NULL);
    fsa_register_cib_callback(rc, FALSE, NULL, feature_update_callback);

    update_attr_delegate(fsa_cib_conn, cib_none, XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
                         "dc-version", VERSION "-" BUILD_VERSION, FALSE, NULL);

    update_attr_delegate(fsa_cib_conn, cib_none, XML_CIB_TAG_CRMCONFIG, NULL, NULL, NULL, NULL,
                         "cluster-infrastructure", cluster_type, FALSE, NULL);

    mainloop_set_trigger(config_read);
    free_xml(cib);
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
        clear_bit(fsa_input_register, R_THE_DC);

    } else if (action & A_DC_RELEASED) {
        crm_info("DC role released");
#if 0
        if (are there errors) {
            /* we cant stay up if not healthy */
            /* or perhaps I_ERROR and go to S_RECOVER? */
            result = I_SHUTDOWN;
        }
#endif
        register_fsa_input(C_FSA_INTERNAL, I_RELEASE_SUCCESS, NULL);

    } else {
        crm_err("Unknown action %s", fsa_action2string(action));
    }

    crm_trace("Am I still the DC? %s", AM_I_DC ? XML_BOOLEAN_YES : XML_BOOLEAN_NO);

}

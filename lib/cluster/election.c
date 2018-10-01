/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/common/mainloop.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election.h>
#include <crm/crm.h>

#define STORM_INTERVAL   2      /* in seconds */

struct election_s {
    enum election_result state;
    guint count;        // How many times local node has voted
    char *name;         // Descriptive name for this election
    char *uname;        // Local node's name
    GSourceFunc cb;     // Function to call if election is won
    GHashTable *voted;  // Key = node name, value = how node voted
    mainloop_timer_t *timeout; // When to abort if all votes not received
};

static void election_complete(election_t *e)
{
    e->state = election_won;

    if(e->cb) {
        e->cb(e);
    }

    election_reset(e);
}

static gboolean election_timer_cb(gpointer user_data)
{
    election_t *e = user_data;

    crm_info("%s timed out, declaring local node as winner", e->name);
    election_complete(e);
    return FALSE;
}

enum election_result
election_state(election_t *e)
{
    if(e) {
        return e->state;
    }
    return election_error;
}

/*!
 * \brief Create a new election object
 *
 * Every node that wishes to participate in an election must create an election
 * object. Typically, this should be done once, at start-up. A caller should
 * only create a single election object.
 *
 * \param[in] name       Label for election (for logging)
 * \param[in] uname      Local node's name
 * \param[in] period_ms  How long to wait for all peers to vote
 * \param[in] cb         Function to call if local node wins election
 *
 * \return Newly allocated election object on success, NULL on error
 * \note The caller is responsible for freeing the returned value using
 *       election_fini().
 */
election_t *
election_init(const char *name, const char *uname, guint period_ms, GSourceFunc cb)
{
    election_t *e = NULL;

    static guint count = 0;

    CRM_CHECK(uname != NULL, return NULL);

    e = calloc(1, sizeof(election_t));
    if (e == NULL) {
        crm_perror(LOG_CRIT, "Cannot create election");
        return NULL;
    }

    e->uname = strdup(uname);
    if (e->uname == NULL) {
        crm_perror(LOG_CRIT, "Cannot create election");
        free(e);
        return NULL;
    }

    e->name = name? crm_strdup_printf("election-%s", name)
                  : crm_strdup_printf("election-%u", count++);
    e->cb = cb;
    e->timeout = mainloop_timer_add(e->name, period_ms, FALSE,
                                    election_timer_cb, e);
    crm_trace("Created %s", e->name);
    return e;
}

/*!
 * \brief Disregard any previous vote by specified peer
 *
 * This discards any recorded vote from a specified peer. Election users should
 * call this whenever a voting peer becomes inactive.
 *
 * \param[in] e      Election object
 * \param[in] uname  Name of peer to disregard
 */
void
election_remove(election_t *e, const char *uname)
{
    if(e && uname && e->voted) {
        crm_trace("Discarding %s (no-)vote from lost peer %s", e->name, uname);
        g_hash_table_remove(e->voted, uname);
    }
}

/*!
 * \brief Stop election timer and disregard all votes
 *
 * \param[in] e      Election object
 */
void
election_reset(election_t *e)
{
    if (e != NULL) {
        crm_trace("Resetting election %s", e->name);
        mainloop_timer_stop(e->timeout);
        if (e->voted) {
            crm_trace("Destroying voted cache with %d members", g_hash_table_size(e->voted));
            g_hash_table_destroy(e->voted);
            e->voted = NULL;
        }
    }
}

/*!
 * \brief Free an election object
 *
 * Free all memory associated with an election object, stopping its
 * election timer (if running).
 *
 * \param[in] e      Election object
 */
void
election_fini(election_t *e)
{
    if(e) {
        election_reset(e);
        crm_trace("Destroying %s", e->name);
        mainloop_timer_del(e->timeout);
        free(e->uname);
        free(e->name);
        free(e);
    }
}

static void
election_timeout_start(election_t *e)
{
    if(e) {
        mainloop_timer_start(e->timeout);
    }
}

/*!
 * \brief Stop an election's timer, if running
 *
 * \param[in] e      Election object
 */
void
election_timeout_stop(election_t *e)
{
    if(e) {
        mainloop_timer_stop(e->timeout);
    }
}

/*!
 * \brief Change an election's timeout (restarting timer if running)
 *
 * \param[in] e      Election object
 * \param[in] period New timeout
 */
void
election_timeout_set_period(election_t *e, guint period)
{
    if(e) {
        mainloop_timer_set_period(e->timeout, period);
    } else {
        crm_err("No election defined");
    }
}

static int
crm_uptime(struct timeval *output)
{
    static time_t expires = 0;
    static struct rusage info;

    time_t tm_now = time(NULL);

    if (expires < tm_now) {
        int rc = 0;

        info.ru_utime.tv_sec = 0;
        info.ru_utime.tv_usec = 0;
        rc = getrusage(RUSAGE_SELF, &info);

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

    crm_uptime(&our_age); /* If an error occurred, our_age will be compared as {0,0} */

    if (our_age.tv_sec > your_age.tv_sec) {
        crm_debug("Win: %ld vs %ld (seconds)", (long)our_age.tv_sec, (long)your_age.tv_sec);
        return 1;
    } else if (our_age.tv_sec < your_age.tv_sec) {
        crm_debug("Lose: %ld vs %ld (seconds)", (long)our_age.tv_sec, (long)your_age.tv_sec);
        return -1;
    } else if (our_age.tv_usec > your_age.tv_usec) {
        crm_debug("Win: %ld.%ld vs %ld.%ld (usec)",
                  (long)our_age.tv_sec, (long)our_age.tv_usec, (long)your_age.tv_sec, (long)your_age.tv_usec);
        return 1;
    } else if (our_age.tv_usec < your_age.tv_usec) {
        crm_debug("Lose: %ld.%ld vs %ld.%ld (usec)",
                  (long)our_age.tv_sec, (long)our_age.tv_usec, (long)your_age.tv_sec, (long)your_age.tv_usec);
        return -1;
    }

    return 0;
}

/*!
 * \brief Start a new election by offering local node's candidacy
 *
 * Broadcast a "vote" election message containing the local node's ID,
 * (incremented) election counter, and uptime, and start the election timer.
 *
 * \param[in] e      Election object
 * \note Any nodes agreeing to the candidacy will send a "no-vote" reply, and if
 *       all active peers do so, or if the election times out, the local node
 *       wins the election. (If we lose to any peer vote, we will stop the
 *       timer, so a timeout means we did not lose -- either some peer did not
 *       vote, or we did not call election_check() in time.)
 */
void
election_vote(election_t *e)
{
    struct timeval age;
    xmlNode *vote = NULL;
    crm_node_t *our_node;

    if (e == NULL) {
        crm_trace("Election vote requested, but no election available");
        return;
    }

    our_node = crm_get_peer(0, e->uname);
    if ((our_node == NULL) || (crm_is_peer_active(our_node) == FALSE)) {
        crm_trace("Cannot vote in %s yet: local node not connected to cluster",
                  e->name);
        return;
    }

    election_reset(e);
    e->state = election_in_progress;
    vote = create_request(CRM_OP_VOTE, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

    e->count++;
    crm_xml_add(vote, F_CRM_ELECTION_OWNER, our_node->uuid);
    crm_xml_add_int(vote, F_CRM_ELECTION_ID, e->count);

    crm_uptime(&age);
    crm_xml_add_int(vote, F_CRM_ELECTION_AGE_S, age.tv_sec);
    crm_xml_add_int(vote, F_CRM_ELECTION_AGE_US, age.tv_usec);

    send_cluster_message(NULL, crm_msg_crmd, vote, TRUE);
    free_xml(vote);

    crm_debug("Started %s round %d", e->name, e->count);
    election_timeout_start(e);
    return;
}

/*!
 * \brief Check whether local node has won an election
 *
 * If all known peers have sent no-vote messages, stop the election timer, set
 * the election state to won, and call any registered win callback.
 *
 * \param[in] e      Election object
 *
 * \return TRUE if local node has won, FALSE otherwise
 * \note If all known peers have sent no-vote messages, but the election owner
 *       does not call this function, the election will not be won (and the
 *       callback will not be called) until the election times out.
 * \note This should be called when election_count_vote() returns
 *       \c election_in_progress.
 */
bool
election_check(election_t *e)
{
    int voted_size = 0;
    int num_members = 0;

    if(e == NULL) {
        crm_trace("Election check requested, but no election available");
        return FALSE;
    }
    if (e->voted == NULL) {
        crm_trace("%s check requested, but no votes received yet", e->name);
        return FALSE;
    }

    voted_size = g_hash_table_size(e->voted);
    num_members = crm_active_peers();

    /* in the case of #voted > #members, it is better to
     *   wait for the timeout and give the cluster time to
     *   stabilize
     */
    if (voted_size >= num_members) {
        /* we won and everyone has voted */
        election_timeout_stop(e);
        if (voted_size > num_members) {
            GHashTableIter gIter;
            const crm_node_t *node;
            char *key = NULL;

            crm_warn("Received too many votes in %s", e->name);
            g_hash_table_iter_init(&gIter, crm_peer_cache);
            while (g_hash_table_iter_next(&gIter, NULL, (gpointer *) & node)) {
                if (crm_is_peer_active(node)) {
                    crm_warn("* expected vote: %s", node->uname);
                }
            }

            g_hash_table_iter_init(&gIter, e->voted);
            while (g_hash_table_iter_next(&gIter, (gpointer *) & key, NULL)) {
                crm_warn("* actual vote: %s", key);
            }

        }

        crm_info("%s won by local node", e->name);
        election_complete(e);
        return TRUE;

    } else {
        crm_debug("%s still waiting on %d of %d votes",
                  e->name, num_members - voted_size, num_members);
    }

    return FALSE;
}

#define LOSS_DAMPEN 2           /* in seconds */

struct vote {
    const char *op;
    const char *from;
    const char *version;
    const char *election_owner;
    int election_id;
    struct timeval age;
};

/*!
 * \brief Unpack an election message
 *
 * \param[in] e        Election object
 * \param[in] message  Election message XML
 * \param[out] vote    Parsed fields from message
 *
 * \return TRUE if election message and election are valid, FALSE otherwise
 * \note The parsed struct's pointer members are valid only for the lifetime of
 *       the message argument.
 */
static bool
parse_election_message(election_t *e, xmlNode *message, struct vote *vote)
{
    CRM_CHECK(message && vote, return FALSE);

    vote->election_id = -1;
    vote->age.tv_sec = -1;
    vote->age.tv_usec = -1;

    vote->op = crm_element_value(message, F_CRM_TASK);
    vote->from = crm_element_value(message, F_CRM_HOST_FROM);
    vote->version = crm_element_value(message, F_CRM_VERSION);
    vote->election_owner = crm_element_value(message, F_CRM_ELECTION_OWNER);

    crm_element_value_int(message, F_CRM_ELECTION_ID, &(vote->election_id));

    if ((vote->op == NULL) || (vote->from == NULL) || (vote->version == NULL)
        || (vote->election_owner == NULL) || (vote->election_id < 0)) {

        crm_warn("Invalid %s message from %s in %s ",
                 (vote->op? vote->op : "election"),
                 (vote->from? vote->from : "unspecified node"),
                 (e? e->name : "election"));
        return FALSE;
    }

    // Op-specific validation

    if (crm_str_eq(vote->op, CRM_OP_VOTE, TRUE)) {
        // Only vote ops have uptime
        int age_s = -1;
        int age_us = -1;

        // @TODO add functions to parse time_t / suseconds_t directly from XML
        crm_element_value_int(message, F_CRM_ELECTION_AGE_S, &age_s);
        crm_element_value_int(message, F_CRM_ELECTION_AGE_US, &age_us);

        if ((age_s < 0) || (age_us < 0)) {
            crm_warn("Cannot count %s %s from %s because it is missing uptime",
                     (e? e->name : "election"), vote->op, vote->from);
            return FALSE;
        }
        vote->age.tv_sec = age_s;
        vote->age.tv_usec = age_us;

    } else if (!crm_str_eq(vote->op, CRM_OP_NOVOTE, TRUE)) {
        crm_info("Cannot process %s message from %s because %s is not a known election op",
                 (e? e->name : "election"), vote->from, vote->op);
        return FALSE;
    }

    // Election validation

    if (e == NULL) {
        crm_info("Cannot count %s from %s because no election available",
                 vote->op, vote->from);
        return FALSE;
    }

    /* If the membership cache is NULL, we REALLY shouldn't be voting --
     * the question is how we managed to get here.
     */
    if (crm_peer_cache == NULL) {
        crm_info("Cannot count %s %s from %s because no peer information available",
                 e->name, vote->op, vote->from);
        return FALSE;
    }
    return TRUE;
}

static void
record_vote(election_t *e, struct vote *vote)
{
    char *voter_copy = NULL;
    char *vote_copy = NULL;

    CRM_ASSERT(e && vote && vote->from && vote->op);
    if (e->voted == NULL) {
        e->voted = crm_str_table_new();
    }

    voter_copy = strdup(vote->from);
    vote_copy = strdup(vote->op);
    CRM_ASSERT(voter_copy && vote_copy);

    g_hash_table_replace(e->voted, voter_copy, vote_copy);
}

static void
send_no_vote(crm_node_t *peer, struct vote *vote)
{
    // @TODO probably shouldn't hardcode CRM_SYSTEM_CRMD and crm_msg_crmd

    xmlNode *novote = create_request(CRM_OP_NOVOTE, NULL, vote->from,
                                     CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

    crm_xml_add(novote, F_CRM_ELECTION_OWNER, vote->election_owner);
    crm_xml_add_int(novote, F_CRM_ELECTION_ID, vote->election_id);

    send_cluster_message(peer, crm_msg_crmd, novote, TRUE);
    free_xml(novote);
}

/*!
 * \brief Process an election message (vote or no-vote) from a peer
 *
 * \param[in] e        Election object
 * \param[in] vote     Election message XML from peer
 * \param[in] can_win  Whether to consider the local node eligible for winning
 *
 * \return Election state after new vote is considered
 * \note If the peer message is a vote, and we prefer the peer to win, this will
 *       send a no-vote reply to the peer.
 * \note The situations "we lost to this vote" from "this is a late no-vote
 *       after we've already lost" both return election_lost. If a caller needs
 *       to distinguish them, it should save the current state before calling
 *       this function, and then compare the result.
 */
enum election_result
election_count_vote(election_t *e, xmlNode *message, bool can_win)
{
    int log_level = LOG_INFO;
    gboolean done = FALSE;
    gboolean we_lose = FALSE;
    const char *reason = "unknown";
    bool we_are_owner = FALSE;
    crm_node_t *our_node = NULL, *your_node = NULL;
    time_t tm_now = time(NULL);
    struct vote vote;

    // @TODO these should be in election_t
    static int election_wins = 0;
    static time_t expires = 0;
    static time_t last_election_loss = 0;

    CRM_CHECK(message != NULL, return election_error);
    if (parse_election_message(e, message, &vote) == FALSE) {
        return election_error;
    }

    your_node = crm_get_peer(0, vote.from);
    our_node = crm_get_peer(0, e->uname);
    we_are_owner = (our_node != NULL)
                   && crm_str_eq(our_node->uuid, vote.election_owner, TRUE);

    if(can_win == FALSE) {
        reason = "Not eligible";
        we_lose = TRUE;

    } else if (our_node == NULL || crm_is_peer_active(our_node) == FALSE) {
        reason = "We are not part of the cluster";
        log_level = LOG_ERR;
        we_lose = TRUE;

    } else if (we_are_owner && (vote.election_id != e->count)) {
        log_level = LOG_TRACE;
        reason = "Superseded";
        done = TRUE;

    } else if (your_node == NULL || crm_is_peer_active(your_node) == FALSE) {
        /* Possibly we cached the message in the FSA queue at a point that it wasn't */
        reason = "Peer is not part of our cluster";
        log_level = LOG_WARNING;
        done = TRUE;

    } else if (crm_str_eq(vote.op, CRM_OP_NOVOTE, TRUE)
               || crm_str_eq(vote.from, e->uname, TRUE)) {
        /* Receiving our own broadcast vote, or a no-vote from peer, is a vote
         * for us to win
         */
        if (!we_are_owner) {
            crm_warn("Cannot count %s round %d %s from %s because we are not election owner (%s)",
                     e->name, vote.election_id, vote.op, vote.from,
                     vote.election_owner);
            return election_error;
        }
        if (e->state != election_in_progress) {
            // Should only happen if we already lost
            crm_debug("Not counting %s round %d %s from %s because no election in progress",
                      e->name, vote.election_id, vote.op, vote.from);
            return e->state;
        }
        record_vote(e, &vote);
        reason = "Recorded";
        done = TRUE;

    } else {
        // A peer vote requires a comparison to determine which node is better
        int age_result = crm_compare_age(vote.age);
        int version_result = compare_version(vote.version, CRM_FEATURE_SET);

        if (version_result < 0) {
            reason = "Version";
            we_lose = TRUE;

        } else if (version_result > 0) {
            reason = "Version";

        } else if (age_result < 0) {
            reason = "Uptime";
            we_lose = TRUE;

        } else if (age_result > 0) {
            reason = "Uptime";

        } else if (strcasecmp(e->uname, vote.from) > 0) {
            reason = "Host name";
            we_lose = TRUE;

        } else {
            reason = "Host name";
        }
    }

    if (expires < tm_now) {
        election_wins = 0;
        expires = tm_now + STORM_INTERVAL;

    } else if (done == FALSE && we_lose == FALSE) {
        int peers = 1 + g_hash_table_size(crm_peer_cache);
        static bool wrote_blackbox = FALSE; // @TODO move to election_t

        /* If every node has to vote down every other node, thats N*(N-1) total elections
         * Allow some leeway before _really_ complaining
         */
        election_wins++;
        if (election_wins > (peers * peers)) {
            crm_warn("%s election storm detected: %d wins in %d seconds",
                     e->name, election_wins, STORM_INTERVAL);
            election_wins = 0;
            expires = tm_now + STORM_INTERVAL;
            if (wrote_blackbox == FALSE) {
                /* It's questionable whether a black box (from every node in the
                 * cluster) would be truly helpful in diagnosing an election
                 * storm. It's also highly doubtful a production environment
                 * would get multiple election storms from distinct causes, so
                 * saving one blackbox per process lifetime should be
                 * sufficient. Alternatives would be to save a timestamp of the
                 * last blackbox write instead of a boolean, and write a new one
                 * if some amount of time has passed; or to save a storm count,
                 * write a blackbox on every Nth occurrence.
                 */
                crm_write_blackbox(0, NULL);
            }
        }
    }

    if (done) {
        do_crm_log(log_level + 1,
                   "Processed %s round %d %s (current round %d) from %s (%s)",
                   e->name, vote.election_id, vote.op, e->count, vote.from,
                   reason);
        return e->state;

    } else if (we_lose == FALSE) {
        if (last_election_loss == 0
            || tm_now - last_election_loss > (time_t) LOSS_DAMPEN) {

            do_crm_log(log_level, "%s round %d (owner node ID %s) pass: %s from %s (%s)",
                       e->name, vote.election_id, vote.election_owner, vote.op,
                       vote.from, reason);

            last_election_loss = 0;
            election_timeout_stop(e);

            /* Start a new election by voting down this, and other, peers */
            e->state = election_start;
            return e->state;
        } else {
            char *loss_time = ctime(&last_election_loss);

            if (loss_time) {
                // Show only HH:MM:SS
                loss_time += 11;
                loss_time[8] = '\0';
            }
            crm_info("Ignoring %s round %d (owner node ID %s) pass vs %s because we lost less than %ds ago at %s",
                     e->name, vote.election_id, vote.election_owner, vote.from,
                     LOSS_DAMPEN, (loss_time? loss_time : "unknown"));
        }
    }

    last_election_loss = tm_now;

    do_crm_log(log_level, "%s round %d (owner node ID %s) lost: %s from %s (%s)",
               e->name, vote.election_id, vote.election_owner, vote.op,
               vote.from, reason);

    election_reset(e);
    send_no_vote(your_node, &vote);
    e->state = election_lost;
    return e->state;
}

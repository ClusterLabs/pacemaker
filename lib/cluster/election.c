/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>
#include <crm/common/xml.h>

#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include "crmcluster_private.h"

#define STORM_INTERVAL   2      /* in seconds */

struct pcmk__election {
    enum election_result state;     // Current state of election
    guint count;                    // How many times local node has voted
    void (*cb)(pcmk_cluster_t *);   // Function to call if election is won
    GHashTable *voted;  // Key = node name, value = how node voted
    mainloop_timer_t *timeout; // When to abort if all votes not received
    int election_wins;         // Track wins, for storm detection
    bool wrote_blackbox;       // Write a storm blackbox at most once
    time_t expires;            // When storm detection period ends
    time_t last_election_loss; // When dampening period ends
};

static void
election_complete(pcmk_cluster_t *cluster)
{
    pcmk__assert((cluster != NULL) && (cluster->priv->election != NULL));
    cluster->priv->election->state = election_won;
    if (cluster->priv->election->cb != NULL) {
        cluster->priv->election->cb(cluster);
    }
    election_reset(cluster);
}

static gboolean
election_timer_cb(gpointer user_data)
{
    pcmk_cluster_t *cluster = user_data;

    crm_info("Declaring local node as winner after election timed out");
    election_complete(cluster);
    return FALSE;
}

/*!
 * \internal
 * \brief Get current state of an election
 *
 * \param[in] cluster  Cluster with election
 *
 * \return Current state of \e
 */
enum election_result
election_state(const pcmk_cluster_t *cluster)
{
    if ((cluster == NULL) || (cluster->priv->election == NULL)) {
        return election_error;
    }
    return cluster->priv->election->state;
}

/* The local node will be declared the winner if missing votes are not received
 * within this time. The value is chosen to be the same as the default for the
 * election-timeout cluster option.
 */
#define ELECTION_TIMEOUT_MS 120000

/*!
 * \internal
 * \brief Track election state in a cluster
 *
 * Every node that wishes to participate in an election must initialize the
 * election once, typically at start-up.
 *
 * \param[in] cluster    Cluster that election is for
 * \param[in] cb         Function to call if local node wins election
 */
void
election_init(pcmk_cluster_t *cluster, void (*cb)(pcmk_cluster_t *))
{
    const char *name = pcmk__s(crm_system_name, "election");

    CRM_CHECK(cluster->priv->election == NULL, return);

    cluster->priv->election = pcmk__assert_alloc(1, sizeof(pcmk__election_t));
    cluster->priv->election->cb = cb;
    cluster->priv->election->timeout = mainloop_timer_add(name,
                                                          ELECTION_TIMEOUT_MS,
                                                          FALSE,
                                                          election_timer_cb,
                                                          cluster);
}

/*!
 * \internal
 * \brief Disregard any previous vote by specified peer
 *
 * This discards any recorded vote from a specified peer. Election users should
 * call this whenever a voting peer becomes inactive.
 *
 * \param[in,out] cluster  Cluster with election
 * \param[in]     uname    Name of peer to disregard
 */
void
election_remove(pcmk_cluster_t *cluster, const char *uname)
{
    if ((cluster != NULL) && (cluster->priv->election != NULL)
        && (uname != NULL) && (cluster->priv->election->voted != NULL)) {
        crm_trace("Discarding (no-)vote from lost peer %s", uname);
        g_hash_table_remove(cluster->priv->election->voted, uname);
    }
}

/*!
 * \internal
 * \brief Stop election timer and disregard all votes
 *
 * \param[in,out] cluster  Cluster with election
 */
void
election_reset(pcmk_cluster_t *cluster)
{
    if ((cluster != NULL) && (cluster->priv->election != NULL)) {
        crm_trace("Resetting election");
        mainloop_timer_stop(cluster->priv->election->timeout);
        if (cluster->priv->election->voted != NULL) {
            g_hash_table_destroy(cluster->priv->election->voted);
            cluster->priv->election->voted = NULL;
        }
    }
}

/*!
 * \internal
 * \brief Free an election object
 *
 * Free all memory associated with an election object, stopping its
 * election timer (if running).
 *
 * \param[in,out] cluster  Cluster with election
 */
void
election_fini(pcmk_cluster_t *cluster)
{
    if ((cluster != NULL) && (cluster->priv->election != NULL)) {
        election_reset(cluster);
        crm_trace("Destroying election");
        mainloop_timer_del(cluster->priv->election->timeout);
        free(cluster->priv->election);
        cluster->priv->election = NULL;
    }
}

static void
election_timeout_start(pcmk_cluster_t *cluster)
{
    mainloop_timer_start(cluster->priv->election->timeout);
}

/*!
 * \internal
 * \brief Stop an election's timer, if running
 *
 * \param[in,out] cluster  Cluster with election
 */
void
election_timeout_stop(pcmk_cluster_t *cluster)
{
    if ((cluster != NULL) && (cluster->priv->election != NULL)) {
        mainloop_timer_stop(cluster->priv->election->timeout);
    }
}

/*!
 * \internal
 * \brief Change an election's timeout (restarting timer if running)
 *
 * \param[in,out] cluster  Cluster with election
 * \param[in]     period   New timeout
 */
void
election_timeout_set_period(pcmk_cluster_t *cluster, guint period)
{
    CRM_CHECK((cluster != NULL) && (cluster->priv->election != NULL), return);
    mainloop_timer_set_period(cluster->priv->election->timeout, period);
}

static int
get_uptime(struct timeval *output)
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
compare_age(struct timeval your_age)
{
    struct timeval our_age;

    get_uptime(&our_age); /* If an error occurred, our_age will be compared as {0,0} */

    if (our_age.tv_sec > your_age.tv_sec) {
        crm_debug("Win: %ld vs %ld (seconds)", (long)our_age.tv_sec, (long)your_age.tv_sec);
        return 1;
    } else if (our_age.tv_sec < your_age.tv_sec) {
        crm_debug("Lose: %ld vs %ld (seconds)", (long)our_age.tv_sec, (long)your_age.tv_sec);
        return -1;
    } else if (our_age.tv_usec > your_age.tv_usec) {
        crm_debug("Win: %ld.%06ld vs %ld.%06ld (usec)",
                  (long)our_age.tv_sec, (long)our_age.tv_usec, (long)your_age.tv_sec, (long)your_age.tv_usec);
        return 1;
    } else if (our_age.tv_usec < your_age.tv_usec) {
        crm_debug("Lose: %ld.%06ld vs %ld.%06ld (usec)",
                  (long)our_age.tv_sec, (long)our_age.tv_usec, (long)your_age.tv_sec, (long)your_age.tv_usec);
        return -1;
    }

    return 0;
}

/*!
 * \internal
 * \brief Start a new election by offering local node's candidacy
 *
 * Broadcast a "vote" election message containing the local node's ID,
 * (incremented) election counter, and uptime, and start the election timer.
 *
 * \param[in,out] cluster  Cluster with election
 *
 * \note Any nodes agreeing to the candidacy will send a "no-vote" reply, and if
 *       all active peers do so, or if the election times out, the local node
 *       wins the election. (If we lose to any peer vote, we will stop the
 *       timer, so a timeout means we did not lose -- either some peer did not
 *       vote, or we did not call election_check() in time.)
 */
void
election_vote(pcmk_cluster_t *cluster)
{
    struct timeval age;
    xmlNode *vote = NULL;
    pcmk__node_status_t *our_node = NULL;
    const char *message_type = NULL;

    CRM_CHECK((cluster != NULL) && (cluster->priv->election != NULL), return);

    if (cluster->priv->node_name == NULL) {
        crm_err("Cannot start an election: Local node name unknown");
        return;
    }

    our_node = pcmk__get_node(0, cluster->priv->node_name, NULL,
                              pcmk__node_search_cluster_member);
    if (!pcmk__cluster_is_node_active(our_node)) {
        crm_trace("Cannot vote yet: local node not connected to cluster");
        return;
    }

    election_reset(cluster);
    cluster->priv->election->state = election_in_progress;
    message_type = pcmk__server_message_type(cluster->priv->server);

    /* @COMPAT We use message_type as the sender and recipient system for
     * backward compatibility (see T566).
     */
    vote = pcmk__new_request(cluster->priv->server, message_type,
                             NULL, message_type, CRM_OP_VOTE, NULL);

    cluster->priv->election->count++;
    crm_xml_add(vote, PCMK__XA_ELECTION_OWNER,
                pcmk__cluster_get_xml_id(our_node));
    crm_xml_add_int(vote, PCMK__XA_ELECTION_ID, cluster->priv->election->count);

    // Warning: PCMK__XA_ELECTION_AGE_NANO_SEC value is actually microseconds
    get_uptime(&age);
    crm_xml_add_timeval(vote, PCMK__XA_ELECTION_AGE_SEC,
                        PCMK__XA_ELECTION_AGE_NANO_SEC, &age);

    pcmk__cluster_send_message(NULL, cluster->priv->server, vote);
    pcmk__xml_free(vote);

    crm_debug("Started election round %u", cluster->priv->election->count);
    election_timeout_start(cluster);
    return;
}

/*!
 * \internal
 * \brief Check whether local node has won an election
 *
 * If all known peers have sent no-vote messages, stop the election timer, set
 * the election state to won, and call any registered win callback.
 *
 * \param[in,out] cluster  Cluster with election
 *
 * \return TRUE if local node has won, FALSE otherwise
 * \note If all known peers have sent no-vote messages, but the election owner
 *       does not call this function, the election will not be won (and the
 *       callback will not be called) until the election times out.
 * \note This should be called when election_count_vote() returns
 *       \c election_in_progress.
 */
bool
election_check(pcmk_cluster_t *cluster)
{
    int voted_size = 0;
    int num_members = 0;

    CRM_CHECK((cluster != NULL) && (cluster->priv->election != NULL),
              return false);

    if (cluster->priv->election->voted == NULL) {
        crm_trace("Election check requested, but no votes received yet");
        return FALSE;
    }

    voted_size = g_hash_table_size(cluster->priv->election->voted);
    num_members = pcmk__cluster_num_active_nodes();

    /* in the case of #voted > #members, it is better to
     *   wait for the timeout and give the cluster time to
     *   stabilize
     */
    if (voted_size >= num_members) {
        /* we won and everyone has voted */
        election_timeout_stop(cluster);
        if (voted_size > num_members) {
            GHashTableIter gIter;
            const pcmk__node_status_t *node = NULL;
            char *key = NULL;

            crm_warn("Received too many votes in election");
            g_hash_table_iter_init(&gIter, pcmk__peer_cache);
            while (g_hash_table_iter_next(&gIter, NULL, (gpointer *) & node)) {
                if (pcmk__cluster_is_node_active(node)) {
                    crm_warn("* expected vote: %s", node->name);
                }
            }

            g_hash_table_iter_init(&gIter, cluster->priv->election->voted);
            while (g_hash_table_iter_next(&gIter, (gpointer *) & key, NULL)) {
                crm_warn("* actual vote: %s", key);
            }

        }

        crm_info("Election won by local node");
        election_complete(cluster);
        return TRUE;

    } else {
        crm_debug("Election still waiting on %d of %d vote%s",
                  num_members - voted_size, num_members,
                  pcmk__plural_s(num_members));
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
 * \internal
 * \brief Unpack an election message
 *
 * \param[in] message  Election message XML
 * \param[out] vote    Parsed fields from message
 *
 * \return TRUE if election message and election are valid, FALSE otherwise
 * \note The parsed struct's pointer members are valid only for the lifetime of
 *       the message argument.
 */
static bool
parse_election_message(const xmlNode *message, struct vote *vote)
{
    CRM_CHECK(message && vote, return FALSE);

    vote->election_id = -1;
    vote->age.tv_sec = -1;
    vote->age.tv_usec = -1;

    vote->op = crm_element_value(message, PCMK__XA_CRM_TASK);
    vote->from = crm_element_value(message, PCMK__XA_SRC);
    vote->version = crm_element_value(message, PCMK_XA_VERSION);
    vote->election_owner = crm_element_value(message, PCMK__XA_ELECTION_OWNER);

    crm_element_value_int(message, PCMK__XA_ELECTION_ID, &(vote->election_id));

    if ((vote->op == NULL) || (vote->from == NULL) || (vote->version == NULL)
        || (vote->election_owner == NULL) || (vote->election_id < 0)) {

        crm_warn("Invalid %s message from %s",
                 pcmk__s(vote->op, "election"),
                 pcmk__s(vote->from, "unspecified node"));
        crm_log_xml_trace(message, "bad-vote");
        return FALSE;
    }

    // Op-specific validation

    if (pcmk__str_eq(vote->op, CRM_OP_VOTE, pcmk__str_none)) {
        /* Only vote ops have uptime.
           Warning: PCMK__XA_ELECTION_AGE_NANO_SEC value is in microseconds.
         */
        if ((pcmk__xe_get_timeval(message, PCMK__XA_ELECTION_AGE_SEC,
                                   PCMK__XA_ELECTION_AGE_NANO_SEC,
                                   &(vote->age)) != pcmk_rc_ok)
            || (vote->age.tv_sec < 0) || (vote->age.tv_usec < 0)) {

            crm_warn("Cannot count election %s from %s because uptime is "
                     "missing or invalid",
                     vote->op, vote->from);
            return FALSE;
        }

    } else if (!pcmk__str_eq(vote->op, CRM_OP_NOVOTE, pcmk__str_none)) {
        crm_info("Cannot process election message from %s "
                 "because %s is not a known election op", vote->from, vote->op);
        return FALSE;
    }

    /* If the membership cache is NULL, we REALLY shouldn't be voting --
     * the question is how we managed to get here.
     */
    if (pcmk__peer_cache == NULL) {
        crm_info("Cannot count election %s from %s "
                 "because no peer information available", vote->op, vote->from);
        return FALSE;
    }
    return TRUE;
}

static void
record_vote(pcmk_cluster_t *cluster, struct vote *vote)
{
    pcmk__assert((vote->from != NULL) && (vote->op != NULL));

    if (cluster->priv->election->voted == NULL) {
        cluster->priv->election->voted = pcmk__strkey_table(free, free);
    }
    pcmk__insert_dup(cluster->priv->election->voted, vote->from, vote->op);
}

static void
send_no_vote(pcmk_cluster_t *cluster, pcmk__node_status_t *peer,
             struct vote *vote)
{
    const char *message_type = NULL;
    xmlNode *novote = NULL;

    message_type = pcmk__server_message_type(cluster->priv->server);
    novote = pcmk__new_request(cluster->priv->server, message_type,
                               vote->from, message_type, CRM_OP_NOVOTE, NULL);
    crm_xml_add(novote, PCMK__XA_ELECTION_OWNER, vote->election_owner);
    crm_xml_add_int(novote, PCMK__XA_ELECTION_ID, vote->election_id);

    pcmk__cluster_send_message(peer, cluster->priv->server, novote);
    pcmk__xml_free(novote);
}

/*!
 * \internal
 * \brief Process an election message (vote or no-vote) from a peer
 *
 * \param[in,out] cluster  Cluster with election
 * \param[in]     message  Election message XML from peer
 * \param[in]     can_win  Whether local node is eligible to win
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
election_count_vote(pcmk_cluster_t *cluster, const xmlNode *message,
                    bool can_win)
{
    int log_level = LOG_INFO;
    gboolean done = FALSE;
    gboolean we_lose = FALSE;
    const char *reason = "unknown";
    bool we_are_owner = FALSE;
    pcmk__node_status_t *our_node = NULL;
    pcmk__node_status_t *your_node = NULL;
    time_t tm_now = time(NULL);
    struct vote vote;

    CRM_CHECK((cluster != NULL) && (cluster->priv->election != NULL)
              && (message != NULL) && (cluster->priv->node_name != NULL),
              return election_error);

    if (!parse_election_message(message, &vote)) {
        return election_error;
    }

    your_node = pcmk__get_node(0, vote.from, NULL,
                               pcmk__node_search_cluster_member);
    our_node = pcmk__get_node(0, cluster->priv->node_name, NULL,
                              pcmk__node_search_cluster_member);
    we_are_owner = (our_node != NULL)
                   && pcmk__str_eq(pcmk__cluster_get_xml_id(our_node),
                                   vote.election_owner, pcmk__str_none);

    if (!can_win) {
        reason = "Not eligible";
        we_lose = TRUE;

    } else if (!pcmk__cluster_is_node_active(our_node)) {
        reason = "We are not part of the cluster";
        log_level = LOG_ERR;
        we_lose = TRUE;

    } else if (we_are_owner
               && (vote.election_id != cluster->priv->election->count)) {
        log_level = LOG_TRACE;
        reason = "Superseded";
        done = TRUE;

    } else if (!pcmk__cluster_is_node_active(your_node)) {
        /* Possibly we cached the message in the FSA queue at a point that it wasn't */
        reason = "Peer is not part of our cluster";
        log_level = LOG_WARNING;
        done = TRUE;

    } else if (pcmk__str_eq(vote.op, CRM_OP_NOVOTE, pcmk__str_none)
               || pcmk__str_eq(vote.from, cluster->priv->node_name,
                               pcmk__str_casei)) {
        /* Receiving our own broadcast vote, or a no-vote from peer, is a vote
         * for us to win
         */
        if (!we_are_owner) {
            crm_warn("Cannot count election round %d %s from %s "
                     "because we did not start election (node ID %s did)",
                     vote.election_id, vote.op, vote.from,
                     vote.election_owner);
            return election_error;
        }
        if (cluster->priv->election->state != election_in_progress) {
            // Should only happen if we already lost
            crm_debug("Not counting election round %d %s from %s "
                      "because no election in progress",
                      vote.election_id, vote.op, vote.from);
            return cluster->priv->election->state;
        }
        record_vote(cluster, &vote);
        reason = "Recorded";
        done = TRUE;

    } else {
        // A peer vote requires a comparison to determine which node is better
        int age_result = compare_age(vote.age);
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

        } else if (strcasecmp(cluster->priv->node_name, vote.from) > 0) {
            reason = "Host name";
            we_lose = TRUE;

        } else {
            reason = "Host name";
        }
    }

    if (cluster->priv->election->expires < tm_now) {
        cluster->priv->election->election_wins = 0;
        cluster->priv->election->expires = tm_now + STORM_INTERVAL;

    } else if (done == FALSE && we_lose == FALSE) {
        int peers = 1 + g_hash_table_size(pcmk__peer_cache);

        /* If every node has to vote down every other node, thats N*(N-1) total elections
         * Allow some leeway before _really_ complaining
         */
        cluster->priv->election->election_wins++;
        if (cluster->priv->election->election_wins > (peers * peers)) {
            crm_warn("Election storm detected: %d wins in %d seconds",
                     cluster->priv->election->election_wins, STORM_INTERVAL);
            cluster->priv->election->election_wins = 0;
            cluster->priv->election->expires = tm_now + STORM_INTERVAL;
            if (!(cluster->priv->election->wrote_blackbox)) {
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
                cluster->priv->election->wrote_blackbox = true;
            }
        }
    }

    if (done) {
        do_crm_log(log_level + 1,
                   "Processed election round %u %s (current round %d) "
                   "from %s (%s)",
                   vote.election_id, vote.op, cluster->priv->election->count,
                   vote.from, reason);
        return cluster->priv->election->state;

    } else if (we_lose == FALSE) {
        /* We track the time of the last election loss to implement an election
         * dampening period, reducing the likelihood of an election storm. If
         * this node has lost within the dampening period, don't start a new
         * election, even if we win against a peer's vote -- the peer we lost to
         * should win again.
         *
         * @TODO This has a problem case: if an election winner immediately
         * leaves the cluster, and a new election is immediately called, all
         * nodes could lose, with no new winner elected. The ideal solution
         * would be to tie the election structure with the peer caches, which
         * would allow us to clear the dampening when the previous winner
         * leaves (and would allow other improvements as well).
         */
        if ((cluster->priv->election->last_election_loss == 0)
            || ((tm_now - cluster->priv->election->last_election_loss)
                > (time_t) LOSS_DAMPEN)) {

            do_crm_log(log_level,
                       "Election round %d (started by node ID %s) pass: "
                       "%s from %s (%s)",
                       vote.election_id, vote.election_owner, vote.op,
                       vote.from, reason);

            cluster->priv->election->last_election_loss = 0;
            election_timeout_stop(cluster);

            /* Start a new election by voting down this, and other, peers */
            cluster->priv->election->state = election_start;
            return cluster->priv->election->state;
        } else {
            char *loss_time = NULL;

            loss_time = ctime(&(cluster->priv->election->last_election_loss));
            if (loss_time) {
                // Show only HH:MM:SS
                loss_time += 11;
                loss_time[8] = '\0';
            }
            crm_info("Ignoring election round %d (started by node ID %s) pass "
                     "vs %s because we lost less than %ds ago at %s",
                     vote.election_id, vote.election_owner, vote.from,
                     LOSS_DAMPEN, (loss_time? loss_time : "unknown"));
        }
    }

    cluster->priv->election->last_election_loss = tm_now;

    do_crm_log(log_level,
               "Election round %d (started by node ID %s) lost: "
               "%s from %s (%s)",
               vote.election_id, vote.election_owner, vote.op,
               vote.from, reason);

    election_reset(cluster);
    send_no_vote(cluster, your_node, &vote);
    cluster->priv->election->state = election_lost;
    return cluster->priv->election->state;
}

/*!
 * \internal
 * \brief Reset any election dampening currently in effect
 *
 * \param[in,out] cluster  Cluster with election
 */
void
election_clear_dampening(pcmk_cluster_t *cluster)
{
    if ((cluster != NULL) && (cluster->priv->election != NULL)) {
        cluster->priv->election->last_election_loss = 0;
    }
}

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

struct election_s
{
        enum election_result state;
        guint count;
        char *name;
        char *uname;
        GSourceFunc cb;
        GHashTable *voted;
        mainloop_timer_t *timeout; /* When to stop if not everyone casts a vote */
};

static void election_complete(election_t *e)
{
    crm_info("Election %s complete", e->name);
    e->state = election_won;

    if(e->cb) {
        e->cb(e);
    }

    election_reset(e);
}

static gboolean election_timer_cb(gpointer user_data)
{
    election_t *e = user_data;

    crm_info("Election %s %p timed out", e->name, e);
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
    static guint count = 0;
    election_t *e = calloc(1, sizeof(election_t));

    if(e != NULL) {
        if(name) {
            e->name = crm_strdup_printf("election-%s", name);
        } else {
            e->name = crm_strdup_printf("election-%u", count++);
        }

        e->cb = cb;
        e->uname = strdup(uname);
        e->timeout = mainloop_timer_add(e->name, period_ms, FALSE, election_timer_cb, e);
        crm_trace("Created %s %p", e->name, e);
    }
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

    if(e == NULL) {
        crm_trace("Not voting in election: not initialized");
        return;
    }

    our_node = crm_get_peer(0, e->uname);
    if (our_node == NULL || crm_is_peer_active(our_node) == FALSE) {
        crm_trace("Cannot vote yet: %p", our_node);
        return;
    }

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

    crm_debug("Started election %d", e->count);
    if (e->voted) {
        g_hash_table_destroy(e->voted);
        e->voted = NULL;
    }

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
    int num_members = crm_active_peers();

    if(e == NULL) {
        crm_trace("not initialized");
        return FALSE;
    }

    if (e->voted) {
        voted_size = g_hash_table_size(e->voted);
    }
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

            g_hash_table_iter_init(&gIter, crm_peer_cache);
            while (g_hash_table_iter_next(&gIter, NULL, (gpointer *) & node)) {
                if (crm_is_peer_active(node)) {
                    crm_err("member: %s proc=%.32x", node->uname, node->processes);
                }
            }

            g_hash_table_iter_init(&gIter, e->voted);
            while (g_hash_table_iter_next(&gIter, (gpointer *) & key, NULL)) {
                crm_err("voted: %s", key);
            }

        }

        election_complete(e);
        return TRUE;

    } else {
        crm_debug("Still waiting on %d non-votes (%d total)",
                  num_members - voted_size, num_members);
    }

    return FALSE;
}

#define LOSS_DAMPEN 2           /* in seconds */

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
election_count_vote(election_t *e, xmlNode *vote, bool can_win)
{
    int age = 0;
    int election_id = -1;
    int log_level = LOG_INFO;
    gboolean done = FALSE;
    gboolean we_lose = FALSE;
    const char *op = NULL;
    const char *from = NULL;
    const char *reason = "unknown";
    const char *election_owner = NULL;
    crm_node_t *our_node = NULL, *your_node = NULL;

    static int election_wins = 0;

    xmlNode *novote = NULL;
    time_t tm_now = time(NULL);
    static time_t expires = 0;
    static time_t last_election_loss = 0;

    /* if the membership copy is NULL we REALLY shouldn't be voting
     * the question is how we managed to get here.
     */

    CRM_CHECK(vote != NULL, return election_error);

    if(e == NULL) {
        crm_info("Not voting in election: not initialized");
        return election_lost;

    } else if(crm_peer_cache == NULL) {
        crm_info("Not voting in election: no peer cache");
        return election_lost;
    }

    op = crm_element_value(vote, F_CRM_TASK);
    from = crm_element_value(vote, F_CRM_HOST_FROM);
    election_owner = crm_element_value(vote, F_CRM_ELECTION_OWNER);
    crm_element_value_int(vote, F_CRM_ELECTION_ID, &election_id);

    your_node = crm_get_peer(0, from);
    our_node = crm_get_peer(0, e->uname);

    if (e->voted == NULL) {
        crm_debug("Created voted hash");
        e->voted = crm_str_table_new();
    }

    if(can_win == FALSE) {
        reason = "Not eligible";
        we_lose = TRUE;

    } else if (our_node == NULL || crm_is_peer_active(our_node) == FALSE) {
        reason = "We are not part of the cluster";
        log_level = LOG_ERR;
        we_lose = TRUE;

    } else if (election_id != e->count && crm_str_eq(our_node->uuid, election_owner, TRUE)) {
        log_level = LOG_TRACE;
        reason = "Superseded";
        done = TRUE;

    } else if (your_node == NULL || crm_is_peer_active(your_node) == FALSE) {
        /* Possibly we cached the message in the FSA queue at a point that it wasn't */
        reason = "Peer is not part of our cluster";
        log_level = LOG_WARNING;
        done = TRUE;

    } else if (crm_str_eq(op, CRM_OP_NOVOTE, TRUE)) {
        char *op_copy = strdup(op);
        char *uname_copy = strdup(from);

        CRM_ASSERT(crm_str_eq(our_node->uuid, election_owner, TRUE));

        /* update the list of nodes that have voted */
        g_hash_table_replace(e->voted, uname_copy, op_copy);
        reason = "Recorded";
        done = TRUE;

    } else {
        struct timeval your_age;
        const char *your_version = crm_element_value(vote, F_CRM_VERSION);
        int tv_sec = 0;
        int tv_usec = 0;

        crm_element_value_int(vote, F_CRM_ELECTION_AGE_S, &tv_sec);
        crm_element_value_int(vote, F_CRM_ELECTION_AGE_US, &tv_usec);

        your_age.tv_sec = tv_sec;
        your_age.tv_usec = tv_usec;

        age = crm_compare_age(your_age);
        if (crm_str_eq(from, e->uname, TRUE)) {
            char *op_copy = strdup(op);
            char *uname_copy = strdup(from);

            CRM_ASSERT(crm_str_eq(our_node->uuid, election_owner, TRUE));

            /* update ourselves in the list of nodes that have voted */
            g_hash_table_replace(e->voted, uname_copy, op_copy);
            reason = "Recorded";
            done = TRUE;

        } else if (compare_version(your_version, CRM_FEATURE_SET) < 0) {
            reason = "Version";
            we_lose = TRUE;

        } else if (compare_version(your_version, CRM_FEATURE_SET) > 0) {
            reason = "Version";

        } else if (age < 0) {
            reason = "Uptime";
            we_lose = TRUE;

        } else if (age > 0) {
            reason = "Uptime";

        } else if (e->uname == NULL) {
            reason = "Unknown host name";
            we_lose = TRUE;

        } else if (strcasecmp(e->uname, from) > 0) {
            reason = "Host name";
            we_lose = TRUE;

        } else {
            reason = "Host name";
            CRM_ASSERT(strcasecmp(e->uname, from) < 0);
/* can't happen...
 *	} else if(strcasecmp(e->uname, from) == 0) {
 *
 */
        }
    }

    if (expires < tm_now) {
        election_wins = 0;
        expires = tm_now + STORM_INTERVAL;

    } else if (done == FALSE && we_lose == FALSE) {
        int peers = 1 + g_hash_table_size(crm_peer_cache);

        /* If every node has to vote down every other node, thats N*(N-1) total elections
         * Allow some leeway before _really_ complaining
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
                   election_id, e->count, election_owner, op, from, reason);
        return e->state;

    } else if (we_lose == FALSE) {
        do_crm_log(log_level, "Election %d (owner: %s) pass: %s from %s (%s)",
                   election_id, election_owner, op, from, reason);

        if (last_election_loss == 0
            || tm_now - last_election_loss > (time_t) LOSS_DAMPEN) {

            last_election_loss = 0;
            election_timeout_stop(e);

            /* Start a new election by voting down this, and other, peers */
            e->state = election_start;
            return e->state;
        }

        crm_info("Election %d ignore: We already lost an election less than %ds ago (%s)",
                 election_id, LOSS_DAMPEN, ctime(&last_election_loss));
    }

    novote = create_request(CRM_OP_NOVOTE, NULL, from,
                            CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

    do_crm_log(log_level, "Election %d (owner: %s) lost: %s from %s (%s)",
               election_id, election_owner, op, from, reason);

    election_timeout_stop(e);

    crm_xml_add(novote, F_CRM_ELECTION_OWNER, election_owner);
    crm_xml_add_int(novote, F_CRM_ELECTION_ID, election_id);

    send_cluster_message(your_node, crm_msg_crmd, novote, TRUE);
    free_xml(novote);

    last_election_loss = tm_now;
    e->state = election_lost;
    return e->state;
}

/*
 * Copyright 2009-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CRM_COMMON_ELECTION__H
#  define CRM_COMMON_ELECTION__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Functions for conducting elections
 *
 * An election is useful for a daemon that runs on all nodes but needs any one
 * instance to perform a special role.
 *
 * Elections are closely tied to the cluster peer cache. Peers in the cache that
 * are active members are eligible to vote. Elections are named for logging
 * purposes, but only one election may exist at any time, so typically an
 * election would be created at daemon start-up and freed at shutdown.
 *
 * Pacemaker's election procedure has been heavily adapted from the
 * Invitation Algorithm variant of the Garcia-Molina Bully Algorithm:
 *
 *   https://en.wikipedia.org/wiki/Bully_algorithm
 *
 * Elections are conducted via cluster messages. There are two types of
 * messages: a "vote" is a declaration of the voting node's candidacy, and is
 * always broadcast; a "no-vote" is a concession by the responding node, and is
 * always a reply to the preferred node's vote. (These correspond to "invite"
 * and "accept" in the traditional algorithm.)
 *
 * A vote together with any no-vote replies to it is considered an election
 * round. Rounds are numbered with a simple counter unique to each node
 * (this would be the group number in the traditional algorithm). Concurrent
 * election rounds are possible.
 *
 * An election round is started when any node broadcasts a vote. When a node
 * receives another node's vote, it compares itself against the sending node
 * according to certain metrics, and either starts a new round (if it prefers
 * itself) or replies to the other node with a no-vote (if it prefers that
 * node).
 *
 * If a node receives no-votes from all other active nodes, it declares itself
 * the winner. The library API does not notify other nodes of this; callers
 * must implement that if desired.
 */

typedef struct election_s election_t;

/*! Possible election states */
enum election_result {
    election_start = 0,     /*! new election needed */
    election_in_progress,   /*! election started but not all peers have voted */
    election_lost,          /*! local node lost most recent election */
    election_won,           /*! local node won most recent election */
    election_error,         /*! election message or election object invalid */
};

void election_fini(election_t *e);
void election_reset(election_t *e);
election_t *election_init(const char *name, const char *uname, guint period_ms, GSourceFunc cb);

void election_timeout_set_period(election_t *e, guint period_ms);
void election_timeout_stop(election_t *e);

void election_vote(election_t *e);
bool election_check(election_t *e);
void election_remove(election_t *e, const char *uname);
enum election_result election_state(const election_t *e);
enum election_result election_count_vote(election_t *e, const xmlNode *message,
                                         bool can_win);
void election_clear_dampening(election_t *e);

#ifdef __cplusplus
}
#endif

#endif

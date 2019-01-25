/*
 * Copyright 2013-2019 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster.h>
#include <crm/cluster/election.h>

#include "internal.h"

static char *peer_writer = NULL;
static election_t *writer = NULL;

void
attrd_election_init()
{
    writer = election_init(T_ATTRD, attrd_cluster->uname, 120000,
                           attrd_election_cb);
}

void
attrd_election_fini()
{
    election_fini(writer);
}

void
attrd_start_election_if_needed()
{
    if ((peer_writer == NULL)
        && (election_state(writer) != election_in_progress)) {
        crm_info("Starting an election to determine the writer");
        election_vote(writer);
    }
}

bool
attrd_election_won()
{
    return (election_state(writer) == election_won);
}

void
attrd_handle_election_op(const crm_node_t *peer, xmlNode *xml)
{
    enum election_result rc = 0;
    enum election_result previous = election_state(writer);

    crm_xml_add(xml, F_CRM_HOST_FROM, peer->uname);
    rc = election_count_vote(writer, xml, TRUE);
    switch(rc) {
        case election_start:
            crm_debug("Unsetting writer (was %s) and starting new election",
                      peer_writer? peer_writer : "unset");
            free(peer_writer);
            peer_writer = NULL;
            election_vote(writer);
            break;

        case election_lost:
            /* The election API should really distinguish between "we just lost
             * to this peer" and "we already lost previously, and we are
             * discarding this vote for some reason", but it doesn't.
             *
             * In the first case, we want to tentatively set the peer writer to
             * this peer, even though another peer may eventually win (which we
             * will learn via attrd_check_for_new_writer()), so
             * attrd_start_election_if_needed() doesn't start a new election.
             *
             * Approximate a test for that case as best as possible.
             */
            if ((peer_writer == NULL) || (previous != election_lost)) {
                free(peer_writer);
                peer_writer = strdup(peer->uname);
                crm_debug("Election lost, presuming %s is writer for now",
                          peer_writer);
            }
            break;

        case election_in_progress:
            election_check(writer);
            break;

        default:
            crm_info("Ignoring election op from %s due to error", peer->uname);
            break;
    }
}

bool
attrd_check_for_new_writer(const crm_node_t *peer, xmlNode *xml)
{
    int peer_state = 0;

    crm_element_value_int(xml, F_ATTRD_WRITER, &peer_state);
    if (peer_state == election_won) {
        if ((election_state(writer) == election_won)
           && safe_str_neq(peer->uname, attrd_cluster->uname)) {
            crm_notice("Detected another attribute writer (%s), starting new election",
                       peer->uname);
            election_vote(writer);

        } else if (safe_str_neq(peer->uname, peer_writer)) {
            crm_notice("Recorded new attribute writer: %s (was %s)",
                       peer->uname, (peer_writer? peer_writer : "unset"));
            free(peer_writer);
            peer_writer = strdup(peer->uname);
        }
    }
    return (peer_state == election_won);
}

void
attrd_declare_winner()
{
    crm_notice("Recorded local node as attribute writer (was %s)",
               (peer_writer? peer_writer : "unset"));
    free(peer_writer);
    peer_writer = strdup(attrd_cluster->uname);
}

void
attrd_remove_voter(const crm_node_t *peer)
{
    election_remove(writer, peer->uname);
    if (peer_writer && safe_str_eq(peer->uname, peer_writer)) {
        free(peer_writer);
        peer_writer = NULL;
        crm_notice("Lost attribute writer %s", peer->uname);

        /* Clear any election dampening in effect. Otherwise, if the lost writer
         * had just won, the election could fizzle out with no new writer.
         */
        election_clear_dampening(writer);

        /* If the writer received attribute updates during its shutdown, it will
         * not have written them to the CIB. Ensure we get a new writer so they
         * are written out. This means that every node that sees the writer
         * leave will start a new election, but that's better than losing
         * attributes.
         */
        attrd_start_election_if_needed();
    }
}

void
attrd_xml_add_writer(xmlNode *xml)
{
    crm_xml_add_int(xml, F_ATTRD_WRITER, election_state(writer));
}

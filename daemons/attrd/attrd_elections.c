/*
 * Copyright 2013-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/cluster.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

static char *peer_writer = NULL;

static void
attrd_election_cb(pcmk_cluster_t *cluster)
{
    attrd_declare_winner();

    /* Update the peers after an election */
    attrd_peer_sync(NULL);

    /* After winning an election, update the CIB with the values of all
     * attributes as the winner knows them.
     */
    attrd_write_attributes(attrd_write_all);
}

void
attrd_election_init(void)
{
    election_init(attrd_cluster, attrd_election_cb);
}

void
attrd_start_election_if_needed(void)
{
    if ((peer_writer == NULL)
        && (election_state(attrd_cluster) != election_in_progress)
        && !attrd_shutting_down()) {

        crm_info("Starting an election to determine the writer");
        election_vote(attrd_cluster);
    }
}

bool
attrd_election_won(void)
{
    return (election_state(attrd_cluster) == election_won);
}

void
attrd_handle_election_op(const pcmk__node_status_t *peer, xmlNode *xml)
{
    enum election_result rc = 0;
    enum election_result previous = election_state(attrd_cluster);

    crm_xml_add(xml, PCMK__XA_SRC, peer->name);

    // Don't become writer if we're shutting down
    rc = election_count_vote(attrd_cluster, xml, !attrd_shutting_down());

    switch(rc) {
        case election_start:
            crm_debug("Unsetting writer (was %s) and starting new election",
                      peer_writer? peer_writer : "unset");
            free(peer_writer);
            peer_writer = NULL;
            election_vote(attrd_cluster);
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
                pcmk__str_update(&peer_writer, peer->name);
                crm_debug("Election lost, presuming %s is writer for now",
                          peer_writer);
            }
            break;

        case election_in_progress:
            election_check(attrd_cluster);
            break;

        default:
            crm_info("Ignoring election op from %s due to error", peer->name);
            break;
    }
}

bool
attrd_check_for_new_writer(const pcmk__node_status_t *peer, const xmlNode *xml)
{
    int peer_state = 0;

    crm_element_value_int(xml, PCMK__XA_ATTR_WRITER, &peer_state);
    if (peer_state == election_won) {
        if ((election_state(attrd_cluster) == election_won)
            && !pcmk__str_eq(peer->name, attrd_cluster->priv->node_name,
                             pcmk__str_casei)) {
            crm_notice("Detected another attribute writer (%s), starting new "
                       "election",
                       peer->name);
            election_vote(attrd_cluster);

        } else if (!pcmk__str_eq(peer->name, peer_writer, pcmk__str_casei)) {
            crm_notice("Recorded new attribute writer: %s (was %s)",
                       peer->name, pcmk__s(peer_writer, "unset"));
            pcmk__str_update(&peer_writer, peer->name);
        }
    }
    return (peer_state == election_won);
}

void
attrd_declare_winner(void)
{
    crm_notice("Recorded local node as attribute writer (was %s)",
               (peer_writer? peer_writer : "unset"));
    pcmk__str_update(&peer_writer, attrd_cluster->priv->node_name);
}

void
attrd_remove_voter(const pcmk__node_status_t *peer)
{
    election_remove(attrd_cluster, peer->name);
    if ((peer_writer != NULL)
        && pcmk__str_eq(peer->name, peer_writer, pcmk__str_casei)) {

        free(peer_writer);
        peer_writer = NULL;
        crm_notice("Lost attribute writer %s", peer->name);

        /* Clear any election dampening in effect. Otherwise, if the lost writer
         * had just won, the election could fizzle out with no new writer.
         */
        election_clear_dampening(attrd_cluster);

        /* If the writer received attribute updates during its shutdown, it will
         * not have written them to the CIB. Ensure we get a new writer so they
         * are written out. This means that every node that sees the writer
         * leave will start a new election, but that's better than losing
         * attributes.
         */
        attrd_start_election_if_needed();

    /* If an election is in progress, we need to call election_check(), in case
     * this lost peer is the only one that hasn't voted, otherwise the election
     * would be pending until it's timed out.
     */
    } else if (election_state(attrd_cluster) == election_in_progress) {
       crm_debug("Checking election status upon loss of voter %s", peer->name);
       election_check(attrd_cluster);
    }
}

void
attrd_xml_add_writer(xmlNode *xml)
{
    crm_xml_add_int(xml, PCMK__XA_ATTR_WRITER, election_state(attrd_cluster));
}

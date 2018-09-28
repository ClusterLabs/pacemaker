/*
 * Copyright 2013-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/cluster.h>
#include <crm/cluster/election.h>

#include "pacemaker-attrd.h"

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

    crm_xml_add(xml, F_CRM_HOST_FROM, peer->uname);
    rc = election_count_vote(writer, xml, TRUE);
    switch(rc) {
        case election_start:
            free(peer_writer);
            peer_writer = NULL;
            crm_debug("Unsetting writer (was %s) and starting new election",
                      peer_writer? peer_writer : "unset");
            election_vote(writer);
            break;
        case election_lost:
            free(peer_writer);
            peer_writer = strdup(peer->uname);
            crm_debug("Election lost, presuming %s is writer for now",
                      peer_writer);
            break;
        default:
            election_check(writer);
            break;
    }
}

bool
attrd_check_for_new_writer(const crm_node_t *peer, const xmlNode *xml)
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
    if (peer_writer && safe_str_eq(peer->uname, peer_writer)) {
        free(peer_writer);
        peer_writer = NULL;
        crm_notice("Lost attribute writer %s", peer->uname);
    }
    election_remove(writer, peer->uname);
}

void
attrd_xml_add_writer(xmlNode *xml)
{
    crm_xml_add_int(xml, F_ATTRD_WRITER, election_state(writer));
}

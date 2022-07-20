/*
 * Copyright 2013-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <crm/cluster.h>
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/strings_internal.h>
#include <crm/msg_xml.h>

#include "pacemaker-attrd.h"

extern crm_exit_t attrd_exit_status;

static void
attrd_peer_message(crm_node_t *peer, xmlNode *xml)
{
    const char *op = crm_element_value(xml, PCMK__XA_TASK);
    const char *election_op = crm_element_value(xml, F_CRM_TASK);
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
    bool peer_won = false;

    if (election_op) {
        attrd_handle_election_op(peer, xml);
        return;
    }

    if (attrd_shutting_down()) {
        /* If we're shutting down, we want to continue responding to election
         * ops as long as we're a cluster member (because our vote may be
         * needed). Ignore all other messages.
         */
        return;
    }

    peer_won = attrd_check_for_new_writer(peer, xml);

    if (pcmk__str_any_of(op, PCMK__ATTRD_CMD_UPDATE, PCMK__ATTRD_CMD_UPDATE_BOTH,
                         PCMK__ATTRD_CMD_UPDATE_DELAY, NULL)) {
        attrd_peer_update(peer, xml, host, false);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_SYNC, pcmk__str_none)) {
        attrd_peer_sync(peer, xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_PEER_REMOVE, pcmk__str_none)) {
        attrd_peer_remove(host, true, peer->uname);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_CLEAR_FAILURE, pcmk__str_none)) {
        /* It is not currently possible to receive this as a peer command,
         * but will be, if we one day enable propagating this operation.
         */
        attrd_peer_clear_failure(peer, xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_SYNC_RESPONSE, pcmk__str_none)
               && !pcmk__str_eq(peer->uname, attrd_cluster->uname, pcmk__str_casei)) {
        attrd_peer_sync_response(peer, peer_won, xml);

    } else if (pcmk__str_eq(op, PCMK__ATTRD_CMD_FLUSH, pcmk__str_none)) {
        /* Ignore. The flush command was removed in 2.0.0 but may be
         * received from peers running older versions.
         */
    }
}

static void
attrd_cpg_dispatch(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }

    if (kind == crm_class_cluster) {
        xml = string2xml(data);
    }

    if (xml == NULL) {
        crm_err("Bad message of class %d received from %s[%u]: '%.120s'", kind, from, nodeid, data);
    } else {
        crm_node_t *peer = crm_get_peer(nodeid, from);

        attrd_peer_message(peer, xml);
    }

    free_xml(xml);
    free(data);
}

static void
attrd_cpg_destroy(gpointer unused)
{
    if (attrd_shutting_down()) {
        crm_info("Corosync disconnection complete");

    } else {
        crm_crit("Lost connection to cluster layer, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }
}

int
attrd_cluster_connect(void)
{
    attrd_cluster = calloc(1, sizeof(crm_cluster_t));

    attrd_cluster->destroy = attrd_cpg_destroy;
    attrd_cluster->cpg.cpg_deliver_fn = attrd_cpg_dispatch;
    attrd_cluster->cpg.cpg_confchg_fn = pcmk_cpg_membership;

    crm_set_status_callback(&attrd_peer_change_cb);

    if (crm_cluster_connect(attrd_cluster) == FALSE) {
        crm_err("Cluster connection failed");
        return -ENOTCONN;
    }
    return pcmk_ok;
}

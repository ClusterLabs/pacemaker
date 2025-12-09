/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>                         // uint32_t, PRIu32
#include <stdlib.h>                           // NULL, free, size_t

#include <corosync/cpg.h>                     // cpg_handle_t, cpg_name
#include <glib.h>                             // gpointer
#include <libxml/tree.h>                      // xmlNode

#include <crm/cluster.h>                      // pcmk_cluster_connect
#include <crm/common/ipc.h>                   // pcmk_ipc_server
#include <crm/common/results.h>               // pcmk_rc_*

#include "pacemaker-fenced.h"

pcmk_cluster_t *fenced_cluster = NULL;

static void
stonith_peer_callback(xmlNode *msg, void *private_data)
{
    const char *remote_peer = pcmk__xe_get(msg, PCMK__XA_SRC);
    const char *op = pcmk__xe_get(msg, PCMK__XA_ST_OP);

    if (pcmk__str_eq(op, STONITH_OP_POKE, pcmk__str_none)) {
        return;
    }

    crm_log_xml_trace(msg, "Peer[inbound]");
    stonith_command(NULL, 0, 0, msg, remote_peer);
}

/*!
 * \internal
 * \brief Callback for peer status changes
 *
 * \param[in] type  What changed
 * \param[in] node  What peer had the change
 * \param[in] data  Previous value of what changed
 */
static void
fenced_peer_change_cb(enum pcmk__node_update type, pcmk__node_status_t *node,
                      const void *data)
{
    if ((type != pcmk__node_update_processes)
        && !pcmk__is_set(node->flags, pcmk__node_status_remote)) {
        /*
         * This is a hack until we can send to a nodeid and/or we fix node name lookups
         * These messages are ignored in stonith_peer_callback()
         */
        xmlNode *query = pcmk__xe_create(NULL, PCMK__XE_STONITH_COMMAND);

        pcmk__xe_set(query, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
        pcmk__xe_set(query, PCMK__XA_ST_OP, STONITH_OP_POKE);

        crm_debug("Broadcasting our uname because of node %" PRIu32,
                  node->cluster_layer_id);
        pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, query);

        pcmk__xml_free(query);
    }
}

#if SUPPORT_COROSYNC
/*!
 * \internal
 * \brief Callback for when a peer message is received
 *
 * \param[in]     handle     The cluster connection
 * \param[in]     group_name The group that \p nodeid is a member of
 * \param[in]     nodeid     Peer node that sent \p msg
 * \param[in]     pid        Process that sent \p msg
 * \param[in,out] msg        Received message
 * \param[in]     msg_len    Length of \p msg
 */
static void
fenced_cpg_dispatch(cpg_handle_t handle, const struct cpg_name *group_name,
                    uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk__cpg_message_data(handle, nodeid, pid, msg, &from);

    if (data == NULL) {
        return;
    }

    xml = pcmk__xml_parse(data);
    if (xml == NULL) {
        crm_err("Bad message received from %s[%" PRIu32 "]: '%.120s'",
                from, nodeid, data);
    } else {
        pcmk__xe_set(xml, PCMK__XA_SRC, from);
        stonith_peer_callback(xml, NULL);
    }

    pcmk__xml_free(xml);
    free(data);
}

/*!
 * \internal
 * \brief Callback for when the cluster object is destroyed
 *
 * \param[in] unused Unused
 */
static void
fenced_cpg_destroy(gpointer unused)
{
    crm_crit("Lost connection to cluster layer, shutting down");
    stonith_shutdown(0);
}
#endif // SUPPORT_COROSYNC

int
fenced_cluster_connect(void)
{
    int rc = pcmk_rc_ok;

    fenced_cluster = pcmk_cluster_new();

#if SUPPORT_COROSYNC
    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        pcmk_cluster_set_destroy_fn(fenced_cluster, fenced_cpg_destroy);
        pcmk_cpg_set_deliver_fn(fenced_cluster, fenced_cpg_dispatch);
        pcmk_cpg_set_confchg_fn(fenced_cluster, pcmk__cpg_confchg_cb);
    }
#endif // SUPPORT_COROSYNC

    pcmk__cluster_set_status_callback(&fenced_peer_change_cb);

    rc = pcmk_cluster_connect(fenced_cluster);
    if (rc != pcmk_rc_ok) {
        crm_err("Cluster connection failed");
    }

    return rc;
}

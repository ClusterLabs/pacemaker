/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>               // PRIu32
#include <stddef.h>                 // NULL, size_t
#include <stdint.h>                 // uint32_t
#include <stdlib.h>                 // free

#include <corosync/cpg.h>           // cpg_*
#include <glib.h>                   // gpointer
#include <libxml/tree.h>            // xmlNode

#include <crm_config.h>             // SUPPORT_COROSYNC
#include <crm/cluster.h>            // pcmk_cluster_*
#include <crm/cluster/internal.h>   // pcmk__cluster_*, etc.
#include <crm/common/internal.h>    // pcmk__err, pcmk__xml_free, etc.
#include <crm/common/results.h>     // CRM_EX_DISCONNECT, pcmk_rc_ok

#include "pacemaker-based.h"

static pcmk_cluster_t *cluster = NULL;

static void
based_peer_message(pcmk__node_status_t *peer, xmlNode *xml)
{
    int rc = pcmk_rc_ok;

    if (based_shutting_down()) {
        pcmk__info("Ignoring CPG message from %s[%" PRIu32 "] during shutdown",
                   peer->name, peer->cluster_layer_id);
        return;

    } else {
        pcmk__request_t request = {
            .ipc_client     = NULL,
            .ipc_id         = 0,
            .ipc_flags      = 0,
            .peer           = peer->name,
            .xml            = xml,
            .call_options   = cib_none,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        rc = pcmk__xe_get_flags(xml, PCMK__XA_CIB_CALLOPT,
                                (uint32_t *) &request.call_options, cib_none);
        if (rc != pcmk_rc_ok) {
            pcmk__warn("Couldn't parse options from request: %s",
                       pcmk_rc_str(rc));
        }

        request.op = pcmk__xe_get_copy(request.xml, PCMK__XA_CIB_OP);
        CRM_CHECK(request.op != NULL, return);

        if (pcmk__is_set(request.call_options, cib_sync_call)) {
            pcmk__set_request_flags(&request, pcmk__request_sync);
        }

        if (pcmk__xe_get(request.xml, PCMK__XA_CIB_CLIENTNAME) == NULL) {
            pcmk__xe_set(request.xml, PCMK__XA_CIB_CLIENTNAME,
                         pcmk__xe_get(request.xml, PCMK__XA_SRC));
        }

        based_handle_request(&request);
    }
}

#if SUPPORT_COROSYNC
/*!
 * \internal
 * \brief Callback for when a peer message is received
 *
 * \param[in]     handle      Cluster connection
 * \param[in]     group_name  Group that \p nodeid is a member of
 * \param[in]     nodeid      Peer node that sent \p msg
 * \param[in]     pid         Process that sent \p msg
 * \param[in,out] msg         Received message
 * \param[in]     msg_len     Length of \p msg
 */
static void
based_cpg_dispatch(cpg_handle_t handle, const struct cpg_name *group_name,
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
        pcmk__err("Bad message received from %s[%" PRIu32 "]: '%.120s'", from,
                  nodeid, data);

    } else {
        pcmk__xe_set(xml, PCMK__XA_SRC, from);
        based_peer_message(pcmk__get_node(nodeid, from, NULL,
                                          pcmk__node_search_cluster_member),
                           xml);
    }

    pcmk__xml_free(xml);
    free(data);
}

static void
based_cpg_destroy(gpointer user_data)
{
    if (based_shutting_down()) {
        pcmk__info("Corosync disconnection complete");
        return;
    }

    pcmk__crit("Exiting after losing connection to cluster layer");
    based_quit_main_loop(CRM_EX_DISCONNECT);
}
#endif

/*!
 * \internal
 * \brief Initialize the cluster object and connect to the cluster layer
 *
 * \return Standard Pacemaker return code
 */
int
based_cluster_connect(void)
{
    int rc = pcmk_rc_ok;

    cluster = pcmk_cluster_new();

#if SUPPORT_COROSYNC
    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        pcmk_cluster_set_destroy_fn(cluster, based_cpg_destroy);
        pcmk_cpg_set_deliver_fn(cluster, based_cpg_dispatch);
        pcmk_cpg_set_confchg_fn(cluster, pcmk__cpg_confchg_cb);
    }
#endif // SUPPORT_COROSYNC

    rc = pcmk_cluster_connect(cluster);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Cluster connection failed");
    }

    return rc;
}

/*!
 * \internal
 * \brief Disconnect from the cluster layer and free the cluster object
 */
void
based_cluster_disconnect(void)
{
    if (cluster == NULL) {
        return;
    }

    pcmk_cluster_disconnect(cluster);
    g_clear_pointer(&cluster, pcmk_cluster_free);
}

/*!
 * \internal
 * \brief Get the local node name at the cluster layer
 *
 * \return Local cluster-layer node name, or \c NULL if there is no active
 *         cluster connection
 */
const char *
based_cluster_node_name(void)
{
    return (cluster != NULL)? cluster->priv->node_name : NULL;
}

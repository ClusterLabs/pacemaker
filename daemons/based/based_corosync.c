/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
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

pcmk_cluster_t *based_cluster = NULL;

static void
based_peer_callback(xmlNode *msg, void *private_data)
{
    const char *reason = NULL;
    const char *originator = pcmk__xe_get(msg, PCMK__XA_SRC);

    if (pcmk__peer_cache == NULL) {
        reason = "membership not established";
        goto bail;
    }

    if (pcmk__xe_get(msg, PCMK__XA_CIB_CLIENTNAME) == NULL) {
        pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTNAME, originator);
    }

    based_process_request(msg, true, NULL);
    return;

  bail:
    if (reason) {
        const char *op = pcmk__xe_get(msg, PCMK__XA_CIB_OP);

        pcmk__warn("Discarding %s message from %s: %s", op, originator, reason);
    }
}

#if SUPPORT_COROSYNC
static void
based_cpg_dispatch(cpg_handle_t handle,
                   const struct cpg_name *groupName,
                   uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk__cpg_message_data(handle, nodeid, pid, msg, &from);

    if(data == NULL) {
        return;
    }

    xml = pcmk__xml_parse(data);
    if (xml == NULL) {
        pcmk__err("Invalid XML: '%.120s'", data);
        free(data);
        return;
    }
    pcmk__xe_set(xml, PCMK__XA_SRC, from);
    based_peer_callback(xml, NULL);

    pcmk__xml_free(xml);
    free(data);
}

static void
based_cpg_destroy(gpointer user_data)
{
    if (cib_shutdown_flag) {
        pcmk__info("Corosync disconnection complete");
    } else {
        pcmk__crit("Exiting immediately after losing connection to cluster "
                   "layer");
        based_terminate(CRM_EX_DISCONNECT);
    }
}
#endif

/*!
 * \internal
 * \brief Initialize \c based_cluster and connect to the cluster layer
 *
 * \return Standard Pacemaker return code
 */
int
based_cluster_connect(void)
{
    int rc = pcmk_rc_ok;

    based_cluster = pcmk_cluster_new();

#if SUPPORT_COROSYNC
    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        pcmk_cluster_set_destroy_fn(based_cluster, based_cpg_destroy);
        pcmk_cpg_set_deliver_fn(based_cluster, based_cpg_dispatch);
        pcmk_cpg_set_confchg_fn(based_cluster, pcmk__cpg_confchg_cb);
    }
#endif // SUPPORT_COROSYNC

    rc = pcmk_cluster_connect(based_cluster);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Cluster connection failed");
    }

    return rc;
}

/*!
 * \internal
 * \brief Disconnect from the cluster layer and free \c based_cluster
 */
void
based_cluster_disconnect(void)
{
    if (based_cluster == NULL) {
        return;
    }

    pcmk_cluster_disconnect(based_cluster);
    g_clear_pointer(&based_cluster, pcmk_cluster_free);
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
    return (based_cluster != NULL)? based_cluster->priv->node_name : NULL;
}

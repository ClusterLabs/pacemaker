/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <dlfcn.h>

#include <inttypes.h>               // PRIu32
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/utsname.h>            // uname()

#include <glib.h>                   // gboolean

#include <crm/crm.h>

#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>
#include "crmcluster_private.h"

/*!
 * \internal
 * \brief Get a node's XML ID in the CIB, setting it if not already set
 *
 * \param[in,out] node  Node to check
 *
 * \return CIB XML ID of \p node if known, otherwise \c NULL
 */
const char *
pcmk__cluster_get_xml_id(pcmk__node_status_t *node)
{
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();

    if (node == NULL) {
        return NULL;
    }
    if (node->xml_id != NULL) {
        return node->xml_id;
    }

    // xml_id is always set when a Pacemaker Remote node entry is created
    CRM_CHECK(!pcmk__is_set(node->flags, pcmk__node_status_remote),
              return NULL);

    switch (cluster_layer) {
#if SUPPORT_COROSYNC
        case pcmk_cluster_layer_corosync:
            node->xml_id = pcmk__corosync_uuid(node);
            return node->xml_id;
#endif  // SUPPORT_COROSYNC

        default:
            pcmk__err("Unsupported cluster layer %s",
                      pcmk_cluster_layer_text(cluster_layer));
            return NULL;
    }
}

/*!
 * \internal
 * \brief Connect to the cluster layer
 *
 * \param[in,out] cluster  Initialized cluster object to connect
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_cluster_connect(pcmk_cluster_t *cluster)
{
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();
    const char *cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);

    if (cluster == NULL) {
        return EINVAL;
    }

    // cts-lab looks for this message
    pcmk__notice("Connecting to %s cluster layer", cluster_layer_s);

    switch (cluster_layer) {
#if SUPPORT_COROSYNC
        case pcmk_cluster_layer_corosync:
            return pcmk__corosync_connect(cluster);
#endif // SUPPORT_COROSYNC

        default:
            break;
    }

    pcmk__err("Failed to connect to unsupported cluster layer %s",
              cluster_layer_s);
    return EPROTONOSUPPORT;
}

/*!
 * \brief Disconnect from the cluster layer
 *
 * \param[in,out] cluster  Cluster object to disconnect
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_cluster_disconnect(pcmk_cluster_t *cluster)
{
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();
    const char *cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);

    pcmk__info("Disconnecting from %s cluster layer", cluster_layer_s);

    switch (cluster_layer) {
#if SUPPORT_COROSYNC
        case pcmk_cluster_layer_corosync:
            pcmk__corosync_disconnect(cluster);
            pcmk__cluster_destroy_node_caches();
            return pcmk_rc_ok;
#endif // SUPPORT_COROSYNC

        default:
            break;
    }

    pcmk__err("Failed to disconnect from unsupported cluster layer %s",
              cluster_layer_s);
    return EPROTONOSUPPORT;
}

/*!
 * \brief Allocate a new \p pcmk_cluster_t object
 *
 * \return A newly allocated \p pcmk_cluster_t object (guaranteed not \c NULL)
 * \note The caller is responsible for freeing the return value using
 *       \p pcmk_cluster_free().
 */
pcmk_cluster_t *
pcmk_cluster_new(void)
{
    pcmk_cluster_t *cluster = pcmk__assert_alloc(1, sizeof(pcmk_cluster_t));

    cluster->priv = pcmk__assert_alloc(1, sizeof(pcmk__cluster_private_t));
    cluster->priv->server = pcmk__parse_server(crm_system_name);
    return cluster;
}

/*!
 * \brief Free a \p pcmk_cluster_t object and its dynamically allocated members
 *
 * \param[in,out] cluster  Cluster object to free
 */
void
pcmk_cluster_free(pcmk_cluster_t *cluster)
{
    if (cluster == NULL) {
        return;
    }
    election_fini(cluster);
    free(cluster->priv->node_xml_id);
    free(cluster->priv->node_name);
    free(cluster->priv);
    free(cluster);
}

/*!
 * \brief Set the destroy function for a cluster object
 *
 * \param[in,out] cluster  Cluster object
 * \param[in]     fn       Destroy function to set
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_cluster_set_destroy_fn(pcmk_cluster_t *cluster, void (*fn)(gpointer))
{
    if (cluster == NULL) {
        return EINVAL;
    }
    cluster->destroy = fn;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Send an XML message via the cluster messaging layer
 *
 * \param[in] node     Cluster node to send message to
 * \param[in] service  Message type to use in message host info
 * \param[in] data     XML message to send
 *
 * \return \c true on success, or \c false otherwise
 */
bool
pcmk__cluster_send_message(const pcmk__node_status_t *node,
                           enum pcmk_ipc_server service, const xmlNode *data)
{
    // @TODO Return standard Pacemaker return code
    switch (pcmk_get_cluster_layer()) {
#if SUPPORT_COROSYNC
        case pcmk_cluster_layer_corosync:
            return pcmk__cpg_send_xml(data, node, service);
#endif  // SUPPORT_COROSYNC

        default:
            break;
    }
    return false;
}

/*!
 * \internal
 * \brief Get the node name corresponding to a cluster-layer node ID
 *
 * Get the node name from the cluster layer if possible. Otherwise, if for the
 * local node, call \c uname() and get the \c nodename member from the
 * <tt>struct utsname</tt> object.
 *
 * \param[in] nodeid  Node ID to check (or 0 for the local node)
 *
 * \return Node name corresponding to \p nodeid
 *
 * \note This will fatally exit if \c uname() fails to get the local node name
 *       or we run out of memory.
 * \note The caller is responsible for freeing the return value using \c free().
 */
char *
pcmk__cluster_node_name(uint32_t nodeid)
{
    char *name = NULL;
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();
    const char *cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);

    switch (cluster_layer) {
#if SUPPORT_COROSYNC
        case pcmk_cluster_layer_corosync:
            name = pcmk__corosync_name(0, nodeid);
            if (name != NULL) {
                return name;
            }
            break;
#endif // SUPPORT_COROSYNC

        default:
            pcmk__err("Unsupported cluster layer: %s", cluster_layer_s);
            break;
    }

    if (nodeid == 0) {
        struct utsname hostinfo;

        pcmk__notice("Could not get local node name from %s cluster layer, "
                     "defaulting to local hostname",
                     cluster_layer_s);

        if (uname(&hostinfo) < 0) {
            // @TODO Maybe let the caller decide what to do
            pcmk__err("Failed to get the local hostname");
            crm_exit(CRM_EX_FATAL);
        }
        return pcmk__str_copy(hostinfo.nodename);
    }

    pcmk__notice("Could not obtain a node name for node with "
                 PCMK_XA_ID "=%" PRIu32,
                 nodeid);
    return NULL;
}

/*!
 * \internal
 * \brief Get the local node's cluster-layer node name
 *
 * If getting the node name from the cluster layer is impossible, call
 * \c uname() and get the \c nodename member from the <tt>struct utsname</tt>
 * object.
 *
 * \return Local node's name
 *
 * \note This will fatally exit if \c uname() fails to get the local node name
 *       or we run out of memory.
 */
const char *
pcmk__cluster_local_node_name(void)
{
    // @TODO Refactor to avoid trivially leaking name at exit
    static char *name = NULL;

    if (name == NULL) {
        name = pcmk__cluster_node_name(0);
    }
    return name;
}

/*!
 * \internal
 * \brief Get the node name corresonding to a node UUID
 *
 * Look for the UUID in both the remote node cache and the cluster member cache.
 *
 * \param[in] uuid  UUID to search for
 *
 * \return Node name corresponding to \p uuid if found, or \c NULL otherwise
 */
const char *
pcmk__node_name_from_uuid(const char *uuid)
{
    /* @TODO There are too many functions in libcrmcluster that look up a node
     * from the node caches (possibly creating a cache entry if none exists).
     * There are at least the following:
     * * pcmk__cluster_lookup_remote_node()
     * * pcmk__get_node()
     * * pcmk__node_name_from_uuid()
     * * pcmk__search_node_caches()
     *
     * There's a lot of duplication among them, but they all do slightly
     * different things. We should try to clean them up and consolidate them to
     * the extent possible, likely with new helper functions.
     */
    GHashTableIter iter;
    pcmk__node_status_t *node = NULL;

    CRM_CHECK(uuid != NULL, return NULL);

    // Remote nodes have the same uname and uuid
    if (g_hash_table_lookup(pcmk__remote_peer_cache, uuid)) {
        return uuid;
    }

    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        if (pcmk__str_eq(uuid, pcmk__cluster_get_xml_id(node),
                         pcmk__str_none)) {
            return node->name;
        }
    }
    return NULL;
}

/*!
 * \brief Get a log-friendly string equivalent of a cluster layer
 *
 * \param[in] layer  Cluster layer
 *
 * \return Log-friendly string corresponding to \p layer
 */
const char *
pcmk_cluster_layer_text(enum pcmk_cluster_layer layer)
{
    switch (layer) {
        case pcmk_cluster_layer_corosync:
            return "corosync";
        case pcmk_cluster_layer_unknown:
            return "unknown";
        case pcmk_cluster_layer_invalid:
            return "invalid";
        default:
            pcmk__err("Invalid cluster layer: %d", layer);
            return "invalid";
    }
}

/*!
 * \brief Get and validate the local cluster layer
 *
 * If a cluster layer is not configured via the \c PCMK__ENV_CLUSTER_TYPE local
 * option, this will try to detect an active cluster from among the supported
 * cluster layers.
 *
 * \return Local cluster layer
 *
 * \note This will fatally exit if the configured cluster layer is invalid.
 */
enum pcmk_cluster_layer
pcmk_get_cluster_layer(void)
{
    static enum pcmk_cluster_layer cluster_layer = pcmk_cluster_layer_unknown;
    const char *cluster = NULL;

    // Cluster layer is stable once set
    if (cluster_layer != pcmk_cluster_layer_unknown) {
        return cluster_layer;
    }

    cluster = pcmk__env_option(PCMK__ENV_CLUSTER_TYPE);

    if (cluster != NULL) {
        pcmk__info("Verifying configured cluster layer '%s'", cluster);
        cluster_layer = pcmk_cluster_layer_invalid;

#if SUPPORT_COROSYNC
        if (pcmk__str_eq(cluster, PCMK_VALUE_COROSYNC, pcmk__str_casei)) {
            cluster_layer = pcmk_cluster_layer_corosync;
        }
#endif  // SUPPORT_COROSYNC

        if (cluster_layer == pcmk_cluster_layer_invalid) {
            pcmk__notice("This installation does not support the '%s' cluster "
                         "infrastructure: terminating",
                         cluster);
            crm_exit(CRM_EX_FATAL);
        }
        pcmk__info("Assuming an active '%s' cluster", cluster);

    } else {
        // Nothing configured, so test supported cluster layers
#if SUPPORT_COROSYNC
        pcmk__debug("Testing with Corosync");
        if (pcmk__corosync_is_active()) {
            cluster_layer = pcmk_cluster_layer_corosync;
        }
#endif  // SUPPORT_COROSYNC

        if (cluster_layer == pcmk_cluster_layer_unknown) {
            pcmk__notice("Could not determine the current cluster layer");
        } else {
            pcmk__info("Detected an active '%s' cluster",
                       pcmk_cluster_layer_text(cluster_layer));
        }
    }

    return cluster_layer;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/cluster/compat.h>

gboolean
crm_cluster_connect(pcmk_cluster_t *cluster)
{
    if (cluster == NULL) {
        return FALSE;
    }
    if (cluster->priv == NULL) {
        /* sbd (as of at least 1.5.2) doesn't call pcmk_cluster_new() to
         * allocate the pcmk_cluster_t
         */
        cluster->priv = pcmk__assert_alloc(1, sizeof(pcmk__cluster_private_t));
    }
    return pcmk_cluster_connect(cluster) == pcmk_rc_ok;
}

const char *
name_for_cluster_type(enum cluster_type_e type)
{
    switch (type) {
        case pcmk_cluster_corosync:
            return "corosync";
        case pcmk_cluster_unknown:
            return "unknown";
        case pcmk_cluster_invalid:
            return "invalid";
    }
    pcmk__err("Invalid cluster type: %d", type);
    return "invalid";
}

enum cluster_type_e
get_cluster_type(void)
{
    return (enum cluster_type_e) pcmk_get_cluster_layer();
}

// LCOV_EXCL_STOP
// End deprecated API

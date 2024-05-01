/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <dlfcn.h>

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>

#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>
#include "crmcluster_private.h"

CRM_TRACE_INIT_DATA(cluster);

/*!
 * \brief Get (and set if needed) a node's UUID
 *
 * \param[in,out] peer  Node to check
 *
 * \return Node UUID of \p peer, or NULL if unknown
 */
const char *
crm_peer_uuid(crm_node_t *peer)
{
    char *uuid = NULL;

    // Check simple cases first, to avoid any calls that might block
    if (peer == NULL) {
        return NULL;
    }
    if (peer->uuid != NULL) {
        return peer->uuid;
    }

    switch (pcmk_get_cluster_layer()) {
        case pcmk_cluster_layer_corosync:
#if SUPPORT_COROSYNC
            uuid = pcmk__corosync_uuid(peer);
#endif
            break;

        case pcmk_cluster_layer_unknown:
        case pcmk_cluster_layer_invalid:
            crm_err("Unsupported cluster layer");
            break;
    }

    peer->uuid = uuid;
    return peer->uuid;
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

    crm_notice("Connecting to %s cluster layer", cluster_layer_s);

    switch (cluster_layer) {
        case pcmk_cluster_layer_corosync:
#if SUPPORT_COROSYNC
            crm_peer_init();
            return pcmk__corosync_connect(cluster);
#else
            break;
#endif // SUPPORT_COROSYNC
        default:
            break;
    }

    crm_err("Failed to connect to unsupported cluster layer %s",
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

    crm_info("Disconnecting from %s cluster layer", cluster_layer_s);

    switch (cluster_layer) {
        case pcmk_cluster_layer_corosync:
#if SUPPORT_COROSYNC
            crm_peer_destroy();
            pcmk__corosync_disconnect(cluster);
            return pcmk_rc_ok;
#else
            break;
#endif // SUPPORT_COROSYNC
        default:
            break;
    }

    crm_err("Failed to disconnect from unsupported cluster layer %s",
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
    return (pcmk_cluster_t *) pcmk__assert_alloc(1, sizeof(pcmk_cluster_t));
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
    free(cluster->uuid);
    free(cluster->uname);
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
 * \brief Send an XML message via the cluster messaging layer
 *
 * \param[in] node     Cluster node to send message to
 * \param[in] service  Message type to use in message host info
 * \param[in] data     XML message to send
 * \param[in] ordered  Ignored for currently supported messaging layers
 *
 * \return TRUE on success, otherwise FALSE
 */
gboolean
send_cluster_message(const crm_node_t *node, enum crm_ais_msg_types service,
                     const xmlNode *data, gboolean ordered)
{
    switch (pcmk_get_cluster_layer()) {
        case pcmk_cluster_layer_corosync:
#if SUPPORT_COROSYNC
            return pcmk__cpg_send_xml(data, node, service);
#endif
            break;
        default:
            break;
    }
    return FALSE;
}

/*!
 * \brief Get the local node's name
 *
 * \return Local node's name
 * \note This will fatally exit if local node name cannot be known.
 */
const char *
get_local_node_name(void)
{
    static char *name = NULL;

    if (name == NULL) {
        name = get_node_name(0);
    }
    return name;
}

/*!
 * \brief Get the node name corresponding to a cluster node ID
 *
 * \param[in] nodeid  Node ID to check (or 0 for local node)
 *
 * \return Node name corresponding to \p nodeid
 * \note This will fatally exit if \p nodeid is 0 and local node name cannot be
 *       known.
 */
char *
get_node_name(uint32_t nodeid)
{
    char *name = NULL;
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();
    const char *cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);

    switch (cluster_layer) {
        case pcmk_cluster_layer_corosync:
#if SUPPORT_COROSYNC
            name = pcmk__corosync_name(0, nodeid);
            break;
#endif // SUPPORT_COROSYNC

        default:
            crm_err("Unknown cluster layer: %s (%d)",
                    cluster_layer_s, cluster_layer);
    }

    if ((name == NULL) && (nodeid == 0)) {
        name = pcmk_hostname();
        if (name == NULL) {
            // @TODO Maybe let the caller decide what to do
            crm_err("Could not obtain the local %s node name", cluster_layer_s);
            crm_exit(CRM_EX_FATAL);
        }
        crm_notice("Defaulting to uname -n for the local %s node name",
                   cluster_layer_s);
    }

    if (name == NULL) {
        crm_notice("Could not obtain a node name for %s node with "
                   PCMK_XA_ID " %u",
                   cluster_layer_s, nodeid);
    }
    return name;
}

/*!
 * \brief Get the node name corresponding to a node UUID
 *
 * \param[in] uuid  UUID of desired node
 *
 * \return name of desired node
 *
 * \note This relies on the remote peer cache being populated with all
 *       remote nodes in the cluster, so callers should maintain that cache.
 */
const char *
crm_peer_uname(const char *uuid)
{
    GHashTableIter iter;
    crm_node_t *node = NULL;

    CRM_CHECK(uuid != NULL, return NULL);

    /* remote nodes have the same uname and uuid */
    if (g_hash_table_lookup(crm_remote_peer_cache, uuid)) {
        return uuid;
    }

    /* avoid blocking calls where possible */
    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        if (pcmk__str_eq(node->uuid, uuid, pcmk__str_casei)) {
            if (node->uname != NULL) {
                return node->uname;
            }
            break;
        }
    }
    node = NULL;

    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        long long id;

        if ((pcmk__scan_ll(uuid, &id, 0LL) != pcmk_rc_ok)
            || (id < 1LL) || (id > UINT32_MAX))  {
            crm_err("Invalid Corosync node ID '%s'", uuid);
            return NULL;
        }

        node = pcmk__search_node_caches((uint32_t) id, NULL,
                                        pcmk__node_search_cluster);
        if (node != NULL) {
            crm_info("Setting uuid for node %s[%u] to %s",
                     node->uname, node->id, uuid);
            node->uuid = strdup(uuid);
            return node->uname;
        }
        return NULL;
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
            crm_err("Invalid cluster layer: %d", layer);
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
        crm_info("Verifying configured cluster layer '%s'", cluster);
        cluster_layer = pcmk_cluster_layer_invalid;

#if SUPPORT_COROSYNC
        if (pcmk__str_eq(cluster, PCMK_VALUE_COROSYNC, pcmk__str_casei)) {
            cluster_layer = pcmk_cluster_layer_corosync;
        }
#endif  // SUPPORT_COROSYNC

        if (cluster_layer == pcmk_cluster_layer_invalid) {
            crm_notice("This installation does not support the '%s' cluster "
                       "infrastructure: terminating",
                       cluster);
            crm_exit(CRM_EX_FATAL);
        }
        crm_info("Assuming an active '%s' cluster", cluster);

    } else {
        // Nothing configured, so test supported cluster layers
#if SUPPORT_COROSYNC
        crm_debug("Testing with Corosync");
        if (pcmk__corosync_is_active()) {
            cluster_layer = pcmk_cluster_layer_corosync;
        }
#endif  // SUPPORT_COROSYNC

        if (cluster_layer == pcmk_cluster_layer_unknown) {
            crm_notice("Could not determine the current cluster layer");
        } else {
            crm_info("Detected an active '%s' cluster",
                     pcmk_cluster_layer_text(cluster_layer));
        }
    }

    return cluster_layer;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/cluster/compat.h>

void
set_uuid(xmlNode *xml, const char *attr, crm_node_t *node)
{
    crm_xml_add(xml, attr, crm_peer_uuid(node));
}

gboolean
crm_cluster_connect(pcmk_cluster_t *cluster)
{
    return pcmk_cluster_connect(cluster) == pcmk_rc_ok;
}

void
crm_cluster_disconnect(pcmk_cluster_t *cluster)
{
    pcmk_cluster_disconnect(cluster);
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
    crm_err("Invalid cluster type: %d", type);
    return "invalid";
}

enum cluster_type_e
get_cluster_type(void)
{
    return (enum cluster_type_e) pcmk_get_cluster_layer();
}

gboolean
is_corosync_cluster(void)
{
    return pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync;
}

// LCOV_EXCL_STOP
// End deprecated API

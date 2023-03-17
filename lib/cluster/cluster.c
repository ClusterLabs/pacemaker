/*
 * Copyright 2004-2022 the Pacemaker project contributors
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
#include <crm/msg_xml.h>

#include <crm/common/ipc.h>
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

    switch (get_cluster_type()) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            uuid = pcmk__corosync_uuid(peer);
#endif
            break;

        case pcmk_cluster_unknown:
        case pcmk_cluster_invalid:
            crm_err("Unsupported cluster type");
            break;
    }

    peer->uuid = uuid;
    return peer->uuid;
}

/*!
 * \brief Connect to the cluster layer
 *
 * \param[in,out] Initialized cluster object to connect
 *
 * \return TRUE on success, otherwise FALSE
 */
gboolean
crm_cluster_connect(crm_cluster_t *cluster)
{
    enum cluster_type_e type = get_cluster_type();

    crm_notice("Connecting to %s cluster infrastructure",
               name_for_cluster_type(type));
    switch (type) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            crm_peer_init();
            return pcmk__corosync_connect(cluster);
#else
            break;
#endif // SUPPORT_COROSYNC
        default:
            break;
    }
    return FALSE;
}

/*!
 * \brief Disconnect from the cluster layer
 *
 * \param[in,out] cluster  Cluster object to disconnect
 */
void
crm_cluster_disconnect(crm_cluster_t *cluster)
{
    enum cluster_type_e type = get_cluster_type();

    crm_info("Disconnecting from %s cluster infrastructure",
             name_for_cluster_type(type));
    switch (type) {
        case pcmk_cluster_corosync:
#if SUPPORT_COROSYNC
            crm_peer_destroy();
            pcmk__corosync_disconnect(cluster);
#else
            break;
#endif // SUPPORT_COROSYNC
        default:
            break;
    }
}

/*!
 * \brief Allocate a new \p crm_cluster_t object
 *
 * \return A newly allocated \p crm_cluster_t object (guaranteed not \p NULL)
 * \note The caller is responsible for freeing the return value using
 *       \p pcmk_cluster_free().
 */
crm_cluster_t *
pcmk_cluster_new(void)
{
    crm_cluster_t *cluster = calloc(1, sizeof(crm_cluster_t));

    CRM_ASSERT(cluster != NULL);
    return cluster;
}

/*!
 * \brief Free a \p crm_cluster_t object and its dynamically allocated members
 *
 * \param[in,out] cluster  Cluster object to free
 */
void
pcmk_cluster_free(crm_cluster_t *cluster)
{
    if (cluster == NULL) {
        return;
    }
    free(cluster->uuid);
    free(cluster->uname);
    free(cluster);
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
                     xmlNode *data, gboolean ordered)
{
    switch (get_cluster_type()) {
        case pcmk_cluster_corosync:
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
    enum cluster_type_e stack = get_cluster_type();

    switch (stack) {
#  if SUPPORT_COROSYNC
        case pcmk_cluster_corosync:
            name = pcmk__corosync_name(0, nodeid);
            break;
#  endif

        default:
            crm_err("Unknown cluster type: %s (%d)", name_for_cluster_type(stack), stack);
    }

    if ((name == NULL) && (nodeid == 0)) {
        name = pcmk_hostname();
        if (name == NULL) {
            // @TODO Maybe let the caller decide what to do
            crm_err("Could not obtain the local %s node name",
                    name_for_cluster_type(stack));
            crm_exit(CRM_EX_FATAL);
        }
        crm_notice("Defaulting to uname -n for the local %s node name",
                   name_for_cluster_type(stack));
    }

    if (name == NULL) {
        crm_notice("Could not obtain a node name for %s node with id %u",
                   name_for_cluster_type(stack), nodeid);
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

#if SUPPORT_COROSYNC
    if (is_corosync_cluster()) {
        long long id;

        if ((pcmk__scan_ll(uuid, &id, 0LL) != pcmk_rc_ok)
            || (id < 1LL) || (id > UINT32_MAX))  {
            crm_err("Invalid Corosync node ID '%s'", uuid);
            return NULL;
        }

        node = pcmk__search_cluster_node_cache((uint32_t) id, NULL);
        if (node != NULL) {
            crm_info("Setting uuid for node %s[%u] to %s",
                     node->uname, node->id, uuid);
            node->uuid = strdup(uuid);
            return node->uname;
        }
        return NULL;
    }
#endif

    return NULL;
}

/*!
 * \brief Add a node's UUID as an XML attribute
 *
 * \param[in,out] xml   XML element to add UUID to
 * \param[in]     attr  XML attribute name to set
 * \param[in,out] node  Node whose UUID should be used as attribute value
 */
void
set_uuid(xmlNode *xml, const char *attr, crm_node_t *node)
{
    crm_xml_add(xml, attr, crm_peer_uuid(node));
}

/*!
 * \brief  Get a log-friendly string equivalent of a cluster type
 *
 * \param[in] type  Cluster type
 *
 * \return Log-friendly string corresponding to \p type
 */
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

/*!
 * \brief Get (and validate) the local cluster type
 *
 * \return Local cluster type
 * \note This will fatally exit if the local cluster type is invalid.
 */
enum cluster_type_e
get_cluster_type(void)
{
    bool detected = false;
    const char *cluster = NULL;
    static enum cluster_type_e cluster_type = pcmk_cluster_unknown;

    /* Return the previous calculation, if any */
    if (cluster_type != pcmk_cluster_unknown) {
        return cluster_type;
    }

    cluster = pcmk__env_option(PCMK__ENV_CLUSTER_TYPE);

#if SUPPORT_COROSYNC
    /* If nothing is defined in the environment, try corosync (if supported) */
    if (cluster == NULL) {
        crm_debug("Testing with Corosync");
        cluster_type = pcmk__corosync_detect();
        if (cluster_type != pcmk_cluster_unknown) {
            detected = true;
            goto done;
        }
    }
#endif

    /* Something was defined in the environment, test it against what we support */
    crm_info("Verifying cluster type: '%s'",
             ((cluster == NULL)? "-unspecified-" : cluster));
    if (cluster == NULL) {

#if SUPPORT_COROSYNC
    } else if (pcmk__str_eq(cluster, "corosync", pcmk__str_casei)) {
        cluster_type = pcmk_cluster_corosync;
#endif

    } else {
        cluster_type = pcmk_cluster_invalid;
        goto done; /* Keep the compiler happy when no stacks are supported */
    }

  done:
    if (cluster_type == pcmk_cluster_unknown) {
        crm_notice("Could not determine the current cluster type");

    } else if (cluster_type == pcmk_cluster_invalid) {
        crm_notice("This installation does not support the '%s' cluster infrastructure: terminating.",
                   cluster);
        crm_exit(CRM_EX_FATAL);

    } else {
        crm_info("%s an active '%s' cluster",
                 (detected? "Detected" : "Assuming"),
                 name_for_cluster_type(cluster_type));
    }

    return cluster_type;
}

/*!
 * \brief Check whether the local cluster is a Corosync cluster
 *
 * \return TRUE if the local cluster is a Corosync cluster, otherwise FALSE
 */
gboolean
is_corosync_cluster(void)
{
    return get_cluster_type() == pcmk_cluster_corosync;
}

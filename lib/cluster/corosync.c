/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // ENXIO, EINVAL
#include <inttypes.h>               // PRIu32, PRIu64, PRIx32
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdint.h>                 // uint32_t, uint64_t
#include <stdio.h>                  // sscanf
#include <stdlib.h>                 // free
#include <string.h>                 // strerror, strchr
#include <sys/types.h>              // gid_t, pid_t, uid_t
#include <unistd.h>                 // sleep

#include <corosync/cmap.h>          // cmap_*
#include <corosync/corotypes.h>     // cs_*, CS_*
#include <corosync/quorum.h>        // quorum_*
#include <glib.h>                   // gboolean, gpointer, g_*, G_PRIORITY_HIGH
#include <libxml/tree.h>            // xmlNode
#include <qb/qblog.h>               // QB_XS

#include <crm/cluster.h>            // pcmk_cluster_*, etc.
#include <crm/cluster/internal.h>   // pcmk__cluster_private_t members
#include <crm/common/internal.h>    // pcmk__corosync2rc, pcmk__err, etc.
#include <crm/common/ipc.h>         // crm_ipc_is_authentic_process
#include <crm/common/logging.h>     // CRM_LOG_ASSERT
#include <crm/common/mainloop.h>    // mainloop_*
#include <crm/common/options.h>     // PCMK_VALUE_MEMBER
#include <crm/common/results.h>     // CRM_EX_FATAL, crm_exit, pcmk_rc_*, etc.
#include <crm/common/xml.h>         // PCMK_XA_*, PCMK_XE_*

#include "crmcluster_private.h"

static quorum_handle_t pcmk_quorum_handle = 0;

static gboolean (*quorum_app_callback)(unsigned long long seq,
                                       gboolean quorate) = NULL;

/*!
 * \internal
 * \brief Get the Corosync UUID associated with a Pacemaker node
 *
 * \param[in] node  Pacemaker node
 *
 * \return Newly allocated string with node's Corosync UUID, or NULL if unknown
 * \note It is the caller's responsibility to free the result with free().
 */
char *
pcmk__corosync_uuid(const pcmk__node_status_t *node)
{
    pcmk__assert(pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync);

    if (node != NULL) {
        if (node->cluster_layer_id > 0) {
            return pcmk__assert_asprintf("%" PRIu32, node->cluster_layer_id);
        } else {
            pcmk__info("Node %s is not yet known by Corosync", node->name);
        }
    }
    return NULL;
}

static bool
node_name_is_valid(const char *key, const char *name)
{
    int octet;

    if (name == NULL) {
        pcmk__trace("%s is empty", key);
        return false;

    } else if (sscanf(name, "%d.%d.%d.%d", &octet, &octet, &octet, &octet) == 4) {
        pcmk__trace("%s contains an IPv4 address (%s), ignoring", key, name);
        return false;

    } else if (strchr(name, ':') != NULL) {
        pcmk__trace("%s contains an IPv6 address (%s), ignoring", key, name);
        return false;
    }
    pcmk__trace("'%s: %s' is valid", key, name);
    return true;
}

/*
 * \internal
 * \brief Get Corosync node name corresponding to a node ID
 *
 * \param[in] cmap_handle  Connection to Corosync CMAP
 * \param[in] nodeid       Node ID to check
 *
 * \return Newly allocated string with name or (if no name) IP address
 *         associated with first address assigned to a Corosync node ID (or NULL
 *         if unknown)
 * \note It is the caller's responsibility to free the result with free().
 */
char *
pcmk__corosync_name(uint64_t /*cmap_handle_t */ cmap_handle, uint32_t nodeid)
{
    // Originally based on corosync-quorumtool.c:node_name()

    int lpc = 0;
    cs_error_t rc = CS_OK;
    int retries = 0;
    char *name = NULL;
    cmap_handle_t local_handle = 0;
    int fd = -1;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;

    if (nodeid == 0) {
        nodeid = pcmk__cpg_local_nodeid(0);
    }

    if (cmap_handle == 0 && local_handle == 0) {
        retries = 0;
        pcmk__trace("Initializing CMAP connection");
        do {
            rc = pcmk__init_cmap(&local_handle);
            if (rc != CS_OK) {
                retries++;
                pcmk__debug("API connection setup failed: %s.  Retrying in %ds",
                            pcmk_rc_str(pcmk__corosync2rc(rc)), retries);
                sleep(retries);
            }

        } while (retries < 5 && rc != CS_OK);

        if (rc != CS_OK) {
            pcmk__warn("Could not connect to Cluster Configuration Database "
                       "API, error %s",
                       pcmk_rc_str(pcmk__corosync2rc(rc)));
            local_handle = 0;
        }
    }

    if (cmap_handle == 0) {
        cmap_handle = local_handle;

        rc = cmap_fd_get(cmap_handle, &fd);
        if (rc != CS_OK) {
            pcmk__err("Could not obtain the CMAP API connection: %s (%d)",
                      pcmk_rc_str(pcmk__corosync2rc(rc)), rc);
            goto bail;
        }

        /* CMAP provider run as root (in given user namespace, anyway)? */
        if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                                &found_uid, &found_gid))) {
            pcmk__err("CMAP provider is not authentic: process %lld "
                      "(uid: %lld, gid: %lld)",
                      (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                      (long long) found_uid, (long long) found_gid);
            goto bail;
        } else if (rv < 0) {
            pcmk__err("Could not verify authenticity of CMAP provider: %s (%d)",
                      strerror(-rv), -rv);
            goto bail;
        }
    }

    while (name == NULL && cmap_handle != 0) {
        uint32_t id = 0;
        char *key = NULL;

        key = pcmk__assert_asprintf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &id);
        pcmk__trace("Checking %u vs %u from %s", nodeid, id, key);
        free(key);

        if (rc != CS_OK) {
            break;
        }

        if (nodeid == id) {
            pcmk__trace("Searching for node name for %u in nodelist.node.%d %s",
                        nodeid, lpc, pcmk__s(name, "<null>"));
            if (name == NULL) {
                key = pcmk__assert_asprintf("nodelist.node.%d.name", lpc);
                cmap_get_string(cmap_handle, key, &name);
                pcmk__trace("%s = %s", key, pcmk__s(name, "<null>"));
                free(key);
            }
            if (name == NULL) {
                key = pcmk__assert_asprintf("nodelist.node.%d.ring0_addr", lpc);
                cmap_get_string(cmap_handle, key, &name);
                pcmk__trace("%s = %s", key, pcmk__s(name, "<null>"));

                if (!node_name_is_valid(key, name)) {
                    free(name);
                    name = NULL;
                }
                free(key);
            }
            break;
        }

        lpc++;
    }

bail:
    if(local_handle) {
        cmap_finalize(local_handle);
    }

    if (name == NULL) {
        pcmk__info("Unable to get node name for nodeid %u", nodeid);
    }
    return name;
}

/*!
 * \internal
 * \brief Disconnect from Corosync cluster
 *
 * \param[in,out] cluster  Cluster object to disconnect
 */
void
pcmk__corosync_disconnect(pcmk_cluster_t *cluster)
{
    pcmk__cpg_disconnect(cluster);

    if (pcmk_quorum_handle != 0) {
        quorum_finalize(pcmk_quorum_handle);
        pcmk_quorum_handle = 0;
    }
    pcmk__notice("Disconnected from Corosync");
}

/*!
 * \internal
 * \brief Dispatch function for quorum connection file descriptor
 *
 * \param[in] user_data  Ignored
 *
 * \return 0 on success, -1 on error (per mainloop_io_t interface)
 */
static int
quorum_dispatch_cb(gpointer user_data)
{
    int rc = quorum_dispatch(pcmk_quorum_handle, CS_DISPATCH_ALL);

    if (rc < 0) {
        pcmk__err("Connection to the Quorum API failed: %d", rc);
        quorum_finalize(pcmk_quorum_handle);
        pcmk_quorum_handle = 0;
        return -1;
    }
    return 0;
}

/*!
 * \internal
 * \brief Notification callback for Corosync quorum connection
 *
 * \param[in] handle             Corosync quorum connection
 * \param[in] quorate            Whether cluster is quorate
 * \param[in] ring_id            Corosync ring ID
 * \param[in] view_list_entries  Number of entries in \p view_list
 * \param[in] view_list          Corosync node IDs in membership
 */
static void
quorum_notification_cb(quorum_handle_t handle, uint32_t quorate,
                       uint64_t ring_id, uint32_t view_list_entries,
                       uint32_t *view_list)
{
    int i;
    GHashTableIter iter;
    pcmk__node_status_t *node = NULL;
    static gboolean init_phase = TRUE;

    bool is_quorate = (quorate != 0);
    bool was_quorate = pcmk__cluster_has_quorum();

    if (is_quorate && !was_quorate) {
        pcmk__notice("Quorum acquired " QB_XS " membership=%" PRIu64
                     " members=%" PRIu32,
                     ring_id, view_list_entries);
        pcmk__cluster_set_quorum(true);

    } else if (!is_quorate && was_quorate) {
        pcmk__warn("Quorum lost " QB_XS " membership=%" PRIu64
                   " members=%" PRIu32,
                   ring_id, view_list_entries);
        pcmk__cluster_set_quorum(false);

    } else {
        pcmk__info("Quorum %s " QB_XS " membership=%" PRIu64
                   " members=%" PRIu32,
                   (is_quorate? "retained" : "still lost"), ring_id,
                   view_list_entries);
    }

    if (view_list_entries == 0 && init_phase) {
        pcmk__info("Corosync membership is still forming, ignoring");
        return;
    }

    init_phase = FALSE;

    /* Reset membership_id for all cached nodes so we can tell which ones aren't
     * in the view list */
    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        node->membership_id = 0;
    }

    /* Update the peer cache for each node in view list */
    for (i = 0; i < view_list_entries; i++) {
        uint32_t id = view_list[i];

        pcmk__debug("Member[%d] %" PRIu32, i, id);

        /* Get this node's peer cache entry (adding one if not already there) */
        node = pcmk__get_node(id, NULL, NULL, pcmk__node_search_cluster_member);
        if (node->name == NULL) {
            char *name = pcmk__corosync_name(0, id);

            pcmk__info("Obtaining name for new node %u", id);
            node = pcmk__get_node(id, name, NULL,
                                  pcmk__node_search_cluster_member);
            free(name);
        }

        // Update the node state (including updating membership_id to ring_id)
        pcmk__update_peer_state(__func__, node, PCMK_VALUE_MEMBER, ring_id);
    }

    /* Remove any peer cache entries we didn't update */
    pcmk__reap_unseen_nodes(ring_id);

    if (quorum_app_callback) {
        quorum_app_callback(ring_id, is_quorate);
    }
}

/*!
 * \internal
 * \brief Connect to Corosync quorum service
 *
 * \param[in] dispatch   Connection dispatch callback
 * \param[in] destroy    Connection destroy callback
 */
void
pcmk__corosync_quorum_connect(gboolean (*dispatch)(unsigned long long,
                                                   gboolean),
                              void (*destroy)(gpointer))
{
    cs_error_t rc;
    int fd = 0;
    int quorate = 0;
    uint32_t quorum_type = 0;
    struct mainloop_fd_callbacks quorum_fd_callbacks;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;

    quorum_fd_callbacks.dispatch = quorum_dispatch_cb;
    quorum_fd_callbacks.destroy = destroy;

    pcmk__debug("Configuring Pacemaker to obtain quorum from Corosync");

    {
#if 0
        // New way but not supported by all Corosync 2 versions
        quorum_model_v0_data_t quorum_model_data = {
            .model = QUORUM_MODEL_V0,
            .quorum_notify_fn = quorum_notification_cb,
        };

        rc = quorum_model_initialize(&pcmk_quorum_handle, QUORUM_MODEL_V0,
                                     (quorum_model_data_t *) &quorum_model_data,
                                     &quorum_type, NULL);
#else
        quorum_callbacks_t quorum_callbacks = {
            .quorum_notify_fn = quorum_notification_cb,
        };

        rc = quorum_initialize(&pcmk_quorum_handle, &quorum_callbacks,
                               &quorum_type);
#endif
    }

    if (rc != CS_OK) {
        pcmk__err("Could not connect to the Quorum API: %s (%d)",
                  pcmk_rc_str(pcmk__corosync2rc(rc)), rc);
        goto bail;

    } else if (quorum_type != QUORUM_SET) {
        pcmk__err("Corosync quorum is not configured");
        goto bail;
    }

    rc = quorum_fd_get(pcmk_quorum_handle, &fd);
    if (rc != CS_OK) {
        pcmk__err("Could not obtain the Quorum API connection: %s (%d)",
                  strerror(rc), rc);
        goto bail;
    }

    /* Quorum provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        pcmk__err("Quorum provider is not authentic: process %lld "
                  "(uid: %lld, gid: %lld)",
                  (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                  (long long) found_uid, (long long) found_gid);
        rc = CS_ERR_ACCESS;
        goto bail;
    } else if (rv < 0) {
        pcmk__err("Could not verify authenticity of Quorum provider: %s (%d)",
                  strerror(-rv), -rv);
        rc = CS_ERR_ACCESS;
        goto bail;
    }

    rc = quorum_getquorate(pcmk_quorum_handle, &quorate);
    if (rc != CS_OK) {
        pcmk__err("Could not obtain the current Quorum API state: %d", rc);
        goto bail;
    }

    if (quorate) {
        pcmk__notice("Quorum acquired");
    } else {
        pcmk__warn("No quorum");
    }
    quorum_app_callback = dispatch;
    pcmk__cluster_set_quorum(quorate != 0);

    rc = quorum_trackstart(pcmk_quorum_handle, CS_TRACK_CHANGES | CS_TRACK_CURRENT);
    if (rc != CS_OK) {
        pcmk__err("Could not setup Quorum API notifications: %d", rc);
        goto bail;
    }

    mainloop_add_fd("quorum", G_PRIORITY_HIGH, fd, dispatch, &quorum_fd_callbacks);

    pcmk__corosync_add_nodes(NULL);

  bail:
    if (rc != CS_OK) {
        quorum_finalize(pcmk_quorum_handle);
    }
}

/*!
 * \internal
 * \brief Connect to Corosync cluster layer
 *
 * \param[in,out] cluster  Initialized cluster object to connect
 *
 * \return Standard Pacemaker return code
 *
 * \note This initializes the node caches on success by calling
 *       \c pcmk__get_node().
 */
int
pcmk__corosync_connect(pcmk_cluster_t *cluster)
{
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();
    const char *cluster_layer_s = pcmk_cluster_layer_text(cluster_layer);
    pcmk__node_status_t *local_node = NULL;
    int rc = pcmk_rc_ok;

    if (cluster_layer != pcmk_cluster_layer_corosync) {
        pcmk__err("Invalid cluster layer: %s " QB_XS " cluster_layer=%d",
                  cluster_layer_s, cluster_layer);
        return EINVAL;
    }

    rc = pcmk__cpg_connect(cluster);
    if (rc != pcmk_rc_ok) {
        // Error message was logged by pcmk__cpg_connect()
        return rc;
    }
    pcmk__info("Connection to %s established", cluster_layer_s);

    cluster->priv->node_id = pcmk__cpg_local_nodeid(0);
    if (cluster->priv->node_id == 0) {
        pcmk__err("Could not determine local node ID");
        return ENXIO;
    }

    cluster->priv->node_name = pcmk__cluster_node_name(0);
    if (cluster->priv->node_name == NULL) {
        pcmk__err("Could not determine local node name");
        return ENXIO;
    }

    // Ensure local node always exists in peer cache
    local_node = pcmk__get_node(cluster->priv->node_id,
                                cluster->priv->node_name, NULL,
                                pcmk__node_search_cluster_member);

    cluster->priv->node_xml_id = pcmk__corosync_uuid(local_node);
    CRM_LOG_ASSERT(cluster->priv->node_xml_id != NULL);

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Check whether a Corosync cluster is active
 *
 * \return \c true if Corosync is found active, or \c false otherwise
 */
bool
pcmk__corosync_is_active(void)
{
    cmap_handle_t handle;
    int rc = pcmk__init_cmap(&handle);

    if (rc == CS_OK) {
        cmap_finalize(handle);
        return true;
    }

    pcmk__info("Failed to initialize the cmap API: %s (%d)",
               pcmk_rc_str(pcmk__corosync2rc(rc)), rc);
    return false;
}

/*!
 * \internal
 * \brief Check whether a Corosync cluster peer is active
 *
 * \param[in] node  Node to check
 *
 * \return \c true if \p node is an active Corosync peer, or \c false otherwise
 */
bool
pcmk__corosync_is_peer_active(const pcmk__node_status_t *node)
{
    if (node == NULL) {
        pcmk__trace("Corosync peer inactive: NULL");
        return false;
    }
    if (!pcmk__str_eq(node->state, PCMK_VALUE_MEMBER, pcmk__str_none)) {
        pcmk__trace("Corosync peer %s inactive: state=%s", node->name,
                    node->state);
        return false;
    }
    if (!pcmk__is_set(node->processes, crm_proc_cpg)) {
        pcmk__trace("Corosync peer %s inactive " QB_XS " processes=%.16" PRIx32,
                    node->name, node->processes);
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Load Corosync node list (via CMAP) into peer cache and optionally XML
 *
 * \param[in,out] xml_parent  If not NULL, add <node> entry here for each node
 *
 * \return true if any nodes were found, false otherwise
 */
bool
pcmk__corosync_add_nodes(xmlNode *xml_parent)
{
    int lpc = 0;
    cs_error_t rc = CS_OK;
    int retries = 0;
    bool any = false;
    cmap_handle_t cmap_handle;
    int fd = -1;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;

    do {
        rc = pcmk__init_cmap(&cmap_handle);
        if (rc != CS_OK) {
            retries++;
            pcmk__debug("API connection setup failed: %s.  Retrying in %ds",
                        pcmk_rc_str(pcmk__corosync2rc(rc)), retries);
            sleep(retries);
        }

    } while (retries < 5 && rc != CS_OK);

    if (rc != CS_OK) {
        pcmk__warn("Could not connect to Cluster Configuration Database API, "
                   "error %d",
                   rc);
        return false;
    }

    rc = cmap_fd_get(cmap_handle, &fd);
    if (rc != CS_OK) {
        pcmk__err("Could not obtain the CMAP API connection: %s (%d)",
                  pcmk_rc_str(pcmk__corosync2rc(rc)), rc);
        goto bail;
    }

    /* CMAP provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        pcmk__err("CMAP provider is not authentic: process %lld "
                  "(uid: %lld, gid: %lld)",
                  (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                  (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rv < 0) {
        pcmk__err("Could not verify authenticity of CMAP provider: %s (%d)",
                  strerror(-rv), -rv);
        goto bail;
    }

    pcmk__cluster_init_node_caches();
    pcmk__trace("Initializing Corosync node list");
    for (lpc = 0; TRUE; lpc++) {
        uint32_t nodeid = 0;
        char *name = NULL;
        char *key = NULL;

        key = pcmk__assert_asprintf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &nodeid);
        free(key);

        if (rc != CS_OK) {
            break;
        }

        name = pcmk__corosync_name(cmap_handle, nodeid);
        if (name != NULL) {
            GHashTableIter iter;
            pcmk__node_status_t *node = NULL;

            g_hash_table_iter_init(&iter, pcmk__peer_cache);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
                if ((node != NULL)
                    && (node->cluster_layer_id > 0)
                    && (node->cluster_layer_id != nodeid)
                    && pcmk__str_eq(node->name, name, pcmk__str_casei)) {

                    pcmk__crit("Nodes %" PRIu32 " and %" PRIu32 " share the "
                               "same name '%s': shutting down",
                               node->cluster_layer_id, nodeid, name);
                    crm_exit(CRM_EX_FATAL);
                }
            }
        }

        if (nodeid > 0 || name != NULL) {
            pcmk__trace("Initializing node[%d] %u = %s", lpc, nodeid, name);
            pcmk__get_node(nodeid, name, NULL, pcmk__node_search_cluster_member);
        }

        if (nodeid > 0 && name != NULL) {
            any = true;

            if (xml_parent) {
                xmlNode *node = pcmk__xe_create(xml_parent, PCMK_XE_NODE);

                pcmk__xe_set_ll(node, PCMK_XA_ID, (long long) nodeid);
                pcmk__xe_set(node, PCMK_XA_UNAME, name);
            }
        }

        free(name);
    }
bail:
    cmap_finalize(cmap_handle);
    return any;
}

/*!
 * \internal
 * \brief Get cluster name from Corosync configuration (via CMAP)
 *
 * \return Newly allocated string with cluster name if configured, or NULL
 */
char *
pcmk__corosync_cluster_name(void)
{
    cmap_handle_t handle;
    char *cluster_name = NULL;
    cs_error_t rc = CS_OK;
    int fd = -1;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;

    rc = pcmk__init_cmap(&handle);
    if (rc != CS_OK) {
        pcmk__info("Failed to initialize the cmap API: %s (%d)",
                   pcmk_rc_str(pcmk__corosync2rc(rc)), rc);
        return NULL;
    }

    rc = cmap_fd_get(handle, &fd);
    if (rc != CS_OK) {
        pcmk__err("Could not obtain the CMAP API connection: %s (%d)",
                  pcmk_rc_str(pcmk__corosync2rc(rc)), rc);
        goto bail;
    }

    /* CMAP provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        pcmk__err("CMAP provider is not authentic: process %lld "
                  "(uid: %lld, gid: %lld)",
                  (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                  (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rv < 0) {
        pcmk__err("Could not verify authenticity of CMAP provider: %s (%d)",
                  strerror(-rv), -rv);
        goto bail;
    }

    rc = cmap_get_string(handle, "totem.cluster_name", &cluster_name);
    if (rc != CS_OK) {
        pcmk__info("Cannot get totem.cluster_name: %s (%d)",
                   pcmk_rc_str(pcmk__corosync2rc(rc)), rc);

    } else {
        pcmk__debug("cmap totem.cluster_name = '%s'", cluster_name);
    }

bail:
    cmap_finalize(handle);
    return cluster_name;
}

/*!
 * \internal
 * \brief Check (via CMAP) whether Corosync configuration has a node list
 *
 * \return true if Corosync has node list, otherwise false
 */
bool
pcmk__corosync_has_nodelist(void)
{
    cs_error_t cs_rc = CS_OK;
    int retries = 0;
    cmap_handle_t cmap_handle;
    cmap_iter_handle_t iter_handle;
    char key_name[CMAP_KEYNAME_MAXLEN + 1];
    int fd = -1;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rc = pcmk_ok;

    static bool got_result = false;
    static bool result = false;

    if (got_result) {
        return result;
    }

    // Connect to CMAP
    do {
        cs_rc = pcmk__init_cmap(&cmap_handle);
        if (cs_rc != CS_OK) {
            retries++;
            pcmk__debug("CMAP connection failed: %s (rc=%d, retrying in %ds)",
                        pcmk_rc_str(pcmk__corosync2rc(cs_rc)), cs_rc, retries);
            sleep(retries);
        }
    } while ((retries < 5) && (cs_rc != CS_OK));
    if (cs_rc != CS_OK) {
        pcmk__warn("Assuming Corosync does not have node list: CMAP connection "
                   "failed (%s) " QB_XS " rc=%d",
                   pcmk_rc_str(pcmk__corosync2rc(cs_rc)), cs_rc);
        return false;
    }

    // Get CMAP connection file descriptor
    cs_rc = cmap_fd_get(cmap_handle, &fd);
    if (cs_rc != CS_OK) {
        pcmk__warn("Assuming Corosync does not have node list: CMAP unusable "
                   "(%s) " QB_XS " rc=%d",
                   pcmk_rc_str(pcmk__corosync2rc(cs_rc)), cs_rc);
        goto bail;
    }

    // Check whether CMAP connection is authentic (i.e. provided by root)
    rc = crm_ipc_is_authentic_process(fd, (uid_t) 0, (gid_t) 0,
                                      &found_pid, &found_uid, &found_gid);
    if (rc == 0) {
        pcmk__warn("Assuming Corosync does not have node list: CMAP provider "
                   "is inauthentic "
                   QB_XS " pid=%lld uid=%lld gid=%lld",
                   (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                   (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rc < 0) {
        pcmk__warn("Assuming Corosync does not have node list: Could not "
                   "verify CMAP authenticity (%s) " QB_XS " rc=%d",
                   pcmk_strerror(rc), rc);
        goto bail;
    }

    // Check whether nodelist section is presetn
    cs_rc = cmap_iter_init(cmap_handle, "nodelist", &iter_handle);
    if (cs_rc != CS_OK) {
        pcmk__warn("Assuming Corosync does not have node list: CMAP not "
                   "readable (%s) " QB_XS " rc=%d",
                   pcmk_rc_str(pcmk__corosync2rc(cs_rc)), cs_rc);
        goto bail;
    }

    cs_rc = cmap_iter_next(cmap_handle, iter_handle, key_name, NULL, NULL);
    if (cs_rc == CS_OK) {
        result = true;
    }

    cmap_iter_finalize(cmap_handle, iter_handle);
    got_result = true;
    pcmk__debug("Corosync %s node list", (result? "has" : "does not have"));

bail:
    cmap_finalize(cmap_handle);
    return result;
}

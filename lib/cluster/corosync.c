/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <inttypes.h>   // PRIu64

#include <bzlib.h>

#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>
#include <sys/utsname.h>

#include <qb/qbipcc.h>
#include <qb/qbutil.h>

#include <corosync/corodefs.h>
#include <corosync/corotypes.h>
#include <corosync/hdb.h>
#include <corosync/cfg.h>
#include <corosync/cmap.h>
#include <corosync/quorum.h>

#include <crm/msg_xml.h>

#include <crm/common/ipc_internal.h>  /* PCMK__SPECIAL_PID* */
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
pcmk__corosync_uuid(crm_node_t *node)
{
    if ((node != NULL) && is_corosync_cluster()) {
        if (node->id > 0) {
            return crm_strdup_printf("%u", node->id);
        } else {
            crm_info("Node %s is not yet known by Corosync", node->uname);
        }
    }
    return NULL;
}

static bool
node_name_is_valid(const char *key, const char *name)
{
    int octet;

    if (name == NULL) {
        crm_trace("%s is empty", key);
        return false;

    } else if (sscanf(name, "%d.%d.%d.%d", &octet, &octet, &octet, &octet) == 4) {
        crm_trace("%s contains an IPv4 address (%s), ignoring", key, name);
        return false;

    } else if (strstr(name, ":") != NULL) {
        crm_trace("%s contains an IPv6 address (%s), ignoring", key, name);
        return false;
    }
    crm_trace("'%s: %s' is valid", key, name);
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
        nodeid = get_local_nodeid(0);
    }

    if (cmap_handle == 0 && local_handle == 0) {
        retries = 0;
        crm_trace("Initializing CMAP connection");
        do {
            rc = pcmk__init_cmap(&local_handle);
            if (rc != CS_OK) {
                retries++;
                crm_debug("API connection setup failed: %s.  Retrying in %ds", cs_strerror(rc),
                          retries);
                sleep(retries);
            }

        } while (retries < 5 && rc != CS_OK);

        if (rc != CS_OK) {
            crm_warn("Could not connect to Cluster Configuration Database API, error %s",
                     cs_strerror(rc));
            local_handle = 0;
        }
    }

    if (cmap_handle == 0) {
        cmap_handle = local_handle;

        rc = cmap_fd_get(cmap_handle, &fd);
        if (rc != CS_OK) {
            crm_err("Could not obtain the CMAP API connection: %s (%d)",
                    cs_strerror(rc), rc);
            goto bail;
        }

        /* CMAP provider run as root (in given user namespace, anyway)? */
        if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                                &found_uid, &found_gid))) {
            crm_err("CMAP provider is not authentic:"
                    " process %lld (uid: %lld, gid: %lld)",
                    (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                    (long long) found_uid, (long long) found_gid);
            goto bail;
        } else if (rv < 0) {
            crm_err("Could not verify authenticity of CMAP provider: %s (%d)",
                    strerror(-rv), -rv);
            goto bail;
        }
    }

    while (name == NULL && cmap_handle != 0) {
        uint32_t id = 0;
        char *key = NULL;

        key = crm_strdup_printf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &id);
        crm_trace("Checking %u vs %u from %s", nodeid, id, key);
        free(key);

        if (rc != CS_OK) {
            break;
        }

        if (nodeid == id) {
            crm_trace("Searching for node name for %u in nodelist.node.%d %s",
                      nodeid, lpc, pcmk__s(name, "<null>"));
            if (name == NULL) {
                key = crm_strdup_printf("nodelist.node.%d.name", lpc);
                cmap_get_string(cmap_handle, key, &name);
                crm_trace("%s = %s", key, pcmk__s(name, "<null>"));
                free(key);
            }
            if (name == NULL) {
                key = crm_strdup_printf("nodelist.node.%d.ring0_addr", lpc);
                cmap_get_string(cmap_handle, key, &name);
                crm_trace("%s = %s", key, pcmk__s(name, "<null>"));

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
        crm_info("Unable to get node name for nodeid %u", nodeid);
    }
    return name;
}

/*!
 * \internal
 * \brief Disconnect from Corosync cluster
 *
 * \param[in] cluster  Cluster connection to disconnect
 */
void
pcmk__corosync_disconnect(crm_cluster_t *cluster)
{
    cluster_disconnect_cpg(cluster);
    if (pcmk_quorum_handle) {
        quorum_finalize(pcmk_quorum_handle);
        pcmk_quorum_handle = 0;
    }
    crm_notice("Disconnected from Corosync");
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
        crm_err("Connection to the Quorum API failed: %d", rc);
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
    crm_node_t *node = NULL;
    static gboolean init_phase = TRUE;

    if (quorate != crm_have_quorum) {
        if (quorate) {
            crm_notice("Quorum acquired " CRM_XS " membership=%" PRIu64 " members=%lu",
                       ring_id, (long unsigned int)view_list_entries);
        } else {
            crm_warn("Quorum lost " CRM_XS " membership=%" PRIu64 " members=%lu",
                     ring_id, (long unsigned int)view_list_entries);
        }
        crm_have_quorum = quorate;

    } else {
        crm_info("Quorum %s " CRM_XS " membership=%" PRIu64 " members=%lu",
                 (quorate? "retained" : "still lost"), ring_id,
                 (long unsigned int)view_list_entries);
    }

    if (view_list_entries == 0 && init_phase) {
        crm_info("Corosync membership is still forming, ignoring");
        return;
    }

    init_phase = FALSE;

    /* Reset last_seen for all cached nodes so we can tell which ones aren't
     * in the view list */
    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        node->last_seen = 0;
    }

    /* Update the peer cache for each node in view list */
    for (i = 0; i < view_list_entries; i++) {
        uint32_t id = view_list[i];

        crm_debug("Member[%d] %u ", i, id);

        /* Get this node's peer cache entry (adding one if not already there) */
        node = crm_get_peer(id, NULL);
        if (node->uname == NULL) {
            char *name = pcmk__corosync_name(0, id);

            crm_info("Obtaining name for new node %u", id);
            node = crm_get_peer(id, name);
            free(name);
        }

        /* Update the node state (including updating last_seen to ring_id) */
        pcmk__update_peer_state(__func__, node, CRM_NODE_MEMBER, ring_id);
    }

    /* Remove any peer cache entries we didn't update */
    pcmk__reap_unseen_nodes(ring_id);

    if (quorum_app_callback) {
        quorum_app_callback(ring_id, quorate);
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

    crm_debug("Configuring Pacemaker to obtain quorum from Corosync");

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
        crm_err("Could not connect to the Quorum API: %s (%d)",
                cs_strerror(rc), rc);
        goto bail;

    } else if (quorum_type != QUORUM_SET) {
        crm_err("Corosync quorum is not configured");
        goto bail;
    }

    rc = quorum_fd_get(pcmk_quorum_handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the Quorum API connection: %s (%d)",
                strerror(rc), rc);
        goto bail;
    }

    /* Quorum provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        crm_err("Quorum provider is not authentic:"
                " process %lld (uid: %lld, gid: %lld)",
                (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        rc = CS_ERR_ACCESS;
        goto bail;
    } else if (rv < 0) {
        crm_err("Could not verify authenticity of Quorum provider: %s (%d)",
                strerror(-rv), -rv);
        rc = CS_ERR_ACCESS;
        goto bail;
    }

    rc = quorum_getquorate(pcmk_quorum_handle, &quorate);
    if (rc != CS_OK) {
        crm_err("Could not obtain the current Quorum API state: %d", rc);
        goto bail;
    }

    if (quorate) {
        crm_notice("Quorum acquired");
    } else {
        crm_warn("No quorum");
    }
    quorum_app_callback = dispatch;
    crm_have_quorum = quorate;

    rc = quorum_trackstart(pcmk_quorum_handle, CS_TRACK_CHANGES | CS_TRACK_CURRENT);
    if (rc != CS_OK) {
        crm_err("Could not setup Quorum API notifications: %d", rc);
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
 * \param[in] cluster   Initialized cluster object to connect
 */
gboolean
pcmk__corosync_connect(crm_cluster_t *cluster)
{
    crm_node_t *peer = NULL;
    enum cluster_type_e stack = get_cluster_type();

    crm_peer_init();

    if (stack != pcmk_cluster_corosync) {
        crm_err("Invalid cluster type: %s " CRM_XS " stack=%d",
                name_for_cluster_type(stack), stack);
        return FALSE;
    }

    if (!cluster_connect_cpg(cluster)) {
        // Error message was logged by cluster_connect_cpg()
        return FALSE;
    }
    crm_info("Connection to %s established", name_for_cluster_type(stack));

    cluster->nodeid = get_local_nodeid(0);
    if (cluster->nodeid == 0) {
        crm_err("Could not determine local node ID");
        return FALSE;
    }

    cluster->uname = get_node_name(0);
    if (cluster->uname == NULL) {
        crm_err("Could not determine local node name");
        return FALSE;
    }

    // Ensure local node always exists in peer cache
    peer = crm_get_peer(cluster->nodeid, cluster->uname);
    cluster->uuid = pcmk__corosync_uuid(peer);

    return TRUE;
}

/*!
 * \internal
 * \brief Check whether a Corosync cluster is active
 *
 * \return pcmk_cluster_corosync if Corosync is found, else pcmk_cluster_unknown
 */
enum cluster_type_e
pcmk__corosync_detect(void)
{
    int rc = CS_OK;
    cmap_handle_t handle;

    rc = pcmk__init_cmap(&handle);

    switch(rc) {
        case CS_OK:
            break;
        case CS_ERR_SECURITY:
            crm_debug("Failed to initialize the cmap API: Permission denied (%d)", rc);
            /* It's there, we just can't talk to it.
             * Good enough for us to identify as 'corosync'
             */
            return pcmk_cluster_corosync;

        default:
            crm_info("Failed to initialize the cmap API: %s (%d)",
                     pcmk__cs_err_str(rc), rc);
            return pcmk_cluster_unknown;
    }

    cmap_finalize(handle);
    return pcmk_cluster_corosync;
}

/*!
 * \brief Check whether a Corosync cluster peer is active
 *
 * \param[in] node  Node to check
 *
 * \return TRUE if \p node is an active Corosync peer, otherwise FALSE
 */
gboolean
crm_is_corosync_peer_active(const crm_node_t *node)
{
    if (node == NULL) {
        crm_trace("Corosync peer inactive: NULL");
        return FALSE;

    } else if (!pcmk__str_eq(node->state, CRM_NODE_MEMBER, pcmk__str_casei)) {
        crm_trace("Corosync peer %s inactive: state=%s",
                  node->uname, node->state);
        return FALSE;

    } else if (!pcmk_is_set(node->processes, crm_proc_cpg)) {
        crm_trace("Corosync peer %s inactive: processes=%.16x",
                  node->uname, node->processes);
        return FALSE;
    }
    return TRUE;
}

/*!
 * \internal
 * \brief Load Corosync node list (via CMAP) into peer cache and optionally XML
 *
 * \param[in] xml_parent  If not NULL, add a <node> entry to this for each node
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
            crm_debug("API connection setup failed: %s.  Retrying in %ds", cs_strerror(rc),
                      retries);
            sleep(retries);
        }

    } while (retries < 5 && rc != CS_OK);

    if (rc != CS_OK) {
        crm_warn("Could not connect to Cluster Configuration Database API, error %d", rc);
        return false;
    }

    rc = cmap_fd_get(cmap_handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the CMAP API connection: %s (%d)",
                cs_strerror(rc), rc);
        goto bail;
    }

    /* CMAP provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        crm_err("CMAP provider is not authentic:"
                " process %lld (uid: %lld, gid: %lld)",
                (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rv < 0) {
        crm_err("Could not verify authenticity of CMAP provider: %s (%d)",
                strerror(-rv), -rv);
        goto bail;
    }

    crm_peer_init();
    crm_trace("Initializing Corosync node list");
    for (lpc = 0; TRUE; lpc++) {
        uint32_t nodeid = 0;
        char *name = NULL;
        char *key = NULL;

        key = crm_strdup_printf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &nodeid);
        free(key);

        if (rc != CS_OK) {
            break;
        }

        name = pcmk__corosync_name(cmap_handle, nodeid);
        if (name != NULL) {
            GHashTableIter iter;
            crm_node_t *node = NULL;

            g_hash_table_iter_init(&iter, crm_peer_cache);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
                if(node && node->uname && strcasecmp(node->uname, name) == 0) {
                    if (node->id && node->id != nodeid) {
                        crm_crit("Nodes %u and %u share the same name '%s': shutting down", node->id,
                                 nodeid, name);
                        crm_exit(CRM_EX_FATAL);
                    }
                }
            }
        }

        if (nodeid > 0 || name != NULL) {
            crm_trace("Initializing node[%d] %u = %s", lpc, nodeid, name);
            crm_get_peer(nodeid, name);
        }

        if (nodeid > 0 && name != NULL) {
            any = true;

            if (xml_parent) {
                xmlNode *node = create_xml_node(xml_parent, XML_CIB_TAG_NODE);

                crm_xml_set_id(node, "%u", nodeid);
                crm_xml_add(node, XML_ATTR_UNAME, name);
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
        crm_info("Failed to initialize the cmap API: %s (%d)",
                 cs_strerror(rc), rc);
        return NULL;
    }

    rc = cmap_fd_get(handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the CMAP API connection: %s (%d)",
                cs_strerror(rc), rc);
        goto bail;
    }

    /* CMAP provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        crm_err("CMAP provider is not authentic:"
                " process %lld (uid: %lld, gid: %lld)",
                (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rv < 0) {
        crm_err("Could not verify authenticity of CMAP provider: %s (%d)",
                strerror(-rv), -rv);
        goto bail;
    }

    rc = cmap_get_string(handle, "totem.cluster_name", &cluster_name);
    if (rc != CS_OK) {
        crm_info("Cannot get totem.cluster_name: %s (%d)", cs_strerror(rc), rc);

    } else {
        crm_debug("cmap totem.cluster_name = '%s'", cluster_name);
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
            crm_debug("CMAP connection failed: %s (rc=%d, retrying in %ds)",
                      cs_strerror(cs_rc), cs_rc, retries);
            sleep(retries);
        }
    } while ((retries < 5) && (cs_rc != CS_OK));
    if (cs_rc != CS_OK) {
        crm_warn("Assuming Corosync does not have node list: "
                 "CMAP connection failed (%s) " CRM_XS " rc=%d",
                 cs_strerror(cs_rc), cs_rc);
        return false;
    }

    // Get CMAP connection file descriptor
    cs_rc = cmap_fd_get(cmap_handle, &fd);
    if (cs_rc != CS_OK) {
        crm_warn("Assuming Corosync does not have node list: "
                 "CMAP unusable (%s) " CRM_XS " rc=%d",
                 cs_strerror(cs_rc), cs_rc);
        goto bail;
    }

    // Check whether CMAP connection is authentic (i.e. provided by root)
    rc = crm_ipc_is_authentic_process(fd, (uid_t) 0, (gid_t) 0,
                                      &found_pid, &found_uid, &found_gid);
    if (rc == 0) {
        crm_warn("Assuming Corosync does not have node list: "
                 "CMAP provider is inauthentic "
                 CRM_XS " pid=%lld uid=%lld gid=%lld",
                 (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                 (long long) found_uid, (long long) found_gid);
        goto bail;
    } else if (rc < 0) {
        crm_warn("Assuming Corosync does not have node list: "
                 "Could not verify CMAP authenticity (%s) " CRM_XS " rc=%d",
                  pcmk_strerror(rc), rc);
        goto bail;
    }

    // Check whether nodelist section is presetn
    cs_rc = cmap_iter_init(cmap_handle, "nodelist", &iter_handle);
    if (cs_rc != CS_OK) {
        crm_warn("Assuming Corosync does not have node list: "
                 "CMAP not readable (%s) " CRM_XS " rc=%d",
                 cs_strerror(cs_rc), cs_rc);
        goto bail;
    }

    cs_rc = cmap_iter_next(cmap_handle, iter_handle, key_name, NULL, NULL);
    if (cs_rc == CS_OK) {
        result = true;
    }

    cmap_iter_finalize(cmap_handle, iter_handle);
    got_result = true;
    crm_debug("Corosync %s node list", (result? "has" : "does not have"));

bail:
    cmap_finalize(cmap_handle);
    return result;
}

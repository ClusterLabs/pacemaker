/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>
#include <bzlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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

quorum_handle_t pcmk_quorum_handle = 0;

gboolean(*quorum_app_callback) (unsigned long long seq, gboolean quorate) = NULL;

/*
 * CFG functionality stolen from node_name() in corosync-quorumtool.c
 * This resolves the first address assigned to a node and returns the name or IP address.
 */
char *
corosync_node_name(uint64_t /*cmap_handle_t */ cmap_handle, uint32_t nodeid)
{
    int lpc = 0;
    int rc = CS_OK;
    int retries = 0;
    char *name = NULL;
    cmap_handle_t local_handle = 0;

    /* nodeid == 0 == CMAN_NODEID_US */
    if (nodeid == 0) {
        nodeid = get_local_nodeid(0);
    }

    if (cmap_handle == 0 && local_handle == 0) {
        retries = 0;
        crm_trace("Initializing CMAP connection");
        do {
            rc = cmap_initialize(&local_handle);
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
    }

    while (name == NULL && cmap_handle != 0) {
        uint32_t id = 0;
        char *key = NULL;

        key = g_strdup_printf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &id);
        crm_trace("Checking %u vs %u from %s", nodeid, id, key);
        g_free(key);

        if (rc != CS_OK) {
            break;
        }

        if (nodeid == id) {
            crm_trace("Searching for node name for %u in nodelist.node.%d %s", nodeid, lpc, name);
            if (name == NULL) {
                key = g_strdup_printf("nodelist.node.%d.ring0_addr", lpc);
                rc = cmap_get_string(cmap_handle, key, &name);
                crm_trace("%s = %s", key, name);

                if (node_name_is_valid(key, name) == FALSE) {
                    free(name);
                    name = NULL;
                }
                g_free(key);
            }

            if (name == NULL) {
                key = g_strdup_printf("nodelist.node.%d.name", lpc);
                rc = cmap_get_string(cmap_handle, key, &name);
                crm_trace("%s = %s %d", key, name, rc);
                g_free(key);
            }
            break;
        }

        lpc++;
    }

    if(local_handle) {
        cmap_finalize(local_handle);
    }

    if (name == NULL) {
        crm_info("Unable to get node name for nodeid %u", nodeid);
    }
    return name;
}

void
terminate_cs_connection(crm_cluster_t *cluster)
{
    crm_notice("Disconnecting from Corosync");

    cluster_disconnect_cpg(cluster);

    if (pcmk_quorum_handle) {
        crm_trace("Disconnecting quorum");
        quorum_finalize(pcmk_quorum_handle);
        pcmk_quorum_handle = 0;

    } else {
        crm_info("No Quorum connection");
    }
}

int ais_membership_timer = 0;
gboolean ais_membership_force = FALSE;


static int
pcmk_quorum_dispatch(gpointer user_data)
{
    int rc = 0;

    rc = quorum_dispatch(pcmk_quorum_handle, CS_DISPATCH_ALL);
    if (rc < 0) {
        crm_err("Connection to the Quorum API failed: %d", rc);
        pcmk_quorum_handle = 0;
        return -1;
    }
    return 0;
}

static void
pcmk_quorum_notification(quorum_handle_t handle,
                         uint32_t quorate,
                         uint64_t ring_id, uint32_t view_list_entries, uint32_t * view_list)
{
    int i;
    GHashTableIter iter;
    crm_node_t *node = NULL;
    static gboolean init_phase = TRUE;

    if (quorate != crm_have_quorum) {
        crm_notice("Membership " U64T ": quorum %s (%lu)", ring_id,
                   quorate ? "acquired" : "lost", (long unsigned int)view_list_entries);
        crm_have_quorum = quorate;

    } else {
        crm_info("Membership " U64T ": quorum %s (%lu)", ring_id,
                 quorate ? "retained" : "still lost", (long unsigned int)view_list_entries);
    }

    if (view_list_entries == 0 && init_phase) {
        crm_info("Corosync membership is still forming, ignoring");
        return;
    }

    init_phase = FALSE;

    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        node->last_seen = 0;
    }

    for (i = 0; i < view_list_entries; i++) {
        uint32_t id = view_list[i];
        char *name = NULL;

        crm_debug("Member[%d] %u ", i, id);

        node = crm_get_peer(id, NULL);
        if (node->uname == NULL) {
            crm_info("Obtaining name for new node %u", id);
            name = corosync_node_name(0, id);
            node = crm_get_peer(id, name);
        }

        crm_update_peer_state(__FUNCTION__, node, CRM_NODE_MEMBER, ring_id);
        free(name);
    }

    crm_trace("Reaping unseen nodes...");
    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        if (node->last_seen != ring_id && node->state) {
            crm_update_peer_state(__FUNCTION__, node, CRM_NODE_LOST, 0);
        } else if (node->last_seen != ring_id) {
            crm_info("State of node %s[%u] is still unknown", node->uname, node->id);
        }
    }

    if (quorum_app_callback) {
        quorum_app_callback(ring_id, quorate);
    }
}

quorum_callbacks_t quorum_callbacks = {
    .quorum_notify_fn = pcmk_quorum_notification,
};

gboolean
cluster_connect_quorum(gboolean(*dispatch) (unsigned long long, gboolean),
                       void (*destroy) (gpointer))
{
    int rc = -1;
    int fd = 0;
    int quorate = 0;
    uint32_t quorum_type = 0;
    struct mainloop_fd_callbacks quorum_fd_callbacks;

    quorum_fd_callbacks.dispatch = pcmk_quorum_dispatch;
    quorum_fd_callbacks.destroy = destroy;

    crm_debug("Configuring Pacemaker to obtain quorum from Corosync");

    rc = quorum_initialize(&pcmk_quorum_handle, &quorum_callbacks, &quorum_type);
    if (rc != CS_OK) {
        crm_err("Could not connect to the Quorum API: %d\n", rc);
        goto bail;

    } else if (quorum_type != QUORUM_SET) {
        crm_err("Corosync quorum is not configured\n");
        goto bail;
    }

    rc = quorum_getquorate(pcmk_quorum_handle, &quorate);
    if (rc != CS_OK) {
        crm_err("Could not obtain the current Quorum API state: %d\n", rc);
        goto bail;
    }

    crm_notice("Quorum %s", quorate ? "acquired" : "lost");
    quorum_app_callback = dispatch;
    crm_have_quorum = quorate;

    rc = quorum_trackstart(pcmk_quorum_handle, CS_TRACK_CHANGES | CS_TRACK_CURRENT);
    if (rc != CS_OK) {
        crm_err("Could not setup Quorum API notifications: %d\n", rc);
        goto bail;
    }

    rc = quorum_fd_get(pcmk_quorum_handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the Quorum API connection: %d\n", rc);
        goto bail;
    }

    mainloop_add_fd("quorum", G_PRIORITY_HIGH, fd, dispatch, &quorum_fd_callbacks);

    corosync_initialize_nodelist(NULL, FALSE, NULL);

  bail:
    if (rc != CS_OK) {
        quorum_finalize(pcmk_quorum_handle);
        return FALSE;
    }
    return TRUE;
}

gboolean
init_cs_connection(crm_cluster_t * cluster)
{
    int retries = 0;

    while (retries < 5) {
        int rc = init_cs_connection_once(cluster);

        retries++;

        switch (rc) {
            case CS_OK:
                return TRUE;
                break;
            case CS_ERR_TRY_AGAIN:
            case CS_ERR_QUEUE_FULL:
                sleep(retries);
                break;
            default:
                return FALSE;
        }
    }

    crm_err("Could not connect to corosync after %d retries", retries);
    return FALSE;
}

gboolean
init_cs_connection_once(crm_cluster_t * cluster)
{
    crm_node_t *peer = NULL;
    enum cluster_type_e stack = get_cluster_type();

    crm_peer_init();

    /* Here we just initialize comms */
    if (stack != pcmk_cluster_corosync) {
        crm_err("Invalid cluster type: %s (%d)", name_for_cluster_type(stack), stack);
        return FALSE;
    }

    if (cluster_connect_cpg(cluster) == FALSE) {
        return FALSE;
    }
    crm_info("Connection to '%s': established", name_for_cluster_type(stack));

    cluster->nodeid = get_local_nodeid(0);
    if(cluster->nodeid == 0) {
        crm_err("Could not establish local nodeid");
        return FALSE;
    }

    cluster->uname = get_node_name(0);
    if(cluster->uname == NULL) {
        crm_err("Could not establish local node name");
        return FALSE;
    }

    /* Ensure the local node always exists */
    peer = crm_get_peer(cluster->nodeid, cluster->uname);
    cluster->uuid = get_corosync_uuid(peer);

    return TRUE;
}

gboolean
check_message_sanity(const AIS_Message * msg, const char *data)
{
    gboolean sane = TRUE;
    int dest = msg->host.type;
    int tmp_size = msg->header.size - sizeof(AIS_Message);

    if (sane && msg->header.size == 0) {
        crm_warn("Message with no size");
        sane = FALSE;
    }

    if (sane && msg->header.error != CS_OK) {
        crm_warn("Message header contains an error: %d", msg->header.error);
        sane = FALSE;
    }

    if (sane && ais_data_len(msg) != tmp_size) {
        crm_warn("Message payload size is incorrect: expected %d, got %d", ais_data_len(msg),
                 tmp_size);
        sane = TRUE;
    }

    if (sane && ais_data_len(msg) == 0) {
        crm_warn("Message with no payload");
        sane = FALSE;
    }

    if (sane && data && msg->is_compressed == FALSE) {
        int str_size = strlen(data) + 1;

        if (ais_data_len(msg) != str_size) {
            int lpc = 0;

            crm_warn("Message payload is corrupted: expected %d bytes, got %d",
                     ais_data_len(msg), str_size);
            sane = FALSE;
            for (lpc = (str_size - 10); lpc < msg->size; lpc++) {
                if (lpc < 0) {
                    lpc = 0;
                }
                crm_debug("bad_data[%d]: %d / '%c'", lpc, data[lpc], data[lpc]);
            }
        }
    }

    if (sane == FALSE) {
        crm_err("Invalid message %d: (dest=%s:%s, from=%s:%s.%u, compressed=%d, size=%d, total=%d)",
                msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
                ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
                msg->sender.pid, msg->is_compressed, ais_data_len(msg), msg->header.size);

    } else {
        crm_trace
            ("Verified message %d: (dest=%s:%s, from=%s:%s.%u, compressed=%d, size=%d, total=%d)",
             msg->id, ais_dest(&(msg->host)), msg_type2text(dest), ais_dest(&(msg->sender)),
             msg_type2text(msg->sender.type), msg->sender.pid, msg->is_compressed,
             ais_data_len(msg), msg->header.size);
    }

    return sane;
}

enum cluster_type_e
find_corosync_variant(void)
{
    int rc = CS_OK;
    cmap_handle_t handle;

    rc = cmap_initialize(&handle);

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
                     ais_error2text(rc), rc);
            return pcmk_cluster_unknown;
    }

    cmap_finalize(handle);
    return pcmk_cluster_corosync;
}

gboolean
crm_is_corosync_peer_active(const crm_node_t * node)
{
    if (node == NULL) {
        crm_trace("NULL");
        return FALSE;

    } else if (safe_str_neq(node->state, CRM_NODE_MEMBER)) {
        crm_trace("%s: state=%s", node->uname, node->state);
        return FALSE;

    } else if ((node->processes & crm_proc_cpg) == 0) {
        crm_trace("%s: processes=%.16x", node->uname, node->processes);
        return FALSE;
    }
    return TRUE;
}

gboolean
corosync_initialize_nodelist(void *cluster, gboolean force_member, xmlNode * xml_parent)
{
    int lpc = 0;
    int rc = CS_OK;
    int retries = 0;
    gboolean any = FALSE;
    cmap_handle_t cmap_handle;

    do {
        rc = cmap_initialize(&cmap_handle);
        if (rc != CS_OK) {
            retries++;
            crm_debug("API connection setup failed: %s.  Retrying in %ds", cs_strerror(rc),
                      retries);
            sleep(retries);
        }

    } while (retries < 5 && rc != CS_OK);

    if (rc != CS_OK) {
        crm_warn("Could not connect to Cluster Configuration Database API, error %d", rc);
        return FALSE;
    }

    crm_peer_init();
    crm_trace("Initializing corosync nodelist");
    for (lpc = 0;; lpc++) {
        uint32_t nodeid = 0;
        char *name = NULL;
        char *key = NULL;

        key = g_strdup_printf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &nodeid);
        g_free(key);

        if (rc != CS_OK) {
            break;
        }

        name = corosync_node_name(cmap_handle, nodeid);
        if (name != NULL) {
            GHashTableIter iter;
            crm_node_t *node = NULL;

            g_hash_table_iter_init(&iter, crm_peer_cache);
            while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
                if(node && node->uname && strcasecmp(node->uname, name) == 0) {
                    if (node->id && node->id != nodeid) {
                        crm_crit("Nodes %u and %u share the same name '%s': shutting down", node->id,
                                 nodeid, name);
                        crm_exit(DAEMON_RESPAWN_STOP);
                    }
                }
            }
        }

        if (nodeid > 0 || name != NULL) {
            crm_trace("Initializing node[%d] %u = %s", lpc, nodeid, name);
            crm_get_peer(nodeid, name);
        }

        if (nodeid > 0 && name != NULL) {
            any = TRUE;

            if (xml_parent) {
                char buffer[64];
                xmlNode *node = create_xml_node(xml_parent, XML_CIB_TAG_NODE);

                if(snprintf(buffer, 63, "%u", nodeid) > 0) {
                    crm_xml_add(node, XML_ATTR_ID, buffer);
                }
                crm_xml_add(node, XML_ATTR_UNAME, name);
                if (force_member) {
                    crm_xml_add(node, XML_ATTR_TYPE, CRM_NODE_MEMBER);
                }
            }
        }

        free(name);
    }
    cmap_finalize(cmap_handle);
    return any;
}

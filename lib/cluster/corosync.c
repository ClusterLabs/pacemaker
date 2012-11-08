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
#include <corosync/cpg.h>
#include <corosync/cfg.h>
#include <corosync/cmap.h>
#include <corosync/quorum.h>

#include <crm/msg_xml.h>

cpg_handle_t pcmk_cpg_handle = 0;

struct cpg_name pcmk_cpg_group = {
    .length = 0,
    .value[0] = 0,
};

quorum_handle_t pcmk_quorum_handle = 0;
gboolean(*quorum_app_callback) (unsigned long long seq, gboolean quorate) = NULL;

static char *pcmk_uname = NULL;
static int pcmk_uname_len = 0;
static uint32_t pcmk_nodeid = 0;

#define cs_repeat(counter, max, code) do {		\
	code;						\
	if(rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {  \
	    counter++;					\
	    crm_debug("Retrying operation after %ds", counter);	\
	    sleep(counter);				\
	} else {                                        \
            break;                                      \
        }                                               \
    } while(counter < max)

/*
 * CFG functionality stolen from node_name() in corosync-quorumtool.c
 * This resolves the first address assigned to a node and returns the name or IP address.
 */
char *corosync_node_name(uint64_t /*cmap_handle_t*/ cmap_handle, uint32_t nodeid)
{
    int lpc = 0;
    int rc = CS_OK;
    int retries = 0;
    char *name = NULL;

    cmap_handle_t local_handle = 0;
    corosync_cfg_handle_t cfg_handle = 0;
    static corosync_cfg_callbacks_t cfg_callbacks = {};

    /* nodeid == 0 == CMAN_NODEID_US */
    if(nodeid == 0 && pcmk_nodeid) {
        nodeid = pcmk_nodeid;

    } else if(nodeid == 0) {
        /* Look it up */
        int rc = -1;
        int retries = 0;
        cpg_handle_t handle = 0;
        cpg_callbacks_t cb = {};

        cs_repeat(retries, 5, rc = cpg_initialize(&handle, &cb));
        if (rc == CS_OK) {
            retries = 0;
            cs_repeat(retries, 5, rc = cpg_local_get(handle, &pcmk_nodeid));
        }

        if (rc != CS_OK) {
            crm_err("Could not get local node id from the CPG API: %d", rc);
        }
        cpg_finalize(handle);
    }
    
    if(cmap_handle == 0 && local_handle == 0) {
        retries = 0;
        crm_trace("Initializing CMAP connection");
        do {
            rc = cmap_initialize(&local_handle);
            if(rc != CS_OK) {
                retries++;
                crm_debug("API connection setup failed: %s.  Retrying in %ds", cs_strerror(rc), retries);
                sleep(retries);
            }

        } while(retries < 5 && rc != CS_OK);

        if (rc != CS_OK) {
            crm_warn("Could not connect to Cluster Configuration Database API, error %s", cs_strerror(rc));
            local_handle = 0;
        }
    }

    if(cmap_handle == 0) {
        cmap_handle = local_handle;
    }

    while(name == NULL && cmap_handle != 0) {
        uint32_t id = 0;
        char *key = NULL;

        key = g_strdup_printf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &id);
        crm_trace("Checking %u vs %u from %s", nodeid, id, key);
        g_free(key);

        if(rc != CS_OK) {
            break;
        }

        if(nodeid == id) {
            crm_trace("Searching for node name for %u in nodelist.node.%d %s", nodeid, lpc, name);
            if(name == NULL) {
                key = g_strdup_printf("nodelist.node.%d.ring0_addr", lpc);
                rc = cmap_get_string(cmap_handle, key, &name);
                crm_trace("%s = %s", key, name);

                if(node_name_is_valid(key, name) == FALSE) {
                    free(name); name = NULL;
                }
                g_free(key);
            }

            if(name == NULL) {
                key = g_strdup_printf("nodelist.node.%d.name", lpc);
                rc = cmap_get_string(cmap_handle, key, &name);
                crm_trace("%s = %s %d", key, name, rc);
                g_free(key);
            }
            break;
        }

        lpc++;
    }

    if(name == NULL) {
        retries = 0;
        crm_trace("Initializing CFG connection");
        do {
            rc = corosync_cfg_initialize(&cfg_handle, &cfg_callbacks);
            if(rc != CS_OK) {
                retries++;
                crm_debug("API connection setup failed: %s.  Retrying in %ds", cs_strerror(rc), retries);
                sleep(retries);
            }

        } while(retries < 5 && rc != CS_OK);

        if (rc != CS_OK) {
            crm_warn("Could not connect to the Corosync CFG API, error %d", cs_strerror(rc));
            cfg_handle = 0;
        }
    }

    if(name == NULL && cfg_handle != 0) {
        int numaddrs;
        char buf[INET6_ADDRSTRLEN];

        socklen_t addrlen;
        struct sockaddr_storage *ss;
        corosync_cfg_node_address_t addrs[INTERFACE_MAX];

        rc = corosync_cfg_get_node_addrs(cfg_handle, nodeid, INTERFACE_MAX, &numaddrs, addrs);
        if (rc == CS_OK) {
            ss = (struct sockaddr_storage *)addrs[0].address;
            if (ss->ss_family == AF_INET6) {
                addrlen = sizeof(struct sockaddr_in6);
            } else {
                addrlen = sizeof(struct sockaddr_in);
            }

            if (getnameinfo((struct sockaddr *)addrs[0].address, addrlen, buf, sizeof(buf), NULL, 0, 0) == 0) {
                crm_notice("Inferred node name '%s' for nodeid %u from DNS", buf, nodeid);

                if(node_name_is_valid("DNS", buf)) {
                    name = strdup(buf);
                    strip_domain(name);
                }
            }
        } else {
            crm_debug("Unable to get node address for nodeid %u: %s", nodeid, cs_strerror(rc));
        }
        corosync_cfg_finalize(cfg_handle); 
    }

    if(local_handle) {
        cmap_finalize(local_handle); 
    }

    if(name == NULL) {
        crm_err("Unable to get node name for nodeid %u", nodeid);
    }
    return name;
}

enum crm_ais_msg_types
text2msg_type(const char *text)
{
    int type = crm_msg_none;

    CRM_CHECK(text != NULL, return type);
    if (safe_str_eq(text, "ais")) {
        type = crm_msg_ais;
    } else if (safe_str_eq(text, "crm_plugin")) {
        type = crm_msg_ais;
    } else if (safe_str_eq(text, CRM_SYSTEM_CIB)) {
        type = crm_msg_cib;
    } else if (safe_str_eq(text, CRM_SYSTEM_CRMD)) {
        type = crm_msg_crmd;
    } else if (safe_str_eq(text, CRM_SYSTEM_DC)) {
        type = crm_msg_crmd;
    } else if (safe_str_eq(text, CRM_SYSTEM_TENGINE)) {
        type = crm_msg_te;
    } else if (safe_str_eq(text, CRM_SYSTEM_PENGINE)) {
        type = crm_msg_pe;
    } else if (safe_str_eq(text, CRM_SYSTEM_LRMD)) {
        type = crm_msg_lrmd;
    } else if (safe_str_eq(text, CRM_SYSTEM_STONITHD)) {
        type = crm_msg_stonithd;
    } else if (safe_str_eq(text, "stonith-ng")) {
        type = crm_msg_stonith_ng;
    } else if (safe_str_eq(text, "attrd")) {
        type = crm_msg_attrd;

    } else {
        /* This will normally be a transient client rather than
         * a cluster daemon.  Set the type to the pid of the client
         */
        int scan_rc = sscanf(text, "%d", &type);

        if (scan_rc != 1) {
            /* Ensure its sane */
            type = crm_msg_none;
        }
    }
    return type;
}

static char *ais_cluster_name = NULL;

gboolean
crm_get_cluster_name(char **cname)
{
    CRM_CHECK(cname != NULL, return FALSE);
    if (ais_cluster_name) {
        *cname = strdup(ais_cluster_name);
        return TRUE;
    }
    return FALSE;
}

gboolean
send_ais_text(int class, const char *data,
              gboolean local, crm_node_t *node, enum crm_ais_msg_types dest)
{
    static int msg_id = 0;
    static int local_pid = 0;

    int retries = 0;
    int rc = CS_OK;
    int buf_len = sizeof(cs_ipc_header_response_t);

    char *buf = NULL;
    struct iovec iov;
    const char *transport = "pcmk";
    AIS_Message *ais_msg = NULL;
    enum crm_ais_msg_types sender = text2msg_type(crm_system_name);

    /* There are only 6 handlers registered to crm_lib_service in plugin.c */
    CRM_CHECK(class < 6, crm_err("Invalid message class: %d", class); return FALSE);

    if (data == NULL) {
        data = "";
    }

    if (local_pid == 0) {
        local_pid = getpid();
    }

    if (sender == crm_msg_none) {
        sender = local_pid;
    }

    ais_msg = calloc(1, sizeof(AIS_Message));

    ais_msg->id = msg_id++;
    ais_msg->header.id = class;
    ais_msg->header.error = CS_OK;

    ais_msg->host.type = dest;
    ais_msg->host.local = local;

    if (node) {
        if (node->uname) {
            ais_msg->host.size = strlen(node->uname);
            memset(ais_msg->host.uname, 0, MAX_NAME);
            memcpy(ais_msg->host.uname, node->uname, ais_msg->host.size);
        }
        ais_msg->host.id = node->id;
    }

    ais_msg->sender.id = 0;
    ais_msg->sender.type = sender;
    ais_msg->sender.pid = local_pid;
    ais_msg->sender.size = pcmk_uname_len;
    memset(ais_msg->sender.uname, 0, MAX_NAME);
    memcpy(ais_msg->sender.uname, pcmk_uname, ais_msg->sender.size);

    ais_msg->size = 1 + strlen(data);

    if (ais_msg->size < CRM_BZ2_THRESHOLD) {
  failback:
        ais_msg = realloc(ais_msg, sizeof(AIS_Message) + ais_msg->size);
        memcpy(ais_msg->data, data, ais_msg->size);

    } else {
        char *compressed = NULL;
        char *uncompressed = strdup(data);
        unsigned int len = (ais_msg->size * 1.1) + 600; /* recomended size */

        crm_trace("Compressing message payload");

        /* coverity[returned_null] Ignore */
        compressed = malloc( len);

        rc = BZ2_bzBuffToBuffCompress(compressed, &len, uncompressed, ais_msg->size, CRM_BZ2_BLOCKS,
                                      0, CRM_BZ2_WORK);

        free(uncompressed);

        if (rc != BZ_OK) {
            crm_err("Compression failed: %d", rc);
            free(compressed);
            goto failback;
        }

        ais_msg = realloc(ais_msg, sizeof(AIS_Message) + len + 1);
        memcpy(ais_msg->data, compressed, len);
        ais_msg->data[len] = 0;
        free(compressed);

        ais_msg->is_compressed = TRUE;
        ais_msg->compressed_size = len;

        crm_trace("Compression details: %d -> %d", ais_msg->size, ais_data_len(ais_msg));
    }

    ais_msg->header.size = sizeof(AIS_Message) + ais_data_len(ais_msg);

    crm_trace("Sending%s message %d to %s.%s (data=%d, total=%d)",
              ais_msg->is_compressed ? " compressed" : "",
              ais_msg->id, ais_dest(&(ais_msg->host)), msg_type2text(dest),
              ais_data_len(ais_msg), ais_msg->header.size);

    iov.iov_base = ais_msg;
    iov.iov_len = ais_msg->header.size;
    buf = realloc(buf, buf_len);

    do {
        if (rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {
            retries++;
            crm_info("Peer overloaded or membership in flux:"
                     " Re-sending message (Attempt %d of 20)", retries);
            sleep(retries);     /* Proportional back off */
        }

        errno = 0;
        transport = "cpg";
        CRM_CHECK(dest != crm_msg_ais, rc = CS_ERR_MESSAGE_ERROR; goto bail);
        rc = cpg_mcast_joined(pcmk_cpg_handle, CPG_TYPE_AGREED, &iov, 1);
        if (rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {
            cpg_flow_control_state_t fc_state = CPG_FLOW_CONTROL_DISABLED;
            int rc2 = cpg_flow_control_state_get(pcmk_cpg_handle, &fc_state);

            if (rc2 == CS_OK && fc_state == CPG_FLOW_CONTROL_ENABLED) {
                crm_warn("Connection overloaded, cannot send messages");
                goto bail;

            } else if (rc2 != CS_OK) {
                crm_warn("Could not determin the connection state: %s (%d)",
                         ais_error2text(rc2), rc2);
                goto bail;
            }
        }

    } while ((rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) && retries < 20);

  bail:
    if (rc != CS_OK) {
        crm_perror(LOG_ERR, "Sending message %d via %s: FAILED (rc=%d): %s",
                   ais_msg->id, transport, rc, ais_error2text(rc));

    } else {
        crm_trace("Message %d: sent", ais_msg->id);
    }

    free(buf);
    free(ais_msg);
    return (rc == CS_OK);
}

gboolean
send_ais_message(xmlNode * msg, gboolean local, crm_node_t *node, enum crm_ais_msg_types dest)
{
    gboolean rc = TRUE;
    char *data = dump_xml_unformatted(msg);
    rc = send_ais_text(crm_class_cluster, data, local, node, dest);
    free(data);
    return rc;
}

void
terminate_cs_connection(void)
{
    crm_notice("Disconnecting from Corosync");

    if(pcmk_cpg_handle) {
        crm_trace("Disconnecting CPG");
        cpg_leave(pcmk_cpg_handle, &pcmk_cpg_group);
        cpg_finalize(pcmk_cpg_handle);
        pcmk_cpg_handle = 0;
        
    } else {
        crm_info("No CPG connection");
    }

    if(pcmk_quorum_handle) {
        crm_trace("Disconnecting quorum");
        quorum_finalize(pcmk_quorum_handle);
        pcmk_quorum_handle = 0;
        
    } else {
        crm_info("No Quorum connection");
    }
}

int ais_membership_timer = 0;
gboolean ais_membership_force = FALSE;

static gboolean
ais_dispatch_message(AIS_Message * msg, gboolean(*dispatch) (int kind, const char *from, const char *data))
{
    char *data = NULL;
    char *uncompressed = NULL;

    xmlNode *xml = NULL;

    CRM_ASSERT(msg != NULL);

    crm_trace("Got new%s message (size=%d, %d, %d)",
              msg->is_compressed ? " compressed" : "",
              ais_data_len(msg), msg->size, msg->compressed_size);

    data = msg->data;
    if (msg->is_compressed && msg->size > 0) {
        int rc = BZ_OK;
        unsigned int new_size = msg->size + 1;

        if (check_message_sanity(msg, NULL) == FALSE) {
            goto badmsg;
        }

        crm_trace("Decompressing message data");
        uncompressed = calloc(1, new_size);
        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &new_size, data, msg->compressed_size, 1, 0);

        if (rc != BZ_OK) {
            crm_err("Decompression failed: %d", rc);
            goto badmsg;
        }

        CRM_ASSERT(rc == BZ_OK);
        CRM_ASSERT(new_size == msg->size);

        data = uncompressed;

    } else if (check_message_sanity(msg, data) == FALSE) {
        goto badmsg;

    } else if (safe_str_eq("identify", data)) {
        int pid = getpid();
        char *pid_s = crm_itoa(pid);

        send_ais_text(crm_class_cluster, pid_s, TRUE, NULL, crm_msg_ais);
        free(pid_s);
        goto done;
    }

    if (msg->header.id != crm_class_members) {
        /* Is this even needed anymore? */
        crm_get_peer(msg->sender.id, msg->sender.uname);
    }

    if (msg->header.id == crm_class_rmpeer) {
        uint32_t id = crm_int_helper(data, NULL);

        crm_info("Removing peer %s/%u", data, id);
        reap_crm_member(id, NULL);
        goto done;
    }

    crm_trace("Payload: %s", data);
    if (dispatch != NULL) {
        dispatch(msg->header.id, msg->sender.uname, data);
    }

  done:
    free(uncompressed);
    free_xml(xml);
    return TRUE;

  badmsg:
    crm_err("Invalid message (id=%d, dest=%s:%s, from=%s:%s.%d):"
            " min=%d, total=%d, size=%d, bz2_size=%d",
            msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
            ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
            msg->sender.pid, (int)sizeof(AIS_Message),
            msg->header.size, msg->size, msg->compressed_size);
    goto done;
}

gboolean(*pcmk_cpg_dispatch_fn) (int kind, const char *from, const char *data) = NULL;

static int
pcmk_cpg_dispatch(gpointer user_data)
{
    int rc = 0;

    pcmk_cpg_dispatch_fn = user_data;
    rc = cpg_dispatch(pcmk_cpg_handle, CS_DISPATCH_ALL);
    if (rc != CS_OK) {
        crm_err("Connection to the CPG API failed: %d", rc);
        return -1;
    }
    return 0;
}

static void
pcmk_cpg_deliver(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    AIS_Message *ais_msg = (AIS_Message *) msg;

    if (ais_msg->sender.id > 0 && ais_msg->sender.id != nodeid) {
        crm_err("Nodeid mismatch from %d.%d: claimed nodeid=%u", nodeid, pid, ais_msg->sender.id);
        return;

    } else if (ais_msg->host.size != 0 && safe_str_neq(ais_msg->host.uname, pcmk_uname)) {
        /* Not for us */
        return;
    } else if (ais_msg->host.id != 0 && (pcmk_nodeid != ais_msg->host.id)) {
        /* Not for us */
        return;
    }

    ais_msg->sender.id = nodeid;
    if (ais_msg->sender.size == 0) {
        crm_node_t *peer = crm_get_peer(nodeid, NULL);

        if (peer == NULL) {
            crm_err("Peer with nodeid=%u is unknown", nodeid);

        } else if (peer->uname == NULL) {
            crm_err("No uname for peer with nodeid=%u", nodeid);

        } else {
            crm_notice("Fixing uname for peer with nodeid=%u", nodeid);
            ais_msg->sender.size = strlen(peer->uname);
            memset(ais_msg->sender.uname, 0, MAX_NAME);
            memcpy(ais_msg->sender.uname, peer->uname, ais_msg->sender.size);
        }
    }

    ais_dispatch_message(ais_msg, pcmk_cpg_dispatch_fn);
}

static void
pcmk_cpg_membership(cpg_handle_t handle,
                    const struct cpg_name *groupName,
                    const struct cpg_address *member_list, size_t member_list_entries,
                    const struct cpg_address *left_list, size_t left_list_entries,
                    const struct cpg_address *joined_list, size_t joined_list_entries)
{
    int i;
    gboolean found = FALSE;
    static int counter = 0;

    for (i = 0; i < left_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(left_list[i].nodeid, NULL);
        crm_info("Left[%d.%d] %s.%d ", counter, i, groupName->value, left_list[i].nodeid);
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, OFFLINESTATUS);
    }

    for (i = 0; i < joined_list_entries; i++) {
        crm_info("Joined[%d.%d] %s.%d ", counter, i, groupName->value, joined_list[i].nodeid);
    }

    for (i = 0; i < member_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(member_list[i].nodeid, NULL);
        crm_info("Member[%d.%d] %s.%d ", counter, i, groupName->value, member_list[i].nodeid);
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, ONLINESTATUS);
        if(pcmk_nodeid == member_list[i].nodeid) {
            found = TRUE;
        }
    }

    if(!found) {
        crm_err("We're not part of CPG group %s anymore!", groupName->value);
        /* Possibly re-call cpg_join() */
    }
    
    counter++;
}

cpg_callbacks_t cpg_callbacks = {
    .cpg_deliver_fn = pcmk_cpg_deliver,
    .cpg_confchg_fn = pcmk_cpg_membership,
};

static gboolean
init_cpg_connection(gboolean(*dispatch) (int kind, const char *from, const char *data), void (*destroy) (gpointer),
                    uint32_t * nodeid)
{
    int rc = -1;
    int fd = 0;
    int retries = 0;
    crm_node_t *peer = NULL;
    struct mainloop_fd_callbacks cpg_fd_callbacks = {
        .dispatch = pcmk_cpg_dispatch,
        .destroy = destroy,
    };
    
    strncpy(pcmk_cpg_group.value, crm_system_name, 128);
    pcmk_cpg_group.length = strlen(crm_system_name) + 1;

    cs_repeat(retries, 30, rc = cpg_initialize(&pcmk_cpg_handle, &cpg_callbacks));
    if (rc != CS_OK) {
        crm_err("Could not connect to the Cluster Process Group API: %d\n", rc);
        goto bail;
    }

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_local_get(pcmk_cpg_handle, (unsigned int *)nodeid));
    if (rc != CS_OK) {
        crm_err("Could not get local node id from the CPG API");
        goto bail;
    }

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_join(pcmk_cpg_handle, &pcmk_cpg_group));
    if (rc != CS_OK) {
        crm_err("Could not join the CPG group '%s': %d", crm_system_name, rc);
        goto bail;
    }

    rc = cpg_fd_get(pcmk_cpg_handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the CPG API connection: %d\n", rc);
        goto bail;
    }

    mainloop_add_fd("corosync-cpg", G_PRIORITY_MEDIUM, fd, dispatch, &cpg_fd_callbacks);

  bail:
    if (rc != CS_OK) {
        cpg_finalize(pcmk_cpg_handle);
        return FALSE;
    }

    peer = crm_get_peer(pcmk_nodeid, pcmk_uname);
    crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, ONLINESTATUS);
    return TRUE;
}

static int
pcmk_quorum_dispatch(gpointer user_data)
{
    int rc = 0;

    rc = quorum_dispatch(pcmk_quorum_handle, CS_DISPATCH_ALL);
    if (rc < 0) {
        crm_err("Connection to the Quorum API failed: %d", rc);
        return -1;
    }
    return 0;
}

static void
corosync_mark_unseen_peer_dead(gpointer key, gpointer value, gpointer user_data)
{
    int *seq = user_data;
    crm_node_t *node = value;

    if (node->last_seen != *seq && node->state && crm_str_eq(CRM_NODE_LOST, node->state, TRUE) == FALSE) {
        crm_notice("Node %d/%s was not seen in the previous transition", node->id, node->uname);
        crm_update_peer_state(__FUNCTION__, node, CRM_NODE_LOST, 0);
    }
}

static void
corosync_mark_node_unseen(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;

    node->last_seen = 0;
}

static void
pcmk_quorum_notification(quorum_handle_t handle,
                         uint32_t quorate,
                         uint64_t ring_id, uint32_t view_list_entries, uint32_t * view_list)
{
    int i;
    static gboolean init_phase = TRUE;

    if (quorate != crm_have_quorum) {
        crm_notice("Membership " U64T ": quorum %s (%lu)", ring_id,
                   quorate ? "acquired" : "lost", (long unsigned int)view_list_entries);
        crm_have_quorum = quorate;

    } else {
        crm_info("Membership " U64T ": quorum %s (%lu)", ring_id,
                 quorate ? "retained" : "still lost", (long unsigned int)view_list_entries);
    }

    if(view_list_entries == 0 && init_phase) {
        crm_info("Corosync membership is still forming, ignoring");
        return;
    }

    init_phase = FALSE;
    g_hash_table_foreach(crm_peer_cache, corosync_mark_node_unseen, NULL);

    for (i = 0; i < view_list_entries; i++) {
        uint32_t id = view_list[i];
        char *name = NULL;
        crm_node_t *node = NULL;

        crm_debug("Member[%d] %d ", i, id);

        node = crm_get_peer(id, NULL);
        if(node->uname == NULL) {
            crm_info("Obtaining name for new node %u", id);
            name = corosync_node_name(0, id);
            node = crm_get_peer(id, name);
        }

        crm_update_peer_state(__FUNCTION__, node, CRM_NODE_MEMBER, ring_id);
        free(name);
    }

    crm_trace("Reaping unseen nodes...");
    g_hash_table_foreach(crm_peer_cache, corosync_mark_unseen_peer_dead, &ring_id);

    if (quorum_app_callback) {
        quorum_app_callback(ring_id, quorate);
    }
}

quorum_callbacks_t quorum_callbacks = {
    .quorum_notify_fn = pcmk_quorum_notification,
};

gboolean
init_quorum_connection(gboolean(*dispatch) (unsigned long long, gboolean),
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
init_cs_connection(crm_cluster_t *cluster)
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
init_cs_connection_once(crm_cluster_t *cluster)
{
    enum cluster_type_e stack = get_cluster_type();

    crm_peer_init();

    /* Here we just initialize comms */
    if(stack != pcmk_cluster_corosync) {
        crm_err("Invalid cluster type: %s (%d)", name_for_cluster_type(stack), stack);
        return FALSE;
    }
    
    if (init_cpg_connection(cluster->cs_dispatch, cluster->destroy, &pcmk_nodeid) == FALSE) {
        return FALSE;
    }
    pcmk_uname = get_local_node_name();
    crm_info("Connection to '%s': established", name_for_cluster_type(stack));

    CRM_ASSERT(pcmk_uname != NULL);
    pcmk_uname_len = strlen(pcmk_uname);

    if (pcmk_nodeid != 0) {
        /* Ensure the local node always exists */
        crm_get_peer(pcmk_nodeid, pcmk_uname);
    }

    cluster->uuid = get_corosync_uuid(pcmk_nodeid, pcmk_uname);
    cluster->uname = strdup(pcmk_uname);
    cluster->nodeid = pcmk_nodeid;

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
        crm_err("Invalid message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
                msg->id, ais_dest(&(msg->host)), msg_type2text(dest),
                ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
                msg->sender.pid, msg->is_compressed, ais_data_len(msg), msg->header.size);

    } else {
        crm_trace
            ("Verfied message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
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

    /* There can be only one (possibility if confdb isn't around) */
    rc = cmap_initialize(&handle);
    if (rc != CS_OK) {
        crm_info("Failed to initialize the cmap API. Error %d", rc);
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

    } else if(safe_str_neq(node->state, CRM_NODE_MEMBER)) {
        crm_trace("%s: state=%s", node->uname, node->state);
        return FALSE;

    } else if((node->processes & crm_proc_cpg) == 0) {
        crm_trace("%s: processes=%.16x", node->uname, node->processes);
        return FALSE;
    }
    return TRUE;
}

gboolean
corosync_initialize_nodelist(void *cluster, gboolean force_member, xmlNode *xml_parent) 
{
    int lpc = 0;
    int rc = CS_OK;
    int retries = 0;
    gboolean any = FALSE;
    cmap_handle_t cmap_handle;

    do {
        rc = cmap_initialize(&cmap_handle);
	if(rc != CS_OK) {
	    retries++;
	    crm_debug("API connection setup failed: %s.  Retrying in %ds", cs_strerror(rc), retries);
	    sleep(retries);
        }

    } while(retries < 5 && rc != CS_OK);

    if (rc != CS_OK) {
        crm_warn("Could not connect to Cluster Configuration Database API, error %d", rc);
        return FALSE;
    }

    crm_peer_init();
    crm_trace("Initializing corosync nodelist");
    for(lpc = 0; ; lpc++) {
        uint32_t nodeid = 0;
        char *name = NULL;
        char *key = NULL;

        key = g_strdup_printf("nodelist.node.%d.nodeid", lpc);
        rc = cmap_get_uint32(cmap_handle, key, &nodeid);
        g_free(key);

        if(rc != CS_OK) {
            break;
        }

        name = corosync_node_name(cmap_handle, nodeid);
        if (name != NULL) {
            crm_node_t *node = g_hash_table_lookup(crm_peer_cache, name);
            if(node && node->id != nodeid) {
                crm_crit("Nodes %u and %u share the same name '%s': shutting down", node->id, nodeid, name);
                crm_exit(100);
            }
        }

        if(nodeid > 0 || name != NULL) {
            crm_trace("Initializing node[%d] %u = %s", lpc, nodeid, name);
            crm_get_peer(nodeid, name);
        }

        if(nodeid > 0 && name != NULL) {
            any = TRUE;

            if(xml_parent) {
                xmlNode *node = create_xml_node(xml_parent, XML_CIB_TAG_NODE);
                crm_xml_add_int(node, XML_ATTR_ID, nodeid);
                crm_xml_add(node, XML_ATTR_UNAME, name);
                if(force_member) {
                    crm_xml_add(node, XML_ATTR_TYPE, CRM_NODE_MEMBER);
                }
            }
        }

        free(name);
    }
    cmap_finalize(cmap_handle); 
    return any;
}

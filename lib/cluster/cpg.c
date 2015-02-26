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

#include <crm/msg_xml.h>

cpg_handle_t pcmk_cpg_handle = 0; /* TODO: Remove, use cluster.cpg_handle */

static bool cpg_evicted = FALSE;
gboolean(*pcmk_cpg_dispatch_fn) (int kind, const char *from, const char *data) = NULL;

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

void
cluster_disconnect_cpg(crm_cluster_t *cluster)
{
    pcmk_cpg_handle = 0;
    if (cluster->cpg_handle) {
        crm_trace("Disconnecting CPG");
        cpg_leave(cluster->cpg_handle, &cluster->group);
        cpg_finalize(cluster->cpg_handle);
        cluster->cpg_handle = 0;

    } else {
        crm_info("No CPG connection");
    }
}

uint32_t get_local_nodeid(cpg_handle_t handle)
{
    int rc = CS_OK;
    int retries = 0;
    static uint32_t local_nodeid = 0;
    cpg_handle_t local_handle = handle;
    cpg_callbacks_t cb = { };

    if(local_nodeid != 0) {
        return local_nodeid;
    }

#if 0
    /* Should not be necessary */
    if(get_cluster_type() == pcmk_cluster_classic_ais) {
        get_ais_details(&local_nodeid, NULL);
        goto done;
    }
#endif

    if(handle == 0) {
        crm_trace("Creating connection");
        cs_repeat(retries, 5, rc = cpg_initialize(&local_handle, &cb));
    }

    if (rc == CS_OK) {
        retries = 0;
        crm_trace("Performing lookup");
        cs_repeat(retries, 5, rc = cpg_local_get(local_handle, &local_nodeid));
    }

    if (rc != CS_OK) {
        crm_err("Could not get local node id from the CPG API: %s (%d)", ais_error2text(rc), rc);
    }
    if(handle == 0) {
        crm_trace("Closing connection");
        cpg_finalize(local_handle);
    }
    crm_debug("Local nodeid is %u", local_nodeid);
    return local_nodeid;
}


GListPtr cs_message_queue = NULL;
int cs_message_timer = 0;

static ssize_t crm_cs_flush(gpointer data);

static gboolean
crm_cs_flush_cb(gpointer data)
{
    cs_message_timer = 0;
    crm_cs_flush(data);
    return FALSE;
}

#define CS_SEND_MAX 200
static ssize_t
crm_cs_flush(gpointer data)
{
    int sent = 0;
    ssize_t rc = 0;
    int queue_len = 0;
    static unsigned int last_sent = 0;
    cpg_handle_t *handle = (cpg_handle_t *)data;

    if (*handle == 0) {
        crm_trace("Connection is dead");
        return pcmk_ok;
    }

    queue_len = g_list_length(cs_message_queue);
    if ((queue_len % 1000) == 0 && queue_len > 1) {
        crm_err("CPG queue has grown to %d", queue_len);

    } else if (queue_len == CS_SEND_MAX) {
        crm_warn("CPG queue has grown to %d", queue_len);
    }

    if (cs_message_timer) {
        /* There is already a timer, wait until it goes off */
        crm_trace("Timer active %d", cs_message_timer);
        return pcmk_ok;
    }

    while (cs_message_queue && sent < CS_SEND_MAX) {
        struct iovec *iov = cs_message_queue->data;

        errno = 0;
        rc = cpg_mcast_joined(*handle, CPG_TYPE_AGREED, iov, 1);

        if (rc != CS_OK) {
            break;
        }

        sent++;
        last_sent++;
        crm_trace("CPG message sent, size=%d", iov->iov_len);

        cs_message_queue = g_list_remove(cs_message_queue, iov);
        free(iov->iov_base);
        free(iov);
    }

    queue_len -= sent;
    if (sent > 1 || cs_message_queue) {
        crm_info("Sent %d CPG messages  (%d remaining, last=%u): %s (%d)",
                 sent, queue_len, last_sent, ais_error2text(rc), rc);
    } else {
        crm_trace("Sent %d CPG messages  (%d remaining, last=%u): %s (%d)",
                  sent, queue_len, last_sent, ais_error2text(rc), rc);
    }

    if (cs_message_queue) {
        uint32_t delay_ms = 100;
        if(rc != CS_OK) {
            /* Proportionally more if sending failed but cap at 1s */
            delay_ms = QB_MIN(1000, CS_SEND_MAX + (10 * queue_len));
        }
        cs_message_timer = g_timeout_add(delay_ms, crm_cs_flush_cb, data);
    }

    return rc;
}

gboolean
send_cpg_iov(struct iovec * iov)
{
    static unsigned int queued = 0;

    queued++;
    crm_trace("Queueing CPG message %u (%d bytes)", queued, iov->iov_len);
    cs_message_queue = g_list_append(cs_message_queue, iov);
    crm_cs_flush(&pcmk_cpg_handle);
    return TRUE;
}

static int
pcmk_cpg_dispatch(gpointer user_data)
{
    int rc = 0;
    crm_cluster_t *cluster = (crm_cluster_t*) user_data;

    rc = cpg_dispatch(cluster->cpg_handle, CS_DISPATCH_ONE);
    if (rc != CS_OK) {
        crm_err("Connection to the CPG API failed: %s (%d)", ais_error2text(rc), rc);
        cluster->cpg_handle = 0;
        return -1;

    } else if(cpg_evicted) {
        crm_err("Evicted from CPG membership");
        return -1;
    }
    return 0;
}

char *
pcmk_message_common_cs(cpg_handle_t handle, uint32_t nodeid, uint32_t pid, void *content,
                        uint32_t *kind, const char **from)
{
    char *data = NULL;
    AIS_Message *msg = (AIS_Message *) content;

    if(handle) {
        /* 'msg' came from CPG not the plugin
         * Do filtering and field massaging
         */
        uint32_t local_nodeid = get_local_nodeid(handle);
        const char *local_name = get_local_node_name();

        if (msg->sender.id > 0 && msg->sender.id != nodeid) {
            crm_err("Nodeid mismatch from %d.%d: claimed nodeid=%u", nodeid, pid, msg->sender.id);
            return NULL;

        } else if (msg->host.id != 0 && (local_nodeid != msg->host.id)) {
            /* Not for us */
            crm_trace("Not for us: %u != %u", msg->host.id, local_nodeid);
            return NULL;
        } else if (msg->host.size != 0 && safe_str_neq(msg->host.uname, local_name)) {
            /* Not for us */
            crm_trace("Not for us: %s != %s", msg->host.uname, local_name);
            return NULL;
        }

        msg->sender.id = nodeid;
        if (msg->sender.size == 0) {
            crm_node_t *peer = crm_get_peer(nodeid, NULL);

            if (peer == NULL) {
                crm_err("Peer with nodeid=%u is unknown", nodeid);

            } else if (peer->uname == NULL) {
                crm_err("No uname for peer with nodeid=%u", nodeid);

            } else {
                crm_notice("Fixing uname for peer with nodeid=%u", nodeid);
                msg->sender.size = strlen(peer->uname);
                memset(msg->sender.uname, 0, MAX_NAME);
                memcpy(msg->sender.uname, peer->uname, msg->sender.size);
            }
        }
    }

    crm_trace("Got new%s message (size=%d, %d, %d)",
              msg->is_compressed ? " compressed" : "",
              ais_data_len(msg), msg->size, msg->compressed_size);

    if (kind != NULL) {
        *kind = msg->header.id;
    }
    if (from != NULL) {
        *from = msg->sender.uname;
    }

    if (msg->is_compressed && msg->size > 0) {
        int rc = BZ_OK;
        char *uncompressed = NULL;
        unsigned int new_size = msg->size + 1;

        if (check_message_sanity(msg, NULL) == FALSE) {
            goto badmsg;
        }

        crm_trace("Decompressing message data");
        uncompressed = calloc(1, new_size);
        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &new_size, msg->data, msg->compressed_size, 1, 0);

        if (rc != BZ_OK) {
            crm_err("Decompression failed: %d", rc);
            free(uncompressed);
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

        send_cluster_text(crm_class_cluster, pid_s, TRUE, NULL, crm_msg_ais);
        free(pid_s);
        return NULL;

    } else {
        data = strdup(msg->data);
    }

    if (msg->header.id != crm_class_members) {
        /* Is this even needed anymore? */
        crm_get_peer(msg->sender.id, msg->sender.uname);
    }

    if (msg->header.id == crm_class_rmpeer) {
        uint32_t id = crm_int_helper(data, NULL);

        crm_info("Removing peer %s/%u", data, id);
        reap_crm_member(id, NULL);
        free(data);
        return NULL;

#if SUPPORT_PLUGIN
    } else if (is_classic_ais_cluster()) {
        plugin_handle_membership(msg);
#endif
    }

    crm_trace("Payload: %.200s", data);
    return data;

  badmsg:
    crm_err("Invalid message (id=%d, dest=%s:%s, from=%s:%s.%d):"
            " min=%d, total=%d, size=%d, bz2_size=%d",
            msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
            ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
            msg->sender.pid, (int)sizeof(AIS_Message),
            msg->header.size, msg->size, msg->compressed_size);

    free(data);
    return NULL;
}

void
pcmk_cpg_membership(cpg_handle_t handle,
                    const struct cpg_name *groupName,
                    const struct cpg_address *member_list, size_t member_list_entries,
                    const struct cpg_address *left_list, size_t left_list_entries,
                    const struct cpg_address *joined_list, size_t joined_list_entries)
{
    int i;
    gboolean found = FALSE;
    static int counter = 0;
    uint32_t local_nodeid = get_local_nodeid(handle);

    for (i = 0; i < left_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(left_list[i].nodeid, NULL);

        crm_info("Left[%d.%d] %s.%u ", counter, i, groupName->value, left_list[i].nodeid);
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, OFFLINESTATUS);
    }

    for (i = 0; i < joined_list_entries; i++) {
        crm_info("Joined[%d.%d] %s.%u ", counter, i, groupName->value, joined_list[i].nodeid);
    }

    for (i = 0; i < member_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(member_list[i].nodeid, NULL);

        crm_info("Member[%d.%d] %s.%u ", counter, i, groupName->value, member_list[i].nodeid);

        /* Anyone that is sending us CPG messages must also be a _CPG_ member.
         * But its _not_ safe to assume its in the quorum membership.
         * We may have just found out its dead and are processing the last couple of messages it sent
         */
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, ONLINESTATUS);
        if(peer && peer->state && crm_is_peer_active(peer) == FALSE) {
            time_t now = time(NULL);

            /* Co-opt the otherwise unused votes field */
            if(peer->votes == 0) {
                peer->votes = now;

            } else if(now > (60 + peer->votes)) {
                /* On the otherhand, if we're still getting messages, at a certain point
                 * we need to acknowledge our internal cache is probably wrong
                 *
                 * Set the threshold to 1 minute
                 */
                crm_err("Node %s[%u] appears to be online even though we think it is dead", peer->uname, peer->id);
                crm_update_peer_state(__FUNCTION__, peer, CRM_NODE_MEMBER, 0);
                peer->votes = 0;
            }
        }

        if (local_nodeid == member_list[i].nodeid) {
            found = TRUE;
        }
    }

    if (!found) {
        crm_err("We're not part of CPG group '%s' anymore!", groupName->value);
        cpg_evicted = TRUE;
    }

    counter++;
}

gboolean
cluster_connect_cpg(crm_cluster_t *cluster)
{
    int rc = -1;
    int fd = 0;
    int retries = 0;
    uint32_t id = 0;
    crm_node_t *peer = NULL;
    cpg_handle_t handle = 0;

    struct mainloop_fd_callbacks cpg_fd_callbacks = {
        .dispatch = pcmk_cpg_dispatch,
        .destroy = cluster->destroy,
    };

    cpg_callbacks_t cpg_callbacks = {
        .cpg_deliver_fn = cluster->cpg.cpg_deliver_fn,
        .cpg_confchg_fn = cluster->cpg.cpg_confchg_fn,
        /* .cpg_deliver_fn = pcmk_cpg_deliver, */
        /* .cpg_confchg_fn = pcmk_cpg_membership, */
    };

    cpg_evicted = FALSE;
    cluster->group.length = 0;
    cluster->group.value[0] = 0;

    /* group.value is char[128] */
    strncpy(cluster->group.value, crm_system_name, 127);
    cluster->group.value[127] = 0;
    cluster->group.length = 1 + QB_MIN(127, strlen(crm_system_name));

    cs_repeat(retries, 30, rc = cpg_initialize(&handle, &cpg_callbacks));
    if (rc != CS_OK) {
        crm_err("Could not connect to the Cluster Process Group API: %d\n", rc);
        goto bail;
    }

    id = get_local_nodeid(handle);
    if (id == 0) {
        crm_err("Could not get local node id from the CPG API");
        goto bail;

    }
    cluster->nodeid = id;

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_join(handle, &cluster->group));
    if (rc != CS_OK) {
        crm_err("Could not join the CPG group '%s': %d", crm_system_name, rc);
        goto bail;
    }

    rc = cpg_fd_get(handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the CPG API connection: %d\n", rc);
        goto bail;
    }

    pcmk_cpg_handle = handle;
    cluster->cpg_handle = handle;
    mainloop_add_fd("corosync-cpg", G_PRIORITY_MEDIUM, fd, cluster, &cpg_fd_callbacks);

  bail:
    if (rc != CS_OK) {
        cpg_finalize(handle);
        return FALSE;
    }

    peer = crm_get_peer(id, NULL);
    crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, ONLINESTATUS);
    return TRUE;
}

gboolean
send_cluster_message_cs(xmlNode * msg, gboolean local, crm_node_t * node, enum crm_ais_msg_types dest)
{
    gboolean rc = TRUE;
    char *data = NULL;

    data = dump_xml_unformatted(msg);
    rc = send_cluster_text(crm_class_cluster, data, local, node, dest);
    free(data);
    return rc;
}

gboolean
send_cluster_text(int class, const char *data,
              gboolean local, crm_node_t * node, enum crm_ais_msg_types dest)
{
    static int msg_id = 0;
    static int local_pid = 0;
    static int local_name_len = 0;
    static const char *local_name = NULL;

    char *target = NULL;
    struct iovec *iov;
    AIS_Message *msg = NULL;
    enum crm_ais_msg_types sender = text2msg_type(crm_system_name);

    /* There are only 6 handlers registered to crm_lib_service in plugin.c */
    CRM_CHECK(class < 6, crm_err("Invalid message class: %d", class);
              return FALSE);

#if !SUPPORT_PLUGIN
    CRM_CHECK(dest != crm_msg_ais, return FALSE);
#endif

    if(local_name == NULL) {
        local_name = get_local_node_name();
    }
    if(local_name_len == 0 && local_name) {
        local_name_len = strlen(local_name);
    }

    if (data == NULL) {
        data = "";
    }

    if (local_pid == 0) {
        local_pid = getpid();
    }

    if (sender == crm_msg_none) {
        sender = local_pid;
    }

    msg = calloc(1, sizeof(AIS_Message));

    msg_id++;
    msg->id = msg_id;
    msg->header.id = class;
    msg->header.error = CS_OK;

    msg->host.type = dest;
    msg->host.local = local;

    if (node) {
        if (node->uname) {
            target = strdup(node->uname);
            msg->host.size = strlen(node->uname);
            memset(msg->host.uname, 0, MAX_NAME);
            memcpy(msg->host.uname, node->uname, msg->host.size);
        } else {
            target = crm_strdup_printf("%u", node->id);
        }
        msg->host.id = node->id;
    } else {
        target = strdup("all");
    }

    msg->sender.id = 0;
    msg->sender.type = sender;
    msg->sender.pid = local_pid;
    msg->sender.size = local_name_len;
    memset(msg->sender.uname, 0, MAX_NAME);
    if(local_name && msg->sender.size) {
        memcpy(msg->sender.uname, local_name, msg->sender.size);
    }

    msg->size = 1 + strlen(data);
    msg->header.size = sizeof(AIS_Message) + msg->size;

    if (msg->size < CRM_BZ2_THRESHOLD) {
        msg = realloc_safe(msg, msg->header.size);
        memcpy(msg->data, data, msg->size);

    } else {
        char *compressed = NULL;
        unsigned int new_size = 0;
        char *uncompressed = strdup(data);

        if (crm_compress_string(uncompressed, msg->size, 0, &compressed, &new_size)) {

            msg->header.size = sizeof(AIS_Message) + new_size;
            msg = realloc_safe(msg, msg->header.size);
            memcpy(msg->data, compressed, new_size);

            msg->is_compressed = TRUE;
            msg->compressed_size = new_size;

        } else {
            msg = realloc_safe(msg, msg->header.size);
            memcpy(msg->data, data, msg->size);
        }

        free(uncompressed);
        free(compressed);
    }

    iov = calloc(1, sizeof(struct iovec));
    iov->iov_base = msg;
    iov->iov_len = msg->header.size;

    if (msg->compressed_size) {
        crm_trace("Queueing CPG message %u to %s (%d bytes, %d bytes compressed payload): %.200s",
                  msg->id, target, iov->iov_len, msg->compressed_size, data);
    } else {
        crm_trace("Queueing CPG message %u to %s (%d bytes, %d bytes payload): %.200s",
                  msg->id, target, iov->iov_len, msg->size, data);
    }
    free(target);

#if SUPPORT_PLUGIN
    /* The plugin is the only time we dont use CPG messaging */
    if(get_cluster_type() == pcmk_cluster_classic_ais) {
        return send_plugin_text(class, iov);
    }
#endif

    send_cpg_iov(iov);

    return TRUE;
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

        if (scan_rc != 1 || type <= crm_msg_stonith_ng) {
            /* Ensure its sane */
            type = crm_msg_none;
        }
    }
    return type;
}

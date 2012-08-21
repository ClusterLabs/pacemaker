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
#include <crm/cluster/internal.h>
#include <bzlib.h>
#include <crm/common/ipc.h>
#include <crm/cluster.h>
#include <crm/common/mainloop.h>
#include <sys/utsname.h>

#if SUPPORT_COROSYNC
#    include <corosync/confdb.h>
#    include <corosync/corodefs.h>
#  include <corosync/cpg.h>
cpg_handle_t pcmk_cpg_handle = 0;

struct cpg_name pcmk_cpg_group = {
    .length = 0,
    .value[0] = 0,
};
#endif

#if HAVE_CMAP
#  include <corosync/cmap.h>
#endif

#if SUPPORT_CMAN
#  include <libcman.h>
cman_handle_t pcmk_cman_handle = NULL;
#endif

static char *pcmk_uname = NULL;
static int pcmk_uname_len = 0;
static uint32_t pcmk_nodeid = 0;
int ais_membership_timer = 0;
gboolean ais_membership_force = FALSE;
int ais_dispatch(gpointer user_data);

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

char *
get_ais_data(const AIS_Message * msg)
{
    int rc = BZ_OK;
    char *uncompressed = NULL;
    unsigned int new_size = msg->size + 1;

    if (msg->is_compressed == FALSE) {
        crm_trace("Returning uncompressed message data");
        uncompressed = strdup(msg->data);

    } else {
        crm_trace("Decompressing message data");
        uncompressed = calloc(1, new_size);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &new_size, (char *)msg->data,
                                        msg->compressed_size, 1, 0);

        CRM_ASSERT(rc == BZ_OK);
        CRM_ASSERT(new_size == msg->size);
    }

    return uncompressed;
}

#if SUPPORT_COROSYNC
int ais_fd_sync = -1;
int ais_fd_async = -1;          /* never send messages via this channel */
void *ais_ipc_ctx = NULL;

hdb_handle_t ais_ipc_handle = 0;
static char *ais_cluster_name = NULL;

gboolean
get_ais_nodeid(uint32_t * id, char **uname)
{
    struct iovec iov;
    int retries = 0;
    int rc = CS_OK;
    cs_ipc_header_response_t header;
    struct crm_ais_nodeid_resp_s answer;

    header.error = CS_OK;
    header.id = crm_class_nodeid;
    header.size = sizeof(cs_ipc_header_response_t);

    CRM_CHECK(id != NULL, return FALSE);
    CRM_CHECK(uname != NULL, return FALSE);

    iov.iov_base = &header;
    iov.iov_len = header.size;

  retry:
    errno = 0;
    rc = coroipcc_msg_send_reply_receive(ais_ipc_handle, &iov, 1, &answer, sizeof(answer));
    if (rc == CS_OK) {
        CRM_CHECK(answer.header.size == sizeof(struct crm_ais_nodeid_resp_s),
                  crm_err("Odd message: id=%d, size=%d, error=%d",
                          answer.header.id, answer.header.size, answer.header.error));
        CRM_CHECK(answer.header.id == crm_class_nodeid,
                  crm_err("Bad response id: %d", answer.header.id));
    }

    if ((rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) && retries < 20) {
        retries++;
        crm_info("Peer overloaded: Re-sending message (Attempt %d of 20)", retries);
        sleep(retries);         /* Proportional back off */
        goto retry;
    }

    if (rc != CS_OK) {
        crm_err("Sending nodeid request: FAILED (rc=%d): %s", rc, ais_error2text(rc));
        return FALSE;

    } else if (answer.header.error != CS_OK) {
        crm_err("Bad response from peer: (rc=%d): %s", rc, ais_error2text(rc));
        return FALSE;
    }

    crm_info("Server details: id=%u uname=%s cname=%s", answer.id, answer.uname, answer.cname);

    *id = answer.id;
    *uname = strdup(answer.uname);
    ais_cluster_name = strdup(answer.cname);

    return TRUE;
}

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
              gboolean local, const char *node, enum crm_ais_msg_types dest)
{
    static int msg_id = 0;
    static int local_pid = 0;
    enum cluster_type_e cluster_type = get_cluster_type();

    int retries = 0;
    int rc = CS_OK;
    int buf_len = sizeof(cs_ipc_header_response_t);

    char *buf = NULL;
    struct iovec iov;
    const char *transport = "pcmk";
    cs_ipc_header_response_t *header = NULL;
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
        ais_msg->host.size = strlen(node);
        memset(ais_msg->host.uname, 0, MAX_NAME);
        memcpy(ais_msg->host.uname, node, ais_msg->host.size);
        ais_msg->host.id = 0;

    } else {
        ais_msg->host.size = 0;
        memset(ais_msg->host.uname, 0, MAX_NAME);
        ais_msg->host.id = 0;
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
        switch (cluster_type) {
            case pcmk_cluster_corosync:
                CRM_ASSERT(FALSE/*Not supported here*/);
                break;

            case pcmk_cluster_classic_ais:
                rc = coroipcc_msg_send_reply_receive(ais_ipc_handle, &iov, 1, buf, buf_len);
                header = (cs_ipc_header_response_t *) buf;
                if (rc == CS_OK) {
                    CRM_CHECK(header->size == sizeof(cs_ipc_header_response_t),
                              crm_err("Odd message: id=%d, size=%d, class=%d, error=%d",
                                      header->id, header->size, class, header->error));

                    CRM_ASSERT(buf_len >= header->size);
                    CRM_CHECK(header->id == CRM_MESSAGE_IPC_ACK,
                              crm_err("Bad response id (%d) for request (%d)", header->id,
                                      ais_msg->header.id));
                    CRM_CHECK(header->error == CS_OK, rc = header->error);
                }
                break;

            case pcmk_cluster_cman:
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
                break;

            case pcmk_cluster_unknown:
            case pcmk_cluster_invalid:
            case pcmk_cluster_heartbeat:
                CRM_ASSERT(is_openais_cluster());
                break;
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
send_ais_message(xmlNode * msg, gboolean local, const char *node, enum crm_ais_msg_types dest)
{
    gboolean rc = TRUE;
    char *data = NULL;

    if (is_classic_ais_cluster()) {
        if (ais_fd_async < 0) {
            crm_err("Not connected to AIS: %d", ais_fd_async);
            return FALSE;
        }
    }

    data = dump_xml_unformatted(msg);
    rc = send_ais_text(crm_class_cluster, data, local, node, dest);
    free(data);
    return rc;
}

void
terminate_cs_connection(void)
{
    crm_notice("Disconnecting from Corosync");

    if (is_classic_ais_cluster()) {
        if(ais_ipc_handle) {
            crm_trace("Disconnecting plugin");
            coroipcc_service_disconnect(ais_ipc_handle);
            ais_ipc_handle = 0;
        } else {
            crm_info("No plugin connection");
        }

    } else {
        if(pcmk_cpg_handle) {
            crm_trace("Disconnecting CPG");
            cpg_leave(pcmk_cpg_handle, &pcmk_cpg_group);
            cpg_finalize(pcmk_cpg_handle);
            pcmk_cpg_handle = 0;

        } else {
            crm_info("No CPG connection");
        }
    }

#  if SUPPORT_CMAN
    if (is_cman_cluster()) {
        if(pcmk_cman_handle) {
            crm_trace("Disconnecting cman");
            cman_stop_notification(pcmk_cman_handle);
            cman_finish(pcmk_cman_handle);

        } else {
            crm_info("No cman connection");
        }
    }
#  endif
    ais_fd_async = -1;
    ais_fd_sync = -1;
}


static crm_node_t *
crm_update_ais_node(xmlNode * member, long long seq)
{
    const char *id_s = crm_element_value(member, "id");
    const char *addr = crm_element_value(member, "addr");
    const char *uname = crm_element_value(member, "uname");
    const char *state = crm_element_value(member, "state");
    const char *born_s = crm_element_value(member, "born");
    const char *seen_s = crm_element_value(member, "seen");
    const char *votes_s = crm_element_value(member, "votes");
    const char *procs_s = crm_element_value(member, "processes");

    int votes = crm_int_helper(votes_s, NULL);
    unsigned int id = crm_int_helper(id_s, NULL);
    unsigned int procs = crm_int_helper(procs_s, NULL);

    /* TODO: These values will contain garbage if version < 0.7.1 */
    uint64_t born = crm_int_helper(born_s, NULL);
    uint64_t seen = crm_int_helper(seen_s, NULL);

    return crm_update_peer(__FUNCTION__, id, born, seen, votes, procs, uname, uname, addr, state);
}

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
        crm_get_peer(msg->sender.id, msg->sender.uname);
    }

    if (msg->header.id == crm_class_rmpeer) {
        uint32_t id = crm_int_helper(data, NULL);

        crm_info("Removing peer %s/%u", data, id);
        reap_crm_member(id);
        goto done;

    } else if (is_classic_ais_cluster()) { 
        if (msg->header.id == crm_class_members || msg->header.id == crm_class_quorum) {
            xmlNode *node = NULL;
            const char *value = NULL;
            gboolean quorate = FALSE;

            xml = string2xml(data);
            if (xml == NULL) {
                crm_err("Invalid membership update: %s", data);
                goto badmsg;
            }

            value = crm_element_value(xml, "quorate");
            CRM_CHECK(value != NULL, crm_log_xml_err(xml, "No quorum value:"); goto badmsg);
            if (crm_is_true(value)) {
                quorate = TRUE;
            }

            value = crm_element_value(xml, "id");
            CRM_CHECK(value != NULL, crm_log_xml_err(xml, "No membership id"); goto badmsg);
            crm_peer_seq = crm_int_helper(value, NULL);

            if (quorate != crm_have_quorum) {
                crm_notice("Membership %s: quorum %s", value, quorate ? "acquired" : "lost");
                crm_have_quorum = quorate;

            } else {
                crm_info("Membership %s: quorum %s", value, quorate ? "retained" : "still lost");
            }

            for (node = __xml_first_child(xml); node != NULL; node = __xml_next(node)) {
                crm_update_ais_node(node, crm_peer_seq);
            }
        }
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

int
ais_dispatch(gpointer user_data)
{
    int rc = CS_OK;
    gboolean good = TRUE;

    gboolean(*dispatch) (int kind, const char *from, const char *data) = user_data;

    do {
        char *buffer = NULL;

        rc = coroipcc_dispatch_get(ais_ipc_handle, (void **)&buffer, 0);
        if (rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {
            return 0;
        }
        if (rc != CS_OK) {
            crm_perror(LOG_ERR, "Receiving message body failed: (%d) %s", rc, ais_error2text(rc));
            return -1;
        }
        if (buffer == NULL) {
            /* NULL is a legal "no message afterall" value */
            return 0;
        }
        good = ais_dispatch_message((AIS_Message *) buffer, dispatch);
        coroipcc_dispatch_put(ais_ipc_handle);

    } while (good && ais_ipc_handle);

    if(good) {
        return 0;
    }

    return -1;
}

static void
ais_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_sync = -1;
    exit(1);
}


#  if SUPPORT_CMAN

static int
pcmk_cman_dispatch(gpointer user_data)
{
    int rc = cman_dispatch(pcmk_cman_handle, CMAN_DISPATCH_ALL);

    if (rc < 0) {
        crm_err("Connection to cman failed: %d", rc);
        return FALSE;
    }
    return TRUE;
}

#    define MAX_NODES 256

static void
cman_event_callback(cman_handle_t handle, void *privdata, int reason, int arg)
{
    int rc = 0, lpc = 0, node_count = 0;

    cman_cluster_t cluster;
    static cman_node_t cman_nodes[MAX_NODES];

    gboolean(*dispatch) (unsigned long long, gboolean) = privdata;

    switch (reason) {
        case CMAN_REASON_STATECHANGE:

            memset(&cluster, 0, sizeof(cluster));
            rc = cman_get_cluster(pcmk_cman_handle, &cluster);
            if (rc < 0) {
                crm_err("Couldn't query cman cluster details: %d %d", rc, errno);
                return;
            }

            crm_peer_seq = cluster.ci_generation;
            if (arg != crm_have_quorum) {
                crm_notice("Membership %llu: quorum %s", crm_peer_seq, arg ? "acquired" : "lost");
                crm_have_quorum = arg;

            } else {
                crm_info("Membership %llu: quorum %s", crm_peer_seq,
                         arg ? "retained" : "still lost");
            }

            rc = cman_get_nodes(pcmk_cman_handle, MAX_NODES, &node_count, cman_nodes);
            if (rc < 0) {
                crm_err("Couldn't query cman node list: %d %d", rc, errno);
                return;
            }

            for (lpc = 0; lpc < node_count; lpc++) {
                if (cman_nodes[lpc].cn_nodeid == 0) {
                    /* Never allow node ID 0 to be considered a member #315711 */
                    cman_nodes[lpc].cn_member = 0;
                }
                crm_update_peer(__FUNCTION__, cman_nodes[lpc].cn_nodeid, cman_nodes[lpc].cn_incarnation,
                                cman_nodes[lpc].cn_member ? crm_peer_seq : 0, 0, 0,
                                cman_nodes[lpc].cn_name, cman_nodes[lpc].cn_name, NULL,
                                cman_nodes[lpc].cn_member ? CRM_NODE_MEMBER : CRM_NODE_LOST);
            }

            if (dispatch) {
                dispatch(crm_peer_seq, crm_have_quorum);
            }
            break;

        case CMAN_REASON_TRY_SHUTDOWN:
            /* Always reply with a negative - pacemaker needs to be stopped first */
            crm_info("CMAN wants to shut down: %s", arg ? "forced" : "optional");
            cman_replyto_shutdown(pcmk_cman_handle, 0);
            break;

        case CMAN_REASON_CONFIG_UPDATE:
            /* Ignore */
            break;
    }
}
#  endif

gboolean
init_cman_connection(gboolean(*dispatch) (unsigned long long, gboolean), void (*destroy) (gpointer))
{
#  if SUPPORT_CMAN
    int rc = -1, fd = -1;
    cman_cluster_t cluster;
    struct mainloop_fd_callbacks cman_fd_callbacks = {
        .dispatch = pcmk_cman_dispatch,
        .destroy = destroy,
    };

    crm_info("Configuring Pacemaker to obtain quorum from cman");

    memset(&cluster, 0, sizeof(cluster));

    pcmk_cman_handle = cman_init(dispatch);
    if (pcmk_cman_handle == NULL || cman_is_active(pcmk_cman_handle) == FALSE) {
        crm_err("Couldn't connect to cman");
        goto cman_bail;
    }

    rc = cman_get_cluster(pcmk_cman_handle, &cluster);
    if (rc < 0) {
        crm_err("Couldn't query cman cluster details: %d %d", rc, errno);
        goto cman_bail;
    }
    ais_cluster_name = strdup(cluster.ci_name);

    rc = cman_start_notification(pcmk_cman_handle, cman_event_callback);
    if (rc < 0) {
        crm_err("Couldn't register for cman notifications: %d %d", rc, errno);
        goto cman_bail;
    }

    /* Get the current membership state */
    cman_event_callback(pcmk_cman_handle, dispatch, CMAN_REASON_STATECHANGE,
                        cman_is_quorate(pcmk_cman_handle));

    fd = cman_get_fd(pcmk_cman_handle);

    mainloop_add_fd("cman", G_PRIORITY_MEDIUM, fd, dispatch, &cman_fd_callbacks);

  cman_bail:
    if (rc < 0) {
        cman_finish(pcmk_cman_handle);
        return FALSE;
    }
#  else
    crm_err("cman qorum is not supported in this build");
    exit(100);
#  endif
    return TRUE;
}

#  ifdef SUPPORT_COROSYNC
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

    for (i = 0; i < member_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(member_list[i].nodeid, NULL);
        crm_debug("Member[%d] %d ", i, member_list[i].nodeid);
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, ONLINESTATUS);
    }

    for (i = 0; i < left_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(left_list[i].nodeid, NULL);
        crm_debug("Left[%d] %d ", i, left_list[i].nodeid);
        crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, OFFLINESTATUS);
    }
}

cpg_callbacks_t cpg_callbacks = {
    .cpg_deliver_fn = pcmk_cpg_deliver,
    .cpg_confchg_fn = pcmk_cpg_membership,
};
#  endif

static gboolean
init_cpg_connection(crm_cluster_t *cluster)
{
#  ifdef SUPPORT_COROSYNC
    int rc = -1;
    int fd = 0;
    int retries = 0;
    crm_node_t *peer = NULL;
    struct mainloop_fd_callbacks cpg_fd_callbacks = {
        .dispatch = pcmk_cpg_dispatch,
        .destroy = cluster->destroy,
    };    

    strcpy(pcmk_cpg_group.value, crm_system_name);
    pcmk_cpg_group.length = strlen(crm_system_name) + 1;

    cs_repeat(retries, 30, rc = cpg_initialize(&pcmk_cpg_handle, &cpg_callbacks));
    if (rc != CS_OK) {
        crm_err("Could not connect to the Cluster Process Group API: %d\n", rc);
        goto bail;
    }

    retries = 0;
    cs_repeat(retries, 30, rc = cpg_local_get(pcmk_cpg_handle, (unsigned int *)&cluster->nodeid));
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

    mainloop_add_fd("corosync-cpg", G_PRIORITY_MEDIUM, fd, cluster->cs_dispatch, &cpg_fd_callbacks);

  bail:
    if (rc != CS_OK) {
        cpg_finalize(pcmk_cpg_handle);
        return FALSE;
    }

    peer = crm_get_peer(cluster->nodeid, pcmk_uname);
    crm_update_peer_proc(__FUNCTION__, peer, crm_proc_cpg, ONLINESTATUS);

#  else
    crm_err("The Corosync CPG API is not supported in this build");
    exit(100);
#  endif
    return TRUE;
}

gboolean
init_quorum_connection(gboolean(*dispatch) (unsigned long long, gboolean),
                       void (*destroy) (gpointer))
{
    crm_err("The Corosync quorum API is not supported in this build");
    exit(100);
    return TRUE;
}

static gboolean
init_cs_connection_classic(crm_cluster_t *cluster)
{
    int rc;
    int pid = 0;
    char *pid_s = NULL;
    struct utsname name;
    struct mainloop_fd_callbacks ais_fd_callbacks = {
        .dispatch = ais_dispatch,
        .destroy = cluster->destroy,
    };

    crm_info("Creating connection to our Corosync plugin");
    rc = coroipcc_service_connect(COROSYNC_SOCKET_NAME, PCMK_SERVICE_ID,
                                  AIS_IPC_MESSAGE_SIZE, AIS_IPC_MESSAGE_SIZE, AIS_IPC_MESSAGE_SIZE,
                                  &ais_ipc_handle);
    if (ais_ipc_handle) {
        coroipcc_fd_get(ais_ipc_handle, &ais_fd_async);
    } else {
        crm_info("Connection to our AIS plugin (%d) failed: %s (%d)",
                 PCMK_SERVICE_ID, strerror(errno), errno);
        return FALSE;
    }
    if (ais_fd_async <= 0 && rc == CS_OK) {
        crm_err("No context created, but connection reported 'ok'");
        rc = CS_ERR_LIBRARY;
    }
    if (rc != CS_OK) {
        crm_info("Connection to our AIS plugin (%d) failed: %s (%d)", PCMK_SERVICE_ID,
                 ais_error2text(rc), rc);
    }

    if (rc != CS_OK) {
        return FALSE;
    }

    if (ais_fd_callbacks.destroy == NULL) {
        ais_fd_callbacks.destroy = ais_destroy;
    }

    mainloop_add_fd("corosync-plugin", G_PRIORITY_MEDIUM, ais_fd_async, cluster->cs_dispatch, &ais_fd_callbacks);
    crm_info("AIS connection established");

    pid = getpid();
    pid_s = crm_itoa(pid);
    send_ais_text(crm_class_cluster, pid_s, TRUE, NULL, crm_msg_ais);
    free(pid_s);

    if (uname(&name) < 0) {
        crm_perror(LOG_ERR, "Could not determin the current host");
        exit(100);
    }

    get_ais_nodeid(&pcmk_nodeid, &pcmk_uname);
    if (safe_str_neq(name.nodename, pcmk_uname)) {
        crm_crit("Node name mismatch!  OpenAIS supplied %s, our lookup returned %s",
                 pcmk_uname, name.nodename);
        crm_notice
            ("Node name mismatches usually occur when assigned automatically by DHCP servers");
        crm_notice("If this node was part of the cluster with a different name,"
                   " you will need to remove the old entry with crm_node --remove");
    }
    return TRUE;
}


static int
pcmk_mcp_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    xmlNode *msg = string2xml(buffer);

    if (msg && is_classic_ais_cluster()) {
        xmlNode *node = NULL;
        
        for (node = __xml_first_child(msg); node != NULL; node = __xml_next(node)) {
            int id = 0;
            int children = 0;
            const char *uname = crm_element_value(node, "uname");
            
            crm_element_value_int(node, "id", &id);
            crm_element_value_int(node, "processes", &children);
            if (id == 0) {
                crm_log_xml_err(msg, "Bad Update");
            } else {
                crm_node_t *peer = crm_get_peer(id, uname);
                crm_update_peer_proc(__FUNCTION__, peer, children, NULL);
            }
        }
    }

    free_xml(msg);
    return 0;
}

static void
pcmk_mcp_destroy(gpointer user_data)
{
    void (*callback)(gpointer data) = user_data;
    if(callback) {
        callback(NULL);
    }
}

gboolean
init_cs_connection(crm_cluster_t *cluster)
{
    int retries = 0;
    static struct ipc_client_callbacks mcp_callbacks = 
        {
            .dispatch = pcmk_mcp_dispatch,
            .destroy = pcmk_mcp_destroy
        };

    while (retries < 5) {
        int rc = init_cs_connection_once(cluster);
        retries++;

        switch (rc) {
            case CS_OK:
                if (getenv("HA_mcp")) {
                    xmlNode *poke = create_xml_node(NULL, "poke");
                    mainloop_io_t *ipc = mainloop_add_ipc_client(CRM_SYSTEM_MCP, G_PRIORITY_MEDIUM, 0, cluster->destroy, &mcp_callbacks);
                    crm_ipc_send(mainloop_get_ipc_client(ipc), poke, 0, 0, NULL);
                    free_xml(poke);
                }
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

    crm_err("Retry count exceeded: %d", retries);
    return FALSE;
}

static char *
get_local_node_name(void)
{
    char *name = NULL;
    struct utsname res;

    if (is_cman_cluster()) {
#  if SUPPORT_CMAN
        cman_node_t us;
        cman_handle_t cman;

        cman = cman_init(NULL);
        if (cman != NULL && cman_is_active(cman)) {
            us.cn_name[0] = 0;
            cman_get_node(cman, CMAN_NODEID_US, &us);
            name = strdup(us.cn_name);
            crm_info("Using CMAN node name: %s", name);

        } else {
            crm_err("Couldn't determin node name from CMAN");
        }

        cman_finish(cman);
#  endif

    } else if (uname(&res) < 0) {
        crm_perror(LOG_ERR, "Could not determin the current host");
        exit(100);

    } else {
        name = strdup(res.nodename);
    }
    return name;
}

extern int set_cluster_type(enum cluster_type_e type);

gboolean
init_cs_connection_once(crm_cluster_t *cluster)
{
    enum cluster_type_e stack = get_cluster_type();

    crm_peer_init();

    /* Here we just initialize comms */
    switch (stack) {
        case pcmk_cluster_classic_ais:
            if (init_cs_connection_classic(cluster) == FALSE) {
                return FALSE;
            }
            break;
        case pcmk_cluster_cman:
            if (init_cpg_connection(cluster) == FALSE) {
                return FALSE;
            }
            pcmk_uname = get_local_node_name();
            break;
        case pcmk_cluster_heartbeat:
            crm_info("Could not find an active corosync based cluster");
            return FALSE;
            break;
        default:
            crm_err("Invalid cluster type: %s (%d)", name_for_cluster_type(stack), stack);
            return FALSE;
            break;
    }

    crm_info("Connection to '%s': established", name_for_cluster_type(stack));

    CRM_ASSERT(pcmk_uname != NULL);
    pcmk_uname_len = strlen(pcmk_uname);

    pcmk_nodeid = cluster->nodeid;
    if (pcmk_nodeid != 0) {
        /* Ensure the local node always exists */
        crm_get_peer(pcmk_nodeid, pcmk_uname);
    }

    cluster->uuid = get_corosync_uuid(pcmk_nodeid, pcmk_uname);
    cluster->uname = strdup(pcmk_uname);

    return TRUE;
}

gboolean
check_message_sanity(const AIS_Message * msg, const char *data)
{
    gboolean sane = TRUE;
    gboolean repaired = FALSE;
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

    } else if (repaired) {
        crm_err
            ("Repaired message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
             msg->id, ais_dest(&(msg->host)), msg_type2text(dest), ais_dest(&(msg->sender)),
             msg_type2text(msg->sender.type), msg->sender.pid, msg->is_compressed,
             ais_data_len(msg), msg->header.size);
    } else {
        crm_trace
            ("Verfied message %d: (dest=%s:%s, from=%s:%s.%d, compressed=%d, size=%d, total=%d)",
             msg->id, ais_dest(&(msg->host)), msg_type2text(dest), ais_dest(&(msg->sender)),
             msg_type2text(msg->sender.type), msg->sender.pid, msg->is_compressed,
             ais_data_len(msg), msg->header.size);
    }

    return sane;
}
#endif

static int
get_config_opt(confdb_handle_t config,
               hdb_handle_t object_handle, const char *key, char **value, const char *fallback)
{
    size_t len = 0;
    char *env_key = NULL;
    const char *env_value = NULL;
    char buffer[256];

    if (*value) {
        free(*value);
        *value = NULL;
    }

    if (object_handle > 0) {
        if (CS_OK == confdb_key_get(config, object_handle, key, strlen(key), &buffer, &len)) {
            *value = strdup(buffer);
        }
    }

    if (*value) {
        crm_info("Found '%s' for option: %s", *value, key);
        return 0;
    }

    env_key = crm_concat("HA", key, '_');
    env_value = getenv(env_key);
    free(env_key);

    if (*value) {
        crm_info("Found '%s' in ENV for option: %s", *value, key);
        *value = strdup(env_value);
        return 0;
    }

    if (fallback) {
        crm_info("Defaulting to '%s' for option: %s", fallback, key);
        *value = strdup(fallback);

    } else {
        crm_info("No default for option: %s", key);
    }

    return -1;
}

static confdb_handle_t
config_find_init(confdb_handle_t config)
{
    cs_error_t rc = CS_OK;
    confdb_handle_t local_handle = OBJECT_PARENT_HANDLE;

    rc = confdb_object_find_start(config, local_handle);
    if (rc == CS_OK) {
        return local_handle;
    } else {
        crm_err("Couldn't create search context: %d", rc);
    }
    return 0;
}

static hdb_handle_t
config_find_next(confdb_handle_t config, const char *name, confdb_handle_t top_handle)
{
    cs_error_t rc = CS_OK;
    hdb_handle_t local_handle = 0;

    if (top_handle == 0) {
        crm_err("Couldn't search for %s: no valid context", name);
        return 0;
    }

    crm_trace("Searching for %s in " HDB_X_FORMAT, name, top_handle);
    rc = confdb_object_find(config, top_handle, name, strlen(name), &local_handle);
    if (rc != CS_OK) {
        crm_info("No additional configuration supplied for: %s", name);
        local_handle = 0;
    } else {
        crm_info("Processing additional %s options...", name);
    }
    return local_handle;
}

enum cluster_type_e
find_corosync_variant(void)
{
    confdb_handle_t config;
    enum cluster_type_e found = pcmk_cluster_unknown;

    int rc;
    char *value = NULL;
    confdb_handle_t top_handle = 0;
    hdb_handle_t local_handle = 0;
    static confdb_callbacks_t callbacks = { };

    rc = confdb_initialize(&config, &callbacks);
    if (rc != CS_OK) {
        crm_debug("Could not initialize Cluster Configuration Database API instance error %d", rc);
        return found;
    }

    top_handle = config_find_init(config);
    local_handle = config_find_next(config, "service", top_handle);
    while (local_handle) {
        get_config_opt(config, local_handle, "name", &value, NULL);
        if (safe_str_eq("pacemaker", value)) {
            found = pcmk_cluster_classic_ais;

            get_config_opt(config, local_handle, "ver", &value, "0");
            crm_trace("Found Pacemaker plugin version: %s", value);
            break;
        }

        local_handle = config_find_next(config, "service", top_handle);
    }

    if (found == pcmk_cluster_unknown) {
        top_handle = config_find_init(config);
        local_handle = config_find_next(config, "quorum", top_handle);
        get_config_opt(config, local_handle, "provider", &value, NULL);

        if (safe_str_eq("quorum_cman", value)) {
            crm_trace("Found CMAN quorum provider");
            found = pcmk_cluster_cman;
        }
    }
    free(value);

    confdb_finalize(config);
    return found;
}

gboolean
crm_is_corosync_peer_active(const crm_node_t * node)
{
    enum crm_proc_flag proc = crm_proc_none;
    if (node == NULL) {
        crm_trace("NULL");
        return FALSE;

    } else if(safe_str_neq(node->state, CRM_NODE_MEMBER)) {
        crm_trace("%s: state=%s", node->uname, node->state);
        return FALSE;

    } else if(is_cman_cluster() && (node->processes & crm_proc_cpg)) {
        /* If we can still talk to our peer process on that node,
         * then its also part of the corosync membership
         */
        crm_trace("%s: processes=%.16x", node->uname, node->processes);
        return TRUE;

    } else if(is_classic_ais_cluster() && (node->processes & crm_proc_plugin) == 0) {
        crm_trace("%s: processes=%.16x", node->uname, node->processes);
        return FALSE;
    }

    proc = text2proc(crm_system_name);
    if(proc != crm_proc_none && (node->processes & proc) == 0) {
        crm_trace("%s: proc %.16x not in %.16x", node->uname, proc, node->processes);
        return FALSE;
    }

    return TRUE;
}

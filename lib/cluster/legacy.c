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
#include <sys/socket.h>
#include <netdb.h>

#if SUPPORT_COROSYNC
#  include <corosync/confdb.h>
#  include <corosync/corodefs.h>
#  include <corosync/cpg.h>
#  include <corosync/cfg.h>
#endif

#if HAVE_CMAP
#  include <corosync/cmap.h>
#endif

#if SUPPORT_CMAN
#  include <libcman.h>
cman_handle_t pcmk_cman_handle = NULL;
#endif

int ais_membership_timer = 0;
gboolean ais_membership_force = FALSE;
int plugin_dispatch(gpointer user_data);

int ais_fd_sync = -1;
int ais_fd_async = -1;          /* never send messages via this channel */
void *ais_ipc_ctx = NULL;

hdb_handle_t ais_ipc_handle = 0;

static gboolean
plugin_get_details(uint32_t * id, char **uname)
{
    struct iovec iov;
    int retries = 0;
    int rc = CS_OK;
    cs_ipc_header_response_t header;
    struct crm_ais_nodeid_resp_s answer;

    static uint32_t local_id = 0;
    static char *local_uname = NULL;

    if(local_id) {
        if(id) *id = local_id;
        if(uname) *uname = strdup(local_uname);
        return TRUE;
    }

    header.error = CS_OK;
    header.id = crm_class_nodeid;
    header.size = sizeof(cs_ipc_header_response_t);

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

    local_id = answer.id;
    local_uname = strdup(answer.uname);

    if(id) *id = local_id;
    if(uname) *uname = strdup(local_uname);
    return TRUE;
}

bool
send_plugin_text(int class, struct iovec *iov)
{
    int rc = CS_OK;
    int retries = 0;
    int buf_len = sizeof(cs_ipc_header_response_t);
    char *buf = malloc(buf_len);
    AIS_Message *ais_msg = (AIS_Message*)iov[0].iov_base;
    cs_ipc_header_response_t *header = (cs_ipc_header_response_t *) buf;

    CRM_ASSERT(buf != NULL);
    /* There are only 6 handlers registered to crm_lib_service in plugin.c */
    CRM_CHECK(class < 6, crm_err("Invalid message class: %d", class);
              return FALSE);

    do {
        if (rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) {
            retries++;
            crm_info("Peer overloaded or membership in flux:"
                     " Re-sending message (Attempt %d of 20)", retries);
            sleep(retries);     /* Proportional back off */
        }

        errno = 0;
        rc = coroipcc_msg_send_reply_receive(ais_ipc_handle, iov, 1, buf, buf_len);

    } while ((rc == CS_ERR_TRY_AGAIN || rc == CS_ERR_QUEUE_FULL) && retries < 20);

    if (rc == CS_OK) {
        CRM_CHECK(header->size == sizeof(cs_ipc_header_response_t),
                  crm_err("Odd message: id=%d, size=%d, class=%d, error=%d",
                          header->id, header->size, class, header->error));

        CRM_ASSERT(buf_len >= header->size);
        CRM_CHECK(header->id == CRM_MESSAGE_IPC_ACK,
                  crm_err("Bad response id (%d) for request (%d)", header->id,
                          ais_msg->header.id));
        CRM_CHECK(header->error == CS_OK, rc = header->error);

    } else {
        crm_perror(LOG_ERR, "Sending plugin message %d FAILED: %s (%d)",
                   ais_msg->id, ais_error2text(rc), rc);
    }

    free(iov[0].iov_base);
    free(iov);
    free(buf);

    return (rc == CS_OK);
}

void
terminate_cs_connection(crm_cluster_t *cluster)
{
    crm_notice("Disconnecting from Corosync");

    if (is_classic_ais_cluster()) {
        if (ais_ipc_handle) {
            crm_trace("Disconnecting plugin");
            coroipcc_service_disconnect(ais_ipc_handle);
            ais_ipc_handle = 0;
        } else {
            crm_info("No plugin connection");
        }
    }
    cluster_disconnect_cpg(cluster);

#  if SUPPORT_CMAN
    if (is_cman_cluster()) {
        if (pcmk_cman_handle) {
            crm_info("Disconnecting cman");
            if (cman_stop_notification(pcmk_cman_handle) >= 0) {
                crm_info("Destroying cman");
                cman_finish(pcmk_cman_handle);
            }

        } else {
            crm_info("No cman connection");
        }
    }
#  endif
    ais_fd_async = -1;
    ais_fd_sync = -1;
}

void
plugin_handle_membership(AIS_Message *msg)
{
    if (msg->header.id == crm_class_members || msg->header.id == crm_class_quorum) {
        xmlNode *member = NULL;
        const char *value = NULL;
        gboolean quorate = FALSE;
        xmlNode *xml = string2xml(msg->data);

        if (xml == NULL) {
            crm_err("Invalid membership update: %s", msg->data);
            return;
        }

        value = crm_element_value(xml, "quorate");
        CRM_CHECK(value != NULL, crm_log_xml_err(xml, "No quorum value:"); return);
        if (crm_is_true(value)) {
            quorate = TRUE;
        }

        value = crm_element_value(xml, "id");
        CRM_CHECK(value != NULL, crm_log_xml_err(xml, "No membership id"); return);
        crm_peer_seq = crm_int_helper(value, NULL);

        if (quorate != crm_have_quorum) {
            crm_notice("Membership %s: quorum %s", value, quorate ? "acquired" : "lost");
            crm_have_quorum = quorate;

        } else {
            crm_info("Membership %s: quorum %s", value, quorate ? "retained" : "still lost");
        }

        for (member = __xml_first_child(xml); member != NULL; member = __xml_next(member)) {
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

            crm_update_peer(__FUNCTION__, id, born, seen, votes, procs, uname, uname, addr, state);
        }
        free_xml(xml);
    }
}

static void
plugin_default_deliver_message(cpg_handle_t handle,
                               const struct cpg_name *groupName,
                               uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    free(data);
}

int
plugin_dispatch(gpointer user_data)
{
    int rc = CS_OK;
    crm_cluster_t *cluster = (crm_cluster_t *) user_data;

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
        /*
        cpg_deliver_fn_t(cpg_handle_t handle, const struct cpg_name *group_name,
                         uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len);
        */
        if (cluster && cluster->cpg.cpg_deliver_fn) {
            cluster->cpg.cpg_deliver_fn(0, NULL, 0, 0, buffer, 0);

        } else {
            plugin_default_deliver_message(0, NULL, 0, 0, buffer, 0);
        }

        coroipcc_dispatch_put(ais_ipc_handle);

    } while (ais_ipc_handle);

    return 0;
}

static void
plugin_destroy(gpointer user_data)
{
    crm_err("AIS connection terminated");
    ais_fd_sync = -1;
    crm_exit(ENOTCONN);
}

#  if SUPPORT_CMAN

static int
pcmk_cman_dispatch(gpointer user_data)
{
    int rc = cman_dispatch(pcmk_cman_handle, CMAN_DISPATCH_ALL);

    if (rc < 0) {
        crm_err("Connection to cman failed: %d", rc);
        pcmk_cman_handle = 0;
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
                crm_node_t *peer = NULL;

                if (cman_nodes[lpc].cn_nodeid == 0) {
                    /* Never allow node ID 0 to be considered a member #315711 */
                    /* Skip entirely, its a qdisk */
                    continue;
                }

                peer = crm_get_peer(cman_nodes[lpc].cn_nodeid, cman_nodes[lpc].cn_name);
                if(cman_nodes[lpc].cn_member) {
                    crm_update_peer_state(__FUNCTION__, peer, CRM_NODE_MEMBER, crm_peer_seq);

                } else if(peer->state) {
                    crm_update_peer_state(__FUNCTION__, peer, CRM_NODE_LOST, 0);

                } else {
                    crm_info("State of node %s[%u] is still unknown", peer->uname, peer->id);
                }
            }

            if (dispatch) {
                dispatch(crm_peer_seq, crm_have_quorum);
            }
            break;

        case CMAN_REASON_TRY_SHUTDOWN:
            /* Always reply with a negative - pacemaker needs to be stopped first */
            crm_notice("CMAN wants to shut down: %s", arg ? "forced" : "optional");
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
    crm_exit(DAEMON_RESPAWN_STOP);
#  endif
    return TRUE;
}

#  ifdef SUPPORT_COROSYNC

gboolean
cluster_connect_quorum(gboolean(*dispatch) (unsigned long long, gboolean),
                       void (*destroy) (gpointer))
{
    crm_err("The Corosync quorum API is not supported in this build");
    crm_exit(DAEMON_RESPAWN_STOP);
    return TRUE;
}

static gboolean
init_cs_connection_classic(crm_cluster_t * cluster)
{
    int rc;
    int pid = 0;
    char *pid_s = NULL;
    const char *name = NULL;
    crm_node_t *peer = NULL;
    enum crm_proc_flag proc = 0;

    struct mainloop_fd_callbacks ais_fd_callbacks = {
        .dispatch = plugin_dispatch,
        .destroy = cluster->destroy,
    };

    crm_info("Creating connection to our Corosync plugin");
    rc = coroipcc_service_connect(COROSYNC_SOCKET_NAME, PCMK_SERVICE_ID,
                                  AIS_IPC_MESSAGE_SIZE, AIS_IPC_MESSAGE_SIZE, AIS_IPC_MESSAGE_SIZE,
                                  &ais_ipc_handle);
    if (ais_ipc_handle) {
        coroipcc_fd_get(ais_ipc_handle, &ais_fd_async);
    } else {
        crm_info("Connection to our Corosync plugin (%d) failed: %s (%d)",
                 PCMK_SERVICE_ID, strerror(errno), errno);
        return FALSE;
    }
    if (ais_fd_async <= 0 && rc == CS_OK) {
        crm_err("No context created, but connection reported 'ok'");
        rc = CS_ERR_LIBRARY;
    }
    if (rc != CS_OK) {
        crm_info("Connection to our Corosync plugin (%d) failed: %s (%d)", PCMK_SERVICE_ID,
                 ais_error2text(rc), rc);
    }

    if (rc != CS_OK) {
        return FALSE;
    }

    if (ais_fd_callbacks.destroy == NULL) {
        ais_fd_callbacks.destroy = plugin_destroy;
    }

    mainloop_add_fd("corosync-plugin", G_PRIORITY_MEDIUM, ais_fd_async, cluster, &ais_fd_callbacks);
    crm_info("AIS connection established");

    pid = getpid();
    pid_s = crm_itoa(pid);
    send_cluster_text(crm_class_cluster, pid_s, TRUE, NULL, crm_msg_ais);
    free(pid_s);

    cluster->nodeid = get_local_nodeid(0);

    name = get_local_node_name();
    plugin_get_details(NULL, &(cluster->uname));
    if (safe_str_neq(name, cluster->uname)) {
        crm_crit("Node name mismatch!  Corosync supplied %s but our lookup returned %s",
                 cluster->uname, name);
        crm_notice
            ("Node name mismatches usually occur when assigned automatically by DHCP servers");
        crm_exit(ENOTUNIQ);
    }

    proc = text2proc(crm_system_name);
    peer = crm_get_peer(cluster->nodeid, cluster->uname);
    crm_update_peer_proc(__FUNCTION__, peer, proc|crm_proc_plugin, ONLINESTATUS);

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
    void (*callback) (gpointer data) = user_data;

    if (callback) {
        callback(NULL);
    }
}

gboolean
init_cs_connection(crm_cluster_t * cluster)
{
    int retries = 0;

    static struct ipc_client_callbacks mcp_callbacks = {
        .dispatch = pcmk_mcp_dispatch,
        .destroy = pcmk_mcp_destroy
    };

    while (retries < 5) {
        int rc = init_cs_connection_once(cluster);

        retries++;
        switch (rc) {
            case CS_OK:
                if (getenv("HA_mcp") && get_cluster_type() != pcmk_cluster_cman) {
                    xmlNode *poke = create_xml_node(NULL, "poke");
                    mainloop_io_t *ipc =
                        mainloop_add_ipc_client(CRM_SYSTEM_MCP, G_PRIORITY_MEDIUM, 0,
                                                cluster->destroy, &mcp_callbacks);

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

char *
classic_node_name(uint32_t nodeid)
{
    return NULL;                /* Always use the uname() default for localhost.  No way to look up peers */
}

char *
cman_node_name(uint32_t nodeid)
{
    char *name = NULL;

#  if SUPPORT_CMAN
    cman_node_t us;
    cman_handle_t cman;

    cman = cman_init(NULL);
    if (cman != NULL && cman_is_active(cman)) {
        us.cn_name[0] = 0;
        cman_get_node(cman, nodeid, &us);
        name = strdup(us.cn_name);
        crm_info("Using CMAN node name %s for %u", name, nodeid);
    }

    cman_finish(cman);
#  endif

    if (name == NULL) {
        crm_debug("Unable to get node name for nodeid %u", nodeid);
    }
    return name;
}

extern int set_cluster_type(enum cluster_type_e type);

gboolean
init_cs_connection_once(crm_cluster_t * cluster)
{
    crm_node_t *peer = NULL;
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
            if (cluster_connect_cpg(cluster) == FALSE) {
                return FALSE;
            }
            cluster->uname = cman_node_name(0 /* CMAN_NODEID_US */ );
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
    if (found == pcmk_cluster_unknown) {
        crm_err
            ("Corosync is running, but Pacemaker could not find the CMAN or Pacemaker plugin loaded");
        found = pcmk_cluster_invalid;
    }
    return found;
}

gboolean
crm_is_corosync_peer_active(const crm_node_t * node)
{
    enum crm_proc_flag proc = crm_proc_none;

    if (node == NULL) {
        crm_trace("NULL");
        return FALSE;

    } else if (safe_str_neq(node->state, CRM_NODE_MEMBER)) {
        crm_trace("%s: state=%s", node->uname, node->state);
        return FALSE;

    } else if (is_cman_cluster() && (node->processes & crm_proc_cpg)) {
        /* If we can still talk to our peer process on that node,
         * then its also part of the corosync membership
         */
        crm_trace("%s: processes=%.8x", node->uname, node->processes);
        return TRUE;

    } else if (is_classic_ais_cluster()) {
        if (node->processes < crm_proc_none) {
            crm_debug("%s: unknown process list, assuming active for now", node->uname);
            return TRUE;

        } else if (is_set(node->processes, crm_proc_none)) {
            crm_debug("%s: all processes are inactive", node->uname);
            return FALSE;

        } else if (is_not_set(node->processes, crm_proc_plugin)) {
            crm_trace("%s: processes=%.8x", node->uname, node->processes);
            return FALSE;
        }
    }

    proc = text2proc(crm_system_name);
    if (proc > crm_proc_none && (node->processes & proc) == 0) {
        crm_trace("%s: proc %.8x not in %.8x", node->uname, proc, node->processes);
        return FALSE;
    }

    return TRUE;
}

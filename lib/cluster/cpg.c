/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
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

#include <qb/qbipc_common.h>
#include <qb/qbipcc.h>
#include <qb/qbutil.h>

#include <corosync/corodefs.h>
#include <corosync/corotypes.h>
#include <corosync/hdb.h>
#include <corosync/cpg.h>

#include <crm/msg_xml.h>

#include <crm/common/ipc_internal.h>  /* PCMK__SPECIAL_PID* */
#include "crmcluster_private.h"

/* @TODO Once we can update the public API to require crm_cluster_t* in more
 *       functions, we can ditch this in favor of cluster->cpg_handle.
 */
static cpg_handle_t pcmk_cpg_handle = 0;

// @TODO These could be moved to crm_cluster_t* at that time as well
static bool cpg_evicted = false;
static GList *cs_message_queue = NULL;
static int cs_message_timer = 0;

struct pcmk__cpg_host_s {
    uint32_t id;
    uint32_t pid;
    gboolean local;
    enum crm_ais_msg_types type;
    uint32_t size;
    char uname[MAX_NAME];
} __attribute__ ((packed));

typedef struct pcmk__cpg_host_s pcmk__cpg_host_t;

struct pcmk__cpg_msg_s {
    struct qb_ipc_response_header header __attribute__ ((aligned(8)));
    uint32_t id;
    gboolean is_compressed;

    pcmk__cpg_host_t host;
    pcmk__cpg_host_t sender;

    uint32_t size;
    uint32_t compressed_size;
    /* 584 bytes */
    char data[0];

} __attribute__ ((packed));

typedef struct pcmk__cpg_msg_s pcmk__cpg_msg_t;

static void crm_cs_flush(gpointer data);

#define msg_data_len(msg) (msg->is_compressed?msg->compressed_size:msg->size)

#define cs_repeat(rc, counter, max, code) do {                          \
        rc = code;                                                      \
        if ((rc == CS_ERR_TRY_AGAIN) || (rc == CS_ERR_QUEUE_FULL)) {    \
            counter++;                                                  \
            crm_debug("Retrying operation after %ds", counter);         \
            sleep(counter);                                             \
        } else {                                                        \
            break;                                                      \
        }                                                               \
    } while (counter < max)

/*!
 * \brief Disconnect from Corosync CPG
 *
 * \param[in] Cluster to disconnect
 */
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

/*!
 * \brief Get the local Corosync node ID (via CPG)
 *
 * \param[in] handle  CPG connection to use (or 0 to use new connection)
 *
 * \return Corosync ID of local node (or 0 if not known)
 */
uint32_t
get_local_nodeid(cpg_handle_t handle)
{
    cs_error_t rc = CS_OK;
    int retries = 0;
    static uint32_t local_nodeid = 0;
    cpg_handle_t local_handle = handle;
    cpg_model_v1_data_t cpg_model_info = {CPG_MODEL_V1, NULL, NULL, NULL, 0};
    int fd = -1;
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;

    if(local_nodeid != 0) {
        return local_nodeid;
    }

    if(handle == 0) {
        crm_trace("Creating connection");
        cs_repeat(rc, retries, 5, cpg_model_initialize(&local_handle, CPG_MODEL_V1, (cpg_model_data_t *)&cpg_model_info, NULL));
        if (rc != CS_OK) {
            crm_err("Could not connect to the CPG API: %s (%d)",
                    cs_strerror(rc), rc);
            return 0;
        }

        rc = cpg_fd_get(local_handle, &fd);
        if (rc != CS_OK) {
            crm_err("Could not obtain the CPG API connection: %s (%d)",
                    cs_strerror(rc), rc);
            goto bail;
        }

        /* CPG provider run as root (in given user namespace, anyway)? */
        if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                                &found_uid, &found_gid))) {
            crm_err("CPG provider is not authentic:"
                    " process %lld (uid: %lld, gid: %lld)",
                    (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                    (long long) found_uid, (long long) found_gid);
            goto bail;
        } else if (rv < 0) {
            crm_err("Could not verify authenticity of CPG provider: %s (%d)",
                    strerror(-rv), -rv);
            goto bail;
        }
    }

    if (rc == CS_OK) {
        retries = 0;
        crm_trace("Performing lookup");
        cs_repeat(rc, retries, 5, cpg_local_get(local_handle, &local_nodeid));
    }

    if (rc != CS_OK) {
        crm_err("Could not get local node id from the CPG API: %s (%d)",
                pcmk__cs_err_str(rc), rc);
    }

bail:
    if(handle == 0) {
        crm_trace("Closing connection");
        cpg_finalize(local_handle);
    }
    crm_debug("Local nodeid is %u", local_nodeid);
    return local_nodeid;
}

/*!
 * \internal
 * \brief Callback function for Corosync message queue timer
 *
 * \param[in] data  CPG handle
 *
 * \return FALSE (to indicate to glib that timer should not be removed)
 */
static gboolean
crm_cs_flush_cb(gpointer data)
{
    cs_message_timer = 0;
    crm_cs_flush(data);
    return FALSE;
}

// Send no more than this many CPG messages in one flush
#define CS_SEND_MAX 200

/*!
 * \internal
 * \brief Send messages in Corosync CPG message queue
 *
 * \param[in] data   CPG handle
 */
static void
crm_cs_flush(gpointer data)
{
    unsigned int sent = 0;
    guint queue_len = 0;
    cs_error_t rc = 0;
    cpg_handle_t *handle = (cpg_handle_t *) data;

    if (*handle == 0) {
        crm_trace("Connection is dead");
        return;
    }

    queue_len = g_list_length(cs_message_queue);
    if (((queue_len % 1000) == 0) && (queue_len > 1)) {
        crm_err("CPG queue has grown to %d", queue_len);

    } else if (queue_len == CS_SEND_MAX) {
        crm_warn("CPG queue has grown to %d", queue_len);
    }

    if (cs_message_timer != 0) {
        /* There is already a timer, wait until it goes off */
        crm_trace("Timer active %d", cs_message_timer);
        return;
    }

    while ((cs_message_queue != NULL) && (sent < CS_SEND_MAX)) {
        struct iovec *iov = cs_message_queue->data;

        rc = cpg_mcast_joined(*handle, CPG_TYPE_AGREED, iov, 1);
        if (rc != CS_OK) {
            break;
        }

        sent++;
        crm_trace("CPG message sent, size=%llu",
                  (unsigned long long) iov->iov_len);

        cs_message_queue = g_list_remove(cs_message_queue, iov);
        free(iov->iov_base);
        free(iov);
    }

    queue_len -= sent;
    do_crm_log((queue_len > 5)? LOG_INFO : LOG_TRACE,
               "Sent %u CPG message%s (%d still queued): %s (rc=%d)",
               sent, pcmk__plural_s(sent), queue_len, pcmk__cs_err_str(rc),
               (int) rc);

    if (cs_message_queue) {
        uint32_t delay_ms = 100;
        if (rc != CS_OK) {
            /* Proportionally more if sending failed but cap at 1s */
            delay_ms = QB_MIN(1000, CS_SEND_MAX + (10 * queue_len));
        }
        cs_message_timer = g_timeout_add(delay_ms, crm_cs_flush_cb, data);
    }
}

/*!
 * \internal
 * \brief Dispatch function for CPG handle
 *
 * \param[in] user_data  Cluster object
 *
 * \return 0 on success, -1 on error (per mainloop_io_t interface)
 */
static int
pcmk_cpg_dispatch(gpointer user_data)
{
    cs_error_t rc = CS_OK;
    crm_cluster_t *cluster = (crm_cluster_t *) user_data;

    rc = cpg_dispatch(cluster->cpg_handle, CS_DISPATCH_ONE);
    if (rc != CS_OK) {
        crm_err("Connection to the CPG API failed: %s (%d)",
                pcmk__cs_err_str(rc), rc);
        cpg_finalize(cluster->cpg_handle);
        cluster->cpg_handle = 0;
        return -1;

    } else if (cpg_evicted) {
        crm_err("Evicted from CPG membership");
        return -1;
    }
    return 0;
}

static inline const char *
ais_dest(const pcmk__cpg_host_t *host)
{
    if (host->local) {
        return "local";
    } else if (host->size > 0) {
        return host->uname;
    } else {
        return "<all>";
    }
}

static inline const char *
msg_type2text(enum crm_ais_msg_types type)
{
    const char *text = "unknown";

    switch (type) {
        case crm_msg_none:
            text = "unknown";
            break;
        case crm_msg_ais:
            text = "ais";
            break;
        case crm_msg_cib:
            text = "cib";
            break;
        case crm_msg_crmd:
            text = "crmd";
            break;
        case crm_msg_pe:
            text = "pengine";
            break;
        case crm_msg_te:
            text = "tengine";
            break;
        case crm_msg_lrmd:
            text = "lrmd";
            break;
        case crm_msg_attrd:
            text = "attrd";
            break;
        case crm_msg_stonithd:
            text = "stonithd";
            break;
        case crm_msg_stonith_ng:
            text = "stonith-ng";
            break;
    }
    return text;
}

/*!
 * \internal
 * \brief Check whether a Corosync CPG message is valid
 *
 * \param[in] msg   Corosync CPG message to check
 *
 * \return true if \p msg is valid, otherwise false
 */
static bool
check_message_sanity(const pcmk__cpg_msg_t *msg)
{
    int32_t payload_size = msg->header.size - sizeof(pcmk__cpg_msg_t);

    if (payload_size < 1) {
        crm_err("%sCPG message %d from %s invalid: "
                "Claimed size of %d bytes is too small "
                CRM_XS " from %s[%u] to %s@%s",
                (msg->is_compressed? "Compressed " : ""),
                msg->id, ais_dest(&(msg->sender)),
                (int) msg->header.size,
                msg_type2text(msg->sender.type), msg->sender.pid,
                msg_type2text(msg->host.type), ais_dest(&(msg->host)));
        return false;
    }

    if (msg->header.error != CS_OK) {
        crm_err("%sCPG message %d from %s invalid: "
                "Sender indicated error %d "
                CRM_XS " from %s[%u] to %s@%s",
                (msg->is_compressed? "Compressed " : ""),
                msg->id, ais_dest(&(msg->sender)),
                msg->header.error,
                msg_type2text(msg->sender.type), msg->sender.pid,
                msg_type2text(msg->host.type), ais_dest(&(msg->host)));
        return false;
    }

    if (msg_data_len(msg) != payload_size) {
        crm_err("%sCPG message %d from %s invalid: "
                "Total size %d inconsistent with payload size %d "
                CRM_XS " from %s[%u] to %s@%s",
                (msg->is_compressed? "Compressed " : ""),
                msg->id, ais_dest(&(msg->sender)),
                (int) msg->header.size, (int) msg_data_len(msg),
                msg_type2text(msg->sender.type), msg->sender.pid,
                msg_type2text(msg->host.type), ais_dest(&(msg->host)));
        return false;
    }

    if (!msg->is_compressed &&
        /* msg->size != (strlen(msg->data) + 1) would be a stronger check,
         * but checking the last byte or two should be quick
         */
        (((msg->size > 1) && (msg->data[msg->size - 2] == '\0'))
         || (msg->data[msg->size - 1] != '\0'))) {
        crm_err("CPG message %d from %s invalid: "
                "Payload does not end at byte %llu "
                CRM_XS " from %s[%u] to %s@%s",
                msg->id, ais_dest(&(msg->sender)),
                (unsigned long long) msg->size,
                msg_type2text(msg->sender.type), msg->sender.pid,
                msg_type2text(msg->host.type), ais_dest(&(msg->host)));
        return false;
    }

    crm_trace("Verified %d-byte %sCPG message %d from %s[%u]@%s to %s@%s",
              (int) msg->header.size, (msg->is_compressed? "compressed " : ""),
              msg->id, msg_type2text(msg->sender.type), msg->sender.pid,
              ais_dest(&(msg->sender)),
              msg_type2text(msg->host.type), ais_dest(&(msg->host)));
    return true;
}

/*!
 * \brief Extract text data from a Corosync CPG message
 *
 * \param[in]  handle   CPG connection (to get local node ID if not yet known)
 * \param[in]  nodeid   Corosync ID of node that sent message
 * \param[in]  pid      Process ID of message sender (for logging only)
 * \param[in]  content  CPG message
 * \param[out] kind     If not NULL, will be set to CPG header ID
 *                      (which should be an enum crm_ais_msg_class value,
 *                      currently always crm_class_cluster)
 * \param[out] from     If not NULL, will be set to sender uname
 *                      (valid for the lifetime of \p content)
 *
 * \return Newly allocated string with message data
 * \note It is the caller's responsibility to free the return value with free().
 */
char *
pcmk_message_common_cs(cpg_handle_t handle, uint32_t nodeid, uint32_t pid, void *content,
                        uint32_t *kind, const char **from)
{
    char *data = NULL;
    pcmk__cpg_msg_t *msg = (pcmk__cpg_msg_t *) content;

    if(handle) {
        // Do filtering and field massaging
        uint32_t local_nodeid = get_local_nodeid(handle);
        const char *local_name = get_local_node_name();

        if (msg->sender.id > 0 && msg->sender.id != nodeid) {
            crm_err("Nodeid mismatch from %d.%d: claimed nodeid=%u", nodeid, pid, msg->sender.id);
            return NULL;

        } else if (msg->host.id != 0 && (local_nodeid != msg->host.id)) {
            /* Not for us */
            crm_trace("Not for us: %u != %u", msg->host.id, local_nodeid);
            return NULL;
        } else if (msg->host.size != 0 && !pcmk__str_eq(msg->host.uname, local_name, pcmk__str_casei)) {
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
              msg_data_len(msg), msg->size, msg->compressed_size);

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

        if (!check_message_sanity(msg)) {
            goto badmsg;
        }

        crm_trace("Decompressing message data");
        uncompressed = calloc(1, new_size);
        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &new_size, msg->data, msg->compressed_size, 1, 0);

        if (rc != BZ_OK) {
            crm_err("Decompression failed: %s " CRM_XS " bzerror=%d",
                    bz2_strerror(rc), rc);
            free(uncompressed);
            goto badmsg;
        }

        CRM_ASSERT(rc == BZ_OK);
        CRM_ASSERT(new_size == msg->size);

        data = uncompressed;

    } else if (!check_message_sanity(msg)) {
        goto badmsg;

    } else {
        data = strdup(msg->data);
    }

    // Is this necessary?
    crm_get_peer(msg->sender.id, msg->sender.uname);

    crm_trace("Payload: %.200s", data);
    return data;

  badmsg:
    crm_err("Invalid message (id=%d, dest=%s:%s, from=%s:%s.%d):"
            " min=%d, total=%d, size=%d, bz2_size=%d",
            msg->id, ais_dest(&(msg->host)), msg_type2text(msg->host.type),
            ais_dest(&(msg->sender)), msg_type2text(msg->sender.type),
            msg->sender.pid, (int)sizeof(pcmk__cpg_msg_t),
            msg->header.size, msg->size, msg->compressed_size);

    free(data);
    return NULL;
}

/*!
 * \internal
 * \brief Compare cpg_address objects by node ID
 *
 * \param[in] first   First cpg_address structure to compare
 * \param[in] second  Second cpg_address structure to compare
 *
 * \return Negative number if first's node ID is lower,
 *         positive number if first's node ID is greater,
 *         or 0 if both node IDs are equal
 */
static int
cmp_member_list_nodeid(const void *first, const void *second)
{
    const struct cpg_address *const a = *((const struct cpg_address **) first),
                             *const b = *((const struct cpg_address **) second);
    if (a->nodeid < b->nodeid) {
        return -1;
    } else if (a->nodeid > b->nodeid) {
        return 1;
    }
    /* don't bother with "reason" nor "pid" */
    return 0;
}

/*!
 * \internal
 * \brief Get a readable string equivalent of a cpg_reason_t value
 *
 * \param[in] reason  CPG reason value
 *
 * \return Readable string suitable for logging
 */
static const char *
cpgreason2str(cpg_reason_t reason)
{
    switch (reason) {
        case CPG_REASON_JOIN:       return " via cpg_join";
        case CPG_REASON_LEAVE:      return " via cpg_leave";
        case CPG_REASON_NODEDOWN:   return " via cluster exit";
        case CPG_REASON_NODEUP:     return " via cluster join";
        case CPG_REASON_PROCDOWN:   return " for unknown reason";
        default:                    break;
    }
    return "";
}

/*!
 * \internal
 * \brief Get a log-friendly node name
 *
 * \param[in] peer  Node to check
 *
 * \return Node's uname, or readable string if not known
 */
static inline const char *
peer_name(crm_node_t *peer)
{
    if (peer == NULL) {
        return "unknown node";
    } else if (peer->uname == NULL) {
        return "peer node";
    } else {
        return peer->uname;
    }
}

/*!
 * \internal
 * \brief Process a CPG peer's leaving the cluster
 *
 * \param[in] cpg_group_name      CPG group name (for logging)
 * \param[in] event_counter       Event number (for logging)
 * \param[in] local_nodeid        Node ID of local node
 * \param[in] cpg_peer            CPG peer that left
 * \param[in] sorted_member_list  List of remaining members, qsort()-ed by ID
 * \param[in] member_list_entries Number of entries in \p sorted_member_list
 */
static void
node_left(const char *cpg_group_name, int event_counter,
          uint32_t local_nodeid, const struct cpg_address *cpg_peer,
          const struct cpg_address **sorted_member_list,
          size_t member_list_entries)
{
    crm_node_t *peer = pcmk__search_cluster_node_cache(cpg_peer->nodeid,
                                                       NULL);
    const struct cpg_address **rival = NULL;

    /* Most CPG-related Pacemaker code assumes that only one process on a node
     * can be in the process group, but Corosync does not impose this
     * limitation, and more than one can be a member in practice due to a
     * daemon attempting to start while another instance is already running.
     *
     * Check for any such duplicate instances, because we don't want to process
     * their leaving as if our actual peer left. If the peer that left still has
     * an entry in sorted_member_list (with a different PID), we will ignore the
     * leaving.
     *
     * @TODO Track CPG members' PIDs so we can tell exactly who left.
     */
    if (peer != NULL) {
        rival = bsearch(&cpg_peer, sorted_member_list, member_list_entries,
                        sizeof(const struct cpg_address *),
                        cmp_member_list_nodeid);
    }

    if (rival == NULL) {
        crm_info("Group %s event %d: %s (node %u pid %u) left%s",
                 cpg_group_name, event_counter, peer_name(peer),
                 cpg_peer->nodeid, cpg_peer->pid,
                 cpgreason2str(cpg_peer->reason));
        if (peer != NULL) {
            crm_update_peer_proc(__func__, peer, crm_proc_cpg,
                                 OFFLINESTATUS);
        }
    } else if (cpg_peer->nodeid == local_nodeid) {
        crm_warn("Group %s event %d: duplicate local pid %u left%s",
                 cpg_group_name, event_counter,
                 cpg_peer->pid, cpgreason2str(cpg_peer->reason));
    } else {
        crm_warn("Group %s event %d: "
                 "%s (node %u) duplicate pid %u left%s (%u remains)",
                 cpg_group_name, event_counter, peer_name(peer),
                 cpg_peer->nodeid, cpg_peer->pid,
                 cpgreason2str(cpg_peer->reason), (*rival)->pid);
    }
}

/*!
 * \brief Handle a CPG configuration change event
 *
 * \param[in] handle               CPG connection
 * \param[in] cpg_name             CPG group name
 * \param[in] member_list          List of current CPG members
 * \param[in] member_list_entries  Number of entries in \p member_list
 * \param[in] left_list            List of CPG members that left
 * \param[in] left_list_entries    Number of entries in \p left_list
 * \param[in] joined_list          List of CPG members that joined
 * \param[in] joined_list_entries  Number of entries in \p joined_list
 */
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
    const struct cpg_address **sorted;

    sorted = malloc(member_list_entries * sizeof(const struct cpg_address *));
    CRM_ASSERT(sorted != NULL);

    for (size_t iter = 0; iter < member_list_entries; iter++) {
        sorted[iter] = member_list + iter;
    }
    /* so that the cross-matching multiply-subscribed nodes is then cheap */
    qsort(sorted, member_list_entries, sizeof(const struct cpg_address *),
          cmp_member_list_nodeid);

    for (i = 0; i < left_list_entries; i++) {
        node_left(groupName->value, counter, local_nodeid, &left_list[i],
                  sorted, member_list_entries);
    }
    free(sorted);
    sorted = NULL;

    for (i = 0; i < joined_list_entries; i++) {
        crm_info("Group %s event %d: node %u pid %u joined%s",
                 groupName->value, counter, joined_list[i].nodeid,
                 joined_list[i].pid, cpgreason2str(joined_list[i].reason));
    }

    for (i = 0; i < member_list_entries; i++) {
        crm_node_t *peer = crm_get_peer(member_list[i].nodeid, NULL);

        if (member_list[i].nodeid == local_nodeid
                && member_list[i].pid != getpid()) {
            // See the note in node_left()
            crm_warn("Group %s event %d: detected duplicate local pid %u",
                     groupName->value, counter, member_list[i].pid);
            continue;
        }
        crm_info("Group %s event %d: %s (node %u pid %u) is member",
                 groupName->value, counter, peer_name(peer),
                 member_list[i].nodeid, member_list[i].pid);

        /* If the caller left auto-reaping enabled, this will also update the
         * state to member.
         */
        peer = crm_update_peer_proc(__func__, peer, crm_proc_cpg,
                                    ONLINESTATUS);

        if (peer && peer->state && strcmp(peer->state, CRM_NODE_MEMBER)) {
            /* The node is a CPG member, but we currently think it's not a
             * cluster member. This is possible only if auto-reaping was
             * disabled. The node may be joining, and we happened to get the CPG
             * notification before the quorum notification; or the node may have
             * just died, and we are processing its final messages; or a bug
             * has affected the peer cache.
             */
            time_t now = time(NULL);

            if (peer->when_lost == 0) {
                // Track when we first got into this contradictory state
                peer->when_lost = now;

            } else if (now > (peer->when_lost + 60)) {
                // If it persists for more than a minute, update the state
                crm_warn("Node %u is member of group %s but was believed offline",
                         member_list[i].nodeid, groupName->value);
                pcmk__update_peer_state(__func__, peer, CRM_NODE_MEMBER, 0);
            }
        }

        if (local_nodeid == member_list[i].nodeid) {
            found = TRUE;
        }
    }

    if (!found) {
        crm_err("Local node was evicted from group %s", groupName->value);
        cpg_evicted = true;
    }

    counter++;
}

/*!
 * \brief Connect to Corosync CPG
 *
 * \param[in] cluster  Cluster object
 *
 * \return TRUE on success, otherwise FALSE
 */
gboolean
cluster_connect_cpg(crm_cluster_t *cluster)
{
    cs_error_t rc;
    int fd = -1;
    int retries = 0;
    uint32_t id = 0;
    crm_node_t *peer = NULL;
    cpg_handle_t handle = 0;
    const char *message_name = pcmk__message_name(crm_system_name);
    uid_t found_uid = 0;
    gid_t found_gid = 0;
    pid_t found_pid = 0;
    int rv;

    struct mainloop_fd_callbacks cpg_fd_callbacks = {
        .dispatch = pcmk_cpg_dispatch,
        .destroy = cluster->destroy,
    };

    cpg_model_v1_data_t cpg_model_info = {
	    .model = CPG_MODEL_V1,
	    .cpg_deliver_fn = cluster->cpg.cpg_deliver_fn,
	    .cpg_confchg_fn = cluster->cpg.cpg_confchg_fn,
	    .cpg_totem_confchg_fn = NULL,
	    .flags = 0,
    };

    cpg_evicted = false;
    cluster->group.length = 0;
    cluster->group.value[0] = 0;

    /* group.value is char[128] */
    strncpy(cluster->group.value, message_name, 127);
    cluster->group.value[127] = 0;
    cluster->group.length = 1 + QB_MIN(127, strlen(cluster->group.value));

    cs_repeat(rc, retries, 30, cpg_model_initialize(&handle, CPG_MODEL_V1, (cpg_model_data_t *)&cpg_model_info, NULL));
    if (rc != CS_OK) {
        crm_err("Could not connect to the CPG API: %s (%d)",
                cs_strerror(rc), rc);
        goto bail;
    }

    rc = cpg_fd_get(handle, &fd);
    if (rc != CS_OK) {
        crm_err("Could not obtain the CPG API connection: %s (%d)",
                cs_strerror(rc), rc);
        goto bail;
    }

    /* CPG provider run as root (in given user namespace, anyway)? */
    if (!(rv = crm_ipc_is_authentic_process(fd, (uid_t) 0,(gid_t) 0, &found_pid,
                                            &found_uid, &found_gid))) {
        crm_err("CPG provider is not authentic:"
                " process %lld (uid: %lld, gid: %lld)",
                (long long) PCMK__SPECIAL_PID_AS_0(found_pid),
                (long long) found_uid, (long long) found_gid);
        rc = CS_ERR_ACCESS;
        goto bail;
    } else if (rv < 0) {
        crm_err("Could not verify authenticity of CPG provider: %s (%d)",
                strerror(-rv), -rv);
        rc = CS_ERR_ACCESS;
        goto bail;
    }

    id = get_local_nodeid(handle);
    if (id == 0) {
        crm_err("Could not get local node id from the CPG API");
        goto bail;

    }
    cluster->nodeid = id;

    retries = 0;
    cs_repeat(rc, retries, 30, cpg_join(handle, &cluster->group));
    if (rc != CS_OK) {
        crm_err("Could not join the CPG group '%s': %d", message_name, rc);
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
    crm_update_peer_proc(__func__, peer, crm_proc_cpg, ONLINESTATUS);
    return TRUE;
}

/*!
 * \internal
 * \brief Send an XML message via Corosync CPG
 *
 * \param[in] msg   XML message to send
 * \param[in] node  Cluster node to send message to
 * \param[in] dest  Type of message to send
 *
 * \return TRUE on success, otherwise FALSE
 */
gboolean
pcmk__cpg_send_xml(xmlNode *msg, crm_node_t *node, enum crm_ais_msg_types dest)
{
    gboolean rc = TRUE;
    char *data = NULL;

    data = dump_xml_unformatted(msg);
    rc = send_cluster_text(crm_class_cluster, data, FALSE, node, dest);
    free(data);
    return rc;
}

/*!
 * \internal
 * \brief Send string data via Corosync CPG
 *
 * \param[in] msg_class  Message class (to set as CPG header ID)
 * \param[in] data       Data to send
 * \param[in] local      What to set as host "local" value (which is never used)
 * \param[in] node       Cluster node to send message to
 * \param[in] dest       Type of message to send
 *
 * \return TRUE on success, otherwise FALSE
 */
gboolean
send_cluster_text(enum crm_ais_msg_class msg_class, const char *data,
                  gboolean local, crm_node_t *node, enum crm_ais_msg_types dest)
{
    static int msg_id = 0;
    static int local_pid = 0;
    static int local_name_len = 0;
    static const char *local_name = NULL;

    char *target = NULL;
    struct iovec *iov;
    pcmk__cpg_msg_t *msg = NULL;
    enum crm_ais_msg_types sender = text2msg_type(crm_system_name);

    switch (msg_class) {
        case crm_class_cluster:
            break;
        default:
            crm_err("Invalid message class: %d", msg_class);
            return FALSE;
    }

    CRM_CHECK(dest != crm_msg_ais, return FALSE);

    if (local_name == NULL) {
        local_name = get_local_node_name();
    }
    if ((local_name_len == 0) && (local_name != NULL)) {
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

    msg = calloc(1, sizeof(pcmk__cpg_msg_t));

    msg_id++;
    msg->id = msg_id;
    msg->header.id = msg_class;
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
    if ((local_name != NULL) && (msg->sender.size != 0)) {
        memcpy(msg->sender.uname, local_name, msg->sender.size);
    }

    msg->size = 1 + strlen(data);
    msg->header.size = sizeof(pcmk__cpg_msg_t) + msg->size;

    if (msg->size < CRM_BZ2_THRESHOLD) {
        msg = pcmk__realloc(msg, msg->header.size);
        memcpy(msg->data, data, msg->size);

    } else {
        char *compressed = NULL;
        unsigned int new_size = 0;
        char *uncompressed = strdup(data);

        if (pcmk__compress(uncompressed, (unsigned int) msg->size, 0,
                           &compressed, &new_size) == pcmk_rc_ok) {

            msg->header.size = sizeof(pcmk__cpg_msg_t) + new_size;
            msg = pcmk__realloc(msg, msg->header.size);
            memcpy(msg->data, compressed, new_size);

            msg->is_compressed = TRUE;
            msg->compressed_size = new_size;

        } else {
            // cppcheck seems not to understand the abort logic in pcmk__realloc
            // cppcheck-suppress memleak
            msg = pcmk__realloc(msg, msg->header.size);
            memcpy(msg->data, data, msg->size);
        }

        free(uncompressed);
        free(compressed);
    }

    iov = calloc(1, sizeof(struct iovec));
    iov->iov_base = msg;
    iov->iov_len = msg->header.size;

    if (msg->compressed_size) {
        crm_trace("Queueing CPG message %u to %s (%llu bytes, %d bytes compressed payload): %.200s",
                  msg->id, target, (unsigned long long) iov->iov_len,
                  msg->compressed_size, data);
    } else {
        crm_trace("Queueing CPG message %u to %s (%llu bytes, %d bytes payload): %.200s",
                  msg->id, target, (unsigned long long) iov->iov_len,
                  msg->size, data);
    }
    free(target);

    cs_message_queue = g_list_append(cs_message_queue, iov);
    crm_cs_flush(&pcmk_cpg_handle);

    return TRUE;
}

/*!
 * \brief Get the message type equivalent of a string
 *
 * \param[in] text  String of message type
 *
 * \return Message type equivalent of \p text
 */
enum crm_ais_msg_types
text2msg_type(const char *text)
{
    int type = crm_msg_none;

    CRM_CHECK(text != NULL, return type);
    text = pcmk__message_name(text);
    if (pcmk__str_eq(text, "ais", pcmk__str_casei)) {
        type = crm_msg_ais;
    } else if (pcmk__str_eq(text, CRM_SYSTEM_CIB, pcmk__str_casei)) {
        type = crm_msg_cib;
    } else if (pcmk__strcase_any_of(text, CRM_SYSTEM_CRMD, CRM_SYSTEM_DC, NULL)) {
        type = crm_msg_crmd;
    } else if (pcmk__str_eq(text, CRM_SYSTEM_TENGINE, pcmk__str_casei)) {
        type = crm_msg_te;
    } else if (pcmk__str_eq(text, CRM_SYSTEM_PENGINE, pcmk__str_casei)) {
        type = crm_msg_pe;
    } else if (pcmk__str_eq(text, CRM_SYSTEM_LRMD, pcmk__str_casei)) {
        type = crm_msg_lrmd;
    } else if (pcmk__str_eq(text, CRM_SYSTEM_STONITHD, pcmk__str_casei)) {
        type = crm_msg_stonithd;
    } else if (pcmk__str_eq(text, "stonith-ng", pcmk__str_casei)) {
        type = crm_msg_stonith_ng;
    } else if (pcmk__str_eq(text, "attrd", pcmk__str_casei)) {
        type = crm_msg_attrd;

    } else {
        /* This will normally be a transient client rather than
         * a cluster daemon.  Set the type to the pid of the client
         */
        int scan_rc = sscanf(text, "%d", &type);

        if (scan_rc != 1 || type <= crm_msg_stonith_ng) {
            /* Ensure it's sane */
            type = crm_msg_none;
        }
    }
    return type;
}

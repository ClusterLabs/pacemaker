/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <arpa/inet.h>
#include <inttypes.h>                   // PRIu32
#include <netdb.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>                     // uint32_t
#include <sys/socket.h>
#include <sys/types.h>                  // size_t
#include <sys/utsname.h>

#include <bzlib.h>
#include <corosync/corodefs.h>
#include <corosync/corotypes.h>
#include <corosync/hdb.h>
#include <corosync/cpg.h>
#include <qb/qbipc_common.h>
#include <qb/qbipcc.h>
#include <qb/qbutil.h>

#include <crm/cluster/internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>    // PCMK__SPECIAL_PID
#include <crm/common/mainloop.h>
#include <crm/common/xml.h>

#include "crmcluster_private.h"

/* @TODO Once we can update the public API to require pcmk_cluster_t* in more
 *       functions, we can ditch this in favor of cluster->cpg_handle.
 */
static cpg_handle_t pcmk_cpg_handle = 0;

// @TODO These could be moved to pcmk_cluster_t* at that time as well
static bool cpg_evicted = false;
static GList *cs_message_queue = NULL;
static int cs_message_timer = 0;

/* @COMPAT Any changes to these structs (other than renames) will break all
 * rolling upgrades, and should be avoided if possible or done at a major
 * version bump if not
 */

struct pcmk__cpg_host_s {
    uint32_t id;
    uint32_t pid;
    gboolean local;             // Unused but needed for compatibility
    enum pcmk_ipc_server type;  // For logging only
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
 * \internal
 * \brief Get the local Corosync node ID (via CPG)
 *
 * \param[in] handle  CPG connection to use (or 0 to use new connection)
 *
 * \return Corosync ID of local node (or 0 if not known)
 */
uint32_t
pcmk__cpg_local_nodeid(cpg_handle_t handle)
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
    int rv = 0;

    if (local_nodeid != 0) {
        return local_nodeid;
    }

    if (handle == 0) {
        crm_trace("Creating connection");
        cs_repeat(rc, retries, 5,
                  cpg_model_initialize(&local_handle, CPG_MODEL_V1,
                                       (cpg_model_data_t *) &cpg_model_info,
                                       NULL));
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

        // CPG provider run as root (at least in given user namespace)?
        rv = crm_ipc_is_authentic_process(fd, (uid_t) 0, (gid_t) 0, &found_pid,
                                          &found_uid, &found_gid);
        if (rv == 0) {
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
    if (handle == 0) {
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
        crm_trace("CPG message sent, size=%zu", iov->iov_len);

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
        cs_message_timer = pcmk__create_timer(delay_ms, crm_cs_flush_cb, data);
    }
}

/*!
 * \internal
 * \brief Dispatch function for CPG handle
 *
 * \param[in,out] user_data  Cluster object
 *
 * \return 0 on success, -1 on error (per mainloop_io_t interface)
 */
static int
pcmk_cpg_dispatch(gpointer user_data)
{
    cs_error_t rc = CS_OK;
    pcmk_cluster_t *cluster = (pcmk_cluster_t *) user_data;

    rc = cpg_dispatch(cluster->priv->cpg_handle, CS_DISPATCH_ONE);
    if (rc != CS_OK) {
        crm_err("Connection to the CPG API failed: %s (%d)",
                pcmk__cs_err_str(rc), rc);
        cpg_finalize(cluster->priv->cpg_handle);
        cluster->priv->cpg_handle = 0;
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
    return (host->size > 0)? host->uname : "<all>";
}

static inline const char *
msg_type2text(enum pcmk_ipc_server type)
{
    const char *name = pcmk__server_message_type(type);

    return pcmk__s(name, "unknown");
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
                QB_XS " from %s[%u] to %s@%s",
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
                QB_XS " from %s[%u] to %s@%s",
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
                QB_XS " from %s[%u] to %s@%s",
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
                "Payload does not end at byte %" PRIu32 " "
                QB_XS " from %s[%u] to %s@%s",
                msg->id, ais_dest(&(msg->sender)), msg->size,
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
 * \internal
 * \brief Extract text data from a Corosync CPG message
 *
 * \param[in]     handle     CPG connection (to get local node ID if not known)
 * \param[in]     sender_id  Corosync ID of node that sent message
 * \param[in]     pid        Process ID of message sender (for logging only)
 * \param[in,out] content    CPG message
 * \param[out]    from       If not \c NULL, will be set to sender uname
 *                           (valid for the lifetime of \p content)
 *
 * \return Newly allocated string with message data, or NULL for errors and
 *         messages not intended for the local node
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
char *
pcmk__cpg_message_data(cpg_handle_t handle, uint32_t sender_id, uint32_t pid,
                       void *content, const char **from)
{
    char *data = NULL;
    pcmk__cpg_msg_t *msg = content;

    if (from != NULL) {
        *from = NULL;
    }

    if (handle != 0) {
        uint32_t local_nodeid = pcmk__cpg_local_nodeid(handle);
        const char *local_name = pcmk__cluster_local_node_name();

        // Update or validate message sender ID
        if (msg->sender.id == 0) {
            msg->sender.id = sender_id;
        } else if (msg->sender.id != sender_id) {
            crm_warn("Ignoring CPG message from ID %" PRIu32 " PID %" PRIu32
                     ": claimed ID %" PRIu32,
                    sender_id, pid, msg->sender.id);
            return NULL;
        }

        // Ignore messages that aren't for the local node
        if ((msg->host.id != 0) && (local_nodeid != msg->host.id)) {
            crm_trace("Ignoring CPG message from ID %" PRIu32 " PID %" PRIu32
                      ": for ID %" PRIu32 " not %" PRIu32,
                      sender_id, pid, msg->host.id, local_nodeid);
            return NULL;
        }
        if ((msg->host.size > 0)
            && !pcmk__str_eq(msg->host.uname, local_name, pcmk__str_casei)) {

            crm_trace("Ignoring CPG message from ID %" PRIu32 " PID %" PRIu32
                      ": for name %s not %s",
                      sender_id, pid, msg->host.uname, local_name);
            return NULL;
        }

        // Add sender name if not in original message
        if (msg->sender.size == 0) {
            const pcmk__node_status_t *peer =
                pcmk__get_node(sender_id, NULL, NULL,
                               pcmk__node_search_cluster_member);

            if (peer->name == NULL) {
                crm_debug("Received CPG message from node with ID %" PRIu32
                          " but its name is unknown", sender_id);
            } else {
                crm_debug("Updating name of CPG message sender with ID %" PRIu32
                          " to %s", sender_id, peer->name);
                msg->sender.size = strlen(peer->name);
                memset(msg->sender.uname, 0, MAX_NAME);
                memcpy(msg->sender.uname, peer->name, msg->sender.size);
            }
        }
    }

    // Ensure sender is in peer cache (though it should already be)
    pcmk__get_node(msg->sender.id, msg->sender.uname, NULL,
                   pcmk__node_search_cluster_member);

    if (from != NULL) {
        *from = msg->sender.uname;
    }

    if (!check_message_sanity(msg)) {
        return NULL;
    }

    if (msg->is_compressed && (msg->size > 0)) {
        int rc = BZ_OK;
        unsigned int new_size = msg->size + 1;
        char *uncompressed = pcmk__assert_alloc(1, new_size);

        rc = BZ2_bzBuffToBuffDecompress(uncompressed, &new_size, msg->data,
                                        msg->compressed_size, 1, 0);
        rc = pcmk__bzlib2rc(rc);
        if ((rc == pcmk_rc_ok) && (msg->size != new_size)) { // libbz2 bug?
            rc = pcmk_rc_compression;
        }
        if (rc != pcmk_rc_ok) {
            free(uncompressed);
            crm_warn("Ignoring compressed CPG message %d from %s (ID %" PRIu32
                    " PID %" PRIu32 "): %s",
                     msg->id, ais_dest(&(msg->sender)), sender_id, pid,
                     pcmk_rc_str(rc));
            return NULL;
        }
        data = uncompressed;

    } else {
        data = pcmk__str_copy(msg->data);
    }

    crm_trace("Received %sCPG message %d from %s (ID %" PRIu32
              " PID %" PRIu32 "): %.40s...",
              (msg->is_compressed? "compressed " : ""),
              msg->id, ais_dest(&(msg->sender)), sender_id, pid, msg->data);
    return data;
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
peer_name(const pcmk__node_status_t *peer)
{
    return (peer != NULL)? pcmk__s(peer->name, "peer node") : "unknown node";
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
    pcmk__node_status_t *peer =
        pcmk__search_node_caches(cpg_peer->nodeid, NULL, NULL,
                                 pcmk__node_search_cluster_member);
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
                                 PCMK_VALUE_OFFLINE);
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
 * \internal
 * \brief Handle a CPG configuration change event
 *
 * \param[in] handle               CPG connection
 * \param[in] group_name           CPG group name
 * \param[in] member_list          List of current CPG members
 * \param[in] member_list_entries  Number of entries in \p member_list
 * \param[in] left_list            List of CPG members that left
 * \param[in] left_list_entries    Number of entries in \p left_list
 * \param[in] joined_list          List of CPG members that joined
 * \param[in] joined_list_entries  Number of entries in \p joined_list
 *
 * \note This is of type \c cpg_confchg_fn_t, intended to be used in a
 *       \c cpg_callbacks_t object.
 */
void
pcmk__cpg_confchg_cb(cpg_handle_t handle,
                     const struct cpg_name *group_name,
                     const struct cpg_address *member_list,
                     size_t member_list_entries,
                     const struct cpg_address *left_list,
                     size_t left_list_entries,
                     const struct cpg_address *joined_list,
                     size_t joined_list_entries)
{
    static int counter = 0;

    bool found = false;
    uint32_t local_nodeid = pcmk__cpg_local_nodeid(handle);
    const struct cpg_address **sorted = NULL;

    sorted = pcmk__assert_alloc(member_list_entries,
                                sizeof(const struct cpg_address *));

    for (size_t iter = 0; iter < member_list_entries; iter++) {
        sorted[iter] = member_list + iter;
    }

    // So that the cross-matching of multiply-subscribed nodes is then cheap
    qsort(sorted, member_list_entries, sizeof(const struct cpg_address *),
          cmp_member_list_nodeid);

    for (int i = 0; i < left_list_entries; i++) {
        node_left(group_name->value, counter, local_nodeid, &left_list[i],
                  sorted, member_list_entries);
    }
    free(sorted);
    sorted = NULL;

    for (int i = 0; i < joined_list_entries; i++) {
        crm_info("Group %s event %d: node %u pid %u joined%s",
                 group_name->value, counter, joined_list[i].nodeid,
                 joined_list[i].pid, cpgreason2str(joined_list[i].reason));
    }

    for (int i = 0; i < member_list_entries; i++) {
        pcmk__node_status_t *peer =
            pcmk__get_node(member_list[i].nodeid, NULL, NULL,
                           pcmk__node_search_cluster_member);

        if (member_list[i].nodeid == local_nodeid
                && member_list[i].pid != getpid()) {
            // See the note in node_left()
            crm_warn("Group %s event %d: detected duplicate local pid %u",
                     group_name->value, counter, member_list[i].pid);
            continue;
        }
        crm_info("Group %s event %d: %s (node %u pid %u) is member",
                 group_name->value, counter, peer_name(peer),
                 member_list[i].nodeid, member_list[i].pid);

        /* If the caller left auto-reaping enabled, this will also update the
         * state to member.
         */
        peer = crm_update_peer_proc(__func__, peer, crm_proc_cpg,
                                    PCMK_VALUE_ONLINE);

        if (peer && peer->state && strcmp(peer->state, PCMK_VALUE_MEMBER)) {
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
                crm_warn("Node %u is member of group %s but was believed "
                         "offline",
                         member_list[i].nodeid, group_name->value);
                pcmk__update_peer_state(__func__, peer, PCMK_VALUE_MEMBER, 0);
            }
        }

        if (local_nodeid == member_list[i].nodeid) {
            found = true;
        }
    }

    if (!found) {
        crm_err("Local node was evicted from group %s", group_name->value);
        cpg_evicted = true;
    }

    counter++;
}

/*!
 * \brief Set the CPG deliver callback function for a cluster object
 *
 * \param[in,out] cluster  Cluster object
 * \param[in]     fn       Deliver callback function to set
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_cpg_set_deliver_fn(pcmk_cluster_t *cluster, cpg_deliver_fn_t fn)
{
    if (cluster == NULL) {
        return EINVAL;
    }
    cluster->cpg.cpg_deliver_fn = fn;
    return pcmk_rc_ok;
}

/*!
 * \brief Set the CPG config change callback function for a cluster object
 *
 * \param[in,out] cluster  Cluster object
 * \param[in]     fn       Configuration change callback function to set
 *
 * \return Standard Pacemaker return code
 */
int
pcmk_cpg_set_confchg_fn(pcmk_cluster_t *cluster, cpg_confchg_fn_t fn)
{
    if (cluster == NULL) {
        return EINVAL;
    }
    cluster->cpg.cpg_confchg_fn = fn;
    return pcmk_rc_ok;
}

/*!
 * \brief Connect to Corosync CPG
 *
 * \param[in,out] cluster  Initialized cluster object to connect
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__cpg_connect(pcmk_cluster_t *cluster)
{
    cs_error_t rc;
    int fd = -1;
    int retries = 0;
    uint32_t id = 0;
    pcmk__node_status_t *peer = NULL;
    cpg_handle_t handle = 0;
    const char *cpg_group_name = NULL;
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

    if (cluster->priv->server != pcmk_ipc_unknown) {
        cpg_group_name = pcmk__server_message_type(cluster->priv->server);
    }

    if (cpg_group_name == NULL) {
        /* The name will already be non-NULL for Pacemaker servers. If a
         * command-line tool or external caller connects to the cluster,
         * they will join this CPG group.
         */
        cpg_group_name = pcmk__s(crm_system_name, "unknown");
    }
    memset(cluster->priv->group.value, 0, 128);
    strncpy(cluster->priv->group.value, cpg_group_name, 127);
    cluster->priv->group.length = strlen(cluster->priv->group.value) + 1;

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

    id = pcmk__cpg_local_nodeid(handle);
    if (id == 0) {
        crm_err("Could not get local node id from the CPG API");
        goto bail;

    }
    cluster->priv->node_id = id;

    retries = 0;
    cs_repeat(rc, retries, 30, cpg_join(handle, &cluster->priv->group));
    if (rc != CS_OK) {
        crm_err("Could not join the CPG group '%s': %d", cpg_group_name, rc);
        goto bail;
    }

    pcmk_cpg_handle = handle;
    cluster->priv->cpg_handle = handle;
    mainloop_add_fd("corosync-cpg", G_PRIORITY_MEDIUM, fd, cluster, &cpg_fd_callbacks);

  bail:
    if (rc != CS_OK) {
        cpg_finalize(handle);
        // @TODO Map rc to more specific Pacemaker return code
        return ENOTCONN;
    }

    peer = pcmk__get_node(id, NULL, NULL, pcmk__node_search_cluster_member);
    crm_update_peer_proc(__func__, peer, crm_proc_cpg, PCMK_VALUE_ONLINE);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Disconnect from Corosync CPG
 *
 * \param[in,out] cluster  Cluster object to disconnect
 */
void
pcmk__cpg_disconnect(pcmk_cluster_t *cluster)
{
    pcmk_cpg_handle = 0;
    if (cluster->priv->cpg_handle != 0) {
        crm_trace("Disconnecting CPG");
        cpg_leave(cluster->priv->cpg_handle, &cluster->priv->group);
        cpg_finalize(cluster->priv->cpg_handle);
        cluster->priv->cpg_handle = 0;

    } else {
        crm_info("No CPG connection");
    }
}

/*!
 * \internal
 * \brief Send string data via Corosync CPG
 *
 * \param[in] data   Data to send
 * \param[in] node   Cluster node to send message to
 * \param[in] dest   Type of message to send
 *
 * \return \c true on success, or \c false otherwise
 */
static bool
send_cpg_text(const char *data, const pcmk__node_status_t *node,
              enum pcmk_ipc_server dest)
{
    static int msg_id = 0;
    static int local_pid = 0;
    static int local_name_len = 0;
    static const char *local_name = NULL;

    char *target = NULL;
    struct iovec *iov;
    pcmk__cpg_msg_t *msg = NULL;

    if (local_name == NULL) {
        local_name = pcmk__cluster_local_node_name();
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

    msg = pcmk__assert_alloc(1, sizeof(pcmk__cpg_msg_t));

    msg_id++;
    msg->id = msg_id;
    msg->header.error = CS_OK;

    msg->host.type = dest;

    if (node != NULL) {
        if (node->name != NULL) {
            target = pcmk__str_copy(node->name);
            msg->host.size = strlen(node->name);
            memset(msg->host.uname, 0, MAX_NAME);
            memcpy(msg->host.uname, node->name, msg->host.size);

        } else {
            target = crm_strdup_printf("%" PRIu32, node->cluster_layer_id);
        }
        msg->host.id = node->cluster_layer_id;

    } else {
        target = pcmk__str_copy("all");
    }

    msg->sender.id = 0;
    msg->sender.type = pcmk__parse_server(crm_system_name);
    msg->sender.pid = local_pid;
    msg->sender.size = local_name_len;
    memset(msg->sender.uname, 0, MAX_NAME);

    if ((local_name != NULL) && (msg->sender.size != 0)) {
        memcpy(msg->sender.uname, local_name, msg->sender.size);
    }

    msg->size = 1 + strlen(data);
    msg->header.size = sizeof(pcmk__cpg_msg_t) + msg->size;

    if (msg->size < PCMK__BZ2_THRESHOLD) {
        msg = pcmk__realloc(msg, msg->header.size);
        memcpy(msg->data, data, msg->size);

    } else {
        char *compressed = NULL;
        unsigned int new_size = 0;

        if (pcmk__compress(data, (unsigned int) msg->size, 0, &compressed,
                           &new_size) == pcmk_rc_ok) {

            msg->header.size = sizeof(pcmk__cpg_msg_t) + new_size;
            msg = pcmk__realloc(msg, msg->header.size);
            memcpy(msg->data, compressed, new_size);

            msg->is_compressed = TRUE;
            msg->compressed_size = new_size;

        } else {
            msg = pcmk__realloc(msg, msg->header.size);
            memcpy(msg->data, data, msg->size);
        }

        free(compressed);
    }

    iov = pcmk__assert_alloc(1, sizeof(struct iovec));
    iov->iov_base = msg;
    iov->iov_len = msg->header.size;

    if (msg->compressed_size > 0) {
        crm_trace("Queueing CPG message %" PRIu32 " to %s "
                  "(%zu bytes, %" PRIu32 " bytes compressed payload): %.200s",
                  msg->id, target, iov->iov_len, msg->compressed_size, data);
    } else {
        crm_trace("Queueing CPG message %" PRIu32 " to %s "
                  "(%zu bytes, %" PRIu32 " bytes payload): %.200s",
                  msg->id, target, iov->iov_len, msg->size, data);
    }

    free(target);

    cs_message_queue = g_list_append(cs_message_queue, iov);
    crm_cs_flush(&pcmk_cpg_handle);

    return true;
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
bool
pcmk__cpg_send_xml(const xmlNode *msg, const pcmk__node_status_t *node,
                   enum pcmk_ipc_server dest)
{
    bool rc = true;
    GString *data = g_string_sized_new(1024);

    pcmk__xml_string(msg, 0, data, 0);

    rc = send_cpg_text(data->str, node, dest);
    g_string_free(data, TRUE);
    return rc;
}

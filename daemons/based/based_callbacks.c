/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <stdint.h>     // uint32_t, uint64_t, UINT64_C()
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>   // PRIu64

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/cluster/internal.h>

#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>

#include <pacemaker-based.h>

#define EXIT_ESCALATION_MS 10000
#define OUR_NODENAME (stand_alone? "localhost" : crm_cluster->uname)

static unsigned long cib_local_bcast_num = 0;

typedef struct cib_local_notify_s {
    xmlNode *notify_src;
    char *client_id;
    gboolean from_peer;
    gboolean sync_reply;
} cib_local_notify_t;

struct digest_data {
    char *nodes;
    char *alerts;
    char *status;
};

int next_client_id = 0;

gboolean legacy_mode = FALSE;

qb_ipcs_service_t *ipcs_ro = NULL;
qb_ipcs_service_t *ipcs_rw = NULL;
qb_ipcs_service_t *ipcs_shm = NULL;

static void cib_process_request(xmlNode *request, gboolean privileged,
                                const pcmk__client_t *cib_client);

static int cib_process_command(xmlNode *request, xmlNode **reply,
                               xmlNode **cib_diff, gboolean privileged);

static gboolean cib_common_callback(qb_ipcs_connection_t *c, void *data,
                                    size_t size, gboolean privileged);

gboolean
cib_legacy_mode(void)
{
    return legacy_mode;
}

/*!
 * \internal
 * \brief Free a <tt>struct digest_data</tt> object's members
 *
 * \param[in,out] digests  Object whose members to free
 *
 * \note This does not free the object itself, which may be stack-allocated.
 */
static void
free_digests(struct digest_data *digests)
{
    if (digests != NULL) {
        free(digests->nodes);
        free(digests->alerts);
        free(digests->status);
    }
}

static int32_t
cib_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    if (cib_shutdown_flag) {
        crm_info("Ignoring new IPC client [%d] during shutdown",
                 pcmk__client_pid(c));
        return -EPERM;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static int32_t
cib_ipc_dispatch_rw(qb_ipcs_connection_t * c, void *data, size_t size)
{
    pcmk__client_t *client = pcmk__find_client(c);

    crm_trace("%p message from %s", c, client->id);
    return cib_common_callback(c, data, size, TRUE);
}

static int32_t
cib_ipc_dispatch_ro(qb_ipcs_connection_t * c, void *data, size_t size)
{
    pcmk__client_t *client = pcmk__find_client(c);

    crm_trace("%p message from %s", c, client->id);
    return cib_common_callback(c, data, size, FALSE);
}

/* Error code means? */
static int32_t
cib_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }
    crm_trace("Connection %p", c);
    pcmk__free_client(client);
    return 0;
}

static void
cib_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
    cib_ipc_closed(c);
    if (cib_shutdown_flag) {
        cib_shutdown(0);
    }
}

struct qb_ipcs_service_handlers ipc_ro_callbacks = {
    .connection_accept = cib_ipc_accept,
    .connection_created = NULL,
    .msg_process = cib_ipc_dispatch_ro,
    .connection_closed = cib_ipc_closed,
    .connection_destroyed = cib_ipc_destroy
};

struct qb_ipcs_service_handlers ipc_rw_callbacks = {
    .connection_accept = cib_ipc_accept,
    .connection_created = NULL,
    .msg_process = cib_ipc_dispatch_rw,
    .connection_closed = cib_ipc_closed,
    .connection_destroyed = cib_ipc_destroy
};

/*!
 * \internal
 * \brief Create reply XML for a CIB request
 *
 * \param[in] op            CIB operation type
 * \param[in] call_id       CIB call ID
 * \param[in] client_id     CIB client ID
 * \param[in] call_options  Group of <tt>enum cib_call_options</tt> flags
 * \param[in] rc            Request return code
 * \param[in] call_data     Request output data
 *
 * \return Reply XML
 *
 * \note The caller is responsible for freeing the return value using
 *       \p free_xml().
 */
static xmlNode *
create_cib_reply(const char *op, const char *call_id, const char *client_id,
                 int call_options, int rc, xmlNode *call_data)
{
    xmlNode *reply = create_xml_node(NULL, "cib-reply");

    CRM_ASSERT(reply != NULL);

    crm_xml_add(reply, F_TYPE, T_CIB);
    crm_xml_add(reply, F_CIB_OPERATION, op);
    crm_xml_add(reply, F_CIB_CALLID, call_id);
    crm_xml_add(reply, F_CIB_CLIENTID, client_id);
    crm_xml_add_int(reply, F_CIB_CALLOPTS, call_options);
    crm_xml_add_int(reply, F_CIB_RC, rc);

    if (call_data != NULL) {
        crm_trace("Attaching reply output");
        add_message_xml(reply, F_CIB_CALLDATA, call_data);
    }

    crm_log_xml_explicit(reply, "cib:reply");
    return reply;
}

void
cib_common_callback_worker(uint32_t id, uint32_t flags, xmlNode * op_request,
                           pcmk__client_t *cib_client, gboolean privileged)
{
    const char *op = crm_element_value(op_request, F_CIB_OPERATION);

    if (pcmk__str_eq(op, CRM_OP_REGISTER, pcmk__str_none)) {
        if (flags & crm_ipc_client_response) {
            xmlNode *ack = create_xml_node(NULL, __func__);

            crm_xml_add(ack, F_CIB_OPERATION, CRM_OP_REGISTER);
            crm_xml_add(ack, F_CIB_CLIENTID, cib_client->id);
            pcmk__ipc_send_xml(cib_client, id, ack, flags);
            cib_client->request_id = 0;
            free_xml(ack);
        }
        return;

    } else if (pcmk__str_eq(op, T_CIB_NOTIFY, pcmk__str_none)) {
        /* Update the notify filters for this client */
        int on_off = 0;
        crm_exit_t status = CRM_EX_OK;
        uint64_t bit = UINT64_C(0);
        const char *type = crm_element_value(op_request, F_CIB_NOTIFY_TYPE);

        crm_element_value_int(op_request, F_CIB_NOTIFY_ACTIVATE, &on_off);

        crm_debug("Setting %s callbacks %s for client %s",
                  type, (on_off? "on" : "off"), pcmk__client_name(cib_client));

        if (pcmk__str_eq(type, T_CIB_POST_NOTIFY, pcmk__str_casei)) {
            bit = cib_notify_post;

        } else if (pcmk__str_eq(type, T_CIB_PRE_NOTIFY, pcmk__str_casei)) {
            bit = cib_notify_pre;

        } else if (pcmk__str_eq(type, T_CIB_UPDATE_CONFIRM, pcmk__str_casei)) {
            bit = cib_notify_confirm;

        } else if (pcmk__str_eq(type, T_CIB_DIFF_NOTIFY, pcmk__str_casei)) {
            bit = cib_notify_diff;

        } else if (pcmk__str_eq(type, T_CIB_REPLACE_NOTIFY, pcmk__str_casei)) {
            bit = cib_notify_replace;

        } else {
            status = CRM_EX_INVALID_PARAM;
        }

        if (bit != 0) {
            if (on_off) {
                pcmk__set_client_flags(cib_client, bit);
            } else {
                pcmk__clear_client_flags(cib_client, bit);
            }
        }

        pcmk__ipc_send_ack(cib_client, id, flags, "ack", NULL, status);
        return;
    }

    cib_process_request(op_request, privileged, cib_client);
}

int32_t
cib_common_callback(qb_ipcs_connection_t * c, void *data, size_t size, gboolean privileged)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    int call_options = 0;
    pcmk__client_t *cib_client = pcmk__find_client(c);
    xmlNode *op_request = pcmk__client_data2xml(cib_client, data, &id, &flags);

    if (op_request) {
        crm_element_value_int(op_request, F_CIB_CALLOPTS, &call_options);
    }

    if (op_request == NULL) {
        crm_trace("Invalid message from %p", c);
        pcmk__ipc_send_ack(cib_client, id, flags, "nack", NULL, CRM_EX_PROTOCOL);
        return 0;

    } else if(cib_client == NULL) {
        crm_trace("Invalid client %p", c);
        return 0;
    }

    if (pcmk_is_set(call_options, cib_sync_call)) {
        CRM_LOG_ASSERT(flags & crm_ipc_client_response);
        CRM_LOG_ASSERT(cib_client->request_id == 0);    /* This means the client has two synchronous events in-flight */
        cib_client->request_id = id;    /* Reply only to the last one */
    }

    if (cib_client->name == NULL) {
        const char *value = crm_element_value(op_request, F_CIB_CLIENTNAME);

        if (value == NULL) {
            cib_client->name = pcmk__itoa(cib_client->pid);
        } else {
            cib_client->name = strdup(value);
            if (crm_is_daemon_name(value)) {
                pcmk__set_client_flags(cib_client, cib_is_daemon);
            }
        }
    }

    /* Allow cluster daemons more leeway before being evicted */
    if (pcmk_is_set(cib_client->flags, cib_is_daemon)) {
        const char *qmax = cib_config_lookup("cluster-ipc-limit");

        if (pcmk__set_client_queue_max(cib_client, qmax)) {
            crm_trace("IPC threshold for client %s[%u] is now %u",
                      pcmk__client_name(cib_client), cib_client->pid,
                      cib_client->queue_max);
        }
    }

    crm_xml_add(op_request, F_CIB_CLIENTID, cib_client->id);
    crm_xml_add(op_request, F_CIB_CLIENTNAME, cib_client->name);

    CRM_LOG_ASSERT(cib_client->user != NULL);
    pcmk__update_acl_user(op_request, F_CIB_USER, cib_client->user);

    cib_common_callback_worker(id, flags, op_request, cib_client, privileged);
    free_xml(op_request);

    return 0;
}

static uint64_t ping_seq = 0;
static char *ping_digest = NULL;
static bool ping_modified_since = FALSE;

static gboolean
cib_digester_cb(gpointer data)
{
    if (based_is_primary) {
        char buffer[32];
        xmlNode *ping = create_xml_node(NULL, "ping");

        ping_seq++;
        free(ping_digest);
        ping_digest = NULL;
        ping_modified_since = FALSE;
        snprintf(buffer, 32, "%" PRIu64, ping_seq);
        crm_trace("Requesting peer digests (%s)", buffer);

        crm_xml_add(ping, F_TYPE, "cib");
        crm_xml_add(ping, F_CIB_OPERATION, CRM_OP_PING);
        crm_xml_add(ping, F_CIB_PING_ID, buffer);

        crm_xml_add(ping, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
        send_cluster_message(NULL, crm_msg_cib, ping, TRUE);

        free_xml(ping);
    }
    return FALSE;
}

static void
process_ping_reply(xmlNode *reply) 
{
    uint64_t seq = 0;
    const char *host = crm_element_value(reply, F_ORIG);

    xmlNode *pong = get_message_xml(reply, F_CIB_CALLDATA);
    const char *seq_s = crm_element_value(pong, F_CIB_PING_ID);
    const char *digest = crm_element_value(pong, XML_ATTR_DIGEST);

    if (seq_s == NULL) {
        crm_debug("Ignoring ping reply with no " F_CIB_PING_ID);
        return;

    } else {
        long long seq_ll;

        if (pcmk__scan_ll(seq_s, &seq_ll, 0LL) != pcmk_rc_ok) {
            return;
        }
        seq = (uint64_t) seq_ll;
    }

    if(digest == NULL) {
        crm_trace("Ignoring ping reply %s from %s with no digest", seq_s, host);

    } else if(seq != ping_seq) {
        crm_trace("Ignoring out of sequence ping reply %s from %s", seq_s, host);

    } else if(ping_modified_since) {
        crm_trace("Ignoring ping reply %s from %s: cib updated since", seq_s, host);

    } else {
        const char *version = crm_element_value(pong, XML_ATTR_CRM_VERSION);

        if(ping_digest == NULL) {
            crm_trace("Calculating new digest");
            ping_digest = calculate_xml_versioned_digest(the_cib, FALSE, TRUE, version);
        }

        crm_trace("Processing ping reply %s from %s (%s)", seq_s, host, digest);
        if (!pcmk__str_eq(ping_digest, digest, pcmk__str_casei)) {
            xmlNode *remote_cib = get_message_xml(pong, F_CIB_CALLDATA);

            crm_notice("Local CIB %s.%s.%s.%s differs from %s: %s.%s.%s.%s %p",
                       crm_element_value(the_cib, XML_ATTR_GENERATION_ADMIN),
                       crm_element_value(the_cib, XML_ATTR_GENERATION),
                       crm_element_value(the_cib, XML_ATTR_NUMUPDATES),
                       ping_digest, host,
                       remote_cib?crm_element_value(remote_cib, XML_ATTR_GENERATION_ADMIN):"_",
                       remote_cib?crm_element_value(remote_cib, XML_ATTR_GENERATION):"_",
                       remote_cib?crm_element_value(remote_cib, XML_ATTR_NUMUPDATES):"_",
                       digest, remote_cib);

            if(remote_cib && remote_cib->children) {
                // Additional debug
                xml_calculate_changes(the_cib, remote_cib);

                pcmk__output_set_log_level(logger_out, LOG_INFO);
                pcmk__xml_show_changes(logger_out, remote_cib);
                crm_trace("End of differences");
            }

            free_xml(remote_cib);
            sync_our_cib(reply, FALSE);
        }
    }
}

static void
do_local_notify(xmlNode * notify_src, const char *client_id,
                gboolean sync_reply, gboolean from_peer)
{
    int rid = 0;
    int call_id = 0;
    pcmk__client_t *client_obj = NULL;

    CRM_ASSERT(notify_src && client_id);

    crm_element_value_int(notify_src, F_CIB_CALLID, &call_id);

    client_obj = pcmk__find_client_by_id(client_id);
    if (client_obj == NULL) {
        crm_debug("Could not send response %d: client %s not found",
                  call_id, client_id);
        return;
    }

    if (sync_reply) {
        if (client_obj->ipcs) {
            CRM_LOG_ASSERT(client_obj->request_id);

            rid = client_obj->request_id;
            client_obj->request_id = 0;

            crm_trace("Sending response %d to client %s%s",
                      rid, pcmk__client_name(client_obj),
                      (from_peer? " (originator of delegated request)" : ""));
        } else {
            crm_trace("Sending response (call %d) to client %s%s",
                      call_id, pcmk__client_name(client_obj),
                      (from_peer? " (originator of delegated request)" : ""));
        }

    } else {
        crm_trace("Sending event %d to client %s%s",
                  call_id, pcmk__client_name(client_obj),
                  (from_peer? " (originator of delegated request)" : ""));
    }

    switch (PCMK__CLIENT_TYPE(client_obj)) {
        case pcmk__client_ipc:
            {
                int rc = pcmk__ipc_send_xml(client_obj, rid, notify_src,
                                            (sync_reply? crm_ipc_flags_none
                                             : crm_ipc_server_event));

                if (rc != pcmk_rc_ok) {
                    crm_warn("%s reply to client %s failed: %s " CRM_XS " rc=%d",
                             (sync_reply? "Synchronous" : "Asynchronous"),
                             pcmk__client_name(client_obj), pcmk_rc_str(rc),
                             rc);
                }
            }
            break;
#ifdef HAVE_GNUTLS_GNUTLS_H
        case pcmk__client_tls:
#endif
        case pcmk__client_tcp:
            pcmk__remote_send_xml(client_obj->remote, notify_src);
            break;
        default:
            crm_err("Unknown transport for client %s "
                    CRM_XS " flags=%#016" PRIx64,
                    pcmk__client_name(client_obj), client_obj->flags);
    }
}

static void
local_notify_destroy_callback(gpointer data)
{
    cib_local_notify_t *notify = data;

    free_xml(notify->notify_src);
    free(notify->client_id);
    free(notify);
}

static void
check_local_notify(int bcast_id)
{
    cib_local_notify_t *notify = NULL;

    if (!local_notify_queue) {
        return;
    }

    notify = pcmk__intkey_table_lookup(local_notify_queue, bcast_id);

    if (notify) {
        do_local_notify(notify->notify_src, notify->client_id, notify->sync_reply,
                        notify->from_peer);
        pcmk__intkey_table_remove(local_notify_queue, bcast_id);
    }
}

static void
queue_local_notify(xmlNode * notify_src, const char *client_id, gboolean sync_reply,
                   gboolean from_peer)
{
    cib_local_notify_t *notify = calloc(1, sizeof(cib_local_notify_t));

    notify->notify_src = notify_src;
    notify->client_id = strdup(client_id);
    notify->sync_reply = sync_reply;
    notify->from_peer = from_peer;

    if (!local_notify_queue) {
        local_notify_queue = pcmk__intkey_table(local_notify_destroy_callback);
    }
    pcmk__intkey_table_insert(local_notify_queue, cib_local_bcast_num, notify);
    // cppcheck doesn't know notify will get freed when hash table is destroyed
    // cppcheck-suppress memleak
}

static void
parse_local_options_v1(const pcmk__client_t *cib_client,
                       const cib_operation_t *operation, int call_options,
                       const char *host, const char *op, gboolean *local_notify,
                       gboolean *needs_reply, gboolean *process,
                       gboolean *needs_forward)
{
    if (pcmk_is_set(operation->flags, cib_op_attr_modifies)
        && !pcmk_is_set(call_options, cib_inhibit_bcast)) {
        /* we need to send an update anyway */
        *needs_reply = TRUE;
    } else {
        *needs_reply = FALSE;
    }

    if (host == NULL && (call_options & cib_scope_local)) {
        crm_trace("Processing locally scoped %s op from client %s",
                  op, pcmk__client_name(cib_client));
        *local_notify = TRUE;

    } else if ((host == NULL) && based_is_primary) {
        crm_trace("Processing %s op locally from client %s as primary",
                  op, pcmk__client_name(cib_client));
        *local_notify = TRUE;

    } else if (pcmk__str_eq(host, OUR_NODENAME, pcmk__str_casei)) {
        crm_trace("Processing locally addressed %s op from client %s",
                  op, pcmk__client_name(cib_client));
        *local_notify = TRUE;

    } else if (stand_alone) {
        *needs_forward = FALSE;
        *local_notify = TRUE;
        *process = TRUE;

    } else {
        crm_trace("%s op from %s needs to be forwarded to client %s",
                  op, pcmk__client_name(cib_client),
                  pcmk__s(host, "the primary instance"));
        *needs_forward = TRUE;
        *process = FALSE;
    }
}

static void
parse_local_options_v2(const pcmk__client_t *cib_client,
                       const cib_operation_t *operation, int call_options,
                       const char *host, const char *op, gboolean *local_notify,
                       gboolean *needs_reply, gboolean *process,
                       gboolean *needs_forward)
{
    // Process locally and notify local client
    *process = TRUE;
    *needs_reply = FALSE;
    *local_notify = TRUE;
    *needs_forward = FALSE;

    if (pcmk_is_set(operation->flags, cib_op_attr_local)) {
        /* Always process locally if cib_op_attr_local is set.
         *
         * @COMPAT: Currently host is ignored. At a compatibility break, throw
         * an error (from cib_process_request() or earlier) if host is not NULL or
         * OUR_NODENAME.
         */
        crm_trace("Processing always-local %s op from client %s",
                  op, pcmk__client_name(cib_client));

        if (!pcmk__str_eq(host, OUR_NODENAME,
                          pcmk__str_casei|pcmk__str_null_matches)) {

            crm_warn("Operation '%s' is always local but its target host is "
                     "set to '%s'",
                     op, host);
        }
        return;
    }

    if (pcmk_is_set(operation->flags, cib_op_attr_modifies)
        || !pcmk__str_eq(host, OUR_NODENAME,
                         pcmk__str_casei|pcmk__str_null_matches)) {

        // Forward modifying and non-local requests via cluster
        *process = FALSE;
        *needs_reply = FALSE;
        *local_notify = FALSE;
        *needs_forward = TRUE;

        crm_trace("%s op from %s needs to be forwarded to %s",
                  op, pcmk__client_name(cib_client),
                  pcmk__s(host, "all nodes"));
        return;
    }

    if (stand_alone) {
        crm_trace("Processing %s op from client %s (stand-alone)",
                  op, pcmk__client_name(cib_client));

    } else {
        crm_trace("Processing %saddressed %s op from client %s",
                  ((host != NULL)? "locally " : "un"),
                  op, pcmk__client_name(cib_client));
    }
}

static void
parse_local_options(const pcmk__client_t *cib_client,
                    const cib_operation_t *operation, int call_options,
                    const char *host, const char *op, gboolean *local_notify,
                    gboolean *needs_reply, gboolean *process,
                    gboolean *needs_forward)
{
    if(cib_legacy_mode()) {
        parse_local_options_v1(cib_client, operation, call_options, host,
                               op, local_notify, needs_reply, process,
                               needs_forward);
    } else {
        parse_local_options_v2(cib_client, operation, call_options, host,
                               op, local_notify, needs_reply, process,
                               needs_forward);
    }
}

static gboolean
parse_peer_options_v1(const cib_operation_t *operation, xmlNode *request,
                      gboolean *local_notify, gboolean *needs_reply,
                      gboolean *process)
{
    const char *op = NULL;
    const char *host = NULL;
    const char *delegated = NULL;
    const char *originator = crm_element_value(request, F_ORIG);
    const char *reply_to = crm_element_value(request, F_CIB_ISREPLY);

    gboolean is_reply = pcmk__str_eq(reply_to, OUR_NODENAME, pcmk__str_casei);

    if (pcmk__xe_attr_is_true(request, F_CIB_GLOBAL_UPDATE)) {
        *needs_reply = FALSE;
        if (is_reply) {
            *local_notify = TRUE;
            crm_trace("Processing global/peer update from %s"
                      " that originated from us", originator);
        } else {
            crm_trace("Processing global/peer update from %s", originator);
        }
        return TRUE;
    }

    op = crm_element_value(request, F_CIB_OPERATION);
    crm_trace("Processing %s request sent by %s", op, originator);
    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_SHUTDOWN, pcmk__str_none)) {
        /* Always process these */
        *local_notify = FALSE;
        if (reply_to == NULL || is_reply) {
            *process = TRUE;
        }
        if (is_reply) {
            *needs_reply = FALSE;
        }
        return *process;
    }

    if (is_reply && pcmk__str_eq(op, CRM_OP_PING, pcmk__str_casei)) {
        process_ping_reply(request);
        return FALSE;
    }

    if (is_reply) {
        crm_trace("Forward reply sent from %s to local clients", originator);
        *process = FALSE;
        *needs_reply = FALSE;
        *local_notify = TRUE;
        return TRUE;
    }

    host = crm_element_value(request, F_CIB_HOST);
    if (pcmk__str_eq(host, OUR_NODENAME, pcmk__str_casei)) {
        crm_trace("Processing %s request sent to us from %s", op, originator);
        return TRUE;

    } else if(is_reply == FALSE && pcmk__str_eq(op, CRM_OP_PING, pcmk__str_casei)) {
        crm_trace("Processing %s request sent to %s by %s", op, host?host:"everyone", originator);
        *needs_reply = TRUE;
        return TRUE;

    } else if ((host == NULL) && based_is_primary) {
        crm_trace("Processing %s request sent to primary instance from %s",
                  op, originator);
        return TRUE;
    }

    delegated = crm_element_value(request, F_CIB_DELEGATED);
    if (delegated != NULL) {
        crm_trace("Ignoring message for primary instance");

    } else if (host != NULL) {
        /* this is for a specific instance and we're not it */
        crm_trace("Ignoring msg for instance on %s", host);

    } else if ((reply_to == NULL) && !based_is_primary) {
        // This is for the primary instance, and we're not it
        crm_trace("Ignoring reply for primary instance");

    } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_SHUTDOWN, pcmk__str_none)) {
        if (reply_to != NULL) {
            crm_debug("Processing %s from %s", op, originator);
            *needs_reply = FALSE;

        } else {
            crm_debug("Processing %s reply from %s", op, originator);
        }
        return TRUE;

    } else {
        crm_err("Nothing for us to do?");
        crm_log_xml_err(request, "Peer[inbound]");
    }

    return FALSE;
}

static gboolean
parse_peer_options_v2(const cib_operation_t *operation, xmlNode *request,
                      gboolean *local_notify, gboolean *needs_reply,
                      gboolean *process)
{
    const char *host = NULL;
    const char *delegated = crm_element_value(request, F_CIB_DELEGATED);
    const char *op = crm_element_value(request, F_CIB_OPERATION);
    const char *originator = crm_element_value(request, F_ORIG);
    const char *reply_to = crm_element_value(request, F_CIB_ISREPLY);

    gboolean is_reply = pcmk__str_eq(reply_to, OUR_NODENAME, pcmk__str_casei);

    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_REPLACE, pcmk__str_none)) {
        /* sync_our_cib() sets F_CIB_ISREPLY */
        if (reply_to) {
            delegated = reply_to;
        }
        goto skip_is_reply;

    } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_SYNC_TO_ALL,
                            pcmk__str_none)) {
        // Nothing to do

    } else if (is_reply && pcmk__str_eq(op, CRM_OP_PING, pcmk__str_casei)) {
        process_ping_reply(request);
        return FALSE;

    } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_UPGRADE, pcmk__str_none)) {
        /* Only the DC (node with the oldest software) should process
         * this operation if F_CIB_SCHEMA_MAX is unset
         *
         * If the DC is happy it will then send out another
         * PCMK__CIB_REQUEST_UPGRADE which will tell all nodes to do the actual
         * upgrade.
         *
         * Except this time F_CIB_SCHEMA_MAX will be set which puts a
         * limit on how far newer nodes will go
         */
        const char *max = crm_element_value(request, F_CIB_SCHEMA_MAX);
        const char *upgrade_rc = crm_element_value(request, F_CIB_UPGRADE_RC);

        crm_trace("Parsing %s operation%s for %s with max=%s and upgrade_rc=%s",
                  op, (is_reply? " reply" : ""),
                  (based_is_primary? "primary" : "secondary"),
                  (max? max : "none"), (upgrade_rc? upgrade_rc : "none"));

        if (upgrade_rc != NULL) {
            // Our upgrade request was rejected by DC, notify clients of result
            crm_xml_add(request, F_CIB_RC, upgrade_rc);

        } else if ((max == NULL) && based_is_primary) {
            /* We are the DC, check if this upgrade is allowed */
            goto skip_is_reply;

        } else if(max) {
            /* Ok, go ahead and upgrade to 'max' */
            goto skip_is_reply;

        } else {
            // Ignore broadcast client requests when we're not DC
            return FALSE;
        }

    } else if (pcmk__xe_attr_is_true(request, F_CIB_GLOBAL_UPDATE)) {
        crm_info("Detected legacy %s global update from %s", op, originator);
        send_sync_request(NULL);
        legacy_mode = TRUE;
        return FALSE;

    } else if (is_reply
               && pcmk_is_set(operation->flags, cib_op_attr_modifies)) {
        crm_trace("Ignoring legacy %s reply sent from %s to local clients", op, originator);
        return FALSE;

    } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_SHUTDOWN, pcmk__str_none)) {
        // @COMPAT: Legacy handling
        crm_debug("Legacy handling of %s message from %s", op, originator);
        *local_notify = FALSE;
        if (reply_to == NULL) {
            *process = TRUE;
        }
        return *process;
    }

    if(is_reply) {
        crm_trace("Handling %s reply sent from %s to local clients", op, originator);
        *process = FALSE;
        *needs_reply = FALSE;
        *local_notify = TRUE;
        return TRUE;
    }

  skip_is_reply:
    *process = TRUE;
    *needs_reply = FALSE;

    *local_notify = pcmk__str_eq(delegated, OUR_NODENAME, pcmk__str_casei);

    host = crm_element_value(request, F_CIB_HOST);
    if (pcmk__str_eq(host, OUR_NODENAME, pcmk__str_casei)) {
        crm_trace("Processing %s request sent to us from %s", op, originator);
        *needs_reply = TRUE;
        return TRUE;

    } else if (host != NULL) {
        /* this is for a specific instance and we're not it */
        crm_trace("Ignoring %s operation for instance on %s", op, host);
        return FALSE;

    } else if(is_reply == FALSE && pcmk__str_eq(op, CRM_OP_PING, pcmk__str_casei)) {
        *needs_reply = TRUE;
    }

    crm_trace("Processing %s request sent to everyone by %s/%s on %s %s", op,
              crm_element_value(request, F_CIB_CLIENTNAME),
              crm_element_value(request, F_CIB_CALLID),
              originator, (*local_notify)?"(notify)":"");
    return TRUE;
}

static gboolean
parse_peer_options(const cib_operation_t *operation, xmlNode *request,
                   gboolean *local_notify, gboolean *needs_reply,
                   gboolean *process)
{
    /* TODO: What happens when an update comes in after node A
     * requests the CIB from node B, but before it gets the reply (and
     * sends out the replace operation)
     */
    if(cib_legacy_mode()) {
        return parse_peer_options_v1(operation, request, local_notify,
                                     needs_reply, process);
    } else {
        return parse_peer_options_v2(operation, request, local_notify,
                                     needs_reply, process);
    }
}

static void
forward_request(xmlNode *request, int call_options)
{
    const char *op = crm_element_value(request, F_CIB_OPERATION);
    const char *host = crm_element_value(request, F_CIB_HOST);

    crm_xml_add(request, F_CIB_DELEGATED, OUR_NODENAME);

    if (host != NULL) {
        crm_trace("Forwarding %s op to %s", op, host);
        send_cluster_message(crm_get_peer(0, host), crm_msg_cib, request, FALSE);

    } else {
        crm_trace("Forwarding %s op to primary instance", op);
        send_cluster_message(NULL, crm_msg_cib, request, FALSE);
    }

    /* Return the request to its original state */
    xml_remove_prop(request, F_CIB_DELEGATED);

    if (call_options & cib_discard_reply) {
        crm_trace("Client not interested in reply");
    }
}

static gboolean
send_peer_reply(xmlNode * msg, xmlNode * result_diff, const char *originator, gboolean broadcast)
{
    CRM_ASSERT(msg != NULL);

    if (broadcast) {
        /* @COMPAT: Legacy code
         *
         * This successful call modified the CIB, and the change needs to be
         * broadcast (sent via cluster to all nodes).
         */
        int diff_add_updates = 0;
        int diff_add_epoch = 0;
        int diff_add_admin_epoch = 0;

        int diff_del_updates = 0;
        int diff_del_epoch = 0;
        int diff_del_admin_epoch = 0;

        const char *digest = NULL;
        int format = 1;

        CRM_LOG_ASSERT(result_diff != NULL);
        digest = crm_element_value(result_diff, XML_ATTR_DIGEST);
        crm_element_value_int(result_diff, "format", &format);

        cib_diff_version_details(result_diff,
                                 &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                                 &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

        crm_trace("Sending update diff %d.%d.%d -> %d.%d.%d %s",
                  diff_del_admin_epoch, diff_del_epoch, diff_del_updates,
                  diff_add_admin_epoch, diff_add_epoch, diff_add_updates, digest);

        crm_xml_add(msg, F_CIB_ISREPLY, originator);
        pcmk__xe_set_bool_attr(msg, F_CIB_GLOBAL_UPDATE, true);
        crm_xml_add(msg, F_CIB_OPERATION, PCMK__CIB_REQUEST_APPLY_PATCH);
        crm_xml_add(msg, F_CIB_USER, CRM_DAEMON_USER);

        if (format == 1) {
            CRM_ASSERT(digest != NULL);
        }

        add_message_xml(msg, F_CIB_UPDATE_DIFF, result_diff);
        crm_log_xml_explicit(msg, "copy");
        return send_cluster_message(NULL, crm_msg_cib, msg, TRUE);

    } else if (originator != NULL) {
        /* send reply via HA to originating node */
        crm_trace("Sending request result to %s only", originator);
        crm_xml_add(msg, F_CIB_ISREPLY, originator);
        return send_cluster_message(crm_get_peer(0, originator), crm_msg_cib, msg, FALSE);
    }

    return FALSE;
}

/*!
 * \internal
 * \brief Handle an IPC or CPG message containing a request
 *
 * \param[in,out] request        Request XML
 * \param[in] privileged         Whether privileged commands may be run
 *                               (see cib_server_ops[] definition)
 * \param[in] cib_client         IPC client that sent request (or NULL if CPG)
 */
static void
cib_process_request(xmlNode *request, gboolean privileged,
                    const pcmk__client_t *cib_client)
{
    int call_options = 0;

    gboolean process = TRUE;        // Whether to process request locally now
    gboolean is_update = TRUE;      // Whether request would modify CIB
    gboolean needs_reply = TRUE;    // Whether to build a reply
    gboolean local_notify = FALSE;  // Whether to notify (local) requester
    gboolean needs_forward = FALSE; // Whether to forward request somewhere else

    xmlNode *op_reply = NULL;
    xmlNode *result_diff = NULL;

    int rc = pcmk_ok;
    const char *op = crm_element_value(request, F_CIB_OPERATION);
    const char *originator = crm_element_value(request, F_ORIG);
    const char *host = crm_element_value(request, F_CIB_HOST);
    const char *target = NULL;
    const char *call_id = crm_element_value(request, F_CIB_CALLID);
    const char *client_id = crm_element_value(request, F_CIB_CLIENTID);
    const char *client_name = crm_element_value(request, F_CIB_CLIENTNAME);
    const char *reply_to = crm_element_value(request, F_CIB_ISREPLY);

    const cib_operation_t *operation = NULL;

    crm_element_value_int(request, F_CIB_CALLOPTS, &call_options);

    if ((host != NULL) && (*host == '\0')) {
        host = NULL;
    }

    if (host) {
        target = host;

    } else if (call_options & cib_scope_local) {
        target = "local host";

    } else {
        target = "primary";
    }

    if (cib_client == NULL) {
        crm_trace("Processing peer %s operation from %s/%s on %s intended for %s (reply=%s)",
                  op, client_name, call_id, originator, target, reply_to);
    } else {
        crm_xml_add(request, F_ORIG, OUR_NODENAME);
        crm_trace("Processing local %s operation from %s/%s intended for %s", op, client_name, call_id, target);
    }

    rc = cib_get_operation(op, &operation);
    if (rc != pcmk_ok) {
        /* TODO: construct error reply? */
        crm_err("Pre-processing of command failed: %s", pcmk_strerror(rc));
        return;
    }

    if (cib_client != NULL) {
        parse_local_options(cib_client, operation, call_options, host, op,
                            &local_notify, &needs_reply, &process,
                            &needs_forward);

    } else if (!parse_peer_options(operation, request, &local_notify,
                                   &needs_reply, &process)) {
        return;
    }

    is_update = pcmk_is_set(operation->flags, cib_op_attr_modifies);

    if (call_options & cib_discard_reply) {
        /* If the request will modify the CIB, and we are in legacy mode, we
         * need to build a reply so we can broadcast a diff, even if the
         * requester doesn't want one.
         */
        needs_reply = is_update && cib_legacy_mode();
        local_notify = FALSE;
    }

    if (needs_forward) {
        const char *section = crm_element_value(request, F_CIB_SECTION);
        int log_level = LOG_INFO;

        if (pcmk__str_eq(op, PCMK__CIB_REQUEST_NOOP, pcmk__str_none)) {
            log_level = LOG_DEBUG;
        }

        do_crm_log(log_level,
                   "Forwarding %s operation for section %s to %s (origin=%s/%s/%s)",
                   op,
                   section ? section : "'all'",
                   pcmk__s(host, (cib_legacy_mode() ? "primary" : "all")),
                   originator ? originator : "local",
                   client_name, call_id);

        forward_request(request, call_options);
        return;
    }

    if (cib_status != pcmk_ok) {
        rc = cib_status;
        crm_err("Operation ignored, cluster configuration is invalid."
                " Please repair and restart: %s", pcmk_strerror(cib_status));

        op_reply = create_cib_reply(op, call_id, client_id, call_options, rc,
                                    the_cib);

    } else if (process) {
        time_t finished = 0;
        time_t now = time(NULL);
        int level = LOG_INFO;
        const char *section = crm_element_value(request, F_CIB_SECTION);

        rc = cib_process_command(request, &op_reply, &result_diff, privileged);

        if (!is_update) {
            level = LOG_TRACE;

        } else if (pcmk__xe_attr_is_true(request, F_CIB_GLOBAL_UPDATE)) {
            switch (rc) {
                case pcmk_ok:
                    level = LOG_INFO;
                    break;
                case -pcmk_err_old_data:
                case -pcmk_err_diff_resync:
                case -pcmk_err_diff_failed:
                    level = LOG_TRACE;
                    break;
                default:
                    level = LOG_ERR;
            }

        } else if (rc != pcmk_ok) {
            level = LOG_WARNING;
        }

        do_crm_log(level,
                   "Completed %s operation for section %s: %s (rc=%d, origin=%s/%s/%s, version=%s.%s.%s)",
                   op, section ? section : "'all'", pcmk_strerror(rc), rc,
                   originator ? originator : "local", client_name, call_id,
                   the_cib ? crm_element_value(the_cib, XML_ATTR_GENERATION_ADMIN) : "0",
                   the_cib ? crm_element_value(the_cib, XML_ATTR_GENERATION) : "0",
                   the_cib ? crm_element_value(the_cib, XML_ATTR_NUMUPDATES) : "0");

        finished = time(NULL);
        if ((finished - now) > 3) {
            crm_trace("%s operation took %lds to complete", op, (long)(finished - now));
            crm_write_blackbox(0, NULL);
        }

        if (op_reply == NULL && (needs_reply || local_notify)) {
            crm_err("Unexpected NULL reply to message");
            crm_log_xml_err(request, "null reply");
            needs_reply = FALSE;
            local_notify = FALSE;
        }
    }

    if (is_update && !cib_legacy_mode()) {
        crm_trace("Completed pre-sync update from %s/%s/%s%s",
                  originator ? originator : "local", client_name, call_id,
                  local_notify?" with local notification":"");

    } else if (!needs_reply || stand_alone) {
        // This was a non-originating secondary update
        crm_trace("Completed update as secondary");

    } else if (cib_legacy_mode() &&
               rc == pcmk_ok && result_diff != NULL && !(call_options & cib_inhibit_bcast)) {
        gboolean broadcast = FALSE;

        cib_local_bcast_num++;
        crm_xml_add_int(request, F_CIB_LOCAL_NOTIFY_ID, cib_local_bcast_num);
        broadcast = send_peer_reply(request, result_diff, originator, TRUE);

        if (broadcast && client_id && local_notify && op_reply) {

            /* If we have been asked to sync the reply,
             * and a bcast msg has gone out, we queue the local notify
             * until we know the bcast message has been received */
            local_notify = FALSE;
            crm_trace("Queuing local %ssync notification for %s",
                      (call_options & cib_sync_call) ? "" : "a-", client_id);

            queue_local_notify(op_reply, client_id,
                               pcmk_is_set(call_options, cib_sync_call),
                               (cib_client == NULL));
            op_reply = NULL;    /* the reply is queued, so don't free here */
        }

    } else if (call_options & cib_discard_reply) {
        crm_trace("Caller isn't interested in reply");

    } else if (cib_client == NULL) {
        if (is_update == FALSE || result_diff == NULL) {
            crm_trace("Request not broadcast: R/O call");

        } else if (call_options & cib_inhibit_bcast) {
            crm_trace("Request not broadcast: inhibited");

        } else if (rc != pcmk_ok) {
            crm_trace("Request not broadcast: call failed: %s", pcmk_strerror(rc));

        } else {
            crm_trace("Directing reply to %s", originator);
        }

        send_peer_reply(op_reply, result_diff, originator, FALSE);
    }

    if (local_notify && client_id) {
        crm_trace("Performing local %ssync notification for %s",
                  (pcmk_is_set(call_options, cib_sync_call)? "" : "a"),
                  client_id);
        if (process == FALSE) {
            do_local_notify(request, client_id,
                            pcmk_is_set(call_options, cib_sync_call),
                            (cib_client == NULL));
        } else {
            do_local_notify(op_reply, client_id,
                            pcmk_is_set(call_options, cib_sync_call),
                            (cib_client == NULL));
        }
    }

    free_xml(op_reply);
    free_xml(result_diff);

    return;
}

static char *
calculate_section_digest(const char *xpath, xmlNode * xml_obj)
{
    xmlNode *xml_section = NULL;

    if (xml_obj == NULL) {
        return NULL;
    }

    xml_section = get_xpath_object(xpath, xml_obj, LOG_TRACE);
    if (xml_section == NULL) {
        return NULL;
    }
    return calculate_xml_versioned_digest(xml_section, FALSE, TRUE, CRM_FEATURE_SET); 

}

#define XPATH_CONFIG    "/" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION
#define XPATH_NODES     XPATH_CONFIG "/" XML_CIB_TAG_NODES
#define XPATH_ALERTS    XPATH_CONFIG "/" XML_CIB_TAG_ALERTS
#define XPATH_STATUS    "/" XML_TAG_CIB "/" XML_CIB_TAG_STATUS

/*!
 * \internal
 * \brief Calculate digests of CIB sections
 *
 * \param[in]  cib      CIB to get digests from
 * \param[out] digests  Where to store digests
 *
 * \note The caller is responsible for freeing the output argument's members
 *       using \p free_digests().
 */
static void
get_digests(xmlNode *cib, struct digest_data *digests)
{
    digests->nodes = calculate_section_digest(XPATH_NODES, cib);
    digests->alerts = calculate_section_digest(XPATH_ALERTS, cib);
    digests->status = calculate_section_digest(XPATH_STATUS, cib);
}

/*!
 * \internal
 * \brief Determine which CIB sections were changed by an operation
 *
 * \param[in] before  Digests before the operation
 * \param[in] after   Digests after the operation
 *
 * \return Group of <tt>enum cib_change_section_info</tt> flags indicating which
 *         sections have changed
 */
static uint32_t
get_change_sections(const struct digest_data *before,
                    const struct digest_data *after)
{
    uint32_t change_sections = cib_change_section_none;

    if (!pcmk__str_eq(before->nodes, after->nodes, pcmk__str_none)) {
        pcmk__set_change_section(change_sections, cib_change_section_nodes);
    }
    if (!pcmk__str_eq(before->alerts, after->alerts, pcmk__str_none)) {
        pcmk__set_change_section(change_sections, cib_change_section_alerts);
    }
    if (!pcmk__str_eq(before->status, after->status, pcmk__str_none)) {
        pcmk__set_change_section(change_sections, cib_change_section_status);
    }

    return change_sections;
}

// v1 and v2 patch formats
#define XPATH_CONFIG_CHANGE             \
    "//" XML_CIB_TAG_CRMCONFIG " | "    \
    "//" XML_DIFF_CHANGE                \
    "[contains(@" XML_DIFF_PATH ",'/" XML_CIB_TAG_CRMCONFIG "/')]"

static bool
contains_config_change(xmlNode *diff)
{
    bool changed = false;

    if (diff) {
        xmlXPathObject *xpathObj = xpath_search(diff, XPATH_CONFIG_CHANGE);

        if (numXpathResults(xpathObj) > 0) {
            changed = true;
        }
        freeXpathObject(xpathObj);
    }
    return changed;
}

static int
cib_process_command(xmlNode * request, xmlNode ** reply, xmlNode ** cib_diff, gboolean privileged)
{
    xmlNode *input = NULL;
    xmlNode *output = NULL;
    xmlNode *result_cib = NULL;

    int call_options = 0;

    const char *op = NULL;
    const char *section = NULL;
    const char *call_id = crm_element_value(request, F_CIB_CALLID);
    const char *client_id = crm_element_value(request, F_CIB_CLIENTID);
    const char *client_name = crm_element_value(request, F_CIB_CLIENTNAME);
    const char *origin = crm_element_value(request, F_ORIG);

    const cib_operation_t *operation = NULL;

    int rc = pcmk_ok;

    gboolean config_changed = FALSE;
    gboolean manage_counters = TRUE;

    static mainloop_timer_t *digest_timer = NULL;

    struct digest_data before_digests = { 0, };

    CRM_ASSERT(cib_status == pcmk_ok);

    if(digest_timer == NULL) {
        digest_timer = mainloop_timer_add("digester", 5000, FALSE, cib_digester_cb, NULL);
    }

    *reply = NULL;
    *cib_diff = NULL;

    /* Start processing the request... */
    op = crm_element_value(request, F_CIB_OPERATION);
    crm_element_value_int(request, F_CIB_CALLOPTS, &call_options);

    rc = cib_get_operation(op, &operation);
    if (rc != pcmk_ok) {
        crm_trace("Failed to get operation: %s", pcmk_strerror(rc));
        goto done;
    }

    if (!privileged && pcmk_is_set(operation->flags, cib_op_attr_privileged)) {
        rc = -EACCES;
        crm_trace("Failed due to lack of privileges: %s", pcmk_strerror(rc));
        goto done;
    }

    rc = operation->prepare(request, &input, &section);
    if (rc != pcmk_ok) {
        crm_trace("Failed to prepare operation: %s", pcmk_strerror(rc));
        goto done;
    }

    if (!pcmk_is_set(operation->flags, cib_op_attr_modifies)) {
        rc = cib_perform_op(op, call_options, operation->fn, TRUE, section,
                            request, input, FALSE, &config_changed, the_cib,
                            &result_cib, NULL, &output);

        CRM_CHECK(result_cib == NULL, free_xml(result_cib));
        goto done;
    }

    /* @COMPAT: Handle a valid write action (legacy)
     *
     * @TODO: Re-evaluate whether this is all truly legacy. The cib_force_diff
     * portion is. However, F_CIB_GLOBAL_UPDATE may be set by a sync operation
     * even in non-legacy mode, and manage_counters tells xml_create_patchset()
     * whether to update version/epoch info.
     */
    if (pcmk__xe_attr_is_true(request, F_CIB_GLOBAL_UPDATE)) {
        manage_counters = FALSE;
        cib__set_call_options(call_options, "call", cib_force_diff);
        crm_trace("Global update detected");

        CRM_LOG_ASSERT(pcmk__str_any_of(op,
                                        PCMK__CIB_REQUEST_APPLY_PATCH,
                                        PCMK__CIB_REQUEST_REPLACE,
                                        NULL));
    }

    ping_modified_since = TRUE;
    if (pcmk_is_set(call_options, cib_inhibit_bcast)) {
        crm_trace("Skipping update: inhibit broadcast");
        manage_counters = FALSE;
    }

    if (!pcmk_is_set(call_options, cib_dryrun)
        && pcmk__str_eq(section, XML_CIB_TAG_STATUS, pcmk__str_casei)) {
        // Copying large CIBs accounts for a huge percentage of our CIB usage
        cib__set_call_options(call_options, "call", cib_zero_copy);
    } else {
        cib__clear_call_options(call_options, "call", cib_zero_copy);
    }

    // Calculate the digests of relevant sections before the operation
    if (pcmk_is_set(operation->flags, cib_op_attr_replaces)
        && !pcmk_any_flags_set(call_options, cib_dryrun|cib_inhibit_notify)) {

        get_digests(the_cib, &before_digests);
        crm_trace("before-digest %s:%s:%s",
                  pcmk__s(before_digests.nodes, "(null)"),
                  pcmk__s(before_digests.alerts, "(null)"),
                  pcmk__s(before_digests.status, "(null)"));
    }

    // result_cib must not be modified after cib_perform_op() returns
    rc = cib_perform_op(op, call_options, operation->fn, FALSE, section,
                        request, input, manage_counters, &config_changed,
                        the_cib, &result_cib, cib_diff, &output);

    // @COMPAT: Legacy code
    if (!manage_counters) {
        int format = 1;

        // If the diff is NULL at this point, it's because nothing changed
        if (*cib_diff != NULL) {
            crm_element_value_int(*cib_diff, "format", &format);
        }

        if (format == 1) {
            config_changed = cib__config_changed_v1(NULL, NULL, cib_diff);
        }
    }

    /* Always write to disk for successful ops with the flag set. This also
     * negates the need to detect ordering changes.
     */
    if ((rc == pcmk_ok)
        && pcmk_is_set(operation->flags, cib_op_attr_writes_through)) {

        config_changed = TRUE;
    }

    if (rc == pcmk_ok && !pcmk_is_set(call_options, cib_dryrun)) {
        crm_trace("Activating %s->%s%s%s",
                  crm_element_value(the_cib, XML_ATTR_NUMUPDATES),
                  crm_element_value(result_cib, XML_ATTR_NUMUPDATES),
                  (pcmk_is_set(call_options, cib_zero_copy)? " zero-copy" : ""),
                  (config_changed? " changed" : ""));

        if (!pcmk_is_set(call_options, cib_zero_copy)) {
            rc = activateCibXml(result_cib, config_changed, op);
            if (rc != pcmk_ok) {
                crm_err("Failed to activate new CIB: %s", pcmk_strerror(rc));
            }
        }

        if ((rc == pcmk_ok) && contains_config_change(*cib_diff)) {
            cib_read_config(config_hash, result_cib);
        }

        if (pcmk_is_set(operation->flags, cib_op_attr_replaces)
            && !pcmk_is_set(call_options, cib_inhibit_notify)) {

            struct digest_data after_digests = { 0, };
            uint32_t change_sections = cib_change_section_none;

            get_digests(result_cib, &after_digests);
            crm_trace("after-digest %s:%s:%s",
                      pcmk__s(after_digests.nodes, "(null)"),
                      pcmk__s(after_digests.alerts, "(null)"),
                      pcmk__s(after_digests.status, "(null)"));

            change_sections = get_change_sections(&before_digests,
                                                  &after_digests);
            free_digests(&after_digests);

            if (change_sections != cib_change_section_none) {
                cib_replace_notify(op, rc, call_id, client_id, client_name,
                                   origin, the_cib, *cib_diff, change_sections);
            }
        }

        mainloop_timer_stop(digest_timer);
        mainloop_timer_start(digest_timer);

    } else if (rc == -pcmk_err_schema_validation) {
        CRM_ASSERT(!pcmk_is_set(call_options, cib_zero_copy));

        if (output != NULL) {
            crm_log_xml_info(output, "cib:output");
            free_xml(output);
        }

        output = result_cib;

    } else {
        crm_trace("Not activating %d %d %s", rc,
                  pcmk_is_set(call_options, cib_dryrun),
                  crm_element_value(result_cib, XML_ATTR_NUMUPDATES));
        if (!pcmk_is_set(call_options, cib_zero_copy)) {
            free_xml(result_cib);
        }
    }

    if ((call_options & (cib_inhibit_notify|cib_dryrun)) == 0) {
        crm_trace("Sending notifications %d",
                  pcmk_is_set(call_options, cib_dryrun));
        cib_diff_notify(op, rc, call_id, client_id, client_name, origin, input,
                        *cib_diff);
    }

    pcmk__output_set_log_level(logger_out, LOG_TRACE);
    logger_out->message(logger_out, "xml-patchset", *cib_diff);

  done:
    if (!pcmk_is_set(call_options, cib_discard_reply) || cib_legacy_mode()) {
        *reply = create_cib_reply(op, call_id, client_id, call_options, rc,
                                  output);
    }

    crm_trace("cleanup");

    if (operation != NULL) {
        operation->cleanup(call_options, &input, &output);
    }

    free_digests(&before_digests);

    crm_trace("done");
    return rc;
}

void
cib_peer_callback(xmlNode * msg, void *private_data)
{
    const char *reason = NULL;
    const char *originator = crm_element_value(msg, F_ORIG);

    if (cib_legacy_mode()
        && pcmk__str_eq(originator, OUR_NODENAME,
                        pcmk__str_casei|pcmk__str_null_matches)) {
        /* message is from ourselves */
        int bcast_id = 0;

        if (!(crm_element_value_int(msg, F_CIB_LOCAL_NOTIFY_ID, &bcast_id))) {
            check_local_notify(bcast_id);
        }
        return;

    } else if (crm_peer_cache == NULL) {
        reason = "membership not established";
        goto bail;
    }

    if (crm_element_value(msg, F_CIB_CLIENTNAME) == NULL) {
        crm_xml_add(msg, F_CIB_CLIENTNAME, originator);
    }

    /* crm_log_xml_trace(msg, "Peer[inbound]"); */
    cib_process_request(msg, TRUE, NULL);
    return;

  bail:
    if (reason) {
        const char *seq = crm_element_value(msg, F_SEQ);
        const char *op = crm_element_value(msg, F_CIB_OPERATION);

        crm_warn("Discarding %s message (%s) from %s: %s", op, seq, originator, reason);
    }
}

static gboolean
cib_force_exit(gpointer data)
{
    crm_notice("Forcing exit!");
    terminate_cib(__func__, CRM_EX_ERROR);
    return FALSE;
}

static void
disconnect_remote_client(gpointer key, gpointer value, gpointer user_data)
{
    pcmk__client_t *a_client = value;

    crm_err("Can't disconnect client %s: Not implemented",
            pcmk__client_name(a_client));
}

static void
initiate_exit(void)
{
    int active = 0;
    xmlNode *leaving = NULL;

    active = crm_active_peers();
    if (active < 2) {
        terminate_cib(__func__, 0);
        return;
    }

    crm_info("Sending disconnect notification to %d peers...", active);

    leaving = create_xml_node(NULL, "exit-notification");
    crm_xml_add(leaving, F_TYPE, "cib");
    crm_xml_add(leaving, F_CIB_OPERATION, PCMK__CIB_REQUEST_SHUTDOWN);

    send_cluster_message(NULL, crm_msg_cib, leaving, TRUE);
    free_xml(leaving);

    g_timeout_add(EXIT_ESCALATION_MS, cib_force_exit, NULL);
}

void
cib_shutdown(int nsig)
{
    struct qb_ipcs_stats srv_stats;

    if (cib_shutdown_flag == FALSE) {
        int disconnects = 0;
        qb_ipcs_connection_t *c = NULL;

        cib_shutdown_flag = TRUE;

        c = qb_ipcs_connection_first_get(ipcs_rw);
        while (c != NULL) {
            qb_ipcs_connection_t *last = c;

            c = qb_ipcs_connection_next_get(ipcs_rw, last);

            crm_debug("Disconnecting r/w client %p...", last);
            qb_ipcs_disconnect(last);
            qb_ipcs_connection_unref(last);
            disconnects++;
        }

        c = qb_ipcs_connection_first_get(ipcs_ro);
        while (c != NULL) {
            qb_ipcs_connection_t *last = c;

            c = qb_ipcs_connection_next_get(ipcs_ro, last);

            crm_debug("Disconnecting r/o client %p...", last);
            qb_ipcs_disconnect(last);
            qb_ipcs_connection_unref(last);
            disconnects++;
        }

        c = qb_ipcs_connection_first_get(ipcs_shm);
        while (c != NULL) {
            qb_ipcs_connection_t *last = c;

            c = qb_ipcs_connection_next_get(ipcs_shm, last);

            crm_debug("Disconnecting non-blocking r/w client %p...", last);
            qb_ipcs_disconnect(last);
            qb_ipcs_connection_unref(last);
            disconnects++;
        }

        disconnects += pcmk__ipc_client_count();

        crm_debug("Disconnecting %d remote clients", pcmk__ipc_client_count());
        pcmk__foreach_ipc_client(disconnect_remote_client, NULL);
        crm_info("Disconnected %d clients", disconnects);
    }

    qb_ipcs_stats_get(ipcs_rw, &srv_stats, QB_FALSE);

    if (pcmk__ipc_client_count() == 0) {
        crm_info("All clients disconnected (%d)", srv_stats.active_connections);
        initiate_exit();

    } else {
        crm_info("Waiting on %d clients to disconnect (%d)",
                 pcmk__ipc_client_count(), srv_stats.active_connections);
    }
}

extern int remote_fd;
extern int remote_tls_fd;

/*!
 * \internal
 * \brief Close remote sockets, free the global CIB and quit
 *
 * \param[in] caller           Name of calling function (for log message)
 * \param[in] fast             If -1, skip disconnect; if positive, exit that
 */
void
terminate_cib(const char *caller, int fast)
{
    crm_info("%s: Exiting%s...", caller,
             (fast > 0)? " fast" : mainloop ? " from mainloop" : "");

    if (remote_fd > 0) {
        close(remote_fd);
        remote_fd = 0;
    }
    if (remote_tls_fd > 0) {
        close(remote_tls_fd);
        remote_tls_fd = 0;
    }

    uninitializeCib();

    if (logger_out != NULL) {
        logger_out->finish(logger_out, CRM_EX_OK, true, NULL);
        pcmk__output_free(logger_out);
        logger_out = NULL;
    }

    if (fast > 0) {
        /* Quit fast on error */
        pcmk__stop_based_ipc(ipcs_ro, ipcs_rw, ipcs_shm);
        crm_exit(fast);

    } else if ((mainloop != NULL) && g_main_loop_is_running(mainloop)) {
        /* Quit via returning from the main loop. If fast == -1, we skip the
         * disconnect here, and it will be done when the main loop returns
         * (this allows the peer status callback to avoid messing with the
         * peer caches).
         */
        if (fast == 0) {
            crm_cluster_disconnect(crm_cluster);
        }
        g_main_loop_quit(mainloop);

    } else {
        /* Quit via clean exit. Even the peer status callback can disconnect
         * here, because we're not returning control to the caller. */
        crm_cluster_disconnect(crm_cluster);
        pcmk__stop_based_ipc(ipcs_ro, ipcs_rw, ipcs_shm);
        crm_exit(CRM_EX_OK);
    }
}

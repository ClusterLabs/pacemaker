/*
 * Copyright 2004-2024 the Pacemaker project contributors
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

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/cluster/internal.h>

#include <crm/common/xml.h>
#include <crm/common/remote_internal.h>

#include <pacemaker-based.h>

#define EXIT_ESCALATION_MS 10000

qb_ipcs_service_t *ipcs_ro = NULL;
qb_ipcs_service_t *ipcs_rw = NULL;
qb_ipcs_service_t *ipcs_shm = NULL;

static int cib_process_command(xmlNode *request,
                               const cib__operation_t *operation,
                               cib__op_fn_t op_function, xmlNode **reply,
                               xmlNode **cib_diff, bool privileged);

static gboolean cib_common_callback(qb_ipcs_connection_t *c, void *data,
                                    size_t size, gboolean privileged);

static int32_t
cib_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    if (cib_shutdown_flag) {
        crm_info("Ignoring new IPC client [%d] during shutdown",
                 pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
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
 * \return Reply XML (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \p pcmk__xml_free().
 */
static xmlNode *
create_cib_reply(const char *op, const char *call_id, const char *client_id,
                 uint32_t call_options, int rc, xmlNode *call_data)
{
    xmlNode *reply = pcmk__xe_create(NULL, PCMK__XE_CIB_REPLY);

    crm_xml_add(reply, PCMK__XA_T, PCMK__VALUE_CIB);
    crm_xml_add(reply, PCMK__XA_CIB_OP, op);
    crm_xml_add(reply, PCMK__XA_CIB_CALLID, call_id);
    crm_xml_add(reply, PCMK__XA_CIB_CLIENTID, client_id);
    crm_xml_add_int(reply, PCMK__XA_CIB_CALLOPT, call_options);
    crm_xml_add_int(reply, PCMK__XA_CIB_RC, rc);

    if (call_data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(reply, PCMK__XE_CIB_CALLDATA);

        crm_trace("Attaching reply output");
        pcmk__xml_copy(wrapper, call_data);
    }

    crm_log_xml_explicit(reply, "cib:reply");
    return reply;
}

static void
do_local_notify(const xmlNode *notify_src, const char *client_id,
                bool sync_reply, bool from_peer)
{
    int msg_id = 0;
    int rc = pcmk_rc_ok;
    pcmk__client_t *client_obj = NULL;
    uint32_t flags = crm_ipc_server_event;

    CRM_CHECK((notify_src != NULL) && (client_id != NULL), return);

    crm_element_value_int(notify_src, PCMK__XA_CIB_CALLID, &msg_id);

    client_obj = pcmk__find_client_by_id(client_id);
    if (client_obj == NULL) {
        crm_debug("Could not notify client %s%s %s of call %d result: "
                  "client no longer exists", client_id,
                  (from_peer? " (originator of delegated request)" : ""),
                  (sync_reply? "synchronously" : "asynchronously"), msg_id);
        return;
    }

    if (sync_reply) {
        flags = crm_ipc_flags_none;
        if (client_obj->ipcs != NULL) {
            msg_id = client_obj->request_id;
            client_obj->request_id = 0;
        }
    }

    switch (PCMK__CLIENT_TYPE(client_obj)) {
        case pcmk__client_ipc:
            rc = pcmk__ipc_send_xml(client_obj, msg_id, notify_src, flags);
            break;
        case pcmk__client_tls:
        case pcmk__client_tcp:
            rc = pcmk__remote_send_xml(client_obj->remote, notify_src);
            break;
        default:
            rc = EPROTONOSUPPORT;
            break;
    }
    if (rc == pcmk_rc_ok) {
        crm_trace("Notified %s client %s%s %s of call %d result",
                  pcmk__client_type_str(PCMK__CLIENT_TYPE(client_obj)),
                  pcmk__client_name(client_obj),
                  (from_peer? " (originator of delegated request)" : ""),
                  (sync_reply? "synchronously" : "asynchronously"), msg_id);
    } else {
        crm_warn("Could not notify %s client %s%s %s of call %d result: %s",
                 pcmk__client_type_str(PCMK__CLIENT_TYPE(client_obj)),
                 pcmk__client_name(client_obj),
                 (from_peer? " (originator of delegated request)" : ""),
                 (sync_reply? "synchronously" : "asynchronously"), msg_id,
                 pcmk_rc_str(rc));
    }
}

void
cib_common_callback_worker(uint32_t id, uint32_t flags, xmlNode * op_request,
                           pcmk__client_t *cib_client, gboolean privileged)
{
    const char *op = crm_element_value(op_request, PCMK__XA_CIB_OP);
    uint32_t call_options = cib_none;
    int rc = pcmk_rc_ok;

    rc = pcmk__xe_get_flags(op_request, PCMK__XA_CIB_CALLOPT, &call_options,
                            cib_none);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    /* Requests with cib_transaction set should not be sent to based directly
     * (outside of a commit-transaction request)
     */
    if (pcmk_is_set(call_options, cib_transaction)) {
        return;
    }

    if (pcmk__str_eq(op, CRM_OP_REGISTER, pcmk__str_none)) {
        if (flags & crm_ipc_client_response) {
            xmlNode *ack = pcmk__xe_create(NULL, __func__);

            crm_xml_add(ack, PCMK__XA_CIB_OP, CRM_OP_REGISTER);
            crm_xml_add(ack, PCMK__XA_CIB_CLIENTID, cib_client->id);
            pcmk__ipc_send_xml(cib_client, id, ack, flags);
            cib_client->request_id = 0;
            pcmk__xml_free(ack);
        }
        return;

    } else if (pcmk__str_eq(op, PCMK__VALUE_CIB_NOTIFY, pcmk__str_none)) {
        /* Update the notify filters for this client */
        int on_off = 0;
        crm_exit_t status = CRM_EX_OK;
        uint64_t bit = UINT64_C(0);
        const char *type = crm_element_value(op_request,
                                             PCMK__XA_CIB_NOTIFY_TYPE);

        crm_element_value_int(op_request, PCMK__XA_CIB_NOTIFY_ACTIVATE,
                              &on_off);

        crm_debug("Setting %s callbacks %s for client %s",
                  type, (on_off? "on" : "off"), pcmk__client_name(cib_client));

        if (pcmk__str_eq(type, PCMK__VALUE_CIB_POST_NOTIFY, pcmk__str_none)) {
            bit = cib_notify_post;

        } else if (pcmk__str_eq(type, PCMK__VALUE_CIB_PRE_NOTIFY,
                                pcmk__str_none)) {
            bit = cib_notify_pre;

        } else if (pcmk__str_eq(type, PCMK__VALUE_CIB_UPDATE_CONFIRMATION,
                                pcmk__str_none)) {
            bit = cib_notify_confirm;

        } else if (pcmk__str_eq(type, PCMK__VALUE_CIB_DIFF_NOTIFY,
                                pcmk__str_none)) {
            bit = cib_notify_diff;

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

        pcmk__ipc_send_ack(cib_client, id, flags, PCMK__XE_ACK, NULL, status);
        return;
    }

    cib_process_request(op_request, privileged, cib_client);
}

int32_t
cib_common_callback(qb_ipcs_connection_t * c, void *data, size_t size, gboolean privileged)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    uint32_t call_options = cib_none;
    pcmk__client_t *cib_client = pcmk__find_client(c);
    xmlNode *op_request = pcmk__client_data2xml(cib_client, data, &id, &flags);

    if (op_request) {
        int rc = pcmk_rc_ok;

        rc = pcmk__xe_get_flags(op_request, PCMK__XA_CIB_CALLOPT, &call_options,
                                cib_none);
        if (rc != pcmk_rc_ok) {
            crm_warn("Couldn't parse options from request: %s",
                     pcmk_rc_str(rc));
        }
    }

    if (op_request == NULL) {
        crm_trace("Invalid message from %p", c);
        pcmk__ipc_send_ack(cib_client, id, flags, PCMK__XE_NACK, NULL,
                           CRM_EX_PROTOCOL);
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
        const char *value = crm_element_value(op_request,
                                              PCMK__XA_CIB_CLIENTNAME);

        if (value == NULL) {
            cib_client->name = pcmk__itoa(cib_client->pid);
        } else {
            cib_client->name = pcmk__str_copy(value);
            if (pcmk__parse_server(value) != pcmk_ipc_unknown) {
                pcmk__set_client_flags(cib_client, cib_is_daemon);
            }
        }
    }

    /* Allow cluster daemons more leeway before being evicted */
    if (pcmk_is_set(cib_client->flags, cib_is_daemon)) {
        const char *qmax = cib_config_lookup(PCMK_OPT_CLUSTER_IPC_LIMIT);

        pcmk__set_client_queue_max(cib_client, qmax);
    }

    crm_xml_add(op_request, PCMK__XA_CIB_CLIENTID, cib_client->id);
    crm_xml_add(op_request, PCMK__XA_CIB_CLIENTNAME, cib_client->name);

    CRM_LOG_ASSERT(cib_client->user != NULL);
    pcmk__update_acl_user(op_request, PCMK__XA_CIB_USER, cib_client->user);

    cib_common_callback_worker(id, flags, op_request, cib_client, privileged);
    pcmk__xml_free(op_request);

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
        xmlNode *ping = pcmk__xe_create(NULL, PCMK__XE_PING);

        ping_seq++;
        free(ping_digest);
        ping_digest = NULL;
        ping_modified_since = FALSE;
        snprintf(buffer, 32, "%" PRIu64, ping_seq);
        crm_trace("Requesting peer digests (%s)", buffer);

        crm_xml_add(ping, PCMK__XA_T, PCMK__VALUE_CIB);
        crm_xml_add(ping, PCMK__XA_CIB_OP, CRM_OP_PING);
        crm_xml_add(ping, PCMK__XA_CIB_PING_ID, buffer);

        crm_xml_add(ping, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
        pcmk__cluster_send_message(NULL, pcmk_ipc_based, ping);

        pcmk__xml_free(ping);
    }
    return FALSE;
}

static void
process_ping_reply(xmlNode *reply) 
{
    uint64_t seq = 0;
    const char *host = crm_element_value(reply, PCMK__XA_SRC);

    xmlNode *wrapper = pcmk__xe_first_child(reply, PCMK__XE_CIB_CALLDATA, NULL,
                                            NULL);
    xmlNode *pong = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    const char *seq_s = crm_element_value(pong, PCMK__XA_CIB_PING_ID);
    const char *digest = crm_element_value(pong, PCMK__XA_DIGEST);

    if (seq_s == NULL) {
        crm_debug("Ignoring ping reply with no " PCMK__XA_CIB_PING_ID);
        return;

    } else {
        long long seq_ll;
        int rc = pcmk__scan_ll(seq_s, &seq_ll, 0LL);

        if (rc != pcmk_rc_ok) {
            crm_debug("Ignoring ping reply with invalid " PCMK__XA_CIB_PING_ID
                      " '%s': %s", seq_s, pcmk_rc_str(rc));
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
        if(ping_digest == NULL) {
            crm_trace("Calculating new digest");
            ping_digest = pcmk__digest_xml(the_cib, true);
        }

        crm_trace("Processing ping reply %s from %s (%s)", seq_s, host, digest);
        if (!pcmk__str_eq(ping_digest, digest, pcmk__str_casei)) {
            xmlNode *wrapper = pcmk__xe_first_child(pong, PCMK__XE_CIB_CALLDATA,
                                                    NULL, NULL);
            xmlNode *remote_cib = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

            const char *admin_epoch_s = NULL;
            const char *epoch_s = NULL;
            const char *num_updates_s = NULL;

            if (remote_cib != NULL) {
                admin_epoch_s = crm_element_value(remote_cib,
                                                  PCMK_XA_ADMIN_EPOCH);
                epoch_s = crm_element_value(remote_cib, PCMK_XA_EPOCH);
                num_updates_s = crm_element_value(remote_cib,
                                                  PCMK_XA_NUM_UPDATES);
            }

            crm_notice("Local CIB %s.%s.%s.%s differs from %s: %s.%s.%s.%s %p",
                       crm_element_value(the_cib, PCMK_XA_ADMIN_EPOCH),
                       crm_element_value(the_cib, PCMK_XA_EPOCH),
                       crm_element_value(the_cib, PCMK_XA_NUM_UPDATES),
                       ping_digest, host,
                       pcmk__s(admin_epoch_s, "_"),
                       pcmk__s(epoch_s, "_"),
                       pcmk__s(num_updates_s, "_"),
                       digest, remote_cib);

            if(remote_cib && remote_cib->children) {
                // Additional debug
                xml_calculate_changes(the_cib, remote_cib);
                pcmk__log_xml_changes(LOG_INFO, remote_cib);
                crm_trace("End of differences");
            }

            pcmk__xml_free(remote_cib);
            sync_our_cib(reply, FALSE);
        }
    }
}

static void
parse_local_options(const pcmk__client_t *cib_client,
                    const cib__operation_t *operation,
                    const char *host, const char *op, gboolean *local_notify,
                    gboolean *needs_reply, gboolean *process,
                    gboolean *needs_forward)
{
    // Process locally and notify local client
    *process = TRUE;
    *needs_reply = FALSE;
    *local_notify = TRUE;
    *needs_forward = FALSE;

    if (pcmk_is_set(operation->flags, cib__op_attr_local)) {
        /* Always process locally if cib__op_attr_local is set.
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

    if (pcmk_is_set(operation->flags, cib__op_attr_modifies)
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

static gboolean
parse_peer_options(const cib__operation_t *operation, xmlNode *request,
                   gboolean *local_notify, gboolean *needs_reply,
                   gboolean *process)
{
    /* TODO: What happens when an update comes in after node A
     * requests the CIB from node B, but before it gets the reply (and
     * sends out the replace operation)?
     *
     * (This may no longer be relevant since legacy mode was dropped; need to
     * trace code more closely to check.)
     */
    const char *host = NULL;
    const char *delegated = crm_element_value(request,
                                              PCMK__XA_CIB_DELEGATED_FROM);
    const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
    const char *originator = crm_element_value(request, PCMK__XA_SRC);
    const char *reply_to = crm_element_value(request, PCMK__XA_CIB_ISREPLYTO);

    gboolean is_reply = pcmk__str_eq(reply_to, OUR_NODENAME, pcmk__str_casei);

    if (originator == NULL) { // Shouldn't be possible
        originator = "peer";
    }

    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_REPLACE, pcmk__str_none)) {
        // sync_our_cib() sets PCMK__XA_CIB_ISREPLYTO
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
         * this operation if PCMK__XA_CIB_SCHEMA_MAX is unset.
         *
         * If the DC is happy it will then send out another
         * PCMK__CIB_REQUEST_UPGRADE which will tell all nodes to do the actual
         * upgrade.
         *
         * Except this time PCMK__XA_CIB_SCHEMA_MAX will be set which puts a
         * limit on how far newer nodes will go
         */
        const char *max = crm_element_value(request, PCMK__XA_CIB_SCHEMA_MAX);
        const char *upgrade_rc = crm_element_value(request,
                                                   PCMK__XA_CIB_UPGRADE_RC);

        crm_trace("Parsing upgrade %s for %s with max=%s and upgrade_rc=%s",
                  (is_reply? "reply" : "request"),
                  (based_is_primary? "primary" : "secondary"),
                  pcmk__s(max, "none"), pcmk__s(upgrade_rc, "none"));

        if (upgrade_rc != NULL) {
            // Our upgrade request was rejected by DC, notify clients of result
            crm_xml_add(request, PCMK__XA_CIB_RC, upgrade_rc);

        } else if ((max == NULL) && based_is_primary) {
            /* We are the DC, check if this upgrade is allowed */
            goto skip_is_reply;

        } else if(max) {
            /* Ok, go ahead and upgrade to 'max' */
            goto skip_is_reply;

        } else {
            // Ignore broadcast client requests when we're not primary
            return FALSE;
        }

    } else if (pcmk__xe_attr_is_true(request, PCMK__XA_CIB_UPDATE)) {
        crm_info("Detected legacy %s global update from %s", op, originator);
        send_sync_request(NULL);
        return FALSE;

    } else if (is_reply
               && pcmk_is_set(operation->flags, cib__op_attr_modifies)) {
        crm_trace("Ignoring legacy %s reply sent from %s to local clients", op, originator);
        return FALSE;

    } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_SHUTDOWN, pcmk__str_none)) {
        *local_notify = FALSE;
        if (reply_to == NULL) {
            *process = TRUE;
        } else { // Not possible?
            crm_debug("Ignoring shutdown request from %s because reply_to=%s",
                      originator, reply_to);
        }
        return *process;
    }

    if (is_reply) {
        crm_trace("Will notify local clients for %s reply from %s",
                  op, originator);
        *process = FALSE;
        *needs_reply = FALSE;
        *local_notify = TRUE;
        return TRUE;
    }

  skip_is_reply:
    *process = TRUE;
    *needs_reply = FALSE;

    *local_notify = pcmk__str_eq(delegated, OUR_NODENAME, pcmk__str_casei);

    host = crm_element_value(request, PCMK__XA_CIB_HOST);
    if (pcmk__str_eq(host, OUR_NODENAME, pcmk__str_casei)) {
        crm_trace("Processing %s request sent to us from %s", op, originator);
        *needs_reply = TRUE;
        return TRUE;

    } else if (host != NULL) {
        crm_trace("Ignoring %s request intended for CIB manager on %s",
                  op, host);
        return FALSE;

    } else if(is_reply == FALSE && pcmk__str_eq(op, CRM_OP_PING, pcmk__str_casei)) {
        *needs_reply = TRUE;
    }

    crm_trace("Processing %s request broadcast by %s call %s on %s "
              "(local clients will%s be notified)", op,
              pcmk__s(crm_element_value(request, PCMK__XA_CIB_CLIENTNAME),
                      "client"),
              pcmk__s(crm_element_value(request, PCMK__XA_CIB_CALLID),
                      "without ID"),
              originator, (*local_notify? "" : "not"));
    return TRUE;
}

/*!
 * \internal
 * \brief Forward a CIB request to the appropriate target host(s)
 *
 * \param[in] request  CIB request to forward
 */
static void
forward_request(xmlNode *request)
{
    const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
    const char *section = crm_element_value(request, PCMK__XA_CIB_SECTION);
    const char *host = crm_element_value(request, PCMK__XA_CIB_HOST);
    const char *originator = crm_element_value(request, PCMK__XA_SRC);
    const char *client_name = crm_element_value(request,
                                                PCMK__XA_CIB_CLIENTNAME);
    const char *call_id = crm_element_value(request, PCMK__XA_CIB_CALLID);
    pcmk__node_status_t *peer = NULL;

    int log_level = LOG_INFO;

    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_NOOP, pcmk__str_none)) {
        log_level = LOG_DEBUG;
    }

    do_crm_log(log_level,
               "Forwarding %s operation for section %s to %s (origin=%s/%s/%s)",
               pcmk__s(op, "invalid"),
               pcmk__s(section, "all"),
               pcmk__s(host, "all"),
               pcmk__s(originator, "local"),
               pcmk__s(client_name, "unspecified"),
               pcmk__s(call_id, "unspecified"));

    crm_xml_add(request, PCMK__XA_CIB_DELEGATED_FROM, OUR_NODENAME);

    if (host != NULL) {
        peer = pcmk__get_node(0, host, NULL, pcmk__node_search_cluster_member);
    }
    pcmk__cluster_send_message(peer, pcmk_ipc_based, request);

    // Return the request to its original state
    pcmk__xe_remove_attr(request, PCMK__XA_CIB_DELEGATED_FROM);
}

static void
send_peer_reply(xmlNode *msg, const char *originator)
{
    const pcmk__node_status_t *node = NULL;

    if ((msg == NULL) || (originator == NULL)) {
        return;
    }

    // Send reply via cluster to originating node
    node = pcmk__get_node(0, originator, NULL,
                          pcmk__node_search_cluster_member);

    crm_trace("Sending request result to %s only", originator);
    crm_xml_add(msg, PCMK__XA_CIB_ISREPLYTO, originator);
    pcmk__cluster_send_message(node, pcmk_ipc_based, msg);
}

/*!
 * \internal
 * \brief Handle an IPC or CPG message containing a request
 *
 * \param[in,out] request        Request XML
 * \param[in] privileged         Whether privileged commands may be run
 *                               (see cib_server_ops[] definition)
 * \param[in] cib_client         IPC client that sent request (or NULL if CPG)
 *
 * \return Legacy Pacemaker return code
 */
int
cib_process_request(xmlNode *request, gboolean privileged,
                    const pcmk__client_t *cib_client)
{
    // @TODO: Break into multiple smaller functions
    uint32_t call_options = cib_none;

    gboolean process = TRUE;        // Whether to process request locally now
    gboolean is_update = TRUE;      // Whether request would modify CIB
    gboolean needs_reply = TRUE;    // Whether to build a reply
    gboolean local_notify = FALSE;  // Whether to notify (local) requester
    gboolean needs_forward = FALSE; // Whether to forward request somewhere else

    xmlNode *op_reply = NULL;
    xmlNode *result_diff = NULL;

    int rc = pcmk_ok;
    const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
    const char *originator = crm_element_value(request, PCMK__XA_SRC);
    const char *host = crm_element_value(request, PCMK__XA_CIB_HOST);
    const char *call_id = crm_element_value(request, PCMK__XA_CIB_CALLID);
    const char *client_id = crm_element_value(request, PCMK__XA_CIB_CLIENTID);
    const char *client_name = crm_element_value(request,
                                                PCMK__XA_CIB_CLIENTNAME);
    const char *reply_to = crm_element_value(request, PCMK__XA_CIB_ISREPLYTO);

    const cib__operation_t *operation = NULL;
    cib__op_fn_t op_function = NULL;

    rc = pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &call_options,
                            cib_none);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    if ((host != NULL) && (*host == '\0')) {
        host = NULL;
    }

    if (cib_client == NULL) {
        crm_trace("Processing peer %s operation from %s/%s on %s intended for %s (reply=%s)",
                  op, pcmk__s(client_name, "client"), call_id, originator,
                  pcmk__s(host, "all"), reply_to);
    } else {
        crm_xml_add(request, PCMK__XA_SRC, OUR_NODENAME);
        crm_trace("Processing local %s operation from %s/%s intended for %s",
                  op, pcmk__s(client_name, "client"), call_id,
                  pcmk__s(host, "all"));
    }

    rc = cib__get_operation(op, &operation);
    rc = pcmk_rc2legacy(rc);
    if (rc != pcmk_ok) {
        /* TODO: construct error reply? */
        crm_err("Pre-processing of command failed: %s", pcmk_strerror(rc));
        return rc;
    }

    op_function = based_get_op_function(operation);
    if (op_function == NULL) {
        crm_err("Operation %s not supported by CIB manager", op);
        return -EOPNOTSUPP;
    }

    if (cib_client != NULL) {
        parse_local_options(cib_client, operation, host, op,
                            &local_notify, &needs_reply, &process,
                            &needs_forward);

    } else if (!parse_peer_options(operation, request, &local_notify,
                                   &needs_reply, &process)) {
        return rc;
    }

    if (pcmk_is_set(call_options, cib_transaction)) {
        /* All requests in a transaction are processed locally against a working
         * CIB copy, and we don't notify for individual requests because the
         * entire transaction is atomic.
         *
         * We still call the option parser functions above, for the sake of log
         * messages and checking whether we're the target for peer requests.
         */
        process = TRUE;
        needs_reply = FALSE;
        local_notify = FALSE;
        needs_forward = FALSE;
    }

    is_update = pcmk_is_set(operation->flags, cib__op_attr_modifies);

    if (pcmk_is_set(call_options, cib_discard_reply)) {
        /* If the request will modify the CIB, and we are in legacy mode, we
         * need to build a reply so we can broadcast a diff, even if the
         * requester doesn't want one.
         */
        needs_reply = FALSE;
        local_notify = FALSE;
        crm_trace("Client is not interested in the reply");
    }

    if (needs_forward) {
        forward_request(request);
        return rc;
    }

    if (cib_status != pcmk_ok) {
        rc = cib_status;
        crm_err("Ignoring request because cluster configuration is invalid "
                "(please repair and restart): %s", pcmk_strerror(rc));
        op_reply = create_cib_reply(op, call_id, client_id, call_options, rc,
                                    the_cib);

    } else if (process) {
        time_t finished = 0;
        time_t now = time(NULL);
        int level = LOG_INFO;
        const char *section = crm_element_value(request, PCMK__XA_CIB_SECTION);
        const char *admin_epoch_s = NULL;
        const char *epoch_s = NULL;
        const char *num_updates_s = NULL;

        rc = cib_process_command(request, operation, op_function, &op_reply,
                                 &result_diff, privileged);

        if (!is_update) {
            level = LOG_TRACE;

        } else if (pcmk__xe_attr_is_true(request, PCMK__XA_CIB_UPDATE)) {
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

        if (the_cib != NULL) {
            admin_epoch_s = crm_element_value(the_cib, PCMK_XA_ADMIN_EPOCH);
            epoch_s = crm_element_value(the_cib, PCMK_XA_EPOCH);
            num_updates_s = crm_element_value(the_cib, PCMK_XA_NUM_UPDATES);
        }

        do_crm_log(level,
                   "Completed %s operation for section %s: %s (rc=%d, origin=%s/%s/%s, version=%s.%s.%s)",
                   op, section ? section : "'all'", pcmk_strerror(rc), rc,
                   originator ? originator : "local",
                   pcmk__s(client_name, "client"), call_id,
                   pcmk__s(admin_epoch_s, "0"),
                   pcmk__s(epoch_s, "0"),
                   pcmk__s(num_updates_s, "0"));

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

    if (is_update) {
        crm_trace("Completed pre-sync update from %s/%s/%s%s",
                  originator ? originator : "local",
                  pcmk__s(client_name, "client"), call_id,
                  local_notify?" with local notification":"");

    } else if (!needs_reply || stand_alone) {
        // This was a non-originating secondary update
        crm_trace("Completed update as secondary");

    } else if ((cib_client == NULL)
               && !pcmk_is_set(call_options, cib_discard_reply)) {

        if (is_update == FALSE || result_diff == NULL) {
            crm_trace("Request not broadcast: R/O call");

        } else if (rc != pcmk_ok) {
            crm_trace("Request not broadcast: call failed: %s", pcmk_strerror(rc));

        } else {
            crm_trace("Directing reply to %s", originator);
        }

        send_peer_reply(op_reply, originator);
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

    pcmk__xml_free(op_reply);
    pcmk__xml_free(result_diff);

    return rc;
}

/*!
 * \internal
 * \brief Get a CIB operation's input from the request XML
 *
 * \param[in]  request  CIB request XML
 * \param[in]  type     CIB operation type
 * \param[out] section  Where to store CIB section name
 *
 * \return Input XML for CIB operation
 *
 * \note If not \c NULL, the return value is a non-const pointer to part of
 *       \p request. The caller should not free it directly.
 */
static xmlNode *
prepare_input(const xmlNode *request, enum cib__op_type type,
              const char **section)
{
    xmlNode *wrapper = pcmk__xe_first_child(request, PCMK__XE_CIB_CALLDATA,
                                            NULL, NULL);
    xmlNode *input = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if (type == cib__op_apply_patch) {
        *section = NULL;
    } else {
        *section = crm_element_value(request, PCMK__XA_CIB_SECTION);
    }

    // Grab the specified section
    if ((*section != NULL) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        input = pcmk_find_cib_element(input, *section);
    }

    return input;
}

#define XPATH_CONFIG_CHANGE         \
    "//" PCMK_XE_CHANGE             \
    "[contains(@" PCMK_XA_PATH ",'/" PCMK_XE_CRM_CONFIG "/')]"

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
cib_process_command(xmlNode *request, const cib__operation_t *operation,
                    cib__op_fn_t op_function, xmlNode **reply,
                    xmlNode **cib_diff, bool privileged)
{
    xmlNode *input = NULL;
    xmlNode *output = NULL;
    xmlNode *result_cib = NULL;

    uint32_t call_options = cib_none;

    const char *op = NULL;
    const char *section = NULL;
    const char *call_id = crm_element_value(request, PCMK__XA_CIB_CALLID);
    const char *client_id = crm_element_value(request, PCMK__XA_CIB_CLIENTID);
    const char *client_name = crm_element_value(request,
                                                PCMK__XA_CIB_CLIENTNAME);
    const char *originator = crm_element_value(request, PCMK__XA_SRC);

    int rc = pcmk_ok;

    bool config_changed = false;
    bool manage_counters = true;

    static mainloop_timer_t *digest_timer = NULL;

    pcmk__assert(cib_status == pcmk_ok);

    if(digest_timer == NULL) {
        digest_timer = mainloop_timer_add("digester", 5000, FALSE, cib_digester_cb, NULL);
    }

    *reply = NULL;
    *cib_diff = NULL;

    /* Start processing the request... */
    op = crm_element_value(request, PCMK__XA_CIB_OP);
    rc = pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &call_options,
                            cib_none);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    if (!privileged && pcmk_is_set(operation->flags, cib__op_attr_privileged)) {
        rc = -EACCES;
        crm_trace("Failed due to lack of privileges: %s", pcmk_strerror(rc));
        goto done;
    }

    input = prepare_input(request, operation->type, &section);

    if (!pcmk_is_set(operation->flags, cib__op_attr_modifies)) {
        rc = cib_perform_op(NULL, op, call_options, op_function, true, section,
                            request, input, false, &config_changed, &the_cib,
                            &result_cib, NULL, &output);

        CRM_CHECK(result_cib == NULL, pcmk__xml_free(result_cib));
        goto done;
    }

    /* @COMPAT: Handle a valid write action (legacy)
     *
     * @TODO: Re-evaluate whether this is all truly legacy. The cib_force_diff
     * portion is. However, PCMK__XA_CIB_UPDATE may be set by a sync operation
     * even in non-legacy mode, and manage_counters tells xml_create_patchset()
     * whether to update version/epoch info.
     */
    if (pcmk__xe_attr_is_true(request, PCMK__XA_CIB_UPDATE)) {
        manage_counters = false;
        cib__set_call_options(call_options, "call", cib_force_diff);
        crm_trace("Global update detected");

        CRM_LOG_ASSERT(pcmk__str_any_of(op,
                                        PCMK__CIB_REQUEST_APPLY_PATCH,
                                        PCMK__CIB_REQUEST_REPLACE,
                                        NULL));
    }

    ping_modified_since = TRUE;

    // result_cib must not be modified after cib_perform_op() returns
    rc = cib_perform_op(NULL, op, call_options, op_function, false, section,
                        request, input, manage_counters, &config_changed,
                        &the_cib, &result_cib, cib_diff, &output);

    /* Always write to disk for successful ops with the flag set. This also
     * negates the need to detect ordering changes.
     */
    if ((rc == pcmk_ok)
        && pcmk_is_set(operation->flags, cib__op_attr_writes_through)) {

        config_changed = true;
    }

    if ((rc == pcmk_ok)
        && !pcmk_any_flags_set(call_options, cib_dryrun|cib_transaction)) {

        if (result_cib != the_cib) {
            if (pcmk_is_set(operation->flags, cib__op_attr_writes_through)) {
                config_changed = true;
            }

            crm_trace("Activating %s->%s%s",
                      crm_element_value(the_cib, PCMK_XA_NUM_UPDATES),
                      crm_element_value(result_cib, PCMK_XA_NUM_UPDATES),
                      (config_changed? " changed" : ""));

            rc = activateCibXml(result_cib, config_changed, op);
            if (rc != pcmk_ok) {
                crm_err("Failed to activate new CIB: %s", pcmk_strerror(rc));
            }
        }

        if ((rc == pcmk_ok) && contains_config_change(*cib_diff)) {
            cib_read_config(config_hash, result_cib);
        }

        /* @COMPAT Nodes older than feature set 3.19.0 don't support
         * transactions. In a mixed-version cluster with nodes <3.19.0, we must
         * sync the updated CIB, so that the older nodes receive the changes.
         * Any node that has already applied the transaction will ignore the
         * synced CIB.
         *
         * To ensure the updated CIB is synced from only one node, we sync it
         * from the originator.
         */
        if ((operation->type == cib__op_commit_transact)
            && pcmk__str_eq(originator, OUR_NODENAME, pcmk__str_casei)
            && compare_version(crm_element_value(the_cib,
                                                 PCMK_XA_CRM_FEATURE_SET),
                               "3.19.0") < 0) {

            sync_our_cib(request, TRUE);
        }

        mainloop_timer_stop(digest_timer);
        mainloop_timer_start(digest_timer);

    } else if (rc == -pcmk_err_schema_validation) {
        pcmk__assert(result_cib != the_cib);

        if (output != NULL) {
            crm_log_xml_info(output, "cib:output");
            pcmk__xml_free(output);
        }

        output = result_cib;

    } else {
        crm_trace("Not activating %d %d %s", rc,
                  pcmk_is_set(call_options, cib_dryrun),
                  crm_element_value(result_cib, PCMK_XA_NUM_UPDATES));

        if (result_cib != the_cib) {
            pcmk__xml_free(result_cib);
        }
    }

    if (!pcmk_any_flags_set(call_options,
                            cib_dryrun|cib_inhibit_notify|cib_transaction)) {
        crm_trace("Sending notifications %d",
                  pcmk_is_set(call_options, cib_dryrun));
        cib_diff_notify(op, rc, call_id, client_id, client_name, originator,
                        input, *cib_diff);
    }

    pcmk__log_xml_patchset(LOG_TRACE, *cib_diff);

  done:
    if (!pcmk_is_set(call_options, cib_discard_reply)) {
        *reply = create_cib_reply(op, call_id, client_id, call_options, rc,
                                  output);
    }

    if (output != the_cib) {
        pcmk__xml_free(output);
    }
    crm_trace("done");
    return rc;
}

void
cib_peer_callback(xmlNode * msg, void *private_data)
{
    const char *reason = NULL;
    const char *originator = crm_element_value(msg, PCMK__XA_SRC);

    if (pcmk__peer_cache == NULL) {
        reason = "membership not established";
        goto bail;
    }

    if (crm_element_value(msg, PCMK__XA_CIB_CLIENTNAME) == NULL) {
        crm_xml_add(msg, PCMK__XA_CIB_CLIENTNAME, originator);
    }

    /* crm_log_xml_trace(msg, "Peer[inbound]"); */
    cib_process_request(msg, TRUE, NULL);
    return;

  bail:
    if (reason) {
        const char *op = crm_element_value(msg, PCMK__XA_CIB_OP);

        crm_warn("Discarding %s message from %s: %s", op, originator, reason);
    }
}

static gboolean
cib_force_exit(gpointer data)
{
    crm_notice("Exiting immediately after %s without shutdown acknowledgment",
               pcmk__readable_interval(EXIT_ESCALATION_MS));
    terminate_cib(CRM_EX_ERROR);
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

    active = pcmk__cluster_num_active_nodes();
    if (active < 2) { // This is the last active node
        crm_info("Exiting without sending shutdown request (no active peers)");
        terminate_cib(CRM_EX_OK);
        return;
    }

    crm_info("Sending shutdown request to %d peers", active);

    leaving = pcmk__xe_create(NULL, PCMK__XE_EXIT_NOTIFICATION);
    crm_xml_add(leaving, PCMK__XA_T, PCMK__VALUE_CIB);
    crm_xml_add(leaving, PCMK__XA_CIB_OP, PCMK__CIB_REQUEST_SHUTDOWN);

    pcmk__cluster_send_message(NULL, pcmk_ipc_based, leaving);
    pcmk__xml_free(leaving);

    pcmk__create_timer(EXIT_ESCALATION_MS, cib_force_exit, NULL);
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
 * \param[in] exit_status  What exit status to use (if -1, use CRM_EX_OK, but
 *                         skip disconnecting from the cluster layer)
 */
void
terminate_cib(int exit_status)
{
    if (remote_fd > 0) {
        close(remote_fd);
        remote_fd = 0;
    }
    if (remote_tls_fd > 0) {
        close(remote_tls_fd);
        remote_tls_fd = 0;
    }

    uninitializeCib();

    // Exit immediately on error
    if (exit_status > CRM_EX_OK) {
        pcmk__stop_based_ipc(ipcs_ro, ipcs_rw, ipcs_shm);
        crm_exit(exit_status);
        return;
    }

    if ((mainloop != NULL) && g_main_loop_is_running(mainloop)) {
        /* Quit via returning from the main loop. If exit_status has the special
         * value -1, we skip the disconnect here, and it will be done when the
         * main loop returns (this allows the peer status callback to avoid
         * messing with the peer caches).
         */
        if (exit_status == CRM_EX_OK) {
            pcmk_cluster_disconnect(crm_cluster);
        }
        g_main_loop_quit(mainloop);
        return;
    }

    /* Exit cleanly. Even the peer status callback can disconnect here, because
     * we're not returning control to the caller.
     */
    pcmk_cluster_disconnect(crm_cluster);
    pcmk__stop_based_ipc(ipcs_ro, ipcs_rw, ipcs_shm);
    crm_exit(CRM_EX_OK);
}

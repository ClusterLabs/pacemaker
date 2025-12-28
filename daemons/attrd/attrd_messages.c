/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>   // PRIu32
#include <stdbool.h>

#include <glib.h>

#include <crm/cluster/internal.h>   // pcmk__get_node()
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

int minimum_protocol_version = -1;

static GHashTable *attrd_handlers = NULL;

static bool
is_sync_point_attr(const xmlAttr *attr, void *data)
{
    return pcmk__str_eq((const char *) attr->name, PCMK__XA_ATTR_SYNC_POINT,
                        pcmk__str_none);
}

static int
remove_sync_point_attribute(xmlNode *xml, void *data)
{
    pcmk__xe_remove_matching_attrs(xml, false, is_sync_point_attr, NULL);
    pcmk__xe_foreach_child(xml, PCMK_XE_OP, remove_sync_point_attribute, NULL);
    return pcmk_rc_ok;
}

/* Sync points on a multi-update IPC message to an attrd too old to support
 * multi-update messages won't work.  Strip the sync point attribute off here
 * so we don't pretend to support this situation and instead ACK the client
 * immediately.
 */
static void
remove_unsupported_sync_points(pcmk__request_t *request)
{
    if (request->xml->children != NULL && !ATTRD_SUPPORTS_MULTI_MESSAGE(minimum_protocol_version) &&
        attrd_request_has_sync_point(request->xml)) {
        pcmk__warn("Ignoring sync point in request from %s because not all "
                   "nodes support it",
                   pcmk__request_origin(request));
        remove_sync_point_attribute(request->xml, NULL);
    }
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    pcmk__err("Unknown %s request %s from %s %s",
              (request->ipc_client != NULL) ? "IPC" : "CPG",
              request->op, pcmk__request_origin_type(request),
              pcmk__request_origin(request));
    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown request type '%s' (bug?)",
                        pcmk__s(request->op, ""));
    return NULL;
}

static xmlNode *
handle_clear_failure_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        /* It is not currently possible to receive this as a peer command,
         * but will be, if we one day enable propagating this operation.
         */
        attrd_peer_clear_failure(request);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    }

    remove_unsupported_sync_points(request);

    if (attrd_request_has_sync_point(request->xml)) {
        /* If this client supplied a sync point it wants to wait for, add it to
         * the wait list. Clients on this list will not receive an ACK until
         * their sync point is hit which will result in the client stalled there
         * until it receives a response.
         *
         * All other clients will receive the expected response as normal.
         */
        attrd_add_client_to_waitlist(request);

    } else {
        /* If the client doesn't want to wait for a sync point, go ahead and
         * send the ACK immediately. Otherwise, we'll send the ACK when the
         * appropriate sync point is reached.
         */
        attrd_send_ack(request->ipc_client, request->ipc_id,
                       request->ipc_flags);
    }

    attrd_client_clear_failure(request);
    return NULL;
}

static xmlNode *
handle_confirm_request(pcmk__request_t *request)
{
    int callid = 0;

    if (request->ipc_client != NULL) {
        return handle_unknown_request(request);
    }

    pcmk__debug("Received confirmation from %s", request->peer);

    if (pcmk__xe_get_int(request->xml, PCMK__XA_CALL_ID,
                         &callid) != pcmk_rc_ok) {
        pcmk__set_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                         "Could not get callid from XML");
    } else {
        attrd_handle_confirmation(callid, request->peer);
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static xmlNode *
handle_query_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        return handle_unknown_request(request);
    }

    return attrd_client_query(request);
}

static xmlNode *
handle_remove_request(pcmk__request_t *request)
{
    const char *host = NULL;
    bool reap = false;

    if (request->ipc_client != NULL) {
        attrd_client_peer_remove(request);
        return NULL;
    }

    host = pcmk__xe_get(request->xml, PCMK__XA_ATTR_HOST);

    if (pcmk__xe_get_bool(request->xml, PCMK__XA_REAP,
                          &reap) != pcmk_rc_ok) {
        reap = true; // Default to true for backward compatibility
    }

    attrd_peer_remove(host, reap, request->peer);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static xmlNode *
handle_refresh_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        return handle_unknown_request(request);
    }

    attrd_client_refresh(request);
    return NULL;
}

static xmlNode *
handle_sync_response_request(pcmk__request_t *request)
{
    pcmk__node_status_t *peer = NULL;
    bool peer_won = false;

    if (request->ipc_client != NULL) {
        return handle_unknown_request(request);
    }

    peer = pcmk__get_node(0, request->peer, NULL,
                          pcmk__node_search_cluster_member);
    peer_won = attrd_check_for_new_writer(peer, request->xml);

    if (!pcmk__str_eq(peer->name, attrd_cluster->priv->node_name,
                      pcmk__str_casei)) {
        attrd_peer_sync_response(peer, peer_won, request->xml);
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static xmlNode *
handle_update_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        const char *host = pcmk__xe_get(request->xml, PCMK__XA_ATTR_HOST);
        pcmk__node_status_t *peer =
            pcmk__get_node(0, request->peer, NULL,
                           pcmk__node_search_cluster_member);

        attrd_peer_update(peer, request->xml, host, false);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    }

    remove_unsupported_sync_points(request);

    if (attrd_request_has_sync_point(request->xml)) {
        /* If this client supplied a sync point it wants to wait for, add it to
         * the wait list. Clients on this list will not receive an ACK until
         * their sync point is hit which will result in the client stalled there
         * until it receives a response.
         *
         * All other clients will receive the expected response as normal.
         */
        attrd_add_client_to_waitlist(request);

    } else {
        /* If the client doesn't want to wait for a sync point, go ahead and
         * send the ACK immediately. Otherwise, we'll send the ACK when the
         * appropriate sync point is reached.
         *
         * In the normal case, attrd_client_update() can be called recursively,
         * which makes where to send the ACK tricky. Doing it here ensures that
         * the client only ever receives one.
         */
        attrd_send_ack(request->ipc_client, request->ipc_id,
                       request->flags|crm_ipc_client_response);
    }

    attrd_client_update(request);
    return NULL;
}

static void
attrd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { PCMK__ATTRD_CMD_CLEAR_FAILURE, handle_clear_failure_request },
        { PCMK__ATTRD_CMD_CONFIRM, handle_confirm_request },
        { PCMK__ATTRD_CMD_PEER_REMOVE, handle_remove_request },
        { PCMK__ATTRD_CMD_QUERY, handle_query_request },
        { PCMK__ATTRD_CMD_REFRESH, handle_refresh_request },
        { PCMK__ATTRD_CMD_SYNC_RESPONSE, handle_sync_response_request },
        { PCMK__ATTRD_CMD_UPDATE, handle_update_request },
        { PCMK__ATTRD_CMD_UPDATE_DELAY, handle_update_request },
        { PCMK__ATTRD_CMD_UPDATE_BOTH, handle_update_request },
        { NULL, handle_unknown_request },
    };

    attrd_handlers = pcmk__register_handlers(handlers);
}

void
attrd_unregister_handlers(void)
{
    if (attrd_handlers != NULL) {
        g_hash_table_destroy(attrd_handlers);
        attrd_handlers = NULL;
    }
}

void
attrd_handle_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    char *log_msg = NULL;
    const char *exec_status_s = NULL;
    const char *reason = NULL;

    if (attrd_handlers == NULL) {
        attrd_register_handlers();
    }

    reply = pcmk__process_request(request, attrd_handlers);

    if (reply != NULL) {
        pcmk__log_xml_trace(reply, "Reply");

        if (request->ipc_client != NULL) {
            pcmk__ipc_send_xml(request->ipc_client, request->ipc_id, reply,
                               request->ipc_flags);
        } else {
            pcmk__err("Not sending CPG reply to client");
        }

        pcmk__xml_free(reply);
    }

    exec_status_s = pcmk_exec_status_str(request->result.execution_status);
    reason = request->result.exit_reason;
    log_msg = pcmk__assert_asprintf("Processed %s request from %s %s: %s%s%s%s",
                                    request->op,
                                    pcmk__request_origin_type(request),
                                    pcmk__request_origin(request),
                                    exec_status_s,
                                    (reason == NULL)? "" : " (",
                                    pcmk__s(reason, ""),
                                    (reason == NULL)? "" : ")");

    if (!pcmk__result_ok(&request->result)) {
        pcmk__warn("%s", log_msg);
    } else {
        pcmk__debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}

/*!
    \internal
    \brief Send or broadcast private attribute for local node with protocol version
*/
void
attrd_send_protocol(const pcmk__node_status_t *peer)
{
    xmlNode *attrd_op = pcmk__xe_create(NULL, __func__);

    pcmk__xe_set(attrd_op, PCMK__XA_T, PCMK__VALUE_ATTRD);
    pcmk__xe_set(attrd_op, PCMK__XA_SRC, crm_system_name);
    pcmk__xe_set(attrd_op, PCMK_XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    pcmk__xe_set(attrd_op, PCMK__XA_ATTR_NAME, CRM_ATTR_PROTOCOL);
    pcmk__xe_set(attrd_op, PCMK__XA_ATTR_VALUE, ATTRD_PROTOCOL_VERSION);
    pcmk__xe_set_int(attrd_op, PCMK__XA_ATTR_IS_PRIVATE, 1);
    pcmk__xe_set(attrd_op, PCMK__XA_ATTR_HOST, attrd_cluster->priv->node_name);
    pcmk__xe_set(attrd_op, PCMK__XA_ATTR_HOST_ID,
                 attrd_cluster->priv->node_xml_id);

    if (peer == NULL) {
        pcmk__debug("Broadcasting attrd protocol version "
                    ATTRD_PROTOCOL_VERSION " for node %s[%" PRIu32 "]",
                    pcmk__s(attrd_cluster->priv->node_name, "unknown"),
                    attrd_cluster->priv->node_id);

    } else {
        pcmk__debug("Sending attrd protocol version " ATTRD_PROTOCOL_VERSION " "
                    "for node %s[%" PRIu32 "] to node %s[%" PRIu32 "]",
                    pcmk__s(attrd_cluster->priv->node_name, "unknown"),
                    attrd_cluster->priv->node_id,
                    pcmk__s(peer->name, "unknown"), peer->cluster_layer_id);
    }

    attrd_send_message(peer, attrd_op, false); /* ends up at attrd_peer_message() */

    pcmk__xml_free(attrd_op);
}

gboolean
attrd_send_message(const pcmk__node_status_t *node, xmlNode *data, bool confirm)
{
    const char *op = pcmk__xe_get(data, PCMK_XA_TASK);

    pcmk__xe_set(data, PCMK__XA_T, PCMK__VALUE_ATTRD);
    pcmk__xe_set(data, PCMK__XA_ATTR_VERSION, ATTRD_PROTOCOL_VERSION);

    /* Request a confirmation from the destination peer node (which could
     * be all if node is NULL) that the message has been received and
     * acted upon.
     */
    if (!pcmk__str_eq(op, PCMK__ATTRD_CMD_CONFIRM, pcmk__str_none)) {
        pcmk__xe_set_bool(data, PCMK__XA_CONFIRM, confirm);
    }

    attrd_xml_add_writer(data);
    return pcmk__cluster_send_message(node, pcmk_ipc_attrd, data);
}

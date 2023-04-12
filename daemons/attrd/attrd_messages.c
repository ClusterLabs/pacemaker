/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/common/messages_internal.h>
#include <crm/msg_xml.h>

#include "pacemaker-attrd.h"

int minimum_protocol_version = -1;

static GHashTable *attrd_handlers = NULL;

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    crm_err("Unknown IPC request %s from %s %s",
            request->op, pcmk__request_origin_type(request),
            pcmk__request_origin(request));
    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown request type '%s' (bug?)", request->op);
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
    } else {
        if (attrd_request_has_sync_point(request->xml)) {
            /* If this client supplied a sync point it wants to wait for, add it to
             * the wait list.  Clients on this list will not receive an ACK until
             * their sync point is hit which will result in the client stalled there
             * until it receives a response.
             *
             * All other clients will receive the expected response as normal.
             */
            attrd_add_client_to_waitlist(request);

        } else {
            /* If the client doesn't want to wait for a sync point, go ahead and send
             * the ACK immediately.  Otherwise, we'll send the ACK when the appropriate
             * sync point is reached.
             */
            attrd_send_ack(request->ipc_client, request->ipc_id,
                           request->ipc_flags);
        }

        return attrd_client_clear_failure(request);
    }
}

static xmlNode *
handle_confirm_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        int callid;

        crm_debug("Received confirmation from %s", request->peer);

        if (crm_element_value_int(request->xml, XML_LRM_ATTR_CALLID, &callid) == -1) {
            pcmk__set_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                             "Could not get callid from XML");
        } else {
            attrd_handle_confirmation(callid, request->peer);
        }

        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    } else {
        return handle_unknown_request(request);
    }
}

static xmlNode *
handle_flush_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        /* Ignore. The flush command was removed in 2.0.0 but may be
         * received from peers running older versions.
         */
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    } else {
        return handle_unknown_request(request);
    }
}

static xmlNode *
handle_query_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        return handle_unknown_request(request);
    } else {
        return attrd_client_query(request);
    }
}

static xmlNode *
handle_remove_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        const char *host = crm_element_value(request->xml, PCMK__XA_ATTR_NODE_NAME);
        attrd_peer_remove(host, true, request->peer);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    } else {
        return attrd_client_peer_remove(request);
    }
}

static xmlNode *
handle_refresh_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        return handle_unknown_request(request);
    } else {
        return attrd_client_refresh(request);
    }
}

static xmlNode *
handle_sync_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        crm_node_t *peer = crm_get_peer(0, request->peer);

        attrd_peer_sync(peer, request->xml);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    } else {
        return handle_unknown_request(request);
    }
}

static xmlNode *
handle_sync_response_request(pcmk__request_t *request)
{
    if (request->ipc_client != NULL) {
        return handle_unknown_request(request);
    } else {
        if (request->peer != NULL) {
            crm_node_t *peer = crm_get_peer(0, request->peer);
            bool peer_won = attrd_check_for_new_writer(peer, request->xml);

            if (!pcmk__str_eq(peer->uname, attrd_cluster->uname, pcmk__str_casei)) {
                attrd_peer_sync_response(peer, peer_won, request->xml);
            }
        }

        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    }
}

static xmlNode *
handle_update_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        const char *host = crm_element_value(request->xml, PCMK__XA_ATTR_NODE_NAME);
        crm_node_t *peer = crm_get_peer(0, request->peer);

        attrd_peer_update(peer, request->xml, host, false);
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;

    } else {
        if (attrd_request_has_sync_point(request->xml)) {
            /* If this client supplied a sync point it wants to wait for, add it to
             * the wait list.  Clients on this list will not receive an ACK until
             * their sync point is hit which will result in the client stalled there
             * until it receives a response.
             *
             * All other clients will receive the expected response as normal.
             */
            attrd_add_client_to_waitlist(request);

        } else {
            /* If the client doesn't want to wait for a sync point, go ahead and send
             * the ACK immediately.  Otherwise, we'll send the ACK when the appropriate
             * sync point is reached.
             *
             * In the normal case, attrd_client_update can be called recursively which
             * makes where to send the ACK tricky.  Doing it here ensures the client
             * only ever receives one.
             */
            attrd_send_ack(request->ipc_client, request->ipc_id,
                           request->flags|crm_ipc_client_response);
        }

        return attrd_client_update(request);
    }
}

static void
attrd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { PCMK__ATTRD_CMD_CLEAR_FAILURE, handle_clear_failure_request },
        { PCMK__ATTRD_CMD_CONFIRM, handle_confirm_request },
        { PCMK__ATTRD_CMD_FLUSH, handle_flush_request },
        { PCMK__ATTRD_CMD_PEER_REMOVE, handle_remove_request },
        { PCMK__ATTRD_CMD_QUERY, handle_query_request },
        { PCMK__ATTRD_CMD_REFRESH, handle_refresh_request },
        { PCMK__ATTRD_CMD_SYNC, handle_sync_request },
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
    const char *reason = NULL;

    if (attrd_handlers == NULL) {
        attrd_register_handlers();
    }

    reply = pcmk__process_request(request, attrd_handlers);

    if (reply != NULL) {
        crm_log_xml_trace(reply, "Reply");

        if (request->ipc_client != NULL) {
            pcmk__ipc_send_xml(request->ipc_client, request->ipc_id, reply,
                               request->ipc_flags);
        } else {
            crm_err("Not sending CPG reply to client");
        }

        free_xml(reply);
    }

    reason = request->result.exit_reason;
    log_msg = crm_strdup_printf("Processed %s request from %s %s: %s%s%s%s",
                                request->op, pcmk__request_origin_type(request),
                                pcmk__request_origin(request),
                                pcmk_exec_status_str(request->result.execution_status),
                                (reason == NULL)? "" : " (",
                                pcmk__s(reason, ""),
                                (reason == NULL)? "" : ")");

    if (!pcmk__result_ok(&request->result)) {
        crm_warn("%s", log_msg);
    } else {
        crm_debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}

/*!
    \internal
    \brief Broadcast private attribute for local node with protocol version
*/
void
attrd_broadcast_protocol(void)
{
    xmlNode *attrd_op = create_xml_node(NULL, __func__);

    crm_xml_add(attrd_op, F_TYPE, T_ATTRD);
    crm_xml_add(attrd_op, F_ORIG, crm_system_name);
    crm_xml_add(attrd_op, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    crm_xml_add(attrd_op, PCMK__XA_ATTR_NAME, CRM_ATTR_PROTOCOL);
    crm_xml_add(attrd_op, PCMK__XA_ATTR_VALUE, ATTRD_PROTOCOL_VERSION);
    crm_xml_add_int(attrd_op, PCMK__XA_ATTR_IS_PRIVATE, 1);
    pcmk__xe_add_node(attrd_op, attrd_cluster->uname, attrd_cluster->nodeid);

    crm_debug("Broadcasting attrd protocol version %s for node %s",
              ATTRD_PROTOCOL_VERSION, attrd_cluster->uname);

    attrd_send_message(NULL, attrd_op, false); /* ends up at attrd_peer_message() */

    free_xml(attrd_op);
}

gboolean
attrd_send_message(crm_node_t *node, xmlNode *data, bool confirm)
{
    const char *op = crm_element_value(data, PCMK__XA_TASK);

    crm_xml_add(data, F_TYPE, T_ATTRD);
    crm_xml_add(data, PCMK__XA_ATTR_VERSION, ATTRD_PROTOCOL_VERSION);

    /* Request a confirmation from the destination peer node (which could
     * be all if node is NULL) that the message has been received and
     * acted upon.
     */
    if (!pcmk__str_eq(op, PCMK__ATTRD_CMD_CONFIRM, pcmk__str_none)) {
        pcmk__xe_set_bool_attr(data, PCMK__XA_CONFIRM, confirm);
    }

    attrd_xml_add_writer(data);
    return send_cluster_message(node, crm_msg_attrd, data, TRUE);
}

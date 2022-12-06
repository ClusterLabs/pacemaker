/*
 * Copyright 2015-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>

#include <crm/pengine/status.h>
#include <crm/cib.h>
#include <crm/lrmd.h>
#include <crm/lrmd_internal.h>

int lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg);
GHashTable *proxy_table = NULL;

static void
remote_proxy_notify_destroy(lrmd_t *lrmd, const char *session_id)
{
    /* sending to the remote node that an ipc connection has been destroyed */
    xmlNode *msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(msg, F_LRMD_IPC_OP, LRMD_IPC_OP_DESTROY);
    crm_xml_add(msg, F_LRMD_IPC_SESSION, session_id);
    lrmd_internal_proxy_send(lrmd, msg);
    free_xml(msg);
}

/*!
 * \internal
 * \brief Acknowledge a remote proxy shutdown request
 *
 * \param[in,out] lrmd  Connection to proxy
 */
void
remote_proxy_ack_shutdown(lrmd_t *lrmd)
{
    xmlNode *msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(msg, F_LRMD_IPC_OP, LRMD_IPC_OP_SHUTDOWN_ACK);
    lrmd_internal_proxy_send(lrmd, msg);
    free_xml(msg);
}

/*!
 * \internal
 * \brief Reject a remote proxy shutdown request
 *
 * \param[in,out] lrmd  Connection to proxy
 */
void
remote_proxy_nack_shutdown(lrmd_t *lrmd)
{
    xmlNode *msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(msg, F_LRMD_IPC_OP, LRMD_IPC_OP_SHUTDOWN_NACK);
    lrmd_internal_proxy_send(lrmd, msg);
    free_xml(msg);
}

void
remote_proxy_relay_event(remote_proxy_t *proxy, xmlNode *msg)
{
    /* sending to the remote node an event msg. */
    xmlNode *event = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(event, F_LRMD_IPC_OP, LRMD_IPC_OP_EVENT);
    crm_xml_add(event, F_LRMD_IPC_SESSION, proxy->session_id);
    add_message_xml(event, F_LRMD_IPC_MSG, msg);
    crm_log_xml_explicit(event, "EventForProxy");
    lrmd_internal_proxy_send(proxy->lrm, event);
    free_xml(event);
}

void
remote_proxy_relay_response(remote_proxy_t *proxy, xmlNode *msg, int msg_id)
{
    /* sending to the remote node a response msg. */
    xmlNode *response = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(response, F_LRMD_IPC_OP, LRMD_IPC_OP_RESPONSE);
    crm_xml_add(response, F_LRMD_IPC_SESSION, proxy->session_id);
    crm_xml_add_int(response, F_LRMD_IPC_MSG_ID, msg_id);
    add_message_xml(response, F_LRMD_IPC_MSG, msg);
    lrmd_internal_proxy_send(proxy->lrm, response);
    free_xml(response);
}

static void
remote_proxy_end_session(remote_proxy_t *proxy)
{
    if (proxy == NULL) {
        return;
    }
    crm_trace("ending session ID %s", proxy->session_id);

    if (proxy->source) {
        mainloop_del_ipc_client(proxy->source);
    }
}

void
remote_proxy_free(gpointer data)
{
    remote_proxy_t *proxy = data;

    crm_trace("freed proxy session ID %s", proxy->session_id);
    free(proxy->node_name);
    free(proxy->session_id);
    free(proxy);
}

int
remote_proxy_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    // Async responses from cib and friends to clients via pacemaker-remoted
    xmlNode *xml = NULL;
    uint32_t flags = 0;
    remote_proxy_t *proxy = userdata;

    xml = string2xml(buffer);
    if (xml == NULL) {
        crm_warn("Received a NULL msg from IPC service.");
        return 1;
    }

    flags = crm_ipc_buffer_flags(proxy->ipc);
    if (flags & crm_ipc_proxied_relay_response) {
        crm_trace("Passing response back to %.8s on %s: %.200s - request id: %d", proxy->session_id, proxy->node_name, buffer, proxy->last_request_id);
        remote_proxy_relay_response(proxy, xml, proxy->last_request_id);
        proxy->last_request_id = 0;

    } else {
        crm_trace("Passing event back to %.8s on %s: %.200s", proxy->session_id, proxy->node_name, buffer);
        remote_proxy_relay_event(proxy, xml);
    }
    free_xml(xml);
    return 1;
}


void
remote_proxy_disconnected(gpointer userdata)
{
    remote_proxy_t *proxy = userdata;

    crm_trace("destroying %p", proxy);

    proxy->source = NULL;
    proxy->ipc = NULL;

    if(proxy->lrm) {
        remote_proxy_notify_destroy(proxy->lrm, proxy->session_id);
        proxy->lrm = NULL;
    }

    g_hash_table_remove(proxy_table, proxy->session_id);
}

remote_proxy_t *
remote_proxy_new(lrmd_t *lrmd, struct ipc_client_callbacks *proxy_callbacks,
                 const char *node_name, const char *session_id, const char *channel)
{
    remote_proxy_t *proxy = NULL;

    if(channel == NULL) {
        crm_err("No channel specified to proxy");
        remote_proxy_notify_destroy(lrmd, session_id);
        return NULL;
    }

    proxy = calloc(1, sizeof(remote_proxy_t));

    proxy->node_name = strdup(node_name);
    proxy->session_id = strdup(session_id);
    proxy->lrm = lrmd;

    if (!strcmp(pcmk__message_name(crm_system_name), CRM_SYSTEM_CRMD)
        && !strcmp(pcmk__message_name(channel), CRM_SYSTEM_CRMD)) {
        // The controller doesn't need to connect to itself
        proxy->is_local = TRUE;

    } else {
        proxy->source = mainloop_add_ipc_client(channel, G_PRIORITY_LOW, 0, proxy, proxy_callbacks);
        proxy->ipc = mainloop_get_ipc_client(proxy->source);
        if (proxy->source == NULL) {
            remote_proxy_free(proxy);
            remote_proxy_notify_destroy(lrmd, session_id);
            return NULL;
        }
    }

    crm_trace("new remote proxy client established to %s on %s, session id %s",
              channel, node_name, session_id);
    g_hash_table_insert(proxy_table, proxy->session_id, proxy);

    return proxy;
}

void
remote_proxy_cb(lrmd_t *lrmd, const char *node_name, xmlNode *msg)
{
    const char *op = crm_element_value(msg, F_LRMD_IPC_OP);
    const char *session = crm_element_value(msg, F_LRMD_IPC_SESSION);
    remote_proxy_t *proxy = g_hash_table_lookup(proxy_table, session);
    int msg_id = 0;

    /* sessions are raw ipc connections to IPC,
     * all we do is proxy requests/responses exactly
     * like they are given to us at the ipc level. */

    CRM_CHECK(op != NULL, return);
    CRM_CHECK(session != NULL, return);

    crm_element_value_int(msg, F_LRMD_IPC_MSG_ID, &msg_id);
    /* This is msg from remote ipc client going to real ipc server */

    if (pcmk__str_eq(op, LRMD_IPC_OP_DESTROY, pcmk__str_casei)) {
        remote_proxy_end_session(proxy);

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_REQUEST, pcmk__str_casei)) {
        int flags = 0;
        xmlNode *request = get_message_xml(msg, F_LRMD_IPC_MSG);
        const char *name = crm_element_value(msg, F_LRMD_IPC_CLIENT);

        CRM_CHECK(request != NULL, return);

        if (proxy == NULL) {
            /* proxy connection no longer exists */
            remote_proxy_notify_destroy(lrmd, session);
            return;
        }

        // Controller requests MUST be handled by the controller, not us
        CRM_CHECK(proxy->is_local == FALSE,
                  remote_proxy_end_session(proxy); return);

        if (!crm_ipc_connected(proxy->ipc)) {
            remote_proxy_end_session(proxy);
            return;
        }
        proxy->last_request_id = 0;
        crm_element_value_int(msg, F_LRMD_IPC_MSG_FLAGS, &flags);
        crm_xml_add(request, XML_ACL_TAG_ROLE, "pacemaker-remote");

        CRM_ASSERT(node_name);
        pcmk__update_acl_user(request, F_LRMD_IPC_USER, node_name);

        if (pcmk_is_set(flags, crm_ipc_proxied)) {
            const char *type = crm_element_value(request, F_TYPE);
            int rc = 0;

            if (pcmk__str_eq(type, T_ATTRD, pcmk__str_casei)
                && crm_element_value(request,
                                     PCMK__XA_ATTR_NODE_NAME) == NULL
                && pcmk__str_any_of(crm_element_value(request, PCMK__XA_TASK),
                                    PCMK__ATTRD_CMD_UPDATE,
                                    PCMK__ATTRD_CMD_UPDATE_BOTH,
                                    PCMK__ATTRD_CMD_UPDATE_DELAY, NULL)) {
                pcmk__xe_add_node(request, proxy->node_name, 0);
            }

            rc = crm_ipc_send(proxy->ipc, request, flags, 5000, NULL);

            if(rc < 0) {
                xmlNode *op_reply = create_xml_node(NULL, "nack");

                crm_err("Could not relay %s request %d from %s to %s for %s: %s (%d)",
                         op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name, pcmk_strerror(rc), rc);

                /* Send a n'ack so the caller doesn't block */
                crm_xml_add(op_reply, "function", __func__);
                crm_xml_add_int(op_reply, "line", __LINE__);
                crm_xml_add_int(op_reply, "rc", rc);
                remote_proxy_relay_response(proxy, op_reply, msg_id);
                free_xml(op_reply);

            } else {
                crm_trace("Relayed %s request %d from %s to %s for %s",
                          op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name);
                proxy->last_request_id = msg_id;
            }

        } else {
            int rc = pcmk_ok;
            xmlNode *op_reply = NULL;
            // @COMPAT pacemaker_remoted <= 1.1.10

            crm_trace("Relaying %s request %d from %s to %s for %s",
                      op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name);

            rc = crm_ipc_send(proxy->ipc, request, flags, 10000, &op_reply);
            if(rc < 0) {
                crm_err("Could not relay %s request %d from %s to %s for %s: %s (%d)",
                         op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name, pcmk_strerror(rc), rc);
            } else {
                crm_trace("Relayed %s request %d from %s to %s for %s",
                          op, msg_id, proxy->node_name, crm_ipc_name(proxy->ipc), name);
            }

            if(op_reply) {
                remote_proxy_relay_response(proxy, op_reply, msg_id);
                free_xml(op_reply);
            }
        }
    } else {
        crm_err("Unknown proxy operation: %s", op);
    }
}

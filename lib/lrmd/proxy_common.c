/*
 * Copyright (c) 2015 David Vossel <davidvossel@gmail.com>
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
 *
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

int lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg);
GHashTable *proxy_table = NULL;

void
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
 * \brief Send an acknowledgment of a remote proxy shutdown request.
 *
 * \param[in] lrmd  Connection to proxy
 */
void
remote_proxy_ack_shutdown(lrmd_t *lrmd)
{
    xmlNode *msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(msg, F_LRMD_IPC_OP, LRMD_IPC_OP_SHUTDOWN_ACK);
    lrmd_internal_proxy_send(lrmd, msg);
    free_xml(msg);
}

void
remote_proxy_relay_event(lrmd_t *lrmd, const char *session_id, xmlNode *msg)
{
    /* sending to the remote node an event msg. */
    xmlNode *event = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(event, F_LRMD_IPC_OP, LRMD_IPC_OP_EVENT);
    crm_xml_add(event, F_LRMD_IPC_SESSION, session_id);
    add_message_xml(event, F_LRMD_IPC_MSG, msg);
    crm_log_xml_explicit(event, "EventForProxy");
    lrmd_internal_proxy_send(lrmd, event);
    free_xml(event);
}

void
remote_proxy_relay_response(lrmd_t *lrmd, const char *session_id, xmlNode *msg, int msg_id)
{
    /* sending to the remote node a response msg. */
    xmlNode *response = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(response, F_LRMD_IPC_OP, LRMD_IPC_OP_RESPONSE);
    crm_xml_add(response, F_LRMD_IPC_SESSION, session_id);
    crm_xml_add_int(response, F_LRMD_IPC_MSG_ID, msg_id);
    add_message_xml(response, F_LRMD_IPC_MSG, msg);
    lrmd_internal_proxy_send(lrmd, response);
    free_xml(response);
}

void
remote_proxy_end_session(const char *session)
{
    remote_proxy_t *proxy = g_hash_table_lookup(proxy_table, session);

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



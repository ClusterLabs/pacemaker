/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
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
#include <lrmd_private.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/cib/internal.h>

static qb_ipcs_service_t *cib_ro = NULL;
static qb_ipcs_service_t *cib_rw = NULL;
static qb_ipcs_service_t *cib_shm = NULL;

static qb_ipcs_service_t *attrd_ipcs = NULL;
static qb_ipcs_service_t *crmd_ipcs = NULL;
static qb_ipcs_service_t *stonith_ipcs = NULL;

/* ipc providers == crmd clients connecting from cluster nodes */
GHashTable *ipc_providers;
/* ipc clients == things like cibadmin, crm_resource, connecting locally */
GHashTable *ipc_clients;

static int32_t
ipc_proxy_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid, const char *ipc_channel)
{
    void *key = NULL;
    void *value = NULL;
    crm_client_t *client;
    crm_client_t *ipc_proxy = NULL;
    GHashTableIter iter;
    xmlNode *msg;

    crm_trace("Connection %p on channel %s", c, ipc_channel);

    if (g_hash_table_size(ipc_providers) == 0) {
        crm_err("No ipc providers available for uid %d gid %d", uid, gid);
        return -EREMOTEIO;
    }

    g_hash_table_iter_init(&iter, ipc_providers);
    if (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
        /* grab the first provider available, any provider in this
         * table will work. Usually there will only be one. These are
         * lrmd client connections originating for a cluster node's crmd. */
        ipc_proxy = value;
    } else {
        crm_err("No ipc providers available for uid %d gid %d", uid, gid);
        return -EREMOTEIO;
    }

    /* this new client is a local ipc client on a remote
     * guest wanting to access the ipc on any available cluster nodes */
    client = crm_client_new(c, uid, gid);
    if (client == NULL) {
        return -EREMOTEIO;
    }

    /* This ipc client is bound to a single ipc provider. If the
     * provider goes away, this client is disconnected */
    client->userdata = strdup(ipc_proxy->id);

    g_hash_table_insert(ipc_clients, client->id, client);

    msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(msg, F_LRMD_IPC_OP, "new");
    crm_xml_add(msg, F_LRMD_IPC_IPC_SERVER, ipc_channel);
    crm_xml_add(msg, F_LRMD_IPC_SESSION, client->id);
    lrmd_server_send_notify(ipc_proxy, msg);
    free_xml(msg);
    crm_debug("created new ipc proxy with session id %s", client->id);
    return 0;
}

static int32_t
crmd_proxy_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, CRM_SYSTEM_CRMD);
}

static int32_t
attrd_proxy_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, T_ATTRD);
}

static int32_t
stonith_proxy_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, "stonith-ng");
}

static int32_t
cib_proxy_accept_rw(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, cib_channel_rw);
}

static int32_t
cib_proxy_accept_ro(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, cib_channel_ro);
}

static void
ipc_proxy_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

void
ipc_proxy_forward_client(crm_client_t *ipc_proxy, xmlNode *xml)
{
    const char *session = crm_element_value(xml, F_LRMD_IPC_SESSION);
    const char *msg_type = crm_element_value(xml, F_LRMD_IPC_OP);
    xmlNode *msg = get_message_xml(xml, F_LRMD_IPC_MSG);
    crm_client_t *ipc_client = crm_client_get_by_id(session);
    int rc = 0;

    if (ipc_client == NULL) {
        xmlNode *msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
        crm_xml_add(msg, F_LRMD_IPC_OP, "destroy");
        crm_xml_add(msg, F_LRMD_IPC_SESSION, session);
        lrmd_server_send_notify(ipc_proxy, msg);
        free_xml(msg);
        return;
    }

    /* This is an event or response from the ipc provider
     * going to the local ipc client.
     *
     * Looking at the chain of events.
     *
     * -----remote node----------------|---- cluster node ------
     * ipc_client <--1--> this code <--2--> crmd <----3----> ipc server
     *
     * This function is receiving a msg from connection 2
     * and forwarding it to connection 1.
     */
    if (safe_str_eq(msg_type, "event")) {
        rc = crm_ipcs_send(ipc_client, 0, msg, TRUE);
    } else if (safe_str_eq(msg_type, "response")) {
        int msg_id = 0;
        crm_element_value_int(xml, F_LRMD_IPC_MSG_ID, &msg_id);
        rc = crm_ipcs_send(ipc_client, msg_id, msg, FALSE);
    } else if (safe_str_eq(msg_type, "destroy")) {
        qb_ipcs_disconnect(ipc_client->ipcs);
    } else {
        crm_err("Unknown ipc proxy msg type %s" , msg_type);
    }

    if (rc < 0) {
        crm_warn("IPC Proxy send to ipc client %s failed, rc = %d", ipc_client->id, rc);
    }
}

static int32_t
ipc_proxy_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crm_client_t *client = crm_client_get(c);
    crm_client_t *ipc_proxy = crm_client_get_by_id(client->userdata);
    xmlNode *request = NULL;
    xmlNode *msg = NULL;

    if (!ipc_proxy) {
        qb_ipcs_disconnect(client->ipcs);
        return 0;
    }

    /* This is a request from the local ipc client going
     * to the ipc provider.
     *
     * Looking at the chain of events.
     *
     * -----remote node----------------|---- cluster node ------
     * ipc_client <--1--> this code <--2--> crmd <----3----> ipc server
     *
     * This function is receiving a request from connection
     * 1 and forwarding it to connection 2.
     */
    request = crm_ipcs_recv(client, data, size, &id, &flags);

    if (!request) {
        return 0;
    }

    CRM_CHECK(client != NULL, crm_err("Invalid client");
              return FALSE);
    CRM_CHECK(client->id != NULL, crm_err("Invalid client: %p", client);
              return FALSE);

    msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
    crm_xml_add(msg, F_LRMD_IPC_OP, "request");
    crm_xml_add(msg, F_LRMD_IPC_SESSION, client->id);
    crm_xml_add(msg, F_LRMD_IPC_USER, client->user);
    crm_xml_add_int(msg, F_LRMD_IPC_MSG_ID, id);
    crm_xml_add_int(msg, F_LRMD_IPC_MSG_FLAGS, flags);
    add_message_xml(msg, F_LRMD_IPC_MSG, request);
    lrmd_server_send_notify(ipc_proxy, msg);
    free_xml(msg);

    return 0;
}

static int32_t
ipc_proxy_closed(qb_ipcs_connection_t * c)
{
    crm_client_t *client = crm_client_get(c);
    crm_client_t *ipc_proxy = crm_client_get_by_id(client->userdata);

    crm_trace("Connection %p", c);

    if (ipc_proxy) {
        xmlNode *msg = create_xml_node(NULL, T_LRMD_IPC_PROXY);
        crm_xml_add(msg, F_LRMD_IPC_OP, "destroy");
        crm_xml_add(msg, F_LRMD_IPC_SESSION, client->id);
        lrmd_server_send_notify(ipc_proxy, msg);
        free_xml(msg);
    }

    g_hash_table_remove(ipc_clients, client->id);

    free(client->userdata);
    client->userdata = NULL;
    crm_client_destroy(client);
    return 0;
}

static void
ipc_proxy_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

static struct qb_ipcs_service_handlers crmd_proxy_callbacks = {
    .connection_accept = crmd_proxy_accept,
    .connection_created = ipc_proxy_created,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers attrd_proxy_callbacks = {
    .connection_accept = attrd_proxy_accept,
    .connection_created = ipc_proxy_created,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers stonith_proxy_callbacks = {
    .connection_accept = stonith_proxy_accept,
    .connection_created = ipc_proxy_created,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers cib_proxy_callbacks_ro = {
    .connection_accept = cib_proxy_accept_ro,
    .connection_created = ipc_proxy_created,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers cib_proxy_callbacks_rw = {
    .connection_accept = cib_proxy_accept_rw,
    .connection_created = ipc_proxy_created,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

void
ipc_proxy_add_provider(crm_client_t *ipc_proxy)
{
    if (ipc_providers == NULL) {
        return;
    }
    g_hash_table_insert(ipc_providers, ipc_proxy->id, ipc_proxy);
}

void
ipc_proxy_remove_provider(crm_client_t *ipc_proxy)
{
    GHashTableIter iter;
    crm_client_t *ipc_client = NULL;
    char *key = NULL;
    GList *remove_these = NULL;
    GListPtr gIter = NULL;

    if (ipc_providers == NULL) {
        return;
    }

    g_hash_table_remove(ipc_providers, ipc_proxy->id);

    g_hash_table_iter_init(&iter, ipc_clients);
    while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & ipc_client)) {
        const char *proxy_id = ipc_client->userdata;
        if (safe_str_eq(proxy_id, ipc_proxy->id)) {
            crm_info("ipc proxy connection for client %s pid %d destroyed because cluster node disconnected.",
                ipc_client->id, ipc_client->pid);
            /* we can't remove during the iteration, so copy items
             * to a list we can destroy later */
            remove_these = g_list_append(remove_these, ipc_client);
        }
    }

    for (gIter = remove_these; gIter != NULL; gIter = gIter->next) {
        ipc_client = gIter->data;
        qb_ipcs_disconnect(ipc_client->ipcs);
    }

    /* just frees the list, not the elements in the list */
    g_list_free(remove_these);
}

void
ipc_proxy_init(void)
{
    ipc_clients = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, NULL);
    ipc_providers = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, NULL);

    cib_ipc_servers_init(&cib_ro,
                         &cib_rw,
                         &cib_shm,
                         &cib_proxy_callbacks_ro,
                         &cib_proxy_callbacks_rw);

    attrd_ipc_server_init(&attrd_ipcs, &attrd_proxy_callbacks);
    stonith_ipc_server_init(&stonith_ipcs, &stonith_proxy_callbacks);
    crmd_ipcs = crmd_ipc_server_init(&crmd_proxy_callbacks);
    if (crmd_ipcs == NULL) {
        crm_err("Failed to create crmd server: exiting and inhibiting respawn.");
        crm_warn("Verify pacemaker and pacemaker_remote are not both enabled.");
        crm_exit(DAEMON_RESPAWN_STOP);
    }
}

void
ipc_proxy_cleanup(void)
{
    if (ipc_providers) {
        g_hash_table_destroy(ipc_providers);
    }
    if (ipc_clients) {
        g_hash_table_destroy(ipc_clients);
    }
    cib_ipc_servers_destroy(cib_ro, cib_rw, cib_shm);
    qb_ipcs_destroy(attrd_ipcs);
    qb_ipcs_destroy(stonith_ipcs);
    qb_ipcs_destroy(crmd_ipcs);
    cib_ro = NULL;
    cib_rw = NULL;
    cib_shm = NULL;
    ipc_providers = NULL;
    ipc_clients = NULL;
}

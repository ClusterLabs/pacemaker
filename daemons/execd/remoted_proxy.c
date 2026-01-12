/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // EREMOTEIO, ENOMEM
#include <stdint.h>                     // int32_t, uint32_t
#include <stdlib.h>                     // NULL, free, size_t
#include <sys/types.h>                  // gid_t, uid_t

#include <glib.h>                       // g_byte_array_free, g_list_*
#include <libxml/tree.h>                // xmlNode
#include <qb/qbipcs.h>                  // qb_ipcs_connection_t
#include <qb/qblog.h>                   // QB_XS

#include <crm/common/internal.h>
#include <crm/common/ipc.h>             // crm_ipc_flags
#include <crm/common/logging.h>         // CRM_CHECK, CRM_LOG_ASSERT
#include <crm/common/results.h>         // pcmk_rc_*, pcmk_rc_str
#include <crm/crm.h>                    // CRM_SYSTEM_CRMD
#include <crm/lrmd.h>                   // LRMD_IPC_OP_DESTROY

#include "pacemaker-execd.h"            // lrmd_server_send_notify

static qb_ipcs_service_t *attrd_ipcs = NULL;
static qb_ipcs_service_t *based_ipcs = NULL;
static qb_ipcs_service_t *crmd_ipcs = NULL;
static qb_ipcs_service_t *fencer_ipcs = NULL;
static qb_ipcs_service_t *pacemakerd_ipcs = NULL;

// An IPC provider is a cluster node controller connecting as a client
static GList *ipc_providers = NULL;


/* ipc clients == things like cibadmin, crm_resource, connecting locally
 *
 * @TODO This should be unnecessary (pcmk__foreach_ipc_client() should be
 * sufficient)
 */
static GHashTable *ipc_clients = NULL;

/*!
 * \internal
 * \brief Get an IPC proxy provider
 *
 * \return Pointer to a provider if one exists, NULL otherwise
 *
 * \note Grab the first provider, which is the most recent connection. That way,
 *       if we haven't yet timed out an old, failed connection, we don't try to
 *       use it.
 */
pcmk__client_t *
ipc_proxy_get_provider(void)
{
    return ipc_providers? (pcmk__client_t *) (ipc_providers->data) : NULL;
}

/*!
 * \internal
 * \brief Accept a client connection on a proxy IPC server
 *
 * \param[in,out] c            New connection
 * \param[in]     uid          Client user id
 * \param[in]     gid          Client group id
 * \param[in]     ipc_channel  Name of IPC server to proxy
 *
 * \return 0 on success, -errno on error
 */
static int32_t
ipc_proxy_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid, const char *ipc_channel)
{
    pcmk__client_t *client = NULL;
    pcmk__client_t *ipc_proxy = ipc_proxy_get_provider();
    xmlNode *msg = NULL;

    if (ipc_proxy == NULL) {
        pcmk__warn("Cannot proxy IPC connection from uid %d gid %d to %s "
                   "because not connected to cluster",
                   uid, gid, ipc_channel);
        return -EREMOTEIO;
    }

    /* This new client is a local IPC client on a Pacemaker Remote controlled
     * node, needing to access cluster node IPC services.
     */
    client = pcmk__new_client(c, uid, gid);
    if (client == NULL) {
        return -ENOMEM;
    }

    /* This ipc client is bound to a single ipc provider. If the
     * provider goes away, this client is disconnected */
    client->userdata = pcmk__str_copy(ipc_proxy->id);
    client->name = pcmk__assert_asprintf("proxy-%s-%d-%.8s", ipc_channel,
                                         client->pid, client->id);

    /* Allow remote executor to distinguish between proxied local clients and
     * actual executor API clients
     */
    pcmk__set_client_flags(client, pcmk__client_to_proxy);

    g_hash_table_insert(ipc_clients, client->id, client);

    msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_NEW);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SERVER, ipc_channel);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SESSION, client->id);
    lrmd_server_send_notify(ipc_proxy, msg);
    pcmk__xml_free(msg);
    pcmk__debug("Accepted IPC proxy connection (session ID %s) from uid %d "
                "gid %d on channel %s",
                client->id, uid, gid, ipc_channel);
    return 0;
}

static int32_t
crmd_proxy_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, CRM_SYSTEM_CRMD);
}

static int32_t
attrd_proxy_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, PCMK__VALUE_ATTRD);
}

static int32_t
based_proxy_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, PCMK__SERVER_BASED_RW);
}

static int32_t
fencer_proxy_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return ipc_proxy_accept(c, uid, gid, "stonith-ng");
}

static int32_t
pacemakerd_proxy_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return -EREMOTEIO;
}

int
ipc_proxy_forward_client(pcmk__client_t *ipc_proxy, xmlNode *xml)
{
    const char *session = pcmk__xe_get(xml, PCMK__XA_LRMD_IPC_SESSION);
    const char *msg_type = pcmk__xe_get(xml, PCMK__XA_LRMD_IPC_OP);

    xmlNode *wrapper = pcmk__xe_first_child(xml, PCMK__XE_LRMD_IPC_MSG, NULL,
                                            NULL);
    xmlNode *msg = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    pcmk__client_t *ipc_client = NULL;
    int rc = pcmk_rc_ok;

    if (pcmk__str_eq(msg_type, LRMD_IPC_OP_SHUTDOWN_ACK, pcmk__str_casei)) {
        handle_shutdown_ack();
        return rc;
    }

    if (pcmk__str_eq(msg_type, LRMD_IPC_OP_SHUTDOWN_NACK, pcmk__str_casei)) {
        handle_shutdown_nack();
        return rc;
    }

    ipc_client = pcmk__find_client_by_id(session);
    if (ipc_client == NULL) {
        xmlNode *msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
        pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_DESTROY);
        pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SESSION, session);
        lrmd_server_send_notify(ipc_proxy, msg);
        pcmk__xml_free(msg);
        return rc;
    }

    /* This is an event or response from the ipc provider
     * going to the local ipc client.
     *
     * Looking at the chain of events.
     *
     * -----remote node----------------|---- cluster node ------
     * ipc_client <--1--> this code
     *    <--2--> pacemaker-controld:remote_proxy_cb/remote_proxy_relay_event()
     *    <--3--> ipc server
     *
     * This function is receiving a msg from connection 2
     * and forwarding it to connection 1.
     */

    if (pcmk__str_eq(msg_type, LRMD_IPC_OP_EVENT, pcmk__str_casei)) {
        pcmk__trace("Sending event to %s", ipc_client->id);
        rc = pcmk__ipc_send_xml(ipc_client, 0, msg, crm_ipc_server_event);

    } else if (pcmk__str_eq(msg_type, LRMD_IPC_OP_RESPONSE, pcmk__str_casei)) {
        int msg_id = 0;

        pcmk__xe_get_int(xml, PCMK__XA_LRMD_IPC_MSG_ID, &msg_id);

        pcmk__trace("Sending response to %d - %s", ipc_client->request_id,
                    ipc_client->id);
        rc = pcmk__ipc_send_xml(ipc_client, msg_id, msg, crm_ipc_flags_none);

        CRM_LOG_ASSERT(msg_id == ipc_client->request_id);
        ipc_client->request_id = 0;

    } else if (pcmk__str_eq(msg_type, LRMD_IPC_OP_DESTROY, pcmk__str_casei)) {
        qb_ipcs_disconnect(ipc_client->ipcs);

    } else {
        pcmk__err("Unknown ipc proxy msg type %s" , msg_type);
    }

    if (rc != pcmk_rc_ok) {
        pcmk__warn("Could not proxy IPC to client %s: %s " QB_XS " rc=%d",
                   ipc_client->id, pcmk_rc_str(rc), rc);
    }

    return rc;
}

/*!
 * \internal
 * \brief Handle a message from an IPC connection
 *
 * \param[in,out] c     Established IPC connection
 * \param[in]     data  The message data read from the connection - this can be
 *                      a complete IPC message or just a part of one if it's
 *                      very large
 * \param[size]   size  Unused
 *
 * \return 0 in all cases
 */
static int32_t
ipc_proxy_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    pcmk__client_t *ipc_proxy = NULL;
    xmlNode *wrapper = NULL;
    xmlNode *request = NULL;
    xmlNode *msg = NULL;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(client != NULL, return 0);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    ipc_proxy = pcmk__find_client_by_id(client->userdata);
    if (ipc_proxy == NULL) {
        qb_ipcs_disconnect(client->ipcs);
        return 0;
    }

    /* This is a request from the local ipc client going
     * to the ipc provider.
     *
     * Looking at the chain of events.
     *
     * -----remote node----------------|---- cluster node ------
     * ipc_client <--1--> this code
     *     <--2--> pacemaker-controld:remote_proxy_dispatch_internal()
     *     <--3--> ipc server
     *
     * This function is receiving a request from connection
     * 1 and forwarding it to connection 2.
     */
    rc = pcmk__ipc_msg_append(&client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        request = pcmk__client_data2xml(client, &id, &flags);
        g_byte_array_free(client->buffer, TRUE);
        client->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        pcmk__err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (client->buffer != NULL) {
            g_byte_array_free(client->buffer, TRUE);
            client->buffer = NULL;
        }

        return 0;
    }

    if (request == NULL) {
        return 0;
    }

    /* This ensures that synced request/responses happen over the event channel
     * in the controller, allowing the controller to process the messages async.
     */
    pcmk__set_ipc_flags(flags, pcmk__client_name(client), crm_ipc_proxied);
    client->request_id = id;

    msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_REQUEST);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SESSION, client->id);
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_CLIENT, pcmk__client_name(client));
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_USER, client->user);
    pcmk__xe_set_int(msg, PCMK__XA_LRMD_IPC_MSG_ID, id);

    // @TODO Use different setter for uint32_t
    pcmk__xe_set_int(msg, PCMK__XA_LRMD_IPC_MSG_FLAGS, flags);

    wrapper = pcmk__xe_create(msg, PCMK__XE_LRMD_IPC_MSG);

    pcmk__xml_copy(wrapper, request);

    lrmd_server_send_notify(ipc_proxy, msg);

    pcmk__xml_free(request);
    pcmk__xml_free(msg);
    return 0;
}

/*!
 * \internal
 * \brief Notify a proxy provider that we wish to shut down
 *
 * \param[in,out] ipc_proxy  IPC client connection to proxy provider
 *
 * \return 0 on success, -1 on error
 */
int
ipc_proxy_shutdown_req(pcmk__client_t *ipc_proxy)
{
    xmlNode *msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
    int rc;

    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_SHUTDOWN_REQ);

    /* We don't really have a session, but the controller needs this attribute
     * to recognize this as proxy communication.
     */
    pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SESSION, "0");

    rc = (lrmd_server_send_notify(ipc_proxy, msg) != pcmk_rc_ok)? -1 : 0;
    pcmk__xml_free(msg);
    return rc;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \return 0 (i.e. do not re-run this callback)
 */
static int32_t
ipc_proxy_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        pcmk__trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        pcmk__client_t *ipc_proxy = pcmk__find_client_by_id(client->userdata);

        pcmk__trace("Cleaning up closed client connection %p", c);

        if (ipc_proxy != NULL) {
            xmlNode *msg = pcmk__xe_create(NULL, PCMK__XE_LRMD_IPC_PROXY);
            pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_OP, LRMD_IPC_OP_DESTROY);
            pcmk__xe_set(msg, PCMK__XA_LRMD_IPC_SESSION, client->id);
            lrmd_server_send_notify(ipc_proxy, msg);
            pcmk__xml_free(msg);
        }

        g_hash_table_remove(ipc_clients, client->id);
        g_clear_pointer(&client->userdata, free);
        pcmk__free_client(client);
    }

    return 0;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \note We handle a destroyed connection the same as a closed one,
 *       but we need a separate handler because the return type is different.
 */
static void
ipc_proxy_destroy(qb_ipcs_connection_t *c)
{
    pcmk__trace("Destroying client connection %p", c);
    ipc_proxy_closed(c);
}

static struct qb_ipcs_service_handlers crmd_proxy_callbacks = {
    .connection_accept = crmd_proxy_accept,
    .connection_created = NULL,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers attrd_proxy_callbacks = {
    .connection_accept = attrd_proxy_accept,
    .connection_created = NULL,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers based_proxy_callbacks = {
    .connection_accept = based_proxy_accept,
    .connection_created = NULL,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers fencer_proxy_callbacks = {
    .connection_accept = fencer_proxy_accept,
    .connection_created = NULL,
    .msg_process = ipc_proxy_dispatch,
    .connection_closed = ipc_proxy_closed,
    .connection_destroyed = ipc_proxy_destroy
};

static struct qb_ipcs_service_handlers pacemakerd_proxy_callbacks = {
    .connection_accept = pacemakerd_proxy_accept,
    .connection_created = NULL,
    .msg_process = NULL,
    .connection_closed = NULL,
    .connection_destroyed = NULL
};

void
ipc_proxy_add_provider(pcmk__client_t *ipc_proxy)
{
    // Prepending ensures the most recent connection is always first
    ipc_providers = g_list_prepend(ipc_providers, ipc_proxy);
}

void
ipc_proxy_remove_provider(pcmk__client_t *ipc_proxy)
{
    GHashTableIter iter;
    pcmk__client_t *ipc_client = NULL;
    char *key = NULL;
    GList *remove_these = NULL;
    GList *gIter = NULL;

    ipc_providers = g_list_remove(ipc_providers, ipc_proxy);

    g_hash_table_iter_init(&iter, ipc_clients);
    while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & ipc_client)) {
        const char *proxy_id = ipc_client->userdata;
        if (pcmk__str_eq(proxy_id, ipc_proxy->id, pcmk__str_casei)) {
            pcmk__info("IPC proxy connection for client %s pid %d destroyed "
                       "because cluster node disconnected",
                       ipc_client->id, ipc_client->pid);
            /* we can't remove during the iteration, so copy items
             * to a list we can destroy later */
            remove_these = g_list_append(remove_these, ipc_client);
        }
    }

    for (gIter = remove_these; gIter != NULL; gIter = gIter->next) {
        ipc_client = gIter->data;

        // Disconnection callback will free the client here
        qb_ipcs_disconnect(ipc_client->ipcs);
    }

    /* just frees the list, not the elements in the list */
    g_list_free(remove_these);
}

void
ipc_proxy_init(void)
{
    ipc_clients = pcmk__strkey_table(NULL, NULL);

    pcmk__serve_attrd_ipc(&attrd_ipcs, &attrd_proxy_callbacks);
    pcmk__serve_based_ipc(&based_ipcs, &based_proxy_callbacks);
    pcmk__serve_fenced_ipc(&fencer_ipcs, &fencer_proxy_callbacks);
    pcmk__serve_pacemakerd_ipc(&pacemakerd_ipcs, &pacemakerd_proxy_callbacks);
    crmd_ipcs = pcmk__serve_controld_ipc(&crmd_proxy_callbacks);
    if (crmd_ipcs == NULL) {
        pcmk__err("Failed to create controller: exiting and inhibiting "
                  "respawn");
        pcmk__warn("Verify pacemaker and pacemaker_remote are not both "
                   "enabled");
        crm_exit(CRM_EX_FATAL);
    }
}

void
ipc_proxy_cleanup(void)
{
    g_clear_pointer(&ipc_providers, g_list_free);
    g_clear_pointer(&ipc_clients, g_hash_table_destroy);

    g_clear_pointer(&attrd_ipcs, qb_ipcs_destroy);
    g_clear_pointer(&based_ipcs, qb_ipcs_destroy);
    g_clear_pointer(&crmd_ipcs, qb_ipcs_destroy);
    g_clear_pointer(&fencer_ipcs, qb_ipcs_destroy);
    g_clear_pointer(&pacemakerd_ipcs, qb_ipcs_destroy);
}

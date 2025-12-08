/*
 * Copyright 2009-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                            // ECONNREFUSED, ENOMEM
#include <inttypes.h>                         // int32_t, uint32_t, PRIu32
#include <stdio.h>                            // NULL, size_t
#include <sys/types.h>                        // gid_t, uid_t

#include <libxml/tree.h>                      // xmlNode
#include <glib.h>                             // g_byte_array_free, TRUE
#include <qb/qbipcs.h>                        // for qb_ipcs_connection_t

#include "pacemaker-fenced.h"                 // fenced_get_local_node

#include <crm/common/ipc.h>                   // crm_ipc_flags, pcmk_ipc_fenced
#include <crm/common/results.h>               // pcmk_rc_*, pcmk_rc_str
#include <crm/crm.h>                          // CRM_OP_RM_NODE_CACHE
#include <crm/stonith-ng.h>                   // stonith_call_options

static qb_ipcs_service_t *ipcs = NULL;

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in,out] c    New connection
 * \param[in]     uid  Client user id
 * \param[in]     gid  Client group id
 *
 * \return 0 on success, -errno otherwise
 */
static int32_t
fenced_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crm_trace("New client connection %p", c);
    if (stonith_shutdown_flag) {
        crm_info("Ignoring new connection from pid %d during shutdown",
                 pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

/*!
 * \internal
 * \brief Handle a message from an IPC connection
 *
 * \param[in,out] c     Established IPC connection
 * \param[in]     data  The message data read from the connection - this can be
 *                      a complete IPC message or just a part of one if it's
 *                      very large
 * \param[in]     size  Unused
 *
 * \return 0 in all cases
 */
static int32_t
fenced_ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    uint32_t call_options = st_opt_none;
    xmlNode *msg = NULL;
    pcmk__client_t *client = pcmk__find_client(c);
    const char *op = NULL;
    int rc = pcmk_rc_ok;

    CRM_CHECK(client != NULL, return 0);

    rc = pcmk__ipc_msg_append(&client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        msg = pcmk__client_data2xml(client, &id, &flags);
        g_byte_array_free(client->buffer, TRUE);
        client->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        crm_err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (client->buffer != NULL) {
            g_byte_array_free(client->buffer, TRUE);
            client->buffer = NULL;
        }

        return 0;
    }

    if (msg == NULL) {
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_NACK, NULL, CRM_EX_PROTOCOL);
        return 0;
    }

    op = pcmk__xe_get(msg, PCMK__XA_CRM_TASK);
    if(pcmk__str_eq(op, CRM_OP_RM_NODE_CACHE, pcmk__str_casei)) {
        pcmk__xe_set(msg, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
        pcmk__xe_set(msg, PCMK__XA_ST_OP, op);
        pcmk__xe_set(msg, PCMK__XA_ST_CLIENTID, client->id);
        pcmk__xe_set(msg, PCMK__XA_ST_CLIENTNAME, pcmk__client_name(client));
        pcmk__xe_set(msg, PCMK__XA_ST_CLIENTNODE, fenced_get_local_node());

        pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, msg);
        pcmk__xml_free(msg);
        return 0;
    }

    if (client->name == NULL) {
        const char *value = pcmk__xe_get(msg, PCMK__XA_ST_CLIENTNAME);

        client->name = pcmk__assert_asprintf("%s.%u", pcmk__s(value, "unknown"),
                                             client->pid);
    }

    rc = pcmk__xe_get_flags(msg, PCMK__XA_ST_CALLOPT, &call_options,
                            st_opt_none);
    if (rc != pcmk_rc_ok) {
        crm_warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    crm_trace("Flags %#08" PRIx32 "/%#08x for command %" PRIu32
              " from client %s", flags, call_options, id, pcmk__client_name(client));

    if (pcmk__is_set(call_options, st_opt_sync_call)) {
        pcmk__assert(pcmk__is_set(flags, crm_ipc_client_response));
        CRM_LOG_ASSERT(client->request_id == 0);     /* This means the client has two synchronous events in-flight */
        client->request_id = id;     /* Reply only to the last one */
    }

    pcmk__xe_set(msg, PCMK__XA_ST_CLIENTID, client->id);
    pcmk__xe_set(msg, PCMK__XA_ST_CLIENTNAME, pcmk__client_name(client));
    pcmk__xe_set(msg, PCMK__XA_ST_CLIENTNODE, fenced_get_local_node());

    crm_log_xml_trace(msg, "ipc-received");
    stonith_command(client, id, flags, msg, NULL);

    pcmk__xml_free(msg);
    return 0;
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
fenced_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        crm_trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        crm_trace("Cleaning up closed client connection %p", c);
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
fenced_ipc_destroy(qb_ipcs_connection_t *c)
{
    crm_trace("Destroying client connection %p", c);
    fenced_ipc_closed(c);
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = fenced_ipc_accept,
    .connection_created = NULL,
    .msg_process = fenced_ipc_dispatch,
    .connection_closed = fenced_ipc_closed,
    .connection_destroyed = fenced_ipc_destroy
};

void
fenced_ipc_cleanup(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        qb_ipcs_destroy(ipcs);
        ipcs = NULL;
    }

    fenced_unregister_handlers();
    pcmk__client_cleanup();
}

/*!
 * \internal
 * \brief Set up fenced IPC communication
 */
void
fenced_ipc_init(void)
{
    pcmk__serve_fenced_ipc(&ipcs, &ipc_callbacks);
}

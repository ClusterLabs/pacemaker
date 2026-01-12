/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // ECONNREFUSED, ENOMEM
#include <stddef.h>                     // NULL, size_t
#include <stdint.h>                     // int32_t, uint32_t
#include <sys/types.h>                  // gid_t, uid_t

#include <glib.h>                       // g_byte_array_free(), TRUE
#include <libxml/tree.h>                // xmlNode
#include <qb/qbipcs.h>                  // qb_ipcs_*

#include <crm/cib.h>                    // cib_none, cib_sync_call
#include <crm/common/internal.h>        // pcmk__client_*, pcmk__trace, etc.
#include <crm/common/ipc.h>             // crm_ipc_client_response
#include <crm/common/logging.h>         // CRM_CHECK(), CRM_LOG_ASSERT()
#include <crm/common/results.h>         // CRM_EX_PROTOCOL, pcmk_rc_*
#include <crm/crm.h>                    // CRM_OP_REGISTER

#include "pacemaker-based.h"

static qb_ipcs_service_t *ipcs = NULL;

/*!
 * \internal
 * \brief Accept a new client IPC connection
 *
 * \param[in,out] c    New connection
 * \param[in]     uid  Client user id
 * \param[in]     gid  Client group id
 *
 * \return 0 on success, \c -errno otherwise
 */
static int32_t
based_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    if (based_shutting_down()) {
        pcmk__info("Ignoring new IPC client [%d] during shutdown",
                   pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    pcmk__trace("New client connection %p", c);
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
based_ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    uint32_t call_options = cib_none;
    xmlNode *msg = NULL;
    pcmk__client_t *client = pcmk__find_client(c);
    const char *op = NULL;
    int rc = pcmk_rc_ok;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(client != NULL, return 0);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

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
        pcmk__err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (client->buffer != NULL) {
            g_byte_array_free(client->buffer, TRUE);
            client->buffer = NULL;
        }

        return 0;
    }

    if (msg == NULL) {
        pcmk__debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_NACK, NULL,
                           CRM_EX_PROTOCOL);
        return 0;
    }

    if (client->name == NULL) {
        const char *value = pcmk__xe_get(msg, PCMK__XA_CIB_CLIENTNAME);

        client->name = pcmk__assert_asprintf("%s.%u", pcmk__s(value, "unknown"),
                                             client->pid);
    }

    rc = pcmk__xe_get_flags(msg, PCMK__XA_CIB_CALLOPT, &call_options, cib_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    /* Requests with cib_transaction set should not be sent to based directly
     * (that is, outside of a commit-transaction request)
     */
    if (pcmk__is_set(call_options, cib_transaction)) {
        pcmk__warn("Ignoring CIB request from IPC client %s with "
                   "cib_transaction flag set outside of any transaction",
                   client->name);
        return 0;
    }

    if (pcmk__is_set(call_options, cib_sync_call)) {
        pcmk__assert(pcmk__is_set(flags, crm_ipc_client_response));

        // If false, the client has two synchronous events in flight
        CRM_LOG_ASSERT(client->request_id == 0);

        // Reply only to the last one
        client->request_id = id;
    }

    pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTID, client->id);
    pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTNAME, client->name);

    CRM_LOG_ASSERT(client->user != NULL);
    pcmk__update_acl_user(msg, PCMK__XA_CIB_USER, client->user);

    op = pcmk__xe_get(msg, PCMK__XA_CIB_OP);

    if (pcmk__str_eq(op, CRM_OP_REGISTER, pcmk__str_none)) {
        xmlNode *ack = NULL;

        if (!pcmk__is_set(flags, crm_ipc_client_response)) {
            return 0;
        }

        ack = pcmk__xe_create(NULL, __func__);
        pcmk__xe_set(ack, PCMK__XA_CIB_OP, CRM_OP_REGISTER);
        pcmk__xe_set(ack, PCMK__XA_CIB_CLIENTID, client->id);
        pcmk__ipc_send_xml(client, id, ack, flags);

        client->request_id = 0;
        pcmk__xml_free(ack);
        return 0;
    }

    if (pcmk__str_eq(op, PCMK__VALUE_CIB_NOTIFY, pcmk__str_none)) {
        crm_exit_t status = CRM_EX_OK;
        int rc = based_update_notify_flags(msg, client);

        if (rc != pcmk_rc_ok) {
            status = CRM_EX_INVALID_PARAM;
        }

        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL, status);

    } else {
        pcmk__request_t request = {
            .ipc_client     = client,
            .ipc_id         = id,
            .ipc_flags      = flags,
            .peer           = NULL,
            .xml            = msg,
            .call_options   = call_options,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = pcmk__xe_get_copy(request.xml, PCMK__XA_CIB_OP);
        CRM_CHECK(request.op != NULL, return 0);

        if (pcmk__is_set(request.call_options, cib_sync_call)) {
            pcmk__set_request_flags(&request, pcmk__request_sync);
        }

        based_handle_request(&request);
    }

    pcmk__xml_free(msg);
    return 0;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 *
 * \return 0 (do not re-run this callback)
 */
static int32_t
based_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        pcmk__trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        pcmk__trace("Cleaning up closed client connection %p", c);
        pcmk__free_client(client);
    }

    return 0;
}

/*!
 * \internal
 * \brief Destroy a client IPC connection
 *
 * \param[in] c  Connection to destroy
 */
static void
based_ipc_destroy(qb_ipcs_connection_t *c)
{
    pcmk__trace("Destroying client connection %p", c);
    based_ipc_closed(c);
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = based_ipc_accept,
    .connection_created = NULL,
    .msg_process = based_ipc_dispatch,
    .connection_closed = based_ipc_closed,
    .connection_destroyed = based_ipc_destroy,
};

/*!
 * \internal
 * \brief Set up \c based IPC communication
 */
void
based_ipc_init(void)
{
    pcmk__serve_based_ipc(&ipcs, &ipc_callbacks);
}

/*!
 * \internal
 * \brief Clean up \c based IPC communication
 */
void
based_ipc_cleanup(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        g_clear_pointer(&ipcs, qb_ipcs_destroy);
    }

    /* Drop remote clients here because they're part of the IPC client table and
     * must be dropped before \c pcmk__client_cleanup()
     */
    based_drop_remote_clients();

    /* @TODO This is where we would call a based_unregister_handlers() to align
     * with other daemons' IPC cleanup functions. Such a function does not yet
     * exist; based doesn't use pcmk__request_t yet.
     */

    pcmk__client_cleanup();
}

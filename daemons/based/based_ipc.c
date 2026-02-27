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
#include <stdbool.h>
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

qb_ipcs_service_t *ipcs_ro = NULL;
qb_ipcs_service_t *ipcs_rw = NULL;
qb_ipcs_service_t *ipcs_shm = NULL;

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
    if (cib_shutdown_flag) {
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
 * \param[in,out] c           Established IPC connection
 * \param[in]     data        The message data read from the connection - this
 *                            can be a complete IPC message or just a part of
 *                            one if it's very large
 * \param[in]     privileged  If \c true, operations with
 *                            \c cib__op_attr_privileged can be run
 *
 * \return 0 in all cases
 */
static int32_t
dispatch_common(qb_ipcs_connection_t *c, void *data, bool privileged)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    uint32_t call_options = cib_none;
    xmlNode *msg = NULL;
    pcmk__client_t *client = pcmk__find_client(c);
    const char *op = NULL;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(client != NULL, return 0);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    pcmk__trace("Dispatching %sprivileged request from client %s",
                (privileged? "" : "un"), client->id);

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
        pcmk__ipc_send_ack(client, id, flags, NULL, CRM_EX_PROTOCOL);
        return 0;
    }

    if (client->name == NULL) {
        const char *value = pcmk__xe_get(msg, PCMK__XA_CIB_CLIENTNAME);

        if (value == NULL) {
            client->name = pcmk__itoa(client->pid);
        } else {
            client->name = pcmk__str_copy(value);
        }
    }

    rc = pcmk__xe_get_flags(msg, PCMK__XA_CIB_CALLOPT, &call_options, cib_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request from IPC client %s: %s",
                   client->name, pcmk_rc_str(rc));
        pcmk__log_xml_info(msg, "bad-call-opts");
    }

    /* Requests with cib_transaction set should not be sent to based directly
     * (that is, outside of a commit-transaction request)
     */
    if (pcmk__is_set(call_options, cib_transaction)) {
        pcmk__warn("Ignoring CIB request from IPC client %s with "
                   "cib_transaction flag set outside of any transaction",
                   client->name);
        pcmk__log_xml_info(msg, "no-transaction");
        return 0;
    }

    if (pcmk__is_set(call_options, cib_sync_call)) {
        CRM_LOG_ASSERT(flags & crm_ipc_client_response);

        // If false, the client has two synchronous events in flight
        CRM_LOG_ASSERT(client->request_id == 0);

        // Reply only to the last one
        client->request_id = id;
    }

    pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTID, client->id);
    pcmk__xe_set(msg, PCMK__XA_CIB_CLIENTNAME, client->name);

    CRM_LOG_ASSERT(client->user != NULL);
    pcmk__update_acl_user(msg, PCMK__XA_CIB_USER, client->user);

    pcmk__log_xml_trace(msg, "ipc-request");

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

        pcmk__ipc_send_ack(client, id, flags, NULL, status);
        return 0;
    }

    based_process_request(msg, privileged, client);
    pcmk__xml_free(msg);
    return 0;
}

/*!
 * \internal
 * \brief Handle a message from a read-only IPC connection
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
based_ipc_dispatch_ro(qb_ipcs_connection_t *c, void *data, size_t size)
{
    return dispatch_common(c, data, false);
}

/*!
 * \internal
 * \brief Handle a message from a read/write IPC connection
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
based_ipc_dispatch_rw(qb_ipcs_connection_t *c, void *data, size_t size)
{
    return dispatch_common(c, data, true);
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

    /* Shut down if this was the last client to leave.
     *
     * @TODO Is it correct to do this for destroy but not for closed? Other
     * daemons handle closed and destroyed connections in the same way.
     */
    if (cib_shutdown_flag) {
        based_shutdown(0);
    }
}

struct qb_ipcs_service_handlers ipc_ro_callbacks = {
    .connection_accept = based_ipc_accept,
    .connection_created = NULL,
    .msg_process = based_ipc_dispatch_ro,
    .connection_closed = based_ipc_closed,
    .connection_destroyed = based_ipc_destroy,
};

struct qb_ipcs_service_handlers ipc_rw_callbacks = {
    .connection_accept = based_ipc_accept,
    .connection_created = NULL,
    .msg_process = based_ipc_dispatch_rw,
    .connection_closed = based_ipc_closed,
    .connection_destroyed = based_ipc_destroy,
};

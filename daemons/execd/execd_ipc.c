/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                          // ENOMEM
#include <stddef.h>                         // NULL, size_t
#include <stdint.h>                         // int32_t, uint32_t
#include <sys/types.h>                      // gid_t, uid_t

#include <glib.h>                           // g_byte_array_free, TRUE
#include <libxml/tree.h>                    // xmlNode
#include <qb/qbipcs.h>                      // qb_ipcs_connection_t

#include <crm/common/internal.h>            // pcmk__client_t, pcmk__find_client
#include <crm/common/ipc.h>                 // crm_ipc_client_response
#include <crm/common/logging.h>             // CRM_CHECK
#include <crm/common/results.h>             // pcmk_rc_*, pcmk_rc_str

#include "pacemaker-execd.h"                // client_disconnect_cleanup

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
execd_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    pcmk__trace("New client connection %p", c);
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

/*!
 * \internal
 * \brief Handle a newly created connection
 *
 * \param[in,out] c  New connection
 */
static void
execd_ipc_created(qb_ipcs_connection_t *c)
{
    pcmk__client_t *new_client = pcmk__find_client(c);

    pcmk__trace("New client connection %p", c);
    pcmk__assert(new_client != NULL);
    /* Now that the connection is offically established, alert
     * the other clients a new connection exists. */

    notify_of_new_client(new_client);
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
execd_ipc_closed(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        pcmk__trace("Ignoring request to clean up unknown connection %p", c);
    } else {
        pcmk__trace("Cleaning up closed client connection %p", c);
        client_disconnect_cleanup(client->id);
#ifdef PCMK__COMPILE_REMOTE
        ipc_proxy_remove_provider(client);
#endif
        lrmd_client_destroy(client);
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
execd_ipc_destroy(qb_ipcs_connection_t *c)
{
    pcmk__trace("Destroying client connection %p", c);
    execd_ipc_closed(c);
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
execd_ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *msg = NULL;

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

    CRM_CHECK(pcmk__is_set(flags, crm_ipc_client_response), goto done);

    if ((msg == NULL) || execd_invalid_msg(msg)) {
        pcmk__debug("Unrecognizable IPC data from PID %d", pcmk__client_pid(c));
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL, CRM_EX_PROTOCOL);
    } else {
        pcmk__request_t request = {
            .ipc_client     = client,
            .ipc_id         = id,
            .ipc_flags      = flags,
            .peer           = NULL,
            .xml            = msg,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = pcmk__xe_get_copy(request.xml, PCMK__XA_LRMD_OP);
        CRM_CHECK(request.op != NULL, goto done);

        execd_handle_request(&request);
    }

done:
    pcmk__xml_free(msg);
    return 0;
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = execd_ipc_accept,
    .connection_created = execd_ipc_created,
    .msg_process = execd_ipc_dispatch,
    .connection_closed = execd_ipc_closed,
    .connection_destroyed = execd_ipc_destroy
};

/*!
 * \internal
 * \brief Clean up executor IPC communication
 */
void
execd_ipc_cleanup(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        g_clear_pointer(&ipcs, qb_ipcs_destroy);
    }

    pcmk__client_cleanup();
}

/*!
 * \internal
 * \brief Set up executor IPC communication
 */
void
execd_ipc_init(void)
{
    pcmk__serve_execd_ipc(&ipcs, &ipc_callbacks);
}

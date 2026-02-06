/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // ENOMEM
#include <stddef.h>                     // NULL, size_t
#include <stdint.h>                     // int32_t, uint32_t
#include <sys/types.h>                  // gid_t, uid_t

#include <glib.h>                       // g_byte_array_free, TRUE
#include <libxml/tree.h>                // xmlNode
#include <qb/qbipcs.h>                  // qb_ipcs_connection_t

#include <crm/crm.h>                    // CRM_SYSTEM_PENGINE
#include <crm/common/results.h>         // CRM_EX_*, pcmk_rc_*

#include "pacemaker-schedulerd.h"       // schedulerd_handle_request

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
schedulerd_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
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
schedulerd_ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    xmlNode *msg = NULL;
    pcmk__client_t *client = pcmk__find_client(c);
    const char *sys_to = NULL;

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
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_PROTOCOL);
        return 0;
    }

    sys_to = pcmk__xe_get(msg, PCMK__XA_CRM_SYS_TO);

    if (pcmk__str_eq(pcmk__xe_get(msg, PCMK__XA_SUBT), PCMK__VALUE_RESPONSE,
                     pcmk__str_none)) {
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_INDETERMINATE);
        pcmk__info("Ignoring IPC reply from %s", pcmk__client_name(client));

    } else if (!pcmk__str_eq(sys_to, CRM_SYSTEM_PENGINE, pcmk__str_none)) {
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_INDETERMINATE);
        pcmk__info("Ignoring invalid IPC message: to '%s' not "
                   CRM_SYSTEM_PENGINE, pcmk__s(sys_to, ""));

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

        request.op = pcmk__xe_get_copy(request.xml, PCMK__XA_CRM_TASK);
        CRM_CHECK(request.op != NULL, goto done);

        schedulerd_handle_request(&request);
    }

done:
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
schedulerd_ipc_closed(qb_ipcs_connection_t *c)
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
 *
 * \note We handle a destroyed connection the same as a closed one,
 *       but we need a separate handler because the return type is different.
 */
static void
schedulerd_ipc_destroy(qb_ipcs_connection_t *c)
{
    pcmk__trace("Destroying client connection %p", c);
    schedulerd_ipc_closed(c);
}

static struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = schedulerd_ipc_accept,
    .connection_created = NULL,
    .msg_process = schedulerd_ipc_dispatch,
    .connection_closed = schedulerd_ipc_closed,
    .connection_destroyed = schedulerd_ipc_destroy
};

/*!
 * \internal
 * \brief Clean up schedulerd IPC communication
 */
void
schedulerd_ipc_cleanup(void)
{
    if (ipcs != NULL) {
        pcmk__drop_all_clients(ipcs);
        g_clear_pointer(&ipcs, qb_ipcs_destroy);
    }

    pcmk__client_cleanup();
}

/*!
 * \internal
 * \brief Set up schedulerd IPC communication
 */
void
schedulerd_ipc_init(void)
{
    pcmk__serve_schedulerd_ipc(&ipcs, &ipc_callbacks);
}

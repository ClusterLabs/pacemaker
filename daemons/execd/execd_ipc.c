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

#include <glib.h>                           // g_byte_array_free, FALSE, TRUE
#include <libxml/tree.h>                    // xmlNode
#include <qb/qbipcs.h>                      // qb_ipcs_connection_t

#include <crm/common/ipc.h>                 // crm_ipc_client_response
#include <crm/common/results.h>             // pcmk_rc_*, pcmk_rc_str

#include "pacemaker-execd.h"                // client_disconnect_cleanup

static int32_t
execd_ipc_accept(qb_ipcs_connection_t *qbc, uid_t uid, gid_t gid)
{
    pcmk__trace("Connection %p", qbc);
    if (pcmk__new_client(qbc, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static void
execd_ipc_created(qb_ipcs_connection_t *qbc)
{
    pcmk__client_t *new_client = pcmk__find_client(qbc);

    pcmk__trace("Connection %p", qbc);
    pcmk__assert(new_client != NULL);
    /* Now that the connection is offically established, alert
     * the other clients a new connection exists. */

    notify_of_new_client(new_client);
}

static int32_t
execd_ipc_closed(qb_ipcs_connection_t *qbc)
{
    pcmk__client_t *client = pcmk__find_client(qbc);

    if (client == NULL) {
        return 0;
    }

    pcmk__trace("Connection %p", qbc);
    client_disconnect_cleanup(client->id);
#ifdef PCMK__COMPILE_REMOTE
    ipc_proxy_remove_provider(client);
#endif
    lrmd_client_destroy(client);
    return 0;
}

static void
execd_ipc_destroy(qb_ipcs_connection_t *qbc)
{
    execd_ipc_closed(qbc);
    pcmk__trace("Connection %p", qbc);
}

static int32_t
execd_ipc_dispatch(qb_ipcs_connection_t *qbc, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(qbc);
    xmlNode *msg = NULL;

    CRM_CHECK(client != NULL,
              pcmk__err("Invalid client");
              return FALSE);
    CRM_CHECK(client->id != NULL,
              pcmk__err("Invalid client: %p", client);
              return FALSE);

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

    CRM_CHECK(pcmk__is_set(flags, crm_ipc_client_response),
              pcmk__err("Invalid client request: %p", client);
              return FALSE);

    if (!msg) {
        return 0;
    }

    execd_process_message(client, id, flags, msg);
    pcmk__xml_free(msg);
    return 0;
}

struct qb_ipcs_service_handlers lrmd_ipc_callbacks = {
    .connection_accept = execd_ipc_accept,
    .connection_created = execd_ipc_created,
    .msg_process = execd_ipc_dispatch,
    .connection_closed = execd_ipc_closed,
    .connection_destroyed = execd_ipc_destroy
};

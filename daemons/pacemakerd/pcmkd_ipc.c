/*
 * Copyright 2010-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>                    // true
#include <stddef.h>                     // NULL, size_t
#include <stdint.h>                     // int32_t, uint32_t
#include <sys/types.h>                  // gid_t, uid_t

#include <qb/qbipcs.h>                  // qb_ipcs_connection_t

#include <crm/common/mainloop.h>        // mainloop_set_trigger

#include "pacemakerd.h"                 // pacemakerd_handle_request

static int32_t
ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return pcmk__daemon_ipc_accept(&pacemakerd, c, uid, gid);
}

static int32_t
ipc_closed(qb_ipcs_connection_t *c)
{
    return pcmk__daemon_ipc_closed(&pacemakerd, c);
}

void
pacemakerd_ipc_closed(pcmk__daemon_t *d, pcmk__client_t *client)
{
    if (shutdown_complete_state_reported_to == client->pid) {
        shutdown_complete_state_reported_client_closed = true;
        mainloop_set_trigger(shutdown_trigger);
    }

    pcmk__free_client(client);
}

static void
ipc_destroy(qb_ipcs_connection_t *c)
{
    pcmk__daemon_ipc_destroy(&pacemakerd, c);
}

static int32_t
ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    pcmk__daemon_ipc_dispatch(&pacemakerd, c, data, size);
    return 0;
}

void
pacemakerd_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request)
{
    request->op = pcmk__xe_get_copy(request->xml, d->op);
    CRM_CHECK(request->op != NULL, return);

    pacemakerd_handle_request(request);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = ipc_accept,
    .connection_created = NULL,
    .msg_process = ipc_dispatch,
    .connection_closed = ipc_closed,
    .connection_destroyed = ipc_destroy
};

/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stddef.h>                         // size_t
#include <stdint.h>                         // int32_t, uint32_t
#include <sys/types.h>                      // gid_t, uid_t

#include <qb/qbipcs.h>                      // qb_ipcs_connection_t

#include <crm/common/internal.h>            // pcmk__client_t
#include <crm/common/ipc.h>                 // crm_ipc_client_response
#include <crm/common/logging.h>             // CRM_CHECK

#include "pacemaker-execd.h"                // client_disconnect_cleanup

static int32_t
ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return pcmk__daemon_ipc_accept(&execd, c, uid, gid);
}

static void
ipc_created(qb_ipcs_connection_t *c)
{
    return pcmk__daemon_ipc_created(&execd, c);
}

void
execd_ipc_created(pcmk__daemon_t *d, pcmk__client_t *client)
{
    notify_of_new_client(client);
}

static int32_t
ipc_closed(qb_ipcs_connection_t *c)
{
    return pcmk__daemon_ipc_closed(&execd, c);
}

void
execd_ipc_closed(pcmk__daemon_t *d, pcmk__client_t *client)
{
    client_disconnect_cleanup(client->id);
#ifdef PCMK__COMPILE_REMOTE
    ipc_proxy_remove_provider(client);
#endif
    lrmd_client_destroy(client);
}

static void
ipc_destroy(qb_ipcs_connection_t *c)
{
    pcmk__daemon_ipc_destroy(&execd, c);
}

static int32_t
ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    pcmk__daemon_ipc_dispatch(&execd, c, data, size);
    return 0;
}

void
execd_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request)
{
    request->op = pcmk__xe_get_copy(request->xml, d->op);
    CRM_CHECK(request->op != NULL, return);

    CRM_CHECK(pcmk__is_set(request->ipc_flags, crm_ipc_client_response),
              g_clear_pointer(&request->op, free); return);
    execd_handle_request(request);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = ipc_accept,
    .connection_created = ipc_created,
    .msg_process = ipc_dispatch,
    .connection_closed = ipc_closed,
    .connection_destroyed = ipc_destroy
};

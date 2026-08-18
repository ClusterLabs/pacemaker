/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/internal.h>            // pcmk__client_t
#include <crm/common/ipc.h>                 // crm_ipc_client_response
#include <crm/common/logging.h>             // CRM_CHECK

#include "pacemaker-execd.h"                // client_disconnect_cleanup

void
execd_ipc_created(pcmk__daemon_t *d, pcmk__client_t *client)
{
    notify_of_new_client(client);
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

void
execd_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request)
{
    request->op = pcmk__xe_get_copy(request->xml, d->op);
    CRM_CHECK(request->op != NULL, return);

    CRM_CHECK(pcmk__is_set(request->ipc_flags, crm_ipc_client_response),
              g_clear_pointer(&request->op, free); return);
    execd_handle_request(request);
}

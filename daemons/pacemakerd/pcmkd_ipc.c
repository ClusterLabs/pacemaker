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

#include <crm/common/mainloop.h>        // mainloop_set_trigger

#include "pacemakerd.h"                 // pacemakerd_handle_request

void
pacemakerd_ipc_closed(pcmk__daemon_t *d, pcmk__client_t *client)
{
    if (shutdown_complete_state_reported_to == client->pid) {
        shutdown_complete_state_reported_client_closed = true;
        mainloop_set_trigger(shutdown_trigger);
    }

    pcmk__free_client(client);
}

void
pacemakerd_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request)
{
    request->op = pcmk__xe_get_copy(request->xml, d->op);
    CRM_CHECK(request->op != NULL, return);

    pacemakerd_handle_request(request);
}

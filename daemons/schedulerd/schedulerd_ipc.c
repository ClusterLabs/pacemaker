/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stddef.h>                     // NULL

#include <crm/crm.h>                    // CRM_SYSTEM_PENGINE
#include <crm/common/results.h>         // CRM_EX_*

#include "pacemaker-schedulerd.h"       // schedulerd_handle_request

void
schedulerd_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request)
{
    const char *sys_to = pcmk__xe_get(request->xml, PCMK__XA_CRM_SYS_TO);

    if (pcmk__str_eq(pcmk__xe_get(request->xml, PCMK__XA_SUBT),
                     PCMK__VALUE_RESPONSE, pcmk__str_none)) {
        pcmk__ipc_send_ack(request->ipc_client, request->ipc_id,
                           request->ipc_flags, NULL, CRM_EX_INDETERMINATE);
        pcmk__info("Ignoring IPC reply from %s",
                   pcmk__client_name(request->ipc_client));

    } else if (!pcmk__str_eq(sys_to, CRM_SYSTEM_PENGINE, pcmk__str_none)) {
        pcmk__ipc_send_ack(request->ipc_client, request->ipc_id,
                           request->ipc_flags, NULL, CRM_EX_INDETERMINATE);
        pcmk__info("Ignoring invalid IPC message: to '%s' not "
                   CRM_SYSTEM_PENGINE, pcmk__s(sys_to, ""));

    } else {
        request->op = pcmk__xe_get_copy(request->xml, d->op);
        CRM_CHECK(request->op != NULL, return);

        schedulerd_handle_request(request);
    }
}

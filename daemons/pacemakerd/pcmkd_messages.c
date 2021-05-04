/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "pacemakerd.h"

crm_exit_t
request_shutdown(crm_ipc_t *ipc)
{
    xmlNode *request = NULL;
    xmlNode *reply = NULL;
    int rc = 0;
    crm_exit_t status = CRM_EX_OK;

    request = create_request(CRM_OP_QUIT, NULL, NULL, CRM_SYSTEM_MCP,
                             CRM_SYSTEM_MCP, NULL);
    if (request == NULL) {
        crm_err("Unable to create shutdown request"); // Probably memory error
        status = CRM_EX_TEMPFAIL;
        goto done;
    }

    crm_notice("Requesting shutdown of existing Pacemaker instance");
    rc = crm_ipc_send(ipc, request, crm_ipc_client_response, 0, &reply);
    if (rc < 0) {
        crm_err("Could not send shutdown request");
        status = crm_errno2exit(rc);
        goto done;
    }

    if ((rc == 0) || (reply == NULL)) {
        crm_err("Unrecognized response to shutdown request");
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    if ((crm_element_value_int(reply, "status", &rc) == 0)
        && (rc != CRM_EX_OK)) {
        crm_err("Shutdown request failed: %s", crm_exit_str(rc));
        status = rc;
        goto done;
    }

    // Wait for pacemakerd to shut down IPC (with 30-minute timeout)
    status = CRM_EX_TIMEOUT;
    for (int i = 0; i < 900; ++i) {
        if (!crm_ipc_connected(ipc)) {
            status = CRM_EX_OK;
            break;
        }
        sleep(2);
    }

done:
    free_xml(request);
    crm_ipc_close(ipc);
    crm_ipc_destroy(ipc);
    return status;
}

/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/common/messages_internal.h>

#include "pacemaker-attrd.h"

static GHashTable *attrd_handlers = NULL;

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    crm_err("Unknown IPC request %s from %s %s",
            request->op, pcmk__request_origin_type(request),
            pcmk__request_origin(request));
    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown request type '%s' (bug?)", request->op);
    return NULL;
}

static xmlNode *
handle_flush_request(pcmk__request_t *request)
{
    if (request->peer != NULL) {
        /* Ignore. The flush command was removed in 2.0.0 but may be
         * received from peers running older versions.
         */
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
        return NULL;
    } else {
        return handle_unknown_request(request);
    }
}

static void
attrd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { PCMK__ATTRD_CMD_FLUSH, handle_flush_request },
        { NULL, handle_unknown_request },
    };

    attrd_handlers = pcmk__register_handlers(handlers);
}

void
attrd_unregister_handlers(void)
{
    if (attrd_handlers != NULL) {
        g_hash_table_destroy(attrd_handlers);
        attrd_handlers = NULL;
    }
}

void
attrd_handle_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    char *log_msg = NULL;
    const char *reason = NULL;

    if (attrd_handlers == NULL) {
        attrd_register_handlers();
    }

    reply = pcmk__process_request(request, attrd_handlers);

    if (reply != NULL) {
        crm_log_xml_trace(reply, "Reply");

        if (request->ipc_client != NULL) {
            pcmk__ipc_send_xml(request->ipc_client, request->ipc_id, reply,
                               request->ipc_flags);
        } else {
            crm_err("Not sending CPG reply to client");
        }

        free_xml(reply);
    }

    reason = request->result.exit_reason;
    log_msg = crm_strdup_printf("Processed %s request from %s %s: %s%s%s%s",
                                request->op, pcmk__request_origin_type(request),
                                pcmk__request_origin(request),
                                pcmk_exec_status_str(request->result.execution_status),
                                (reason == NULL)? "" : " (",
                                pcmk__s(reason, ""),
                                (reason == NULL)? "" : ")");

    if (!pcmk__result_ok(&request->result)) {
        crm_warn("%s", log_msg);
    } else {
        crm_debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}

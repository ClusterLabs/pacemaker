/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include <stdbool.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "pacemaker-schedulerd.h"

static int32_t
pe_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static int32_t
pe_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    xmlNode *msg = NULL;
    pcmk__client_t *c = pcmk__find_client(qbc);
    const char *sys_to = NULL;

    CRM_CHECK(c != NULL, return 0);

    if (schedulerd_handlers == NULL) {
        schedulerd_register_handlers();
    }

    rc = pcmk__ipc_msg_append(&c->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        msg = pcmk__client_data2xml(c, &id, &flags);
        g_byte_array_free(c->buffer, TRUE);
        c->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        crm_err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (c->buffer != NULL) {
            g_byte_array_free(c->buffer, TRUE);
            c->buffer = NULL;
        }

        return 0;
    }

    if (msg == NULL) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_ACK, NULL, CRM_EX_PROTOCOL);
        return 0;
    }

    sys_to = pcmk__xe_get(msg, PCMK__XA_CRM_SYS_TO);

    if (pcmk__str_eq(pcmk__xe_get(msg, PCMK__XA_SUBT), PCMK__VALUE_RESPONSE,
                     pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_INDETERMINATE);
        crm_info("Ignoring IPC reply from %s", pcmk__client_name(c));

    } else if (!pcmk__str_eq(sys_to, CRM_SYSTEM_PENGINE, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_INDETERMINATE);
        crm_info("Ignoring invalid IPC message: to '%s' not "
                 CRM_SYSTEM_PENGINE, pcmk__s(sys_to, ""));

    } else {
        char *log_msg = NULL;
        const char *exec_status_s = NULL;
        const char *reason = NULL;
        xmlNode *reply = NULL;

        pcmk__request_t request = {
            .ipc_client     = c,
            .ipc_id         = id,
            .ipc_flags      = flags,
            .peer           = NULL,
            .xml            = msg,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = pcmk__xe_get_copy(request.xml, PCMK__XA_CRM_TASK);
        CRM_CHECK(request.op != NULL, return 0);

        reply = pcmk__process_request(&request, schedulerd_handlers);

        if (reply != NULL) {
            pcmk__ipc_send_xml(c, id, reply, crm_ipc_server_event);
            pcmk__xml_free(reply);
        }

        exec_status_s = pcmk_exec_status_str(request.result.execution_status);
        reason = request.result.exit_reason;

        log_msg = pcmk__assert_asprintf("Processed %s request from %s %s: "
                                        "%s%s%s%s",
                                        request.op,
                                        pcmk__request_origin_type(&request),
                                        pcmk__request_origin(&request),
                                        exec_status_s,
                                        (reason == NULL)? "" : " (",
                                        pcmk__s(reason, ""),
                                        (reason == NULL)? "" : ")");

        if (!pcmk__result_ok(&request.result)) {
            crm_warn("%s", log_msg);
        } else {
            crm_debug("%s", log_msg);
        }

        free(log_msg);
        pcmk__reset_request(&request);
    }

    pcmk__xml_free(msg);
    return 0;
}

/* Error code means? */
static int32_t
pe_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }
    crm_trace("Connection %p", c);
    pcmk__free_client(client);
    return 0;
}

static void
pe_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
    pe_ipc_closed(c);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = pe_ipc_accept,
    .connection_created = NULL,
    .msg_process = pe_ipc_dispatch,
    .connection_closed = pe_ipc_closed,
    .connection_destroyed = pe_ipc_destroy
};

/*
 * Copyright 2010-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>                       // g_hash_table_destroy
#include <stdbool.h>                    // bool
#include <stdlib.h>                     // free
#include <string.h>                     // NULL, strstr

#include <libxml/tree.h>                // xmlNode

#include <crm/crm.h>                    // CRM_OP_PING, CRM_OP_QUIT
#include <crm/common/ipc.h>             // crm_ipc_flags
#include <crm/common/mainloop.h>        // mainloop_set_trigger
#include <crm/common/results.h>         // CRM_EX_*, pcmk_exec_status_str
#include <crm/common/xml.h>             // PCMK_XA_*

#include "pacemakerd.h"                 // pacemakerd_*

static GHashTable *pacemakerd_handlers = NULL;

static xmlNode *
handle_node_cache_request(pcmk__request_t *request)
{
    pcmk__trace("Ignoring request from client %s to purge node because peer "
                "cache is not used",
                pcmk__client_name(request->ipc_client));

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       NULL, CRM_EX_OK);
    return NULL;
}

static xmlNode *
handle_ping_request(pcmk__request_t *request)
{
    xmlNode *msg = request->xml;

    const char *value = NULL;
    xmlNode *ping = NULL;
    xmlNode *reply = NULL;
    const char *from = pcmk__xe_get(msg, PCMK__XA_CRM_SYS_FROM);

    /* Pinged for status */
    pcmk__trace("Pinged from " PCMK__XA_CRM_SYS_FROM "='%s' "
                PCMK_XA_ORIGIN "='%s'",
                pcmk__s(from, ""),
                pcmk__s(pcmk__xe_get(msg, PCMK_XA_ORIGIN), ""));

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       NULL, CRM_EX_INDETERMINATE);

    ping = pcmk__xe_create(NULL, PCMK__XE_PING_RESPONSE);
    value = pcmk__xe_get(msg, PCMK__XA_CRM_SYS_TO);
    pcmk__xe_set(ping, PCMK__XA_CRM_SUBSYSTEM, value);
    pcmk__xe_set(ping, PCMK__XA_PACEMAKERD_STATE, pacemakerd_state);
    pcmk__xe_set_time(ping, PCMK__XA_CRM_TIMESTAMP, subdaemon_check_progress);
    pcmk__xe_set(ping, PCMK_XA_RESULT, "ok");
    reply = pcmk__new_reply(msg, ping);

    pcmk__xml_free(ping);

    if (reply == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Failed building ping reply for client %s",
                            pcmk__client_name(request->ipc_client));
    } else {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    }

    /* just proceed state on sbd pinging us */
    if ((from != NULL) && g_str_has_prefix(from, "sbd")) {
        if (pcmk__str_eq(pacemakerd_state, PCMK__VALUE_SHUTDOWN_COMPLETE,
                         pcmk__str_none)) {
            if (pcmk__get_sbd_sync_resource_startup()) {
                pcmk__notice("Shutdown-complete-state passed to SBD");
            }

            shutdown_complete_state_reported_to = request->ipc_client->pid;

        } else if (pcmk__str_eq(pacemakerd_state, PCMK__VALUE_WAIT_FOR_PING,
                                pcmk__str_none)) {
            pcmk__notice("Received startup-trigger from SBD");
            pacemakerd_state = PCMK__VALUE_STARTING_DAEMONS;
            mainloop_set_trigger(startup_trigger);
        }
    }

    return reply;
}

static xmlNode *
handle_shutdown_request(pcmk__request_t *request)
{
    xmlNode *msg = request->xml;

    xmlNode *shutdown = NULL;
    xmlNode *reply = NULL;

    /* Only allow privileged users (i.e. root or hacluster) to shut down
     * Pacemaker from the command line (or direct IPC), so that other users
     * are forced to go through the CIB and have ACLs applied.
     */
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       NULL, CRM_EX_INDETERMINATE);

    shutdown = pcmk__xe_create(NULL, PCMK__XE_SHUTDOWN);

    if (allowed) {
        pcmk__notice("Shutting down in response to IPC request %s from %s",
                     pcmk__xe_get(msg, PCMK_XA_REFERENCE),
                     pcmk__xe_get(msg, PCMK_XA_ORIGIN));
        pcmk__xe_set_int(shutdown, PCMK__XA_OP_STATUS, CRM_EX_OK);
    } else {
        pcmk__warn("Ignoring shutdown request from unprivileged client %s",
                   pcmk__client_name(request->ipc_client));
        pcmk__xe_set_int(shutdown, PCMK__XA_OP_STATUS,
                         CRM_EX_INSUFFICIENT_PRIV);
    }

    reply = pcmk__new_reply(msg, shutdown);
    pcmk__xml_free(shutdown);

    if (reply == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Failed building shutdown reply for client %s",
                            pcmk__client_name(request->ipc_client));
    } else {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    }

    if (allowed) {
        pcmk_shutdown(15);
    }

    return reply;
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       NULL, CRM_EX_PROTOCOL);

    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown request type '%s' (bug?)",
                        pcmk__s(request->op, ""));
    return NULL;
}

static void
pacemakerd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_RM_NODE_CACHE, handle_node_cache_request },
        { CRM_OP_PING, handle_ping_request },
        { CRM_OP_QUIT, handle_shutdown_request },
        { NULL, handle_unknown_request },
    };

    pacemakerd_handlers = pcmk__register_handlers(handlers);
}

void
pacemakerd_unregister_handlers(void)
{
    if (pacemakerd_handlers != NULL) {
        g_hash_table_destroy(pacemakerd_handlers);
        pacemakerd_handlers = NULL;
    }
}

void
pacemakerd_handle_request(pcmk__request_t *request)
{
    xmlNode *reply = NULL;
    char *log_msg = NULL;
    const char *exec_status_s = NULL;
    const char *reason = NULL;

    if (pacemakerd_handlers == NULL) {
        pacemakerd_register_handlers();
    }

    reply = pcmk__process_request(request, pacemakerd_handlers);

    if (reply != NULL) {
        pcmk__log_xml_trace(reply, "Reply");

        pcmk__ipc_send_xml(request->ipc_client, request->ipc_id, reply,
                           crm_ipc_server_event);
        pcmk__xml_free(reply);
    }

    exec_status_s = pcmk_exec_status_str(request->result.execution_status);
    reason = request->result.exit_reason;

    log_msg = pcmk__assert_asprintf("Processed %s request from %s %s: %s%s%s%s",
                                    request->op,
                                    pcmk__request_origin_type(request),
                                    pcmk__request_origin(request),
                                    exec_status_s,
                                    (reason == NULL)? "" : " (",
                                    pcmk__s(reason, ""),
                                    (reason == NULL)? "" : ")");

    if (!pcmk__result_ok(&request->result)) {
        pcmk__warn("%s", log_msg);
    } else {
        pcmk__debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}

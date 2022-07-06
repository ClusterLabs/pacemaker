/*
 * Copyright 2010-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include "pacemakerd.h"

#include <crm/crm.h>
#include <crm/msg_xml.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

static GHashTable *pcmkd_handlers = NULL;

static xmlNode *
handle_node_cache_request(pcmk__request_t *request)
{
    crm_trace("Ignoring request from client %s to purge node "
              "because peer cache is not used",
              pcmk__client_name(request->ipc_client));

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       "ack", NULL, CRM_EX_OK);
    return NULL;
}

static xmlNode *
handle_ping_request(pcmk__request_t *request)
{
    xmlNode *msg = request->xml;

    const char *value = NULL;
    xmlNode *ping = NULL;
    xmlNode *reply = NULL;
    const char *from = crm_element_value(msg, F_CRM_SYS_FROM);

    /* Pinged for status */
    crm_trace("Pinged from " F_CRM_SYS_FROM "='%s' " F_CRM_ORIGIN "='%s'",
              pcmk__s(from, ""),
              pcmk__s(crm_element_value(msg, F_CRM_ORIGIN), ""));

    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       "ack", NULL, CRM_EX_INDETERMINATE);

    ping = create_xml_node(NULL, XML_CRM_TAG_PING);
    value = crm_element_value(msg, F_CRM_SYS_TO);
    crm_xml_add(ping, XML_PING_ATTR_SYSFROM, value);
    crm_xml_add(ping, XML_PING_ATTR_PACEMAKERDSTATE, pacemakerd_state);
    crm_xml_add_ll(ping, XML_ATTR_TSTAMP,
                   (long long) subdaemon_check_progress);
    crm_xml_add(ping, XML_PING_ATTR_STATUS, "ok");
    reply = create_reply(msg, ping);

    free_xml(ping);

    if (reply == NULL) {
        pcmk__format_result(&request->result, CRM_EX_ERROR, PCMK_EXEC_ERROR,
                            "Failed building ping reply for client %s",
                            pcmk__client_name(request->ipc_client));
    } else {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    }

    /* just proceed state on sbd pinging us */
    if (from && strstr(from, "sbd")) {
        if (pcmk__str_eq(pacemakerd_state, XML_PING_ATTR_PACEMAKERDSTATE_SHUTDOWNCOMPLETE, pcmk__str_none)) {
            if (pcmk__get_sbd_sync_resource_startup()) {
                crm_notice("Shutdown-complete-state passed to SBD.");
            }

            shutdown_complete_state_reported_to = request->ipc_client->pid;

        } else if (pcmk__str_eq(pacemakerd_state, XML_PING_ATTR_PACEMAKERDSTATE_WAITPING, pcmk__str_none)) {
            crm_notice("Received startup-trigger from SBD.");
            pacemakerd_state = XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS;
            mainloop_set_trigger(startup_trigger);
        }
    }

    return reply;
}

static void
handle_shutdown_request(pcmk__client_t *c, xmlNode *msg, uint32_t id, uint32_t flags)
{
    xmlNode *shutdown = NULL;
    xmlNode *reply = NULL;

    /* Only allow privileged users (i.e. root or hacluster) to shut down
     * Pacemaker from the command line (or direct IPC), so that other users
     * are forced to go through the CIB and have ACLs applied.
     */
    bool allowed = pcmk_is_set(c->flags, pcmk__client_privileged);

    shutdown = create_xml_node(NULL, XML_CIB_ATTR_SHUTDOWN);

    if (allowed) {
        crm_notice("Shutting down in response to IPC request %s from %s",
                   crm_element_value(msg, F_CRM_REFERENCE),
                   crm_element_value(msg, F_CRM_ORIGIN));
        crm_xml_add_int(shutdown, XML_LRM_ATTR_OPSTATUS, CRM_EX_OK);
    } else {
        crm_warn("Ignoring shutdown request from unprivileged client %s",
                 pcmk__client_name(c));
        crm_xml_add_int(shutdown, XML_LRM_ATTR_OPSTATUS, CRM_EX_INSUFFICIENT_PRIV);
    }

    reply = create_reply(msg, shutdown);
    free_xml(shutdown);
    if (reply) {
        if (pcmk__ipc_send_xml(c, id, reply, crm_ipc_server_event) != pcmk_rc_ok) {
            crm_err("Failed sending shutdown reply to client %s",
                    pcmk__client_name(c));
        }
        free_xml(reply);
    } else {
        crm_err("Failed building shutdown reply for client %s",
                pcmk__client_name(c));
    }

    if (allowed) {
        pcmk_shutdown(15);
    }
}

static xmlNode *
handle_unknown_request(pcmk__request_t *request)
{
    pcmk__ipc_send_ack(request->ipc_client, request->ipc_id, request->ipc_flags,
                       "ack", NULL, CRM_EX_INVALID_PARAM);

    pcmk__format_result(&request->result, CRM_EX_PROTOCOL, PCMK_EXEC_INVALID,
                        "Unknown IPC request type '%s' (bug?)",
                        pcmk__client_name(request->ipc_client));
    return NULL;
}

static void
pcmkd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_RM_NODE_CACHE, handle_node_cache_request },
        { CRM_OP_PING, handle_ping_request },
        { NULL, handle_unknown_request },
    };

    pcmkd_handlers = pcmk__register_handlers(handlers);
}

static int32_t
pcmk_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

/* Error code means? */
static int32_t
pcmk_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }
    crm_trace("Connection %p", c);
    if (shutdown_complete_state_reported_to == client->pid) {
        shutdown_complete_state_reported_client_closed = TRUE;
        if (shutdown_trigger) {
            mainloop_set_trigger(shutdown_trigger);
        }
    }
    pcmk__free_client(client);
    return 0;
}

static void
pcmk_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
    pcmk_ipc_closed(c);
}

/* Exit code means? */
static int32_t
pcmk_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    const char *task = NULL;
    xmlNode *msg = NULL;
    pcmk__client_t *c = pcmk__find_client(qbc);

    CRM_CHECK(c != NULL, return 0);

    if (pcmkd_handlers == NULL) {
        pcmkd_register_handlers();
    }

    msg = pcmk__client_data2xml(c, data, &id, &flags);
    if (msg == NULL) {
        pcmk__ipc_send_ack(c, id, flags, "ack", NULL, CRM_EX_PROTOCOL);
        return 0;
    }

    task = crm_element_value(msg, F_CRM_TASK);
    if (pcmk__str_empty(task)) {
        crm_debug("IPC command from client %s is missing task",
                  pcmk__client_name(c));
        pcmk__ipc_send_ack(c, id, flags, "ack", NULL, CRM_EX_INVALID_PARAM);

    } else if (pcmk__str_eq(task, CRM_OP_QUIT, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, "ack", NULL, CRM_EX_INDETERMINATE);
        handle_shutdown_request(c, msg, id, flags);

    } else {
        char *log_msg = NULL;
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

        request.op = crm_element_value_copy(request.xml, F_CRM_TASK);
        CRM_CHECK(request.op != NULL, return 0);

        reply = pcmk__process_request(&request, pcmkd_handlers);

        if (reply != NULL) {
            pcmk__ipc_send_xml(c, id, reply, crm_ipc_server_event);
            free_xml(reply);
        }

        reason = request.result.exit_reason;

        log_msg = crm_strdup_printf("Processed %s request from %s %s: %s%s%s%s",
                                    request.op, pcmk__request_origin_type(&request),
                                    pcmk__request_origin(&request),
                                    pcmk_exec_status_str(request.result.execution_status),
                                    (reason == NULL)? "" : " (",
                                    (reason == NULL)? "" : reason,
                                    (reason == NULL)? "" : ")");

        if (!pcmk__result_ok(&request.result)) {
            crm_warn("%s", log_msg);
        } else {
            crm_debug("%s", log_msg);
        }

        free(log_msg);
        pcmk__reset_request(&request);
    }

    free_xml(msg);
    return 0;
}

struct qb_ipcs_service_handlers mcp_ipc_callbacks = {
    .connection_accept = pcmk_ipc_accept,
    .connection_created = NULL,
    .msg_process = pcmk_ipc_dispatch,
    .connection_closed = pcmk_ipc_closed,
    .connection_destroyed = pcmk_ipc_destroy
};

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

#include <crm/msg_xml.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>

void
pcmk_handle_ping_request(pcmk__client_t *c, xmlNode *msg, uint32_t id)
{
    const char *value = NULL;
    xmlNode *ping = NULL;
    xmlNode *reply = NULL;
    const char *from = crm_element_value(msg, F_CRM_SYS_FROM);

    /* Pinged for status */
    crm_trace("Pinged from %s.%s",
              crm_str(crm_element_value(msg, F_CRM_ORIGIN)),
              from?from:"unknown");
    ping = create_xml_node(NULL, XML_CRM_TAG_PING);
    value = crm_element_value(msg, F_CRM_SYS_TO);
    crm_xml_add(ping, XML_PING_ATTR_SYSFROM, value);
    crm_xml_add(ping, XML_PING_ATTR_PACEMAKERDSTATE, pacemakerd_state);
    crm_xml_add_ll(ping, XML_ATTR_TSTAMP,
                   (long long) subdaemon_check_progress);
    crm_xml_add(ping, XML_PING_ATTR_STATUS, "ok");
    reply = create_reply(msg, ping);
    free_xml(ping);
    if (reply) {
        if (pcmk__ipc_send_xml(c, id, reply, crm_ipc_server_event) !=
                pcmk_rc_ok) {
            crm_err("Failed sending ping reply to client %s",
                    pcmk__client_name(c));
        }
        free_xml(reply);
    } else {
        crm_err("Failed building ping reply for client %s",
                pcmk__client_name(c));
    }
    /* just proceed state on sbd pinging us */
    if (from && strstr(from, "sbd")) {
        if (pcmk__str_eq(pacemakerd_state, XML_PING_ATTR_PACEMAKERDSTATE_SHUTDOWNCOMPLETE, pcmk__str_none)) {
            if (pcmk__get_sbd_sync_resource_startup()) {
                crm_notice("Shutdown-complete-state passed to SBD.");
            }
            shutdown_complete_state_reported_to = c->pid;
        } else if (pcmk__str_eq(pacemakerd_state, XML_PING_ATTR_PACEMAKERDSTATE_WAITPING, pcmk__str_none)) {
            crm_notice("Received startup-trigger from SBD.");
            pacemakerd_state = XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS;
            mainloop_set_trigger(startup_trigger);
        }
    }
}

void
pcmk_handle_shutdown_request(pcmk__client_t *c, xmlNode *msg, uint32_t id, uint32_t flags)
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

    msg = pcmk__client_data2xml(c, data, &id, &flags);
    if (msg == NULL) {
        pcmk__ipc_send_ack(c, id, flags, "ack", CRM_EX_PROTOCOL);
        return 0;
    }

    task = crm_element_value(msg, F_CRM_TASK);
    if (pcmk__str_eq(task, CRM_OP_QUIT, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, "ack", CRM_EX_INDETERMINATE);
        pcmk_handle_shutdown_request(c, msg, id, flags);

    } else if (pcmk__str_eq(task, CRM_OP_RM_NODE_CACHE, pcmk__str_none)) {
        crm_trace("Ignoring request from client %s to purge node "
                  "because peer cache is not used", pcmk__client_name(c));
        pcmk__ipc_send_ack(c, id, flags, "ack", CRM_EX_OK);

    } else if (pcmk__str_eq(task, CRM_OP_PING, pcmk__str_none)) {
        pcmk__ipc_send_ack(c, id, flags, "ack", CRM_EX_INDETERMINATE);
        pcmk_handle_ping_request(c, msg, id);

    } else {
        crm_debug("Unrecognized IPC command '%s' from client %s",
                  crm_str(task), pcmk__client_name(c));
        pcmk__ipc_send_ack(c, id, flags, "ack", CRM_EX_INVALID_PARAM);
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

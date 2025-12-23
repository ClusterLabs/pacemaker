/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                      // ECONNREFUSED, ENOMEM
#include <stdbool.h>
#include <stddef.h>                     // NULL, size_t
#include <stdint.h>                     // int32_t, uint32_t
#include <sys/types.h>                  // gid_t, uid_t

#include <glib.h>                       // g_byte_array_free(), TRUE
#include <libxml/tree.h>                // xmlNode
#include <qb/qbipcs.h>                  // qb_ipcs_*

#include <crm/cib.h>                    // cib_none, cib_sync_call
#include <crm/common/internal.h>        // pcmk__client_*, pcmk__trace, etc.
#include <crm/common/ipc.h>             // crm_ipc_client_response
#include <crm/common/logging.h>         // CRM_CHECK(), CRM_LOG_ASSERT()
#include <crm/common/results.h>         // CRM_EX_PROTOCOL, pcmk_rc_*

#include "pacemaker-based.h"

qb_ipcs_service_t *ipcs_ro = NULL;
qb_ipcs_service_t *ipcs_rw = NULL;
qb_ipcs_service_t *ipcs_shm = NULL;

static int32_t
cib_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    if (cib_shutdown_flag) {
        pcmk__info("Ignoring new IPC client [%d] during shutdown",
                   pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static int32_t
cib_common_callback(qb_ipcs_connection_t *c, void *data, size_t size, bool privileged)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    uint32_t call_options = cib_none;
    pcmk__client_t *cib_client = pcmk__find_client(c);
    xmlNode *op_request = NULL;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(cib_client != NULL, return 0);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    pcmk__trace("Dispatching %sprivileged request from client %s",
                (privileged? "" : "un"), cib_client->id);

    rc = pcmk__ipc_msg_append(&cib_client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        op_request = pcmk__client_data2xml(cib_client, &id, &flags);
        g_byte_array_free(cib_client->buffer, TRUE);
        cib_client->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        pcmk__err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (cib_client->buffer != NULL) {
            g_byte_array_free(cib_client->buffer, TRUE);
            cib_client->buffer = NULL;
        }

        return 0;
    }

    if (op_request) {
        int rc = pcmk_rc_ok;

        rc = pcmk__xe_get_flags(op_request, PCMK__XA_CIB_CALLOPT, &call_options,
                                cib_none);
        if (rc != pcmk_rc_ok) {
            pcmk__warn("Couldn't parse options from request: %s",
                       pcmk_rc_str(rc));
        }
    }

    if (op_request == NULL) {
        pcmk__trace("Invalid message from %p", c);
        pcmk__ipc_send_ack(cib_client, id, flags, PCMK__XE_NACK, NULL,
                           CRM_EX_PROTOCOL);
        return 0;
    }

    if (pcmk__is_set(call_options, cib_sync_call)) {
        CRM_LOG_ASSERT(flags & crm_ipc_client_response);
        CRM_LOG_ASSERT(cib_client->request_id == 0);    /* This means the client has two synchronous events in-flight */
        cib_client->request_id = id;    /* Reply only to the last one */
    }

    if (cib_client->name == NULL) {
        const char *value = pcmk__xe_get(op_request, PCMK__XA_CIB_CLIENTNAME);

        if (value == NULL) {
            cib_client->name = pcmk__itoa(cib_client->pid);
        } else {
            cib_client->name = pcmk__str_copy(value);
        }
    }

    pcmk__xe_set(op_request, PCMK__XA_CIB_CLIENTID, cib_client->id);
    pcmk__xe_set(op_request, PCMK__XA_CIB_CLIENTNAME, cib_client->name);

    CRM_LOG_ASSERT(cib_client->user != NULL);
    pcmk__update_acl_user(op_request, PCMK__XA_CIB_USER, cib_client->user);

    based_common_callback_worker(id, flags, op_request, cib_client, privileged);
    pcmk__xml_free(op_request);

    return 0;
}

static int32_t
cib_ipc_dispatch_rw(qb_ipcs_connection_t * c, void *data, size_t size)
{
    return cib_common_callback(c, data, size, true);
}

static int32_t
cib_ipc_dispatch_ro(qb_ipcs_connection_t * c, void *data, size_t size)
{
    return cib_common_callback(c, data, size, false);
}

/* Error code means? */
static int32_t
cib_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }
    pcmk__trace("Connection %p", c);
    pcmk__free_client(client);
    return 0;
}

static void
cib_ipc_destroy(qb_ipcs_connection_t * c)
{
    pcmk__trace("Connection %p", c);
    cib_ipc_closed(c);
    if (cib_shutdown_flag) {
        based_shutdown(0);
    }
}

struct qb_ipcs_service_handlers ipc_ro_callbacks = {
    .connection_accept = cib_ipc_accept,
    .connection_created = NULL,
    .msg_process = cib_ipc_dispatch_ro,
    .connection_closed = cib_ipc_closed,
    .connection_destroyed = cib_ipc_destroy
};

struct qb_ipcs_service_handlers ipc_rw_callbacks = {
    .connection_accept = cib_ipc_accept,
    .connection_created = NULL,
    .msg_process = cib_ipc_dispatch_rw,
    .connection_closed = cib_ipc_closed,
    .connection_destroyed = cib_ipc_destroy
};

/*
 * Copyright 2012-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                          // ENOMEM
#include <stddef.h>                         // NULL, size_t
#include <stdint.h>                         // int32_t, uint32_t
#include <sys/types.h>                      // gid_t, uid_t

#include <glib.h>                           // g_byte_array_free, FALSE
#include <libxml/parser.h>                  // xmlNode
#include <qb/qbipcs.h>                      // qb_ipcs_connection_t, qb_ipcs_service_handlers

#include <crm/common/internal.h>            // pcmk__xml_free
#include <crm/common/ipc.h>                 // crm_ipc_flags
#include <crm/common/ipc_internal.h>        // pcmk__client_s, pcmk__find_client
#include <crm/common/results.h>             // pcmk_rc_e, pcmk_rc_str
#include <crm/common/xml_element.h>         // crm_xml_add, crm_element_value
#include <crm/common/xml_internal.h>        // PCMK__XA_LRMD_*

#include "pacemaker-execd.h"                // client_disconnect_cleanup

extern int lrmd_call_id;

static int32_t
lrmd_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static void
lrmd_ipc_created(qb_ipcs_connection_t * c)
{
    pcmk__client_t *new_client = pcmk__find_client(c);

    crm_trace("Connection %p", c);
    pcmk__assert(new_client != NULL);
    /* Now that the connection is offically established, alert
     * the other clients a new connection exists. */

    notify_of_new_client(new_client);
}

static int32_t
lrmd_ipc_dispatch(qb_ipcs_connection_t * c, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *request = NULL;

    CRM_CHECK(client != NULL, crm_err("Invalid client");
              return FALSE);
    CRM_CHECK(client->id != NULL, crm_err("Invalid client: %p", client);
              return FALSE);

    rc = pcmk__ipc_msg_append(&client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        request = pcmk__client_data2xml(client, &id, &flags);
        g_byte_array_free(client->buffer, TRUE);
        client->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        crm_err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (client->buffer != NULL) {
            g_byte_array_free(client->buffer, TRUE);
            client->buffer = NULL;
        }

        return 0;
    }

    CRM_CHECK(flags & crm_ipc_client_response, crm_err("Invalid client request: %p", client);
              return FALSE);

    if (!request) {
        return 0;
    }

    /* @TODO functionize some of this to reduce duplication with
     * lrmd_remote_client_msg()
     */

    if (!client->name) {
        const char *value = crm_element_value(request,
                                              PCMK__XA_LRMD_CLIENTNAME);

        if (value == NULL) {
            client->name = pcmk__itoa(pcmk__client_pid(c));
        } else {
            client->name = pcmk__str_copy(value);
        }
    }

    lrmd_call_id++;
    if (lrmd_call_id < 1) {
        lrmd_call_id = 1;
    }

    crm_xml_add(request, PCMK__XA_LRMD_CLIENTID, client->id);
    crm_xml_add(request, PCMK__XA_LRMD_CLIENTNAME, client->name);
    crm_xml_add_int(request, PCMK__XA_LRMD_CALLID, lrmd_call_id);

    process_lrmd_message(client, id, request);
    pcmk__xml_free(request);
    return 0;
}

static int32_t
lrmd_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }

    crm_trace("Connection %p", c);
    client_disconnect_cleanup(client->id);
#ifdef PCMK__COMPILE_REMOTE
    ipc_proxy_remove_provider(client);
#endif
    lrmd_client_destroy(client);
    return 0;
}

static void
lrmd_ipc_destroy(qb_ipcs_connection_t * c)
{
    lrmd_ipc_closed(c);
    crm_trace("Connection %p", c);
}

struct qb_ipcs_service_handlers lrmd_ipc_callbacks = {
    .connection_accept = lrmd_ipc_accept,
    .connection_created = lrmd_ipc_created,
    .msg_process = lrmd_ipc_dispatch,
    .connection_closed = lrmd_ipc_closed,
    .connection_destroyed = lrmd_ipc_destroy
};

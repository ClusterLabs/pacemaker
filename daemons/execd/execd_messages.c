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
#include <stdbool.h>                        // bool
#include <stddef.h>                         // NULL, size_t
#include <stdint.h>                         // int32_t, uint32_t
#include <stdlib.h>                         // free
#include <sys/types.h>                      // gid_t, uid_t

#include <glib.h>                           // g_byte_array_free, FALSE
#include <libxml/parser.h>                  // xmlNode
#include <qb/qbipcs.h>                      // qb_ipcs_connection_t, qb_ipcs_service_handlers
#include <qb/qblog.h>                       // QB_XS

#include <crm/crm.h>                        // CRM_SYSTEM_LRMD
#include <crm/common/internal.h>            // pcmk__process_request, pcmk__xml_free
#include <crm/common/ipc.h>                 // crm_ipc_flags
#include <crm/common/ipc_internal.h>        // pcmk__client_s, pcmk__find_client
#include <crm/common/results.h>             // pcmk_rc_e, pcmk_rc_str
#include <crm/common/strings.h>             // crm_strdup_printf
#include <crm/common/xml_element.h>         // crm_xml_add, crm_element_value
#include <crm/common/xml_internal.h>        // PCMK__XA_LRMD_*, pcmk__xe_is

#include "pacemaker-execd.h"                // client_disconnect_cleanup

static GHashTable *execd_handlers = NULL;
static int lrmd_call_id = 0;

static xmlNode *
handle_register_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    xmlNode *reply = NULL;

    crm_element_value_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);
    rc = execd_process_signon(request->ipc_client, request->xml, call_id, &reply);

    if (rc != pcmk_rc_ok) {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
        return NULL;
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return reply;
}

static void
execd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_REGISTER, handle_register_request },
        { NULL, NULL },
    };

    execd_handlers = pcmk__register_handlers(handlers);
}

void
execd_unregister_handlers(void)
{
    if (execd_handlers != NULL) {
        g_hash_table_destroy(execd_handlers);
        execd_handlers = NULL;
    }
}

static int32_t
lrmd_ipc_accept(qb_ipcs_connection_t *qbc, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", qbc);
    if (pcmk__new_client(qbc, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

static void
lrmd_ipc_created(qb_ipcs_connection_t *qbc)
{
    pcmk__client_t *new_client = pcmk__find_client(qbc);

    crm_trace("Connection %p", qbc);
    pcmk__assert(new_client != NULL);
    /* Now that the connection is offically established, alert
     * the other clients a new connection exists. */

    notify_of_new_client(new_client);
}

static int32_t
lrmd_ipc_dispatch(qb_ipcs_connection_t *qbc, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(qbc);
    xmlNode *msg = NULL;

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
        msg = pcmk__client_data2xml(client, &id, &flags);
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

    if (!msg) {
        return 0;
    }

    execd_process_message(client, id, flags, msg);
    pcmk__xml_free(msg);
    return 0;
}

static int32_t
lrmd_ipc_closed(qb_ipcs_connection_t *qbc)
{
    pcmk__client_t *client = pcmk__find_client(qbc);

    if (client == NULL) {
        return 0;
    }

    crm_trace("Connection %p", qbc);
    client_disconnect_cleanup(client->id);
#ifdef PCMK__COMPILE_REMOTE
    ipc_proxy_remove_provider(client);
#endif
    lrmd_client_destroy(client);
    return 0;
}

static void
lrmd_ipc_destroy(qb_ipcs_connection_t *qbc)
{
    lrmd_ipc_closed(qbc);
    crm_trace("Connection %p", qbc);
}

struct qb_ipcs_service_handlers lrmd_ipc_callbacks = {
    .connection_accept = lrmd_ipc_accept,
    .connection_created = lrmd_ipc_created,
    .msg_process = lrmd_ipc_dispatch,
    .connection_closed = lrmd_ipc_closed,
    .connection_destroyed = lrmd_ipc_destroy
};

static bool
invalid_msg(xmlNode *msg)
{
    const char *to = crm_element_value(msg, PCMK__XA_T);

    /* IPC proxy messages do not get a t="" attribute set on them. */
    bool invalid = !pcmk__str_eq(to, CRM_SYSTEM_LRMD, pcmk__str_none) &&
                   !pcmk__xe_is(msg, PCMK__XE_LRMD_IPC_PROXY);

    if (invalid) {
        crm_info("Ignoring invalid IPC message: to '%s' not " CRM_SYSTEM_LRMD,
                 pcmk__s(to, ""));
        crm_log_xml_info(msg, "[Invalid]");
    }

    return invalid;
}

void
execd_process_message(pcmk__client_t *c, uint32_t id, uint32_t flags, xmlNode *msg)
{
    int rc = pcmk_rc_ok;

    if (execd_handlers == NULL) {
        execd_register_handlers();
    }

    if (!c->name) {
        c->name = crm_element_value_copy(msg, PCMK__XA_LRMD_CLIENTNAME);
    }

    lrmd_call_id++;
    if (lrmd_call_id < 1) {
        lrmd_call_id = 1;
    }

    crm_xml_add(msg, PCMK__XA_LRMD_CLIENTID, c->id);
    crm_xml_add(msg, PCMK__XA_LRMD_CLIENTNAME, c->name);
    crm_xml_add_int(msg, PCMK__XA_LRMD_CALLID, lrmd_call_id);

    if (invalid_msg(msg)) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_NACK, NULL, CRM_EX_PROTOCOL);
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

        request.op = crm_element_value_copy(request.xml, PCMK__XA_LRMD_OP);
        CRM_CHECK(request.op != NULL, return);

        crm_trace("Processing %s operation from %s", request.op, c->id);

        reply = pcmk__process_request(&request, execd_handlers);

        /* FIXME: THIS IS TEMPORARY
         *
         * If the above returns NULL (which could be because something bad happened,
         * or because a message doesn't send a reply, but is most likely because not
         * all messages have been implemented yet), try falling back to the older
         * code.  This means we don't have to implement everything before testing.
         * Memory cleanup isn't important here.  This will be removed.
         */
        if (reply == NULL) {
            crm_trace("Falling back to old function");
            process_lrmd_message(c, id, request.xml);
            return;
        }

        if (reply != NULL) {
            rc = lrmd_server_send_reply(c, id, reply);
            if (rc != pcmk_rc_ok) {
                crm_warn("Reply to client %s failed: %s " QB_XS " rc=%d",
                         pcmk__client_name(c), pcmk_rc_str(rc), rc);
            }

            pcmk__xml_free(reply);
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
}

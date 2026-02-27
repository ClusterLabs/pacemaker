/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                          // EINPROGRESS, ENODEV
#include <stdbool.h>                        // bool
#include <stddef.h>                         // NULL
#include <stdlib.h>                         // free

#include <glib.h>                           // g_hash_table_destroy
#include <libxml/parser.h>                  // xmlNode
#include <qb/qblog.h>                       // QB_XS

#include <crm/crm.h>                        // CRM_OP_*, CRM_SYSTEM_LRMD
#include <crm/common/internal.h>            // pcmk__process_request, pcmk__xml_free
#include <crm/common/results.h>             // pcmk_exec_status, pcmk_rc_*, pcmk_rc_str
#include <crm/lrmd.h>                       // LRMD_OP_*

#include "pacemaker-execd.h"                // execd_*


static GHashTable *execd_handlers = NULL;
static int lrmd_call_id = 0;

static xmlNode *
handle_ipc_fwd_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    xmlNode *reply = NULL;

#ifdef PCMK__COMPILE_REMOTE
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    rc = ipc_proxy_forward_client(request->ipc_client, request->xml);
#else
    rc = EPROTONOSUPPORT;
#endif

    if (rc == pcmk_rc_ok) {
        /* Coverity gets confused by the #ifdef above and thinks this block
         * is unreachable due to rc always being EPROTONOSUPPORT.
         */
        // coverity[dead_error_line]
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    /* Create a generic reply since forwarding doesn't create a more specific one */
    reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    return reply;
}

static xmlNode *
handle_register_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    xmlNode *reply = NULL;

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);
    rc = execd_process_signon(request->ipc_client, request->xml, call_id, &reply);

    if (rc != pcmk_rc_ok) {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
        return NULL;
    }

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return reply;
}

static xmlNode *
handle_alert_exec_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    rc = execd_process_alert_exec(request->ipc_client, request->xml);

    if (rc == pcmk_rc_ok) {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
    }

    /* Create a generic reply since executing an alert doesn't create a
     * more specific one.
     */
    reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    return reply;
}

static xmlNode *
handle_check_request(pcmk__request_t *request)
{
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *wrapper = NULL;
    xmlNode *data = NULL;
    const char *timeout = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    wrapper = pcmk__xe_first_child(request->xml,
                                   PCMK__XE_LRMD_CALLDATA,
                                   NULL, NULL);
    data = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if (data == NULL) {
        pcmk__set_result(&request->result, CRM_EX_SOFTWARE, PCMK_EXEC_INVALID,
                         NULL);
        return NULL;
    }

    timeout = pcmk__xe_get(data, PCMK__XA_LRMD_WATCHDOG);
    /* FIXME: This just exits on certain conditions, which seems like a pretty
     * extreme reaction for a daemon to take.
     */
    pcmk__valid_fencing_watchdog_timeout(timeout);

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return NULL;
}

static xmlNode *
handle_get_recurring_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    rc = execd_process_get_recurring(request->xml, call_id, &reply);

    if (rc == pcmk_rc_ok) {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
    }

    return reply;
}

static xmlNode *
handle_poke_request(pcmk__request_t *request)
{
    int call_id = 0;
    xmlNode *reply = NULL;

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

    /* Create a generic reply since this doesn't create a more specific one */
    reply = execd_create_reply(pcmk_ok, call_id);
    return reply;
}

static xmlNode *
handle_rsc_cancel_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    rc = execd_process_rsc_cancel(request->ipc_client, request->xml);

    if (rc == pcmk_rc_ok) {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
    }

    /* Create a generic reply since canceling a resource doesn't create a
     * more specific one.
     */
    reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    return reply;
}

static xmlNode *
handle_rsc_exec_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    rc = execd_process_rsc_exec(request->ipc_client, request->xml);

    if (rc == pcmk_rc_ok) {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);

        /* This looks redundant, but it's unfortunately necessary.  The first
         * argument is set as the PCMK__XA_LRMD_RC attribute in the response.
         * On the other side of the connection, lrmd_send_command will read
         * this and use it as its return value, which passes back up to the
         * public API function lrmd_api_exec.
         */
        reply = execd_create_reply(call_id, call_id);
    } else {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
        reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    }

    return reply;
}

static xmlNode *
handle_rsc_info_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    /* This returns ENODEV if the resource isn't in the cache which will be
     * logged as an error.  However, this isn't fatal to the client - it may
     * be querying to see if the resource exists before deciding to register it.
     * Thus, we'll ignore an ENODEV to prevent a warning message from being
     * logged.
     */
    rc = execd_process_get_rsc_info(request->xml, call_id, &reply);

    if ((rc == pcmk_rc_ok) || (rc == ENODEV)) {
        pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    } else {
        pcmk__set_result(&request->result, pcmk_rc2exitc(rc), PCMK_EXEC_ERROR,
                         pcmk_rc_str(rc));
    }

    return reply;
}

static xmlNode *
handle_rsc_reg_request(pcmk__request_t *request)
{
    int call_id = 0;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    execd_process_rsc_register(request->ipc_client, request->ipc_id, request->xml);

    /* Create a generic reply since registering a resource doesn't create
     * a more specific one.
     */
    reply = execd_create_reply(pcmk_ok, call_id);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return reply;
}

static xmlNode *
handle_rsc_unreg_request(pcmk__request_t *request)
{
    int call_id = 0;
    int rc = pcmk_rc_ok;
    bool allowed = pcmk__is_set(request->ipc_client->flags,
                                pcmk__client_privileged);
    xmlNode *reply = NULL;

    if (!allowed) {
        pcmk__set_result(&request->result, CRM_EX_INSUFFICIENT_PRIV,
                         PCMK_EXEC_ERROR, NULL);
        pcmk__warn("Rejecting IPC request '%s' from unprivileged client %s",
                   request->op, pcmk__client_name(request->ipc_client));
        return NULL;
    }

    pcmk__xe_get_int(request->xml, PCMK__XA_LRMD_CALLID, &call_id);

    rc = execd_process_rsc_unregister(request->ipc_client, request->xml);

    /* Create a generic reply since unregistering a resource doesn't create
     * a more specific one.
     */
    reply = execd_create_reply(pcmk_rc2legacy(rc), call_id);
    pcmk__set_result(&request->result, CRM_EX_OK, PCMK_EXEC_DONE, NULL);
    return reply;
}

static bool
requires_notify(const char *command, int rc)
{
    if (pcmk__str_eq(command, LRMD_OP_RSC_UNREG, pcmk__str_none)) {
        /* Don't notify about failed unregisters */
        return (rc == pcmk_ok) || (rc == -EINPROGRESS);
    } else {
        return pcmk__str_any_of(command, LRMD_OP_POKE, LRMD_OP_RSC_REG, NULL);
    }
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
execd_register_handlers(void)
{
    pcmk__server_command_t handlers[] = {
        { CRM_OP_IPC_FWD, handle_ipc_fwd_request },
        { CRM_OP_REGISTER, handle_register_request },
        { LRMD_OP_ALERT_EXEC, handle_alert_exec_request },
        { LRMD_OP_CHECK, handle_check_request },
        { LRMD_OP_GET_RECURRING, handle_get_recurring_request },
        { LRMD_OP_POKE, handle_poke_request },
        { LRMD_OP_RSC_CANCEL, handle_rsc_cancel_request },
        { LRMD_OP_RSC_EXEC, handle_rsc_exec_request },
        { LRMD_OP_RSC_INFO, handle_rsc_info_request },
        { LRMD_OP_RSC_REG, handle_rsc_reg_request },
        { LRMD_OP_RSC_UNREG, handle_rsc_unreg_request },
        { NULL, handle_unknown_request },
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

bool
execd_invalid_msg(xmlNode *msg)
{
    const char *to = NULL;
    bool invalid = true;

    CRM_CHECK(msg != NULL, return invalid);

    to = pcmk__xe_get(msg, PCMK__XA_T);

    /* IPC proxy messages do not get a t="" attribute set on them. */
    invalid = !pcmk__str_eq(to, CRM_SYSTEM_LRMD, pcmk__str_none)
              && !pcmk__xe_is(msg, PCMK__XE_LRMD_IPC_PROXY);

    if (invalid) {
        pcmk__info("Ignoring invalid IPC message: to '%s' not " CRM_SYSTEM_LRMD,
                   pcmk__s(to, ""));
        pcmk__log_xml_info(msg, "[Invalid]");
    }

    return invalid;
}

void
execd_handle_request(pcmk__request_t *request)
{
    char *log_msg = NULL;
    const char *reason = NULL;
    const char *exec_status_s = NULL;
    xmlNode *reply = NULL;

    if (execd_handlers == NULL) {
        execd_register_handlers();
    }

    if (request->ipc_client->name == NULL) {
        request->ipc_client->name = pcmk__xe_get_copy(request->xml,
                                                      PCMK__XA_LRMD_CLIENTNAME);
    }

    lrmd_call_id++;
    if (lrmd_call_id < 1) {
        lrmd_call_id = 1;
    }

    pcmk__xe_set(request->xml, PCMK__XA_LRMD_CLIENTID, request->ipc_client->id);
    pcmk__xe_set(request->xml, PCMK__XA_LRMD_CLIENTNAME,
                 request->ipc_client->name);
    pcmk__xe_set_int(request->xml, PCMK__XA_LRMD_CALLID, lrmd_call_id);

    reply = pcmk__process_request(request, execd_handlers);

    if (reply != NULL) {
        int rc = pcmk_rc_ok;
        int reply_rc = pcmk_ok;

        pcmk__log_xml_trace(reply, "Reply");

        rc = lrmd_server_send_reply(request->ipc_client, request->ipc_id, reply);
        if (rc != pcmk_rc_ok) {
            pcmk__warn("Reply to client %s failed: %s " QB_XS " rc=%d",
                       pcmk__client_name(request->ipc_client), pcmk_rc_str(rc),
                       rc);
        }

        pcmk__xe_get_int(reply, PCMK__XA_LRMD_RC, &reply_rc);
        if (requires_notify(request->op, reply_rc)) {
            execd_send_generic_notify(reply_rc, request->xml);
        }

        pcmk__xml_free(reply);
    }

    exec_status_s = pcmk_exec_status_str(request->result.execution_status);
    reason = request->result.exit_reason;

    log_msg = pcmk__assert_asprintf("Processed %s request from %s %s: "
                                    "%s%s%s%s",
                                    request->op,
                                    pcmk__request_origin_type(request),
                                    pcmk__request_origin(request),
                                    exec_status_s,
                                    ((reason == NULL)? "" : " ("),
                                    pcmk__s(reason, ""),
                                    ((reason == NULL)? "" : ")"));

    if (!pcmk__result_ok(&request->result)) {
        pcmk__warn("%s", log_msg);
    } else {
        pcmk__debug("%s", log_msg);
    }

    free(log_msg);
    pcmk__reset_request(request);
}

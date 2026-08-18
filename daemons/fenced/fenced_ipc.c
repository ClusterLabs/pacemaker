/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>                         // int32_t, uint32_t, PRIu32
#include <stdio.h>                            // NULL, size_t
#include <sys/types.h>                        // gid_t, uid_t

#include <libxml/tree.h>                      // xmlNode
#include <qb/qbipcs.h>                        // for qb_ipcs_connection_t

#include "pacemaker-fenced.h"                 // fenced_get_local_node

#include <crm/common/ipc.h>                   // crm_ipc_flags, pcmk_ipc_fenced
#include <crm/common/results.h>               // pcmk_rc_*, pcmk_rc_str
#include <crm/fencing/internal.h>             // STONITH_OP_*
#include <crm/crm.h>                          // CRM_OP_RM_NODE_CACHE
#include <crm/stonith-ng.h>                   // stonith_call_options

static void
handle_ipc_reply(pcmk__client_t *client, xmlNode *request)
{
    const char *op = pcmk__xe_get(request, fenced.op);

    if (pcmk__str_eq(op, STONITH_OP_QUERY, pcmk__str_none)) {
        process_remote_stonith_query(request);

    } else if (pcmk__str_any_of(op, STONITH_OP_NOTIFY, STONITH_OP_FENCE,
                                NULL)) {
        fenced_process_fencing_reply(request);

    } else {
        pcmk__err("Ignoring unknown %s reply from client %s",
                  pcmk__s(op, "untyped"), pcmk__client_name(client));
        pcmk__log_xml_warn(request, "UnknownOp");
        return;
    }

    pcmk__debug("Processed %s reply from client %s", op,
                pcmk__client_name(client));
}

static int32_t
ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    return pcmk__daemon_ipc_accept(&fenced, c, uid, gid);
}

static int32_t
ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    pcmk__daemon_ipc_dispatch(&fenced, c, data, size);
    return 0;
}

void
fenced_ipc_dispatch(pcmk__daemon_t *d, pcmk__request_t *request)
{
    uint32_t call_options = st_opt_none;
    const char *op = NULL;
    int rc = pcmk_rc_ok;

    op = pcmk__xe_get(request->xml, PCMK__XA_CRM_TASK);
    if (pcmk__str_eq(op, CRM_OP_RM_NODE_CACHE, pcmk__str_casei)) {
        pcmk__xe_set(request->xml, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
        pcmk__xe_set(request->xml, fenced.op, op);
        pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTID, request->ipc_client->id);
        pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTNAME,
                     pcmk__client_name(request->ipc_client));
        pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTNODE, fenced_get_local_node());

        pcmk__cluster_send_message(NULL, pcmk_ipc_fenced, request->xml);
        return;
    }

    if (request->ipc_client->name == NULL) {
        const char *value = pcmk__xe_get(request->xml, PCMK__XA_ST_CLIENTNAME);

        request->ipc_client->name =
            pcmk__assert_asprintf("%s.%u", pcmk__s(value, "unknown"),
                                  request->ipc_client->pid);
    }

    rc = pcmk__xe_get_flags(request->xml, PCMK__XA_ST_CALLOPT, &call_options,
                            st_opt_none);
    if (rc != pcmk_rc_ok) {
        pcmk__warn("Couldn't parse options from request: %s", pcmk_rc_str(rc));
    }

    request->call_options = call_options;

    pcmk__trace("Flags %#08" PRIx32 "/%#08x for command %" PRIu32
                " from client %s",
                request->ipc_flags, request->call_options, request->ipc_id,
                pcmk__client_name(request->ipc_client));

    if (pcmk__is_set(request->call_options, st_opt_sync_call)) {
        pcmk__assert(pcmk__is_set(request->ipc_flags, crm_ipc_client_response));
        /* This means the client has two synchronous events in-flight */
        CRM_LOG_ASSERT(request->ipc_client->request_id == 0);
        /* Reply only to the last one */
        request->ipc_client->request_id = request->ipc_id;
    }

    pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTID, request->ipc_client->id);
    pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTNAME,
                 pcmk__client_name(request->ipc_client));
    pcmk__xe_set(request->xml, PCMK__XA_ST_CLIENTNODE, fenced_get_local_node());

    if (pcmk__xpath_find_one(request->xml->doc, "//" PCMK__XE_ST_REPLY,
                             PCMK__LOG_NEVER) != NULL) {
        handle_ipc_reply(request->ipc_client, request->xml);

    } else {
        request->op = pcmk__xe_get_copy(request->xml, d->op);
        CRM_CHECK(request->op != NULL, return);

        if (pcmk__is_set(request->call_options, st_opt_sync_call)) {
            pcmk__set_request_flags(request, pcmk__request_sync);
        }

        fenced_handle_request(request);
    }
}

static int32_t
ipc_closed(qb_ipcs_connection_t *c)
{
    return pcmk__daemon_ipc_closed(&fenced, c);
}

static void
ipc_destroy(qb_ipcs_connection_t *c)
{
    pcmk__daemon_ipc_destroy(&fenced, c);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = ipc_accept,
    .connection_created = NULL,
    .msg_process = ipc_dispatch,
    .connection_closed = ipc_closed,
    .connection_destroyed = ipc_destroy
};

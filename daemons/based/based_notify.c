/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EAGAIN
#include <inttypes.h>               // PRIx64
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdint.h>                 // int32_t, uint16_t
#include <sys/types.h>              // ssize_t

#include <glib.h>                   // gpointer, g_string_free
#include <libxml/tree.h>            // xmlNode
#include <qb/qblog.h>               // QB_XS

#include <crm/common/internal.h>    // pcmk__client_t, etc.
#include <crm/common/ipc.h>         // pcmk_free_ipc_event
#include <crm/common/logging.h>     // CRM_LOG_ASSERT
#include <crm/common/results.h>     // pcmk_rc_*

#include "pacemaker-based.h"

struct cib_notification_s {
    const xmlNode *msg;
    struct iovec *iov;
    int32_t iov_size;
};

static void
cib_notify_send_one(gpointer key, gpointer value, gpointer user_data)
{
    const char *type = NULL;
    bool do_send = false;
    int rc = pcmk_rc_ok;

    pcmk__client_t *client = value;
    struct cib_notification_s *update = user_data;

    if (client->ipcs == NULL && client->remote == NULL) {
        pcmk__warn("Skipping client with NULL channel");
        return;
    }

    type = pcmk__xe_get(update->msg, PCMK__XA_SUBT);
    CRM_LOG_ASSERT(type != NULL);

    if (pcmk__is_set(client->flags, cib_notify_diff)
        && pcmk__str_eq(type, PCMK__VALUE_CIB_DIFF_NOTIFY, pcmk__str_none)) {

        do_send = true;

    } else if (pcmk__is_set(client->flags, cib_notify_confirm)
               && pcmk__str_eq(type, PCMK__VALUE_CIB_UPDATE_CONFIRMATION,
                               pcmk__str_none)) {
        do_send = true;

    } else if (pcmk__is_set(client->flags, cib_notify_pre)
               && pcmk__str_eq(type, PCMK__VALUE_CIB_PRE_NOTIFY,
                               pcmk__str_none)) {
        do_send = true;

    } else if (pcmk__is_set(client->flags, cib_notify_post)
               && pcmk__str_eq(type, PCMK__VALUE_CIB_POST_NOTIFY,
                               pcmk__str_none)) {
        do_send = true;
    }

    if (!do_send) {
        return;
    }

    switch (PCMK__CLIENT_TYPE(client)) {
        case pcmk__client_ipc:
            rc = pcmk__ipc_send_iov(client, update->iov,
                                    crm_ipc_server_event);

            /* EAGAIN isn't an error for server events.  Sending did fail
             * with EAGAIN, but the iov was added to the send queue and we
             * will attempt to send it again the next time pcmk__ipc_send_iov
             * is called, or when crm_ipcs_flush_events_cb happens.
             */
            if ((rc != EAGAIN) && (rc != pcmk_rc_ok)) {
                pcmk__warn("Could not notify client %s: %s " QB_XS " id=%s",
                           pcmk__client_name(client), pcmk_rc_str(rc),
                           client->id);
            }
            break;

        case pcmk__client_tls:
        case pcmk__client_tcp:
            pcmk__debug("Sent %s notification to client %s (id %s)", type,
                        pcmk__client_name(client), client->id);
            pcmk__remote_send_xml(client->remote, update->msg);
            break;

        default:
            pcmk__err("Unknown transport for client %s "
                      QB_XS " flags=%#016" PRIx64,
                      pcmk__client_name(client), client->flags);
    }
}

static void
cib_notify_send(const xmlNode *xml)
{
    struct iovec *iov;
    struct cib_notification_s update;
    GString *iov_buffer = NULL;
    ssize_t bytes = 0;
    int rc = pcmk_rc_ok;
    uint16_t index = 0;

    iov_buffer = g_string_sized_new(1024);
    pcmk__xml_string(xml, 0, iov_buffer, 0);

    do {
        rc = pcmk__ipc_prepare_iov(0, iov_buffer, index, &iov, &bytes);

        if ((rc != pcmk_rc_ok) && (rc != pcmk_rc_ipc_more)) {
            pcmk__notice("Could not notify clients: %s " QB_XS " rc=%d",
                         pcmk_rc_str(rc), rc);
            break;
        }

        update.msg = xml;
        update.iov = iov;
        update.iov_size = bytes;
        pcmk__foreach_ipc_client(cib_notify_send_one, &update);
        pcmk_free_ipc_event(iov);

        if (rc == pcmk_rc_ok) {
            break;
        }

        index++;
    } while (true);

    g_string_free(iov_buffer, TRUE);
}

void
based_diff_notify(const char *op, int result, const char *call_id,
                  const char *client_id, const char *client_name,
                  const char *origin, xmlNode *update, xmlNode *diff)
{
    xmlNode *update_msg = NULL;
    xmlNode *wrapper = NULL;

    if (diff == NULL) {
        return;
    }

    update_msg = pcmk__xe_create(NULL, PCMK__XE_NOTIFY);

    pcmk__xe_set(update_msg, PCMK__XA_T, PCMK__VALUE_CIB_NOTIFY);
    pcmk__xe_set(update_msg, PCMK__XA_SUBT, PCMK__VALUE_CIB_DIFF_NOTIFY);
    pcmk__xe_set(update_msg, PCMK__XA_CIB_OP, op);
    pcmk__xe_set(update_msg, PCMK__XA_CIB_CLIENTID, client_id);
    pcmk__xe_set(update_msg, PCMK__XA_CIB_CLIENTNAME, client_name);
    pcmk__xe_set(update_msg, PCMK__XA_CIB_CALLID, call_id);
    pcmk__xe_set(update_msg, PCMK__XA_SRC, origin);
    pcmk__xe_set_int(update_msg, PCMK__XA_CIB_RC, result);

    wrapper = pcmk__xe_create(update_msg, PCMK__XE_CIB_UPDATE_RESULT);
    pcmk__xml_copy(wrapper, diff);

    pcmk__log_xml_trace(update_msg, "diff-notify");
    cib_notify_send(update_msg);
    pcmk__xml_free(update_msg);
}

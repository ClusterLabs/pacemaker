/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/attrd_internal.h>

#include "pacemaker-attrd.h"

static GList *waitlist = NULL;

struct waitlist_node {
    enum attrd_sync_point sync_point;

    pcmk__client_t *client;
    char *callid;
    uint32_t ipc_id;
    uint32_t flags;
};

static gint
waitlist_node_GCompareFunc(gconstpointer a, gconstpointer b)
{
    const struct waitlist_node *a_node = a;
    const struct waitlist_node *b_node = b;

    int rc = strcmp(pcmk__client_name(a_node->client), pcmk__client_name(b_node->client));

    if (rc == 0) {
        return strcmp(a_node->callid, b_node->callid);
    }

    return rc;
}

static void
free_waitlist_node(struct waitlist_node *wl)
{
    free(wl->client);
    free(wl->callid);
    free(wl);
}

static const char *
sync_point_str(enum attrd_sync_point sync_point)
{
    if (sync_point == attrd_sync_point_local) {
        return "local";
    } else if  (sync_point == attrd_sync_point_all) {
        return "all nodes";
    } else {
        return "unknown";
    }
}

void
attrd_add_client_to_waitlist(pcmk__request_t *request)
{
    const char *sync_point = crm_element_value(request->xml, PCMK__XA_ATTR_SYNC_POINT);
    struct waitlist_node *wl = NULL;

    if (sync_point == NULL) {
        return;
    }

    wl = calloc(sizeof(struct waitlist_node), 1);

    CRM_ASSERT(wl != NULL);

    wl->client = request->ipc_client;
    wl->callid = strdup(crm_element_value(request->xml, F_ATTRD_CALLID));

    if (pcmk__str_eq(sync_point, PCMK__ATTRD_SYNC_POINT_LOCAL, pcmk__str_none)) {
        wl->sync_point = attrd_sync_point_local;
    } else if (pcmk__str_eq(sync_point, PCMK__ATTRD_SYNC_POINT_ALL, pcmk__str_none)) {
        wl->sync_point = attrd_sync_point_all;
    } else {
        return;
    }

    wl->ipc_id = request->ipc_id;
    wl->flags = request->flags;

    crm_debug("Added client %s(%s) to waitlist for %s sync point",
              pcmk__client_name(wl->client), wl->callid,
              sync_point_str(wl->sync_point));

    waitlist = g_list_prepend(waitlist, wl);
}

void
attrd_alert_waitlist_clients(enum attrd_sync_point sync_point)
{
    for (GList *iter = waitlist; iter != NULL; ) {
        GList *client = iter;
        struct waitlist_node *wl = (struct waitlist_node *) client->data;

        iter = client->next;

        if (wl->sync_point != sync_point) {
            continue;
        }

        crm_debug("Alerting client %s(%s) for reached %s sync point",
                  pcmk__client_name(wl->client),
                  wl->callid, sync_point_str(wl->sync_point));

        attrd_send_ack(wl->client, wl->ipc_id,
                       wl->flags | crm_ipc_client_response);

        /* And then remove the client so it doesn't get alerted again. */
        waitlist = g_list_remove_link(waitlist, client);
        g_list_free(client);
        free_waitlist_node(wl);
    }
}

bool
attrd_client_on_waitlist(pcmk__request_t *request)
{
    const char *sync_point = crm_element_value(request->xml, PCMK__XA_ATTR_SYNC_POINT);
    struct waitlist_node wl;

    if (sync_point == NULL) {
        return false;
    }

    wl.client = request->ipc_client;
    wl.callid = strdup(crm_element_value(request->xml, F_ATTRD_CALLID));

    if (pcmk__str_eq(sync_point, PCMK__ATTRD_SYNC_POINT_LOCAL, pcmk__str_none)) {
        wl.sync_point = attrd_sync_point_local;
    } else if (pcmk__str_eq(sync_point, PCMK__ATTRD_SYNC_POINT_ALL, pcmk__str_none)) {
        wl.sync_point = attrd_sync_point_all;
    } else {
        return false;
    }

    return g_list_find_custom(waitlist, &wl, waitlist_node_GCompareFunc) != NULL;
}

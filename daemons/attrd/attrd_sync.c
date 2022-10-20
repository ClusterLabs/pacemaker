/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/msg_xml.h>
#include <crm/common/attrd_internal.h>

#include "pacemaker-attrd.h"

/* A hash table storing clients that are waiting on a sync point to be reached.
 * The key is waitlist_client - just a plain int.  The obvious key would be
 * the IPC client's ID, but this is not guaranteed to be unique.  A single client
 * could be waiting on a sync point for multiple attributes at the same time.
 *
 * It is not expected that this hash table will ever be especially large.
 */
static GHashTable *waitlist = NULL;
static int waitlist_client = 0;

struct waitlist_node {
    /* What kind of sync point does this node describe? */
    enum attrd_sync_point sync_point;

    /* Information required to construct and send a reply to the client. */
    char *client_id;
    uint32_t ipc_id;
    uint32_t flags;
};

static void
next_key(void)
{
    do {
        waitlist_client++;
        if (waitlist_client < 0) {
            waitlist_client = 1;
        }
    } while (g_hash_table_contains(waitlist, GINT_TO_POINTER(waitlist_client)));
}

static void
free_waitlist_node(gpointer data)
{
    struct waitlist_node *wl = (struct waitlist_node *) data;

    free(wl->client_id);
    free(wl);
}

static const char *
sync_point_str(enum attrd_sync_point sync_point)
{
    if (sync_point == attrd_sync_point_local) {
        return PCMK__VALUE_LOCAL;
    } else if  (sync_point == attrd_sync_point_cluster) {
        return PCMK__VALUE_CLUSTER;
    } else {
        return "unknown";
    }
}

void
attrd_add_client_to_waitlist(pcmk__request_t *request)
{
    const char *sync_point = attrd_request_sync_point(request->xml);
    struct waitlist_node *wl = NULL;

    if (sync_point == NULL) {
        return;
    }

    if (waitlist == NULL) {
        waitlist = pcmk__intkey_table(free_waitlist_node);
    }

    wl = calloc(sizeof(struct waitlist_node), 1);

    CRM_ASSERT(wl != NULL);

    wl->client_id = strdup(request->ipc_client->id);

    CRM_ASSERT(wl->client_id);

    if (pcmk__str_eq(sync_point, PCMK__VALUE_LOCAL, pcmk__str_none)) {
        wl->sync_point = attrd_sync_point_local;
    } else if (pcmk__str_eq(sync_point, PCMK__VALUE_CLUSTER, pcmk__str_none)) {
        wl->sync_point = attrd_sync_point_cluster;
    } else {
        free_waitlist_node(wl);
        return;
    }

    wl->ipc_id = request->ipc_id;
    wl->flags = request->flags;

    crm_debug("Added client %s to waitlist for %s sync point",
              wl->client_id, sync_point_str(wl->sync_point));

    next_key();
    pcmk__intkey_table_insert(waitlist, waitlist_client, wl);

    /* And then add the key to the request XML so we can uniquely identify
     * it when it comes time to issue the ACK.
     */
    crm_xml_add_int(request->xml, XML_LRM_ATTR_CALLID, waitlist_client);
}

void
attrd_ack_waitlist_clients(enum attrd_sync_point sync_point, const xmlNode *xml)
{
    int callid;
    gpointer value;

    if (waitlist == NULL) {
        return;
    }

    if (crm_element_value_int(xml, XML_LRM_ATTR_CALLID, &callid) == -1) {
        crm_warn("Could not get callid from request XML");
        return;
    }

    value = pcmk__intkey_table_lookup(waitlist, callid);
    if (value != NULL) {
        struct waitlist_node *wl = (struct waitlist_node *) value;
        pcmk__client_t *client = NULL;

        if (wl->sync_point != sync_point) {
            return;
        }

        crm_debug("Alerting client %s for reached %s sync point",
                  wl->client_id, sync_point_str(wl->sync_point));

        client = pcmk__find_client_by_id(wl->client_id);
        if (client == NULL) {
            return;
        }

        attrd_send_ack(client, wl->ipc_id, wl->flags | crm_ipc_client_response);

        /* And then remove the client so it doesn't get alerted again. */
        pcmk__intkey_table_remove(waitlist, callid);
    }
}

const char *
attrd_request_sync_point(xmlNode *xml)
{
    if (xml_has_children(xml)) {
        xmlNode *child = pcmk__xe_match(xml, XML_ATTR_OP, PCMK__XA_ATTR_SYNC_POINT, NULL);

        if (child) {
            return crm_element_value(child, PCMK__XA_ATTR_SYNC_POINT);
        } else {
            return NULL;
        }

    } else {
        return crm_element_value(xml, PCMK__XA_ATTR_SYNC_POINT);
    }
}

bool
attrd_request_has_sync_point(xmlNode *xml)
{
    return attrd_request_sync_point(xml) != NULL;
}

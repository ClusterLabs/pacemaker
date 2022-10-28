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

/*!
 * \internal
 * \brief Add a client to the attrd waitlist
 *
 * Typically, a client receives an ACK for its XML IPC request immediately.  However,
 * some clients want to wait until their request has been processed and taken effect.
 * This is called a sync point.  Any client placed on this waitlist will have its
 * ACK message delayed until either its requested sync point is hit, or until it
 * times out.
 *
 * The XML IPC request must specify the type of sync point it wants to wait for.
 *
 * \param[in,out] request   The request describing the client to place on the waitlist.
 */
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

/*!
 * \internal
 * \brief Free all memory associated with the waitlist.  This is most typically
 *        used when attrd shuts down.
 */
void
attrd_free_waitlist(void)
{
    if (waitlist == NULL) {
        return;
    }

    g_hash_table_destroy(waitlist);
    waitlist = NULL;
}

/*!
 * \internal
 * \brief Unconditionally remove a client from the waitlist, such as when the client
 *        node disconnects from the cluster
 *
 * \param[in] client    The client to remove
 */
void
attrd_remove_client_from_waitlist(pcmk__client_t *client)
{
    GHashTableIter iter;
    gpointer value;

    if (waitlist == NULL) {
        return;
    }

    g_hash_table_iter_init(&iter, waitlist);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        struct waitlist_node *wl = (struct waitlist_node *) value;

        if (wl->client_id == client->id) {
            g_hash_table_iter_remove(&iter);
        }
    }
}

/*!
 * \internal
 * \brief Send an IPC ACK message to all awaiting clients
 *
 * This function will search the waitlist for all clients that are currently awaiting
 * an ACK indicating their attrd operation is complete.  Only those clients with a
 * matching sync point type and callid from their original XML IPC request will be
 * ACKed.  Once they have received an ACK, they will be removed from the waitlist.
 *
 * \param[in] sync_point What kind of sync point have we hit?
 * \param[in] xml        The original XML IPC request.
 */
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

/*!
 * \internal
 * \brief Return the sync point attribute for an IPC request
 *
 * This function will check both the top-level element of \p xml for a sync
 * point attribute, as well as all of its \p op children, if any.  The latter
 * is useful for newer versions of attrd that can put multiple IPC requests
 * into a single message.
 *
 * \param[in] xml   An XML IPC request
 *
 * \note It is assumed that if one child element has a sync point attribute,
 *       all will have a sync point attribute and they will all be the same
 *       sync point.  No other configuration is supported.
 *
 * \return The sync point attribute of \p xml, or NULL if none.
 */
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

/*!
 * \internal
 * \brief Does an IPC request contain any sync point attribute?
 *
 * \param[in] xml   An XML IPC request
 *
 * \return true if there's a sync point attribute, false otherwise
 */
bool
attrd_request_has_sync_point(xmlNode *xml)
{
    return attrd_request_sync_point(xml) != NULL;
}

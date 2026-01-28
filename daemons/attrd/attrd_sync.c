/*
 * Copyright 2022-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>

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

/* A hash table storing information on in-progress IPC requests that are awaiting
 * confirmations.  These requests are currently being processed by peer attrds and
 * we are waiting to receive confirmation messages from each peer indicating that
 * processing is complete.
 *
 * Multiple requests could be waiting on confirmations at the same time.
 *
 * The key is the unique callid for the IPC request, and the value is a
 * confirmation_action struct.
 */
static GHashTable *expected_confirmations = NULL;

/*!
 * \internal
 * \brief A structure describing a single IPC request that is awaiting confirmations
 */
struct confirmation_action {
    /*!
     * \brief A list of peer attrds that we are waiting to receive confirmation
     *        messages from
     *
     * This list is dynamic - as confirmations arrive from peer attrds, they will
     * be removed from this list.  When the list is empty, all peers have processed
     * the request and the associated confirmation action will be taken.
     */
    GList *respondents;

    /*!
     * \brief A timer that will be used to remove the client should it time out
     *        before receiving all confirmations
     */
    mainloop_timer_t *timer;

    /*!
     * \brief A function to run when all confirmations have been received
     */
    attrd_confirmation_action_fn fn;

    /*!
     * \brief Information required to construct and send a reply to the client
     */
    char *client_id;
    uint32_t ipc_id;
    uint32_t flags;

    /*!
     * \brief The XML request containing the callid associated with this action
     */
    void *xml;
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
        return PCMK_VALUE_UNKNOWN;
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

    wl = pcmk__assert_alloc(1, sizeof(struct waitlist_node));

    if (pcmk__str_eq(sync_point, PCMK__VALUE_LOCAL, pcmk__str_none)) {
        wl->sync_point = attrd_sync_point_local;
    } else if (pcmk__str_eq(sync_point, PCMK__VALUE_CLUSTER, pcmk__str_none)) {
        wl->sync_point = attrd_sync_point_cluster;
    } else {
        free_waitlist_node(wl);
        return;
    }

    wl->client_id = pcmk__str_copy(request->ipc_client->id);
    wl->ipc_id = request->ipc_id;
    wl->flags = request->flags;

    next_key();
    pcmk__intkey_table_insert(waitlist, waitlist_client, wl);

    pcmk__trace("Added client %s to waitlist for %s sync point",
                wl->client_id, sync_point_str(wl->sync_point));
    pcmk__trace("%u clients now on waitlist", g_hash_table_size(waitlist));

    /* And then add the key to the request XML so we can uniquely identify
     * it when it comes time to issue the ACK.
     */
    pcmk__xe_set_int(request->xml, PCMK__XA_CALL_ID, waitlist_client);
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

        if (pcmk__str_eq(wl->client_id, client->id, pcmk__str_none)) {
            g_hash_table_iter_remove(&iter);
            pcmk__trace("%u clients now on waitlist",
                        g_hash_table_size(waitlist));
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

    if (pcmk__xe_get_int(xml, PCMK__XA_CALL_ID, &callid) != pcmk_rc_ok) {
        pcmk__warn("Could not get callid from request XML");
        return;
    }

    value = pcmk__intkey_table_lookup(waitlist, callid);
    if (value != NULL) {
        struct waitlist_node *wl = (struct waitlist_node *) value;
        pcmk__client_t *client = NULL;

        if (wl->sync_point != sync_point) {
            return;
        }

        pcmk__notice("Alerting client %s for reached %s sync point",
                     wl->client_id, sync_point_str(wl->sync_point));

        client = pcmk__find_client_by_id(wl->client_id);
        if (client == NULL) {
            return;
        }

        attrd_send_ack(client, wl->ipc_id, wl->flags | crm_ipc_client_response);

        /* And then remove the client so it doesn't get alerted again. */
        pcmk__intkey_table_remove(waitlist, callid);

        pcmk__trace("%u clients now on waitlist", g_hash_table_size(waitlist));
    }
}

/*!
 * \internal
 * \brief Action to take when a cluster sync point is hit for a
 *        PCMK__ATTRD_CMD_UPDATE* message.
 *
 * \param[in] xml  The request that should be passed along to
 *                 attrd_ack_waitlist_clients.  This should be the original
 *                 IPC request containing the callid for this update message.
 */
int
attrd_cluster_sync_point_update(xmlNode *xml)
{
    pcmk__trace("Hit cluster sync point for attribute update");
    attrd_ack_waitlist_clients(attrd_sync_point_cluster, xml);
    return pcmk_rc_ok;
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
    CRM_CHECK(xml != NULL, return NULL);

    if (xml->children != NULL) {
        xmlNode *child = pcmk__xe_first_child(xml, PCMK_XE_OP,
                                              PCMK__XA_ATTR_SYNC_POINT, NULL);

        if (child) {
            return pcmk__xe_get(child, PCMK__XA_ATTR_SYNC_POINT);
        } else {
            return NULL;
        }

    } else {
        return pcmk__xe_get(xml, PCMK__XA_ATTR_SYNC_POINT);
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

static void
free_action(gpointer data)
{
    struct confirmation_action *action = (struct confirmation_action *) data;
    g_list_free_full(action->respondents, free);
    mainloop_timer_del(action->timer);
    pcmk__xml_free(action->xml);
    free(action->client_id);
    free(action);
}

/* Remove an IPC request from the expected_confirmations table if the peer attrds
 * don't respond before the timeout is hit.  We set the timeout to 15s.  The exact
 * number isn't critical - we just want to make sure that the table eventually gets
 * cleared of things that didn't complete.
 */
static gboolean
confirmation_timeout_cb(gpointer data)
{
    struct confirmation_action *action = (struct confirmation_action *) data;

    GHashTableIter iter;
    gpointer value;

    if (expected_confirmations == NULL) {
        return G_SOURCE_REMOVE;
    }

    g_hash_table_iter_init(&iter, expected_confirmations);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        if (value == action) {
            pcmk__client_t *client = pcmk__find_client_by_id(action->client_id);
            if (client == NULL) {
                return G_SOURCE_REMOVE;
            }

            pcmk__trace("Timed out waiting for confirmations for client %s",
                        client->id);
            pcmk__ipc_send_ack(client, action->ipc_id,
                               action->flags|crm_ipc_client_response,
                               ATTRD_PROTOCOL_VERSION, CRM_EX_TIMEOUT);

            g_hash_table_iter_remove(&iter);
            pcmk__trace("%u requests now in expected confirmations table",
                        g_hash_table_size(expected_confirmations));
            break;
        }
    }

    return G_SOURCE_REMOVE;
}

/*!
 * \internal
 * \brief When a peer disconnects from the cluster, no longer wait for its confirmation
 *        for any IPC action.  If this peer is the last one being waited on, this will
 *        trigger the confirmation action.
 *
 * \param[in] host   The disconnecting peer attrd's uname
 */
void
attrd_do_not_expect_from_peer(const char *host)
{
    GList *keys = NULL;

    if (expected_confirmations == NULL) {
        return;
    }

    keys = g_hash_table_get_keys(expected_confirmations);

    pcmk__trace("Removing peer %s from expected confirmations", host);

    for (GList *node = keys; node != NULL; node = node->next) {
        int callid = *(int *) node->data;
        attrd_handle_confirmation(callid, host);
    }

    g_list_free(keys);
}

/*!
 * \internal
 * \brief When a client disconnects from the cluster, no longer wait on confirmations
 *        for it.  Because the peer attrds may still be processing the original IPC
 *        message, they may still send us confirmations.  However, we will take no
 *        action on them.
 *
 * \param[in] client    The disconnecting client
 */
void
attrd_do_not_wait_for_client(pcmk__client_t *client)
{
    GHashTableIter iter;
    gpointer value;

    if (expected_confirmations == NULL) {
        return;
    }

    g_hash_table_iter_init(&iter, expected_confirmations);

    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        struct confirmation_action *action = (struct confirmation_action *) value;

        if (pcmk__str_eq(action->client_id, client->id, pcmk__str_none)) {
            pcmk__trace("Removing client %s from expected confirmations",
                        client->id);
            g_hash_table_iter_remove(&iter);
            pcmk__trace("%u requests now in expected confirmations table",
                        g_hash_table_size(expected_confirmations));
            break;
        }
    }
}

/*!
 * \internal
 * \brief Register some action to be taken when IPC request confirmations are
 *        received
 *
 * When this function is called, a list of all peer attrds that support confirming
 * requests is generated.  As confirmations from these peer attrds are received,
 * they are removed from this list.  When the list is empty, the registered action
 * will be called.
 *
 * \note This function should always be called before attrd_send_message is called
 *       to broadcast to the peers to ensure that we know what replies we are
 *       waiting on.  Otherwise, it is possible the peer could finish and confirm
 *       before we know to expect it.
 *
 * \param[in] request The request that is awaiting confirmations
 * \param[in] fn      A function to be run after all confirmations are received
 */
void
attrd_expect_confirmations(pcmk__request_t *request, attrd_confirmation_action_fn fn)
{
    struct confirmation_action *action = NULL;
    GHashTableIter iter;
    gpointer host, ver;
    GList *respondents = NULL;
    int callid;

    if (expected_confirmations == NULL) {
        expected_confirmations = pcmk__intkey_table((GDestroyNotify) free_action);
    }

    if (pcmk__xe_get_int(request->xml, PCMK__XA_CALL_ID,
                         &callid) != pcmk_rc_ok) {
        pcmk__err("Could not get callid from xml");
        return;
    }

    if (pcmk__intkey_table_lookup(expected_confirmations, callid)) {
        pcmk__err("Already waiting on confirmations for call id %d", callid);
        return;
    }

    g_hash_table_iter_init(&iter, peer_protocol_vers);
    while (g_hash_table_iter_next(&iter, &host, &ver)) {
        if (ATTRD_SUPPORTS_CONFIRMATION(GPOINTER_TO_INT(ver))) {
            respondents = g_list_prepend(respondents,
                                         pcmk__str_copy((char *) host));
        }
    }

    action = pcmk__assert_alloc(1, sizeof(struct confirmation_action));

    action->respondents = respondents;
    action->fn = fn;
    action->xml = pcmk__xml_copy(NULL, request->xml);
    action->client_id = pcmk__str_copy(request->ipc_client->id);
    action->ipc_id = request->ipc_id;
    action->flags = request->flags;

    action->timer = mainloop_timer_add(NULL, 15000, FALSE, confirmation_timeout_cb, action);
    mainloop_timer_start(action->timer);

    pcmk__intkey_table_insert(expected_confirmations, callid, action);
    pcmk__trace("Callid %d now waiting on %u confirmations", callid,
                g_list_length(respondents));
    pcmk__trace("%u requests now in expected confirmations table",
                g_hash_table_size(expected_confirmations));
}

void
attrd_free_confirmations(void)
{
    if (expected_confirmations != NULL) {
        g_hash_table_destroy(expected_confirmations);
        expected_confirmations = NULL;
    }
}

/*!
 * \internal
 * \brief Process a confirmation message from a peer attrd
 *
 * This function is called every time a PCMK__ATTRD_CMD_CONFIRM message is
 * received from a peer attrd.  If this is the last confirmation we are waiting
 * on for a given operation, the registered action will be called.
 *
 * \param[in] callid The unique callid for the XML IPC request
 * \param[in] host   The confirming peer attrd's uname
 */
void
attrd_handle_confirmation(int callid, const char *host)
{
    struct confirmation_action *action = NULL;
    GList *node = NULL;

    if (expected_confirmations == NULL) {
        return;
    }

    action = pcmk__intkey_table_lookup(expected_confirmations, callid);
    if (action == NULL) {
        return;
    }

    node = g_list_find_custom(action->respondents, host, (GCompareFunc) strcasecmp);

    if (node == NULL) {
        return;
    }

    action->respondents = g_list_remove(action->respondents, node->data);
    pcmk__trace("Callid %d now waiting on %u confirmations", callid,
                g_list_length(action->respondents));

    if (action->respondents == NULL) {
        action->fn(action->xml);
        pcmk__intkey_table_remove(expected_confirmations, callid);
        pcmk__trace("%u requests now in expected confirmations table",
                    g_hash_table_size(expected_confirmations));
    }
}

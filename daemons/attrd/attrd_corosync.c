/*
 * Copyright 2013-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <crm/cluster.h>
#include <crm/cluster/internal.h>
#include <crm/common/logging.h>
#include <crm/common/results.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

pcmk_cluster_t *attrd_cluster = NULL;

/*!
 * \internal
 * \brief Nodes removed by \c attrd_peer_remove()
 *
 * This table is to be used as a set. It contains nodes that have been removed
 * by \c attrd_peer_remove() and whose transient attributes should be erased
 * from the CIB.
 *
 * Setting an attribute value for a node via \c update_attr_on_host() removes
 * the node from the table. At that point, we have transient attributes in
 * memory for the node, so it should no longer be erased from the CIB.
 *
 * If another node erases a removed node's transient attributes from the CIB,
 * the removed node remains in this table until an attribute value is set for
 * it. This is for convenience: it avoids the need to monitor for CIB updates
 * that erase a node's \c node_state or \c transient attributes element, just to
 * remove the node from the table.
 *
 * Leaving a removed node in the table after erasure should be harmless. If a
 * node is in this table, then we have no transient attributes for it in memory.
 * If for some reason we erase its transient attributes from the CIB twice, its
 * state in the CIB will still be correct.
 */
static GHashTable *removed_peers = NULL;

/*!
 * \internal
 * \brief Free the removed nodes table
 */
void
attrd_free_removed_peers(void)
{
    if (removed_peers != NULL) {
        g_hash_table_destroy(removed_peers);
    }
}

static xmlNode *
attrd_confirmation(int callid)
{
    xmlNode *node = pcmk__xe_create(NULL, __func__);

    pcmk__xe_set(node, PCMK__XA_T, PCMK__VALUE_ATTRD);
    pcmk__xe_set(node, PCMK__XA_SRC, pcmk__cluster_local_node_name());
    pcmk__xe_set(node, PCMK_XA_TASK, PCMK__ATTRD_CMD_CONFIRM);
    pcmk__xe_set_int(node, PCMK__XA_CALL_ID, callid);

    return node;
}

static void
attrd_peer_message(pcmk__node_status_t *peer, xmlNode *xml)
{
    const char *election_op = pcmk__xe_get(xml, PCMK__XA_CRM_TASK);

    if (election_op) {
        attrd_handle_election_op(peer, xml);
        return;
    }

    if (attrd_shutting_down()) {
        /* If we're shutting down, we want to continue responding to election
         * ops as long as we're a cluster member (because our vote may be
         * needed). Ignore all other messages.
         */
        return;

    } else {
        pcmk__request_t request = {
            .ipc_client     = NULL,
            .ipc_id         = 0,
            .ipc_flags      = crm_ipc_flags_none,
            .peer           = peer->name,
            .xml            = xml,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = pcmk__xe_get_copy(request.xml, PCMK_XA_TASK);
        CRM_CHECK(request.op != NULL, return);

        attrd_handle_request(&request);

        /* Having finished handling the request, check to see if the originating
         * peer requested confirmation.  If so, send that confirmation back now.
         */
        if (pcmk__xe_attr_is_true(xml, PCMK__XA_CONFIRM) &&
            !pcmk__str_eq(request.op, PCMK__ATTRD_CMD_CONFIRM, pcmk__str_none)) {
            int callid = 0;
            xmlNode *reply = NULL;

            /* Add the confirmation ID for the message we are confirming to the
             * response so the originating peer knows what they're a confirmation
             * for.
             */
            pcmk__xe_get_int(xml, PCMK__XA_CALL_ID, &callid);
            reply = attrd_confirmation(callid);

            /* And then send the confirmation back to the originating peer.  This
             * ends up right back in this same function (attrd_peer_message) on the
             * peer where it will have to do something with a PCMK__XA_CONFIRM type
             * message.
             */
            pcmk__debug("Sending %s a confirmation", peer->name);
            attrd_send_message(peer, reply, false);
            pcmk__xml_free(reply);
        }
    }
}

#if SUPPORT_COROSYNC
/*!
 * \internal
 * \brief Callback for when a peer message is received
 *
 * \param[in]     handle     The cluster connection
 * \param[in]     group_name The group that \p nodeid is a member of
 * \param[in]     nodeid     Peer node that sent \p msg
 * \param[in]     pid        Process that sent \p msg
 * \param[in,out] msg        Received message
 * \param[in]     msg_len    Length of \p msg
 */
static void
attrd_cpg_dispatch(cpg_handle_t handle, const struct cpg_name *group_name,
                   uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk__cpg_message_data(handle, nodeid, pid, msg, &from);

    if (data == NULL) {
        return;
    }

    xml = pcmk__xml_parse(data);
    if (xml == NULL) {
        pcmk__err("Bad message received from %s[%" PRIu32 "]: '%.120s'", from,
                  nodeid, data);
    } else {
        attrd_peer_message(pcmk__get_node(nodeid, from, NULL,
                                          pcmk__node_search_cluster_member),
                           xml);
    }

    pcmk__xml_free(xml);
    free(data);
}

/*!
 * \internal
 * \brief Callback for when the cluster object is destroyed
 *
 * \param[in] unused Unused
 */
static void
attrd_cpg_destroy(gpointer unused)
{
    if (attrd_shutting_down()) {
        pcmk__info("Disconnected from Corosync process group");

    } else {
        pcmk__crit("Lost connection to Corosync process group, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }
}
#endif // SUPPORT_COROSYNC

/*!
 * \internal
 * \brief Broadcast an update for a single attribute value
 *
 * \param[in] a  Attribute to broadcast
 * \param[in] v  Attribute value to broadcast
 */
void
attrd_broadcast_value(const attribute_t *a, const attribute_value_t *v)
{
    xmlNode *op = pcmk__xe_create(NULL, PCMK_XE_OP);

    pcmk__xe_set(op, PCMK_XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    attrd_add_value_xml(op, a, v, false);
    attrd_send_message(NULL, op, false);
    pcmk__xml_free(op);
}

#define state_text(state) pcmk__s((state), "in unknown state")

/*!
 * \internal
 * \brief Callback for peer status changes
 *
 * \param[in] type  What changed
 * \param[in] node  What peer had the change
 * \param[in] data  Previous value of what changed
 */
static void
attrd_peer_change_cb(enum pcmk__node_update kind, pcmk__node_status_t *peer,
                     const void *data)
{
    bool gone = false;
    bool is_remote = pcmk__is_set(peer->flags, pcmk__node_status_remote);

    switch (kind) {
        case pcmk__node_update_name:
            pcmk__debug("%s node %s[%" PRIu32 "] is now %s",
                        (is_remote? "Remote" : "Cluster"),
                        pcmk__s(peer->name, "unknown"), peer->cluster_layer_id,
                        state_text(peer->state));
            break;

        case pcmk__node_update_processes:
            if (!pcmk__is_set(peer->processes, crm_get_cluster_proc())) {
                gone = true;
            }
            pcmk__debug("Node %s[%" PRIu32 "] is %s a peer",
                        pcmk__s(peer->name, "unknown"), peer->cluster_layer_id,
                        (gone? "no longer" : "now"));
            break;

        case pcmk__node_update_state:
            pcmk__debug("%s node %s[%" PRIu32 "] is now %s (was %s)",
                        (is_remote? "Remote" : "Cluster"),
                        pcmk__s(peer->name, "unknown"), peer->cluster_layer_id,
                        state_text(peer->state), state_text(data));

            if (pcmk__str_eq(peer->state, PCMK_VALUE_MEMBER, pcmk__str_none)) {
                /* If we're the writer, send new peers a list of all attributes
                 * (unless it's a remote node, which doesn't run its own attrd)
                 */
                if (!is_remote) {
                   if (attrd_election_won()) {
                       attrd_peer_sync(peer);

                   } else {
                       // Anyway send a message so that the peer learns our name
                       attrd_send_protocol(peer);
                   }
                }

            } else {
                // Remove all attribute values associated with lost nodes
                if (peer->name != NULL) {
                    attrd_peer_remove(peer->name, false, "loss");
                }
                gone = true;
            }
            break;
    }

    // Remove votes from cluster nodes that leave, in case election in progress
    if (gone && !is_remote && peer->name != NULL) {
        attrd_remove_voter(peer);
        attrd_remove_peer_protocol_ver(peer->name);
        attrd_do_not_expect_from_peer(peer->name);
    }
}

#define readable_value(rv_v) pcmk__s((rv_v)->current, "(unset)")

#define readable_peer(p)    \
    (((p) == NULL)? "all peers" : pcmk__s((p)->name, "unknown peer"))

static void
update_attr_on_host(attribute_t *a, const pcmk__node_status_t *peer,
                    const xmlNode *xml, const char *attr, const char *value,
                    const char *host, bool filter)
{
    int is_remote = 0;
    bool changed = false;
    attribute_value_t *v = NULL;
    const char *prev_xml_id = NULL;
    const char *node_xml_id = pcmk__xe_get(xml, PCMK__XA_ATTR_HOST_ID);

    if (removed_peers != NULL) {
        g_hash_table_remove(removed_peers, host);
    }

    // Create entry for value if not already existing
    v = g_hash_table_lookup(a->values, host);
    if (v == NULL) {
        v = pcmk__assert_alloc(1, sizeof(attribute_value_t));

        v->nodename = pcmk__str_copy(host);
        g_hash_table_replace(a->values, v->nodename, v);
    }

    /* If update doesn't contain the node XML ID, fall back to any previously
     * known value (for logging)
     */
    prev_xml_id = attrd_get_node_xml_id(v->nodename);
    if (node_xml_id == NULL) {
        node_xml_id = prev_xml_id;
    }

    // If value is for a Pacemaker Remote node, remember that
    pcmk__xe_get_int(xml, PCMK__XA_ATTR_IS_REMOTE, &is_remote);
    if (is_remote) {
        attrd_set_value_flags(v, attrd_value_remote);
        pcmk__assert(pcmk__cluster_lookup_remote_node(host) != NULL);
    }

    // Check whether the value changed
    changed = !pcmk__str_eq(v->current, value, pcmk__str_casei);

    if (changed && filter
        && pcmk__str_eq(host, attrd_cluster->priv->node_name,
                        pcmk__str_casei)) {
        /* Broadcast the local value for an attribute that differs from the
         * value provided in a peer's attribute synchronization response. This
         * ensures a node's values for itself take precedence and all peers are
         * kept in sync.
         */
        v = g_hash_table_lookup(a->values, attrd_cluster->priv->node_name);
        pcmk__notice("%s[%s]: local value '%s' takes priority over '%s' from "
                     "%s",
                     attr, host, readable_value(v), value, peer->name);
        attrd_broadcast_value(a, v);

    } else if (changed) {
        const char *timeout_s = "no";

        if (a->timeout_ms != 0) {
            timeout_s = pcmk__readable_interval(a->timeout_ms);
        }

        pcmk__notice("Setting %s[%s]%s%s: %s -> %s "
                     QB_XS " from %s with %s write delay and node XML ID %s",
                     attr, host, ((a->set_type != NULL)? " in " : ""),
                     pcmk__s(a->set_type, ""), readable_value(v),
                     pcmk__s(value, "(unset)"), peer->name, timeout_s,
                     pcmk__s(node_xml_id, "unknown"));
        pcmk__str_update(&v->current, value);
        attrd_set_attr_flags(a, attrd_attr_changed);

        // Write out new value or start dampening timer
        if (a->timeout_ms && a->timer) {
            pcmk__trace("Delaying write of %s %s for dampening", attr,
                        pcmk__readable_interval(a->timeout_ms));
            mainloop_timer_start(a->timer);
        } else {
            attrd_write_or_elect_attribute(a);
        }

    } else {
        int is_force_write = 0;

        pcmk__xe_get_int(xml, PCMK__XA_ATTRD_IS_FORCE_WRITE, &is_force_write);

        if (is_force_write == 1 && a->timeout_ms && a->timer) {
            /* Save forced writing and set change flag. */
            /* The actual attribute is written by Writer after election. */
            pcmk__trace("%s[%s] from %s is unchanged (%s), forcing write", attr,
                        host, peer->name, pcmk__s(value, "unset"));
            attrd_set_attr_flags(a, attrd_attr_force_write);
        } else {
            pcmk__trace("%s[%s] from %s is unchanged (%s)", attr, host,
                        peer->name, pcmk__s(value, "unset"));
        }
    }

    // This allows us to later detect local values that peer doesn't know about
    attrd_set_value_flags(v, attrd_value_from_peer);

    // Remember node's XML ID if we're just learning it
    if ((node_xml_id != NULL)
        && !pcmk__str_eq(node_xml_id, prev_xml_id, pcmk__str_none)) {
        // Remember node's name in case unknown in the membership cache
        pcmk__node_status_t *known_peer =
            pcmk__get_node(0, host, node_xml_id,
                           pcmk__node_search_cluster_member);

        pcmk__trace("Learned %s[%s] node XML ID is %s (was %s)", a->id,
                    known_peer->name, node_xml_id,
                    pcmk__s(prev_xml_id, "unknown"));

        attrd_set_node_xml_id(v->nodename, node_xml_id);
        if (attrd_election_won()) {
            // In case we couldn't write a value missing the XML ID before
            attrd_write_attributes(attrd_write_changed);
        }
    }
}

static void
attrd_peer_update_one(const pcmk__node_status_t *peer, xmlNode *xml,
                      bool filter)
{
    attribute_t *a = NULL;
    const char *attr = pcmk__xe_get(xml, PCMK__XA_ATTR_NAME);
    const char *value = pcmk__xe_get(xml, PCMK__XA_ATTR_VALUE);
    const char *host = pcmk__xe_get(xml, PCMK__XA_ATTR_HOST);

    if (attr == NULL) {
        pcmk__warn("Could not update attribute: peer did not specify name");
        return;
    }

    a = attrd_populate_attribute(xml, attr);
    if (a == NULL) {
        return;
    }

    if (host == NULL) {
        // If no host was specified, update all hosts
        GHashTableIter vIter;

        pcmk__debug("Setting %s for all hosts to %s", attr, value);
        pcmk__xe_remove_attr(xml, PCMK__XA_ATTR_HOST_ID);
        g_hash_table_iter_init(&vIter, a->values);

        while (g_hash_table_iter_next(&vIter, (gpointer *) & host, NULL)) {
            update_attr_on_host(a, peer, xml, attr, value, host, filter);
        }

    } else {
        // Update attribute value for the given host
        update_attr_on_host(a, peer, xml, attr, value, host, filter);
    }

    /* If this is a message from some attrd instance broadcasting its protocol
     * version, check to see if it's a new minimum version.
     */
    if (pcmk__str_eq(attr, CRM_ATTR_PROTOCOL, pcmk__str_none)) {
        attrd_update_minimum_protocol_ver(peer->name, value);
    }
}

static void
broadcast_unseen_local_values(void)
{
    GHashTableIter aIter;
    GHashTableIter vIter;
    attribute_t *a = NULL;
    attribute_value_t *v = NULL;
    xmlNode *sync = NULL;

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {

        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & v)) {

            if (!pcmk__is_set(v->flags, attrd_value_from_peer)
                && pcmk__str_eq(v->nodename, attrd_cluster->priv->node_name,
                                pcmk__str_casei)) {
                pcmk__trace("* %s[%s]='%s' is local-only", a->id, v->nodename,
                            readable_value(v));
                if (sync == NULL) {
                    sync = pcmk__xe_create(NULL, __func__);
                    pcmk__xe_set(sync, PCMK_XA_TASK,
                                 PCMK__ATTRD_CMD_SYNC_RESPONSE);
                }
                attrd_add_value_xml(sync, a, v, a->timeout_ms && a->timer);
            }
        }
    }

    if (sync != NULL) {
        pcmk__debug("Broadcasting local-only values");
        attrd_send_message(NULL, sync, false);
        pcmk__xml_free(sync);
    }
}

/*!
 * \internal
 * \brief Initialize \c attrd_cluster and connect to the cluster layer
 *
 * \return Standard Pacemaker return code
 */
int
attrd_cluster_connect(void)
{
    int rc = pcmk_rc_ok;

    attrd_cluster = pcmk_cluster_new();

#if SUPPORT_COROSYNC
    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        pcmk_cluster_set_destroy_fn(attrd_cluster, attrd_cpg_destroy);
        pcmk_cpg_set_deliver_fn(attrd_cluster, attrd_cpg_dispatch);
        pcmk_cpg_set_confchg_fn(attrd_cluster, pcmk__cpg_confchg_cb);
    }
#endif // SUPPORT_COROSYNC

    pcmk__cluster_set_status_callback(&attrd_peer_change_cb);

    rc = pcmk_cluster_connect(attrd_cluster);
    if (rc != pcmk_rc_ok) {
        pcmk__err("Cluster connection failed");
    }

    return rc;
}

/*!
 * \internal
 * \brief Disconnect from the cluster layer and free \c attrd_cluster
 */
void
attrd_cluster_disconnect(void)
{
    if (attrd_cluster == NULL) {
        return;
    }

    pcmk_cluster_disconnect(attrd_cluster);
    g_clear_pointer(&attrd_cluster, pcmk_cluster_free);
}

void
attrd_peer_clear_failure(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;
    const char *rsc = pcmk__xe_get(xml, PCMK__XA_ATTR_RESOURCE);
    const char *host = pcmk__xe_get(xml, PCMK__XA_ATTR_HOST);
    const char *op = pcmk__xe_get(xml, PCMK__XA_ATTR_CLEAR_OPERATION);
    const char *interval_spec = pcmk__xe_get(xml, PCMK__XA_ATTR_CLEAR_INTERVAL);
    guint interval_ms = 0U;
    char *attr = NULL;
    GHashTableIter iter;
    regex_t regex;

    pcmk__node_status_t *peer =
        pcmk__get_node(0, request->peer, NULL,
                       pcmk__node_search_cluster_member);

    pcmk_parse_interval_spec(interval_spec, &interval_ms);

    if (attrd_failure_regex(&regex, rsc, op, interval_ms) != pcmk_ok) {
        pcmk__info("Ignoring invalid request to clear failures for %s",
                   pcmk__s(rsc, "all resources"));
        return;
    }

    pcmk__xe_set(xml, PCMK_XA_TASK, PCMK__ATTRD_CMD_UPDATE);

    /* Make sure value is not set, so we delete */
    pcmk__xe_remove_attr(xml, PCMK__XA_ATTR_VALUE);

    g_hash_table_iter_init(&iter, attributes);
    while (g_hash_table_iter_next(&iter, (gpointer *) &attr, NULL)) {
        if (regexec(&regex, attr, 0, NULL, 0) == 0) {
            pcmk__trace("Matched %s when clearing %s", attr,
                        pcmk__s(rsc, "all resources"));
            pcmk__xe_set(xml, PCMK__XA_ATTR_NAME, attr);
            attrd_peer_update(peer, xml, host, false);
        }
    }
    regfree(&regex);
}

/*!
 * \internal
 * \brief Load attributes from a peer sync response
 *
 * \param[in]     peer      Peer that sent sync response
 * \param[in]     peer_won  Whether peer is the attribute writer
 * \param[in,out] xml       Request XML
 */
void
attrd_peer_sync_response(const pcmk__node_status_t *peer, bool peer_won,
                         xmlNode *xml)
{
    pcmk__info("Processing " PCMK__ATTRD_CMD_SYNC_RESPONSE " from %s",
               peer->name);

    if (peer_won) {
        /* Initialize the "seen" flag for all attributes to cleared, so we can
         * detect attributes that local node has but the writer doesn't.
         */
        attrd_clear_value_seen();
    }

    // Process each attribute update in the sync response
    for (xmlNode *child = pcmk__xe_first_child(xml, NULL, NULL, NULL);
         child != NULL; child = pcmk__xe_next(child, NULL)) {

        attrd_peer_update(peer, child, pcmk__xe_get(child, PCMK__XA_ATTR_HOST),
                          true);
    }

    if (peer_won) {
        /* If any attributes are still not marked as seen, the writer doesn't
         * know about them, so send all peers an update with them.
         */
        broadcast_unseen_local_values();
    }
}

/*!
 * \internal
 * \brief Erase all removed nodes' transient attributes from the CIB
 *
 * This should be called by a newly elected writer upon winning the election.
 */
void
attrd_erase_removed_peer_attributes(void)
{
    const char *host = NULL;
    GHashTableIter iter;

    if (!attrd_election_won() || (removed_peers == NULL)) {
        return;
    }

    g_hash_table_iter_init(&iter, removed_peers);
    while (g_hash_table_iter_next(&iter, (gpointer *) &host, NULL)) {
        attrd_cib_erase_transient_attrs(host);
        g_hash_table_iter_remove(&iter);
    }
}

/*!
 * \internal
 * \brief Remove all attributes and optionally peer cache entries for a node
 *
 * \param[in] host     Name of node to purge
 * \param[in] uncache  If true, remove node from peer caches
 * \param[in] source   Who requested removal (only used for logging)
 */
void
attrd_peer_remove(const char *host, bool uncache, const char *source)
{
    attribute_t *a = NULL;
    GHashTableIter aIter;

    CRM_CHECK(host != NULL, return);
    pcmk__notice("Removing all %s attributes for node %s "
                 QB_XS " %s reaping node from cache",
                 host, source, (uncache? "and" : "without"));

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        if(g_hash_table_remove(a->values, host)) {
            pcmk__debug("Removed %s[%s] for peer %s", a->id, host, source);
        }
    }

    if (attrd_election_won()) {
        // We are the writer. Wipe node's transient attributes from CIB now.
        attrd_cib_erase_transient_attrs(host);

    } else {
        /* Make sure the attributes get erased from the CIB eventually.
         * - If there's already a writer, it will call this function and enter
         *   the "if" block above, requesting the erasure (unless it leaves
         *   before sending the request -- see below).
         *   attrd_start_election_if_needed() will do nothing here.
         * - Otherwise, we ensure an election is happening (unless we're
         *   shutting down). The winner will erase transient attributes from the
         *   CIB for all removed nodes in attrd_election_cb().
         *
         * We add the node to the removed_peers table in case we win an election
         * and need to request CIB erasures based on the table contents. This
         * could happen for either of two reasons:
         * - There is no current writer and we're not shutting down. An election
         *   either is already in progress or will be triggered here.
         * - The current writer leaves before sending the CIB update request. A
         *   new election will be triggered.
         */
        if (removed_peers == NULL) {
            removed_peers = pcmk__strikey_table(free, NULL);
        }
        g_hash_table_add(removed_peers, pcmk__str_copy(host));
        attrd_start_election_if_needed();
    }

    if (uncache) {
        pcmk__purge_node_from_cache(host, 0);
        attrd_forget_node_xml_id(host);
    }
}

/*!
 * \internal
 * \brief Send all known attributes and values to a peer
 *
 * \param[in] peer  Peer to send sync to (if NULL, broadcast to all peers)
 */
void
attrd_peer_sync(pcmk__node_status_t *peer)
{
    GHashTableIter aIter;
    GHashTableIter vIter;

    attribute_t *a = NULL;
    attribute_value_t *v = NULL;
    xmlNode *sync = pcmk__xe_create(NULL, __func__);

    pcmk__xe_set(sync, PCMK_XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & v)) {
            pcmk__debug("Syncing %s[%s]='%s' to %s", a->id, v->nodename,
                        readable_value(v), readable_peer(peer));
            attrd_add_value_xml(sync, a, v, false);
        }
    }

    pcmk__debug("Syncing values to %s", readable_peer(peer));
    attrd_send_message(peer, sync, false);
    pcmk__xml_free(sync);
}

void
attrd_peer_update(const pcmk__node_status_t *peer, xmlNode *xml,
                  const char *host, bool filter)
{
    bool handle_sync_point = false;

    CRM_CHECK((peer != NULL) && (xml != NULL), return);
    if (xml->children != NULL) {
        for (xmlNode *child = pcmk__xe_first_child(xml, PCMK_XE_OP, NULL, NULL);
             child != NULL; child = pcmk__xe_next(child, PCMK_XE_OP)) {

            pcmk__xe_copy_attrs(child, xml, pcmk__xaf_no_overwrite);
            attrd_peer_update_one(peer, child, filter);

            if (attrd_request_has_sync_point(child)) {
                handle_sync_point = true;
            }
        }

    } else {
        attrd_peer_update_one(peer, xml, filter);

        if (attrd_request_has_sync_point(xml)) {
            handle_sync_point = true;
        }
    }

    /* If the update XML specified that the client wanted to wait for a sync
     * point, process that now.
     */
    if (handle_sync_point) {
        pcmk__trace("Hit local sync point for attribute update");
        attrd_ack_waitlist_clients(attrd_sync_point_local, xml);
    }
}

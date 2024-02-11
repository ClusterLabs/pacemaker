/*
 * Copyright 2013-2024 the Pacemaker project contributors
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
#include <crm/common/strings_internal.h>
#include <crm/common/xml.h>

#include "pacemaker-attrd.h"

static xmlNode *
attrd_confirmation(int callid)
{
    xmlNode *node = pcmk__xe_create(NULL, __func__);

    crm_xml_add(node, PCMK__XA_T, PCMK__VALUE_ATTRD);
    crm_xml_add(node, PCMK__XA_SRC, get_local_node_name());
    crm_xml_add(node, PCMK_XA_TASK, PCMK__ATTRD_CMD_CONFIRM);
    crm_xml_add_int(node, PCMK__XA_CALL_ID, callid);

    return node;
}

static void
attrd_peer_message(crm_node_t *peer, xmlNode *xml)
{
    const char *election_op = crm_element_value(xml, PCMK__XA_CRM_TASK);

    if (election_op) {
        attrd_handle_election_op(peer, xml);
        return;
    }

    if (attrd_shutting_down(false)) {
        /* If we're shutting down, we want to continue responding to election
         * ops as long as we're a cluster member (because our vote may be
         * needed). Ignore all other messages.
         */
        return;

    } else {
        pcmk__request_t request = {
            .ipc_client     = NULL,
            .ipc_id         = 0,
            .ipc_flags      = 0,
            .peer           = peer->uname,
            .xml            = xml,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = crm_element_value_copy(request.xml, PCMK_XA_TASK);
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
            crm_element_value_int(xml, PCMK__XA_CALL_ID, &callid);
            reply = attrd_confirmation(callid);

            /* And then send the confirmation back to the originating peer.  This
             * ends up right back in this same function (attrd_peer_message) on the
             * peer where it will have to do something with a PCMK__XA_CONFIRM type
             * message.
             */
            crm_debug("Sending %s a confirmation", peer->uname);
            attrd_send_message(peer, reply, false);
            free_xml(reply);
        }

        pcmk__reset_request(&request);
    }
}

static void
attrd_cpg_dispatch(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }

    if (kind == crm_class_cluster) {
        xml = pcmk__xml_parse(data);
    }

    if (xml == NULL) {
        crm_err("Bad message of class %d received from %s[%u]: '%.120s'", kind, from, nodeid, data);
    } else {
        attrd_peer_message(pcmk__get_node(nodeid, from, NULL,
                                          pcmk__node_search_cluster),
                           xml);
    }

    free_xml(xml);
    free(data);
}

static void
attrd_cpg_destroy(gpointer unused)
{
    if (attrd_shutting_down(false)) {
        crm_info("Disconnected from Corosync process group");

    } else {
        crm_crit("Lost connection to Corosync process group, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }
}

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

    crm_xml_add(op, PCMK_XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    attrd_add_value_xml(op, a, v, false);
    attrd_send_message(NULL, op, false);
    free_xml(op);
}

#define state_text(state) pcmk__s((state), "in unknown state")

static void
attrd_peer_change_cb(enum crm_status_type kind, crm_node_t *peer, const void *data)
{
    bool gone = false;
    bool is_remote = pcmk_is_set(peer->flags, crm_remote_node);

    switch (kind) {
        case crm_status_uname:
            crm_debug("%s node %s is now %s",
                      (is_remote? "Remote" : "Cluster"),
                      peer->uname, state_text(peer->state));
            break;

        case crm_status_processes:
            if (!pcmk_is_set(peer->processes, crm_get_cluster_proc())) {
                gone = true;
            }
            crm_debug("Node %s is %s a peer",
                      peer->uname, (gone? "no longer" : "now"));
            break;

        case crm_status_nstate:
            crm_debug("%s node %s is now %s (was %s)",
                      (is_remote? "Remote" : "Cluster"),
                      peer->uname, state_text(peer->state), state_text(data));
            if (pcmk__str_eq(peer->state, CRM_NODE_MEMBER, pcmk__str_casei)) {
                /* If we're the writer, send new peers a list of all attributes
                 * (unless it's a remote node, which doesn't run its own attrd)
                 */
                if (attrd_election_won()
                    && !pcmk_is_set(peer->flags, crm_remote_node)) {
                    attrd_peer_sync(peer);
                }
            } else {
                // Remove all attribute values associated with lost nodes
                attrd_peer_remove(peer->uname, false, "loss");
                gone = true;
            }
            break;
    }

    // Remove votes from cluster nodes that leave, in case election in progress
    if (gone && !is_remote) {
        attrd_remove_voter(peer);
        attrd_remove_peer_protocol_ver(peer->uname);
        attrd_do_not_expect_from_peer(peer->uname);
    }
}

static void
record_peer_nodeid(attribute_value_t *v, const char *host)
{
    crm_node_t *known_peer = pcmk__get_node(v->nodeid, host, NULL,
                                            pcmk__node_search_cluster);

    crm_trace("Learned %s has node id %s", known_peer->uname, known_peer->uuid);
    if (attrd_election_won()) {
        attrd_write_attributes(attrd_write_changed);
    }
}

#define readable_value(rv_v) pcmk__s((rv_v)->current, "(unset)")

#define readable_peer(p)    \
    (((p) == NULL)? "all peers" : pcmk__s((p)->uname, "unknown peer"))

static void
update_attr_on_host(attribute_t *a, const crm_node_t *peer, const xmlNode *xml,
                    const char *attr, const char *value, const char *host,
                    bool filter)
{
    int is_remote = 0;
    bool changed = false;
    attribute_value_t *v = NULL;

    // Create entry for value if not already existing
    v = g_hash_table_lookup(a->values, host);
    if (v == NULL) {
        v = pcmk__assert_alloc(1, sizeof(attribute_value_t));

        v->nodename = pcmk__str_copy(host);
        g_hash_table_replace(a->values, v->nodename, v);
    }

    // If value is for a Pacemaker Remote node, remember that
    crm_element_value_int(xml, PCMK__XA_ATTR_IS_REMOTE, &is_remote);
    if (is_remote) {
        attrd_set_value_flags(v, attrd_value_remote);
        CRM_ASSERT(crm_remote_peer_get(host) != NULL);
    }

    // Check whether the value changed
    changed = !pcmk__str_eq(v->current, value, pcmk__str_casei);

    if (changed && filter && pcmk__str_eq(host, attrd_cluster->uname,
                                          pcmk__str_casei)) {
        /* Broadcast the local value for an attribute that differs from the
         * value provided in a peer's attribute synchronization response. This
         * ensures a node's values for itself take precedence and all peers are
         * kept in sync.
         */
        v = g_hash_table_lookup(a->values, attrd_cluster->uname);
        crm_notice("%s[%s]: local value '%s' takes priority over '%s' from %s",
                   attr, host, readable_value(v), value, peer->uname);
        attrd_broadcast_value(a, v);

    } else if (changed) {
        crm_notice("Setting %s[%s]%s%s: %s -> %s "
                   CRM_XS " from %s with %s write delay",
                   attr, host, a->set_type ? " in " : "",
                   pcmk__s(a->set_type, ""), readable_value(v),
                   pcmk__s(value, "(unset)"), peer->uname,
                   (a->timeout_ms == 0)? "no" : pcmk__readable_interval(a->timeout_ms));
        pcmk__str_update(&v->current, value);
        attrd_set_attr_flags(a, attrd_attr_changed);

        if (pcmk__str_eq(host, attrd_cluster->uname, pcmk__str_casei)
            && pcmk__str_eq(attr, PCMK__NODE_ATTR_SHUTDOWN, pcmk__str_none)) {

            if (!pcmk__str_eq(value, "0", pcmk__str_null_matches)) {
                attrd_set_requesting_shutdown();

            } else {
                attrd_clear_requesting_shutdown();
            }
        }

        // Write out new value or start dampening timer
        if (a->timeout_ms && a->timer) {
            crm_trace("Delaying write of %s %s for dampening",
                      attr, pcmk__readable_interval(a->timeout_ms));
            mainloop_timer_start(a->timer);
        } else {
            attrd_write_or_elect_attribute(a);
        }

    } else {
        int is_force_write = 0;

        crm_element_value_int(xml, PCMK__XA_ATTRD_IS_FORCE_WRITE,
                              &is_force_write);

        if (is_force_write == 1 && a->timeout_ms && a->timer) {
            /* Save forced writing and set change flag. */
            /* The actual attribute is written by Writer after election. */
            crm_trace("%s[%s] from %s is unchanged (%s), forcing write",
                      attr, host, peer->uname, pcmk__s(value, "unset"));
            attrd_set_attr_flags(a, attrd_attr_force_write);
        } else {
            crm_trace("%s[%s] from %s is unchanged (%s)",
                      attr, host, peer->uname, pcmk__s(value, "unset"));
        }
    }

    // This allows us to later detect local values that peer doesn't know about
    attrd_set_value_flags(v, attrd_value_from_peer);

    /* If this is a cluster node whose node ID we are learning, remember it */
    if ((v->nodeid == 0) && !pcmk_is_set(v->flags, attrd_value_remote)
        && (crm_element_value_int(xml, PCMK__XA_ATTR_HOST_ID,
                                  (int*)&v->nodeid) == 0) && (v->nodeid > 0)) {
        record_peer_nodeid(v, host);
    }
}

static void
attrd_peer_update_one(const crm_node_t *peer, xmlNode *xml, bool filter)
{
    attribute_t *a = NULL;
    const char *attr = crm_element_value(xml, PCMK__XA_ATTR_NAME);
    const char *value = crm_element_value(xml, PCMK__XA_ATTR_VALUE);
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_HOST);

    if (attr == NULL) {
        crm_warn("Could not update attribute: peer did not specify name");
        return;
    }

    a = attrd_populate_attribute(xml, attr);
    if (a == NULL) {
        return;
    }

    if (host == NULL) {
        // If no host was specified, update all hosts
        GHashTableIter vIter;

        crm_debug("Setting %s for all hosts to %s", attr, value);
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
        attrd_update_minimum_protocol_ver(peer->uname, value);
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

            if (!pcmk_is_set(v->flags, attrd_value_from_peer)
                && pcmk__str_eq(v->nodename, attrd_cluster->uname,
                                pcmk__str_casei)) {
                crm_trace("* %s[%s]='%s' is local-only",
                          a->id, v->nodename, readable_value(v));
                if (sync == NULL) {
                    sync = pcmk__xe_create(NULL, __func__);
                    crm_xml_add(sync, PCMK_XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);
                }
                attrd_add_value_xml(sync, a, v, a->timeout_ms && a->timer);
            }
        }
    }

    if (sync != NULL) {
        crm_debug("Broadcasting local-only values");
        attrd_send_message(NULL, sync, false);
        free_xml(sync);
    }
}

int
attrd_cluster_connect(void)
{
    attrd_cluster = pcmk_cluster_new();

    attrd_cluster->destroy = attrd_cpg_destroy;
    attrd_cluster->cpg.cpg_deliver_fn = attrd_cpg_dispatch;
    attrd_cluster->cpg.cpg_confchg_fn = pcmk_cpg_membership;

    crm_set_status_callback(&attrd_peer_change_cb);

    if (crm_cluster_connect(attrd_cluster) == FALSE) {
        crm_err("Cluster connection failed");
        return -ENOTCONN;
    }
    return pcmk_ok;
}

void
attrd_peer_clear_failure(pcmk__request_t *request)
{
    xmlNode *xml = request->xml;
    const char *rsc = crm_element_value(xml, PCMK__XA_ATTR_RESOURCE);
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_HOST);
    const char *op = crm_element_value(xml, PCMK__XA_ATTR_CLEAR_OPERATION);
    const char *interval_spec = crm_element_value(xml,
                                                  PCMK__XA_ATTR_CLEAR_INTERVAL);
    guint interval_ms = 0U;
    char *attr = NULL;
    GHashTableIter iter;
    regex_t regex;

    crm_node_t *peer = pcmk__get_node(0, request->peer, NULL,
                                      pcmk__node_search_cluster);

    pcmk_parse_interval_spec(interval_spec, &interval_ms);

    if (attrd_failure_regex(&regex, rsc, op, interval_ms) != pcmk_ok) {
        crm_info("Ignoring invalid request to clear failures for %s",
                 pcmk__s(rsc, "all resources"));
        return;
    }

    crm_xml_add(xml, PCMK_XA_TASK, PCMK__ATTRD_CMD_UPDATE);

    /* Make sure value is not set, so we delete */
    pcmk__xe_remove_attr(xml, PCMK__XA_ATTR_VALUE);

    g_hash_table_iter_init(&iter, attributes);
    while (g_hash_table_iter_next(&iter, (gpointer *) &attr, NULL)) {
        if (regexec(&regex, attr, 0, NULL, 0) == 0) {
            crm_trace("Matched %s when clearing %s",
                      attr, pcmk__s(rsc, "all resources"));
            crm_xml_add(xml, PCMK__XA_ATTR_NAME, attr);
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
attrd_peer_sync_response(const crm_node_t *peer, bool peer_won, xmlNode *xml)
{
    crm_info("Processing " PCMK__ATTRD_CMD_SYNC_RESPONSE " from %s",
             peer->uname);

    if (peer_won) {
        /* Initialize the "seen" flag for all attributes to cleared, so we can
         * detect attributes that local node has but the writer doesn't.
         */
        attrd_clear_value_seen();
    }

    // Process each attribute update in the sync response
    for (xmlNode *child = pcmk__xe_first_child_any(xml); child != NULL;
         child = pcmk__xe_next(child)) {
        attrd_peer_update(peer, child,
                          crm_element_value(child, PCMK__XA_ATTR_HOST), true);
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
    crm_notice("Removing all %s attributes for node %s "
               CRM_XS " %s reaping node from cache",
               host, source, (uncache? "and" : "without"));

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        if(g_hash_table_remove(a->values, host)) {
            crm_debug("Removed %s[%s] for peer %s", a->id, host, source);
        }
    }

    if (uncache) {
        pcmk__purge_node_from_cache(host, 0);
    }
}

/*!
 * \internal
 * \brief Send all known attributes and values to a peer
 *
 * \param[in] peer  Peer to send sync to (if NULL, broadcast to all peers)
 */
void
attrd_peer_sync(crm_node_t *peer)
{
    GHashTableIter aIter;
    GHashTableIter vIter;

    attribute_t *a = NULL;
    attribute_value_t *v = NULL;
    xmlNode *sync = pcmk__xe_create(NULL, __func__);

    crm_xml_add(sync, PCMK_XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & v)) {
            crm_debug("Syncing %s[%s]='%s' to %s",
                      a->id, v->nodename, readable_value(v),
                      readable_peer(peer));
            attrd_add_value_xml(sync, a, v, false);
        }
    }

    crm_debug("Syncing values to %s", readable_peer(peer));
    attrd_send_message(peer, sync, false);
    free_xml(sync);
}

void
attrd_peer_update(const crm_node_t *peer, xmlNode *xml, const char *host,
                  bool filter)
{
    bool handle_sync_point = false;

    CRM_CHECK((peer != NULL) && (xml != NULL), return);
    if (xml->children != NULL) {
        for (xmlNode *child = pcmk__xe_first_child(xml, PCMK_XE_OP, NULL, NULL);
             child != NULL; child = pcmk__xe_next_same(child)) {

            attrd_copy_xml_attributes(xml, child);
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
        crm_trace("Hit local sync point for attribute update");
        attrd_ack_waitlist_clients(attrd_sync_point_local, xml);
    }
}

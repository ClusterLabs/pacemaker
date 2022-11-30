/*
 * Copyright 2013-2022 the Pacemaker project contributors
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
#include <crm/msg_xml.h>

#include "pacemaker-attrd.h"

extern crm_exit_t attrd_exit_status;

static xmlNode *
attrd_confirmation(int callid)
{
    xmlNode *node = create_xml_node(NULL, __func__);

    crm_xml_add(node, F_TYPE, T_ATTRD);
    crm_xml_add(node, F_ORIG, get_local_node_name());
    crm_xml_add(node, PCMK__XA_TASK, PCMK__ATTRD_CMD_CONFIRM);
    crm_xml_add_int(node, XML_LRM_ATTR_CALLID, callid);

    return node;
}

static void
attrd_peer_message(crm_node_t *peer, xmlNode *xml)
{
    const char *election_op = crm_element_value(xml, F_CRM_TASK);

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
            .ipc_flags      = 0,
            .peer           = peer->uname,
            .xml            = xml,
            .call_options   = 0,
            .result         = PCMK__UNKNOWN_RESULT,
        };

        request.op = crm_element_value_copy(request.xml, PCMK__XA_TASK);
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
            crm_element_value_int(xml, XML_LRM_ATTR_CALLID, &callid);
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
        xml = string2xml(data);
    }

    if (xml == NULL) {
        crm_err("Bad message of class %d received from %s[%u]: '%.120s'", kind, from, nodeid, data);
    } else {
        crm_node_t *peer = crm_get_peer(nodeid, from);

        attrd_peer_message(peer, xml);
    }

    free_xml(xml);
    free(data);
}

static void
attrd_cpg_destroy(gpointer unused)
{
    if (attrd_shutting_down()) {
        crm_info("Corosync disconnection complete");

    } else {
        crm_crit("Lost connection to cluster layer, shutting down");
        attrd_exit_status = CRM_EX_DISCONNECT;
        attrd_shutdown(0);
    }
}

/*!
 * \internal
 * \brief Override an attribute sync with a local value
 *
 * Broadcast the local node's value for an attribute that's different from the
 * value provided in a peer's attribute synchronization response. This ensures a
 * node's values for itself take precedence and all peers are kept in sync.
 *
 * \param[in] a          Attribute entry to override
 *
 * \return Local instance of attribute value
 */
static attribute_value_t *
broadcast_local_value(const attribute_t *a)
{
    attribute_value_t *v = g_hash_table_lookup(a->values, attrd_cluster->uname);
    xmlNode *sync = create_xml_node(NULL, __func__);

    crm_xml_add(sync, PCMK__XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);
    attrd_add_value_xml(sync, a, v, false);
    attrd_send_message(NULL, sync, false);
    free_xml(sync);
    return v;
}

/*!
 * \internal
 * \brief Ensure a Pacemaker Remote node is in the correct peer cache
 *
 * \param[in] node_name  Name of Pacemaker Remote node to check
 */
static void
cache_remote_node(const char *node_name)
{
    /* If we previously assumed this node was an unseen cluster node,
     * remove its entry from the cluster peer cache.
     */
    crm_node_t *dup = pcmk__search_cluster_node_cache(0, node_name);

    if (dup && (dup->uuid == NULL)) {
        reap_crm_member(0, node_name);
    }

    // Ensure node is in the remote peer cache
    CRM_ASSERT(crm_remote_peer_get(node_name) != NULL);
}

#define state_text(state) pcmk__s((state), "in unknown state")

/*!
 * \internal
 * \brief Return host's hash table entry (creating one if needed)
 *
 * \param[in,out] values Hash table of values
 * \param[in]     host   Name of peer to look up
 * \param[in]     xml    XML describing the attribute
 *
 * \return Pointer to new or existing hash table entry
 */
static attribute_value_t *
attrd_lookup_or_create_value(GHashTable *values, const char *host,
                             const xmlNode *xml)
{
    attribute_value_t *v = g_hash_table_lookup(values, host);
    int is_remote = 0;

    crm_element_value_int(xml, PCMK__XA_ATTR_IS_REMOTE, &is_remote);
    if (is_remote) {
        cache_remote_node(host);
    }

    if (v == NULL) {
        v = calloc(1, sizeof(attribute_value_t));
        CRM_ASSERT(v != NULL);

        pcmk__str_update(&v->nodename, host);
        v->is_remote = is_remote;
        g_hash_table_replace(values, v->nodename, v);
    }
    return(v);
}

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
                    attrd_peer_sync(peer, NULL);
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

    // Ensure remote nodes that come up are in the remote node cache
    } else if (!gone && is_remote) {
        cache_remote_node(peer->uname);
    }
}

static void
record_peer_nodeid(attribute_value_t *v, const char *host)
{
    crm_node_t *known_peer = crm_get_peer(v->nodeid, host);

    crm_trace("Learned %s has node id %s", known_peer->uname, known_peer->uuid);
    if (attrd_election_won()) {
        attrd_write_attributes(false, false);
    }
}

static void
update_attr_on_host(attribute_t *a, const crm_node_t *peer, const xmlNode *xml,
                    const char *attr, const char *value, const char *host,
                    bool filter, int is_force_write)
{
    attribute_value_t *v = NULL;

    v = attrd_lookup_or_create_value(a->values, host, xml);

    if (filter && !pcmk__str_eq(v->current, value, pcmk__str_casei)
        && pcmk__str_eq(host, attrd_cluster->uname, pcmk__str_casei)) {

        crm_notice("%s[%s]: local value '%s' takes priority over '%s' from %s",
                   attr, host, v->current, value, peer->uname);
        v = broadcast_local_value(a);

    } else if (!pcmk__str_eq(v->current, value, pcmk__str_casei)) {
        crm_notice("Setting %s[%s]: %s -> %s "
                   CRM_XS " from %s with %s write delay",
                   attr, host, pcmk__s(v->current, "(unset)"),
                   pcmk__s(value, "(unset)"), peer->uname,
                   (a->timeout_ms == 0)? "no" : pcmk__readable_interval(a->timeout_ms));
        pcmk__str_update(&v->current, value);
        a->changed = true;

        if (pcmk__str_eq(host, attrd_cluster->uname, pcmk__str_casei)
            && pcmk__str_eq(attr, XML_CIB_ATTR_SHUTDOWN, pcmk__str_none)) {

            if (!pcmk__str_eq(value, "0", pcmk__str_null_matches)) {
                attrd_set_requesting_shutdown();

            } else {
                attrd_clear_requesting_shutdown();
            }
        }

        // Write out new value or start dampening timer
        if (a->timeout_ms && a->timer) {
            crm_trace("Delayed write out (%dms) for %s", a->timeout_ms, attr);
            mainloop_timer_start(a->timer);
        } else {
            attrd_write_or_elect_attribute(a);
        }

    } else {
        if (is_force_write == 1 && a->timeout_ms && a->timer) {
            /* Save forced writing and set change flag. */
            /* The actual attribute is written by Writer after election. */
            crm_trace("Unchanged %s[%s] from %s is %s(Set the forced write flag)",
                      attr, host, peer->uname, value);
            a->force_write = TRUE;
        } else {
            crm_trace("Unchanged %s[%s] from %s is %s", attr, host, peer->uname, value);
        }
    }

    /* Set the seen flag for attribute processing held only in the own node. */
    v->seen = TRUE;

    /* If this is a cluster node whose node ID we are learning, remember it */
    if ((v->nodeid == 0) && (v->is_remote == FALSE)
        && (crm_element_value_int(xml, PCMK__XA_ATTR_NODE_ID,
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
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
    int is_force_write = 0;

    if (attr == NULL) {
        crm_warn("Could not update attribute: peer did not specify name");
        return;
    }

    crm_element_value_int(xml, PCMK__XA_ATTR_FORCE, &is_force_write);

    a = attrd_populate_attribute(xml, attr);
    if (a == NULL) {
        return;
    }

    if (host == NULL) {
        // If no host was specified, update all hosts
        GHashTableIter vIter;

        crm_debug("Setting %s for all hosts to %s", attr, value);
        xml_remove_prop(xml, PCMK__XA_ATTR_NODE_ID);
        g_hash_table_iter_init(&vIter, a->values);

        while (g_hash_table_iter_next(&vIter, (gpointer *) & host, NULL)) {
            update_attr_on_host(a, peer, xml, attr, value, host, filter, is_force_write);
        }

    } else {
        // Update attribute value for the given host
        update_attr_on_host(a, peer, xml, attr, value, host, filter, is_force_write);
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
            if (!(v->seen) && pcmk__str_eq(v->nodename, attrd_cluster->uname,
                                           pcmk__str_casei)) {
                if (sync == NULL) {
                    sync = create_xml_node(NULL, __func__);
                    crm_xml_add(sync, PCMK__XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);
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
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
    const char *op = crm_element_value(xml, PCMK__XA_ATTR_OPERATION);
    const char *interval_spec = crm_element_value(xml, PCMK__XA_ATTR_INTERVAL);
    guint interval_ms = crm_parse_interval_spec(interval_spec);
    char *attr = NULL;
    GHashTableIter iter;
    regex_t regex;

    crm_node_t *peer = crm_get_peer(0, request->peer);

    if (attrd_failure_regex(&regex, rsc, op, interval_ms) != pcmk_ok) {
        crm_info("Ignoring invalid request to clear failures for %s",
                 pcmk__s(rsc, "all resources"));
        return;
    }

    crm_xml_add(xml, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE);

    /* Make sure value is not set, so we delete */
    if (crm_element_value(xml, PCMK__XA_ATTR_VALUE)) {
        crm_xml_replace(xml, PCMK__XA_ATTR_VALUE, NULL);
    }

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
 * \param[in]     peer      Peer that sent clear request
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
    for (xmlNode *child = pcmk__xml_first_child(xml); child != NULL;
         child = pcmk__xml_next(child)) {
        attrd_peer_update(peer, child,
                          crm_element_value(child, PCMK__XA_ATTR_NODE_NAME),
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
    crm_notice("Removing all %s attributes for peer %s", host, source);

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        if(g_hash_table_remove(a->values, host)) {
            crm_debug("Removed %s[%s] for peer %s", a->id, host, source);
        }
    }

    if (uncache) {
        crm_remote_peer_cache_remove(host);
        reap_crm_member(0, host);
    }
}

void
attrd_peer_sync(crm_node_t *peer, xmlNode *xml)
{
    GHashTableIter aIter;
    GHashTableIter vIter;

    attribute_t *a = NULL;
    attribute_value_t *v = NULL;
    xmlNode *sync = create_xml_node(NULL, __func__);

    crm_xml_add(sync, PCMK__XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & v)) {
            crm_debug("Syncing %s[%s] = %s to %s", a->id, v->nodename, v->current, peer?peer->uname:"everyone");
            attrd_add_value_xml(sync, a, v, false);
        }
    }

    crm_debug("Syncing values to %s", peer?peer->uname:"everyone");
    attrd_send_message(peer, sync, false);
    free_xml(sync);
}

static void
copy_attrs(xmlNode *src, xmlNode *dest)
{
    /* Copy attributes from the wrapper parent node into the child node.
     * We can't just use copy_in_properties because we want to skip any
     * attributes that are already set on the child.  For instance, if
     * we were told to use a specific node, there will already be a node
     * attribute on the child.  Copying the parent's node attribute over
     * could result in the wrong value.
     */
    for (xmlAttrPtr a = pcmk__xe_first_attr(src); a != NULL; a = a->next) {
        const char *p_name = (const char *) a->name;
        const char *p_value = ((a == NULL) || (a->children == NULL)) ? NULL :
                              (const char *) a->children->content;

        if (crm_element_value(dest, p_name) == NULL) {
            crm_xml_add(dest, p_name, p_value);
        }
    }
}

void
attrd_peer_update(const crm_node_t *peer, xmlNode *xml, const char *host,
                  bool filter)
{
    bool handle_sync_point = false;

    if (xml_has_children(xml)) {
        for (xmlNode *child = first_named_child(xml, XML_ATTR_OP); child != NULL;
             child = crm_next_same_xml(child)) {
            copy_attrs(xml, child);
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

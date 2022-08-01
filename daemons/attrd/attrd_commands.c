/*
 * Copyright 2013-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/types.h>
#include <regex.h>
#include <glib.h>

#include <crm/msg_xml.h>
#include <crm/cluster.h>
#include <crm/cib.h>
#include <crm/common/xml_internal.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include <crm/cib/internal.h>

#include "pacemaker-attrd.h"

int minimum_protocol_version = -1;

GHashTable *attributes = NULL;

static void broadcast_unseen_local_values(crm_node_t *peer, xmlNode *xml);

gboolean
send_attrd_message(crm_node_t * node, xmlNode * data)
{
    crm_xml_add(data, F_TYPE, T_ATTRD);
    crm_xml_add(data, PCMK__XA_ATTR_VERSION, ATTRD_PROTOCOL_VERSION);
    attrd_xml_add_writer(data);
    return send_cluster_message(node, crm_msg_attrd, data, TRUE);
}

/*!
 * \internal
 * \brief Ensure a Pacemaker Remote node is in the correct peer cache
 *
 * \param[in]
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

/*!
 * \internal
 * \brief Create an XML representation of an attribute for use in peer messages
 *
 * \param[in] parent       Create attribute XML as child element of this element
 * \param[in] a            Attribute to represent
 * \param[in] v            Attribute value to represent
 * \param[in] force_write  If true, value should be written even if unchanged
 *
 * \return XML representation of attribute
 */
static xmlNode *
add_attribute_value_xml(xmlNode *parent, attribute_t *a, attribute_value_t *v,
                        bool force_write)
{
    xmlNode *xml = create_xml_node(parent, __func__);

    crm_xml_add(xml, PCMK__XA_ATTR_NAME, a->id);
    crm_xml_add(xml, PCMK__XA_ATTR_SET, a->set);
    crm_xml_add(xml, PCMK__XA_ATTR_UUID, a->uuid);
    crm_xml_add(xml, PCMK__XA_ATTR_USER, a->user);
    crm_xml_add(xml, PCMK__XA_ATTR_NODE_NAME, v->nodename);
    if (v->nodeid > 0) {
        crm_xml_add_int(xml, PCMK__XA_ATTR_NODE_ID, v->nodeid);
    }
    if (v->is_remote != 0) {
        crm_xml_add_int(xml, PCMK__XA_ATTR_IS_REMOTE, 1);
    }
    crm_xml_add(xml, PCMK__XA_ATTR_VALUE, v->current);
    crm_xml_add_int(xml, PCMK__XA_ATTR_DAMPENING, a->timeout_ms / 1000);
    crm_xml_add_int(xml, PCMK__XA_ATTR_IS_PRIVATE, a->is_private);
    crm_xml_add_int(xml, PCMK__XA_ATTR_FORCE, force_write);

    return xml;
}

static void
clear_attribute_value_seen(void)
{
    GHashTableIter aIter;
    GHashTableIter vIter;
    attribute_t *a;
    attribute_value_t *v = NULL;

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & v)) {
            v->seen = FALSE;
            crm_trace("Clear seen flag %s[%s] = %s.", a->id, v->nodename, v->current);
        }
    }
}

/*!
 * \internal
 * \brief Clear failure-related attributes
 *
 * \param[in] peer  Peer that sent clear request
 * \param[in] xml   Request XML
 */
void
attrd_peer_clear_failure(crm_node_t *peer, xmlNode *xml)
{
    const char *rsc = crm_element_value(xml, PCMK__XA_ATTR_RESOURCE);
    const char *host = crm_element_value(xml, PCMK__XA_ATTR_NODE_NAME);
    const char *op = crm_element_value(xml, PCMK__XA_ATTR_OPERATION);
    const char *interval_spec = crm_element_value(xml, PCMK__XA_ATTR_INTERVAL);
    guint interval_ms = crm_parse_interval_spec(interval_spec);
    char *attr = NULL;
    GHashTableIter iter;
    regex_t regex;

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
 * \param[in] peer      Peer that sent clear request
 * \param[in] peer_won  Whether peer is the attribute writer
 * \param[in] xml       Request XML
 */
void
attrd_peer_sync_response(crm_node_t *peer, bool peer_won, xmlNode *xml)
{
    crm_info("Processing " PCMK__ATTRD_CMD_SYNC_RESPONSE " from %s",
             peer->uname);

    if (peer_won) {
        /* Initialize the "seen" flag for all attributes to cleared, so we can
         * detect attributes that local node has but the writer doesn't.
         */
        clear_attribute_value_seen();
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
        broadcast_unseen_local_values(peer, xml);
    }
}

/*!
    \internal
    \brief Broadcast private attribute for local node with protocol version
*/
void
attrd_broadcast_protocol(void)
{
    xmlNode *attrd_op = create_xml_node(NULL, __func__);

    crm_xml_add(attrd_op, F_TYPE, T_ATTRD);
    crm_xml_add(attrd_op, F_ORIG, crm_system_name);
    crm_xml_add(attrd_op, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    crm_xml_add(attrd_op, PCMK__XA_ATTR_NAME, CRM_ATTR_PROTOCOL);
    crm_xml_add(attrd_op, PCMK__XA_ATTR_VALUE, ATTRD_PROTOCOL_VERSION);
    crm_xml_add_int(attrd_op, PCMK__XA_ATTR_IS_PRIVATE, 1);
    attrd_client_update(attrd_op);
    free_xml(attrd_op);
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
            add_attribute_value_xml(sync, a, v, false);
        }
    }

    crm_debug("Syncing values to %s", peer?peer->uname:"everyone");
    send_attrd_message(peer, sync);
    free_xml(sync);
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

/*!
 * \internal
 * \brief Return host's hash table entry (creating one if needed)
 *
 * \param[in] values Hash table of values
 * \param[in] host Name of peer to look up
 * \param[in] xml XML describing the attribute
 *
 * \return Pointer to new or existing hash table entry
 */
static attribute_value_t *
attrd_lookup_or_create_value(GHashTable *values, const char *host, xmlNode *xml)
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

void
broadcast_unseen_local_values(crm_node_t *peer, xmlNode *xml)
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
                add_attribute_value_xml(sync, a, v, a->timeout_ms && a->timer);
            }
        }
    }

    if (sync != NULL) {
        crm_debug("Broadcasting local-only values");
        send_attrd_message(NULL, sync);
        free_xml(sync);
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
broadcast_local_value(attribute_t *a)
{
    attribute_value_t *v = g_hash_table_lookup(a->values, attrd_cluster->uname);
    xmlNode *sync = create_xml_node(NULL, __func__);

    crm_xml_add(sync, PCMK__XA_TASK, PCMK__ATTRD_CMD_SYNC_RESPONSE);
    add_attribute_value_xml(sync, a, v, false);
    attrd_xml_add_writer(sync);
    send_attrd_message(NULL, sync);
    free_xml(sync);
    return v;
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
update_attr_on_host(attribute_t *a, crm_node_t *peer, xmlNode *xml, const char *attr,
                    const char *value, const char *host, bool filter,
                    int is_force_write)
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
update_minimum_protocol_ver(const char *value)
{
    int ver;

    pcmk__scan_min_int(value, &ver, 0);

    if (ver > 0 && (minimum_protocol_version == -1 || ver < minimum_protocol_version)) {
        minimum_protocol_version = ver;
        crm_trace("Set minimum attrd protocol version to %d",
                  minimum_protocol_version);
    }
}

static void
attrd_peer_update_one(crm_node_t *peer, xmlNode *xml, bool filter)
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
        update_minimum_protocol_ver(value);
    }
}

void
attrd_peer_update(crm_node_t *peer, xmlNode *xml, const char *host, bool filter)
{
    if (xml_has_children(xml)) {
        for (xmlNode *child = first_named_child(xml, XML_ATTR_OP); child != NULL;
             child = crm_next_same_xml(child)) {
            /* Set the node name on the child message, assuming it isn't already. */
            if (crm_element_value(child, PCMK__XA_ATTR_NODE_NAME) == NULL) {
                crm_xml_add(child, PCMK__XA_ATTR_NODE_NAME, host);
            }

            attrd_peer_update_one(peer, child, filter);
        }

    } else {
        attrd_peer_update_one(peer, xml, filter);
    }
}

gboolean
attrd_election_cb(gpointer user_data)
{
    attrd_declare_winner();

    /* Update the peers after an election */
    attrd_peer_sync(NULL, NULL);

    /* Update the CIB after an election */
    attrd_write_attributes(true, false);
    return FALSE;
}

#define state_text(state) pcmk__s((state), "in unknown state")

void
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

    // Ensure remote nodes that come up are in the remote node cache
    } else if (!gone && is_remote) {
        cache_remote_node(peer->uname);
    }
}

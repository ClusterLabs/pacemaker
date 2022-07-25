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

int last_cib_op_done = 0;
GHashTable *attributes = NULL;

void write_attribute(attribute_t *a, bool ignore_delay);
void write_or_elect_attribute(attribute_t *a);

static void broadcast_unseen_local_values(crm_node_t *peer, xmlNode *xml);

gboolean
send_attrd_message(crm_node_t * node, xmlNode * data)
{
    crm_xml_add(data, F_TYPE, T_ATTRD);
    crm_xml_add(data, PCMK__XA_ATTR_VERSION, ATTRD_PROTOCOL_VERSION);
    attrd_xml_add_writer(data);
    return send_cluster_message(node, crm_msg_attrd, data, TRUE);
}

static gboolean
attribute_timer_cb(gpointer data)
{
    attribute_t *a = data;
    crm_trace("Dampen interval expired for %s", a->id);
    write_or_elect_attribute(a);
    return FALSE;
}

static void
free_attribute_value(gpointer data)
{
    attribute_value_t *v = data;

    free(v->nodename);
    free(v->current);
    free(v->requested);
    free(v);
}

void
free_attribute(gpointer data)
{
    attribute_t *a = data;
    if(a) {
        free(a->id);
        free(a->set);
        free(a->uuid);
        free(a->user);

        mainloop_timer_del(a->timer);
        g_hash_table_destroy(a->values);

        free(a);
    }
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

static attribute_t *
create_attribute(xmlNode *xml)
{
    int dampen = 0;
    const char *value = crm_element_value(xml, PCMK__XA_ATTR_DAMPENING);
    attribute_t *a = calloc(1, sizeof(attribute_t));

    a->id      = crm_element_value_copy(xml, PCMK__XA_ATTR_NAME);
    a->set     = crm_element_value_copy(xml, PCMK__XA_ATTR_SET);
    a->uuid    = crm_element_value_copy(xml, PCMK__XA_ATTR_UUID);
    a->values = pcmk__strikey_table(NULL, free_attribute_value);

    crm_element_value_int(xml, PCMK__XA_ATTR_IS_PRIVATE, &a->is_private);

    a->user = crm_element_value_copy(xml, PCMK__XA_ATTR_USER);
    crm_trace("Performing all %s operations as user '%s'", a->id, a->user);

    if (value != NULL) {
        dampen = crm_get_msec(value);
    }
    crm_trace("Created attribute %s with %s write delay", a->id,
              (a->timeout_ms == 0)? "no" : pcmk__readable_interval(a->timeout_ms));

    if(dampen > 0) {
        a->timeout_ms = dampen;
        a->timer = mainloop_timer_add(a->id, a->timeout_ms, FALSE, attribute_timer_cb, a);
    } else if (dampen < 0) {
        crm_warn("Ignoring invalid delay %s for attribute %s", value, a->id);
    }

    g_hash_table_replace(attributes, a->id, a);
    return a;
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
        write_attributes(false, false);
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
            write_or_elect_attribute(a);
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

static int
update_attr_dampening(attribute_t *a, xmlNode *xml, const char *attr)
{
    const char *dvalue = crm_element_value(xml, PCMK__XA_ATTR_DAMPENING);
    int dampen = 0;

    if (dvalue == NULL) {
        crm_warn("Could not update %s: peer did not specify value for delay",
                 attr);
        return EINVAL;
    }

    dampen = crm_get_msec(dvalue);
    if (dampen < 0) {
        crm_warn("Could not update %s: invalid delay value %dms (%s)",
                 attr, dampen, dvalue);
        return EINVAL;
    }

    if (a->timeout_ms != dampen) {
        mainloop_timer_del(a->timer);
        a->timeout_ms = dampen;
        if (dampen > 0) {
            a->timer = mainloop_timer_add(attr, a->timeout_ms, FALSE,
                                          attribute_timer_cb, a);
            crm_info("Update attribute %s delay to %dms (%s)",
                     attr, dampen, dvalue);
        } else {
            a->timer = NULL;
            crm_info("Update attribute %s to remove delay", attr);
        }

        /* If dampening changed, do an immediate write-out,
         * otherwise repeated dampening changes would prevent write-outs
         */
        write_or_elect_attribute(a);
    }

    return pcmk_rc_ok;
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

static attribute_t *
populate_attribute(xmlNode *xml, const char *attr)
{
    attribute_t *a = NULL;
    bool update_both = false;

    const char *op = crm_element_value(xml, PCMK__XA_TASK);

    // NULL because PCMK__ATTRD_CMD_SYNC_RESPONSE has no PCMK__XA_TASK
    update_both = pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_BOTH,
                               pcmk__str_null_matches);

    // Look up or create attribute entry
    a = g_hash_table_lookup(attributes, attr);
    if (a == NULL) {
        if (update_both || pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE, pcmk__str_none)) {
            a = create_attribute(xml);
        } else {
            crm_warn("Could not update %s: attribute not found", attr);
            return NULL;
        }
    }

    // Update attribute dampening
    if (update_both || pcmk__str_eq(op, PCMK__ATTRD_CMD_UPDATE_DELAY, pcmk__str_none)) {
        int rc = update_attr_dampening(a, xml, attr);

        if (rc != pcmk_rc_ok || !update_both) {
            return NULL;
        }
    }

    return a;
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

    a = populate_attribute(xml, attr);
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

void
write_or_elect_attribute(attribute_t *a)
{
    if (attrd_election_won()) {
        write_attribute(a, false);
    } else {
        attrd_start_election_if_needed();
    }
}

gboolean
attrd_election_cb(gpointer user_data)
{
    attrd_declare_winner();

    /* Update the peers after an election */
    attrd_peer_sync(NULL, NULL);

    /* Update the CIB after an election */
    write_attributes(true, false);
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

static void
attrd_cib_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    int level = LOG_ERR;
    GHashTableIter iter;
    const char *peer = NULL;
    attribute_value_t *v = NULL;

    char *name = user_data;
    attribute_t *a = g_hash_table_lookup(attributes, name);

    if(a == NULL) {
        crm_info("Attribute %s no longer exists", name);
        return;
    }

    a->update = 0;
    if (rc == pcmk_ok && call_id < 0) {
        rc = call_id;
    }

    switch (rc) {
        case pcmk_ok:
            level = LOG_INFO;
            last_cib_op_done = call_id;
            if (a->timer && !a->timeout_ms) {
                // Remove temporary dampening for failed writes
                mainloop_timer_del(a->timer);
                a->timer = NULL;
            }
            break;

        case -pcmk_err_diff_failed:    /* When an attr changes while the CIB is syncing */
        case -ETIME:           /* When an attr changes while there is a DC election */
        case -ENXIO:           /* When an attr changes while the CIB is syncing a
                                *   newer config from a node that just came up
                                */
            level = LOG_WARNING;
            break;
    }

    do_crm_log(level, "CIB update %d result for %s: %s " CRM_XS " rc=%d",
               call_id, a->id, pcmk_strerror(rc), rc);

    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, (gpointer *) & peer, (gpointer *) & v)) {
        do_crm_log(level, "* %s[%s]=%s", a->id, peer, v->requested);
        free(v->requested);
        v->requested = NULL;
        if (rc != pcmk_ok) {
            a->changed = true; /* Attempt write out again */
        }
    }

    if (a->changed && attrd_election_won()) {
        if (rc == pcmk_ok) {
            /* We deferred a write of a new update because this update was in
             * progress. Write out the new value without additional delay.
             */
            write_attribute(a, false);

        /* We're re-attempting a write because the original failed; delay
         * the next attempt so we don't potentially flood the CIB manager
         * and logs with a zillion attempts per second.
         *
         * @TODO We could elect a new writer instead. However, we'd have to
         * somehow downgrade our vote, and we'd still need something like this
         * if all peers similarly fail to write this attribute (which may
         * indicate a corrupted attribute entry rather than a CIB issue).
         */
        } else if (a->timer) {
            // Attribute has a dampening value, so use that as delay
            if (!mainloop_timer_running(a->timer)) {
                crm_trace("Delayed re-attempted write for %s by %s",
                          name, pcmk__readable_interval(a->timeout_ms));
                mainloop_timer_start(a->timer);
            }
        } else {
            /* Set a temporary dampening of 2 seconds (timer will continue
             * to exist until the attribute's dampening gets set or the
             * write succeeds).
             */
            a->timer = mainloop_timer_add(a->id, 2000, FALSE,
                                          attribute_timer_cb, a);
            mainloop_timer_start(a->timer);
        }
    }
}

void
write_attributes(bool all, bool ignore_delay)
{
    GHashTableIter iter;
    attribute_t *a = NULL;

    crm_debug("Writing out %s attributes", all? "all" : "changed");
    g_hash_table_iter_init(&iter, attributes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & a)) {
        if (!all && a->unknown_peer_uuids) {
            // Try writing this attribute again, in case peer ID was learned
            a->changed = true;
        } else if (a->force_write) {
            /* If the force_write flag is set, write the attribute. */
            a->changed = true;
        }

        if(all || a->changed) {
            /* When forced write flag is set, ignore delay. */
            write_attribute(a, (a->force_write ? true : ignore_delay));
        } else {
            crm_trace("Skipping unchanged attribute %s", a->id);
        }
    }
}

static void
build_update_element(xmlNode *parent, attribute_t *a, const char *nodeid, const char *value)
{
    const char *set = NULL;
    xmlNode *xml_obj = NULL;

    xml_obj = create_xml_node(parent, XML_CIB_TAG_STATE);
    crm_xml_add(xml_obj, XML_ATTR_ID, nodeid);

    xml_obj = create_xml_node(xml_obj, XML_TAG_TRANSIENT_NODEATTRS);
    crm_xml_add(xml_obj, XML_ATTR_ID, nodeid);

    xml_obj = create_xml_node(xml_obj, XML_TAG_ATTR_SETS);
    if (a->set) {
        crm_xml_set_id(xml_obj, "%s", a->set);
    } else {
        crm_xml_set_id(xml_obj, "%s-%s", XML_CIB_TAG_STATUS, nodeid);
    }
    set = ID(xml_obj);

    xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
    if (a->uuid) {
        crm_xml_set_id(xml_obj, "%s", a->uuid);
    } else {
        crm_xml_set_id(xml_obj, "%s-%s", set, a->id);
    }
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, a->id);

    if(value) {
        crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, value);

    } else {
        crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, "");
        crm_xml_add(xml_obj, "__delete__", XML_NVPAIR_ATTR_VALUE);
    }
}

static void
set_alert_attribute_value(GHashTable *t, attribute_value_t *v)
{
    attribute_value_t *a_v = NULL;
    a_v = calloc(1, sizeof(attribute_value_t));
    CRM_ASSERT(a_v != NULL);

    a_v->nodeid = v->nodeid;
    a_v->nodename = strdup(v->nodename);
    pcmk__str_update(&a_v->current, v->current);

    g_hash_table_replace(t, a_v->nodename, a_v);
}

static void
send_alert_attributes_value(attribute_t *a, GHashTable *t)
{
    int rc = 0;
    attribute_value_t *at = NULL;
    GHashTableIter vIter;

    g_hash_table_iter_init(&vIter, t);

    while (g_hash_table_iter_next(&vIter, NULL, (gpointer *) & at)) {
        rc = attrd_send_attribute_alert(at->nodename, at->nodeid,
                                        a->id, at->current);
        crm_trace("Sent alerts for %s[%s]=%s: nodeid=%d rc=%d",
                  a->id, at->nodename, at->current, at->nodeid, rc);
    }
}

void
write_attribute(attribute_t *a, bool ignore_delay)
{
    int private_updates = 0, cib_updates = 0;
    xmlNode *xml_top = NULL;
    attribute_value_t *v = NULL;
    GHashTableIter iter;
    enum cib_call_options flags = cib_quorum_override;
    GHashTable *alert_attribute_value = NULL;

    if (a == NULL) {
        return;
    }

    /* If this attribute will be written to the CIB ... */
    if (!a->is_private) {

        /* Defer the write if now's not a good time */
        CRM_CHECK(the_cib != NULL, return);
        if (a->update && (a->update < last_cib_op_done)) {
            crm_info("Write out of '%s' continuing: update %d considered lost", a->id, a->update);
            a->update = 0; // Don't log this message again

        } else if (a->update) {
            crm_info("Write out of '%s' delayed: update %d in progress", a->id, a->update);
            return;

        } else if (mainloop_timer_running(a->timer)) {
            if (ignore_delay) {
                /* 'refresh' forces a write of the current value of all attributes
                 * Cancel any existing timers, we're writing it NOW
                 */
                mainloop_timer_stop(a->timer);
                crm_debug("Write out of '%s': timer is running but ignore delay", a->id);
            } else {
                crm_info("Write out of '%s' delayed: timer is running", a->id);
                return;
            }
        }

        /* Initialize the status update XML */
        xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);
    }

    /* Attribute will be written shortly, so clear changed flag */
    a->changed = false;

    /* We will check all peers' uuids shortly, so initialize this to false */
    a->unknown_peer_uuids = false;

    /* Attribute will be written shortly, so clear forced write flag */
    a->force_write = FALSE;

    /* Make the table for the attribute trap */
    alert_attribute_value = pcmk__strikey_table(NULL, free_attribute_value);

    /* Iterate over each peer value of this attribute */
    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & v)) {
        crm_node_t *peer = crm_get_peer_full(v->nodeid, v->nodename, CRM_GET_PEER_ANY);

        /* If the value's peer info does not correspond to a peer, ignore it */
        if (peer == NULL) {
            crm_notice("Cannot update %s[%s]=%s because peer not known",
                       a->id, v->nodename, v->current);
            continue;
        }

        /* If we're just learning the peer's node id, remember it */
        if (peer->id && (v->nodeid == 0)) {
            crm_trace("Learned ID %u for node %s", peer->id, v->nodename);
            v->nodeid = peer->id;
        }

        /* If this is a private attribute, no update needs to be sent */
        if (a->is_private) {
            private_updates++;
            continue;
        }

        /* If the peer is found, but its uuid is unknown, defer write */
        if (peer->uuid == NULL) {
            a->unknown_peer_uuids = true;
            crm_notice("Cannot update %s[%s]=%s because peer UUID not known "
                       "(will retry if learned)",
                       a->id, v->nodename, v->current);
            continue;
        }

        /* Add this value to status update XML */
        crm_debug("Updating %s[%s]=%s (peer known as %s, UUID %s, ID %u/%u)",
                  a->id, v->nodename, v->current,
                  peer->uname, peer->uuid, peer->id, v->nodeid);
        build_update_element(xml_top, a, peer->uuid, v->current);
        cib_updates++;

        /* Preservation of the attribute to transmit alert */
        set_alert_attribute_value(alert_attribute_value, v);

        free(v->requested);
        v->requested = NULL;
        if (v->current) {
            v->requested = strdup(v->current);
        } else {
            /* Older attrd versions don't know about the cib_mixed_update
             * flag so make sure it goes to the local cib which does
             */
            cib__set_call_options(flags, crm_system_name,
                                  cib_mixed_update|cib_scope_local);
        }
    }

    if (private_updates) {
        crm_info("Processed %d private change%s for %s, id=%s, set=%s",
                 private_updates, pcmk__plural_s(private_updates),
                 a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set, "n/a"));
    }
    if (cib_updates) {
        crm_log_xml_trace(xml_top, __func__);

        a->update = cib_internal_op(the_cib, CIB_OP_MODIFY, NULL, XML_CIB_TAG_STATUS, xml_top, NULL,
                                    flags, a->user);

        crm_info("Sent CIB request %d with %d change%s for %s (id %s, set %s)",
                 a->update, cib_updates, pcmk__plural_s(cib_updates),
                 a->id, pcmk__s(a->uuid, "n/a"), pcmk__s(a->set, "n/a"));

        the_cib->cmds->register_callback_full(the_cib, a->update,
                                              CIB_OP_TIMEOUT_S, FALSE,
                                              strdup(a->id),
                                              "attrd_cib_callback",
                                              attrd_cib_callback, free);
        /* Transmit alert of the attribute */
        send_alert_attributes_value(a, alert_attribute_value);
    }

    g_hash_table_destroy(alert_attribute_value);
    free_xml(xml_top);
}

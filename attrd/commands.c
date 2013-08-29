/*
 * Copyright (C) 2013 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <crm_internal.h>

#include <glib.h>

#include <crm/msg_xml.h>
#include <crm/cluster.h>
#include <crm/cib.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election.h>
#include <crm/cib/internal.h>

#include <internal.h>

char *peer_writer = NULL;
GHashTable *attributes = NULL;

typedef struct attribute_s {
    char *uuid; /* TODO: Remove if at all possible */
    char *id;
    char *set;

    GHashTable *values;

    int timeout;
    bool changed;
    bool updating;
    mainloop_timer_t *timer;

    char *user;

} attribute_t;

typedef struct attribute_value_s {
        char *current;
        char *requested;
        char *stored;
} attribute_value_t;


void write_attribute(attribute_t *a);
void attrd_peer_update(crm_node_t *peer, xmlNode *xml);
void attrd_peer_sync(crm_node_t *peer, xmlNode *xml);
bool build_update_element(xmlNode *parent, attribute_t *a, const char *node_uuid, const char *attr_value);

static gboolean
attribute_timer_cb(gpointer user_data)
{
    if(election_state(writer) == election_won) {
        write_attribute(user_data);
    }
    return FALSE;
}

static void
free_attribute_value(gpointer data)
{
    attribute_value_t *v = data;

    free(v->current);
    free(v->requested);
    free(v->stored);
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

xmlNode *
build_attribute_xml(
    xmlNode *parent, const char *name, const char *set, const char *uuid, unsigned int timeout, const char *user,
    const char *peer, const char *value)
{
    xmlNode *xml = create_xml_node(parent, __FUNCTION__);

    crm_xml_add(xml, F_ATTRD_ATTRIBUTE, name);
    crm_xml_add(xml, F_ATTRD_SET, set);
    crm_xml_add(xml, F_ATTRD_KEY, uuid);
    crm_xml_add(xml, F_ATTRD_USER, user);
    crm_xml_add(xml, F_ATTRD_HOST, peer);
    crm_xml_add(xml, F_ATTRD_VALUE, value);
    crm_xml_add_int(xml, F_ATTRD_DAMPEN, timeout);

    return xml;
}

static attribute_t *
create_attribute(xmlNode *xml)
{
    attribute_t *a = calloc(1, sizeof(attribute_t));

    a->id      = crm_element_value_copy(xml, F_ATTRD_ATTRIBUTE);
    a->set     = crm_element_value_copy(xml, F_ATTRD_SET);
    a->uuid    = crm_element_value_copy(xml, F_ATTRD_KEY);
    a->values = g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, free_attribute_value);

#if ENABLE_ACL
    crm_trace("Performing all %s operations as user '%s'", a->id, a->user);
    a->user = crm_element_value_copy(xml, F_ATTRD_USER);
#endif

    crm_element_value_int(xml, F_ATTRD_DAMPEN, &a->timeout);
    if(a->timeout > 0) {
        a->timer = mainloop_timer_add(strdup(a->id), a->timeout, FALSE, attribute_timer_cb, a);
    }

    g_hash_table_replace(attributes, a->id, a);
    return a;
}

void
attrd_client_message(crm_client_t *client, xmlNode *xml)
{
    static int plus_plus_len = 5;
    const char *op = crm_element_value(xml, F_ATTRD_TASK);

    if(safe_str_eq(op, "update")) {
        attribute_t *a = NULL;
        attribute_value_t *v = NULL;
        char *key = crm_element_value_copy(xml, F_ATTRD_KEY);
        char *set = crm_element_value_copy(xml, F_ATTRD_SET);
        char *host = crm_element_value_copy(xml, F_ATTRD_HOST);
        const char *attr = crm_element_value(xml, F_ATTRD_ATTRIBUTE);
        const char *value = crm_element_value(xml, F_ATTRD_VALUE);

        a = g_hash_table_lookup(attributes, attr);

        if(host == NULL) {
            crm_trace("Inferring host");
            host = strdup(attrd_cluster->uname);
            crm_xml_add(xml, F_ATTRD_HOST, host);
        }

        if (set == NULL) {
            crm_trace("Inferring set");
            if(a == NULL) {
                set = g_strdup_printf("%s-%s", XML_CIB_TAG_STATUS, host);

            } else if(set == NULL) {
                set = strdup(a->set);
            }
            crm_xml_add(xml, F_ATTRD_SET, set);
        }

        if (key == NULL) {
            crm_trace("Inferring key");
            if(a == NULL) {
                int lpc = 0;
                key = g_strdup_printf("%s-%s", set, attr);

                /* Minimal attempt at sanitizing automatic IDs */
                for (lpc = 0; key[lpc] != 0; lpc++) {
                    switch (key[lpc]) {
                        case ':':
                            key[lpc] = '.';
                    }
                }
            } else if(key == NULL) {
                key = strdup(a->uuid);
            }
            crm_xml_add(xml, F_ATTRD_KEY, key);
        }

        if (value) {
            int offset = 1;
            int int_value = 0;
            int value_len = strlen(value);

            if (value_len < (plus_plus_len + 2)
                || value[plus_plus_len] != '+'
                || (value[plus_plus_len + 1] != '+' && value[plus_plus_len + 1] != '=')) {
                goto send;
            }

            if(a) {
                v = g_hash_table_lookup(a->values, host);
            }
            if(v) {
                int_value = char2score(v->current);
            }

            if (value[plus_plus_len + 1] != '+') {
                const char *offset_s = value + (plus_plus_len + 2);

                offset = char2score(offset_s);
            }
            int_value += offset;

            if (int_value > INFINITY) {
                int_value = INFINITY;
            }

            crm_info("Expanded %s=%s to %d", attr, value, int_value);
            crm_xml_add_int(xml, F_ATTRD_VALUE, int_value);
        }

      send:

        if(peer_writer == NULL) {
            crm_info("Starting an election to determine the writer");
            election_vote(writer);
        }

        crm_info("Broadcasting %s[%s] = %s%s", host, attr, value, election_state(writer) == election_won?" (writer)":"");
        crm_xml_add_int(xml, F_ATTRD_WRITER, election_state(writer));
        send_cluster_message(NULL, crm_msg_attrd, xml, TRUE);

        free(key);
        free(set);
        free(host);
    }
}

void
attrd_peer_message(crm_node_t *peer, xmlNode *xml)
{
    int peer_state = 0;
    const char *op = crm_element_value(xml, F_ATTRD_TASK);
    const char *election_op = crm_element_value(xml, F_CRM_TASK);

    if(election_op) {
        enum election_result rc = 0;

        crm_xml_add(xml, F_CRM_HOST_FROM, peer->uname);
        rc = election_count_vote(writer, xml, TRUE);
        switch(rc) {
            case election_start:
                free(peer_writer);
                peer_writer = NULL;
                election_vote(writer);
                break;
            case election_lost:
                free(peer_writer);
                peer_writer = strdup(peer->uname);
                break;
            default:
                election_check(writer);
                break;
        }
        return;
    }

    crm_element_value_int(xml, F_ATTRD_WRITER, &peer_state);
    if(election_state(writer) == election_won
       && peer_state == election_won
       && safe_str_neq(peer->uname, attrd_cluster->uname)) {
        crm_notice("Detected another attribute writer: %s", peer->uname);
        election_vote(writer);

    } else if(peer_state == election_won) {
        if(peer_writer == NULL) {
            peer_writer = strdup(peer->uname);
            crm_notice("Recorded attribute writer: %s", peer->uname);

        } else if(safe_str_neq(peer->uname, peer_writer)) {
            crm_notice("Recorded new attribute writer: %s (was %s)", peer->uname, peer_writer);
            free(peer_writer);
            peer_writer = strdup(peer->uname);
        }
    }

    if(safe_str_eq(op, "update")) {
        attrd_peer_update(peer, xml);

    } else if(safe_str_eq(op, "sync")) {
        attrd_peer_sync(peer, xml);

    } else if(safe_str_eq(op, "sync-response")) {
        xmlNode *child = NULL;

        crm_notice("Processing %s from %s", op, peer->uname);
        for (child = __xml_first_child(xml); child != NULL; child = __xml_next(child)) {
            attrd_peer_update(peer, child);
        }
    }
}

void
attrd_peer_sync(crm_node_t *peer, xmlNode *xml)
{
    GHashTableIter aIter;
    GHashTableIter vIter;
    const char *host = NULL;

    attribute_t *a = NULL;
    attribute_value_t *v = NULL;
    xmlNode *sync = create_xml_node(NULL, __FUNCTION__);

    crm_xml_add(sync, F_ATTRD_TASK, "sync-response");

    g_hash_table_iter_init(&aIter, attributes);
    while (g_hash_table_iter_next(&aIter, NULL, (gpointer *) & a)) {
        g_hash_table_iter_init(&vIter, a->values);
        while (g_hash_table_iter_next(&vIter, (gpointer *) & host, (gpointer *) & v)) {
            crm_debug("Syncing %s[%s] = %s to %s", a->id, host, v->current, peer->uname);
            build_attribute_xml(sync, a->id, a->set, a->uuid, a->timeout, a->user, host, v->current);
        }
    }

    crm_debug("Syncing values to %s", peer?peer->uname:"everyone");
    crm_xml_add_int(sync, F_ATTRD_WRITER, election_state(writer));
    send_cluster_message(peer, crm_msg_attrd, sync, TRUE);
    free_xml(sync);
}

void
attrd_peer_update(crm_node_t *peer, xmlNode *xml)
{
    attribute_value_t *v = NULL;

    const char *host = crm_element_value(xml, F_ATTRD_HOST);
    const char *attr = crm_element_value(xml, F_ATTRD_ATTRIBUTE);
    const char *value = crm_element_value(xml, F_ATTRD_VALUE);

    attribute_t *a = g_hash_table_lookup(attributes, attr);

    if(a == NULL) {
        a = create_attribute(xml);
    }

    v = g_hash_table_lookup(a->values, host);

    if(v == NULL) {
        crm_trace("Setting %s[%s] to %s from %s", host, attr, value, peer->uname);
        v = calloc(1, sizeof(attribute_value_t));
        if(value) {
            v->current = strdup(value);
        }
        a->changed = TRUE;

    } else {
        crm_trace("Setting %s[%s]: %s -> %s from %s", host, attr, v->current, value, peer->uname);
    }

    if(safe_str_neq(v->current, value)) {
        free(v->current);
        if(value) {
            v->current = strdup(value);
        } else {
            v->current = NULL;
        }
        a->changed = TRUE;
    }

    if(a->changed && a->timer) {
        mainloop_timer_start(a->timer);

    } else if(a->changed && election_state(writer) == election_won) {
        write_attribute(a);
    }
}

gboolean
attrd_election_cb(gpointer user_data)
{
    free(peer_writer);
    peer_writer = strdup(attrd_cluster->uname);
    attrd_peer_sync(NULL, NULL);
    return FALSE;
}


void
attrd_peer_change_cb(enum crm_status_type kind, crm_node_t *peer, const void *data)
{
    if(election_state(writer) == election_won
        && kind == crm_status_nstate
        && safe_str_eq(peer->state, CRM_NODE_MEMBER)) {

        attrd_peer_sync(peer, NULL);

    } else if(kind == crm_status_nstate
       && safe_str_neq(peer->state, CRM_NODE_MEMBER)
       && safe_str_eq(peer->uname, peer_writer)) {

        free(peer_writer);
        peer_writer = NULL;
        crm_notice("Lost attribute writer %s", peer->uname);
    }
}

static void
attrd_cib_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    int level = LOG_ERR;
    GHashTableIter iter;
    const char *key = NULL;
    attribute_value_t *v = NULL;

    char *name = user_data;
    attribute_t *a = g_hash_table_lookup(attributes, name);

    if(a == NULL) {
        crm_info("Attribute %s no longer exists", name);
        goto done;
    }

    if (rc == pcmk_ok && call_id < 0) {
        rc = call_id;
    }

    a->updating = FALSE;
    switch (rc) {
        case pcmk_ok:
            level = LOG_INFO;
            break;
        case -pcmk_err_diff_failed:    /* When an attr changes while the CIB is syncing */
        case -ETIME:           /* When an attr changes while there is a DC election */
        case -ENXIO:           /* When an attr changes while the CIB is syncing a
                                *   newer config from a node that just came up
                                */
            level = LOG_WARNING;
            break;
    }

    do_crm_log(level, "Update %d for %s: %s (%d)", call_id, name, pcmk_strerror(rc), rc);

    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & v)) {
        crm_info("Update %d for %s[%s]=%s: %s (%d)", call_id, a->id, v->requested, pcmk_strerror(rc), rc);
        if(rc == pcmk_ok) {
            free(v->stored);
            v->stored = v->requested;
            v->requested = NULL;

        } else {
            free(v->requested);
            v->requested = NULL;
            a->changed = TRUE; /* Attempt write out again */
        }
    }
  done:
    free(name);
    if(a && a->changed && election_state(writer) == election_won) {
        write_attribute(a);
    }
}

void
write_attributes(bool all)
{
    GHashTableIter iter;
    attribute_t *a = NULL;

    g_hash_table_iter_init(&iter, attributes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & a)) {
        if(all || a->changed) {
            write_attribute(a);
        } else {
            crm_debug("Skipping unchanged attribute %s", a->id);
        }
    }
}

void
write_attribute(attribute_t *a)
{
    int rc = pcmk_ok;
    xmlNode *xml_top = NULL;
    const char *peer = NULL;
    attribute_value_t *v = NULL;
    GHashTableIter iter;

    if (a == NULL) {
        return;

    } else if (the_cib == NULL) {
        crm_info("Delaying storing %s: cib not connected", a->id);
        return;

    } else if(a->updating) {
        crm_info("Delaying storing %s: update in progress", a->id);
        return;
    }

    a->changed = FALSE;
    a->updating = TRUE;

    xml_top = create_xml_node(NULL, XML_CIB_TAG_STATUS);

    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, (gpointer *) & peer, (gpointer *) & v)) {
        crm_info("Update for %s[%s]=%s: %s (%d)", a->id, peer, v->requested, pcmk_strerror(rc), rc);
        if(v->current) {
            free(v->requested);
            v->requested = strdup(v->current);

        } else {
            free(v->requested);
            v->requested = NULL;
        }
        build_update_element(xml_top, a, peer, v->requested);
    }

    crm_log_xml_trace(xml_top, "update_attr");
    rc = cib_internal_op(the_cib, CIB_OP_MODIFY, NULL, XML_CIB_TAG_STATUS, xml_top, NULL,
                         cib_quorum_override, a->user);

    crm_debug("Sent update %d for %s, id=%s, set=%s",
              rc, a->id, a->uuid ? a->uuid : "<n/a>", a->set);

    g_hash_table_iter_init(&iter, a->values);
    while (g_hash_table_iter_next(&iter, (gpointer *) & peer, (gpointer *) & v)) {
        crm_debug("Update %d for %s[%s]=%s", rc, a->id, peer, v->requested);
    }

    the_cib->cmds->register_callback(the_cib, rc, 120, FALSE, strdup(a->id), "attrd_cib_callback", attrd_cib_callback);
}

bool
build_update_element(xmlNode *parent, attribute_t *a, const char *node_uuid, const char *value)
{
    xmlNode *xml_obj = NULL;

    xml_obj = create_xml_node(parent, XML_CIB_TAG_STATE);
    crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);

    xml_obj = create_xml_node(xml_obj, XML_TAG_TRANSIENT_NODEATTRS);
    crm_xml_add(xml_obj, XML_ATTR_ID, node_uuid);

    xml_obj = create_xml_node(xml_obj, XML_TAG_ATTR_SETS);
    crm_xml_add(xml_obj, XML_ATTR_ID, a->set);

    xml_obj = create_xml_node(xml_obj, XML_CIB_TAG_NVPAIR);
    crm_xml_add(xml_obj, XML_ATTR_ID, a->uuid);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_NAME, a->id);
    crm_xml_add(xml_obj, XML_NVPAIR_ATTR_VALUE, value);

    return TRUE;
}

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
#include <crm/cib/internal.h>

#include <internal.h>

cib_t *the_cib = NULL;
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
bool build_update_element(xmlNode *parent, attribute_t *a, const char *node_uuid, const char *attr_value);

static gboolean
attribute_timer_cb(gpointer user_data)
{
    write_attribute(user_data);
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

static attribute_t *
create_attribute(xmlNode *xml)
{
    attribute_t *a = calloc(1, sizeof(attribute_t));
    const char *attr = crm_element_value(xml, F_ATTRD_ATTRIBUTE);

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
        a->timer = mainloop_timer_add(attr, a->timeout, FALSE, attribute_timer_cb, a);
    }

    g_hash_table_replace(attributes, strdup(attr), a);
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
            host = cluster->uname;
            crm_xml_add(xml, F_ATTRD_HOST, host);
        }

        if (set == NULL) {
            if(a == NULL) {
                set = g_strdup_printf("%s-%s", XML_CIB_TAG_STATUS, host);

            } else if(set == NULL) {
                set = a->set;
            }
            crm_xml_add(xml, F_ATTRD_SET, a->set);
        }

        if (key == NULL) {
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
                key = a->uuid;
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
        crm_info("Broadcasting %s[%s] = %s", host, attr, value);
        send_cluster_message(NULL, crm_msg_attrd, xml, TRUE);

        free(key);
        free(set);
        free(host);
    }

}

void
attrd_peer_message(crm_node_t *peer, xmlNode *xml)
{
    const char *op = crm_element_value(xml, F_ATTRD_TASK);

    if(safe_str_eq(op, "update")) {
        bool changed = FALSE;
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
            crm_trace("Setting %s[%s] -> %s", host, attr, value);
            v = calloc(1, sizeof(attribute_value_t));
            v->current = strdup(value);
            changed = TRUE;

        } else {
            crm_trace("Setting %s[%s]: %s -> %s", host, attr, v->current, value);
        }

        if(safe_str_neq(v->current, value)) {
            free(v->current);
            v->current = strdup(value);
            changed = TRUE;
        }

        if(changed && a->timer) {
            mainloop_timer_start(a->timer);

        } else if(changed) {
            write_attribute(a);
        }
    }
}

void
attrd_peer_change_cb(void)
{
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
        }
    }
  done:
    free(name);
    if(a && a->changed) {
        write_attribute(a);
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

/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <crm_internal.h>

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <glib.h>
#include <crm/common/ipc.h>
#include <crm/cluster/internal.h>
#include <crm/msg_xml.h>
#include <crm/stonith-ng.h>

GHashTable *crm_peer_id_cache = NULL;
GHashTable *crm_peer_cache = NULL;
unsigned long long crm_peer_seq = 0;
gboolean crm_have_quorum = FALSE;

gboolean
crm_is_peer_active(const crm_node_t * node)
{
#if SUPPORT_COROSYNC
    if(is_openais_cluster()) {
        return crm_is_corosync_peer_active(node);
    }
#endif
#if SUPPORT_HEARTBEAT
    if(is_heartbeat_cluster()) {
        return crm_is_heartbeat_peer_active(node);
    }
#endif
    crm_err("Unhandled cluster type: %s", name_for_cluster_type(get_cluster_type()));
    return FALSE;
}

static gboolean
crm_reap_dead_member(gpointer key, gpointer value, gpointer user_data)
{
    crm_node_t *node = value;
    crm_node_t *search = user_data;

    if (search != NULL && node->id != search->id) {
        return FALSE;

    } else if (crm_is_peer_active(value) == FALSE) {
        crm_notice("Removing %s/%u from the membership list", node->uname, node->id);
        return TRUE;
    }
    return FALSE;
}

guint
reap_crm_member(uint32_t id)
{
    int matches = 0;
    crm_node_t *node = g_hash_table_lookup(crm_peer_id_cache, GUINT_TO_POINTER(id));

    if (node == NULL) {
        crm_info("Peer %u is unknown", id);

    } else if (crm_is_peer_active(node)) {
        crm_warn("Peer %u/%s is still active", id, node->uname);

    } else {
        if (g_hash_table_remove(crm_peer_id_cache, GUINT_TO_POINTER(id))) {
            crm_notice("Removed dead peer %u from the uuid cache", id);

        } else {
            crm_warn("Peer %u/%s was not removed", id, node->uname);
        }

        matches = g_hash_table_foreach_remove(crm_peer_cache, crm_reap_dead_member, node);

        crm_notice("Removed %d dead peers with id=%u from the membership list", matches, id);
    }

    return matches;
}


static void
crm_count_peer(gpointer key, gpointer value, gpointer user_data)
{
    guint *count = user_data;
    crm_node_t *node = value;

    if (crm_is_peer_active(node)) {
        *count = *count + 1;
    }
}

guint
crm_active_peers(void)
{
    guint count = 0;

    g_hash_table_foreach(crm_peer_cache, crm_count_peer, &count);
    return count;
}

void
destroy_crm_node(gpointer data)
{
    crm_node_t *node = data;

    crm_trace("Destroying entry for node %u", node->id);

    free(node->addr);
    free(node->uname);
    free(node->state);
    free(node->uuid);
    free(node);
}

void
crm_peer_init(void)
{
    static gboolean initialized = FALSE;

    if (initialized) {
        return;
    }
    initialized = TRUE;

    crm_peer_destroy();
    if (crm_peer_cache == NULL) {
        crm_peer_cache = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, destroy_crm_node);
    }

    if (crm_peer_id_cache == NULL) {
        crm_peer_id_cache = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    }
}

void
crm_peer_destroy(void)
{
    if (crm_peer_cache != NULL) {
        g_hash_table_destroy(crm_peer_cache);
        crm_peer_cache = NULL;
    }

    if (crm_peer_id_cache != NULL) {
        g_hash_table_destroy(crm_peer_id_cache);
        crm_peer_id_cache = NULL;
    }
}

void (*crm_status_callback) (enum crm_status_type, crm_node_t *, const void *) = NULL;

void
crm_set_status_callback(void (*dispatch) (enum crm_status_type, crm_node_t *, const void *))
{
    crm_status_callback = dispatch;
}

/* coverity[-alloc] Memory is referenced in one or both hashtables */
crm_node_t *
crm_get_peer(unsigned int id, const char *uname)
{
    crm_node_t *node = NULL;
    CRM_ASSERT(id > 0 || uname != NULL);

    crm_peer_init();

    if (node == NULL && uname != NULL) {
        node = g_hash_table_lookup(crm_peer_cache, uname);
    }

    if (node == NULL && id > 0) {
        node = g_hash_table_lookup(crm_peer_id_cache, GUINT_TO_POINTER(id));

        if (node && node->uname && uname) {
            crm_crit("Node %s and %s share the same cluster node id '%u'!", node->uname, uname, id);
            
            /* NOTE: Calling crm_new_peer() means the entry in 
             * crm_peer_id_cache will point to the new entity
             *
             * TO-DO: Replace the old uname instead?
             */
            node = NULL;
        }
    }

    if (node == NULL) {
        crm_debug("Creating entry for node %s/%u", uname, id);

        node = calloc(1, sizeof(crm_node_t));
        CRM_ASSERT(node);
    }

    if (id > 0 && node->id != id) {
        node->id = id;
        crm_info("Node %s now has id: %u", crm_str(uname), id);
        g_hash_table_replace(crm_peer_id_cache, GUINT_TO_POINTER(node->id), node);
    }

    if (uname && node->uname == NULL) {
        node->uname = strdup(uname);
        crm_info("Node %u is now known as %s", id, uname);
        g_hash_table_replace(crm_peer_cache, node->uname, node);
        if (crm_status_callback) {
            crm_status_callback(crm_status_uname, node, NULL);
        }
    }

    if (node && node->uname && node->uuid == NULL) {
        const char *uuid = get_node_uuid(id, node->uname);

        if(uuid) {
            node->uuid = strdup(uuid);
            crm_info("Node %u has uuid %s", id, node->uuid);
        } else {
            crm_warn("Cannot obtain a UUID for node %d/%s", id, node->uname);
        }
    }

    return node;
}

crm_node_t *
crm_update_peer(const char *source, unsigned int id, uint64_t born, uint64_t seen, int32_t votes, uint32_t children,
                const char *uuid, const char *uname, const char *addr, const char *state)
{
#if SUPPORT_PLUGIN
    gboolean addr_changed = FALSE;
    gboolean votes_changed = FALSE;
#endif
    crm_node_t *node = NULL;

    id = get_corosync_id(id, uuid);
    node = crm_get_peer(id, uname);

    CRM_ASSERT(node != NULL);

    if (node->uuid == NULL) {
        if (is_openais_cluster()) {
            /* Yes, overrule whatever was passed in */
            node->uuid = get_corosync_uuid(id, uname);

        } else if (uuid != NULL) {
            node->uuid = strdup(uuid);
        }
    }

    if (children > 0) {
        crm_update_peer_proc(source, node, children, state);
    }

    if (state != NULL) {
        crm_update_peer_state(source, node, state, seen);
    }

#if SUPPORT_HEARTBEAT
    if (born != 0) {
        node->born = born;
    }
#endif

#if SUPPORT_PLUGIN
    /* These were only used by the plugin */
    if (born != 0) {
        node->born = born;
    }

    if (votes > 0 && node->votes != votes) {
        votes_changed = TRUE;
        node->votes = votes;
    }

    if (addr != NULL) {
        if (node->addr == NULL || crm_str_eq(node->addr, addr, FALSE) == FALSE) {
            addr_changed = TRUE;
            free(node->addr);
            node->addr = strdup(addr);
        }
    }
    if (addr_changed || votes_changed) {
        crm_info("%s: Node %s: id=%u state=%s addr=%s%s votes=%d%s born=" U64T " seen=" U64T
                 " proc=%.32x", source, node->uname, node->id, node->state, 
                 node->addr, addr_changed ? " (new)" : "", node->votes,
                 votes_changed ? " (new)" : "", node->born, node->last_seen, node->processes);
    }
#endif

    return node;
}

void
crm_update_peer_proc(const char *source, crm_node_t *node, uint32_t flag, const char *status)
{
    uint32_t last = 0;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set %s to %s for NULL",
                                    source, peer2text(flag), status);
              return);

    last = node->processes;
    if(status == NULL) {
        node->processes = flag;
        if(node->processes != last) {
            changed = TRUE;
        }

    } else if (safe_str_eq(status, ONLINESTATUS)) {
        if ((node->processes & flag) == 0) {
            set_bit(node->processes, flag);
            changed = TRUE;
        }

    } else if (node->processes & flag) {
        clear_bit(node->processes, flag);
        changed = TRUE;
    }

    if (changed) {
        if(status == NULL) {
            crm_info("%s: Node %s[%d] - all processes are now offline", source, node->uname, node->id);
        } else {
            crm_info("%s: Node %s[%d] - %s is now %s", source, node->uname, node->id, peer2text(flag), status);
        }

        if (crm_status_callback) {
            crm_status_callback(crm_status_processes, node, &last);
        }
    } else {
        crm_trace("%s: Node %s[%d] - %s is unchanged (%s)", source, node->uname, node->id, peer2text(flag), status);
    }
}

void crm_update_peer_expected(const char *source, crm_node_t *node, const char *expected) 
{
    char *last = NULL;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set 'expected' to %s", source, expected); return);

    last = node->expected;
    if (expected != NULL && safe_str_neq(node->expected, expected)) {
        node->expected = strdup(expected);
        changed = TRUE;
    }

    if (changed) {
        crm_info("%s: Node %s[%d] - expected state is now %s", source, node->uname, node->id, expected);
        free(last);
    } else {
        crm_trace("%s: Node %s[%d] - expected state is unchanged (%s)", source, node->uname, node->id, expected);
    }
}

void crm_update_peer_state(const char *source, crm_node_t *node, const char *state, int membership) 
{
    char *last = NULL;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set 'state' to %s", source, state); return);

    last = node->state;
    if (state != NULL && safe_str_neq(node->state, state)) {
        node->state = strdup(state);
        changed = TRUE;
    }

    if (membership != 0 && safe_str_eq(node->state, CRM_NODE_MEMBER)) {
        node->last_seen = membership;
    }

    if (changed) {
        crm_notice("%s: Node %s[%d] - state is now %s", source, node->uname, node->id, state);
        if (crm_status_callback) {
            crm_status_callback(crm_status_nstate, node, last);
        }
        free(last);
    } else {
        crm_trace("%s: Node %s[%d] - state is unchanged (%s)", source, node->uname, node->id, state);
    }
}

int
crm_terminate_member(int nodeid, const char *uname, void * unused)
{
    /* Always use the synchronous, non-mainloop version */
    return stonith_api_kick(nodeid, uname, 120, TRUE);
}

int
crm_terminate_member_no_mainloop(int nodeid, const char *uname, int *connection)
{
    return stonith_api_kick(nodeid, uname, 120, TRUE);
}

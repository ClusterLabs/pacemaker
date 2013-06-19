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

GHashTable *crm_peer_cache = NULL;
unsigned long long crm_peer_seq = 0;
gboolean crm_have_quorum = FALSE;

gboolean
crm_is_peer_active(const crm_node_t * node)
{
    if(node == NULL) {
        return FALSE;
    }
#if SUPPORT_COROSYNC
    if (is_openais_cluster()) {
        return crm_is_corosync_peer_active(node);
    }
#endif
#if SUPPORT_HEARTBEAT
    if (is_heartbeat_cluster()) {
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

    if (search == NULL) {
        return FALSE;

    } else if (search->id && node->id != search->id) {
        return FALSE;

    } else if (search->id == 0 && safe_str_neq(node->uname, search->uname)) {
        return FALSE;

    } else if (crm_is_peer_active(value) == FALSE) {
        crm_notice("Removing %s/%u from the membership list", node->uname, node->id);
        return TRUE;
    }
    return FALSE;
}

guint
reap_crm_member(uint32_t id, const char *name)
{
    int matches = 0;
    crm_node_t search;

    if (crm_peer_cache == NULL) {
        crm_trace("Nothing to do, cache not initialized");
        return 0;
    }

    search.id = id;
    search.uname = strdup(name);
    matches = g_hash_table_foreach_remove(crm_peer_cache, crm_reap_dead_member, &search);
    if(matches) {
        crm_notice("Purged %d peers with id=%u and/or uname=%s from the membership cache", matches, id, name);

    } else {
        crm_info("No peers with id=%u and/or uname=%s exist", id, name);
    }

    free(search.uname);
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

    if (crm_peer_cache) {
        g_hash_table_foreach(crm_peer_cache, crm_count_peer, &count);
    }
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
    free(node->expected);
    free(node);
}

void
crm_peer_init(void)
{
    if (crm_peer_cache == NULL) {
        crm_peer_cache = g_hash_table_new_full(crm_str_hash, g_str_equal, free, destroy_crm_node);
    }
}

void
crm_peer_destroy(void)
{
    if (crm_peer_cache != NULL) {
        crm_trace("Destroying peer cache with %d members", g_hash_table_size(crm_peer_cache));
        g_hash_table_destroy(crm_peer_cache);
        crm_peer_cache = NULL;
    }
}

void (*crm_status_callback) (enum crm_status_type, crm_node_t *, const void *) = NULL;

void
crm_set_status_callback(void (*dispatch) (enum crm_status_type, crm_node_t *, const void *))
{
    crm_status_callback = dispatch;
}

static void crm_dump_peer_hash(int level, const char *caller)
{
    GHashTableIter iter;
    const char *id = NULL;
    crm_node_t *node = NULL;

    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, (gpointer *) &id, (gpointer *) &node)) {
        do_crm_log(level, "%s: Node %u/%s = %p - %s", caller, node->id, node->uname, node, id);
    }
}

/* coverity[-alloc] Memory is referenced in one or both hashtables */
crm_node_t *
crm_get_peer(unsigned int id, const char *uname)
{
    GHashTableIter iter;
    crm_node_t *node = NULL;
    crm_node_t *by_id = NULL;
    crm_node_t *by_name = NULL;

    CRM_ASSERT(id > 0 || uname != NULL);

    crm_peer_init();

    if (uname != NULL) {
        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if(node->uname && strcasecmp(node->uname, uname) == 0) {
                crm_trace("Name match: %s = %p", node->uname, node);
                by_name = node;
                break;
            }
        }
    }

    if (id > 0) {
        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if(node->id == id) {
                crm_trace("ID match: %u = %p", node->id, node);
                by_id = node;
                break;
            }
        }
    }

    node = by_id; /* Good default */
    if(by_id == by_name) {
        /* Nothing to do if they match (both NULL counts) */
        crm_trace("Consistent: %p for %u/%s", by_id, id, uname);

    } else if(by_id == NULL && by_name) {
        crm_trace("Only one: %p for %u/%s", by_name, id, uname);

        if(id && by_name->id) {
            crm_dump_peer_hash(LOG_WARNING, __FUNCTION__);
            crm_crit("Node %u and %u share the same name '%s'",
                     id, by_name->id, uname);
            node = NULL; /* Create a new one */

        } else {
            node = by_name;
        }

    } else if(by_name == NULL && by_id) {
        crm_trace("Only one: %p for %u/%s", by_id, id, uname);

        if(uname && by_id->uname) {
            crm_dump_peer_hash(LOG_WARNING, __FUNCTION__);
            crm_crit("Node '%s' and '%s' share the same cluster nodeid %u: assuming '%s' is correct",
                     uname, by_id->uname, id, uname);
        }

    } else if(uname && by_id->uname) {
        crm_warn("Node '%s' and '%s' share the same cluster nodeid: %u", by_id->uname, by_name->uname, id);

    } else if(id && by_name->id) {
        crm_warn("Node %u and %u share the same name: '%s'", by_id->id, by_name->id, uname);

    } else {
        /* Simple merge */

        /* Only corosync based clusters use nodeid's
         *
         * The functions that call crm_update_peer_state() only know nodeid
         * so 'by_id' is authorative when merging
         *
         * Same for crm_update_peer_proc()
         */
        crm_dump_peer_hash(LOG_DEBUG, __FUNCTION__);

        crm_info("Merging %p into %p", by_name, by_id);
        g_hash_table_remove(crm_peer_cache, by_name);
    }

    if (node == NULL) {
        char *uniqueid = crm_generate_uuid();

        node = calloc(1, sizeof(crm_node_t));
        CRM_ASSERT(node);

        crm_info("Created entry %s/%p for node %s/%u (%d total)",
                 uniqueid, node, uname, id, 1 + g_hash_table_size(crm_peer_cache));
        g_hash_table_replace(crm_peer_cache, uniqueid, node);
    }

    if(id > 0 && uname && (node->id == 0 || node->uname == NULL)) {
        crm_info("Node %u is now known as %s", id, uname);
    }

    if(id > 0 && node->id == 0) {
        node->id = id;
    }

    if(uname && node->uname == NULL) {
        node->uname = strdup(uname);
        if (crm_status_callback) {
            crm_status_callback(crm_status_uname, node, NULL);
        }
    }

    if(node->uuid == NULL) {
        const char *uuid = crm_peer_uuid(node);

        if (uuid) {
            crm_info("Node %u has uuid %s", id, uuid);

        } else {
            crm_info("Cannot obtain a UUID for node %d/%s", id, node->uname);
        }
    }

    return node;
}

crm_node_t *
crm_update_peer(const char *source, unsigned int id, uint64_t born, uint64_t seen, int32_t votes,
                uint32_t children, const char *uuid, const char *uname, const char *addr,
                const char *state)
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
            crm_peer_uuid(node);

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
crm_update_peer_proc(const char *source, crm_node_t * node, uint32_t flag, const char *status)
{
    uint32_t last = 0;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set %s to %s for NULL",
                                    source, peer2text(flag), status); return);

    last = node->processes;
    if (status == NULL) {
        node->processes = flag;
        if (node->processes != last) {
            changed = TRUE;
        }

    } else if (safe_str_eq(status, ONLINESTATUS)) {
        if ((node->processes & flag) == 0) {
            set_bit(node->processes, flag);
            changed = TRUE;
        }
#if SUPPORT_PLUGIN
    } else if (safe_str_eq(status, CRM_NODE_MEMBER)) {
        if (flag > 0 && node->processes != flag) {
            node->processes = flag;
            changed = TRUE;
        }
#endif

    } else if (node->processes & flag) {
        clear_bit(node->processes, flag);
        changed = TRUE;
    }

    if (changed) {
        if (status == NULL && flag <= crm_proc_none) {
            crm_info("%s: Node %s[%u] - all processes are now offline", source, node->uname,
                     node->id);
        } else {
            crm_info("%s: Node %s[%u] - %s is now %s", source, node->uname, node->id,
                     peer2text(flag), status);
        }

        if (crm_status_callback) {
            crm_status_callback(crm_status_processes, node, &last);
        }
    } else {
        crm_trace("%s: Node %s[%u] - %s is unchanged (%s)", source, node->uname, node->id,
                  peer2text(flag), status);
    }
}

void
crm_update_peer_expected(const char *source, crm_node_t * node, const char *expected)
{
    char *last = NULL;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set 'expected' to %s", source, expected);
              return);

    last = node->expected;
    if (expected != NULL && safe_str_neq(node->expected, expected)) {
        node->expected = strdup(expected);
        changed = TRUE;
    }

    if (changed) {
        crm_info("%s: Node %s[%u] - expected state is now %s", source, node->uname, node->id,
                 expected);
        free(last);
    } else {
        crm_trace("%s: Node %s[%u] - expected state is unchanged (%s)", source, node->uname,
                  node->id, expected);
    }
}

void
crm_update_peer_state(const char *source, crm_node_t * node, const char *state, int membership)
{
    char *last = NULL;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set 'state' to %s", source, state);
              return);

    last = node->state;
    if (state != NULL && safe_str_neq(node->state, state)) {
        node->state = strdup(state);
        changed = TRUE;
    }

    if (membership != 0 && safe_str_eq(node->state, CRM_NODE_MEMBER)) {
        node->last_seen = membership;
    }

    if (changed) {
        crm_notice("%s: Node %s[%u] - state is now %s (was %s)", source, node->uname, node->id, state, last);
        if (crm_status_callback) {
            crm_status_callback(crm_status_nstate, node, last);
        }
        free(last);
    } else {
        crm_trace("%s: Node %s[%u] - state is unchanged (%s)", source, node->uname, node->id,
                  state);
    }
}

int
crm_terminate_member(int nodeid, const char *uname, void *unused)
{
    /* Always use the synchronous, non-mainloop version */
    return stonith_api_kick(nodeid, uname, 120, TRUE);
}

int
crm_terminate_member_no_mainloop(int nodeid, const char *uname, int *connection)
{
    return stonith_api_kick(nodeid, uname, 120, TRUE);
}

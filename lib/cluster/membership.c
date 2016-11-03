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

/* The peer cache remembers cluster nodes that have been seen.
 * This is managed mostly automatically by libcluster, based on
 * cluster membership events.
 *
 * Because cluster nodes can have conflicting names or UUIDs,
 * the hash table key is a uniquely generated ID.
 */
GHashTable *crm_peer_cache = NULL;

/*
 * The remote peer cache tracks pacemaker_remote nodes. While the
 * value has the same type as the peer cache's, it is tracked separately for
 * three reasons: pacemaker_remote nodes can't have conflicting names or UUIDs,
 * so the name (which is also the UUID) is used as the hash table key; there
 * is no equivalent of membership events, so management is not automatic; and
 * most users of the peer cache need to exclude pacemaker_remote nodes.
 *
 * That said, using a single cache would be more logical and less error-prone,
 * so it would be a good idea to merge them one day.
 *
 * libcluster provides two avenues for populating the cache:
 * crm_remote_peer_get(), crm_remote_peer_cache_add() and
 * crm_remote_peer_cache_remove() directly manage it,
 * while crm_remote_peer_cache_refresh() populates it via the CIB.
 */
GHashTable *crm_remote_peer_cache = NULL;

unsigned long long crm_peer_seq = 0;
gboolean crm_have_quorum = FALSE;
static gboolean crm_autoreap  = TRUE;

int
crm_remote_peer_cache_size(void)
{
    if (crm_remote_peer_cache == NULL) {
        return 0;
    }
    return g_hash_table_size(crm_remote_peer_cache);
}

/*!
 * \brief Get a remote node peer cache entry, creating it if necessary
 *
 * \param[in] node_name  Name of remote node
 *
 * \return Cache entry for node on success, NULL (and set errno) otherwise
 *
 * \note When creating a new entry, this will leave the node state undetermined,
 *       so the caller should also call crm_update_peer_state() if the state is
 *       known.
 */
crm_node_t *
crm_remote_peer_get(const char *node_name)
{
    crm_node_t *node;

    if (node_name == NULL) {
        errno = -EINVAL;
        return NULL;
    }

    /* Return existing cache entry if one exists */
    node = g_hash_table_lookup(crm_remote_peer_cache, node_name);
    if (node) {
        return node;
    }

    /* Allocate a new entry */
    node = calloc(1, sizeof(crm_node_t));
    if (node == NULL) {
        return NULL;
    }

    /* Populate the essential information */
    node->flags = crm_remote_node;
    node->uuid = strdup(node_name);
    if (node->uuid == NULL) {
        free(node);
        errno = -ENOMEM;
        return NULL;
    }

    /* Add the new entry to the cache */
    g_hash_table_replace(crm_remote_peer_cache, node->uuid, node);
    crm_trace("added %s to remote cache", node_name);

    /* Update the entry's uname, ensuring peer status callbacks are called */
    crm_update_peer_uname(node, node_name);
    return node;
}

/*!
 * \brief Add a node to the remote peer cache
 *
 * \param[in] node_name  Name of remote node
 *
 * \note This is a legacy convenience wrapper for crm_remote_peer_get()
 *       for callers that don't need the cache entry returned.
 */
void
crm_remote_peer_cache_add(const char *node_name)
{
    CRM_ASSERT(crm_remote_peer_get(node_name) != NULL);
}

void
crm_remote_peer_cache_remove(const char *node_name)
{
    if (g_hash_table_remove(crm_remote_peer_cache, node_name)) {
        crm_trace("removed %s from remote peer cache", node_name);
    }
}

/*!
 * \internal
 * \brief Return node status based on a CIB status entry
 *
 * \param[in] node_state  XML of node state
 *
 * \return CRM_NODE_LOST if XML_NODE_IN_CLUSTER is false in node_state,
 *         CRM_NODE_MEMBER otherwise
 * \note Unlike most boolean XML attributes, this one defaults to true, for
 *       backward compatibility with older crmd versions that don't set it.
 */
static const char *
remote_state_from_cib(xmlNode *node_state)
{
    const char *status;

    status = crm_element_value(node_state, XML_NODE_IN_CLUSTER);
    if (status && !crm_is_true(status)) {
        status = CRM_NODE_LOST;
    } else {
        status = CRM_NODE_MEMBER;
    }
    return status;
}

/* user data for looping through remote node xpath searches */
struct refresh_data {
    const char *field;  /* XML attribute to check for node name */
    gboolean has_state; /* whether to update node state based on XML */
};

/*!
 * \internal
 * \brief Process one pacemaker_remote node xpath search result
 *
 * \param[in] result     XML search result
 * \param[in] user_data  what to look for in the XML
 */
static void
remote_cache_refresh_helper(xmlNode *result, void *user_data)
{
    struct refresh_data *data = user_data;
    const char *remote = crm_element_value(result, data->field);
    const char *state = NULL;
    crm_node_t *node;

    CRM_CHECK(remote != NULL, return);

    /* Determine node's state, if the result has it */
    if (data->has_state) {
        state = remote_state_from_cib(result);
    }

    /* Check whether cache already has entry for node */
    node = g_hash_table_lookup(crm_remote_peer_cache, remote);

    if (node == NULL) {
        /* Node is not in cache, so add a new entry for it */
        node = crm_remote_peer_get(remote);
        CRM_ASSERT(node);
        if (state) {
            crm_update_peer_state(__FUNCTION__, node, state, 0);
        }

    } else if (is_set(node->flags, crm_node_dirty)) {
        /* Node is in cache and hasn't been updated already, so mark it clean */
        clear_bit(node->flags, crm_node_dirty);
        if (state) {
            crm_update_peer_state(__FUNCTION__, node, state, 0);
        }
    }
}

static void
mark_dirty(gpointer key, gpointer value, gpointer user_data)
{
    set_bit(((crm_node_t*)value)->flags, crm_node_dirty);
}

static gboolean
is_dirty(gpointer key, gpointer value, gpointer user_data)
{
    return is_set(((crm_node_t*)value)->flags, crm_node_dirty);
}

/* search string to find CIB resources entries for guest nodes */
#define XPATH_GUEST_NODE_CONFIG \
    "//" XML_TAG_CIB "//" XML_CIB_TAG_CONFIGURATION "//" XML_CIB_TAG_RESOURCE \
    "//" XML_TAG_META_SETS "//" XML_CIB_TAG_NVPAIR \
    "[@name='" XML_RSC_ATTR_REMOTE_NODE "']"

/* search string to find CIB resources entries for remote nodes */
#define XPATH_REMOTE_NODE_CONFIG \
    "//" XML_TAG_CIB "//" XML_CIB_TAG_CONFIGURATION "//" XML_CIB_TAG_RESOURCE \
    "[@type='remote'][@provider='pacemaker']"

/* search string to find CIB node status entries for pacemaker_remote nodes */
#define XPATH_REMOTE_NODE_STATUS \
    "//" XML_TAG_CIB "//" XML_CIB_TAG_STATUS "//" XML_CIB_TAG_STATE \
    "[@" XML_NODE_IS_REMOTE "='true']"

/*!
 * \brief Repopulate the remote peer cache based on CIB XML
 *
 * \param[in] xmlNode  CIB XML to parse
 */
void
crm_remote_peer_cache_refresh(xmlNode *cib)
{
    struct refresh_data data;

    crm_peer_init();

    /* First, we mark all existing cache entries as dirty,
     * so that later we can remove any that weren't in the CIB.
     * We don't empty the cache, because we need to detect changes in state.
     */
    g_hash_table_foreach(crm_remote_peer_cache, mark_dirty, NULL);

    /* Look for guest nodes and remote nodes in the status section */
    data.field = "id";
    data.has_state = TRUE;
    crm_foreach_xpath_result(cib, XPATH_REMOTE_NODE_STATUS,
                             remote_cache_refresh_helper, &data);

    /* Look for guest nodes and remote nodes in the configuration section,
     * because they may have just been added and not have a status entry yet.
     * In that case, the cached node state will be left NULL, so that the
     * peer status callback isn't called until we're sure the node started
     * successfully.
     */
    data.field = "value";
    data.has_state = FALSE;
    crm_foreach_xpath_result(cib, XPATH_GUEST_NODE_CONFIG,
                             remote_cache_refresh_helper, &data);
    data.field = "id";
    data.has_state = FALSE;
    crm_foreach_xpath_result(cib, XPATH_REMOTE_NODE_CONFIG,
                             remote_cache_refresh_helper, &data);

    /* Remove all old cache entries that weren't seen in the CIB */
    g_hash_table_foreach_remove(crm_remote_peer_cache, is_dirty, NULL);
}

gboolean
crm_is_peer_active(const crm_node_t * node)
{
    if(node == NULL) {
        return FALSE;
    }

    if (is_set(node->flags, crm_remote_node)) {
        /* remote nodes are never considered active members. This
         * guarantees they will never be considered for DC membership.*/
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
        crm_info("Removing node with name %s and id %u from membership cache",
                 (node->uname? node->uname : "unknown"), node->id);
        return TRUE;
    }
    return FALSE;
}

/*!
 * \brief Remove all peer cache entries matching a node ID and/or uname
 *
 * \param[in] id    ID of node to remove (or 0 to ignore)
 * \param[in] name  Uname of node to remove (or NULL to ignore)
 *
 * \return Number of cache entries removed
 */
guint
reap_crm_member(uint32_t id, const char *name)
{
    int matches = 0;
    crm_node_t search;

    if (crm_peer_cache == NULL) {
        crm_trace("Membership cache not initialized, ignoring purge request");
        return 0;
    }

    search.id = id;
    search.uname = name ? strdup(name) : NULL;
    matches = g_hash_table_foreach_remove(crm_peer_cache, crm_reap_dead_member, &search);
    if(matches) {
        crm_notice("Purged %d peers with id=%u%s%s from the membership cache",
                   matches, search.id,
                   (search.uname? " and/or uname=" : ""),
                   (search.uname? search.uname : ""));

    } else {
        crm_info("No peers with id=%u%s%s to purge from the membership cache",
                 search.id, (search.uname? " and/or uname=" : ""),
                 (search.uname? search.uname : ""));
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

static void
destroy_crm_node(gpointer data)
{
    crm_node_t *node = data;

    crm_trace("Destroying entry for node %u: %s", node->id, node->uname);

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
        crm_peer_cache = g_hash_table_new_full(crm_strcase_hash, crm_strcase_equal, free, destroy_crm_node);
    }

    if (crm_remote_peer_cache == NULL) {
        crm_remote_peer_cache = g_hash_table_new_full(crm_strcase_hash, crm_strcase_equal, NULL, destroy_crm_node);
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

    if (crm_remote_peer_cache != NULL) {
        crm_trace("Destroying remote peer cache with %d members", g_hash_table_size(crm_remote_peer_cache));
        g_hash_table_destroy(crm_remote_peer_cache);
        crm_remote_peer_cache = NULL;
    }
}

void (*crm_status_callback) (enum crm_status_type, crm_node_t *, const void *) = NULL;

/*!
 * \brief Set a client function that will be called after peer status changes
 *
 * \param[in] dispatch  Pointer to function to use as callback
 *
 * \note Previously, client callbacks were responsible for peer cache
 *       management. This is no longer the case, and client callbacks should do
 *       only client-specific handling. Callbacks MUST NOT add or remove entries
 *       in the peer caches.
 */
void
crm_set_status_callback(void (*dispatch) (enum crm_status_type, crm_node_t *, const void *))
{
    crm_status_callback = dispatch;
}

/*!
 * \brief Tell the library whether to automatically reap lost nodes
 *
 * If TRUE (the default), calling crm_update_peer_proc() will also update the
 * peer state to CRM_NODE_MEMBER or CRM_NODE_LOST, and crm_update_peer_state()
 * will reap peers whose state changes to anything other than CRM_NODE_MEMBER.
 * Callers should leave this enabled unless they plan to manage the cache
 * separately on their own.
 *
 * \param[in] autoreap  TRUE to enable automatic reaping, FALSE to disable
 */
void
crm_set_autoreap(gboolean autoreap)
{
    crm_autoreap = autoreap;
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

static gboolean crm_hash_find_by_data(gpointer key, gpointer value, gpointer user_data)
{
    if(value == user_data) {
        return TRUE;
    }
    return FALSE;
}

crm_node_t *
crm_find_peer_full(unsigned int id, const char *uname, int flags)
{
    crm_node_t *node = NULL;

    CRM_ASSERT(id > 0 || uname != NULL);

    crm_peer_init();

    if (flags & CRM_GET_PEER_REMOTE) {
        node = g_hash_table_lookup(crm_remote_peer_cache, uname);
    }

    if (node == NULL && (flags & CRM_GET_PEER_CLUSTER)) {
        node = crm_find_peer(id, uname);
    }
    return node;
}

crm_node_t *
crm_get_peer_full(unsigned int id, const char *uname, int flags)
{
    crm_node_t *node = NULL;

    CRM_ASSERT(id > 0 || uname != NULL);

    crm_peer_init();

    if (flags & CRM_GET_PEER_REMOTE) {
        node = g_hash_table_lookup(crm_remote_peer_cache, uname);
    }

    if (node == NULL && (flags & CRM_GET_PEER_CLUSTER)) {
        node = crm_get_peer(id, uname);
    }
    return node;
}

crm_node_t *
crm_find_peer(unsigned int id, const char *uname)
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
        if(safe_str_eq(uname, by_id->uname)) {
            crm_notice("Node '%s' has changed its ID from %u to %u", by_id->uname, by_name->id, by_id->id);
            g_hash_table_foreach_remove(crm_peer_cache, crm_hash_find_by_data, by_name);

        } else {
            crm_warn("Node '%s' and '%s' share the same cluster nodeid: %u %s", by_id->uname, by_name->uname, id, uname);
            crm_dump_peer_hash(LOG_INFO, __FUNCTION__);
            crm_abort(__FILE__, __FUNCTION__, __LINE__, "member weirdness", TRUE, TRUE);
        }

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
        g_hash_table_foreach_remove(crm_peer_cache, crm_hash_find_by_data, by_name);
    }

    return node;
}

#if SUPPORT_COROSYNC
static guint
crm_remove_conflicting_peer(crm_node_t *node)
{
    int matches = 0;
    GHashTableIter iter;
    crm_node_t *existing_node = NULL;

    if (node->id == 0 || node->uname == NULL) {
        return 0;
    }

#  if !SUPPORT_PLUGIN
    if (corosync_cmap_has_config("nodelist") != 0) {
        return 0;
    }
#  endif

    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &existing_node)) {
        if (existing_node->id > 0
            && existing_node->id != node->id
            && existing_node->uname != NULL
            && strcasecmp(existing_node->uname, node->uname) == 0) {

            if (crm_is_peer_active(existing_node)) {
                continue;
            }

            crm_warn("Removing cached offline node %u/%s which has conflicting uname with %u",
                     existing_node->id, existing_node->uname, node->id);

            g_hash_table_iter_remove(&iter);
            matches++;
        }
    }

    return matches;
}
#endif

/* coverity[-alloc] Memory is referenced in one or both hashtables */
crm_node_t *
crm_get_peer(unsigned int id, const char *uname)
{
    crm_node_t *node = NULL;
    char *uname_lookup = NULL;

    CRM_ASSERT(id > 0 || uname != NULL);

    crm_peer_init();

    node = crm_find_peer(id, uname);

    /* if uname wasn't provided, and find_peer did not turn up a uname based on id.
     * we need to do a lookup of the node name using the id in the cluster membership. */
    if ((node == NULL || node->uname == NULL) && (uname == NULL)) { 
        uname_lookup = get_node_name(id);
    }

    if (uname_lookup) {
        uname = uname_lookup;
        crm_trace("Inferred a name of '%s' for node %u", uname, id);

        /* try to turn up the node one more time now that we know the uname. */
        if (node == NULL) {
            node = crm_find_peer(id, uname);
        }
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

    if (uname && (node->uname == NULL)) {
        crm_update_peer_uname(node, uname);
    }

    if(node->uuid == NULL) {
        const char *uuid = crm_peer_uuid(node);

        if (uuid) {
            crm_info("Node %u has uuid %s", id, uuid);

        } else {
            crm_info("Cannot obtain a UUID for node %u/%s", id, node->uname);
        }
    }

    free(uname_lookup);

    return node;
}

/*!
 * \internal
 * \brief Update all of a node's information (process list, state, etc.)
 *
 * \param[in] source      Caller's function name (for log messages)
 *
 * \return NULL if node was reaped from peer caches, pointer to node otherwise
 *
 * \note This function should not be called within a peer cache iteration,
 *       otherwise reaping could invalidate the iterator.
 */
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
        if (crm_update_peer_proc(source, node, children, state) == NULL) {
            return NULL;
        }
    }

    if (state != NULL) {
        if (crm_update_peer_state(source, node, state, seen) == NULL) {
            return NULL;
        }
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

/*!
 * \internal
 * \brief Update a node's uname
 *
 * \param[in] node        Node object to update
 * \param[in] uname       New name to set
 *
 * \note This function should not be called within a peer cache iteration,
 *       because in some cases it can remove conflicting cache entries,
 *       which would invalidate the iterator.
 */
void
crm_update_peer_uname(crm_node_t *node, const char *uname)
{
    int i, len = strlen(uname);

    for (i = 0; i < len; i++) {
        if (uname[i] >= 'A' && uname[i] <= 'Z') {
            crm_warn("Node names with capitals are discouraged, consider changing '%s'",
                     uname);
            break;
        }
    }

    free(node->uname);
    node->uname = strdup(uname);
    if (crm_status_callback) {
        crm_status_callback(crm_status_uname, node, NULL);
    }

#if SUPPORT_COROSYNC
    if (is_openais_cluster() && !is_set(node->flags, crm_remote_node)) {
        crm_remove_conflicting_peer(node);
    }
#endif
}

/*!
 * \internal
 * \brief Update a node's process information (and potentially state)
 *
 * \param[in] source      Caller's function name (for log messages)
 * \param[in] node        Node object to update
 * \param[in] flag        Bitmask of new process information
 * \param[in] status      node status (online, offline, etc.)
 *
 * \return NULL if any node was reaped from peer caches, value of node otherwise
 *
 * \note If this function returns NULL, the supplied node object was likely
 *       freed and should not be used again. This function should not be
 *       called within a cache iteration if reaping is possible, otherwise
 *       reaping could invalidate the iterator.
 */
crm_node_t *
crm_update_peer_proc(const char *source, crm_node_t * node, uint32_t flag, const char *status)
{
    uint32_t last = 0;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set %s to %s for NULL",
                                    source, peer2text(flag), status); return NULL);

    /* Pacemaker doesn't spawn processes on remote nodes */
    if (is_set(node->flags, crm_remote_node)) {
        return node;
    }

    last = node->processes;
    if (status == NULL) {
        node->processes = flag;
        if (node->processes != last) {
            changed = TRUE;
        }

    } else if (safe_str_eq(status, ONLINESTATUS)) {
        if ((node->processes & flag) != flag) {
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

        /* Call the client callback first, then update the peer state,
         * in case the node will be reaped
         */
        if (crm_status_callback) {
            crm_status_callback(crm_status_processes, node, &last);
        }

        /* The client callback shouldn't touch the peer caches,
         * but as a safety net, bail if the peer cache was destroyed.
         */
        if (crm_peer_cache == NULL) {
            return NULL;
        }

        if (crm_autoreap) {
            node = crm_update_peer_state(__FUNCTION__, node,
                                         is_set(node->processes, crm_get_cluster_proc())?
                                         CRM_NODE_MEMBER : CRM_NODE_LOST, 0);
        }
    } else {
        crm_trace("%s: Node %s[%u] - %s is unchanged (%s)", source, node->uname, node->id,
                  peer2text(flag), status);
    }
    return node;
}

void
crm_update_peer_expected(const char *source, crm_node_t * node, const char *expected)
{
    char *last = NULL;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set 'expected' to %s", source, expected);
              return);

    /* Remote nodes don't participate in joins */
    if (is_set(node->flags, crm_remote_node)) {
        return;
    }

    last = node->expected;
    if (expected != NULL && safe_str_neq(node->expected, expected)) {
        node->expected = strdup(expected);
        changed = TRUE;
    }

    if (changed) {
        crm_info("%s: Node %s[%u] - expected state is now %s (was %s)", source, node->uname, node->id,
                 expected, last);
        free(last);
    } else {
        crm_trace("%s: Node %s[%u] - expected state is unchanged (%s)", source, node->uname,
                  node->id, expected);
    }
}

/*!
 * \internal
 * \brief Update a node's state and membership information
 *
 * \param[in] source      Caller's function name (for log messages)
 * \param[in] node        Node object to update
 * \param[in] state       Node's new state
 * \param[in] membership  Node's new membership ID
 * \param[in] iter        If not NULL, pointer to node's peer cache iterator
 *
 * \return NULL if any node was reaped, value of node otherwise
 *
 * \note If this function returns NULL, the supplied node object was likely
 *       freed and should not be used again. This function may be called from
 *       within a peer cache iteration if the iterator is supplied.
 */
static crm_node_t *
crm_update_peer_state_iter(const char *source, crm_node_t * node, const char *state, int membership, GHashTableIter *iter)
{
    gboolean is_member;

    CRM_CHECK(node != NULL,
              crm_err("Could not set state for unknown host to %s"
                      CRM_XS " source=%s", state, source);
              return NULL);

    is_member = safe_str_eq(state, CRM_NODE_MEMBER);
    if (membership && is_member) {
        node->last_seen = membership;
    }

    if (state && safe_str_neq(node->state, state)) {
        char *last = node->state;
        enum crm_status_type status_type = is_set(node->flags, crm_remote_node)?
                                           crm_status_rstate : crm_status_nstate;

        node->state = strdup(state);
        crm_notice("Node %s state is now %s " CRM_XS
                   " nodeid=%u previous=%s source=%s", node->uname, state,
                   node->id, (last? last : "unknown"), source);
        if (crm_status_callback) {
            crm_status_callback(status_type, node, last);
        }
        free(last);

        if (crm_autoreap && !is_member && !is_set(node->flags, crm_remote_node)) {
            /* We only autoreap from the peer cache, not the remote peer cache,
             * because the latter should be managed only by
             * crm_remote_peer_cache_refresh().
             */
            if(iter) {
                crm_notice("Purged 1 peer with id=%u and/or uname=%s from the membership cache", node->id, node->uname);
                g_hash_table_iter_remove(iter);

            } else {
                reap_crm_member(node->id, node->uname);
            }
            node = NULL;
        }

    } else {
        crm_trace("Node %s state is unchanged (%s) " CRM_XS
                  " nodeid=%u source=%s", node->uname, state, node->id, source);
    }
    return node;
}

/*!
 * \brief Update a node's state and membership information
 *
 * \param[in] source      Caller's function name (for log messages)
 * \param[in] node        Node object to update
 * \param[in] state       Node's new state
 * \param[in] membership  Node's new membership ID
 *
 * \return NULL if any node was reaped, value of node otherwise
 *
 * \note If this function returns NULL, the supplied node object was likely
 *       freed and should not be used again. This function should not be
 *       called within a cache iteration if reaping is possible,
 *       otherwise reaping could invalidate the iterator.
 */
crm_node_t *
crm_update_peer_state(const char *source, crm_node_t * node, const char *state, int membership)
{
    return crm_update_peer_state_iter(source, node, state, membership, NULL);
}

/*!
 * \internal
 * \brief Reap all nodes from cache whose membership information does not match
 *
 * \param[in] membership  Membership ID of nodes to keep
 */
void
crm_reap_unseen_nodes(uint64_t membership)
{
    GHashTableIter iter;
    crm_node_t *node = NULL;

    crm_trace("Reaping unseen nodes...");
    g_hash_table_iter_init(&iter, crm_peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&node)) {
        if (node->last_seen != membership) {
            if (node->state) {
                /*
                 * Calling crm_update_peer_state_iter() allows us to
                 * remove the node from crm_peer_cache without
                 * invalidating our iterator
                 */
                crm_update_peer_state_iter(__FUNCTION__, node, CRM_NODE_LOST, membership, &iter);

            } else {
                crm_info("State of node %s[%u] is still unknown",
                         node->uname, node->id);
            }
        }
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

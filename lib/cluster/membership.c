/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <inttypes.h>                   // PRIu32
#include <stdbool.h>                    // bool
#include <stdio.h>
#include <string.h>
#include <sys/param.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>

#include <crm/common/ipc.h>
#include <crm/common/xml_internal.h>
#include <crm/cluster/internal.h>
#include <crm/common/xml.h>
#include <crm/stonith-ng.h>
#include "crmcluster_private.h"

/* The peer cache remembers cluster nodes that have been seen. This is managed
 * mostly automatically by libcrmcluster, based on cluster membership events.
 *
 * Because cluster nodes can have conflicting names or UUIDs, the hash table key
 * is a uniquely generated ID.
 *
 * @TODO Move caches to pcmk_cluster_t
 */
GHashTable *pcmk__peer_cache = NULL;

/* The remote peer cache tracks pacemaker_remote nodes. While the
 * value has the same type as the peer cache's, it is tracked separately for
 * three reasons: pacemaker_remote nodes can't have conflicting names or UUIDs,
 * so the name (which is also the UUID) is used as the hash table key; there
 * is no equivalent of membership events, so management is not automatic; and
 * most users of the peer cache need to exclude pacemaker_remote nodes.
 *
 * @TODO That said, using a single cache would be more logical and less
 * error-prone, so it would be a good idea to merge them one day.
 *
 * libcrmcluster provides two avenues for populating the cache:
 * pcmk__cluster_lookup_remote_node() and pcmk__cluster_forget_remote_node()
 * directly manage it, while refresh_remote_nodes() populates it via the CIB.
 *
 * @TODO Move caches to pcmk_cluster_t
 */
GHashTable *pcmk__remote_peer_cache = NULL;

/*
 * The CIB cluster node cache tracks cluster nodes that have been seen in
 * the CIB. It is useful mainly when a caller needs to know about a node that
 * may no longer be in the membership, but doesn't want to add the node to the
 * main peer cache tables.
 */
static GHashTable *cluster_node_cib_cache = NULL;

static bool autoreap = true;
static bool has_quorum = false;

// Flag setting and clearing for pcmk__node_status_t:flags

#define set_peer_flags(peer, flags_to_set) do {                               \
        (peer)->flags = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE,     \
                                           "Peer", (peer)->name,              \
                                           (peer)->flags, (flags_to_set),     \
                                           #flags_to_set);                    \
    } while (0)

#define clear_peer_flags(peer, flags_to_clear) do {                           \
        (peer)->flags = pcmk__clear_flags_as(__func__, __LINE__,              \
                                             LOG_TRACE,                       \
                                             "Peer", (peer)->name,            \
                                             (peer)->flags, (flags_to_clear), \
                                             #flags_to_clear);                \
    } while (0)

static void update_peer_uname(pcmk__node_status_t *node, const char *uname);
static pcmk__node_status_t *find_cib_cluster_node(const char *id,
                                                  const char *uname);

/*!
 * \internal
 * \brief Check whether the cluster currently has quorum
 *
 * \return \c true if the cluster has quorum, or \c false otherwise
 */
bool
pcmk__cluster_has_quorum(void)
{
    return has_quorum;
}

/*!
 * \internal
 * \brief Set whether the cluster currently has quorum
 *
 * \param[in] quorate  \c true if the cluster has quorum, or \c false otherwise
 */
void
pcmk__cluster_set_quorum(bool quorate)
{
    has_quorum = quorate;
}

/*!
 * \internal
 * \brief Get the number of Pacemaker Remote nodes that have been seen
 *
 * \return Number of cached Pacemaker Remote nodes
 */
unsigned int
pcmk__cluster_num_remote_nodes(void)
{
    if (pcmk__remote_peer_cache == NULL) {
        return 0U;
    }
    return g_hash_table_size(pcmk__remote_peer_cache);
}

/*!
 * \internal
 * \brief Get a remote node cache entry, creating it if necessary
 *
 * \param[in] node_name  Name of remote node
 *
 * \return Cache entry for node on success, or \c NULL (and set \c errno)
 *         otherwise
 *
 * \note When creating a new entry, this will leave the node state undetermined.
 *       The caller should also call \c pcmk__update_peer_state() if the state
 *       is known.
 * \note Because this can add and remove cache entries, callers should not
 *       assume any previously obtained cache entry pointers remain valid.
 */
pcmk__node_status_t *
pcmk__cluster_lookup_remote_node(const char *node_name)
{
    pcmk__node_status_t *node = NULL;
    char *node_name_copy = NULL;

    if (node_name == NULL) {
        errno = EINVAL;
        return NULL;
    }

    /* It's theoretically possible that the node was added to the cluster peer
     * cache before it was known to be a Pacemaker Remote node. Remove that
     * entry unless it has an XML ID, which means the name actually is
     * associated with a cluster node. (@TODO return an error in that case?)
     */
    node = pcmk__search_node_caches(0, node_name, NULL,
                                    pcmk__node_search_cluster_member);
    if ((node != NULL)
        && ((node->xml_id == NULL)
            /* This assumes only Pacemaker Remote nodes have their XML ID the
             * same as their node name
             */
            || pcmk__str_eq(node->name, node->xml_id, pcmk__str_none))) {

        /* node_name could be a pointer into the cache entry being removed, so
         * reassign it to a copy before the original gets freed
         */
        node_name_copy = strdup(node_name);
        if (node_name_copy == NULL) {
            errno = ENOMEM;
            return NULL;
        }
        node_name = node_name_copy;
        pcmk__cluster_forget_cluster_node(0, node_name);
    }

    /* Return existing cache entry if one exists */
    node = g_hash_table_lookup(pcmk__remote_peer_cache, node_name);
    if (node) {
        free(node_name_copy);
        return node;
    }

    /* Allocate a new entry */
    node = calloc(1, sizeof(pcmk__node_status_t));
    if (node == NULL) {
        free(node_name_copy);
        return NULL;
    }

    /* Populate the essential information */
    set_peer_flags(node, pcmk__node_status_remote);
    node->xml_id = strdup(node_name);
    if (node->xml_id == NULL) {
        free(node);
        errno = ENOMEM;
        free(node_name_copy);
        return NULL;
    }

    /* Add the new entry to the cache */
    g_hash_table_replace(pcmk__remote_peer_cache, node->xml_id, node);
    crm_trace("added %s to remote cache", node_name);

    /* Update the entry's uname, ensuring peer status callbacks are called */
    update_peer_uname(node, node_name);
    free(node_name_copy);
    return node;
}

/*!
 * \internal
 * \brief Remove a node from the Pacemaker Remote node cache
 *
 * \param[in] node_name  Name of node to remove from cache
 *
 * \note The caller must be careful not to use \p node_name after calling this
 *       function if it might be a pointer into the cache entry being removed.
 */
void
pcmk__cluster_forget_remote_node(const char *node_name)
{
    /* Do a lookup first, because node_name could be a pointer within the entry
     * being removed -- we can't log it *after* removing it.
     */
    if (g_hash_table_lookup(pcmk__remote_peer_cache, node_name) != NULL) {
        crm_trace("Removing %s from Pacemaker Remote node cache", node_name);
        g_hash_table_remove(pcmk__remote_peer_cache, node_name);
    }
}

/*!
 * \internal
 * \brief Return node status based on a CIB status entry
 *
 * \param[in] node_state  XML of node state
 *
 * \return \c PCMK_VALUE_MEMBER if \c PCMK__XA_IN_CCM is true in
 *         \c PCMK__XE_NODE_STATE, or \c PCMK__VALUE_LOST otherwise
 */
static const char *
remote_state_from_cib(const xmlNode *node_state)
{
    bool in_ccm = false;

    if ((pcmk__xe_get_bool_attr(node_state, PCMK__XA_IN_CCM,
                                &in_ccm) == pcmk_rc_ok) && in_ccm) {
        return PCMK_VALUE_MEMBER;
    }
    return PCMK__VALUE_LOST;
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
    const struct refresh_data *data = user_data;
    const char *remote = pcmk__xe_get(result, data->field);
    const char *state = NULL;
    pcmk__node_status_t *node;

    CRM_CHECK(remote != NULL, return);

    /* Determine node's state, if the result has it */
    if (data->has_state) {
        state = remote_state_from_cib(result);
    }

    /* Check whether cache already has entry for node */
    node = g_hash_table_lookup(pcmk__remote_peer_cache, remote);

    if (node == NULL) {
        /* Node is not in cache, so add a new entry for it */
        node = pcmk__cluster_lookup_remote_node(remote);
        pcmk__assert(node != NULL);
        if (state) {
            pcmk__update_peer_state(__func__, node, state, 0);
        }

    } else if (pcmk_is_set(node->flags, pcmk__node_status_dirty)) {
        /* Node is in cache and hasn't been updated already, so mark it clean */
        clear_peer_flags(node, pcmk__node_status_dirty);
        if (state) {
            pcmk__update_peer_state(__func__, node, state, 0);
        }
    }
}

static void
mark_dirty(gpointer key, gpointer value, gpointer user_data)
{
    set_peer_flags((pcmk__node_status_t *) value, pcmk__node_status_dirty);
}

static gboolean
is_dirty(gpointer key, gpointer value, gpointer user_data)
{
    const pcmk__node_status_t *node = value;

    return pcmk_is_set(node->flags, pcmk__node_status_dirty);
}

/*!
 * \internal
 * \brief Repopulate the remote node cache based on CIB XML
 *
 * \param[in] cib  CIB XML to parse
 */
static void
refresh_remote_nodes(xmlNode *cib)
{
    struct refresh_data data;

    pcmk__cluster_init_node_caches();

    /* First, we mark all existing cache entries as dirty,
     * so that later we can remove any that weren't in the CIB.
     * We don't empty the cache, because we need to detect changes in state.
     */
    g_hash_table_foreach(pcmk__remote_peer_cache, mark_dirty, NULL);

    /* Look for guest nodes and remote nodes in the status section */
    data.field = PCMK_XA_ID;
    data.has_state = TRUE;
    pcmk__xpath_foreach_result(cib->doc, PCMK__XP_REMOTE_NODE_STATUS,
                               remote_cache_refresh_helper, &data);

    /* Look for guest nodes and remote nodes in the configuration section,
     * because they may have just been added and not have a status entry yet.
     * In that case, the cached node state will be left NULL, so that the
     * peer status callback isn't called until we're sure the node started
     * successfully.
     */
    data.field = PCMK_XA_VALUE;
    data.has_state = FALSE;
    pcmk__xpath_foreach_result(cib->doc, PCMK__XP_GUEST_NODE_CONFIG,
                               remote_cache_refresh_helper, &data);
    data.field = PCMK_XA_ID;
    data.has_state = FALSE;
    pcmk__xpath_foreach_result(cib->doc, PCMK__XP_REMOTE_NODE_CONFIG,
                               remote_cache_refresh_helper, &data);

    /* Remove all old cache entries that weren't seen in the CIB */
    g_hash_table_foreach_remove(pcmk__remote_peer_cache, is_dirty, NULL);
}

/*!
 * \internal
 * \brief Check whether a node is an active cluster node
 *
 * Remote nodes are never considered active. This guarantees that they can never
 * become DC.
 *
 * \param[in] node  Node to check
 *
 * \return \c true if the node is an active cluster node, or \c false otherwise
 */
bool
pcmk__cluster_is_node_active(const pcmk__node_status_t *node)
{
    const enum pcmk_cluster_layer cluster_layer = pcmk_get_cluster_layer();

    if ((node == NULL) || pcmk_is_set(node->flags, pcmk__node_status_remote)) {
        return false;
    }

    switch (cluster_layer) {
        case pcmk_cluster_layer_corosync:
#if SUPPORT_COROSYNC
            return pcmk__corosync_is_peer_active(node);
#else
            break;
#endif  // SUPPORT_COROSYNC
        default:
            break;
    }

    crm_err("Unhandled cluster layer: %s",
            pcmk_cluster_layer_text(cluster_layer));
    return false;
}

/*!
 * \internal
 * \brief Check if a node's entry should be removed from the cluster node cache
 *
 * A node should be removed from the cache if it's inactive and matches another
 * \c pcmk__node_status_t (the search object). The node is considered a
 * mismatch if any of the following are true:
 * * The search object is \c NULL.
 * * The search object has an ID set and the cached node's ID does not match it.
 * * The search object does not have an ID set, and the cached node's name does
 *   not match the search node's name. (If both names are \c NULL, it's a
 *   match.)
 *
 * Otherwise, the node is considered a match.
 *
 * Note that if the search object has both an ID and a name set, the name is
 * ignored for matching purposes.
 *
 * \param[in] key        Ignored
 * \param[in] value      \c pcmk__node_status_t object from cluster node cache
 * \param[in] user_data  \c pcmk__node_status_t object to match against (search
 *                       object)
 *
 * \return \c TRUE if the node entry should be removed from \c pcmk__peer_cache,
 *         or \c FALSE otherwise
 */
static gboolean
should_forget_cluster_node(gpointer key, gpointer value, gpointer user_data)
{
    pcmk__node_status_t *node = value;
    pcmk__node_status_t *search = user_data;

    if (search == NULL) {
        return FALSE;
    }
    if ((search->cluster_layer_id != 0)
        && (node->cluster_layer_id != search->cluster_layer_id)) {
        return FALSE;
    }
    if ((search->cluster_layer_id == 0)
        && !pcmk__str_eq(node->name, search->name, pcmk__str_casei)) {
        // @TODO Consider name even if ID is set?
        return FALSE;
    }
    if (pcmk__cluster_is_node_active(value)) {
        return FALSE;
    }

    crm_info("Removing node with name %s and cluster layer ID %" PRIu32
             " from membership cache",
             pcmk__s(node->name, "(unknown)"), node->cluster_layer_id);
    return TRUE;
}

/*!
 * \internal
 * \brief Remove one or more inactive nodes from the cluster node cache
 *
 * All inactive nodes matching \p id and \p node_name as described in
 * \c should_forget_cluster_node documentation are removed from the cache.
 *
 * If \p id is 0 and \p node_name is \c NULL, all inactive nodes are removed
 * from the cache regardless of ID and name. This differs from clearing the
 * cache, in that entries for active nodes are preserved.
 *
 * \param[in] id         ID of node to remove from cache (0 to ignore)
 * \param[in] node_name  Name of node to remove from cache (ignored if \p id is
 *                       nonzero)
 *
 * \note \p node_name is not modified directly, but it will be freed if it's a
 *       pointer into a cache entry that is removed.
 */
void
pcmk__cluster_forget_cluster_node(uint32_t id, const char *node_name)
{
    pcmk__node_status_t search = { 0, };
    char *criterion = NULL; // For logging
    guint matches = 0;

    if (pcmk__peer_cache == NULL) {
        crm_trace("Membership cache not initialized, ignoring removal request");
        return;
    }

    search.cluster_layer_id = id;
    search.name = pcmk__str_copy(node_name);    // May log after original freed

    if (id > 0) {
        criterion = crm_strdup_printf("cluster layer ID %" PRIu32, id);

    } else if (node_name != NULL) {
        criterion = crm_strdup_printf("name %s", node_name);
    }

    matches = g_hash_table_foreach_remove(pcmk__peer_cache,
                                          should_forget_cluster_node, &search);
    if (matches > 0) {
        if (criterion != NULL) {
            crm_notice("Removed %u inactive node%s with %s from the membership "
                       "cache",
                       matches, pcmk__plural_s(matches), criterion);
        } else {
            crm_notice("Removed all (%u) inactive cluster nodes from the "
                       "membership cache",
                       matches);
        }

    } else {
        crm_info("No inactive cluster nodes%s%s to remove from the membership "
                 "cache",
                 ((criterion != NULL)? " with " : ""), pcmk__s(criterion, ""));
    }

    free(search.name);
    free(criterion);
}

static void
count_peer(gpointer key, gpointer value, gpointer user_data)
{
    unsigned int *count = user_data;
    pcmk__node_status_t *node = value;

    if (pcmk__cluster_is_node_active(node)) {
        *count = *count + 1;
    }
}

/*!
 * \internal
 * \brief Get the number of active cluster nodes that have been seen
 *
 * Remote nodes are never considered active. This guarantees that they can never
 * become DC.
 *
 * \return Number of active nodes in the cluster node cache
 */
unsigned int
pcmk__cluster_num_active_nodes(void)
{
    unsigned int count = 0;

    if (pcmk__peer_cache != NULL) {
        g_hash_table_foreach(pcmk__peer_cache, count_peer, &count);
    }
    return count;
}

static void
destroy_crm_node(gpointer data)
{
    pcmk__node_status_t *node = data;

    crm_trace("Destroying entry for node %" PRIu32 ": %s",
              node->cluster_layer_id, node->name);

    free(node->name);
    free(node->state);
    free(node->xml_id);
    free(node->user_data);
    free(node->expected);
    free(node->conn_host);
    free(node);
}

/*!
 * \internal
 * \brief Initialize node caches
 */
void
pcmk__cluster_init_node_caches(void)
{
    if (pcmk__peer_cache == NULL) {
        pcmk__peer_cache = pcmk__strikey_table(free, destroy_crm_node);
    }

    if (pcmk__remote_peer_cache == NULL) {
        pcmk__remote_peer_cache = pcmk__strikey_table(NULL, destroy_crm_node);
    }

    if (cluster_node_cib_cache == NULL) {
        cluster_node_cib_cache = pcmk__strikey_table(free, destroy_crm_node);
    }
}

/*!
 * \internal
 * \brief Initialize node caches
 */
void
pcmk__cluster_destroy_node_caches(void)
{
    if (pcmk__peer_cache != NULL) {
        crm_trace("Destroying peer cache with %d members",
                  g_hash_table_size(pcmk__peer_cache));
        g_hash_table_destroy(pcmk__peer_cache);
        pcmk__peer_cache = NULL;
    }

    if (pcmk__remote_peer_cache != NULL) {
        crm_trace("Destroying remote peer cache with %d members",
                  pcmk__cluster_num_remote_nodes());
        g_hash_table_destroy(pcmk__remote_peer_cache);
        pcmk__remote_peer_cache = NULL;
    }

    if (cluster_node_cib_cache != NULL) {
        crm_trace("Destroying configured cluster node cache with %d members",
                  g_hash_table_size(cluster_node_cib_cache));
        g_hash_table_destroy(cluster_node_cib_cache);
        cluster_node_cib_cache = NULL;
    }
}

static void (*peer_status_callback)(enum pcmk__node_update,
                                    pcmk__node_status_t *,
                                    const void *) = NULL;

/*!
 * \internal
 * \brief Set a client function that will be called after peer status changes
 *
 * \param[in] dispatch  Pointer to function to use as callback
 *
 * \note Client callbacks should do only client-specific handling. Callbacks
 *       must not add or remove entries in the peer caches.
 */
void
pcmk__cluster_set_status_callback(void (*dispatch)(enum pcmk__node_update,
                                                   pcmk__node_status_t *,
                                                   const void *))
{
    // @TODO Improve documentation of peer_status_callback
    peer_status_callback = dispatch;
}

/*!
 * \internal
 * \brief Tell the library whether to automatically reap lost nodes
 *
 * If \c true (the default), calling \c crm_update_peer_proc() will also update
 * the peer state to \c PCMK_VALUE_MEMBER or \c PCMK__VALUE_LOST, and updating
 * the peer state will reap peers whose state changes to anything other than
 * \c PCMK_VALUE_MEMBER.
 *
 * Callers should leave this enabled unless they plan to manage the cache
 * separately on their own.
 *
 * \param[in] enable  \c true to enable automatic reaping, \c false to disable
 */
void
pcmk__cluster_set_autoreap(bool enable)
{
    autoreap = enable;
}

static void
dump_peer_hash(int level, const char *caller)
{
    GHashTableIter iter;
    const char *id = NULL;
    pcmk__node_status_t *node = NULL;

    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, (gpointer *) &id, (gpointer *) &node)) {
        do_crm_log(level, "%s: Node %" PRIu32 "/%s = %p - %s",
                   caller, node->cluster_layer_id, node->name, node, id);
    }
}

static gboolean
hash_find_by_data(gpointer key, gpointer value, gpointer user_data)
{
    return value == user_data;
}

/*!
 * \internal
 * \brief Search cluster member node cache
 *
 * \param[in] id     If not 0, cluster node ID to search for
 * \param[in] uname  If not NULL, node name to search for
 * \param[in] uuid   If not NULL while id is 0, node UUID instead of cluster
 *                   node ID to search for
 *
 * \return Cluster node cache entry if found, otherwise NULL
 */
static pcmk__node_status_t *
search_cluster_member_cache(unsigned int id, const char *uname,
                            const char *uuid)
{
    GHashTableIter iter;
    pcmk__node_status_t *node = NULL;
    pcmk__node_status_t *by_id = NULL;
    pcmk__node_status_t *by_name = NULL;

    pcmk__assert((id > 0) || (uname != NULL));

    pcmk__cluster_init_node_caches();

    if (uname != NULL) {
        g_hash_table_iter_init(&iter, pcmk__peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (pcmk__str_eq(node->name, uname, pcmk__str_casei)) {
                crm_trace("Name match: %s", node->name);
                by_name = node;
                break;
            }
        }
    }

    if (id > 0) {
        g_hash_table_iter_init(&iter, pcmk__peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (node->cluster_layer_id == id) {
                crm_trace("ID match: %" PRIu32, node->cluster_layer_id);
                by_id = node;
                break;
            }
        }

    } else if (uuid != NULL) {
        g_hash_table_iter_init(&iter, pcmk__peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            const char *this_xml_id = pcmk__cluster_get_xml_id(node);

            if (pcmk__str_eq(uuid, this_xml_id, pcmk__str_none)) {
                crm_trace("Found cluster node cache entry by XML ID %s",
                          this_xml_id);
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

        if (id && by_name->cluster_layer_id) {
            dump_peer_hash(LOG_WARNING, __func__);
            crm_crit("Nodes %u and %" PRIu32 " share the same name '%s'",
                     id, by_name->cluster_layer_id, uname);
            node = NULL; /* Create a new one */

        } else {
            node = by_name;
        }

    } else if(by_name == NULL && by_id) {
        crm_trace("Only one: %p for %u/%s", by_id, id, uname);

        if ((uname != NULL) && (by_id->name != NULL)) {
            dump_peer_hash(LOG_WARNING, __func__);
            crm_crit("Nodes '%s' and '%s' share the same cluster nodeid %u: "
                     "assuming '%s' is correct",
                     uname, by_id->name, id, uname);
        }

    } else if ((uname != NULL) && (by_id->name != NULL)) {
        if (pcmk__str_eq(uname, by_id->name, pcmk__str_casei)) {
            crm_notice("Node '%s' has changed its cluster layer ID "
                       "from %" PRIu32 " to %" PRIu32,
                       by_id->name, by_name->cluster_layer_id,
                       by_id->cluster_layer_id);
            g_hash_table_foreach_remove(pcmk__peer_cache, hash_find_by_data,
                                        by_name);

        } else {
            crm_warn("Nodes '%s' and '%s' share the same cluster nodeid: %u %s",
                     by_id->name, by_name->name, id, uname);
            dump_peer_hash(LOG_INFO, __func__);
            crm_abort(__FILE__, __func__, __LINE__, "member weirdness", TRUE,
                      TRUE);
        }

    } else if ((id > 0) && (by_name->cluster_layer_id > 0)) {
        crm_warn("Nodes %" PRIu32 " and %" PRIu32 " share the same name: '%s'",
                 by_id->cluster_layer_id, by_name->cluster_layer_id, uname);

    } else {
        /* Simple merge */

        /* Only corosync-based clusters use node IDs. The functions that call
         * pcmk__update_peer_state() and crm_update_peer_proc() only know
         * nodeid, so 'by_id' is authoritative when merging.
         */
        dump_peer_hash(LOG_DEBUG, __func__);

        crm_info("Merging %p into %p", by_name, by_id);
        g_hash_table_foreach_remove(pcmk__peer_cache, hash_find_by_data,
                                    by_name);
    }

    return node;
}

/*!
 * \internal
 * \brief Search caches for a node (cluster or Pacemaker Remote)
 *
 * \param[in] id      If not 0, cluster node ID to search for
 * \param[in] uname   If not NULL, node name to search for
 * \param[in] xml_id  If not NULL, CIB XML ID of node to search for
 * \param[in] flags   Group of enum pcmk__node_search_flags
 *
 * \return Node cache entry if found, otherwise NULL
 */
pcmk__node_status_t *
pcmk__search_node_caches(unsigned int id, const char *uname,
                         const char *xml_id, uint32_t flags)
{
    pcmk__node_status_t *node = NULL;

    pcmk__assert((id > 0) || (uname != NULL) || (xml_id != NULL));

    pcmk__cluster_init_node_caches();

    if (pcmk_is_set(flags, pcmk__node_search_remote)) {
        if (uname != NULL) {
            node = g_hash_table_lookup(pcmk__remote_peer_cache, uname);
        } else if (xml_id != NULL) {
            node = g_hash_table_lookup(pcmk__remote_peer_cache, xml_id);
        }
    }

    if ((node == NULL)
        && pcmk_is_set(flags, pcmk__node_search_cluster_member)) {

        node = search_cluster_member_cache(id, uname, xml_id);
    }

    if ((node == NULL) && pcmk_is_set(flags, pcmk__node_search_cluster_cib)) {
        if (xml_id != NULL) {
            node = find_cib_cluster_node(xml_id, uname);
        } else {
            // Assumes XML ID is node ID as string (as with Corosync)
            char *id_str = (id == 0)? NULL : crm_strdup_printf("%u", id);

            node = find_cib_cluster_node(id_str, uname);
            free(id_str);
        }
    }

    return node;
}

/*!
 * \internal
 * \brief Purge a node from cache (both cluster and Pacemaker Remote)
 *
 * \param[in] node_name  If not NULL, purge only nodes with this name
 * \param[in] node_id    If not 0, purge cluster nodes only if they have this ID
 *
 * \note If \p node_name is NULL and \p node_id is 0, no nodes will be purged.
 *       If \p node_name is not NULL and \p node_id is not 0, Pacemaker Remote
 *       nodes that match \p node_name will be purged, and cluster nodes that
 *       match both \p node_name and \p node_id will be purged.
 * \note The caller must be careful not to use \p node_name after calling this
 *       function if it might be a pointer into a cache entry being removed.
 */
void
pcmk__purge_node_from_cache(const char *node_name, uint32_t node_id)
{
    char *node_name_copy = NULL;

    if ((node_name == NULL) && (node_id == 0U)) {
        return;
    }

    // Purge from Pacemaker Remote node cache
    if ((node_name != NULL)
        && (g_hash_table_lookup(pcmk__remote_peer_cache, node_name) != NULL)) {
        /* node_name could be a pointer into the cache entry being purged,
         * so reassign it to a copy before the original gets freed
         */
        node_name_copy = pcmk__str_copy(node_name);
        node_name = node_name_copy;

        crm_trace("Purging %s from Pacemaker Remote node cache", node_name);
        g_hash_table_remove(pcmk__remote_peer_cache, node_name);
    }

    pcmk__cluster_forget_cluster_node(node_id, node_name);
    free(node_name_copy);
}

#if SUPPORT_COROSYNC
static guint
remove_conflicting_peer(pcmk__node_status_t *node)
{
    int matches = 0;
    GHashTableIter iter;
    pcmk__node_status_t *existing_node = NULL;

    if ((node->cluster_layer_id == 0) || (node->name == NULL)) {
        return 0;
    }

    if (!pcmk__corosync_has_nodelist()) {
        return 0;
    }

    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &existing_node)) {
        if ((existing_node->cluster_layer_id > 0)
            && (existing_node->cluster_layer_id != node->cluster_layer_id)
            && pcmk__str_eq(existing_node->name, node->name, pcmk__str_casei)) {

            if (pcmk__cluster_is_node_active(existing_node)) {
                continue;
            }

            crm_warn("Removing cached offline node %" PRIu32 "/%s which has "
                     "conflicting name with %" PRIu32,
                     existing_node->cluster_layer_id, existing_node->name,
                     node->cluster_layer_id);

            g_hash_table_iter_remove(&iter);
            matches++;
        }
    }

    return matches;
}
#endif

/*!
 * \internal
 * \brief Get a cluster node cache entry, possibly creating one if not found
 *
 * If \c pcmk__node_search_cluster_member is set in \p flags, the return value
 * is guaranteed not to be \c NULL. A new cache entry is created if one does not
 * already exist.
 *
 * \param[in] id      If not 0, cluster node ID to search for
 * \param[in] uname   If not NULL, node name to search for
 * \param[in] xml_id  If not NULL while \p id is 0, search for this CIB XML ID
 *                    instead of a cluster ID
 * \param[in] flags   Group of enum pcmk__node_search_flags
 *
 * \return (Possibly newly created) cluster node cache entry
 */
/* coverity[-alloc] Memory is referenced in one or both hashtables */
pcmk__node_status_t *
pcmk__get_node(unsigned int id, const char *uname, const char *xml_id,
               uint32_t flags)
{
    pcmk__node_status_t *node = NULL;
    char *uname_lookup = NULL;

    pcmk__assert((id > 0) || (uname != NULL));

    pcmk__cluster_init_node_caches();

    // Check the Pacemaker Remote node cache first
    if (pcmk_is_set(flags, pcmk__node_search_remote)) {
        node = g_hash_table_lookup(pcmk__remote_peer_cache, uname);
        if (node != NULL) {
            return node;
        }
    }

    if (!pcmk_is_set(flags, pcmk__node_search_cluster_member)) {
        return NULL;
    }

    node = search_cluster_member_cache(id, uname, xml_id);

    /* if uname wasn't provided, and find_peer did not turn up a uname based on id.
     * we need to do a lookup of the node name using the id in the cluster membership. */
    if ((uname == NULL) && ((node == NULL) || (node->name == NULL))) {
        uname_lookup = pcmk__cluster_node_name(id);
    }

    if (uname_lookup) {
        uname = uname_lookup;
        crm_trace("Inferred a name of '%s' for node %u", uname, id);

        /* try to turn up the node one more time now that we know the uname. */
        if (node == NULL) {
            node = search_cluster_member_cache(id, uname, xml_id);
        }
    }

    if (node == NULL) {
        char *uniqueid = crm_generate_uuid();

        node = pcmk__assert_alloc(1, sizeof(pcmk__node_status_t));

        crm_info("Created entry %s/%p for node %s/%u (%d total)",
                 uniqueid, node, uname, id,
                 1 + g_hash_table_size(pcmk__peer_cache));
        g_hash_table_replace(pcmk__peer_cache, uniqueid, node);
    }

    if ((id > 0) && (uname != NULL)
        && ((node->cluster_layer_id == 0) || (node->name == NULL))) {
        crm_info("Node %u is now known as %s", id, uname);
    }

    if ((id > 0) && (node->cluster_layer_id == 0)) {
        node->cluster_layer_id = id;
    }

    if ((uname != NULL) && (node->name == NULL)) {
        update_peer_uname(node, uname);
    }

    if ((xml_id == NULL) && (node->xml_id == NULL)) {
        xml_id = pcmk__cluster_get_xml_id(node);
        if (xml_id == NULL) {
            crm_debug("Cannot obtain an XML ID for node %s[%u] at this time",
                      node->name, id);
        } else {
            crm_info("Node %s[%u] has XML ID %s", node->name, id, xml_id);
        }
    }

    free(uname_lookup);

    return node;
}

/*!
 * \internal
 * \brief Update a node's uname
 *
 * \param[in,out] node   Node object to update
 * \param[in]     uname  New name to set
 *
 * \note This function should not be called within a peer cache iteration,
 *       because in some cases it can remove conflicting cache entries,
 *       which would invalidate the iterator.
 */
static void
update_peer_uname(pcmk__node_status_t *node, const char *uname)
{
    CRM_CHECK(uname != NULL,
              crm_err("Bug: can't update node name without name"); return);
    CRM_CHECK(node != NULL,
              crm_err("Bug: can't update node name to %s without node", uname);
              return);

    if (pcmk__str_eq(uname, node->name, pcmk__str_casei)) {
        crm_debug("Node name '%s' did not change", uname);
        return;
    }

    for (const char *c = uname; *c; ++c) {
        if ((*c >= 'A') && (*c <= 'Z')) {
            crm_warn("Node names with capitals are discouraged, consider changing '%s'",
                     uname);
            break;
        }
    }

    pcmk__str_update(&node->name, uname);

    if (peer_status_callback != NULL) {
        peer_status_callback(pcmk__node_update_name, node, NULL);
    }

#if SUPPORT_COROSYNC
    if ((pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync)
        && !pcmk_is_set(node->flags, pcmk__node_status_remote)) {

        remove_conflicting_peer(node);
    }
#endif
}

/*!
 * \internal
 * \brief Get log-friendly string equivalent of a process flag
 *
 * \param[in] proc  Process flag
 *
 * \return Log-friendly string equivalent of \p proc
 */
static inline const char *
proc2text(enum crm_proc_flag proc)
{
    const char *text = "unknown";

    switch (proc) {
        case crm_proc_none:
            text = "none";
            break;
        case crm_proc_cpg:
            text = "corosync-cpg";
            break;
    }
    return text;
}

/*!
 * \internal
 * \brief Update a node's process information (and potentially state)
 *
 * \param[in]     source  Caller's function name (for log messages)
 * \param[in,out] node    Node object to update
 * \param[in]     flag    Bitmask of new process information
 * \param[in]     status  node status (online, offline, etc.)
 *
 * \return NULL if any node was reaped from peer caches, value of node otherwise
 *
 * \note If this function returns NULL, the supplied node object was likely
 *       freed and should not be used again. This function should not be
 *       called within a cache iteration if reaping is possible, otherwise
 *       reaping could invalidate the iterator.
 */
pcmk__node_status_t *
crm_update_peer_proc(const char *source, pcmk__node_status_t *node,
                     uint32_t flag, const char *status)
{
    uint32_t last = 0;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set %s to %s for NULL",
                                    source, proc2text(flag), status);
                            return NULL);

    /* Pacemaker doesn't spawn processes on remote nodes */
    if (pcmk_is_set(node->flags, pcmk__node_status_remote)) {
        return node;
    }

    last = node->processes;
    if (status == NULL) {
        node->processes = flag;
        if (node->processes != last) {
            changed = TRUE;
        }

    } else if (pcmk__str_eq(status, PCMK_VALUE_ONLINE, pcmk__str_casei)) {
        if ((node->processes & flag) != flag) {
            node->processes = pcmk__set_flags_as(__func__, __LINE__,
                                                 LOG_TRACE, "Peer process",
                                                 node->name, node->processes,
                                                 flag, "processes");
            changed = TRUE;
        }

    } else if (node->processes & flag) {
        node->processes = pcmk__clear_flags_as(__func__, __LINE__,
                                               LOG_TRACE, "Peer process",
                                               node->name, node->processes,
                                               flag, "processes");
        changed = TRUE;
    }

    if (changed) {
        if (status == NULL && flag <= crm_proc_none) {
            crm_info("%s: Node %s[%" PRIu32 "] - all processes are now offline",
                     source, node->name, node->cluster_layer_id);
        } else {
            crm_info("%s: Node %s[%" PRIu32 "] - %s is now %s",
                     source, node->name, node->cluster_layer_id,
                     proc2text(flag), status);
        }

        if (pcmk_is_set(node->processes, crm_get_cluster_proc())) {
            node->when_online = time(NULL);

        } else {
            node->when_online = 0;
        }

        /* Call the client callback first, then update the peer state,
         * in case the node will be reaped
         */
        if (peer_status_callback != NULL) {
            peer_status_callback(pcmk__node_update_processes, node, &last);
        }

        /* The client callback shouldn't touch the peer caches,
         * but as a safety net, bail if the peer cache was destroyed.
         */
        if (pcmk__peer_cache == NULL) {
            return NULL;
        }

        if (autoreap) {
            const char *peer_state = NULL;

            if (pcmk_is_set(node->processes, crm_get_cluster_proc())) {
                peer_state = PCMK_VALUE_MEMBER;
            } else {
                peer_state = PCMK__VALUE_LOST;
            }
            node = pcmk__update_peer_state(__func__, node, peer_state, 0);
        }
    } else {
        crm_trace("%s: Node %s[%" PRIu32 "] - %s is unchanged (%s)",
                  source, node->name, node->cluster_layer_id, proc2text(flag),
                  status);
    }
    return node;
}

/*!
 * \internal
 * \brief Update a cluster node cache entry's expected join state
 *
 * \param[in]     source    Caller's function name (for logging)
 * \param[in,out] node      Node to update
 * \param[in]     expected  Node's new join state
 */
void
pcmk__update_peer_expected(const char *source, pcmk__node_status_t *node,
                           const char *expected)
{
    char *last = NULL;
    gboolean changed = FALSE;

    CRM_CHECK(node != NULL, crm_err("%s: Could not set 'expected' to %s", source, expected);
              return);

    /* Remote nodes don't participate in joins */
    if (pcmk_is_set(node->flags, pcmk__node_status_remote)) {
        return;
    }

    last = node->expected;
    if (expected != NULL && !pcmk__str_eq(node->expected, expected, pcmk__str_casei)) {
        node->expected = strdup(expected);
        changed = TRUE;
    }

    if (changed) {
        crm_info("%s: Node %s[%" PRIu32 "] - expected state is now %s (was %s)",
                 source, node->name, node->cluster_layer_id, expected, last);
        free(last);
    } else {
        crm_trace("%s: Node %s[%" PRIu32 "] - expected state is unchanged (%s)",
                  source, node->name, node->cluster_layer_id, expected);
    }
}

/*!
 * \internal
 * \brief Update a node's state and membership information
 *
 * \param[in]     source      Caller's function name (for log messages)
 * \param[in,out] node        Node object to update
 * \param[in]     state       Node's new state
 * \param[in]     membership  Node's new membership ID
 * \param[in,out] iter        If not NULL, pointer to node's peer cache iterator
 *
 * \return NULL if any node was reaped, value of node otherwise
 *
 * \note If this function returns NULL, the supplied node object was likely
 *       freed and should not be used again. This function may be called from
 *       within a peer cache iteration if the iterator is supplied.
 */
static pcmk__node_status_t *
update_peer_state_iter(const char *source, pcmk__node_status_t *node,
                       const char *state, uint64_t membership,
                       GHashTableIter *iter)
{
    gboolean is_member;

    CRM_CHECK(node != NULL,
              crm_err("Could not set state for unknown host to %s "
                      QB_XS " source=%s", state, source);
              return NULL);

    is_member = pcmk__str_eq(state, PCMK_VALUE_MEMBER, pcmk__str_none);
    if (is_member) {
        node->when_lost = 0;
        if (membership) {
            node->membership_id = membership;
        }
    }

    if (state && !pcmk__str_eq(node->state, state, pcmk__str_casei)) {
        char *last = node->state;

        if (is_member) {
             node->when_member = time(NULL);

        } else {
             node->when_member = 0;
        }

        node->state = strdup(state);
        crm_notice("Node %s state is now %s " QB_XS
                   " nodeid=%" PRIu32 " previous=%s source=%s",
                   node->name, state, node->cluster_layer_id,
                   pcmk__s(last, "unknown"), source);
        if (peer_status_callback != NULL) {
            peer_status_callback(pcmk__node_update_state, node, last);
        }
        free(last);

        if (autoreap && !is_member
            && !pcmk_is_set(node->flags, pcmk__node_status_remote)) {
            /* We only autoreap from the peer cache, not the remote peer cache,
             * because the latter should be managed only by
             * refresh_remote_nodes().
             */
            if(iter) {
                crm_notice("Purged 1 peer with cluster layer ID %" PRIu32
                           "and/or name=%s from the membership cache",
                           node->cluster_layer_id, node->name);
                g_hash_table_iter_remove(iter);

            } else {
                pcmk__cluster_forget_cluster_node(node->cluster_layer_id,
                                                  node->name);
            }
            node = NULL;
        }

    } else {
        crm_trace("Node %s state is unchanged (%s) " QB_XS
                  " nodeid=%" PRIu32 " source=%s",
                  node->name, state, node->cluster_layer_id, source);
    }
    return node;
}

/*!
 * \brief Update a node's state and membership information
 *
 * \param[in]     source      Caller's function name (for log messages)
 * \param[in,out] node        Node object to update
 * \param[in]     state       Node's new state
 * \param[in]     membership  Node's new membership ID
 *
 * \return NULL if any node was reaped, value of node otherwise
 *
 * \note If this function returns NULL, the supplied node object was likely
 *       freed and should not be used again. This function should not be
 *       called within a cache iteration if reaping is possible,
 *       otherwise reaping could invalidate the iterator.
 */
pcmk__node_status_t *
pcmk__update_peer_state(const char *source, pcmk__node_status_t *node,
                        const char *state, uint64_t membership)
{
    return update_peer_state_iter(source, node, state, membership, NULL);
}

/*!
 * \internal
 * \brief Reap all nodes from cache whose membership information does not match
 *
 * \param[in] membership  Membership ID of nodes to keep
 */
void
pcmk__reap_unseen_nodes(uint64_t membership)
{
    GHashTableIter iter;
    pcmk__node_status_t *node = NULL;

    crm_trace("Reaping unseen nodes...");
    g_hash_table_iter_init(&iter, pcmk__peer_cache);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *)&node)) {
        if (node->membership_id != membership) {
            if (node->state) {
                /* Calling update_peer_state_iter() allows us to remove the node
                 * from pcmk__peer_cache without invalidating our iterator
                 */
                update_peer_state_iter(__func__, node, PCMK__VALUE_LOST,
                                       membership, &iter);

            } else {
                crm_info("State of node %s[%" PRIu32 "] is still unknown",
                         node->name, node->cluster_layer_id);
            }
        }
    }
}

static pcmk__node_status_t *
find_cib_cluster_node(const char *id, const char *uname)
{
    GHashTableIter iter;
    pcmk__node_status_t *node = NULL;
    pcmk__node_status_t *by_id = NULL;
    pcmk__node_status_t *by_name = NULL;

    if (uname) {
        g_hash_table_iter_init(&iter, cluster_node_cib_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (pcmk__str_eq(node->name, uname, pcmk__str_casei)) {
                crm_trace("Name match: %s = %p", node->name, node);
                by_name = node;
                break;
            }
        }
    }

    if (id) {
        g_hash_table_iter_init(&iter, cluster_node_cib_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            if (pcmk__str_eq(id, pcmk__cluster_get_xml_id(node),
                             pcmk__str_none)) {
                crm_trace("ID match: %s= %p", id, node);
                by_id = node;
                break;
            }
        }
    }

    node = by_id; /* Good default */
    if (by_id == by_name) {
        /* Nothing to do if they match (both NULL counts) */
        crm_trace("Consistent: %p for %s/%s", by_id, id, uname);

    } else if (by_id == NULL && by_name) {
        crm_trace("Only one: %p for %s/%s", by_name, id, uname);

        if (id) {
            node = NULL;

        } else {
            node = by_name;
        }

    } else if (by_name == NULL && by_id) {
        crm_trace("Only one: %p for %s/%s", by_id, id, uname);

        if (uname) {
            node = NULL;
        }

    } else if ((uname != NULL) && (by_id->name != NULL)
               && pcmk__str_eq(uname, by_id->name, pcmk__str_casei)) {
        /* Multiple nodes have the same uname in the CIB.
         * Return by_id. */

    } else if ((id != NULL) && (by_name->xml_id != NULL)
               && pcmk__str_eq(id, by_name->xml_id, pcmk__str_none)) {
        /* Multiple nodes have the same id in the CIB.
         * Return by_name. */
        node = by_name;

    } else {
        node = NULL;
    }

    if (node == NULL) {
        crm_debug("Couldn't find node%s%s%s%s",
                   id? " " : "",
                   id? id : "",
                   uname? " with name " : "",
                   uname? uname : "");
    }

    return node;
}

static void
cluster_node_cib_cache_refresh_helper(xmlNode *xml_node, void *user_data)
{
    const char *id = pcmk__xe_get(xml_node, PCMK_XA_ID);
    const char *uname = pcmk__xe_get(xml_node, PCMK_XA_UNAME);
    pcmk__node_status_t * node =  NULL;

    CRM_CHECK(id != NULL && uname !=NULL, return);
    node = find_cib_cluster_node(id, uname);

    if (node == NULL) {
        char *uniqueid = crm_generate_uuid();

        node = pcmk__assert_alloc(1, sizeof(pcmk__node_status_t));

        node->name = pcmk__str_copy(uname);
        node->xml_id = pcmk__str_copy(id);

        g_hash_table_replace(cluster_node_cib_cache, uniqueid, node);

    } else if (pcmk_is_set(node->flags, pcmk__node_status_dirty)) {
        pcmk__str_update(&node->name, uname);

        /* Node is in cache and hasn't been updated already, so mark it clean */
        clear_peer_flags(node, pcmk__node_status_dirty);
    }

}

static void
refresh_cluster_node_cib_cache(xmlNode *cib)
{
    pcmk__cluster_init_node_caches();

    g_hash_table_foreach(cluster_node_cib_cache, mark_dirty, NULL);

    pcmk__xpath_foreach_result(cib->doc, PCMK__XP_MEMBER_NODE_CONFIG,
                               cluster_node_cib_cache_refresh_helper, NULL);

    // Remove all old cache entries that weren't seen in the CIB
    g_hash_table_foreach_remove(cluster_node_cib_cache, is_dirty, NULL);
}

void
pcmk__refresh_node_caches_from_cib(xmlNode *cib)
{
    refresh_remote_nodes(cib);
    refresh_cluster_node_cib_cache(cib);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/cluster/compat.h>

void
crm_peer_init(void)
{
    pcmk__cluster_init_node_caches();
}

// LCOV_EXCL_STOP
// End deprecated API

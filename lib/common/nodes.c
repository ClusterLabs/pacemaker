/*
 * Copyright 2022-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <libxml/tree.h>        // xmlNode
#include <crm/common/nvpair.h>

/*!
 * \internal
 * \brief Free a node object
 *
 * \param[in,out] user_data  Node object to free
 */
void
pcmk__free_node(gpointer user_data)
{
    pcmk_node_t *node = user_data;

    if (node == NULL) {
        return;
    }
    if (node->details == NULL) {
        free(node);
        return;
    }

    /* This may be called after freeing resources, which means that we can't
     * use node->private->name for Pacemaker Remote nodes.
     */
    crm_trace("Freeing node %s", (pcmk__is_pacemaker_remote_node(node)?
              "(guest or remote)" : pcmk__node_name(node)));

    if (node->priv->attrs != NULL) {
        g_hash_table_destroy(node->priv->attrs);
    }
    if (node->priv->utilization != NULL) {
        g_hash_table_destroy(node->priv->utilization);
    }
    if (node->priv->digest_cache != NULL) {
        g_hash_table_destroy(node->priv->digest_cache);
    }
    g_list_free(node->details->running_rsc);
    g_list_free(node->priv->assigned_resources);
    free(node->priv);
    free(node->details);
    free(node->assign);
    free(node);
}

/*!
 * \internal
 * \brief Free a copy of a node object
 *
 * \param[in] data  Node copy (created by pe__copy_node()) to free
 */
void
pcmk__free_node_copy(void *data)
{
    if (data != NULL) {
        pcmk_node_t *node = data;

        if (node->assign != NULL) {
            // This is the only member allocated separately for a node copy
            free(node->assign);
        }
        free(node);
    }
}

/*!
 * \internal
 * \brief Check whether a node is online
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is online, otherwise false
 */
bool
pcmk_node_is_online(const pcmk_node_t *node)
{
    return (node != NULL) && node->details->online;
}

/*!
 * \internal
 * \brief Check whether a node is pending
 *
 * Check whether a node is pending. A node is pending if it is a member of the
 * cluster but not the controller group, which means it is in the process of
 * either joining or leaving the cluster.
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is pending, otherwise false
 */
bool
pcmk_node_is_pending(const pcmk_node_t *node)
{
    return (node != NULL) && node->details->pending;
}

/*!
 * \internal
 * \brief Check whether a node is clean
 *
 * Check whether a node is clean. A node is clean if it is a cluster node or
 * remote node that has been seen by the cluster at least once, or the
 * startup-fencing cluster option is false; and the node, and its host if a
 * guest or bundle node, are not scheduled to be fenced.
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is clean, otherwise false
 */
bool
pcmk_node_is_clean(const pcmk_node_t *node)
{
    return (node != NULL) && !(node->details->unclean);
}

/*!
 * \internal
 * \brief Check whether a node is shutting down
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is shutting down, otherwise false
 */
bool
pcmk_node_is_shutting_down(const pcmk_node_t *node)
{
    return (node != NULL) && node->details->shutdown;
}

/*!
 * \internal
 * \brief Check whether a node is in maintenance mode
 *
 * \param[in] node  Node to check
 *
 * \return true if \p node is in maintenance mode, otherwise false
 */
bool
pcmk_node_is_in_maintenance(const pcmk_node_t *node)
{
    return (node != NULL) && node->details->maintenance;
}

/*!
 * \internal
 * \brief Call a function for each resource active on a node
 *
 * Call a caller-supplied function with a caller-supplied argument for each
 * resource that is active on a given node. If the function returns false, this
 * function will return immediately without processing any remaining resources.
 *
 * \param[in] node  Node to check
 *
 * \return Result of last call of \p fn (or false if none)
 */
bool
pcmk_foreach_active_resource(pcmk_node_t *node,
                             bool (*fn)(pcmk_resource_t *, void *),
                             void *user_data)
{
    bool result = false;

    if ((node != NULL) && (fn != NULL)) {
        for (GList *item = node->details->running_rsc; item != NULL;
             item = item->next) {

            result = fn((pcmk_resource_t *) item->data, user_data);
            if (!result) {
                break;
            }
        }
    }
    return result;
}

/*!
 * \internal
 * \brief Find a node by name in a list of nodes
 *
 * \param[in] nodes      List of nodes (as pcmk_node_t*)
 * \param[in] node_name  Name of node to find
 *
 * \return Node from \p nodes that matches \p node_name if any, otherwise NULL
 */
pcmk_node_t *
pcmk__find_node_in_list(const GList *nodes, const char *node_name)
{
    if (node_name != NULL) {
        for (const GList *iter = nodes; iter != NULL; iter = iter->next) {
            pcmk_node_t *node = (pcmk_node_t *) iter->data;

            if (pcmk__str_eq(node->priv->name, node_name, pcmk__str_casei)) {
                return node;
            }
        }
    }
    return NULL;
}

#define XP_SHUTDOWN "//" PCMK__XE_NODE_STATE "[@" PCMK_XA_UNAME "='%s']/"   \
    PCMK__XE_TRANSIENT_ATTRIBUTES "/" PCMK_XE_INSTANCE_ATTRIBUTES "/"       \
    PCMK_XE_NVPAIR "[@" PCMK_XA_NAME "='" PCMK__NODE_ATTR_SHUTDOWN "']"

/*!
 * \brief Get value of a node's shutdown attribute from CIB, if present
 *
 * \param[in] cib   CIB to check
 * \param[in] node  Name of node to check
 *
 * \return Value of shutdown attribute for \p node in \p cib if any,
 *         otherwise NULL
 * \note The return value is a pointer into \p cib and so is valid only for the
 *       lifetime of that object.
 */
const char *
pcmk_cib_node_shutdown(xmlNode *cib, const char *node)
{
    if ((cib != NULL) && (node != NULL)) {
        char *xpath = crm_strdup_printf(XP_SHUTDOWN, node);
        xmlNode *match = pcmk__xpath_find_one(cib->doc, xpath, LOG_TRACE);

        free(xpath);
        if (match != NULL) {
            return pcmk__xe_get(match, PCMK_XA_VALUE);
        }
    }
    return NULL;
}

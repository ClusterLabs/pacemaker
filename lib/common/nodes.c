/*
 * Copyright 2022-2024 the Pacemaker project contributors
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

void
pcmk__xe_add_node(xmlNode *xml, const char *node, int nodeid)
{
    CRM_ASSERT(xml != NULL);

    if (node != NULL) {
        crm_xml_add(xml, PCMK__XA_ATTR_HOST, node);
    }

    if (nodeid > 0) {
        crm_xml_add_int(xml, PCMK__XA_ATTR_HOST_ID, nodeid);
    }
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

            if (pcmk__str_eq(node->details->uname, node_name,
                             pcmk__str_casei)) {
                return node;
            }
        }
    }
    return NULL;
}

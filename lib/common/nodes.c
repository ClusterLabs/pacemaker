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

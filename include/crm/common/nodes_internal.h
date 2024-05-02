/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__NODES_INTERNAL__H
#define PCMK__NODES_INTERNAL__H

/*
 * Special node attributes
 */

#define PCMK__NODE_ATTR_SHUTDOWN            "shutdown"

/* @COMPAT Deprecated since 2.1.8. Use a location constraint with
 * PCMK_XA_RSC_PATTERN=".*" and PCMK_XA_RESOURCE_DISCOVERY="never" instead of
 * PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED="false".
 */
#define PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED  "resource-discovery-enabled"

pcmk_node_t *pcmk__find_node_in_list(const GList *nodes, const char *node_name);

/*!
 * \internal
 * \brief Return a string suitable for logging as a node name
 *
 * \param[in] node  Node to return a node name string for
 *
 * \return Node name if available, otherwise node ID if available,
 *         otherwise "unspecified node" if node is NULL or "unidentified node"
 *         if node has neither a name nor ID.
 */
static inline const char *
pcmk__node_name(const pcmk_node_t *node)
{
    if (node == NULL) {
        return "unspecified node";

    } else if (node->details->uname != NULL) {
        return node->details->uname;

    } else if (node->details->id != NULL) {
        return node->details->id;

    } else {
        return "unidentified node";
    }
}

/*!
 * \internal
 * \brief Check whether two node objects refer to the same node
 *
 * \param[in] node1  First node object to compare
 * \param[in] node2  Second node object to compare
 *
 * \return true if \p node1 and \p node2 refer to the same node
 */
static inline bool
pcmk__same_node(const pcmk_node_t *node1, const pcmk_node_t *node2)
{
    return (node1 != NULL) && (node2 != NULL)
           && (node1->details == node2->details);
}

#endif  // PCMK__NODES_INTERNAL__H

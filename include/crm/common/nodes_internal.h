/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NODES_INTERNAL__H
#define PCMK__CRM_COMMON_NODES_INTERNAL__H

#include <stdio.h>      // NULL
#include <stdbool.h>    // bool
#include <stdint.h>     // uint32_t, UINT32_C()

#include <glib.h>
#include <crm/common/nodes.h>

/*
 * Special node attributes
 */

#define PCMK__NODE_ATTR_SHUTDOWN            "shutdown"

/* @COMPAT Deprecated since 2.1.8. Use a location constraint with
 * PCMK_XA_RSC_PATTERN=".*" and PCMK_XA_RESOURCE_DISCOVERY="never" instead of
 * PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED="false".
 */
#define PCMK__NODE_ATTR_RESOURCE_DISCOVERY_ENABLED  "resource-discovery-enabled"

enum pcmk__node_variant { // Possible node types
    pcmk__node_variant_ping     = 0,    // deprecated
    pcmk__node_variant_cluster  = 1,    // Cluster layer node
    pcmk__node_variant_remote   = 2,    // Pacemaker Remote node
};

enum pcmk__node_flags {
    pcmk__node_none             = UINT32_C(0),

    // Whether node is in standby mode
    pcmk__node_standby          = (UINT32_C(1) << 0),

    // Whether node is in standby mode due to PCMK_META_ON_FAIL
    pcmk__node_fail_standby     = (UINT32_C(1) << 1),

    // Whether node has ever joined cluster (and thus has node state in CIB)
    pcmk__node_seen             = (UINT32_C(1) << 2),

    // Whether expected join state is member
    pcmk__node_expected_up      = (UINT32_C(1) << 3),

    // Whether probes are allowed on node
    pcmk__node_probes_allowed   = (UINT32_C(1) << 4),

    /* Whether this either is a guest node whose guest resource must be
     * recovered or a remote node that must be fenced
     */
    pcmk__node_remote_reset     = (UINT32_C(1) << 5),

    /* Whether this is a Pacemaker Remote node that was fenced since it was last
     * connected by the cluster
     */
    pcmk__node_remote_fenced    = (UINT32_C(1) << 6),

    /*
     * Whether this is a Pacemaker Remote node previously marked in its
     * node state as being in maintenance mode
     */
    pcmk__node_remote_maint     = (UINT32_C(1) << 7),

    // Whether node history has been unpacked
    pcmk__node_unpacked         = (UINT32_C(1) << 8),
};

/* Implementation of pcmk__node_private_t (pcmk_node_t objects are shallow
 * copies, so all pcmk_node_t objects for the same node will share the same
 * private data)
 */
typedef struct pcmk__node_private {
    /* Node's XML ID in the CIB (the cluster layer ID for cluster nodes,
     * the node name for Pacemaker Remote nodes)
     */
    const char *id;

    const char *name;                   // Node name in cluster
    enum pcmk__node_variant variant;    // Node variant
    uint32_t flags;                     // Group of enum pcmk__node_flags
    int num_resources;                  // Number of active resources on node
    GList *assigned_resources;          // List of resources assigned to node
    pcmk_resource_t *remote;            // Pacemaker Remote connection (if any)
} pcmk__node_private_t;

pcmk_node_t *pcmk__find_node_in_list(const GList *nodes, const char *node_name);

/*!
 * \internal
 * \brief Set node flags
 *
 * \param[in,out] node          Node to set flags for
 * \param[in]     flags_to_set  Group of enum pcmk_node_flags to set
 */
#define pcmk__set_node_flags(node, flags_to_set) do {                   \
        (node)->private->flags = pcmk__set_flags_as(__func__, __LINE__, \
            LOG_TRACE, "Node", pcmk__node_name(node),                   \
            (node)->private->flags, (flags_to_set), #flags_to_set);     \
    } while (0)

/*!
 * \internal
 * \brief Clear node flags
 *
 * \param[in,out] node            Node to clear flags for
 * \param[in]     flags_to_clear  Group of enum pcmk_node_flags to clear
 */
#define pcmk__clear_node_flags(node, flags_to_clear) do {                   \
        (node)->private->flags = pcmk__clear_flags_as(__func__, __LINE__,   \
            LOG_TRACE, "Node", pcmk__node_name(node),                       \
            (node)->private->flags, (flags_to_clear), #flags_to_clear);     \
    } while (0)

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

    } else if (node->private->name != NULL) {
        return node->private->name;

    } else if (node->private->id != NULL) {
        return node->private->id;

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
           && (node1->private == node2->private);
}

#endif  // PCMK__CRM_COMMON_NODES_INTERNAL__H

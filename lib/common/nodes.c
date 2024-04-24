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

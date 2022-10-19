/*
 * Copyright 2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/nvpair.h>

void
pcmk__xe_add_node(xmlNode *xml, const char *node, int nodeid)
{
    if (node != NULL) {
        crm_xml_add(xml, PCMK__XA_ATTR_NODE_NAME, node);
    }

    if (nodeid > 0) {
        crm_xml_add_int(xml, PCMK__XA_ATTR_NODE_ID, nodeid);
    }
}

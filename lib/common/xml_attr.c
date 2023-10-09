/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <bzlib.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlIO.h>  /* xmlAllocOutputBuffer */

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  // PCMK__XML_LOG_BASE, etc.
#include "crmcommon_private.h"

void
pcmk__mark_xml_attr_dirty(xmlAttr *a) 
{
    xmlNode *parent = a->parent;
    xml_node_private_t *nodepriv = a->_private;

    pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_modified);
    pcmk__clear_xml_flags(nodepriv, pcmk__xf_deleted);
    pcmk__mark_xml_node_dirty(parent);
}

// This also clears attribute's flags if not marked as deleted
bool
pcmk__marked_as_deleted(xmlAttrPtr a, void *user_data)
{
    xml_node_private_t *nodepriv = a->_private;

    if (pcmk_is_set(nodepriv->flags, pcmk__xf_deleted)) {
        return true;
    }
    nodepriv->flags = pcmk__xf_none;
    return false;
}

/*!
 * \internal
 * \brief Append an XML attribute to a buffer
 *
 * \param[in]     attr     Attribute to append
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 */
void
pcmk__dump_xml_attr(const xmlAttr *attr, GString *buffer)
{
    char *p_value = NULL;
    const char *p_name = NULL;
    xml_node_private_t *nodepriv = NULL;

    if (attr == NULL || attr->children == NULL) {
        return;
    }

    nodepriv = attr->_private;
    if (nodepriv && pcmk_is_set(nodepriv->flags, pcmk__xf_deleted)) {
        return;
    }

    p_name = (const char *) attr->name;
    p_value = crm_xml_escape((const char *)attr->children->content);
    pcmk__g_strcat(buffer, " ", p_name, "=\"", pcmk__s(p_value, "<null>"), "\"",
                   NULL);

    free(p_value);
}
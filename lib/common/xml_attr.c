/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
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
#include <crm/common/xml.h>
#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Remove an XML attribute from its parent and free it
 *
 * \param[in,out] attr   XML attribute to remove
 * \param[in]     force  If \c true, remove the attribute immediately, ignoring
 *                       ACLs and change tracking
 *
 * \return Standard Pacemaker return code (\c EPERM if ACLs prevent removal, or
 *         or \c pcmk_rc_ok otherwise)
 *
 * \note If the attribute has no parent element, this function does not free it.
 *       This mimics \c xmlRemoveProp().
 */
int
pcmk__xa_remove(xmlAttr *attr, bool force)
{
    xmlNode *element = NULL;

    if ((attr == NULL) || (attr->parent == NULL)) {
        return pcmk_rc_ok;
    }

    if (force) {
        goto remove;
    }

    element = attr->parent;

    if (!pcmk__check_acl(element, NULL, pcmk__xf_acl_write)) {
        // ACLs apply to element, not to particular attributes
        pcmk__trace("ACLs prevent removal of attributes from %s element",
                    element->name);
        return EPERM;
    }

    if (pcmk__xml_doc_all_flags_set(element->doc, pcmk__xf_tracking)) {
        // Leave in place (marked for removal) until after diff is calculated
        pcmk__xml_set_parent_flags(element, pcmk__xf_dirty);
        pcmk__set_xml_flags((xml_node_private_t *) attr->_private,
                            pcmk__xf_deleted);
        return pcmk_rc_ok;
    }

remove:
    pcmk__xml_free_private_data((xmlNode *) attr);
    xmlRemoveProp(attr);
    return pcmk_rc_ok;
}

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

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_deleted)) {
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
    const char *name = NULL;
    const char *value = NULL;
    gchar *value_esc = NULL;
    xml_node_private_t *nodepriv = NULL;

    if (attr == NULL || attr->children == NULL) {
        return;
    }

    nodepriv = attr->_private;
    if ((nodepriv != NULL) && pcmk__is_set(nodepriv->flags, pcmk__xf_deleted)) {
        return;
    }

    name = (const char *) attr->name;
    value = (const char *) attr->children->content;
    if (value == NULL) {
        /* Don't print anything for unset attribute. Any null-indicator value,
         * including the empty string, could also be a real value that needs to
         * be treated differently from "unset".
         */
        return;
    }

    if (pcmk__xml_needs_escape(value, pcmk__xml_escape_attr)) {
        value_esc = pcmk__xml_escape(value, pcmk__xml_escape_attr);
        value = value_esc;
    }

    pcmk__g_strcat(buffer, " ", name, "=\"", value, "\"", NULL);
    g_free(value_esc);
}

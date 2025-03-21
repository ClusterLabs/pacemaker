/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stdint.h>                     // uint32_t
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>                   // stat(), S_ISREG, etc.
#include <sys/types.h>

#include <glib.h>                       // gboolean, GString
#include <libxml/parser.h>              // xmlCleanupParser()
#include <libxml/tree.h>                // xmlNode, etc.
#include <libxml/xmlstring.h>           // xmlChar, xmlGetUTF8Char()

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>    // PCMK__XML_LOG_BASE, etc.
#include "crmcommon_private.h"

//! libxml2 supports only XML version 1.0, at least as of libxml2-2.12.5
#define XML_VERSION ((const xmlChar *) "1.0")

/*!
 * \internal
 * \brief Get a string representation of an XML element type for logging
 *
 * \param[in] type  XML element type
 *
 * \return String representation of \p type
 */
const char *
pcmk__xml_element_type_text(xmlElementType type)
{
    static const char *const element_type_names[] = {
        [XML_ELEMENT_NODE]       = "element",
        [XML_ATTRIBUTE_NODE]     = "attribute",
        [XML_TEXT_NODE]          = "text",
        [XML_CDATA_SECTION_NODE] = "CDATA section",
        [XML_ENTITY_REF_NODE]    = "entity reference",
        [XML_ENTITY_NODE]        = "entity",
        [XML_PI_NODE]            = "PI",
        [XML_COMMENT_NODE]       = "comment",
        [XML_DOCUMENT_NODE]      = "document",
        [XML_DOCUMENT_TYPE_NODE] = "document type",
        [XML_DOCUMENT_FRAG_NODE] = "document fragment",
        [XML_NOTATION_NODE]      = "notation",
        [XML_HTML_DOCUMENT_NODE] = "HTML document",
        [XML_DTD_NODE]           = "DTD",
        [XML_ELEMENT_DECL]       = "element declaration",
        [XML_ATTRIBUTE_DECL]     = "attribute declaration",
        [XML_ENTITY_DECL]        = "entity declaration",
        [XML_NAMESPACE_DECL]     = "namespace declaration",
        [XML_XINCLUDE_START]     = "XInclude start",
        [XML_XINCLUDE_END]       = "XInclude end",
    };

    // Assumes the numeric values of the indices are in ascending order
    if ((type < XML_ELEMENT_NODE) || (type > XML_XINCLUDE_END)) {
        return "unrecognized type";
    }
    return element_type_names[type];
}

/*!
 * \internal
 * \brief Apply a function to each XML node in a tree (pre-order, depth-first)
 *
 * \param[in,out] xml        XML tree to traverse
 * \param[in,out] fn         Function to call for each node (returns \c true to
 *                           continue traversing the tree or \c false to stop)
 * \param[in,out] user_data  Argument to \p fn
 *
 * \return \c false if any \p fn call returned \c false, or \c true otherwise
 *
 * \note This function is recursive.
 */
bool
pcmk__xml_tree_foreach(xmlNode *xml, bool (*fn)(xmlNode *, void *),
                       void *user_data)
{
    if (xml == NULL) {
        return true;
    }

    if (!fn(xml, user_data)) {
        return false;
    }

    for (xml = pcmk__xml_first_child(xml); xml != NULL;
         xml = pcmk__xml_next(xml)) {

        if (!pcmk__xml_tree_foreach(xml, fn, user_data)) {
            return false;
        }
    }
    return true;
}

void
pcmk__xml_set_parent_flags(xmlNode *xml, uint64_t flags)
{
    for (; xml != NULL; xml = xml->parent) {
        xml_node_private_t *nodepriv = xml->_private;

        if (nodepriv != NULL) {
            pcmk__set_xml_flags(nodepriv, flags);
        }
    }
}

/*!
 * \internal
 * \brief Set flags for an XML document
 *
 * \param[in,out] doc    XML document
 * \param[in]     flags  Group of <tt>enum pcmk__xml_flags</tt>
 */
void
pcmk__xml_doc_set_flags(xmlDoc *doc, uint32_t flags)
{
    if (doc != NULL) {
        xml_doc_private_t *docpriv = doc->_private;

        pcmk__set_xml_flags(docpriv, flags);
    }
}

/*!
 * \internal
 * \brief Check whether the given flags are set for an XML document
 *
 * \param[in] doc    XML document to check
 * \param[in] flags  Group of <tt>enum pcmk__xml_flags</tt>
 *
 * \return \c true if all of \p flags are set for \p doc, or \c false otherwise
 */
bool
pcmk__xml_doc_all_flags_set(const xmlDoc *doc, uint32_t flags)
{
    if (doc != NULL) {
        xml_doc_private_t *docpriv = doc->_private;

        return (docpriv != NULL) && pcmk_all_flags_set(docpriv->flags, flags);
    }
    return false;
}

// Mark document, element, and all element's parents as changed
void
pcmk__mark_xml_node_dirty(xmlNode *xml)
{
    if (xml == NULL) {
        return;
    }
    pcmk__xml_doc_set_flags(xml->doc, pcmk__xf_dirty);
    pcmk__xml_set_parent_flags(xml, pcmk__xf_dirty);
}

/*!
 * \internal
 * \brief Clear flags on an XML node
 *
 * \param[in,out] xml        XML node whose flags to reset
 * \param[in,out] user_data  Ignored
 *
 * \return \c true (to continue traversing the tree)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
bool
pcmk__xml_reset_node_flags(xmlNode *xml, void *user_data)
{
    xml_node_private_t *nodepriv = xml->_private;

    if (nodepriv != NULL) {
        nodepriv->flags = pcmk__xf_none;
    }
    return true;
}

/*!
 * \internal
 * \brief Set the \c pcmk__xf_dirty and \c pcmk__xf_created flags on an XML node
 *
 * \param[in,out] xml        Node whose flags to set
 * \param[in]     user_data  Ignored
 *
 * \return \c true (to continue traversing the tree)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
mark_xml_dirty_created(xmlNode *xml, void *user_data)
{
    xml_node_private_t *nodepriv = xml->_private;

    if (nodepriv != NULL) {
        pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_created);
    }
    return true;
}

/*!
 * \internal
 * \brief Mark an XML tree as dirty and created, and mark its parents dirty
 *
 * Also mark the document dirty.
 *
 * \param[in,out] xml  Tree to mark as dirty and created
 */
static void
mark_xml_tree_dirty_created(xmlNode *xml)
{
    pcmk__assert(xml != NULL);

    if (!pcmk__xml_doc_all_flags_set(xml->doc, pcmk__xf_tracking)) {
        // Tracking is disabled for entire document
        return;
    }

    // Mark all parents and document dirty
    pcmk__mark_xml_node_dirty(xml);

    pcmk__xml_tree_foreach(xml, mark_xml_dirty_created, NULL);
}

// Free an XML object previously marked as deleted
static void
free_deleted_object(void *data)
{
    if(data) {
        pcmk__deleted_xml_t *deleted_obj = data;

        g_free(deleted_obj->path);
        free(deleted_obj);
    }
}

// Free and NULL user, ACLs, and deleted objects in an XML node's private data
static void
reset_xml_private_data(xml_doc_private_t *docpriv)
{
    if (docpriv != NULL) {
        pcmk__assert(docpriv->check == PCMK__XML_DOC_PRIVATE_MAGIC);

        pcmk__str_update(&(docpriv->acl_user), NULL);

        if (docpriv->acls != NULL) {
            pcmk__free_acls(docpriv->acls);
            docpriv->acls = NULL;
        }

        if(docpriv->deleted_objs) {
            g_list_free_full(docpriv->deleted_objs, free_deleted_object);
            docpriv->deleted_objs = NULL;
        }
    }
}

/*!
 * \internal
 * \brief Allocate and initialize private data for an XML node
 *
 * \param[in,out] node       XML node whose private data to initialize
 * \param[in]     user_data  Ignored
 *
 * \return \c true (to continue traversing the tree)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
new_private_data(xmlNode *node, void *user_data)
{
    bool tracking = false;

    CRM_CHECK(node != NULL, return true);

    if (node->_private != NULL) {
        return true;
    }

    tracking = pcmk__xml_doc_all_flags_set(node->doc, pcmk__xf_tracking);

    switch (node->type) {
        case XML_DOCUMENT_NODE:
            {
                xml_doc_private_t *docpriv =
                    pcmk__assert_alloc(1, sizeof(xml_doc_private_t));

                docpriv->check = PCMK__XML_DOC_PRIVATE_MAGIC;
                node->_private = docpriv;
            }
            break;

        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
        case XML_COMMENT_NODE:
            {
                xml_node_private_t *nodepriv =
                    pcmk__assert_alloc(1, sizeof(xml_node_private_t));

                nodepriv->check = PCMK__XML_NODE_PRIVATE_MAGIC;
                node->_private = nodepriv;
                if (tracking) {
                    pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_created);
                }

                for (xmlAttr *iter = pcmk__xe_first_attr(node); iter != NULL;
                     iter = iter->next) {

                    new_private_data((xmlNode *) iter, user_data);
                }
            }
            break;

        case XML_TEXT_NODE:
        case XML_DTD_NODE:
        case XML_CDATA_SECTION_NODE:
            return true;

        default:
            CRM_LOG_ASSERT(node->type == XML_ELEMENT_NODE);
            return true;
    }

    if (tracking) {
        pcmk__mark_xml_node_dirty(node);
    }
    return true;
}

/*!
 * \internal
 * \brief Free private data for an XML node
 *
 * \param[in,out] node       XML node whose private data to free
 * \param[in]     user_data  Ignored
 *
 * \return \c true (to continue traversing the tree)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
free_private_data(xmlNode *node, void *user_data)
{
    CRM_CHECK(node != NULL, return true);

    if (node->_private == NULL) {
        return true;
    }

    if (node->type == XML_DOCUMENT_NODE) {
        reset_xml_private_data((xml_doc_private_t *) node->_private);

    } else {
        xml_node_private_t *nodepriv = node->_private;

        pcmk__assert(nodepriv->check == PCMK__XML_NODE_PRIVATE_MAGIC);

        for (xmlAttr *iter = pcmk__xe_first_attr(node); iter != NULL;
             iter = iter->next) {

            free_private_data((xmlNode *) iter, user_data);
        }
    }
    free(node->_private);
    node->_private = NULL;
    return true;
}

/*!
 * \internal
 * \brief Allocate and initialize private data recursively for an XML tree
 *
 * \param[in,out] node  XML node whose private data to initialize
 */
void
pcmk__xml_new_private_data(xmlNode *xml)
{
    pcmk__xml_tree_foreach(xml, new_private_data, NULL);
}

/*!
 * \internal
 * \brief Free private data recursively for an XML tree
 *
 * \param[in,out] node  XML node whose private data to free
 */
void
pcmk__xml_free_private_data(xmlNode *xml)
{
    pcmk__xml_tree_foreach(xml, free_private_data, NULL);
}

/*!
 * \internal
 * \brief Return ordinal position of an XML node among its siblings
 *
 * \param[in] xml            XML node to check
 * \param[in] ignore_if_set  Don't count siblings with this flag set
 *
 * \return Ordinal position of \p xml (starting with 0)
 */
int
pcmk__xml_position(const xmlNode *xml, enum pcmk__xml_flags ignore_if_set)
{
    int position = 0;

    for (const xmlNode *cIter = xml; cIter->prev; cIter = cIter->prev) {
        xml_node_private_t *nodepriv = ((xmlNode*)cIter->prev)->_private;

        if (!pcmk_is_set(nodepriv->flags, ignore_if_set)) {
            position++;
        }
    }

    return position;
}

/*!
 * \internal
 * \brief Remove all attributes marked as deleted from an XML node
 *
 * \param[in,out] xml        XML node whose deleted attributes to remove
 * \param[in,out] user_data  Ignored
 *
 * \return \c true (to continue traversing the tree)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
commit_attr_deletions(xmlNode *xml, void *user_data)
{
    pcmk__xml_reset_node_flags(xml, NULL);
    pcmk__xe_remove_matching_attrs(xml, true, pcmk__marked_as_deleted, NULL);
    return true;
}

/*!
 * \internal
 * \brief Finalize all pending changes to an XML document and reset private data
 *
 * Clear the ACL user and all flags, unpacked ACLs, and deleted node records for
 * the document; clear all flags on each node in the tree; and delete any
 * attributes that are marked for deletion.
 *
 * \param[in,out] doc  XML document
 *
 * \note When change tracking is enabled, "deleting" an attribute simply marks
 *       it for deletion (using \c pcmk__xf_deleted) until changes are
 *       committed. Freeing a node (using \c pcmk__xml_free()) adds a deleted
 *       node record (\c pcmk__deleted_xml_t) to the node's document before
 *       freeing it.
 * \note This function clears all flags, not just flags that indicate changes.
 *       In particular, note that it clears the \c pcmk__xf_tracking flag, thus
 *       disabling tracking.
 */
void
pcmk__xml_commit_changes(xmlDoc *doc)
{
    xml_doc_private_t *docpriv = NULL;

    if (doc == NULL) {
        return;
    }

    docpriv = doc->_private;
    if (docpriv == NULL) {
        return;
    }

    if (pcmk_is_set(docpriv->flags, pcmk__xf_dirty)) {
        pcmk__xml_tree_foreach(xmlDocGetRootElement(doc), commit_attr_deletions,
                               NULL);
    }
    reset_xml_private_data(docpriv);
    docpriv->flags = pcmk__xf_none;
}

/*!
 * \internal
 * \brief Create a new XML document
 *
 * \return Newly allocated XML document (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free_doc().
 */
xmlDoc *
pcmk__xml_new_doc(void)
{
    xmlDoc *doc = xmlNewDoc(XML_VERSION);

    pcmk__mem_assert(doc);
    pcmk__xml_new_private_data((xmlNode *) doc);
    return doc;
}

/*!
 * \internal
 * \brief Free a new XML document
 *
 * \param[in,out] doc  XML document to free
 */
void
pcmk__xml_free_doc(xmlDoc *doc)
{
    if (doc != NULL) {
        pcmk__xml_free_private_data((xmlNode *) doc);
        xmlFreeDoc(doc);
    }
}

/*!
 * \internal
 * \brief Check whether the first character of a string is an XML NameStartChar
 *
 * See https://www.w3.org/TR/xml/#NT-NameStartChar.
 *
 * This is almost identical to libxml2's \c xmlIsDocNameStartChar(), but they
 * don't expose it as part of the public API.
 *
 * \param[in]  utf8  UTF-8 encoded string
 * \param[out] len   If not \c NULL, where to store size in bytes of first
 *                   character in \p utf8
 *
 * \return \c true if \p utf8 begins with a valid XML NameStartChar, or \c false
 *         otherwise
 */
bool
pcmk__xml_is_name_start_char(const char *utf8, int *len)
{
    int c = 0;
    int local_len = 0;

    if (len == NULL) {
        len = &local_len;
    }

    /* xmlGetUTF8Char() abuses the len argument. At call time, it must be set to
     * "the minimum number of bytes present in the sequence... to assure the
     * next character is completely contained within the sequence." It's similar
     * to the "n" in the strn*() functions. However, this doesn't make any sense
     * for null-terminated strings, and there's no value that indicates "keep
     * going until '\0'." So we set it to 4, the max number of bytes in a UTF-8
     * character.
     *
     * At return, it's set to the actual number of bytes in the char, or 0 on
     * error.
     */
    *len = 4;

    // Note: xmlGetUTF8Char() assumes a 32-bit int
    c = xmlGetUTF8Char((const xmlChar *) utf8, len);
    if (c < 0) {
        GString *buf = g_string_sized_new(32);

        for (int i = 0; (i < 4) && (utf8[i] != '\0'); i++) {
            g_string_append_printf(buf, " 0x%.2X", utf8[i]);
        }
        crm_info("Invalid UTF-8 character (bytes:%s)",
                 (pcmk__str_empty(buf->str)? " <none>" : buf->str));
        g_string_free(buf, TRUE);
        return false;
    }

    return (c == '_')
           || (c == ':')
           || ((c >= 'a') && (c <= 'z'))
           || ((c >= 'A') && (c <= 'Z'))
           || ((c >= 0xC0) && (c <= 0xD6))
           || ((c >= 0xD8) && (c <= 0xF6))
           || ((c >= 0xF8) && (c <= 0x2FF))
           || ((c >= 0x370) && (c <= 0x37D))
           || ((c >= 0x37F) && (c <= 0x1FFF))
           || ((c >= 0x200C) && (c <= 0x200D))
           || ((c >= 0x2070) && (c <= 0x218F))
           || ((c >= 0x2C00) && (c <= 0x2FEF))
           || ((c >= 0x3001) && (c <= 0xD7FF))
           || ((c >= 0xF900) && (c <= 0xFDCF))
           || ((c >= 0xFDF0) && (c <= 0xFFFD))
           || ((c >= 0x10000) && (c <= 0xEFFFF));
}

/*!
 * \internal
 * \brief Check whether the first character of a string is an XML NameChar
 *
 * See https://www.w3.org/TR/xml/#NT-NameChar.
 *
 * This is almost identical to libxml2's \c xmlIsDocNameChar(), but they don't
 * expose it as part of the public API.
 *
 * \param[in]  utf8  UTF-8 encoded string
 * \param[out] len   If not \c NULL, where to store size in bytes of first
 *                   character in \p utf8
 *
 * \return \c true if \p utf8 begins with a valid XML NameChar, or \c false
 *         otherwise
 */
bool
pcmk__xml_is_name_char(const char *utf8, int *len)
{
    int c = 0;
    int local_len = 0;

    if (len == NULL) {
        len = &local_len;
    }

    // See comment regarding len in pcmk__xml_is_name_start_char()
    *len = 4;

    // Note: xmlGetUTF8Char() assumes a 32-bit int
    c = xmlGetUTF8Char((const xmlChar *) utf8, len);
    if (c < 0) {
        GString *buf = g_string_sized_new(32);

        for (int i = 0; (i < 4) && (utf8[i] != '\0'); i++) {
            g_string_append_printf(buf, " 0x%.2X", utf8[i]);
        }
        crm_info("Invalid UTF-8 character (bytes:%s)",
                 (pcmk__str_empty(buf->str)? " <none>" : buf->str));
        g_string_free(buf, TRUE);
        return false;
    }

    return ((c >= 'a') && (c <= 'z'))
           || ((c >= 'A') && (c <= 'Z'))
           || ((c >= '0') && (c <= '9'))
           || (c == '_')
           || (c == ':')
           || (c == '-')
           || (c == '.')
           || (c == 0xB7)
           || ((c >= 0xC0) && (c <= 0xD6))
           || ((c >= 0xD8) && (c <= 0xF6))
           || ((c >= 0xF8) && (c <= 0x2FF))
           || ((c >= 0x300) && (c <= 0x36F))
           || ((c >= 0x370) && (c <= 0x37D))
           || ((c >= 0x37F) && (c <= 0x1FFF))
           || ((c >= 0x200C) && (c <= 0x200D))
           || ((c >= 0x203F) && (c <= 0x2040))
           || ((c >= 0x2070) && (c <= 0x218F))
           || ((c >= 0x2C00) && (c <= 0x2FEF))
           || ((c >= 0x3001) && (c <= 0xD7FF))
           || ((c >= 0xF900) && (c <= 0xFDCF))
           || ((c >= 0xFDF0) && (c <= 0xFFFD))
           || ((c >= 0x10000) && (c <= 0xEFFFF));
}

/*!
 * \internal
 * \brief Sanitize a string so it is usable as an XML ID
 *
 * An ID must match the Name production as defined here:
 * https://www.w3.org/TR/xml/#NT-Name.
 *
 * Convert an invalid start character to \c '_'. Convert an invalid character
 * after the start character to \c '.'.
 *
 * \param[in,out] id  String to sanitize
 */
void
pcmk__xml_sanitize_id(char *id)
{
    bool valid = true;
    int len = 0;

    // If id is empty or NULL, there's no way to make it a valid XML ID
    pcmk__assert(!pcmk__str_empty(id));

    /* @TODO Suppose there are two strings and each has an invalid ID character
     * in the same position. The strings are otherwise identical. Both strings
     * will be sanitized to the same valid ID, which is incorrect.
     *
     * The caller is responsible for ensuring the sanitized ID does not already
     * exist in a given XML document before using it, if uniqueness is desired.
     */
    valid = pcmk__xml_is_name_start_char(id, &len);
    CRM_CHECK(len > 0, return); // UTF-8 encoding error
    if (!valid) {
        *id = '_';
        for (int i = 1; i < len; i++) {
            id[i] = '.';
        }
    }

    for (id += len; *id != '\0'; id += len) {
        valid = pcmk__xml_is_name_char(id, &len);
        CRM_CHECK(len > 0, return); // UTF-8 encoding error
        if (!valid) {
            for (int i = 0; i < len; i++) {
                id[i] = '.';
            }
        }
    }
}

/*!
 * \internal
 * \brief Free an XML tree without ACL checks or change tracking
 *
 * \param[in,out] xml  XML node to free
 */
void
pcmk__xml_free_node(xmlNode *xml)
{
    pcmk__xml_free_private_data(xml);
    xmlUnlinkNode(xml);
    xmlFreeNode(xml);
}

/*!
 * \internal
 * \brief Free an XML tree if ACLs allow; track deletion if tracking is enabled
 *
 * If \p node is the root of its document, free the entire document.
 *
 * \param[in,out] node      XML node to free
 * \param[in]     position  Position of \p node among its siblings for change
 *                          tracking (negative to calculate automatically if
 *                          needed)
 */
static void
free_xml_with_position(xmlNode *node, int position)
{
    xmlDoc *doc = NULL;
    xml_node_private_t *nodepriv = NULL;

    if (node == NULL) {
        return;
    }
    doc = node->doc;
    nodepriv = node->_private;

    if ((doc != NULL) && (xmlDocGetRootElement(doc) == node)) {
        /* @TODO Should we check ACLs first? Otherwise it seems like we could
         * free the root element without write permission.
         */
        pcmk__xml_free_doc(doc);
        return;
    }

    if (!pcmk__check_acl(node, NULL, pcmk__xf_acl_write)) {
        GString *xpath = NULL;

        pcmk__if_tracing({}, return);
        xpath = pcmk__element_xpath(node);
        qb_log_from_external_source(__func__, __FILE__,
                                    "Cannot remove %s %x", LOG_TRACE,
                                    __LINE__, 0, xpath->str, nodepriv->flags);
        g_string_free(xpath, TRUE);
        return;
    }

    if (pcmk__xml_doc_all_flags_set(node->doc, pcmk__xf_tracking)
        && !pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {

        xml_doc_private_t *docpriv = doc->_private;
        GString *xpath = pcmk__element_xpath(node);

        if (xpath != NULL) {
            pcmk__deleted_xml_t *deleted_obj = NULL;

            crm_trace("Deleting %s %p from %p", xpath->str, node, doc);

            deleted_obj = pcmk__assert_alloc(1, sizeof(pcmk__deleted_xml_t));
            deleted_obj->path = g_string_free(xpath, FALSE);
            deleted_obj->position = -1;

            // Record the position only for XML comments for now
            if (node->type == XML_COMMENT_NODE) {
                if (position >= 0) {
                    deleted_obj->position = position;

                } else {
                    deleted_obj->position = pcmk__xml_position(node,
                                                               pcmk__xf_skip);
                }
            }

            docpriv->deleted_objs = g_list_append(docpriv->deleted_objs,
                                                  deleted_obj);
            pcmk__xml_doc_set_flags(node->doc, pcmk__xf_dirty);
        }
    }
    pcmk__xml_free_node(node);
}

/*!
 * \internal
 * \brief Free an XML tree if ACLs allow; track deletion if tracking is enabled
 *
 * If \p xml is the root of its document, free the entire document.
 *
 * \param[in,out] xml  XML node to free
 */
void
pcmk__xml_free(xmlNode *xml)
{
    free_xml_with_position(xml, -1);
}

/*!
 * \internal
 * \brief Make a deep copy of an XML node under a given parent
 *
 * \param[in,out] parent  XML element that will be the copy's parent (\c NULL
 *                        to create a new XML document with the copy as root)
 * \param[in]     src     XML node to copy
 *
 * \return Deep copy of \p src, or \c NULL if \p src is \c NULL
 */
xmlNode *
pcmk__xml_copy(xmlNode *parent, xmlNode *src)
{
    xmlNode *copy = NULL;

    if (src == NULL) {
        return NULL;
    }

    if (parent == NULL) {
        xmlDoc *doc = NULL;

        // The copy will be the root element of a new document
        pcmk__assert(src->type == XML_ELEMENT_NODE);

        doc = pcmk__xml_new_doc();
        copy = xmlDocCopyNode(src, doc, 1);
        pcmk__mem_assert(copy);

        xmlDocSetRootElement(doc, copy);

    } else {
        copy = xmlDocCopyNode(src, parent->doc, 1);
        pcmk__mem_assert(copy);

        xmlAddChild(parent, copy);
    }

    pcmk__xml_new_private_data(copy);
    return copy;
}

/*!
 * \internal
 * \brief Remove XML text nodes from specified XML and all its children
 *
 * \param[in,out] xml  XML to strip text from
 */
void
pcmk__strip_xml_text(xmlNode *xml)
{
    xmlNode *iter = xml->children;

    while (iter) {
        xmlNode *next = iter->next;

        switch (iter->type) {
            case XML_TEXT_NODE:
                pcmk__xml_free_node(iter);
                break;

            case XML_ELEMENT_NODE:
                /* Search it */
                pcmk__strip_xml_text(iter);
                break;

            default:
                /* Leave it */
                break;
        }

        iter = next;
    }
}

/*!
 * \internal
 * \brief Check whether a string has XML special characters that must be escaped
 *
 * See \c pcmk__xml_escape() and \c pcmk__xml_escape_type for more details.
 *
 * \param[in] text  String to check
 * \param[in] type  Type of escaping
 *
 * \return \c true if \p text has special characters that need to be escaped, or
 *         \c false otherwise
 */
bool
pcmk__xml_needs_escape(const char *text, enum pcmk__xml_escape_type type)
{
    if (text == NULL) {
        return false;
    }

    while (*text != '\0') {
        switch (type) {
            case pcmk__xml_escape_text:
                switch (*text) {
                    case '<':
                    case '>':
                    case '&':
                        return true;
                    case '\n':
                    case '\t':
                        break;
                    default:
                        if (g_ascii_iscntrl(*text)) {
                            return true;
                        }
                        break;
                }
                break;

            case pcmk__xml_escape_attr:
                switch (*text) {
                    case '<':
                    case '>':
                    case '&':
                    case '"':
                        return true;
                    default:
                        if (g_ascii_iscntrl(*text)) {
                            return true;
                        }
                        break;
                }
                break;

            case pcmk__xml_escape_attr_pretty:
                switch (*text) {
                    case '\n':
                    case '\r':
                    case '\t':
                    case '"':
                        return true;
                    default:
                        break;
                }
                break;

            default:    // Invalid enum value
                pcmk__assert(false);
                break;
        }

        text = g_utf8_next_char(text);
    }
    return false;
}

/*!
 * \internal
 * \brief Replace special characters with their XML escape sequences
 *
 * \param[in] text  Text to escape
 * \param[in] type  Type of escaping
 *
 * \return Newly allocated string equivalent to \p text but with special
 *         characters replaced with XML escape sequences (or \c NULL if \p text
 *         is \c NULL). If \p text is not \c NULL, the return value is
 *         guaranteed not to be \c NULL.
 *
 * \note There are libxml functions that purport to do this:
 *       \c xmlEncodeEntitiesReentrant() and \c xmlEncodeSpecialChars().
 *       However, their escaping is incomplete. See:
 *       https://discourse.gnome.org/t/intended-use-of-xmlencodeentitiesreentrant-vs-xmlencodespecialchars/19252
 * \note The caller is responsible for freeing the return value using
 *       \c g_free().
 */
gchar *
pcmk__xml_escape(const char *text, enum pcmk__xml_escape_type type)
{
    GString *copy = NULL;

    if (text == NULL) {
        return NULL;
    }
    copy = g_string_sized_new(strlen(text));

    while (*text != '\0') {
        // Don't escape any non-ASCII characters
        if ((*text & 0x80) != 0) {
            size_t bytes = g_utf8_next_char(text) - text;

            g_string_append_len(copy, text, bytes);
            text += bytes;
            continue;
        }

        switch (type) {
            case pcmk__xml_escape_text:
                switch (*text) {
                    case '<':
                        g_string_append(copy, PCMK__XML_ENTITY_LT);
                        break;
                    case '>':
                        g_string_append(copy, PCMK__XML_ENTITY_GT);
                        break;
                    case '&':
                        g_string_append(copy, PCMK__XML_ENTITY_AMP);
                        break;
                    case '\n':
                    case '\t':
                        g_string_append_c(copy, *text);
                        break;
                    default:
                        if (g_ascii_iscntrl(*text)) {
                            g_string_append_printf(copy, "&#x%.2X;", *text);
                        } else {
                            g_string_append_c(copy, *text);
                        }
                        break;
                }
                break;

            case pcmk__xml_escape_attr:
                switch (*text) {
                    case '<':
                        g_string_append(copy, PCMK__XML_ENTITY_LT);
                        break;
                    case '>':
                        g_string_append(copy, PCMK__XML_ENTITY_GT);
                        break;
                    case '&':
                        g_string_append(copy, PCMK__XML_ENTITY_AMP);
                        break;
                    case '"':
                        g_string_append(copy, PCMK__XML_ENTITY_QUOT);
                        break;
                    default:
                        if (g_ascii_iscntrl(*text)) {
                            g_string_append_printf(copy, "&#x%.2X;", *text);
                        } else {
                            g_string_append_c(copy, *text);
                        }
                        break;
                }
                break;

            case pcmk__xml_escape_attr_pretty:
                switch (*text) {
                    case '"':
                        g_string_append(copy, "\\\"");
                        break;
                    case '\n':
                        g_string_append(copy, "\\n");
                        break;
                    case '\r':
                        g_string_append(copy, "\\r");
                        break;
                    case '\t':
                        g_string_append(copy, "\\t");
                        break;
                    default:
                        g_string_append_c(copy, *text);
                        break;
                }
                break;

            default:    // Invalid enum value
                pcmk__assert(false);
                break;
        }

        text = g_utf8_next_char(text);
    }
    return g_string_free(copy, FALSE);
}

/*!
 * \internal
 * \brief Add an XML attribute to a node, marked as deleted
 *
 * When calculating XML changes, we need to know when an attribute has been
 * deleted. Add the attribute back to the new XML, so that we can check the
 * removal against ACLs, and mark it as deleted for later removal after
 * differences have been calculated.
 *
 * \param[in,out] new_xml     XML to modify
 * \param[in]     element     Name of XML element that changed (for logging)
 * \param[in]     attr_name   Name of attribute that was deleted
 * \param[in]     old_value   Value of attribute that was deleted
 */
static void
mark_attr_deleted(xmlNode *new_xml, const char *element, const char *attr_name,
                  const char *old_value)
{
    xml_doc_private_t *docpriv = new_xml->doc->_private;
    xmlAttr *attr = NULL;
    xml_node_private_t *nodepriv;

    /* Restore the old value (without setting dirty flag recursively upwards or
     * checking ACLs)
     */
    pcmk__clear_xml_flags(docpriv, pcmk__xf_tracking);
    pcmk__xe_set(new_xml, attr_name, old_value);
    pcmk__set_xml_flags(docpriv, pcmk__xf_tracking);

    // Reset flags (so the attribute doesn't appear as newly created)
    attr = xmlHasProp(new_xml, (const xmlChar *) attr_name);
    nodepriv = attr->_private;
    nodepriv->flags = 0;

    // Check ACLs and mark restored value for later removal
    pcmk__xa_remove(attr, false);

    crm_trace("XML attribute %s=%s was removed from %s",
              attr_name, old_value, element);
}

/*
 * \internal
 * \brief Check ACLs for a changed XML attribute
 */
static void
mark_attr_changed(xmlNode *new_xml, const char *element, const char *attr_name,
                  const char *old_value)
{
    xml_doc_private_t *docpriv = new_xml->doc->_private;
    char *vcopy = pcmk__xe_get_copy(new_xml, attr_name);

    crm_trace("XML attribute %s was changed from '%s' to '%s' in %s",
              attr_name, old_value, vcopy, element);

    // Restore the original value (without checking ACLs)
    pcmk__clear_xml_flags(docpriv, pcmk__xf_tracking);
    pcmk__xe_set(new_xml, attr_name, old_value);
    pcmk__set_xml_flags(docpriv, pcmk__xf_tracking);

    // Change it back to the new value, to check ACLs
    pcmk__xe_set(new_xml, attr_name, vcopy);
    free(vcopy);
}

/*!
 * \internal
 * \brief Mark an XML attribute as having changed position
 *
 * \param[in,out] new_xml     XML to modify
 * \param[in]     element     Name of XML element that changed (for logging)
 * \param[in,out] old_attr    Attribute that moved, in original XML
 * \param[in,out] new_attr    Attribute that moved, in \p new_xml
 * \param[in]     p_old       Ordinal position of \p old_attr in original XML
 * \param[in]     p_new       Ordinal position of \p new_attr in \p new_xml
 */
static void
mark_attr_moved(xmlNode *new_xml, const char *element, xmlAttr *old_attr,
                xmlAttr *new_attr, int p_old, int p_new)
{
    xml_node_private_t *nodepriv = new_attr->_private;

    crm_trace("XML attribute %s moved from position %d to %d in %s",
              old_attr->name, p_old, p_new, element);

    // Mark document, element, and all element's parents as changed
    pcmk__mark_xml_node_dirty(new_xml);

    // Mark attribute as changed
    pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_moved);

    nodepriv = (p_old > p_new)? old_attr->_private : new_attr->_private;
    pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);
}

/*!
 * \internal
 * \brief Calculate differences in all previously existing XML attributes
 *
 * \param[in,out] old_xml  Original XML to compare
 * \param[in,out] new_xml  New XML to compare
 */
static void
xml_diff_old_attrs(xmlNode *old_xml, xmlNode *new_xml)
{
    xmlAttr *attr_iter = pcmk__xe_first_attr(old_xml);

    while (attr_iter != NULL) {
        const char *name = (const char *) attr_iter->name;
        xmlAttr *old_attr = attr_iter;
        xmlAttr *new_attr = xmlHasProp(new_xml, attr_iter->name);
        const char *old_value = pcmk__xml_attr_value(attr_iter);

        attr_iter = attr_iter->next;
        if (new_attr == NULL) {
            mark_attr_deleted(new_xml, (const char *) old_xml->name, name,
                              old_value);

        } else {
            xml_node_private_t *nodepriv = new_attr->_private;
            int new_pos = pcmk__xml_position((xmlNode*) new_attr,
                                             pcmk__xf_skip);
            int old_pos = pcmk__xml_position((xmlNode*) old_attr,
                                             pcmk__xf_skip);
            const char *new_value = pcmk__xe_get(new_xml, name);

            // This attribute isn't new
            pcmk__clear_xml_flags(nodepriv, pcmk__xf_created);

            if (strcmp(new_value, old_value) != 0) {
                mark_attr_changed(new_xml, (const char *) old_xml->name, name,
                                  old_value);

            } else if ((old_pos != new_pos)
                       && !pcmk__xml_doc_all_flags_set(new_xml->doc,
                                                       pcmk__xf_ignore_attr_pos
                                                       |pcmk__xf_tracking)) {
                /* pcmk__xf_tracking is always set by pcmk__xml_mark_changes()
                 * before this function is called, so only the
                 * pcmk__xf_ignore_attr_pos check is truly relevant.
                 */
                mark_attr_moved(new_xml, (const char *) old_xml->name,
                                old_attr, new_attr, old_pos, new_pos);
            }
        }
    }
}

/*!
 * \internal
 * \brief Check all attributes in new XML for creation
 *
 * For each of a given XML element's attributes marked as newly created, accept
 * (and mark as dirty) or reject the creation according to ACLs.
 *
 * \param[in,out] new_xml  XML to check
 */
static void
mark_created_attrs(xmlNode *new_xml)
{
    xmlAttr *attr_iter = pcmk__xe_first_attr(new_xml);

    while (attr_iter != NULL) {
        xmlAttr *new_attr = attr_iter;
        xml_node_private_t *nodepriv = attr_iter->_private;

        attr_iter = attr_iter->next;
        if (pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {
            const char *attr_name = (const char *) new_attr->name;

            crm_trace("Created new attribute %s=%s in %s",
                      attr_name, pcmk__xml_attr_value(new_attr),
                      new_xml->name);

            /* Check ACLs (we can't use the remove-then-create trick because it
             * would modify the attribute position).
             */
            if (pcmk__check_acl(new_xml, attr_name, pcmk__xf_acl_write)) {
                pcmk__mark_xml_attr_dirty(new_attr);
            } else {
                // Creation was not allowed, so remove the attribute
                pcmk__xa_remove(new_attr, true);
            }
        }
    }
}

/*!
 * \internal
 * \brief Calculate differences in attributes between two XML nodes
 *
 * \param[in,out] old_xml  Original XML to compare
 * \param[in,out] new_xml  New XML to compare
 */
static void
xml_diff_attrs(xmlNode *old_xml, xmlNode *new_xml)
{
    // Cleared later if attributes are not really new
    for (xmlAttr *attr = pcmk__xe_first_attr(new_xml); attr != NULL;
         attr = attr->next) {
        xml_node_private_t *nodepriv = attr->_private;

        pcmk__set_xml_flags(nodepriv, pcmk__xf_created);
    }

    xml_diff_old_attrs(old_xml, new_xml);
    mark_created_attrs(new_xml);
}

/*!
 * \internal
 * \brief Add an XML child element to a node, marked as deleted
 *
 * When calculating XML changes, we need to know when a child element has been
 * deleted. Add the child back to the new XML, so that we can check the removal
 * against ACLs, and mark it as deleted for later removal after differences have
 * been calculated.
 *
 * \param[in,out] old_child    Child element from original XML
 * \param[in,out] new_parent   New XML to add marked copy to
 */
static void
mark_child_deleted(xmlNode *old_child, xmlNode *new_parent)
{
    // Re-create the child element so we can check ACLs
    xmlNode *candidate = pcmk__xml_copy(new_parent, old_child);

    // Clear flags on new child and its children
    pcmk__xml_tree_foreach(candidate, pcmk__xml_reset_node_flags, NULL);

    // Check whether ACLs allow the deletion
    pcmk__apply_acl(xmlDocGetRootElement(candidate->doc));

    // Remove the child again (which will track it in document's deleted_objs)
    free_xml_with_position(candidate,
                           pcmk__xml_position(old_child, pcmk__xf_skip));

    pcmk__set_xml_flags((xml_node_private_t *) old_child->_private,
                        pcmk__xf_skip);
}

static void
mark_child_moved(xmlNode *old_child, xmlNode *new_parent, xmlNode *new_child,
                 int p_old, int p_new)
{
    xml_node_private_t *nodepriv = new_child->_private;

    crm_trace("Child element %s with "
              PCMK_XA_ID "='%s' moved from position %d to %d under %s",
              new_child->name, pcmk__s(pcmk__xe_id(new_child), "<no id>"),
              p_old, p_new, new_parent->name);
    pcmk__mark_xml_node_dirty(new_parent);
    pcmk__set_xml_flags(nodepriv, pcmk__xf_moved);

    if (p_old > p_new) {
        nodepriv = old_child->_private;
    } else {
        nodepriv = new_child->_private;
    }
    pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);
}

/*!
 * \internal
 * \brief Create a \c GList containing all children of an XML node
 *
 * \param[in] xml  XML node
 *
 * \return List of children of \p xml, in document order
 */
static GList *
children_to_list(const xmlNode *xml)
{
    GList *child_list = NULL;

    for (xmlNode *child = pcmk__xml_first_child(xml); child != NULL;
         child = pcmk__xml_next(child)) {

        child_list = g_list_prepend(child_list, child);
    }
    return g_list_reverse(child_list);
}

/*!
 * \internal
 * \brief Check whether a new XML child comment matches an old XML child comment
 *
 * Two comments match if they have the same position among their siblings and
 * the same contents.
 *
 * If \p new_comment has the \c pcmk__xf_skip flag set, then it is automatically
 * considered not to match.
 *
 * \param[in] old_comment  Old XML child element
 * \param[in] new_comment  New XML child element
 *
 * \retval \c true if \p old_comment matches \p new_comment
 * \retval \c false otherwise
 */
static bool
new_comment_matches(const xmlNode *old_comment, const xmlNode *new_comment)
{
    xml_node_private_t *nodepriv = new_comment->_private;

    if (pcmk_is_set(nodepriv->flags, pcmk__xf_skip)) {
        /* @TODO Should we also return false if old_coment has pcmk__xf_skip
         * set? This preserves existing behavior at time of writing.
         */
        return false;
    }
    if (pcmk__xml_position(old_comment, pcmk__xf_skip)
        != pcmk__xml_position(new_comment, pcmk__xf_skip)) {
        return false;
    }
    return pcmk__xc_matches(old_comment, new_comment);
}

/*!
 * \internal
 * \brief Check whether a new XML child element matches an old XML child element
 *
 * Two elements match if they have the same name and, if \p match_ids is
 * \c true, the same ID. (Both IDs can be \c NULL in this case.)
 *
 * \param[in] old_element  Old XML child element
 * \param[in] new_element  New XML child element
 * \param[in] match_ids    If \c true, require IDs to match (or both be \c NULL)
 *
 * \retval \c true if \p old_element matches \p new_element
 * \retval \c false otherwise
 */
static bool
new_element_matches(const xmlNode *old_element, const xmlNode *new_element,
                    bool match_ids)
{
    if (!pcmk__xe_is(new_element, (const char *) old_element->name)) {
        return false;
    }
    return !match_ids
           || pcmk__str_eq(pcmk__xe_id(old_element), pcmk__xe_id(new_element),
                           pcmk__str_none);
}

/*!
 * \internal
 * \brief User data for \c new_child_matches()
 */
struct new_child_matches_data {
    xmlNode *old_child; //!< Old child to match against
    bool match_ids;     //!< Require element IDs to match
};

/*!
 * \internal
 * \brief Check whether a new XML child node matches an old XML child node
 *
 * Node types must be the same in order to match.
 *
 * For comments, a match is a comment at the same position with the same
 * content.
 *
 * For elements, a match is an element with the same name and, if required, the
 * same ID. (Both IDs can be \c NULL in this case.)
 *
 * For other node types, there is no match.
 *
 * \param[in] a  New XML child node (<tt>xmlNode *</tt>)
 * \param[in] b  Old XML child node and whether to require IDs to match
 *               (<tt>struct new_child_matches_data *</tt>)
 *
 * \retval 0 if \p a matches according to \p b
 * \retval 1 otherwise
 *
 * \note This function is suitable for use with \c g_list_find_custom().
 */
static int
new_child_matches(gconstpointer a, gconstpointer b)
{
    const xmlNode *new_child = a;
    struct new_child_matches_data *data = (struct new_child_matches_data *) b;
    const xmlNode *old_child = data->old_child;
    const bool match_ids = data->match_ids;

    if (old_child->type != new_child->type) {
        return 1;
    }

    switch (old_child->type) {
        case XML_COMMENT_NODE:
            return new_comment_matches(old_child, new_child)? 0 : 1;
        case XML_ELEMENT_NODE:
            return new_element_matches(old_child, new_child, match_ids)? 0 : 1;
        default:
            return 1;
    }
}

/*!
 * \internal
 * \brief Find matching XML node pairs between old and new XML's children
 *
 * A node that is part of a matching pair is removed from its respective list
 * (\p *old_children or \p *new_children) and added to \p *matches with its
 * match.
 *
 * \param[in,out]  old_children  Children of old XML
 * \param[in,out]  new_children  Children of new XML
 * \param[in,out]  matches       Where to prepend pairs of matching nodes from
 *                               \p old_children and \p new_children
 * \param[in]      comments_ids  If \c true, match comments and require element
 *                               IDs to match; otherwise, skip comments and
 *                               match elements by name only
 */
static void
find_matching_children(GList **old_children, GList **new_children,
                       GList **matches, bool comments_ids)
{
    // Save next pointer because we unlink iter on match
    for (GList *iter = *old_children, *next = g_list_next(*old_children);
         iter != NULL;
         iter = next, next = g_list_next(next)) {

        xmlNode *old_child = iter->data;

        struct new_child_matches_data data = {
            .old_child = old_child,
            .match_ids = comments_ids,
        };
        GList *match = NULL;

        if (!comments_ids && (old_child->type == XML_COMMENT_NODE)) {
            continue;
        }

        match = g_list_find_custom(*new_children, &data, new_child_matches);
        if (match == NULL) {
            continue;
        }

        /* Steal iter and match from *old_children and *new_children,
         * respectively, and prepend to *matches.
         *
         * Order should eventually be (iter, match), with pairs appearing in
         * document order. We will reverse the order of *matches in the caller
         * after finding all matches.
         */
        *old_children = g_list_remove_link(*old_children, iter);
        *new_children = g_list_remove_link(*new_children, match);

        *matches = g_list_concat(iter, *matches);
        *matches = g_list_concat(match, *matches);
    }
}

/*!
 * \internal
 * \brief Find changed XML node pairs between old and new XML's children
 *
 * \param[in]  old_xml  Old XML
 * \param[in]  new_xml  New XML
 * \param[out] matches  Pairs of matching nodes from \p old_xml and \p new_xml
 * \param[out] deleted  Nodes in \p old_xml that have no match in \p new_xml
 * \param[out] created  Nodes in \p new_xml that have no match in \p old_xml
 */
static void
find_changed_children(const xmlNode *old_xml, const xmlNode *new_xml,
                      GList **matches, GList **deleted, GList **created)
{
    GList *old_children = children_to_list(old_xml);
    GList *new_children = children_to_list(new_xml);

    find_matching_children(&old_children, &new_children, matches, true);
    find_matching_children(&old_children, &new_children, matches, false);

    // Matches were prepended (via concat) in (new_child, old_child) order
    *matches = g_list_reverse(*matches);

    // Nodes remaining in old_children had no match among new_children
    *deleted = old_children;

    // Nodes remaining in new_children had no match among old_children
    *created = new_children;
}

/*!
 * \internal
 * \brief Mark changes between two XML trees
 *
 * Set flags in a new XML tree to indicate changes relative to an old XML tree.
 *
 * \param[in,out] old_xml  XML before changes
 * \param[in,out] new_xml  XML after changes
 *
 * \note This may set \c pcmk__xf_skip on parts of \p old_xml.
 */
void
pcmk__xml_mark_changes(xmlNode *old_xml, xmlNode *new_xml)
{
    GList *matches = NULL;
    GList *deleted = NULL;
    GList *created = NULL;

    CRM_CHECK((old_xml != NULL) && (new_xml != NULL), return);

    pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_tracking);
    xml_diff_attrs(old_xml, new_xml);

    find_changed_children(old_xml, new_xml, &matches, &deleted, &created);

    // Recurse through matching children (iterate in pairs)
    for (GList *iter = matches; (iter != NULL) && (iter->next != NULL);
         iter = iter->next->next) {

        xmlNode *old_child = iter->data;
        xmlNode *new_child = iter->next->data;
        int old_pos = 0;
        int new_pos = 0;

        pcmk__assert((old_child != NULL) && (new_child != NULL)
                     && (old_child->type == new_child->type));

        if (old_child->type == XML_COMMENT_NODE) {
            // Comments don't match unless their positions and contents match
            continue;
        }

        pcmk__xml_mark_changes(old_child, new_child);

        old_pos = pcmk__xml_position(old_child, pcmk__xf_skip);
        new_pos = pcmk__xml_position(new_child, pcmk__xf_skip);

        if (old_pos != new_pos) {
            mark_child_moved(old_child, new_xml, new_child, old_pos, new_pos);
        }
    }

    // Mark unmatched old children as deleted
    for (GList *iter = deleted; iter != NULL; iter = iter->next) {
        xmlNode *old_child = iter->data;

        mark_child_deleted(old_child, new_xml);
    }

    // Mark unmatched new children as created
    for (GList *iter = created; iter != NULL; iter = iter->next) {
        xmlNode *new_child = iter->data;
        xml_node_private_t *nodepriv = new_child->_private;

        pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);
        mark_xml_tree_dirty_created(new_child);

        // Check whether creation was allowed; may free new_child
        pcmk__apply_creation_acl(new_child, true);
    }

    g_list_free(matches);
    g_list_free(deleted);
    g_list_free(created);
}

/*!
 * \internal
 * \brief Initialize the Pacemaker XML environment
 *
 * Set an XML buffer allocation scheme, set XML node create and destroy
 * callbacks, and load schemas into the cache.
 */
void
pcmk__xml_init(void)
{
    // @TODO Try to find a better caller than crm_log_preinit()
    static bool initialized = false;

    if (!initialized) {
        initialized = true;

        /* Double the buffer size when the buffer needs to grow. The default
         * allocator XML_BUFFER_ALLOC_EXACT was found to cause poor performance
         * due to the number of reallocs.
         */
        xmlSetBufferAllocationScheme(XML_BUFFER_ALLOC_DOUBLEIT);

        // Load schemas into the cache
        pcmk__schema_init();
    }
}

/*!
 * \internal
 * \brief Tear down the Pacemaker XML environment
 *
 * Destroy schema cache and clean up memory allocated by libxml2.
 */
void
pcmk__xml_cleanup(void)
{
    pcmk__schema_cleanup();
    xmlCleanupParser();
}

char *
pcmk__xml_artefact_root(enum pcmk__xml_artefact_ns ns)
{
    static const char *base = NULL;
    char *ret = NULL;

    if (base == NULL) {
        base = pcmk__env_option(PCMK__ENV_SCHEMA_DIRECTORY);
    }
    if (pcmk__str_empty(base)) {
        base = PCMK_SCHEMA_DIR;
    }

    switch (ns) {
        case pcmk__xml_artefact_ns_legacy_rng:
        case pcmk__xml_artefact_ns_legacy_xslt:
            ret = strdup(base);
            break;
        case pcmk__xml_artefact_ns_base_rng:
        case pcmk__xml_artefact_ns_base_xslt:
            ret = crm_strdup_printf("%s/base", base);
            break;
        default:
            crm_err("XML artefact family specified as %u not recognized", ns);
    }
    return ret;
}

static char *
find_artefact(enum pcmk__xml_artefact_ns ns, const char *path, const char *filespec)
{
    char *ret = NULL;

    switch (ns) {
        case pcmk__xml_artefact_ns_legacy_rng:
        case pcmk__xml_artefact_ns_base_rng:
            if (pcmk__ends_with(filespec, ".rng")) {
                ret = crm_strdup_printf("%s/%s", path, filespec);
            } else {
                ret = crm_strdup_printf("%s/%s.rng", path, filespec);
            }
            break;
        case pcmk__xml_artefact_ns_legacy_xslt:
        case pcmk__xml_artefact_ns_base_xslt:
            if (pcmk__ends_with(filespec, ".xsl")) {
                ret = crm_strdup_printf("%s/%s", path, filespec);
            } else {
                ret = crm_strdup_printf("%s/%s.xsl", path, filespec);
            }
            break;
        default:
            crm_err("XML artefact family specified as %u not recognized", ns);
    }

    return ret;
}

char *
pcmk__xml_artefact_path(enum pcmk__xml_artefact_ns ns, const char *filespec)
{
    struct stat sb;
    char *base = pcmk__xml_artefact_root(ns);
    char *ret = NULL;

    ret = find_artefact(ns, base, filespec);
    free(base);

    if (stat(ret, &sb) != 0 || !S_ISREG(sb.st_mode)) {
        const char *remote_schema_dir = pcmk__remote_schema_dir();

        free(ret);
        ret = find_artefact(ns, remote_schema_dir, filespec);
    }

    return ret;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

xmlNode *
copy_xml(xmlNode *src)
{
    xmlDoc *doc = pcmk__xml_new_doc();
    xmlNode *copy = NULL;

    copy = xmlDocCopyNode(src, doc, 1);
    pcmk__mem_assert(copy);

    xmlDocSetRootElement(doc, copy);
    pcmk__xml_new_private_data(copy);
    return copy;
}

void
crm_xml_init(void)
{
    pcmk__xml_init();
}

void
crm_xml_cleanup(void)
{
    pcmk__xml_cleanup();
}

void
pcmk_free_xml_subtree(xmlNode *xml)
{
    pcmk__xml_free_node(xml);
}

void
free_xml(xmlNode *child)
{
    pcmk__xml_free(child);
}

void
crm_xml_sanitize_id(char *id)
{
    char *c;

    for (c = id; *c; ++c) {
        switch (*c) {
            case ':':
            case '#':
                *c = '.';
        }
    }
}

bool
xml_tracking_changes(xmlNode *xml)
{
    return (xml != NULL)
           && pcmk__xml_doc_all_flags_set(xml->doc, pcmk__xf_tracking);
}

bool
xml_document_dirty(xmlNode *xml)
{
    return (xml != NULL)
           && pcmk__xml_doc_all_flags_set(xml->doc, pcmk__xf_dirty);
}

void
xml_accept_changes(xmlNode *xml)
{
    if (xml != NULL) {
        pcmk__xml_commit_changes(xml->doc);
    }
}

void
xml_track_changes(xmlNode *xml, const char *user, xmlNode *acl_source,
                  bool enforce_acls)
{
    if (xml == NULL) {
        return;
    }

    pcmk__xml_commit_changes(xml->doc);
    crm_trace("Tracking changes%s to %p",
              (enforce_acls? " with ACLs" : ""), xml);
    pcmk__xml_doc_set_flags(xml->doc, pcmk__xf_tracking);
    if (enforce_acls) {
        if (acl_source == NULL) {
            acl_source = xml;
        }
        pcmk__xml_doc_set_flags(xml->doc, pcmk__xf_acl_enabled);
        pcmk__unpack_acl(acl_source, xml, user);
        pcmk__apply_acl(xml);
    }
}

void
xml_calculate_changes(xmlNode *old_xml, xmlNode *new_xml)
{
    CRM_CHECK((old_xml != NULL) && (new_xml != NULL)
              && pcmk__xe_is(old_xml, (const char *) new_xml->name)
              && pcmk__str_eq(pcmk__xe_id(old_xml), pcmk__xe_id(new_xml),
                              pcmk__str_none),
              return);

    if (!pcmk__xml_doc_all_flags_set(new_xml->doc, pcmk__xf_tracking)) {
        // Ensure tracking has a clean start
        pcmk__xml_commit_changes(new_xml->doc);
        pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_tracking);
    }

    pcmk__xml_mark_changes(old_xml, new_xml);
}

void
xml_calculate_significant_changes(xmlNode *old_xml, xmlNode *new_xml)
{
    CRM_CHECK((old_xml != NULL) && (new_xml != NULL)
              && pcmk__xe_is(old_xml, (const char *) new_xml->name)
              && pcmk__str_eq(pcmk__xe_id(old_xml), pcmk__xe_id(new_xml),
                              pcmk__str_none),
              return);

    /* BUG: If pcmk__xf_tracking is not set for new_xml when this function is
     * called, then we unset pcmk__xf_ignore_attr_pos via
     * pcmk__xml_commit_changes(). Since this function is about to be
     * deprecated, it's not worth fixing this and changing the user-facing
     * behavior.
     */
    pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_ignore_attr_pos);

    if (!pcmk__xml_doc_all_flags_set(new_xml->doc, pcmk__xf_tracking)) {
        // Ensure tracking has a clean start
        pcmk__xml_commit_changes(new_xml->doc);
        pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_tracking);
    }

    pcmk__xml_mark_changes(old_xml, new_xml);
}

// LCOV_EXCL_STOP
// End deprecated API

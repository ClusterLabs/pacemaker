/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>                   // stat(), S_ISREG, etc.
#include <sys/types.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>    // PCMK__XML_LOG_BASE, etc.
#include "crmcommon_private.h"

// Define this as 1 in development to get insanely verbose trace messages
#ifndef XML_PARSER_DEBUG
#define XML_PARSER_DEBUG 0
#endif

bool
pcmk__tracking_xml_changes(xmlNode *xml, bool lazy)
{
    if(xml == NULL || xml->doc == NULL || xml->doc->_private == NULL) {
        return FALSE;
    } else if (!pcmk_is_set(((xml_doc_private_t *)xml->doc->_private)->flags,
                            pcmk__xf_tracking)) {
        return FALSE;
    } else if (lazy && !pcmk_is_set(((xml_doc_private_t *)xml->doc->_private)->flags,
                                    pcmk__xf_lazy)) {
        return FALSE;
    }
    return TRUE;
}

static inline void
set_parent_flag(xmlNode *xml, long flag) 
{
    for(; xml; xml = xml->parent) {
        xml_node_private_t *nodepriv = xml->_private;

        if (nodepriv == NULL) {
            /* During calls to xmlDocCopyNode(), _private will be unset for parent nodes */
        } else {
            pcmk__set_xml_flags(nodepriv, flag);
        }
    }
}

void
pcmk__set_xml_doc_flag(xmlNode *xml, enum xml_private_flags flag)
{
    if(xml && xml->doc && xml->doc->_private){
        /* During calls to xmlDocCopyNode(), xml->doc may be unset */
        xml_doc_private_t *docpriv = xml->doc->_private;

        pcmk__set_xml_flags(docpriv, flag);
    }
}

// Mark document, element, and all element's parents as changed
void
pcmk__mark_xml_node_dirty(xmlNode *xml)
{
    pcmk__set_xml_doc_flag(xml, pcmk__xf_dirty);
    set_parent_flag(xml, pcmk__xf_dirty);
}

// Clear flags on XML node and its children
static void
reset_xml_node_flags(xmlNode *xml)
{
    xmlNode *cIter = NULL;
    xml_node_private_t *nodepriv = xml->_private;

    if (nodepriv) {
        nodepriv->flags = 0;
    }

    for (cIter = pcmk__xml_first_child(xml); cIter != NULL;
         cIter = pcmk__xml_next(cIter)) {
        reset_xml_node_flags(cIter);
    }
}

// Set xpf_created flag on XML node and any children
void
pcmk__mark_xml_created(xmlNode *xml)
{
    xmlNode *cIter = NULL;
    xml_node_private_t *nodepriv = NULL;

    CRM_ASSERT(xml != NULL);
    nodepriv = xml->_private;

    if (nodepriv && pcmk__tracking_xml_changes(xml, FALSE)) {
        if (!pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {
            pcmk__set_xml_flags(nodepriv, pcmk__xf_created);
            pcmk__mark_xml_node_dirty(xml);
        }
        for (cIter = pcmk__xml_first_child(xml); cIter != NULL;
             cIter = pcmk__xml_next(cIter)) {
            pcmk__mark_xml_created(cIter);
        }
    }
}

#define XML_DOC_PRIVATE_MAGIC   0x81726354UL
#define XML_NODE_PRIVATE_MAGIC  0x54637281UL

// Free an XML object previously marked as deleted
static void
free_deleted_object(void *data)
{
    if(data) {
        pcmk__deleted_xml_t *deleted_obj = data;

        free(deleted_obj->path);
        free(deleted_obj);
    }
}

// Free and NULL user, ACLs, and deleted objects in an XML node's private data
static void
reset_xml_private_data(xml_doc_private_t *docpriv)
{
    if (docpriv != NULL) {
        CRM_ASSERT(docpriv->check == XML_DOC_PRIVATE_MAGIC);

        free(docpriv->user);
        docpriv->user = NULL;

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

// Free all private data associated with an XML node
static void
free_private_data(xmlNode *node)
{
    /* Note:
    
    This function frees private data assosciated with an XML node,
    unless the function is being called as a result of internal
    XSLT cleanup.
    
    That could happen through, for example, the following chain of
    function calls:
    
       xsltApplyStylesheetInternal
    -> xsltFreeTransformContext
    -> xsltFreeRVTs
    -> xmlFreeDoc

    And in that case, the node would fulfill three conditions:
    
    1. It would be a standalone document (i.e. it wouldn't be 
       part of a document)
    2. It would have a space-prefixed name (for reference, please
       see xsltInternals.h: XSLT_MARK_RES_TREE_FRAG)
    3. It would carry its own payload in the _private field.
    
    We do not free data in this circumstance to avoid a failed
    assertion on the XML_*_PRIVATE_MAGIC later.
    
    */
    if (node->name == NULL || node->name[0] != ' ') {
        if (node->_private) {
            if (node->type == XML_DOCUMENT_NODE) {
                reset_xml_private_data(node->_private);
            } else {
                CRM_ASSERT(((xml_node_private_t *) node->_private)->check
                               == XML_NODE_PRIVATE_MAGIC);
                /* nothing dynamically allocated nested */
            }
            free(node->_private);
            node->_private = NULL;
        }
    }
}

// Allocate and initialize private data for an XML node
static void
new_private_data(xmlNode *node)
{
    switch (node->type) {
        case XML_DOCUMENT_NODE: {
            xml_doc_private_t *docpriv =
                pcmk__assert_alloc(1, sizeof(xml_doc_private_t));

            docpriv->check = XML_DOC_PRIVATE_MAGIC;
            /* Flags will be reset if necessary when tracking is enabled */
            pcmk__set_xml_flags(docpriv, pcmk__xf_dirty|pcmk__xf_created);
            node->_private = docpriv;
            break;
        }
        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
        case XML_COMMENT_NODE: {
            xml_node_private_t *nodepriv =
                pcmk__assert_alloc(1, sizeof(xml_node_private_t));

            nodepriv->check = XML_NODE_PRIVATE_MAGIC;
            /* Flags will be reset if necessary when tracking is enabled */
            pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_created);
            node->_private = nodepriv;
            if (pcmk__tracking_xml_changes(node, FALSE)) {
                /* XML_ELEMENT_NODE doesn't get picked up here, node->doc is
                 * not hooked up at the point we are called
                 */
                pcmk__mark_xml_node_dirty(node);
            }
            break;
        }
        case XML_TEXT_NODE:
        case XML_DTD_NODE:
        case XML_CDATA_SECTION_NODE:
            break;
        default:
            /* Ignore */
            crm_trace("Ignoring %p %d", node, node->type);
            CRM_LOG_ASSERT(node->type == XML_ELEMENT_NODE);
            break;
    }
}

void
xml_track_changes(xmlNode * xml, const char *user, xmlNode *acl_source, bool enforce_acls) 
{
    xml_accept_changes(xml);
    crm_trace("Tracking changes%s to %p", enforce_acls?" with ACLs":"", xml);
    pcmk__set_xml_doc_flag(xml, pcmk__xf_tracking);
    if(enforce_acls) {
        if(acl_source == NULL) {
            acl_source = xml;
        }
        pcmk__set_xml_doc_flag(xml, pcmk__xf_acl_enabled);
        pcmk__unpack_acl(acl_source, xml, user);
        pcmk__apply_acl(xml);
    }
}

bool xml_tracking_changes(xmlNode * xml)
{
    return (xml != NULL) && (xml->doc != NULL) && (xml->doc->_private != NULL)
           && pcmk_is_set(((xml_doc_private_t *)(xml->doc->_private))->flags,
                          pcmk__xf_tracking);
}

bool xml_document_dirty(xmlNode *xml) 
{
    return (xml != NULL) && (xml->doc != NULL) && (xml->doc->_private != NULL)
           && pcmk_is_set(((xml_doc_private_t *)(xml->doc->_private))->flags,
                          pcmk__xf_dirty);
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
pcmk__xml_position(const xmlNode *xml, enum xml_private_flags ignore_if_set)
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

// Remove all attributes marked as deleted from an XML node
static void
accept_attr_deletions(xmlNode *xml)
{
    // Clear XML node's flags
    ((xml_node_private_t *) xml->_private)->flags = pcmk__xf_none;

    // Remove this XML node's attributes that were marked as deleted
    pcmk__xe_remove_matching_attrs(xml, pcmk__marked_as_deleted, NULL);

    // Recursively do the same for this XML node's children
    for (xmlNodePtr cIter = pcmk__xml_first_child(xml); cIter != NULL;
         cIter = pcmk__xml_next(cIter)) {
        accept_attr_deletions(cIter);
    }
}

/*!
 * \internal
 * \brief Find first child XML node matching another given XML node
 *
 * \param[in] haystack  XML whose children should be checked
 * \param[in] needle    XML to match (comment content or element name and ID)
 * \param[in] exact     If true and needle is a comment, position must match
 */
xmlNode *
pcmk__xml_match(const xmlNode *haystack, const xmlNode *needle, bool exact)
{
    CRM_CHECK(needle != NULL, return NULL);

    if (needle->type == XML_COMMENT_NODE) {
        return pcmk__xc_match(haystack, needle, exact);

    } else {
        const char *id = pcmk__xe_id(needle);
        const char *attr = (id == NULL)? NULL : PCMK_XA_ID;

        return pcmk__xe_first_child(haystack, (const char *) needle->name, attr,
                                    id);
    }
}

void
xml_accept_changes(xmlNode * xml)
{
    xmlNode *top = NULL;
    xml_doc_private_t *docpriv = NULL;

    if(xml == NULL) {
        return;
    }

    crm_trace("Accepting changes to %p", xml);
    docpriv = xml->doc->_private;
    top = xmlDocGetRootElement(xml->doc);

    reset_xml_private_data(xml->doc->_private);

    if (!pcmk_is_set(docpriv->flags, pcmk__xf_dirty)) {
        docpriv->flags = pcmk__xf_none;
        return;
    }

    docpriv->flags = pcmk__xf_none;
    accept_attr_deletions(top);
}

/*!
 * \internal
 * \brief Find first XML child element matching given criteria
 *
 * \param[in] parent     XML element to search (can be \c NULL)
 * \param[in] node_name  If not \c NULL, only match children of this type
 * \param[in] attr_n     If not \c NULL, only match children with an attribute
 *                       of this name.
 * \param[in] attr_v     If \p attr_n and this are not NULL, only match children
 *                       with an attribute named \p attr_n and this value
 *
 * \return Matching XML child element, or \c NULL if none found
 */
xmlNode *
pcmk__xe_first_child(const xmlNode *parent, const char *node_name,
                     const char *attr_n, const char *attr_v)
{
    xmlNode *child = NULL;
    const char *parent_name = "<null>";

    CRM_CHECK((attr_v == NULL) || (attr_n != NULL), return NULL);

    if (parent != NULL) {
        child = parent->children;
        while ((child != NULL) && (child->type != XML_ELEMENT_NODE)) {
            child = child->next;
        }

        parent_name = (const char *) parent->name;
    }

    for (; child != NULL; child = pcmk__xe_next(child)) {
        const char *value = NULL;

        if ((node_name != NULL) && !pcmk__xe_is(child, node_name)) {
            // Node name mismatch
            continue;
        }
        if (attr_n == NULL) {
            // No attribute match needed
            return child;
        }

        value = crm_element_value(child, attr_n);

        if ((attr_v == NULL) && (value != NULL)) {
            // attr_v == NULL: Attribute attr_n must be set (to any value)
            return child;
        }
        if ((attr_v != NULL) && (pcmk__str_eq(value, attr_v, pcmk__str_none))) {
            // attr_v != NULL: Attribute attr_n must be set to value attr_v
            return child;
        }
    }

    if (node_name == NULL) {
        node_name = "(any)";    // For logging
    }
    if (attr_n != NULL) {
        crm_trace("XML child node <%s %s=%s> not found in %s",
                  node_name, attr_n, attr_v, parent_name);
    } else {
        crm_trace("XML child node <%s> not found in %s",
                  node_name, parent_name);
    }
    return NULL;
}

void
copy_in_properties(xmlNode *target, const xmlNode *src)
{
    if (src == NULL) {
        crm_warn("No node to copy properties from");

    } else if (target == NULL) {
        crm_err("No node to copy properties into");

    } else {
        for (xmlAttrPtr a = pcmk__xe_first_attr(src); a != NULL; a = a->next) {
            const char *p_name = (const char *) a->name;
            const char *p_value = pcmk__xml_attr_value(a);

            expand_plus_plus(target, p_name, p_value);
            if (xml_acl_denied(target)) {
                crm_trace("Cannot copy %s=%s to %s", p_name, p_value, target->name);
                return;
            }
        }
    }

    return;
}

/*!
 * \brief Parse integer assignment statements on this node and all its child
 *        nodes
 *
 * \param[in,out] target  Root XML node to be processed
 *
 * \note This function is recursive
 */
void
fix_plus_plus_recursive(xmlNode *target)
{
    /* TODO: Remove recursion and use xpath searches for value++ */
    xmlNode *child = NULL;

    for (xmlAttrPtr a = pcmk__xe_first_attr(target); a != NULL; a = a->next) {
        const char *p_name = (const char *) a->name;
        const char *p_value = pcmk__xml_attr_value(a);

        expand_plus_plus(target, p_name, p_value);
    }
    for (child = pcmk__xe_first_child(target, NULL, NULL, NULL); child != NULL;
         child = pcmk__xe_next(child)) {

        fix_plus_plus_recursive(child);
    }
}

/*!
 * \brief Update current XML attribute value per parsed integer assignment
          statement
 *
 * \param[in,out]   target  an XML node, containing a XML attribute that is
 *                          initialized to some numeric value, to be processed
 * \param[in]       name    name of the XML attribute, e.g. X, whose value
 *                          should be updated
 * \param[in]       value   assignment statement, e.g. "X++" or
 *                          "X+=5", to be applied to the initialized value.
 *
 * \note The original XML attribute value is treated as 0 if non-numeric and
 *       truncated to be an integer if decimal-point-containing.
 * \note The final XML attribute value is truncated to not exceed 1000000.
 * \note Undefined behavior if unexpected input.
 */
void
expand_plus_plus(xmlNode * target, const char *name, const char *value)
{
    int offset = 1;
    int name_len = 0;
    int int_value = 0;
    int value_len = 0;

    const char *old_value = NULL;

    if (target == NULL || value == NULL || name == NULL) {
        return;
    }

    old_value = crm_element_value(target, name);

    if (old_value == NULL) {
        /* if no previous value, set unexpanded */
        goto set_unexpanded;

    } else if (strstr(value, name) != value) {
        goto set_unexpanded;
    }

    name_len = strlen(name);
    value_len = strlen(value);
    if (value_len < (name_len + 2)
        || value[name_len] != '+' || (value[name_len + 1] != '+' && value[name_len + 1] != '=')) {
        goto set_unexpanded;
    }

    /* if we are expanding ourselves,
     * then no previous value was set and leave int_value as 0
     */
    if (old_value != value) {
        int_value = char2score(old_value);
    }

    if (value[name_len + 1] != '+') {
        const char *offset_s = value + (name_len + 2);

        offset = char2score(offset_s);
    }
    int_value += offset;

    if (int_value > PCMK_SCORE_INFINITY) {
        int_value = PCMK_SCORE_INFINITY;
    }

    crm_xml_add_int(target, name, int_value);
    return;

  set_unexpanded:
    if (old_value == value) {
        /* the old value is already set, nothing to do */
        return;
    }
    crm_xml_add(target, name, value);
    return;
}

/*!
 * \internal
 * \brief Remove an XML attribute from an element
 *
 * \param[in,out] element  XML element that owns \p attr
 * \param[in,out] attr     XML attribute to remove from \p element
 *
 * \return Standard Pacemaker return code (\c EPERM if ACLs prevent removal of
 *         attributes from \p element, or \c pcmk_rc_ok otherwise)
 */
static int
remove_xe_attr(xmlNode *element, xmlAttr *attr)
{
    if (attr == NULL) {
        return pcmk_rc_ok;
    }

    if (!pcmk__check_acl(element, NULL, pcmk__xf_acl_write)) {
        // ACLs apply to element, not to particular attributes
        crm_trace("ACLs prevent removal of attributes from %s element",
                  (const char *) element->name);
        return EPERM;
    }

    if (pcmk__tracking_xml_changes(element, false)) {
        // Leave in place (marked for removal) until after diff is calculated
        set_parent_flag(element, pcmk__xf_dirty);
        pcmk__set_xml_flags((xml_node_private_t *) attr->_private,
                            pcmk__xf_deleted);
    } else {
        xmlRemoveProp(attr);
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Remove a named attribute from an XML element
 *
 * \param[in,out] element  XML element to remove an attribute from
 * \param[in]     name     Name of attribute to remove
 */
void
pcmk__xe_remove_attr(xmlNode *element, const char *name)
{
    if (name != NULL) {
        remove_xe_attr(element, xmlHasProp(element, (pcmkXmlStr) name));
    }
}

/*!
 * \internal
 * \brief Remove an XML element's attributes that match some criteria
 *
 * \param[in,out] element    XML element to modify
 * \param[in]     match      If not NULL, only remove attributes for which
 *                           this function returns true
 * \param[in,out] user_data  Data to pass to \p match
 */
void
pcmk__xe_remove_matching_attrs(xmlNode *element,
                               bool (*match)(xmlAttrPtr, void *),
                               void *user_data)
{
    xmlAttrPtr next = NULL;

    for (xmlAttrPtr a = pcmk__xe_first_attr(element); a != NULL; a = next) {
        next = a->next; // Grab now because attribute might get removed
        if ((match == NULL) || match(a, user_data)) {
            if (remove_xe_attr(element, a) != pcmk_rc_ok) {
                return;
            }
        }
    }
}

/*!
 * \internal
 * \brief Create a new XML element under a given parent
 *
 * \param[in,out] parent  XML element that will be the new element's parent
 *                        (\c NULL to create a new XML document with the new
 *                        node as root)
 * \param[in]     name    Name of new element
 *
 * \return Newly created XML element (guaranteed not to be \c NULL)
 */
xmlNode *
pcmk__xe_create(xmlNode *parent, const char *name)
{
    xmlNode *node = NULL;

    CRM_ASSERT(!pcmk__str_empty(name));

    if (parent == NULL) {
        xmlDoc *doc = xmlNewDoc(PCMK__XML_VERSION);

        pcmk__mem_assert(doc);

        node = xmlNewDocRawNode(doc, NULL, (pcmkXmlStr) name, NULL);
        pcmk__mem_assert(node);

        xmlDocSetRootElement(doc, node);

    } else {
        node = xmlNewChild(parent, NULL, (pcmkXmlStr) name, NULL);
        pcmk__mem_assert(node);
    }
    pcmk__mark_xml_created(node);
    return node;
}

/*!
 * \internal
 * \brief Set a formatted string as an XML node's content
 *
 * \param[in,out] node    Node whose content to set
 * \param[in]     format  <tt>printf(3)</tt>-style format string
 * \param[in]     ...     Arguments for \p format
 *
 * \note This function escapes special characters. \c xmlNodeSetContent() does
 *       not.
 */
G_GNUC_PRINTF(2, 3)
void
pcmk__xe_set_content(xmlNode *node, const char *format, ...)
{
    if (node != NULL) {
        const char *content = NULL;
        char *buf = NULL;

        if (strchr(format, '%') == NULL) {
            // Nothing to format
            content = format;

        } else {
            va_list ap;

            va_start(ap, format);

            if (pcmk__str_eq(format, "%s", pcmk__str_none)) {
                // No need to make a copy
                content = va_arg(ap, const char *);

            } else {
                CRM_ASSERT(vasprintf(&buf, format, ap) >= 0);
                content = buf;
            }
            va_end(ap);
        }

        if (pcmk__xml_needs_escape(content, false)) {
            char *escaped = pcmk__xml_escape(content, false);

            free(buf);
            buf = escaped;
            content = buf;
        }
        xmlNodeSetContent(node, (pcmkXmlStr) content);
        free(buf);
    }
}

/*!
 * Free an XML element and all of its children, removing it from its parent
 *
 * \param[in,out] xml  XML element to free
 */
void
pcmk_free_xml_subtree(xmlNode *xml)
{
    xmlUnlinkNode(xml); // Detaches from parent and siblings
    xmlFreeNode(xml);   // Frees
}

static void
free_xml_with_position(xmlNode * child, int position)
{
    if (child != NULL) {
        xmlNode *top = NULL;
        xmlDoc *doc = child->doc;
        xml_node_private_t *nodepriv = child->_private;
        xml_doc_private_t *docpriv = NULL;

        if (doc != NULL) {
            top = xmlDocGetRootElement(doc);
        }

        if (doc != NULL && top == child) {
            /* Free everything */
            xmlFreeDoc(doc);

        } else if (pcmk__check_acl(child, NULL, pcmk__xf_acl_write) == FALSE) {
            GString *xpath = NULL;

            pcmk__if_tracing({}, return);
            xpath = pcmk__element_xpath(child);
            qb_log_from_external_source(__func__, __FILE__,
                                        "Cannot remove %s %x", LOG_TRACE,
                                        __LINE__, 0, (const char *) xpath->str,
                                        nodepriv->flags);
            g_string_free(xpath, TRUE);
            return;

        } else {
            if (doc && pcmk__tracking_xml_changes(child, FALSE)
                && !pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {

                GString *xpath = pcmk__element_xpath(child);

                if (xpath != NULL) {
                    pcmk__deleted_xml_t *deleted_obj = NULL;

                    crm_trace("Deleting %s %p from %p",
                              (const char *) xpath->str, child, doc);

                    deleted_obj =
                        pcmk__assert_alloc(1, sizeof(pcmk__deleted_xml_t));

                    deleted_obj->path = pcmk__str_copy(xpath->str);
                    g_string_free(xpath, TRUE);

                    deleted_obj->position = -1;
                    /* Record the "position" only for XML comments for now */
                    if (child->type == XML_COMMENT_NODE) {
                        if (position >= 0) {
                            deleted_obj->position = position;

                        } else {
                            deleted_obj->position = pcmk__xml_position(child,
                                                                       pcmk__xf_skip);
                        }
                    }

                    docpriv = doc->_private;
                    docpriv->deleted_objs = g_list_append(docpriv->deleted_objs, deleted_obj);
                    pcmk__set_xml_doc_flag(child, pcmk__xf_dirty);
                }
            }
            pcmk_free_xml_subtree(child);
        }
    }
}


void
free_xml(xmlNode * child)
{
    free_xml_with_position(child, -1);
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
        CRM_ASSERT(src->type == XML_ELEMENT_NODE);

        doc = xmlNewDoc(PCMK__XML_VERSION);
        pcmk__mem_assert(doc);

        copy = xmlDocCopyNode(src, doc, 1);
        pcmk__mem_assert(copy);

        xmlDocSetRootElement(doc, copy);

    } else {
        copy = xmlDocCopyNode(src, parent->doc, 1);
        pcmk__mem_assert(copy);

        xmlAddChild(parent, copy);
    }

    pcmk__mark_xml_created(copy);
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
                /* Remove it */
                pcmk_free_xml_subtree(iter);
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
 * \brief Add a "last written" attribute to an XML element, set to current time
 *
 * \param[in,out] xe  XML element to add attribute to
 *
 * \return Value that was set, or NULL on error
 */
const char *
pcmk__xe_add_last_written(xmlNode *xe)
{
    char *now_s = pcmk__epoch2str(NULL, 0);
    const char *result = NULL;

    result = crm_xml_add(xe, PCMK_XA_CIB_LAST_WRITTEN,
                         pcmk__s(now_s, "Could not determine current time"));
    free(now_s);
    return result;
}

/*!
 * \brief Sanitize a string so it is usable as an XML ID
 *
 * \param[in,out] id  String to sanitize
 */
void
crm_xml_sanitize_id(char *id)
{
    char *c;

    for (c = id; *c; ++c) {
        /* @TODO Sanitize more comprehensively */
        switch (*c) {
            case ':':
            case '#':
                *c = '.';
        }
    }
}

/*!
 * \brief Set the ID of an XML element using a format
 *
 * \param[in,out] xml  XML element
 * \param[in]     fmt  printf-style format
 * \param[in]     ...  any arguments required by format
 */
void
crm_xml_set_id(xmlNode *xml, const char *format, ...)
{
    va_list ap;
    int len = 0;
    char *id = NULL;

    /* equivalent to crm_strdup_printf() */
    va_start(ap, format);
    len = vasprintf(&id, format, ap);
    va_end(ap);
    CRM_ASSERT(len > 0);

    crm_xml_sanitize_id(id);
    crm_xml_add(xml, PCMK_XA_ID, id);
    free(id);
}

/*!
 * \internal
 * \brief Get consecutive bytes encoding non-ASCII UTF-8 characters
 *
 * \param[in] text  String to check
 *
 * \return Number of non-ASCII UTF-8 bytes at the beginning of \p text
 */
static size_t
utf8_bytes(const char *text)
{
    // Total number of consecutive bytes containing UTF-8 characters
    size_t c_bytes = 0;

    if (text == NULL) {
        return 0;
    }

    /* UTF-8 uses one to four 8-bit bytes per character. The first byte
     * indicates the width of the character. A byte beginning with a '0' bit is
     * a one-byte ASCII character.
     *
     * A C byte is 8 bits on most systems, but this is not guaranteed.
     *
     * Count until we find an ASCII character or an invalid byte. Check bytes
     * aligned with the C byte boundary.
     */
    for (const uint8_t *utf8_byte = (const uint8_t *) text;
         (*utf8_byte & 0x80) != 0;
         utf8_byte = (const uint8_t *) (text + c_bytes)) {

        size_t utf8_bits = 0;

        if ((*utf8_byte & 0xf0) == 0xf0) {
            // Four-byte character (first byte: 11110xxx)
            utf8_bits = 32;

        } else if ((*utf8_byte & 0xe0) == 0xe0) {
            // Three-byte character (first byte: 1110xxxx)
            utf8_bits = 24;

        } else if ((*utf8_byte & 0xc0) == 0xc0) {
            // Two-byte character (first byte: 110xxxxx)
            utf8_bits = 16;

        } else {
            crm_warn("Found invalid UTF-8 character %.2x",
                     (unsigned char) *utf8_byte);
            return c_bytes;
        }

        c_bytes += utf8_bits / CHAR_BIT;

#if (CHAR_BIT != 8) // Coverity complains about dead code without this CPP guard
        if ((utf8_bits % CHAR_BIT) > 0) {
            c_bytes++;
        }
#endif  // CHAR_BIT != 8
    }

    return c_bytes;
}

/*!
 * \internal
 * \brief Replace a character in a dynamically allocated string, reallocating
 *        memory
 *
 * \param[in,out] text     String to replace a character in
 * \param[in,out] index    Index of character to replace with new string; on
 *                         return, reset to index of end of replacement string
 * \param[in,out] length   Length of \p text
 * \param[in]     replace  String to replace character at \p index with (must
 *                         not be empty)
 *
 * \return \p text, with the character at \p index replaced by \p replace
 */
static char *
replace_text(char *text, size_t *index, size_t *length, const char *replace)
{
    /* @TODO Replace with GString? Or at least copy char-by-char, escaping
     * characters as needed, instead of shifting characters on every replacement
     */

    // We have space for 1 char already
    size_t offset = strlen(replace) - 1;

    if (offset > 0) {
        *length += offset;
        text = pcmk__realloc(text, *length + 1);

        // Shift characters to the right to make room for the replacement string
        for (size_t i = *length; i > (*index + offset); i--) {
            text[i] = text[i - offset];
        }
    }

    // Replace the character at index by the replacement string
    memcpy(text + *index, replace, offset + 1);

    // Reset index to the end of replacement string
    *index += offset;
    return text;
}

/*!
 * \internal
 * \brief Check whether a string has XML special characters that must be escaped
 *
 * See \c pcmk__xml_escape() for more details.
 *
 * \param[in] text          String to check
 * \param[in] escape_quote  If \c true, double quotes must be escaped
 *
 * \return \c true if \p text has special characters that need to be escaped, or
 *         \c false otherwise
 */
bool
pcmk__xml_needs_escape(const char *text, bool escape_quote)
{
    size_t length = 0;

    if (text == NULL) {
        return false;
    }
    length = strlen(text);

    for (size_t index = 0; index < length; index++) {
        // Don't escape any non-ASCII characters
        index += utf8_bytes(&(text[index]));

        switch (text[index]) {
            case '\0':
                // Reached end of string by skipping UTF-8 bytes
                return false;
            case '<':
                return true;
            case '>':
                // Not necessary, but for symmetry with '<'
                return true;
            case '&':
                return true;
            case '"':
                if (escape_quote) {
                    return true;
                }
                break;
            case '\n':
            case '\t':
                // Don't escape newline or tab
                break;
            default:
                if ((text[index] < 0x20) || (text[index] >= 0x7f)) {
                    // Escape non-printing characters
                    return true;
                }
                break;
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Replace special characters with their XML escape sequences
 *
 * XML allows the escaping of special characters by replacing them with entity
 * references (for example, <tt>"&quot;"</tt>) or character references (for
 * example, <tt>"&#13;"</tt>).
 *
 * The special characters <tt>'<'</tt> and <tt>'&'</tt> are not allowed in their
 * literal forms in XML character data. Character data is non-markup text (for
 * example, the content of a text node).
 *
 * Additionally, if an attribute value is delimited by single quotes, then
 * single quotes must be escaped within the value. Similarly, if an attribute
 * value is delimited by double quotes, then double quotes must be escaped
 * within the value.
 *
 * For more details, see the "Character Data and Markup" section of the XML
 * spec, currently section 2.4:
 * https://www.w3.org/TR/xml/#dt-markup
 *
 * Pacemaker always delimits attribute values with double quotes, so this
 * function doesn't escape single quotes.
 *
 * \param[in] text          Text to escape
 * \param[in] escape_quote  If \c true, escape double quotes (should be enabled
 *                          for attribute values)
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
 */
char *
pcmk__xml_escape(const char *text, bool escape_quote)
{
    size_t length = 0;
    char *copy = NULL;
    char buf[32] = { '\0', };

    if (text == NULL) {
        return NULL;
    }
    length = strlen(text);
    copy = pcmk__str_copy(text);

    for (size_t index = 0; index < length; index++) {
        // Don't escape any non-ASCII characters
        index += utf8_bytes(&(copy[index]));

        switch (copy[index]) {
            case '\0':
                // Reached end of string by skipping UTF-8 bytes
                break;
            case '<':
                copy = replace_text(copy, &index, &length, "&lt;");
                break;
            case '>':
                // Not necessary, but for symmetry with '<'
                copy = replace_text(copy, &index, &length, "&gt;");
                break;
            case '&':
                copy = replace_text(copy, &index, &length, "&amp;");
                break;
            case '"':
                if (escape_quote) {
                    copy = replace_text(copy, &index, &length, "&quot;");
                }
                break;
            case '\n':
            case '\t':
                // Don't escape newlines and tabs
                break;
            default:
                if ((copy[index] < 0x20) || (copy[index] >= 0x7f)) {
                    // Escape non-printing characters
                    snprintf(buf, sizeof(buf), "&#x%.2x;", copy[index]);
                    copy = replace_text(copy, &index, &length, buf);
                }
                break;
        }
    }
    return copy;
}

/*!
 * \internal
 * \brief Set a flag on all attributes of an XML element
 *
 * \param[in,out] xml   XML node to set flags on
 * \param[in]     flag  XML private flag to set
 */
static void
set_attrs_flag(xmlNode *xml, enum xml_private_flags flag)
{
    for (xmlAttr *attr = pcmk__xe_first_attr(xml); attr; attr = attr->next) {
        pcmk__set_xml_flags((xml_node_private_t *) (attr->_private), flag);
    }
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

    // Prevent the dirty flag being set recursively upwards
    pcmk__clear_xml_flags(docpriv, pcmk__xf_tracking);

    // Restore the old value (and the tracking flag)
    attr = xmlSetProp(new_xml, (pcmkXmlStr) attr_name, (pcmkXmlStr) old_value);
    pcmk__set_xml_flags(docpriv, pcmk__xf_tracking);

    // Reset flags (so the attribute doesn't appear as newly created)
    nodepriv = attr->_private;
    nodepriv->flags = 0;

    // Check ACLs and mark restored value for later removal
    remove_xe_attr(new_xml, attr);

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
    char *vcopy = crm_element_value_copy(new_xml, attr_name);

    crm_trace("XML attribute %s was changed from '%s' to '%s' in %s",
              attr_name, old_value, vcopy, element);

    // Restore the original value
    xmlSetProp(new_xml, (pcmkXmlStr) attr_name, (pcmkXmlStr) old_value);

    // Change it back to the new value, to check ACLs
    crm_xml_add(new_xml, attr_name, vcopy);
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
            const char *new_value = crm_element_value(new_xml, name);

            // This attribute isn't new
            pcmk__clear_xml_flags(nodepriv, pcmk__xf_created);

            if (strcmp(new_value, old_value) != 0) {
                mark_attr_changed(new_xml, (const char *) old_xml->name, name,
                                  old_value);

            } else if ((old_pos != new_pos)
                       && !pcmk__tracking_xml_changes(new_xml, TRUE)) {
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
                xmlUnsetProp(new_xml, new_attr->name);
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
    set_attrs_flag(new_xml, pcmk__xf_created); // cleared later if not really new
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
    reset_xml_node_flags(candidate);

    // Check whether ACLs allow the deletion
    pcmk__apply_acl(xmlDocGetRootElement(candidate->doc));

    // Remove the child again (which will track it in document's deleted_objs)
    free_xml_with_position(candidate,
                           pcmk__xml_position(old_child, pcmk__xf_skip));

    if (pcmk__xml_match(new_parent, old_child, true) == NULL) {
        pcmk__set_xml_flags((xml_node_private_t *) (old_child->_private),
                            pcmk__xf_skip);
    }
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

// Given original and new XML, mark new XML portions that have changed
static void
mark_xml_changes(xmlNode *old_xml, xmlNode *new_xml, bool check_top)
{
    xmlNode *cIter = NULL;
    xml_node_private_t *nodepriv = NULL;

    CRM_CHECK(new_xml != NULL, return);
    if (old_xml == NULL) {
        pcmk__mark_xml_created(new_xml);
        pcmk__apply_creation_acl(new_xml, check_top);
        return;
    }

    nodepriv = new_xml->_private;
    CRM_CHECK(nodepriv != NULL, return);

    if(nodepriv->flags & pcmk__xf_processed) {
        /* Avoid re-comparing nodes */
        return;
    }
    pcmk__set_xml_flags(nodepriv, pcmk__xf_processed);

    xml_diff_attrs(old_xml, new_xml);

    // Check for differences in the original children
    for (cIter = pcmk__xml_first_child(old_xml); cIter != NULL; ) {
        xmlNode *old_child = cIter;
        xmlNode *new_child = pcmk__xml_match(new_xml, cIter, true);

        cIter = pcmk__xml_next(cIter);
        if(new_child) {
            mark_xml_changes(old_child, new_child, TRUE);

        } else {
            mark_child_deleted(old_child, new_xml);
        }
    }

    // Check for moved or created children
    for (cIter = pcmk__xml_first_child(new_xml); cIter != NULL; ) {
        xmlNode *new_child = cIter;
        xmlNode *old_child = pcmk__xml_match(old_xml, cIter, true);

        cIter = pcmk__xml_next(cIter);
        if(old_child == NULL) {
            // This is a newly created child
            nodepriv = new_child->_private;
            pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);
            mark_xml_changes(old_child, new_child, TRUE);

        } else {
            /* Check for movement, we already checked for differences */
            int p_new = pcmk__xml_position(new_child, pcmk__xf_skip);
            int p_old = pcmk__xml_position(old_child, pcmk__xf_skip);

            if(p_old != p_new) {
                mark_child_moved(old_child, new_xml, new_child, p_old, p_new);
            }
        }
    }
}

void
xml_calculate_significant_changes(xmlNode *old_xml, xmlNode *new_xml)
{
    pcmk__set_xml_doc_flag(new_xml, pcmk__xf_lazy);
    xml_calculate_changes(old_xml, new_xml);
}

// Called functions may set the \p pcmk__xf_skip flag on parts of \p old_xml
void
xml_calculate_changes(xmlNode *old_xml, xmlNode *new_xml)
{
    CRM_CHECK((old_xml != NULL) && (new_xml != NULL)
              && pcmk__xe_is(old_xml, (const char *) new_xml->name)
              && pcmk__str_eq(pcmk__xe_id(old_xml), pcmk__xe_id(new_xml),
                              pcmk__str_none),
              return);

    if(xml_tracking_changes(new_xml) == FALSE) {
        xml_track_changes(new_xml, NULL, NULL, FALSE);
    }

    mark_xml_changes(old_xml, new_xml, FALSE);
}

/*!
 * \internal
 * \brief Find a comment with matching content in specified XML
 *
 * \param[in] root            XML to search
 * \param[in] search_comment  Comment whose content should be searched for
 * \param[in] exact           If true, comment must also be at same position
 */
xmlNode *
pcmk__xc_match(const xmlNode *root, const xmlNode *search_comment, bool exact)
{
    xmlNode *a_child = NULL;
    int search_offset = pcmk__xml_position(search_comment, pcmk__xf_skip);

    CRM_CHECK(search_comment->type == XML_COMMENT_NODE, return NULL);

    for (a_child = pcmk__xml_first_child(root); a_child != NULL;
         a_child = pcmk__xml_next(a_child)) {
        if (exact) {
            int offset = pcmk__xml_position(a_child, pcmk__xf_skip);
            xml_node_private_t *nodepriv = a_child->_private;

            if (offset < search_offset) {
                continue;

            } else if (offset > search_offset) {
                return NULL;
            }

            if (pcmk_is_set(nodepriv->flags, pcmk__xf_skip)) {
                continue;
            }
        }

        if (a_child->type == XML_COMMENT_NODE
            && pcmk__str_eq((const char *)a_child->content, (const char *)search_comment->content, pcmk__str_casei)) {
            return a_child;

        } else if (exact) {
            return NULL;
        }
    }

    return NULL;
}

/*!
 * \internal
 * \brief Make one XML comment match another (in content)
 *
 * \param[in,out] parent   If \p target is NULL and this is not, add or update
 *                         comment child of this XML node that matches \p update
 * \param[in,out] target   If not NULL, update this XML comment node
 * \param[in]     update   Make comment content match this (must not be NULL)
 *
 * \note At least one of \parent and \target must be non-NULL
 */
void
pcmk__xc_update(xmlNode *parent, xmlNode *target, xmlNode *update)
{
    CRM_CHECK(update != NULL, return);
    CRM_CHECK(update->type == XML_COMMENT_NODE, return);

    if (target == NULL) {
        target = pcmk__xc_match(parent, update, false);
    }

    if (target == NULL) {
        pcmk__xml_copy(parent, update);

    } else if (!pcmk__str_eq((const char *)target->content, (const char *)update->content, pcmk__str_casei)) {
        xmlFree(target->content);
        target->content = xmlStrdup(update->content);
    }
}

/*!
 * \internal
 * \brief Make one XML tree match another (in children and attributes)
 *
 * \param[in,out] parent   If \p target is NULL and this is not, add or update
 *                         child of this XML node that matches \p update
 * \param[in,out] target   If not NULL, update this XML
 * \param[in]     update   Make the desired XML match this (must not be NULL)
 * \param[in]     as_diff  If false, expand "++" when making attributes match
 *
 * \note At least one of \p parent and \p target must be non-NULL
 */
void
pcmk__xml_update(xmlNode *parent, xmlNode *target, xmlNode *update,
                 bool as_diff)
{
    xmlNode *a_child = NULL;
    const char *object_name = NULL,
               *object_href = NULL,
               *object_href_val = NULL;

#if XML_PARSER_DEBUG
    crm_log_xml_trace(update, "update:");
    crm_log_xml_trace(target, "target:");
#endif

    CRM_CHECK(update != NULL, return);

    if (update->type == XML_COMMENT_NODE) {
        pcmk__xc_update(parent, target, update);
        return;
    }

    object_name = (const char *) update->name;
    object_href_val = pcmk__xe_id(update);
    if (object_href_val != NULL) {
        object_href = PCMK_XA_ID;
    } else {
        object_href_val = crm_element_value(update, PCMK_XA_ID_REF);
        object_href = (object_href_val == NULL)? NULL : PCMK_XA_ID_REF;
    }

    CRM_CHECK(object_name != NULL, return);
    CRM_CHECK(target != NULL || parent != NULL, return);

    if (target == NULL) {
        target = pcmk__xe_first_child(parent, object_name,
                                      object_href, object_href_val);
    }

    if (target == NULL) {
        target = pcmk__xe_create(parent, object_name);
#if XML_PARSER_DEBUG
        crm_trace("Added  <%s%s%s%s%s/>", pcmk__s(object_name, "<null>"),
                  object_href ? " " : "",
                  object_href ? object_href : "",
                  object_href ? "=" : "",
                  object_href ? object_href_val : "");

    } else {
        crm_trace("Found node <%s%s%s%s%s/> to update",
                  pcmk__s(object_name, "<null>"),
                  object_href ? " " : "",
                  object_href ? object_href : "",
                  object_href ? "=" : "",
                  object_href ? object_href_val : "");
#endif
    }

    CRM_CHECK(pcmk__xe_is(target, (const char *) update->name), return);

    if (as_diff == FALSE) {
        /* So that expand_plus_plus() gets called */
        copy_in_properties(target, update);

    } else {
        /* No need for expand_plus_plus(), just raw speed */
        for (xmlAttrPtr a = pcmk__xe_first_attr(update); a != NULL;
             a = a->next) {
            const char *p_value = pcmk__xml_attr_value(a);

            /* Remove it first so the ordering of the update is preserved */
            xmlUnsetProp(target, a->name);
            xmlSetProp(target, a->name, (pcmkXmlStr) p_value);
        }
    }

    for (a_child = pcmk__xml_first_child(update); a_child != NULL;
         a_child = pcmk__xml_next(a_child)) {
#if XML_PARSER_DEBUG
        crm_trace("Updating child <%s%s%s%s%s/>",
                  pcmk__s(object_name, "<null>"),
                  object_href ? " " : "",
                  object_href ? object_href : "",
                  object_href ? "=" : "",
                  object_href ? object_href_val : "");
#endif
        pcmk__xml_update(target, NULL, a_child, as_diff);
    }

#if XML_PARSER_DEBUG
    crm_trace("Finished with <%s%s%s%s%s/>", pcmk__s(object_name, "<null>"),
              object_href ? " " : "",
              object_href ? object_href : "",
              object_href ? "=" : "",
              object_href ? object_href_val : "");
#endif
}

gboolean
update_xml_child(xmlNode * child, xmlNode * to_update)
{
    gboolean can_update = TRUE;
    xmlNode *child_of_child = NULL;

    CRM_CHECK(child != NULL, return FALSE);
    CRM_CHECK(to_update != NULL, return FALSE);

    if (!pcmk__xe_is(to_update, (const char *) child->name)) {
        can_update = FALSE;

    } else if (!pcmk__str_eq(pcmk__xe_id(to_update), pcmk__xe_id(child),
                             pcmk__str_none)) {
        can_update = FALSE;

    } else if (can_update) {
#if XML_PARSER_DEBUG
        crm_log_xml_trace(child, "Update match found...");
#endif
        pcmk__xml_update(NULL, child, to_update, false);
    }

    for (child_of_child = pcmk__xml_first_child(child); child_of_child != NULL;
         child_of_child = pcmk__xml_next(child_of_child)) {
        /* only update the first one */
        if (can_update) {
            break;
        }
        can_update = update_xml_child(child_of_child, to_update);
    }

    return can_update;
}

int
find_xml_children(xmlNode ** children, xmlNode * root,
                  const char *tag, const char *field, const char *value, gboolean search_matches)
{
    int match_found = 0;

    CRM_CHECK(root != NULL, return FALSE);
    CRM_CHECK(children != NULL, return FALSE);

    if ((tag != NULL) && !pcmk__xe_is(root, tag)) {

    } else if (value != NULL && !pcmk__str_eq(value, crm_element_value(root, field), pcmk__str_casei)) {

    } else {
        if (*children == NULL) {
            *children = pcmk__xe_create(NULL, __func__);
        }
        pcmk__xml_copy(*children, root);
        match_found = 1;
    }

    if (search_matches || match_found == 0) {
        xmlNode *child = NULL;

        for (child = pcmk__xml_first_child(root); child != NULL;
             child = pcmk__xml_next(child)) {
            match_found += find_xml_children(children, child, tag, field, value, search_matches);
        }
    }

    return match_found;
}

gboolean
replace_xml_child(xmlNode * parent, xmlNode * child, xmlNode * update, gboolean delete_only)
{
    gboolean can_delete = FALSE;
    xmlNode *child_of_child = NULL;

    const char *up_id = NULL;
    const char *child_id = NULL;
    const char *right_val = NULL;

    CRM_CHECK(child != NULL, return FALSE);
    CRM_CHECK(update != NULL, return FALSE);

    up_id = pcmk__xe_id(update);
    child_id = pcmk__xe_id(child);

    if (up_id == NULL || (child_id && strcmp(child_id, up_id) == 0)) {
        can_delete = TRUE;
    }
    if (!pcmk__xe_is(update, (const char *) child->name)) {
        can_delete = FALSE;
    }
    if (can_delete && delete_only) {
        for (xmlAttrPtr a = pcmk__xe_first_attr(update); a != NULL;
             a = a->next) {
            const char *p_name = (const char *) a->name;
            const char *p_value = pcmk__xml_attr_value(a);

            right_val = crm_element_value(child, p_name);
            if (!pcmk__str_eq(p_value, right_val, pcmk__str_casei)) {
                can_delete = FALSE;
            }
        }
    }

    if (can_delete && parent != NULL) {
        crm_log_xml_trace(child, "Delete match found...");
        if (delete_only || update == NULL) {
            free_xml(child);

        } else {
            xmlNode *old = child;
            xmlNode *new = xmlCopyNode(update, 1);

            pcmk__mem_assert(new);

            // May be unnecessary but avoids slight changes to some test outputs
            reset_xml_node_flags(new);

            old = xmlReplaceNode(old, new);

            if (xml_tracking_changes(new)) {
                // Replaced sections may have included relevant ACLs
                pcmk__apply_acl(new);
            }
            xml_calculate_changes(old, new);
            xmlFreeNode(old);
        }
        return TRUE;

    } else if (can_delete) {
        crm_log_xml_debug(child, "Cannot delete the search root");
        can_delete = FALSE;
    }

    child_of_child = pcmk__xml_first_child(child);
    while (child_of_child) {
        xmlNode *next = pcmk__xml_next(child_of_child);

        can_delete = replace_xml_child(child, child_of_child, update, delete_only);

        /* only delete the first one */
        if (can_delete) {
            child_of_child = NULL;
        } else {
            child_of_child = next;
        }
    }

    return can_delete;
}

xmlNode *
sorted_xml(xmlNode *input, xmlNode *parent, gboolean recursive)
{
    xmlNode *child = NULL;
    GSList *nvpairs = NULL;
    xmlNode *result = NULL;

    CRM_CHECK(input != NULL, return NULL);

    result = pcmk__xe_create(parent, (const char *) input->name);
    nvpairs = pcmk_xml_attrs2nvpairs(input);
    nvpairs = pcmk_sort_nvpairs(nvpairs);
    pcmk_nvpairs2xml_attrs(nvpairs, result);
    pcmk_free_nvpairs(nvpairs);

    for (child = pcmk__xe_first_child(input, NULL, NULL, NULL); child != NULL;
         child = pcmk__xe_next(child)) {

        if (recursive) {
            sorted_xml(child, result, recursive);
        } else {
            pcmk__xml_copy(result, child);
        }
    }

    return result;
}

/*!
 * \internal
 * \brief Get next sibling XML element with the same name as a given element
 *
 * \param[in] node  XML element to start from
 *
 * \return Next sibling XML element with same name
 */
xmlNode *
pcmk__xe_next_same(const xmlNode *node)
{
    for (xmlNode *match = pcmk__xe_next(node); match != NULL;
         match = pcmk__xe_next(match)) {

        if (pcmk__xe_is(match, (const char *) node->name)) {
            return match;
        }
    }
    return NULL;
}

void
crm_xml_init(void)
{
    static bool init = true;

    if(init) {
        init = false;
        /* The default allocator XML_BUFFER_ALLOC_EXACT does far too many
         * pcmk__realloc()s and it can take upwards of 18 seconds (yes, seconds)
         * to dump a 28kb tree which XML_BUFFER_ALLOC_DOUBLEIT can do in
         * less than 1 second.
         */
        xmlSetBufferAllocationScheme(XML_BUFFER_ALLOC_DOUBLEIT);

        /* Populate and free the _private field when nodes are created and destroyed */
        xmlDeregisterNodeDefault(free_private_data);
        xmlRegisterNodeDefault(new_private_data);

        crm_schema_init();
    }
}

void
crm_xml_cleanup(void)
{
    crm_schema_cleanup();
    xmlCleanupParser();
}

#define XPATH_MAX 512

xmlNode *
expand_idref(xmlNode * input, xmlNode * top)
{
    char *xpath = NULL;
    const char *ref = NULL;
    xmlNode *result = NULL;

    if (input == NULL) {
        return NULL;
    }

    ref = crm_element_value(input, PCMK_XA_ID_REF);
    if (ref == NULL) {
        return input;
    }

    if (top == NULL) {
        top = input;
    }

    xpath = crm_strdup_printf("//%s[@" PCMK_XA_ID "='%s']", input->name, ref);
    result = get_xpath_object(xpath, top, LOG_DEBUG);
    if (result == NULL) { // Not possible with schema validation enabled
        pcmk__config_err("Ignoring invalid %s configuration: "
                         PCMK_XA_ID_REF " '%s' does not reference "
                         "a valid object " CRM_XS " xpath=%s",
                         input->name, ref, xpath);
    }
    free(xpath);
    return result;
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
        base = CRM_SCHEMA_DIRECTORY;
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
        ret = find_artefact(ns, remote_schema_dir, filespec);
    }

    return ret;
}

void
pcmk__xe_set_propv(xmlNodePtr node, va_list pairs)
{
    while (true) {
        const char *name, *value;

        name = va_arg(pairs, const char *);
        if (name == NULL) {
            return;
        }

        value = va_arg(pairs, const char *);
        if (value != NULL) {
            crm_xml_add(node, name, value);
        }
    }
}

void
pcmk__xe_set_props(xmlNodePtr node, ...)
{
    va_list pairs;
    va_start(pairs, node);
    pcmk__xe_set_propv(node, pairs);
    va_end(pairs);
}

int
pcmk__xe_foreach_child(xmlNode *xml, const char *child_element_name,
                       int (*handler)(xmlNode *xml, void *userdata),
                       void *userdata)
{
    xmlNode *children = (xml? xml->children : NULL);

    CRM_ASSERT(handler != NULL);

    for (xmlNode *node = children; node != NULL; node = node->next) {
        if ((node->type == XML_ELEMENT_NODE)
            && ((child_element_name == NULL)
                || pcmk__xe_is(node, child_element_name))) {
            int rc = handler(node, userdata);

            if (rc != pcmk_rc_ok) {
                return rc;
            }
        }
    }

    return pcmk_rc_ok;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

xmlNode *
find_entity(xmlNode *parent, const char *node_name, const char *id)
{
    return pcmk__xe_first_child(parent, node_name,
                                ((id == NULL)? id : PCMK_XA_ID), id);
}

void
crm_destroy_xml(gpointer data)
{
    free_xml(data);
}

xmlDoc *
getDocPtr(xmlNode *node)
{
    xmlDoc *doc = NULL;

    CRM_CHECK(node != NULL, return NULL);

    doc = node->doc;
    if (doc == NULL) {
        doc = xmlNewDoc(PCMK__XML_VERSION);
        xmlDocSetRootElement(doc, node);
    }
    return doc;
}

xmlNode *
add_node_copy(xmlNode *parent, xmlNode *src_node)
{
    xmlNode *child = NULL;

    CRM_CHECK((parent != NULL) && (src_node != NULL), return NULL);

    child = xmlDocCopyNode(src_node, parent->doc, 1);
    if (child == NULL) {
        return NULL;
    }
    xmlAddChild(parent, child);
    pcmk__mark_xml_created(child);
    return child;
}

int
add_node_nocopy(xmlNode *parent, const char *name, xmlNode *child)
{
    add_node_copy(parent, child);
    free_xml(child);
    return 1;
}

gboolean
xml_has_children(const xmlNode * xml_root)
{
    if (xml_root != NULL && xml_root->children != NULL) {
        return TRUE;
    }
    return FALSE;
}

char *
crm_xml_escape(const char *text)
{
    size_t length = 0;
    char *copy = NULL;

    if (text == NULL) {
        return NULL;
    }

    length = strlen(text);
    copy = pcmk__str_copy(text);
    for (size_t index = 0; index <= length; index++) {
        if(copy[index] & 0x80 && copy[index+1] & 0x80){
            index++;
            continue;
        }
        switch (copy[index]) {
            case 0:
                // Sanity only; loop should stop at the last non-null byte
                break;
            case '<':
                copy = replace_text(copy, &index, &length, "&lt;");
                break;
            case '>':
                copy = replace_text(copy, &index, &length, "&gt;");
                break;
            case '"':
                copy = replace_text(copy, &index, &length, "&quot;");
                break;
            case '\'':
                copy = replace_text(copy, &index, &length, "&apos;");
                break;
            case '&':
                copy = replace_text(copy, &index, &length, "&amp;");
                break;
            case '\t':
                /* Might as well just expand to a few spaces... */
                copy = replace_text(copy, &index, &length, "    ");
                break;
            case '\n':
                copy = replace_text(copy, &index, &length, "\\n");
                break;
            case '\r':
                copy = replace_text(copy, &index, &length, "\\r");
                break;
            default:
                /* Check for and replace non-printing characters with their octal equivalent */
                if(copy[index] < ' ' || copy[index] > '~') {
                    char *replace = crm_strdup_printf("\\%.3o", copy[index]);

                    copy = replace_text(copy, &index, &length, replace);
                    free(replace);
                }
        }
    }
    return copy;
}

xmlNode *
copy_xml(xmlNode *src)
{
    xmlDoc *doc = xmlNewDoc(PCMK__XML_VERSION);
    xmlNode *copy = NULL;

    pcmk__mem_assert(doc);

    copy = xmlDocCopyNode(src, doc, 1);
    pcmk__mem_assert(copy);

    xmlDocSetRootElement(doc, copy);
    return copy;
}

xmlNode *
create_xml_node(xmlNode *parent, const char *name)
{
    // Like pcmk__xe_create(), but returns NULL on failure
    xmlNode *node = NULL;

    CRM_CHECK(!pcmk__str_empty(name), return NULL);

    if (parent == NULL) {
        xmlDoc *doc = xmlNewDoc(PCMK__XML_VERSION);

        if (doc == NULL) {
            return NULL;
        }

        node = xmlNewDocRawNode(doc, NULL, (pcmkXmlStr) name, NULL);
        if (node == NULL) {
            xmlFreeDoc(doc);
            return NULL;
        }
        xmlDocSetRootElement(doc, node);

    } else {
        node = xmlNewChild(parent, NULL, (pcmkXmlStr) name, NULL);
        if (node == NULL) {
            return NULL;
        }
    }
    pcmk__mark_xml_created(node);
    return node;
}

xmlNode *
pcmk_create_xml_text_node(xmlNode *parent, const char *name,
                          const char *content)
{
    xmlNode *node = pcmk__xe_create(parent, name);

    pcmk__xe_set_content(node, "%s", content);
    return node;
}

xmlNode *
pcmk_create_html_node(xmlNode *parent, const char *element_name, const char *id,
                      const char *class_name, const char *text)
{
    xmlNode *node = pcmk__html_create(parent, element_name, id, class_name);

    pcmk__xe_set_content(node, "%s", text);
    return node;
}

xmlNode *
first_named_child(const xmlNode *parent, const char *name)
{
    return pcmk__xe_first_child(parent, name, NULL, NULL);
}

xmlNode *
find_xml_node(const xmlNode *root, const char *search_path, gboolean must_find)
{
    xmlNode *result = NULL;

    if (search_path == NULL) {
        crm_warn("Will never find <NULL>");
        return NULL;
    }

    result = pcmk__xe_first_child(root, search_path, NULL, NULL);

    if (must_find && (result == NULL)) {
        crm_warn("Could not find %s in %s",
                 search_path,
                 ((root != NULL)? (const char *) root->name : "<NULL>"));
    }

    return result;
}

xmlNode *
crm_next_same_xml(const xmlNode *sibling)
{
    return pcmk__xe_next_same(sibling);
}

void
xml_remove_prop(xmlNode * obj, const char *name)
{
    pcmk__xe_remove_attr(obj, name);
}

// LCOV_EXCL_STOP
// End deprecated API

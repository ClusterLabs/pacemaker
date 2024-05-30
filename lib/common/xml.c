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
#include <stdint.h>                     // uint32_t
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
static bool
reset_xml_node_flags(xmlNode *xml, void *user_data)
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
void
pcmk__xml_mark_created(xmlNode *xml)
{
    CRM_ASSERT(xml != NULL);

    if (!pcmk__tracking_xml_changes(xml, false)) {
        // Tracking is disabled for entire document
        return;
    }

    // Mark all parents and document dirty
    pcmk__mark_xml_node_dirty(xml);

    pcmk__xml_tree_foreach(xml, mark_xml_dirty_created, NULL);
}

#define XML_DOC_PRIVATE_MAGIC   0x81726354UL
#define XML_NODE_PRIVATE_MAGIC  0x54637281UL

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
accept_attr_deletions(xmlNode *xml, void *user_data)
{
    reset_xml_node_flags(xml, NULL);
    pcmk__xe_remove_matching_attrs(xml, pcmk__marked_as_deleted, NULL);
    return true;
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
    pcmk__xml_tree_foreach(top, accept_attr_deletions, NULL);
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

/*!
 * \internal
 * \brief Set an XML attribute, expanding \c ++ and \c += where appropriate
 *
 * If \p target already has an attribute named \p name set to an integer value
 * and \p value is an addition assignment expression on \p name, then expand
 * \p value to an integer and set attribute \p name to the expanded value in
 * \p target.
 *
 * Otherwise, set attribute \p name on \p target using the literal \p value.
 *
 * The original attribute value in \p target and the number in an assignment
 * expression in \p value are parsed and added as scores (that is, their values
 * are capped at \c INFINITY and \c -INFINITY). For more details, refer to
 * \c char2score().
 *
 * For example, suppose \p target has an attribute named \c "X" with value
 * \c "5", and that \p name is \c "X".
 * * If \p value is \c "X++", the new value of \c "X" in \p target is \c "6".
 * * If \p value is \c "X+=3", the new value of \c "X" in \p target is \c "8".
 * * If \p value is \c "val", the new value of \c "X" in \p target is \c "val".
 * * If \p value is \c "Y++", the new value of \c "X" in \p target is \c "Y++".
 *
 * \param[in,out] target  XML node whose attribute to set
 * \param[in]     name    Name of the attribute to set
 * \param[in]     value   New value of attribute to set
 *
 * \return Standard Pacemaker return code (specifically, \c EINVAL on invalid
 *         argument, or \c pcmk_rc_ok otherwise)
 */
int
pcmk__xe_set_score(xmlNode *target, const char *name, const char *value)
{
    const char *old_value = NULL;

    CRM_CHECK((target != NULL) && (name != NULL), return EINVAL);

    if (value == NULL) {
        return pcmk_rc_ok;
    }

    old_value = crm_element_value(target, name);

    // If no previous value, skip to default case and set the value unexpanded.
    if (old_value != NULL) {
        const char *n = name;
        const char *v = value;

        // Stop at first character that differs between name and value
        for (; (*n == *v) && (*n != '\0'); n++, v++);

        // If value begins with name followed by a "++" or "+="
        if ((*n == '\0')
            && (*v++ == '+')
            && ((*v == '+') || (*v == '='))) {

            // If we're expanding ourselves, no previous value was set; use 0
            int old_value_i = (old_value != value)? char2score(old_value) : 0;

            /* value="X++": new value of X is old_value + 1
             * value="X+=Y": new value of X is old_value + Y (for some number Y)
             */
            int add = (*v == '+')? 1 : char2score(++v);

            crm_xml_add_int(target, name, pcmk__add_scores(old_value_i, add));
            return pcmk_rc_ok;
        }
    }

    // Default case: set the attribute unexpanded (with value treated literally)
    if (old_value != value) {
        crm_xml_add(target, name, value);
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Copy XML attributes from a source element to a target element
 *
 * This is similar to \c xmlCopyPropList() except that attributes are marked
 * as dirty for change tracking purposes.
 *
 * \param[in,out] target  XML element to receive copied attributes from \p src
 * \param[in]     src     XML element whose attributes to copy to \p target
 * \param[in]     flags   Group of <tt>enum pcmk__xa_flags</tt>
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_copy_attrs(xmlNode *target, const xmlNode *src, uint32_t flags)
{
    CRM_CHECK((src != NULL) && (target != NULL), return EINVAL);

    for (xmlAttr *attr = pcmk__xe_first_attr(src); attr != NULL;
         attr = attr->next) {

        const char *name = (const char *) attr->name;
        const char *value = pcmk__xml_attr_value(attr);

        if (pcmk_is_set(flags, pcmk__xaf_no_overwrite)
            && (crm_element_value(target, name) != NULL)) {
            continue;
        }

        if (pcmk_is_set(flags, pcmk__xaf_score_update)) {
            pcmk__xe_set_score(target, name, value);
        } else {
            crm_xml_add(target, name, value);
        }
    }

    return pcmk_rc_ok;
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
 * \brief Remove a named attribute from an XML element
 *
 * This is a wrapper for \c pcmk__xe_remove_attr() for use with
 * \c pcmk__xml_tree_foreach().
 *
 * \param[in,out] xml        XML element to remove an attribute from
 * \param[in]     user_data  Name of attribute to remove
 *
 * \return \c true (to continue traversing the tree)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
bool
pcmk__xe_remove_attr_cb(xmlNode *xml, void *user_data)
{
    const char *name = user_data;

    pcmk__xe_remove_attr(xml, name);
    return true;
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

    pcmk__xml_mark_created(node);
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

        xmlNodeSetContent(node, (pcmkXmlStr) content);
        free(buf);
    }
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
        xmlFreeDoc(doc);
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

    if ((doc != NULL) && pcmk__tracking_xml_changes(node, false)
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
            pcmk__set_xml_doc_flag(node, pcmk__xf_dirty);
        }
    }
    xmlUnlinkNode(node);
    xmlFreeNode(node);
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

    pcmk__xml_mark_created(copy);
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
                xmlUnlinkNode(iter);
                xmlFreeNode(iter);
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
                CRM_ASSERT(false);
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
                CRM_ASSERT(false);
                break;
        }

        text = g_utf8_next_char(text);
    }
    return g_string_free(copy, FALSE);
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
    pcmk__xml_tree_foreach(candidate, reset_xml_node_flags, NULL);

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
    xmlNode *old_child = NULL;
    xmlNode *new_child = NULL;
    xml_node_private_t *nodepriv = NULL;

    CRM_CHECK(new_xml != NULL, return);
    if (old_xml == NULL) {
        pcmk__xml_mark_created(new_xml);
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
    for (old_child = pcmk__xml_first_child(old_xml); old_child != NULL;
         old_child = pcmk__xml_next(old_child)) {

        new_child = pcmk__xml_match(new_xml, old_child, true);

        if (new_child != NULL) {
            mark_xml_changes(old_child, new_child, true);

        } else {
            mark_child_deleted(old_child, new_xml);
        }
    }

    // Check for moved or created children
    new_child = pcmk__xml_first_child(new_xml);
    while (new_child != NULL) {
        xmlNode *next = pcmk__xml_next(new_child);

        old_child = pcmk__xml_match(old_xml, new_child, true);

        if (old_child == NULL) {
            // This is a newly created child
            nodepriv = new_child->_private;
            pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);

            // May free new_child
            mark_xml_changes(old_child, new_child, true);

        } else {
            /* Check for movement, we already checked for differences */
            int p_new = pcmk__xml_position(new_child, pcmk__xf_skip);
            int p_old = pcmk__xml_position(old_child, pcmk__xf_skip);

            if(p_old != p_new) {
                mark_child_moved(old_child, new_xml, new_child, p_old, p_new);
            }
        }

        new_child = next;
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
 * \brief Merge one XML tree into another
 *
 * Here, "merge" means:
 * 1. Copy attribute values from \p update to the target, overwriting in case of
 *    conflict.
 * 2. Descend through \p update and the target in parallel. At each level, for
 *    each child of \p update, look for a matching child of the target.
 *    a. For each child, if a match is found, go to step 1, recursively merging
 *       the child of \p update into the child of the target.
 *    b. Otherwise, copy the child of \p update as a child of the target.
 *
 * A match is defined as the first child of the same type within the target,
 * with:
 * * the \c PCMK_XA_ID attribute matching, if set in \p update; otherwise,
 * * the \c PCMK_XA_ID_REF attribute matching, if set in \p update
 *
 * This function does not delete any elements or attributes from the target. It
 * may add elements or overwrite attributes, as described above.
 *
 * \param[in,out] parent   If \p target is NULL and this is not, add or update
 *                         child of this XML node that matches \p update
 * \param[in,out] target   If not NULL, update this XML
 * \param[in]     update   Make the desired XML match this (must not be \c NULL)
 * \param[in]     flags    Group of <tt>enum pcmk__xa_flags</tt>
 * \param[in]     as_diff  If \c true, preserve order of attributes (deprecated
 *                         since 2.0.5)
 *
 * \note At least one of \p parent and \p target must be non-<tt>NULL</tt>.
 * \note This function is recursive. For the top-level call, \p parent is
 *       \c NULL and \p target is not \c NULL. For recursive calls, \p target is
 *       \c NULL and \p parent is not \c NULL.
 */
void
pcmk__xml_update(xmlNode *parent, xmlNode *target, xmlNode *update,
                 uint32_t flags, bool as_diff)
{
    /* @COMPAT Refactor further and staticize after v1 patchset deprecation.
     *
     * @COMPAT Drop as_diff argument when apply_xml_diff() is dropped.
     */
    const char *update_name = NULL;
    const char *update_id_attr = NULL;
    const char *update_id_val = NULL;
    char *trace_s = NULL;

    crm_log_xml_trace(update, "update");
    crm_log_xml_trace(target, "target");

    CRM_CHECK(update != NULL, goto done);

    if (update->type == XML_COMMENT_NODE) {
        pcmk__xc_update(parent, target, update);
        goto done;
    }

    update_name = (const char *) update->name;

    CRM_CHECK(update_name != NULL, goto done);
    CRM_CHECK((target != NULL) || (parent != NULL), goto done);

    update_id_val = pcmk__xe_id(update);
    if (update_id_val != NULL) {
        update_id_attr = PCMK_XA_ID;

    } else {
        update_id_val = crm_element_value(update, PCMK_XA_ID_REF);
        if (update_id_val != NULL) {
            update_id_attr = PCMK_XA_ID_REF;
        }
    }

    pcmk__if_tracing(
        {
            if (update_id_attr != NULL) {
                trace_s = crm_strdup_printf("<%s %s=%s/>",
                                            update_name, update_id_attr,
                                            update_id_val);
            } else {
                trace_s = crm_strdup_printf("<%s/>", update_name);
            }
        },
        {}
    );

    if (target == NULL) {
        // Recursive call
        target = pcmk__xe_first_child(parent, update_name, update_id_attr,
                                      update_id_val);
    }

    if (target == NULL) {
        // Recursive call with no existing matching child
        target = pcmk__xe_create(parent, update_name);
        crm_trace("Added %s", pcmk__s(trace_s, update_name));

    } else {
        // Either recursive call with match, or top-level call
        crm_trace("Found node %s to update", pcmk__s(trace_s, update_name));
    }

    CRM_CHECK(pcmk__xe_is(target, (const char *) update->name), return);

    if (!as_diff) {
        pcmk__xe_copy_attrs(target, update, flags);

    } else {
        // Preserve order of attributes. Don't use pcmk__xe_copy_attrs().
        for (xmlAttrPtr a = pcmk__xe_first_attr(update); a != NULL;
             a = a->next) {
            const char *p_value = pcmk__xml_attr_value(a);

            /* Remove it first so the ordering of the update is preserved */
            xmlUnsetProp(target, a->name);
            xmlSetProp(target, a->name, (pcmkXmlStr) p_value);
        }
    }

    for (xmlNode *child = pcmk__xml_first_child(update); child != NULL;
         child = pcmk__xml_next(child)) {

        crm_trace("Updating child of %s", pcmk__s(trace_s, update_name));
        pcmk__xml_update(target, NULL, child, flags, as_diff);
    }

    crm_trace("Finished with %s", pcmk__s(trace_s, update_name));

done:
    free(trace_s);
}

/*!
 * \internal
 * \brief Delete an XML subtree if it matches a search element
 *
 * A match is defined as follows:
 * * \p xml and \p user_data are both element nodes of the same type.
 * * If \p user_data has attributes set, \p xml has those attributes set to the
 *   same values. (\p xml may have additional attributes set to arbitrary
 *   values.)
 *
 * \param[in,out] xml        XML subtree to delete upon match
 * \param[in]     user_data  Search element
 *
 * \return \c true to continue traversing the tree, or \c false to stop (because
 *         \p xml was deleted)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
delete_xe_if_matching(xmlNode *xml, void *user_data)
{
    xmlNode *search = user_data;

    if (!pcmk__xe_is(search, (const char *) xml->name)) {
        // No match: either not both elements, or different element types
        return true;
    }

    for (const xmlAttr *attr = pcmk__xe_first_attr(search); attr != NULL;
         attr = attr->next) {

        const char *search_val = pcmk__xml_attr_value(attr);
        const char *xml_val = crm_element_value(xml, (const char *) attr->name);

        if (!pcmk__str_eq(search_val, xml_val, pcmk__str_casei)) {
            // No match: an attr in xml doesn't match the attr in search
            return true;
        }
    }

    crm_log_xml_trace(xml, "delete-match");
    crm_log_xml_trace(search, "delete-search");
    pcmk__xml_free(xml);

    // Found a match and deleted it; stop traversing tree
    return false;
}

/*!
 * \internal
 * \brief Search an XML tree depth-first and delete the first matching element
 *
 * This function does not attempt to match the tree root (\p xml).
 *
 * A match with a node \c node is defined as follows:
 * * \c node and \p search are both element nodes of the same type.
 * * If \p search has attributes set, \c node has those attributes set to the
 *   same values. (\c node may have additional attributes set to arbitrary
 *   values.)
 *
 * \param[in,out] xml     XML subtree to search
 * \param[in]     search  Element to match against
 *
 * \return Standard Pacemaker return code (specifically, \c pcmk_rc_ok on
 *         successful deletion and an error code otherwise)
 */
int
pcmk__xe_delete_match(xmlNode *xml, xmlNode *search)
{
    // See @COMPAT comment in pcmk__xe_replace_match()
    CRM_CHECK((xml != NULL) && (search != NULL), return EINVAL);

    for (xml = pcmk__xe_first_child(xml, NULL, NULL, NULL); xml != NULL;
         xml = pcmk__xe_next(xml)) {

        if (!pcmk__xml_tree_foreach(xml, delete_xe_if_matching, search)) {
            // Found and deleted an element
            return pcmk_rc_ok;
        }
    }

    // No match found in this subtree
    return ENXIO;
}

/*!
 * \internal
 * \brief Replace one XML node with a copy of another XML node
 *
 * This function handles change tracking and applies ACLs.
 *
 * \param[in,out] old  XML node to replace
 * \param[in]     new  XML node to copy as replacement for \p old
 *
 * \note This frees \p old.
 */
static void
replace_node(xmlNode *old, xmlNode *new)
{
    new = xmlCopyNode(new, 1);
    pcmk__mem_assert(new);

    // May be unnecessary but avoids slight changes to some test outputs
    pcmk__xml_tree_foreach(new, reset_xml_node_flags, NULL);

    old = xmlReplaceNode(old, new);

    if (xml_tracking_changes(new)) {
        // Replaced sections may have included relevant ACLs
        pcmk__apply_acl(new);
    }
    xml_calculate_changes(old, new);
    xmlFreeNode(old);
}

/*!
 * \internal
 * \brief Replace one XML subtree with a copy of another if the two match
 *
 * A match is defined as follows:
 * * \p xml and \p user_data are both element nodes of the same type.
 * * If \p user_data has the \c PCMK_XA_ID attribute set, then \p xml has
 *   \c PCMK_XA_ID set to the same value.
 *
 * \param[in,out] xml        XML subtree to replace with \p user_data upon match
 * \param[in]     user_data  XML to replace \p xml with a copy of upon match
 *
 * \return \c true to continue traversing the tree, or \c false to stop (because
 *         \p xml was replaced by \p user_data)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
replace_xe_if_matching(xmlNode *xml, void *user_data)
{
    xmlNode *replace = user_data;
    const char *xml_id = NULL;
    const char *replace_id = NULL;

    xml_id = pcmk__xe_id(xml);
    replace_id = pcmk__xe_id(replace);

    if (!pcmk__xe_is(replace, (const char *) xml->name)) {
        // No match: either not both elements, or different element types
        return true;
    }

    if ((replace_id != NULL)
        && !pcmk__str_eq(replace_id, xml_id, pcmk__str_none)) {

        // No match: ID was provided in replace and doesn't match xml's ID
        return true;
    }

    crm_log_xml_trace(xml, "replace-match");
    crm_log_xml_trace(replace, "replace-with");
    replace_node(xml, replace);

    // Found a match and replaced it; stop traversing tree
    return false;
}

/*!
 * \internal
 * \brief Search an XML tree depth-first and replace the first matching element
 *
 * This function does not attempt to match the tree root (\p xml).
 *
 * A match with a node \c node is defined as follows:
 * * \c node and \p replace are both element nodes of the same type.
 * * If \p replace has the \c PCMK_XA_ID attribute set, then \c node has
 *   \c PCMK_XA_ID set to the same value.
 *
 * \param[in,out] xml      XML tree to search
 * \param[in]     replace  XML to replace a matching element with a copy of
 *
 * \return Standard Pacemaker return code (specifically, \c pcmk_rc_ok on
 *         successful replacement and an error code otherwise)
 */
int
pcmk__xe_replace_match(xmlNode *xml, xmlNode *replace)
{
    /* @COMPAT Some of this behavior (like not matching the tree root, which is
     * allowed by pcmk__xe_update_match()) is questionable for general use but
     * required for backward compatibility by cib_process_replace() and
     * cib_process_delete(). Behavior can change at a major version release if
     * desired.
     */
    CRM_CHECK((xml != NULL) && (replace != NULL), return EINVAL);

    for (xml = pcmk__xe_first_child(xml, NULL, NULL, NULL); xml != NULL;
         xml = pcmk__xe_next(xml)) {

        if (!pcmk__xml_tree_foreach(xml, replace_xe_if_matching, replace)) {
            // Found and replaced an element
            return pcmk_rc_ok;
        }
    }

    // No match found in this subtree
    return ENXIO;
}

//! User data for \c update_xe_if_matching()
struct update_data {
    xmlNode *update;    //!< Update source
    uint32_t flags;     //!< Group of <tt>enum pcmk__xa_flags</tt>
};

/*!
 * \internal
 * \brief Update one XML subtree with another if the two match
 *
 * "Update" means to merge a source subtree into a target subtree (see
 * \c pcmk__xml_update()).
 *
 * A match is defined as follows:
 * * \p xml and \p user_data->update are both element nodes of the same type.
 * * \p xml and \p user_data->update have the same \c PCMK_XA_ID attribute
 *   value, or \c PCMK_XA_ID is unset in both
 *
 * \param[in,out] xml        XML subtree to update with \p user_data->update
 *                           upon match
 * \param[in]     user_data  <tt>struct update_data</tt> object
 *
 * \return \c true to continue traversing the tree, or \c false to stop (because
 *         \p xml was updated by \p user_data->update)
 *
 * \note This is compatible with \c pcmk__xml_tree_foreach().
 */
static bool
update_xe_if_matching(xmlNode *xml, void *user_data)
{
    struct update_data *data = user_data;
    xmlNode *update = data->update;

    if (!pcmk__xe_is(update, (const char *) xml->name)) {
        // No match: either not both elements, or different element types
        return true;
    }

    if (!pcmk__str_eq(pcmk__xe_id(xml), pcmk__xe_id(update), pcmk__str_none)) {
        // No match: ID mismatch
        return true;
    }

    crm_log_xml_trace(xml, "update-match");
    crm_log_xml_trace(update, "update-with");
    pcmk__xml_update(NULL, xml, update, data->flags, false);

    // Found a match and replaced it; stop traversing tree
    return false;
}

/*!
 * \internal
 * \brief Search an XML tree depth-first and update the first matching element
 *
 * "Update" means to merge a source subtree into a target subtree (see
 * \c pcmk__xml_update()).
 *
 * A match with a node \c node is defined as follows:
 * * \c node and \p update are both element nodes of the same type.
 * * \c node and \p update have the same \c PCMK_XA_ID attribute value, or
 *   \c PCMK_XA_ID is unset in both
 *
 * \param[in,out] xml     XML tree to search
 * \param[in]     update  XML to update a matching element with
 * \param[in]     flags   Group of <tt>enum pcmk__xa_flags</tt>
 *
 * \return Standard Pacemaker return code (specifically, \c pcmk_rc_ok on
 *         successful update and an error code otherwise)
 */
int
pcmk__xe_update_match(xmlNode *xml, xmlNode *update, uint32_t flags)
{
    /* @COMPAT In pcmk__xe_delete_match() and pcmk__xe_replace_match(), we
     * compare IDs only if the equivalent of the update argument has an ID.
     * Here, we're stricter: we consider it a mismatch if only one element has
     * an ID attribute, or if both elements have IDs but they don't match.
     *
     * Perhaps we should align the behavior at a major version release.
     */
    struct update_data data = {
        .update = update,
        .flags = flags,
    };

    CRM_CHECK((xml != NULL) && (update != NULL), return EINVAL);

    if (!pcmk__xml_tree_foreach(xml, update_xe_if_matching, &data)) {
        // Found and updated an element
        return pcmk_rc_ok;
    }

    // No match found in this subtree
    return ENXIO;
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

        // Initialize private data at node creation
        xmlRegisterNodeDefault(new_private_data);

        // Free private data at node destruction
        xmlDeregisterNodeDefault(free_private_data);

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

/*!
 * \internal
 * \brief Get the XML element whose \c PCMK_XA_ID matches an \c PCMK_XA_ID_REF
 *
 * \param[in] xml     Element whose \c PCMK_XA_ID_REF attribute to check
 * \param[in] search  Node whose document to search for node with matching
 *                    \c PCMK_XA_ID (\c NULL to use \p xml)
 *
 * \return If \p xml has a \c PCMK_XA_ID_REF attribute, node in
 *         <tt>search</tt>'s document whose \c PCMK_XA_ID attribute matches;
 *         otherwise, \p xml
 */
xmlNode *
pcmk__xe_resolve_idref(xmlNode *xml, xmlNode *search)
{
    char *xpath = NULL;
    const char *ref = NULL;
    xmlNode *result = NULL;

    if (xml == NULL) {
        return NULL;
    }

    ref = crm_element_value(xml, PCMK_XA_ID_REF);
    if (ref == NULL) {
        return xml;
    }

    if (search == NULL) {
        search = xml;
    }

    xpath = crm_strdup_printf("//%s[@" PCMK_XA_ID "='%s']", xml->name, ref);
    result = get_xpath_object(xpath, search, LOG_DEBUG);
    if (result == NULL) {
        // Not possible with schema validation enabled
        pcmk__config_err("Ignoring invalid %s configuration: "
                         PCMK_XA_ID_REF " '%s' does not reference "
                         "a valid object " CRM_XS " xpath=%s",
                         xml->name, ref, xpath);
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

        free(ret);
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
    pcmk__xml_free(data);
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
    pcmk__xml_mark_created(child);
    return child;
}

int
add_node_nocopy(xmlNode *parent, const char *name, xmlNode *child)
{
    add_node_copy(parent, child);
    pcmk__xml_free(child);
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

static char *
replace_text(char *text, size_t *index, size_t *length, const char *replace)
{
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
    pcmk__xml_mark_created(node);
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
    xmlUnlinkNode(xml); // Detaches from parent and siblings
    xmlFreeNode(xml);   // Frees
}

void
free_xml(xmlNode *child)
{
    pcmk__xml_free(child);
}

xmlNode *
expand_idref(xmlNode *input, xmlNode *top)
{
    return pcmk__xe_resolve_idref(input, top);
}

// LCOV_EXCL_STOP
// End deprecated API

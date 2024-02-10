/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/stat.h>
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
#include <crm/common/xml_internal.h>  // PCMK__XML_LOG_BASE, etc.
#include "crmcommon_private.h"

// Define this as 1 in development to get insanely verbose trace messages
#ifndef XML_PARSER_DEBUG
#define XML_PARSER_DEBUG 0
#endif

/* @TODO XML_PARSE_RECOVER allows some XML errors to be silently worked around
 * by libxml2, which is potentially ambiguous and dangerous. We should drop it
 * when we can break backward compatibility with configurations that might be
 * relying on it (i.e. pacemaker 3.0.0).
 *
 * It might be a good idea to have a transitional period where we first try
 * parsing without XML_PARSE_RECOVER, and if that fails, try parsing again with
 * it, logging a warning if it succeeds.
 */
#define PCMK__XML_PARSE_OPTS_WITHOUT_RECOVER    (XML_PARSE_NOBLANKS)
#define PCMK__XML_PARSE_OPTS_WITH_RECOVER       (XML_PARSE_NOBLANKS | XML_PARSE_RECOVER)

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
            xml_doc_private_t *docpriv = NULL;
            docpriv = calloc(1, sizeof(xml_doc_private_t));
            CRM_ASSERT(docpriv != NULL);
            docpriv->check = XML_DOC_PRIVATE_MAGIC;
            /* Flags will be reset if necessary when tracking is enabled */
            pcmk__set_xml_flags(docpriv, pcmk__xf_dirty|pcmk__xf_created);
            node->_private = docpriv;
            break;
        }
        case XML_ELEMENT_NODE:
        case XML_ATTRIBUTE_NODE:
        case XML_COMMENT_NODE: {
            xml_node_private_t *nodepriv = NULL;
            nodepriv = calloc(1, sizeof(xml_node_private_t));
            CRM_ASSERT(nodepriv != NULL);
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

        return pcmk__xe_match(haystack, (const char *) needle->name, attr, id);
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

xmlNode *
find_xml_node(const xmlNode *root, const char *search_path, gboolean must_find)
{
    xmlNode *a_child = NULL;
    const char *name = (root == NULL)? "<NULL>" : (const char *) root->name;

    if (search_path == NULL) {
        crm_warn("Will never find <NULL>");
        return NULL;
    }

    for (a_child = pcmk__xml_first_child(root); a_child != NULL;
         a_child = pcmk__xml_next(a_child)) {
        if (strcmp((const char *)a_child->name, search_path) == 0) {
            return a_child;
        }
    }

    if (must_find) {
        crm_warn("Could not find %s in %s.", search_path, name);
    } else if (root != NULL) {
        crm_trace("Could not find %s in %s.", search_path, name);
    } else {
        crm_trace("Could not find %s in <NULL>.", search_path);
    }

    return NULL;
}

#define attr_matches(c, n, v) pcmk__str_eq(crm_element_value((c), (n)), \
                                           (v), pcmk__str_none)

/*!
 * \internal
 * \brief Find first XML child element matching given criteria
 *
 * \param[in] parent     XML element to search
 * \param[in] node_name  If not NULL, only match children of this type
 * \param[in] attr_n     If not NULL, only match children with an attribute
 *                       of this name.
 * \param[in] attr_v     If \p attr_n and this are not NULL, only match children
 *                       with an attribute named \p attr_n and this value
 *
 * \return Matching XML child element, or NULL if none found
 */
xmlNode *
pcmk__xe_match(const xmlNode *parent, const char *node_name,
               const char *attr_n, const char *attr_v)
{
    CRM_CHECK(parent != NULL, return NULL);
    CRM_CHECK(attr_v == NULL || attr_n != NULL, return NULL);

    for (xmlNode *child = pcmk__xml_first_child(parent); child != NULL;
         child = pcmk__xml_next(child)) {
        if (((node_name == NULL) || pcmk__xe_is(child, node_name))
            && ((attr_n == NULL) ||
                (attr_v == NULL && xmlHasProp(child, (pcmkXmlStr) attr_n)) ||
                (attr_v != NULL && attr_matches(child, attr_n, attr_v)))) {
            return child;
        }
    }
    crm_trace("XML child node <%s%s%s%s%s> not found in %s",
              (node_name? node_name : "(any)"),
              (attr_n? " " : ""),
              (attr_n? attr_n : ""),
              (attr_n? "=" : ""),
              (attr_n? attr_v : ""),
              (const char *) parent->name);
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
    for (child = pcmk__xml_first_child(target); child != NULL;
         child = pcmk__xml_next(child)) {
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
            if (!pcmk__check_acl(element, NULL, pcmk__xf_acl_write)) {
                crm_trace("ACLs prevent removal of attributes (%s and "
                          "possibly others) from %s element",
                          (const char *) a->name, (const char *) element->name);
                return; // ACLs apply to element, not particular attributes
            }

            if (pcmk__tracking_xml_changes(element, false)) {
                // Leave (marked for removal) until after diff is calculated
                set_parent_flag(element, pcmk__xf_dirty);
                pcmk__set_xml_flags((xml_node_private_t *) a->_private,
                                    pcmk__xf_deleted);
            } else {
                xmlRemoveProp(a);
            }
        }
    }
}

xmlNode *
create_xml_node(xmlNode * parent, const char *name)
{
    xmlDoc *doc = NULL;
    xmlNode *node = NULL;

    if (pcmk__str_empty(name)) {
        CRM_CHECK(name != NULL && name[0] == 0, return NULL);
        return NULL;
    }

    if (parent == NULL) {
        doc = xmlNewDoc(PCMK__XML_VERSION);
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

/*!
 * \internal
 * \brief Set a given string as an XML node's content
 *
 * \param[in,out] node     Node whose content to set
 * \param[in]     content  String to set as the content
 *
 * \note \c xmlNodeSetContent() does not escape special characters.
 */
void
pcmk__xe_set_content(xmlNode *node, const char *content)
{
    if (node != NULL) {
        char *escaped = pcmk__xml_escape(content, false);

        xmlNodeSetContent(node, (pcmkXmlStr) escaped);
        free(escaped);
    }
}

xmlNode *
pcmk_create_xml_text_node(xmlNode * parent, const char *name, const char *content)
{
    xmlNode *node = create_xml_node(parent, name);

    pcmk__xe_set_content(node, content);
    return node;
}

xmlNode *
pcmk_create_html_node(xmlNode * parent, const char *element_name, const char *id,
                      const char *class_name, const char *text)
{
    xmlNode *node = pcmk_create_xml_text_node(parent, element_name, text);

    if (class_name != NULL) {
        crm_xml_add(node, PCMK_XA_CLASS, class_name);
    }

    if (id != NULL) {
        crm_xml_add(node, PCMK_XA_ID, id);
    }

    return node;
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

                    deleted_obj = calloc(1, sizeof(pcmk__deleted_xml_t));
                    deleted_obj->path = strdup((const char *) xpath->str);

                    CRM_ASSERT(deleted_obj->path != NULL);
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
        CRM_ASSERT(doc != NULL);

        copy = xmlDocCopyNode(src, doc, 1);
        CRM_ASSERT(copy != NULL);

        xmlDocSetRootElement(doc, copy);

    } else {
        copy = xmlDocCopyNode(src, parent->doc, 1);
        CRM_ASSERT(copy != NULL);

        xmlAddChild(parent, copy);
    }

    pcmk__mark_xml_created(copy);
    return copy;
}

/*!
 * \internal
 * \brief Read from \c stdin until EOF or error
 *
 * \return Newly allocated string containing the bytes read from \c stdin, or
 *         \c NULL on error
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
static char *
read_stdin(void)
{
    char *buf = NULL;
    size_t length = 0;

    do {
        buf = pcmk__realloc(buf, length + PCMK__BUFFER_SIZE + 1);
        length += fread(buf + length, 1, PCMK__BUFFER_SIZE, stdin);
    } while ((feof(stdin) == 0) && (ferror(stdin) == 0));

    if (ferror(stdin) != 0) {
        crm_err("Error reading input from stdin");
        free(buf);
        buf = NULL;
    } else {
        buf[length] = '\0';
    }
    clearerr(stdin);
    return buf;
}

/*!
 * \internal
 * \brief Decompress a <tt>bzip2</tt>-compressed file into a string buffer
 *
 * \param[in] filename  Name of file to decompress
 *
 * \return Newly allocated string with the decompressed contents of \p filename,
 *         or \c NULL on error.
 *
 * \note The caller is responsible for freeing the return value using \c free().
 */
static char *
decompress_file(const char *filename)
{
    char *buffer = NULL;
    int rc = pcmk_rc_ok;
    size_t length = 0;
    BZFILE *bz_file = NULL;
    FILE *input = fopen(filename, "r");

    if (input == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for reading", filename);
        return NULL;
    }

    bz_file = BZ2_bzReadOpen(&rc, input, 0, 0, NULL, 0);
    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        crm_err("Could not prepare to read compressed %s: %s "
                CRM_XS " rc=%d", filename, pcmk_rc_str(rc), rc);
        goto done;
    }

    // cppcheck seems not to understand the abort-logic in pcmk__realloc
    // cppcheck-suppress memleak
    do {
        int read_len = 0;

        buffer = pcmk__realloc(buffer, length + PCMK__BUFFER_SIZE + 1);
        read_len = BZ2_bzRead(&rc, bz_file, buffer + length, PCMK__BUFFER_SIZE);

        if ((rc == BZ_OK) || (rc == BZ_STREAM_END)) {
            crm_trace("Read %ld bytes from file: %d", (long) read_len, rc);
            length += read_len;
        }
    } while (rc == BZ_OK);

    rc = pcmk__bzlib2rc(rc);
    if (rc != pcmk_rc_ok) {
        rc = pcmk__bzlib2rc(rc);
        crm_err("Could not read compressed %s: %s " CRM_XS " rc=%d",
                filename, pcmk_rc_str(rc), rc);
        free(buffer);
        buffer = NULL;
    } else {
        buffer[length] = '\0';
    }

done:
    BZ2_bzReadClose(&rc, bz_file);
    fclose(input);
    return buffer;
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

// @COMPAT Remove macro at 3.0.0 when we drop XML_PARSE_RECOVER
/*!
 * \internal
 * \brief Try to parse XML first without and then with recovery enabled
 *
 * \param[out] result  Where to store the resulting XML doc (<tt>xmlDoc **</tt>)
 * \param[in]  fn      XML parser function
 * \param[in]  ...     All arguments for \p fn except the final one (an
 *                     \c xmlParserOption group)
 */
#define parse_xml_recover(result, fn, ...) do {                             \
        *result = fn(__VA_ARGS__, PCMK__XML_PARSE_OPTS_WITHOUT_RECOVER);    \
        if (*result == NULL) {                                              \
            *result = fn(__VA_ARGS__, PCMK__XML_PARSE_OPTS_WITH_RECOVER);   \
                                                                            \
            if (*result != NULL) {                                          \
                crm_warn("Successfully recovered from XML errors "          \
                         "(note: a future release will treat this as a "    \
                         "fatal failure)");                                 \
            }                                                               \
        }                                                                   \
    } while (0);

/*!
 * \internal
 * \brief Parse XML from a file
 *
 * \param[in] filename  Name of file containing XML (\c NULL or \c "-" for
 *                      \c stdin); if \p filename ends in \c ".bz2", the file
 *                      will be decompressed using \c bzip2
 *
 * \return XML tree parsed from the given file; may be \c NULL or only partial
 *         on error
 */
xmlNode *
pcmk__xml_read(const char *filename)
{
    bool use_stdin = pcmk__str_eq(filename, "-", pcmk__str_null_matches);
    xmlNode *xml = NULL;
    xmlDoc *output = NULL;
    xmlParserCtxt *ctxt = NULL;
    const xmlError *last_error = NULL;

    // Create a parser context
    ctxt = xmlNewParserCtxt();
    CRM_CHECK(ctxt != NULL, return NULL);

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, pcmk__log_xmllib_err);

    if (use_stdin) {
        /* @COMPAT After dropping XML_PARSE_RECOVER, we can avoid capturing
         * stdin into a buffer and instead call
         * xmlCtxtReadFd(ctxt, STDIN_FILENO, NULL, NULL, XML_PARSE_NOBLANKS);
         *
         * For now we have to save the input so that we can use it twice.
         */
        char *input = read_stdin();

        if (input != NULL) {
            parse_xml_recover(&output, xmlCtxtReadDoc, ctxt, (pcmkXmlStr) input,
                              NULL, NULL);
            free(input);
        }

    } else if (pcmk__ends_with_ext(filename, ".bz2")) {
        char *input = decompress_file(filename);

        if (input != NULL) {
            parse_xml_recover(&output, xmlCtxtReadDoc, ctxt, (pcmkXmlStr) input,
                              NULL, NULL);
            free(input);
        }

    } else {
        parse_xml_recover(&output, xmlCtxtReadFile, ctxt, filename, NULL);
    }

    if (output != NULL) {
        xml = xmlDocGetRootElement(output);
        if (xml != NULL) {
            /* @TODO Should we really be stripping out text? This seems like an
             * overly broad way to get rid of whitespace, if that's the goal.
             * Text nodes may be invalid in most or all Pacemaker inputs, but
             * stripping them in a generic "parse XML from file" function may
             * not be the best way to ignore them.
             */
            pcmk__strip_xml_text(xml);
        }
    }

    // @COMPAT At 3.0.0, free xml and return NULL if xml != NULL on error
    last_error = xmlCtxtGetLastError(ctxt);
    if (last_error != NULL) {
        crm_err("Couldn't parse XML from %s", (use_stdin? "stdin": filename));

        if (xml != NULL) {
            crm_log_xml_info(xml, "Partial");
        }
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
}

/*!
 * \internal
 * \brief Parse XML from a string
 *
 * \param[in] input  String to parse
 *
 * \return XML tree parsed from the given string; may be \c NULL or only partial
 *         on error
 */
xmlNode *
pcmk__xml_parse(const char *input)
{
    xmlNode *xml = NULL;
    xmlDoc *output = NULL;
    xmlParserCtxt *ctxt = NULL;
    const xmlError *last_error = NULL;

    if (input == NULL) {
        return NULL;
    }

    ctxt = xmlNewParserCtxt();
    if (ctxt == NULL) {
        return NULL;
    }

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, pcmk__log_xmllib_err);

    parse_xml_recover(&output, xmlCtxtReadDoc, ctxt, (pcmkXmlStr) input, NULL,
                      NULL);

    if (output != NULL) {
        xml = xmlDocGetRootElement(output);
    }

    // @COMPAT At 3.0.0, free xml and return NULL if xml != NULL; update doxygen
    last_error = xmlCtxtGetLastError(ctxt);
    if (last_error != NULL) {
        crm_err("Couldn't parse XML from string: %s", input);

        if (xml != NULL) {
            crm_log_xml_info(xml, "Partial");
        }
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
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
 * \brief Write XML to a file stream
 *
 * \param[in]     xml       XML to write
 * \param[in]     filename  Name of file being written (for logging only)
 * \param[in,out] stream    Open file stream corresponding to filename
 * \param[in]     compress  Whether to compress XML before writing
 * \param[out]    nbytes    Number of bytes written
 *
 * \return Standard Pacemaker return code
 */
static int
write_xml_stream(const xmlNode *xml, const char *filename, FILE *stream,
                 bool compress, unsigned int *nbytes)
{
    int rc = pcmk_rc_ok;
    char *buffer = NULL;

    *nbytes = 0;
    crm_log_xml_trace(xml, "writing");

    buffer = dump_xml_formatted(xml);
    CRM_CHECK(buffer && strlen(buffer),
              crm_log_xml_warn(xml, "formatting failed");
              rc = pcmk_rc_error;
              goto bail);

    if (compress) {
        unsigned int in = 0;
        BZFILE *bz_file = NULL;

        rc = BZ_OK;
        bz_file = BZ2_bzWriteOpen(&rc, stream, 5, 0, 30);
        rc = pcmk__bzlib2rc(rc);

        if (rc != pcmk_rc_ok) {
            crm_warn("Not compressing %s: could not prepare file stream: %s "
                     CRM_XS " rc=%d", filename, pcmk_rc_str(rc), rc);
        } else {
            BZ2_bzWrite(&rc, bz_file, buffer, strlen(buffer));
            rc = pcmk__bzlib2rc(rc);

            if (rc != pcmk_rc_ok) {
                crm_warn("Not compressing %s: could not compress data: %s "
                         CRM_XS " rc=%d errno=%d",
                         filename, pcmk_rc_str(rc), rc, errno);
            }
        }

        if (rc == pcmk_rc_ok) {
            BZ2_bzWriteClose(&rc, bz_file, 0, &in, nbytes);
            rc = pcmk__bzlib2rc(rc);

            if (rc != pcmk_rc_ok) {
                crm_warn("Not compressing %s: could not write compressed data: %s "
                         CRM_XS " rc=%d errno=%d",
                         filename, pcmk_rc_str(rc), rc, errno);
                *nbytes = 0; // retry without compression
            } else {
                crm_trace("Compressed XML for %s from %u bytes to %u",
                          filename, in, *nbytes);
            }
        }
        rc = pcmk_rc_ok; // Either true, or we'll retry without compression
    }

    if (*nbytes == 0) {
        rc = fprintf(stream, "%s", buffer);
        if (rc < 0) {
            rc = errno;
            crm_perror(LOG_ERR, "writing %s", filename);
        } else {
            *nbytes = (unsigned int) rc;
            rc = pcmk_rc_ok;
        }
    }

  bail:

    if (fflush(stream) != 0) {
        rc = errno;
        crm_perror(LOG_ERR, "flushing %s", filename);
    }

    /* Don't report error if the file does not support synchronization */
    if (fsync(fileno(stream)) < 0 && errno != EROFS  && errno != EINVAL) {
        rc = errno;
        crm_perror(LOG_ERR, "synchronizing %s", filename);
    }

    fclose(stream);

    crm_trace("Saved %d bytes to %s as XML", *nbytes, filename);
    free(buffer);

    return rc;
}

/*!
 * \internal
 * \brief Write XML to a file descriptor
 *
 * \param[in]  xml       XML to write
 * \param[in]  filename  Name of file being written (for logging only)
 * \param[in]  fd        Open file descriptor corresponding to \p filename
 * \param[in]  compress  If \c true, compress XML before writing
 * \param[out] nbytes    Number of bytes written (can be \c NULL)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xml_write_fd(const xmlNode *xml, const char *filename, int fd,
                   bool compress, int *nbytes)
{
    // @COMPAT Drop compress and nbytes arguments when we drop write_xml_fd()
    FILE *stream = NULL;
    unsigned int local_nbytes = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK((xml != NULL) && (fd > 0), return EINVAL);
    stream = fdopen(fd, "w");
    if (stream == NULL) {
        return errno;
    }

    rc = write_xml_stream(xml, filename, stream, compress, &local_nbytes);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if (nbytes != NULL) {
        *nbytes = (int) local_nbytes;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Write XML to a file
 *
 * \param[in]  xml       XML to write
 * \param[in]  filename  Name of file to write
 * \param[in]  compress  If \c true, compress XML before writing
 * \param[out] nbytes    Number of bytes written (can be \c NULL)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xml_write_file(const xmlNode *xml, const char *filename, bool compress,
                     int *nbytes)
{
    // @COMPAT Drop nbytes argument when we drop write_xml_fd()
    FILE *stream = NULL;
    unsigned int local_nbytes = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK((xml != NULL) && (filename != NULL), return EINVAL);
    stream = fopen(filename, "w");
    if (stream == NULL) {
        return errno;
    }

    rc = write_xml_stream(xml, filename, stream, compress, &local_nbytes);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if (nbytes != NULL) {
        *nbytes = (int) local_nbytes;
    }
    return pcmk_rc_ok;
}

/*!
 * \brief Write XML to a file
 *
 * \param[in] xml       XML to write
 * \param[in] filename  Name of file to write
 * \param[in] compress  Whether to compress XML before writing
 *
 * \return Number of bytes written on success, -errno otherwise
 */
int
write_xml_file(const xmlNode *xml, const char *filename, gboolean compress)
{
    int nbytes = 0;
    int rc = pcmk__xml_write_file(xml, filename, compress, &nbytes);

    if (rc != pcmk_rc_ok) {
        return pcmk_rc2legacy(rc);
    }
    return nbytes;
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
    pcmk__str_update(&copy, text);

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
                    snprintf(buf, sizeof(buf), "&#%.2x;", copy[index]);
                    copy = replace_text(copy, &index, &length, buf);
                }
                break;
        }
    }
    return copy;
}

/*!
 * \internal
 * \brief Append a string representation of an XML element to a buffer
 *
 * \param[in]     data     XML whose representation to append
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_element(const xmlNode *data, uint32_t options, GString *buffer,
                 int depth)
{
    bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
    bool filtered = pcmk_is_set(options, pcmk__xml_fmt_filtered);
    int spaces = pretty? (2 * depth) : 0;

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<", data->name, NULL);

    for (const xmlAttr *attr = pcmk__xe_first_attr(data); attr != NULL;
         attr = attr->next) {

        if (!filtered || !pcmk__xa_filterable((const char *) (attr->name))) {
            pcmk__dump_xml_attr(attr, buffer);
        }
    }

    if (data->children == NULL) {
        g_string_append(buffer, "/>");

    } else {
        g_string_append_c(buffer, '>');
    }

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }

    if (data->children) {
        for (const xmlNode *child = data->children; child != NULL;
             child = child->next) {
            pcmk__xml2text(child, options, buffer, depth + 1);
        }

        for (int lpc = 0; lpc < spaces; lpc++) {
            g_string_append_c(buffer, ' ');
        }

        pcmk__g_strcat(buffer, "</", data->name, ">", NULL);

        if (pretty) {
            g_string_append_c(buffer, '\n');
        }
    }
}

/*!
 * \internal
 * \brief Append XML text content to a buffer
 *
 * \param[in]     data     XML whose content to append
 * \param[in]     options  Group of \p xml_log_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_text(const xmlNode *data, uint32_t options, GString *buffer,
              int depth)
{
    bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
    int spaces = pretty? (2 * depth) : 0;
    const char *content = (const char *) data->content;
    char *content_esc = NULL;

    if (pcmk__xml_needs_escape(content, false)) {
        content_esc = pcmk__xml_escape(content, false);
        content = content_esc;
    }

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    g_string_append(buffer, content);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
    free(content_esc);
}

/*!
 * \internal
 * \brief Append XML CDATA content to a buffer
 *
 * \param[in]     data     XML whose content to append
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_cdata(const xmlNode *data, uint32_t options, GString *buffer,
               int depth)
{
    bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
    int spaces = pretty? (2 * depth) : 0;

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<![CDATA[", (const char *) data->content, "]]>",
                   NULL);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
}

/*!
 * \internal
 * \brief Append an XML comment to a buffer
 *
 * \param[in]     data     XML whose content to append
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
static void
dump_xml_comment(const xmlNode *data, uint32_t options, GString *buffer,
                 int depth)
{
    bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
    int spaces = pretty? (2 * depth) : 0;

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<!--", (const char *) data->content, "-->", NULL);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
}

/*!
 * \internal
 * \brief Get a string representation of an XML element type
 *
 * \param[in] type  XML element type
 *
 * \return String representation of \p type
 */
static const char *
xml_element_type2str(xmlElementType type)
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

    if ((type < 0) || (type >= PCMK__NELEM(element_type_names))) {
        return "unrecognized type";
    }
    return element_type_names[type];
}

/*!
 * \internal
 * \brief Create a text representation of an XML object
 *
 * \param[in]     data     XML to convert
 * \param[in]     options  Group of \p pcmk__xml_fmt_options flags
 * \param[in,out] buffer   Where to store the text (must not be \p NULL)
 * \param[in]     depth    Current indentation level
 */
void
pcmk__xml2text(const xmlNode *data, uint32_t options, GString *buffer,
               int depth)
{
    if (data == NULL) {
        crm_trace("Nothing to dump");
        return;
    }

    CRM_ASSERT(buffer != NULL);
    CRM_CHECK(depth >= 0, depth = 0);

    switch(data->type) {
        case XML_ELEMENT_NODE:
            /* Handle below */
            dump_xml_element(data, options, buffer, depth);
            break;
        case XML_TEXT_NODE:
            if (pcmk_is_set(options, pcmk__xml_fmt_text)) {
                dump_xml_text(data, options, buffer, depth);
            }
            break;
        case XML_COMMENT_NODE:
            dump_xml_comment(data, options, buffer, depth);
            break;
        case XML_CDATA_SECTION_NODE:
            dump_xml_cdata(data, options, buffer, depth);
            break;
        default:
            crm_warn("Cannot convert XML %s node to text " CRM_XS " type=%d",
                     xml_element_type2str(data->type), data->type);
            break;
    }
}

char *
dump_xml_formatted_with_text(const xmlNode *xml)
{
    /* libxml's xmlNodeDumpOutput() would work here since we're not specifically
     * filtering out any nodes. However, use pcmk__xml2text() for consistency,
     * to escape attribute values, and to allow a const argument.
     */
    char *buffer = NULL;
    GString *g_buffer = g_string_sized_new(1024);

    pcmk__xml2text(xml, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text, g_buffer, 0);

    pcmk__str_update(&buffer, g_buffer->str);
    g_string_free(g_buffer, TRUE);
    return buffer;
}

char *
dump_xml_formatted(const xmlNode *xml)
{
    char *buffer = NULL;
    GString *g_buffer = g_string_sized_new(1024);

    pcmk__xml2text(xml, pcmk__xml_fmt_pretty, g_buffer, 0);

    pcmk__str_update(&buffer, g_buffer->str);
    g_string_free(g_buffer, TRUE);
    return buffer;
}

char *
dump_xml_unformatted(const xmlNode *xml)
{
    char *buffer = NULL;
    GString *g_buffer = g_string_sized_new(1024);

    pcmk__xml2text(xml, 0, g_buffer, 0);

    pcmk__str_update(&buffer, g_buffer->str);
    g_string_free(g_buffer, TRUE);
    return buffer;
}

int
pcmk__xml2fd(int fd, xmlNode *cur)
{
    bool success;

    xmlOutputBuffer *fd_out = xmlOutputBufferCreateFd(fd, NULL);
    CRM_ASSERT(fd_out != NULL);
    xmlNodeDumpOutput(fd_out, cur->doc, cur, 0, pcmk__xml_fmt_pretty, NULL);

    success = xmlOutputBufferWrite(fd_out, sizeof("\n") - 1, "\n") != -1;

    success = xmlOutputBufferClose(fd_out) != -1 && success;

    if (!success) {
        return EIO;
    }

    fsync(fd);
    return pcmk_rc_ok;
}

void
xml_remove_prop(xmlNode * obj, const char *name)
{
    if (crm_element_value(obj, name) == NULL) {
        return;
    }

    if (pcmk__check_acl(obj, NULL, pcmk__xf_acl_write) == FALSE) {
        crm_trace("Cannot remove %s from %s", name, obj->name);

    } else if (pcmk__tracking_xml_changes(obj, FALSE)) {
        /* Leave in place (marked for removal) until after the diff is calculated */
        xmlAttr *attr = xmlHasProp(obj, (pcmkXmlStr) name);
        xml_node_private_t *nodepriv = attr->_private;

        set_parent_flag(obj, pcmk__xf_dirty);
        pcmk__set_xml_flags(nodepriv, pcmk__xf_deleted);
    } else {
        xmlUnsetProp(obj, (pcmkXmlStr) name);
    }
}

void
save_xml_to_file(const xmlNode *xml, const char *desc, const char *filename)
{
    char *f = NULL;

    if (filename == NULL) {
        char *uuid = crm_generate_uuid();

        f = crm_strdup_printf("%s/%s", pcmk__get_tmpdir(), uuid);
        filename = f;
        free(uuid);
    }

    crm_info("Saving %s to %s", desc, filename);
    pcmk__xml_write_file(xml, filename, false, NULL);
    free(f);
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
    xml_remove_prop(new_xml, attr_name);

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

    crm_trace("Child element %s with id='%s' moved from position %d to %d under %s",
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
        target = pcmk__xe_match(parent, object_name,
                                object_href, object_href_val);
    }

    if (target == NULL) {
        target = create_xml_node(parent, object_name);
        CRM_CHECK(target != NULL, return);
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
            *children = create_xml_node(NULL, __func__);
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

            CRM_ASSERT(new != NULL);

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

    result = create_xml_node(parent, (const char *) input->name);
    nvpairs = pcmk_xml_attrs2nvpairs(input);
    nvpairs = pcmk_sort_nvpairs(nvpairs);
    pcmk_nvpairs2xml_attrs(nvpairs, result);
    pcmk_free_nvpairs(nvpairs);

    for (child = pcmk__xml_first_child(input); child != NULL;
         child = pcmk__xml_next(child)) {

        if (recursive) {
            sorted_xml(child, result, recursive);
        } else {
            pcmk__xml_copy(result, child);
        }
    }

    return result;
}

xmlNode *
first_named_child(const xmlNode *parent, const char *name)
{
    xmlNode *match = NULL;

    for (match = pcmk__xe_first_child(parent); match != NULL;
         match = pcmk__xe_next(match)) {
        /*
         * name == NULL gives first child regardless of name; this is
         * semantically incorrect in this function, but may be necessary
         * due to prior use of xml_child_iter_filter
         */
        if ((name == NULL) || pcmk__xe_is(match, name)) {
            return match;
        }
    }
    return NULL;
}

/*!
 * \brief Get next instance of same XML tag
 *
 * \param[in] sibling  XML tag to start from
 *
 * \return Next sibling XML tag with same name
 */
xmlNode *
crm_next_same_xml(const xmlNode *sibling)
{
    xmlNode *match = pcmk__xe_next(sibling);

    while (match != NULL) {
        if (pcmk__xe_is(match, (const char *) sibling->name)) {
            return match;
        }
        match = pcmk__xe_next(match);
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
    return pcmk__xe_match(parent, node_name,
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
    copy = strdup(text);
    CRM_ASSERT(copy != NULL);
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
    xmlNode *copy = xmlDocCopyNode(src, doc, 1);

    CRM_ASSERT(copy != NULL);
    xmlDocSetRootElement(doc, copy);
    return copy;
}

xmlNode *
filename2xml(const char *filename)
{
    return pcmk__xml_read(filename);
}

xmlNode *
stdin2xml(void)
{
    return pcmk__xml_read(NULL);
}

xmlNode *
string2xml(const char *input)
{
    return pcmk__xml_parse(input);
}

int
write_xml_fd(const xmlNode *xml, const char *filename, int fd,
             gboolean compress)
{
    int nbytes = 0;
    int rc = pcmk__xml_write_fd(xml, filename, fd, compress, &nbytes);

    if (rc != pcmk_rc_ok) {
        return pcmk_rc2legacy(rc);
    }
    return nbytes;
}

// LCOV_EXCL_STOP
// End deprecated API

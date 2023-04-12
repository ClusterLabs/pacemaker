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
#define PCMK__XML_PARSE_OPTS    (XML_PARSE_NOBLANKS | XML_PARSE_RECOVER)

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
static inline void
mark_xml_node_dirty(xmlNode *xml)
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
    xml_node_private_t *nodepriv = xml->_private;

    if (nodepriv && pcmk__tracking_xml_changes(xml, FALSE)) {
        if (!pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {
            pcmk__set_xml_flags(nodepriv, pcmk__xf_created);
            mark_xml_node_dirty(xml);
        }
        for (cIter = pcmk__xml_first_child(xml); cIter != NULL;
             cIter = pcmk__xml_next(cIter)) {
            pcmk__mark_xml_created(cIter);
        }
    }
}

void
pcmk__mark_xml_attr_dirty(xmlAttr *a) 
{
    xmlNode *parent = a->parent;
    xml_node_private_t *nodepriv = a->_private;

    pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_modified);
    pcmk__clear_xml_flags(nodepriv, pcmk__xf_deleted);
    mark_xml_node_dirty(parent);
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
                mark_xml_node_dirty(node);
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

// This also clears attribute's flags if not marked as deleted
static bool
marked_as_deleted(xmlAttrPtr a, void *user_data)
{
    xml_node_private_t *nodepriv = a->_private;

    if (pcmk_is_set(nodepriv->flags, pcmk__xf_deleted)) {
        return true;
    }
    nodepriv->flags = pcmk__xf_none;
    return false;
}

// Remove all attributes marked as deleted from an XML node
static void
accept_attr_deletions(xmlNode *xml)
{
    // Clear XML node's flags
    ((xml_node_private_t *) xml->_private)->flags = pcmk__xf_none;

    // Remove this XML node's attributes that were marked as deleted
    pcmk__xe_remove_matching_attrs(xml, marked_as_deleted, NULL);

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
        const char *id = ID(needle);
        const char *attr = (id == NULL)? NULL : XML_ATTR_ID;

        return pcmk__xe_match(haystack, crm_element_name(needle), attr, id);
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
    const char *name = "NULL";

    if (root != NULL) {
        name = crm_element_name(root);
    }

    if (search_path == NULL) {
        crm_warn("Will never find <NULL>");
        return NULL;
    }

    for (a_child = pcmk__xml_first_child(root); a_child != NULL;
         a_child = pcmk__xml_next(a_child)) {
        if (strcmp((const char *)a_child->name, search_path) == 0) {
/* 		crm_trace("returning node (%s).", crm_element_name(a_child)); */
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
        if (pcmk__str_eq(node_name, (const char *) (child->name),
                         pcmk__str_null_matches)
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
              crm_element_name(parent));
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

    if (int_value > INFINITY) {
        int_value = (int)INFINITY;
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

xmlDoc *
getDocPtr(xmlNode * node)
{
    xmlDoc *doc = NULL;

    CRM_CHECK(node != NULL, return NULL);

    doc = node->doc;
    if (doc == NULL) {
        doc = xmlNewDoc((pcmkXmlStr) "1.0");
        xmlDocSetRootElement(doc, node);
        xmlSetTreeDoc(node, doc);
    }
    return doc;
}

xmlNode *
add_node_copy(xmlNode * parent, xmlNode * src_node)
{
    xmlNode *child = NULL;
    xmlDoc *doc = getDocPtr(parent);

    CRM_CHECK(src_node != NULL, return NULL);

    child = xmlDocCopyNode(src_node, doc, 1);
    xmlAddChild(parent, child);
    pcmk__mark_xml_created(child);
    return child;
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
        doc = xmlNewDoc((pcmkXmlStr) "1.0");
        node = xmlNewDocRawNode(doc, NULL, (pcmkXmlStr) name, NULL);
        xmlDocSetRootElement(doc, node);

    } else {
        doc = getDocPtr(parent);
        node = xmlNewDocRawNode(doc, NULL, (pcmkXmlStr) name, NULL);
        xmlAddChild(parent, node);
    }
    pcmk__mark_xml_created(node);
    return node;
}

xmlNode *
pcmk_create_xml_text_node(xmlNode * parent, const char *name, const char *content)
{
    xmlNode *node = create_xml_node(parent, name);

    if (node != NULL) {
        xmlNodeSetContent(node, (pcmkXmlStr) content);
    }

    return node;
}

xmlNode *
pcmk_create_html_node(xmlNode * parent, const char *element_name, const char *id,
                      const char *class_name, const char *text)
{
    xmlNode *node = pcmk_create_xml_text_node(parent, element_name, text);

    if (class_name != NULL) {
        crm_xml_add(node, "class", class_name);
    }

    if (id != NULL) {
        crm_xml_add(node, "id", id);
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

xmlNode *
copy_xml(xmlNode * src)
{
    xmlDoc *doc = xmlNewDoc((pcmkXmlStr) "1.0");
    xmlNode *copy = xmlDocCopyNode(src, doc, 1);

    CRM_ASSERT(copy != NULL);
    xmlDocSetRootElement(doc, copy);
    xmlSetTreeDoc(copy, doc);
    return copy;
}

xmlNode *
string2xml(const char *input)
{
    xmlNode *xml = NULL;
    xmlDocPtr output = NULL;
    xmlParserCtxtPtr ctxt = NULL;
    xmlErrorPtr last_error = NULL;

    if (input == NULL) {
        crm_err("Can't parse NULL input");
        return NULL;
    }

    /* create a parser context */
    ctxt = xmlNewParserCtxt();
    CRM_CHECK(ctxt != NULL, return NULL);

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, pcmk__log_xmllib_err);
    output = xmlCtxtReadDoc(ctxt, (pcmkXmlStr) input, NULL, NULL,
                            PCMK__XML_PARSE_OPTS);
    if (output) {
        xml = xmlDocGetRootElement(output);
    }
    last_error = xmlCtxtGetLastError(ctxt);
    if (last_error && last_error->code != XML_ERR_OK) {
        /* crm_abort(__FILE__,__func__,__LINE__, "last_error->code != XML_ERR_OK", TRUE, TRUE); */
        /*
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlErrorLevel
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlParserErrors
         */
        crm_warn("Parsing failed (domain=%d, level=%d, code=%d): %s",
                 last_error->domain, last_error->level, last_error->code, last_error->message);

        if (last_error->code == XML_ERR_DOCUMENT_EMPTY) {
            CRM_LOG_ASSERT("Cannot parse an empty string");

        } else if (last_error->code != XML_ERR_DOCUMENT_END) {
            crm_err("Couldn't%s parse %d chars: %s", xml ? " fully" : "", (int)strlen(input),
                    input);
            if (xml != NULL) {
                crm_log_xml_err(xml, "Partial");
            }

        } else {
            int len = strlen(input);
            int lpc = 0;

            while(lpc < len) {
                crm_warn("Parse error[+%.3d]: %.80s", lpc, input+lpc);
                lpc += 80;
            }

            CRM_LOG_ASSERT("String parsing error");
        }
    }

    xmlFreeParserCtxt(ctxt);
    return xml;
}

xmlNode *
stdin2xml(void)
{
    size_t data_length = 0;
    size_t read_chars = 0;

    char *xml_buffer = NULL;
    xmlNode *xml_obj = NULL;

    do {
        xml_buffer = pcmk__realloc(xml_buffer, data_length + PCMK__BUFFER_SIZE);
        read_chars = fread(xml_buffer + data_length, 1, PCMK__BUFFER_SIZE,
                           stdin);
        data_length += read_chars;
    } while (read_chars == PCMK__BUFFER_SIZE);

    if (data_length == 0) {
        crm_warn("No XML supplied on stdin");
        free(xml_buffer);
        return NULL;
    }

    xml_buffer[data_length] = '\0';
    xml_obj = string2xml(xml_buffer);
    free(xml_buffer);

    crm_log_xml_trace(xml_obj, "Created fragment");
    return xml_obj;
}

static char *
decompress_file(const char *filename)
{
    char *buffer = NULL;
    int rc = 0;
    size_t length = 0, read_len = 0;
    BZFILE *bz_file = NULL;
    FILE *input = fopen(filename, "r");

    if (input == NULL) {
        crm_perror(LOG_ERR, "Could not open %s for reading", filename);
        return NULL;
    }

    bz_file = BZ2_bzReadOpen(&rc, input, 0, 0, NULL, 0);
    if (rc != BZ_OK) {
        crm_err("Could not prepare to read compressed %s: %s "
                CRM_XS " bzerror=%d", filename, bz2_strerror(rc), rc);
        BZ2_bzReadClose(&rc, bz_file);
        fclose(input);
        return NULL;
    }

    rc = BZ_OK;
    // cppcheck seems not to understand the abort-logic in pcmk__realloc
    // cppcheck-suppress memleak
    while (rc == BZ_OK) {
        buffer = pcmk__realloc(buffer, PCMK__BUFFER_SIZE + length + 1);
        read_len = BZ2_bzRead(&rc, bz_file, buffer + length, PCMK__BUFFER_SIZE);

        crm_trace("Read %ld bytes from file: %d", (long)read_len, rc);

        if (rc == BZ_OK || rc == BZ_STREAM_END) {
            length += read_len;
        }
    }

    buffer[length] = '\0';

    if (rc != BZ_STREAM_END) {
        crm_err("Could not read compressed %s: %s "
                CRM_XS " bzerror=%d", filename, bz2_strerror(rc), rc);
        free(buffer);
        buffer = NULL;
    }

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

xmlNode *
filename2xml(const char *filename)
{
    xmlNode *xml = NULL;
    xmlDocPtr output = NULL;
    bool uncompressed = true;
    xmlParserCtxtPtr ctxt = NULL;
    xmlErrorPtr last_error = NULL;

    /* create a parser context */
    ctxt = xmlNewParserCtxt();
    CRM_CHECK(ctxt != NULL, return NULL);

    xmlCtxtResetLastError(ctxt);
    xmlSetGenericErrorFunc(ctxt, pcmk__log_xmllib_err);

    if (filename) {
        uncompressed = !pcmk__ends_with_ext(filename, ".bz2");
    }

    if (pcmk__str_eq(filename, "-", pcmk__str_null_matches)) {
        /* STDIN_FILENO == fileno(stdin) */
        output = xmlCtxtReadFd(ctxt, STDIN_FILENO, "unknown.xml", NULL,
                               PCMK__XML_PARSE_OPTS);

    } else if (uncompressed) {
        output = xmlCtxtReadFile(ctxt, filename, NULL, PCMK__XML_PARSE_OPTS);

    } else {
        char *input = decompress_file(filename);

        output = xmlCtxtReadDoc(ctxt, (pcmkXmlStr) input, NULL, NULL,
                                PCMK__XML_PARSE_OPTS);
        free(input);
    }

    if (output && (xml = xmlDocGetRootElement(output))) {
        pcmk__strip_xml_text(xml);
    }

    last_error = xmlCtxtGetLastError(ctxt);
    if (last_error && last_error->code != XML_ERR_OK) {
        /* crm_abort(__FILE__,__func__,__LINE__, "last_error->code != XML_ERR_OK", TRUE, TRUE); */
        /*
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlErrorLevel
         * http://xmlsoft.org/html/libxml-xmlerror.html#xmlParserErrors
         */
        crm_err("Parsing failed (domain=%d, level=%d, code=%d): %s",
                last_error->domain, last_error->level, last_error->code, last_error->message);

        if (last_error && last_error->code != XML_ERR_OK) {
            crm_err("Couldn't%s parse %s", xml ? " fully" : "", filename);
            if (xml != NULL) {
                crm_log_xml_err(xml, "Partial");
            }
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

    result = crm_xml_add(xe, XML_CIB_ATTR_WRITTEN,
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
    crm_xml_add(xml, XML_ATTR_ID, id);
    free(id);
}

/*!
 * \internal
 * \brief Write XML to a file stream
 *
 * \param[in]     xml_node  XML to write
 * \param[in]     filename  Name of file being written (for logging only)
 * \param[in,out] stream    Open file stream corresponding to filename
 * \param[in]     compress  Whether to compress XML before writing
 * \param[out]    nbytes    Number of bytes written
 *
 * \return Standard Pacemaker return code
 */
static int
write_xml_stream(xmlNode *xml_node, const char *filename, FILE *stream,
                 bool compress, unsigned int *nbytes)
{
    int rc = pcmk_rc_ok;
    char *buffer = NULL;

    *nbytes = 0;
    crm_log_xml_trace(xml_node, "writing");

    buffer = dump_xml_formatted(xml_node);
    CRM_CHECK(buffer && strlen(buffer),
              crm_log_xml_warn(xml_node, "formatting failed");
              rc = pcmk_rc_error;
              goto bail);

    if (compress) {
        unsigned int in = 0;
        BZFILE *bz_file = NULL;

        rc = BZ_OK;
        bz_file = BZ2_bzWriteOpen(&rc, stream, 5, 0, 30);
        if (rc != BZ_OK) {
            crm_warn("Not compressing %s: could not prepare file stream: %s "
                     CRM_XS " bzerror=%d", filename, bz2_strerror(rc), rc);
        } else {
            BZ2_bzWrite(&rc, bz_file, buffer, strlen(buffer));
            if (rc != BZ_OK) {
                crm_warn("Not compressing %s: could not compress data: %s "
                         CRM_XS " bzerror=%d errno=%d",
                         filename, bz2_strerror(rc), rc, errno);
            }
        }

        if (rc == BZ_OK) {
            BZ2_bzWriteClose(&rc, bz_file, 0, &in, nbytes);
            if (rc != BZ_OK) {
                crm_warn("Not compressing %s: could not write compressed data: %s "
                         CRM_XS " bzerror=%d errno=%d",
                         filename, bz2_strerror(rc), rc, errno);
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
 * \brief Write XML to a file descriptor
 *
 * \param[in] xml_node  XML to write
 * \param[in] filename  Name of file being written (for logging only)
 * \param[in] fd        Open file descriptor corresponding to filename
 * \param[in] compress  Whether to compress XML before writing
 *
 * \return Number of bytes written on success, -errno otherwise
 */
int
write_xml_fd(xmlNode * xml_node, const char *filename, int fd, gboolean compress)
{
    FILE *stream = NULL;
    unsigned int nbytes = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK(xml_node && (fd > 0), return -EINVAL);
    stream = fdopen(fd, "w");
    if (stream == NULL) {
        return -errno;
    }
    rc = write_xml_stream(xml_node, filename, stream, compress, &nbytes);
    if (rc != pcmk_rc_ok) {
        return pcmk_rc2legacy(rc);
    }
    return (int) nbytes;
}

/*!
 * \brief Write XML to a file
 *
 * \param[in] xml_node  XML to write
 * \param[in] filename  Name of file to write
 * \param[in] compress  Whether to compress XML before writing
 *
 * \return Number of bytes written on success, -errno otherwise
 */
int
write_xml_file(xmlNode * xml_node, const char *filename, gboolean compress)
{
    FILE *stream = NULL;
    unsigned int nbytes = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK(xml_node && filename, return -EINVAL);
    stream = fopen(filename, "w");
    if (stream == NULL) {
        return -errno;
    }
    rc = write_xml_stream(xml_node, filename, stream, compress, &nbytes);
    if (rc != pcmk_rc_ok) {
        return pcmk_rc2legacy(rc);
    }
    return (int) nbytes;
}

// Replace a portion of a dynamically allocated string (reallocating memory)
static char *
replace_text(char *text, int start, size_t *length, const char *replace)
{
    size_t offset = strlen(replace) - 1; // We have space for 1 char already

    *length += offset;
    text = pcmk__realloc(text, *length);

    for (size_t lpc = (*length) - 1; lpc > (start + offset); lpc--) {
        text[lpc] = text[lpc - offset];
    }

    memcpy(text + start, replace, offset + 1);
    return text;
}

/*!
 * \brief Replace special characters with their XML escape sequences
 *
 * \param[in] text  Text to escape
 *
 * \return Newly allocated string equivalent to \p text but with special
 *         characters replaced with XML escape sequences (or NULL if \p text
 *         is NULL)
 */
char *
crm_xml_escape(const char *text)
{
    size_t length;
    char *copy;

    /*
     * When xmlCtxtReadDoc() parses &lt; and friends in a
     * value, it converts them to their human readable
     * form.
     *
     * If one uses xmlNodeDump() to convert it back to a
     * string, all is well, because special characters are
     * converted back to their escape sequences.
     *
     * However xmlNodeDump() is randomly dog slow, even with the same
     * input. So we need to replicate the escaping in our custom
     * version so that the result can be re-parsed by xmlCtxtReadDoc()
     * when necessary.
     */

    if (text == NULL) {
        return NULL;
    }

    length = 1 + strlen(text);
    copy = strdup(text);
    CRM_ASSERT(copy != NULL);
    for (size_t index = 0; index < length; index++) {
        if(copy[index] & 0x80 && copy[index+1] & 0x80){
            index++;
            break;
        }
        switch (copy[index]) {
            case 0:
                break;
            case '<':
                copy = replace_text(copy, index, &length, "&lt;");
                break;
            case '>':
                copy = replace_text(copy, index, &length, "&gt;");
                break;
            case '"':
                copy = replace_text(copy, index, &length, "&quot;");
                break;
            case '\'':
                copy = replace_text(copy, index, &length, "&apos;");
                break;
            case '&':
                copy = replace_text(copy, index, &length, "&amp;");
                break;
            case '\t':
                /* Might as well just expand to a few spaces... */
                copy = replace_text(copy, index, &length, "    ");
                break;
            case '\n':
                copy = replace_text(copy, index, &length, "\\n");
                break;
            case '\r':
                copy = replace_text(copy, index, &length, "\\r");
                break;
            default:
                /* Check for and replace non-printing characters with their octal equivalent */
                if(copy[index] < ' ' || copy[index] > '~') {
                    char *replace = crm_strdup_printf("\\%.3o", copy[index]);

                    copy = replace_text(copy, index, &length, replace);
                    free(replace);
                }
        }
    }
    return copy;
}

/*!
 * \internal
 * \brief Append an XML attribute to a buffer
 *
 * \param[in]     attr     Attribute to append
 * \param[in,out] buffer   Where to append the content (must not be \p NULL)
 */
static void
dump_xml_attr(const xmlAttr *attr, GString *buffer)
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
    const char *name = crm_element_name(data);
    bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
    bool filtered = pcmk_is_set(options, pcmk__xml_fmt_filtered);
    int spaces = pretty? (2 * depth) : 0;

    CRM_ASSERT(name != NULL);

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    pcmk__g_strcat(buffer, "<", name, NULL);

    for (const xmlAttr *attr = pcmk__xe_first_attr(data); attr != NULL;
         attr = attr->next) {

        if (!filtered || !pcmk__xa_filterable((const char *) (attr->name))) {
            dump_xml_attr(attr, buffer);
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
        xmlNode *xChild = NULL;
        for(xChild = data->children; xChild != NULL; xChild = xChild->next) {
            pcmk__xml2text(xChild, options, buffer, depth + 1);
        }

        for (int lpc = 0; lpc < spaces; lpc++) {
            g_string_append_c(buffer, ' ');
        }

        pcmk__g_strcat(buffer, "</", name, ">", NULL);

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
    /* @COMPAT: Remove when log_data_element() is removed. There are no internal
     * code paths to this, except through the deprecated log_data_element().
     */
    bool pretty = pcmk_is_set(options, pcmk__xml_fmt_pretty);
    int spaces = pretty? (2 * depth) : 0;

    for (int lpc = 0; lpc < spaces; lpc++) {
        g_string_append_c(buffer, ' ');
    }

    g_string_append(buffer, (const gchar *) data->content);

    if (pretty) {
        g_string_append_c(buffer, '\n');
    }
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

#define PCMK__XMLDUMP_STATS 0

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
pcmk__xml2text(xmlNodePtr data, uint32_t options, GString *buffer, int depth)
{
    if (data == NULL) {
        crm_trace("Nothing to dump");
        return;
    }

    CRM_ASSERT(buffer != NULL);
    CRM_CHECK(depth >= 0, depth = 0);

    if (pcmk_is_set(options, pcmk__xml_fmt_full)) {
        /* libxml's serialization reuse is a good idea, sadly we cannot
           apply it for the filtered cases (preceding filtering pass
           would preclude further reuse of such in-situ modified XML
           in generic context and is likely not a win performance-wise),
           and there's also a historically unstable throughput argument
           (likely stemming from memory allocation overhead, eventhough
           that shall be minimized with defaults preset in crm_xml_init) */
#if (PCMK__XMLDUMP_STATS - 0)
        time_t next, new = time(NULL);
#endif
        xmlDoc *doc;
        xmlOutputBuffer *xml_buffer;

        doc = getDocPtr(data);
        /* doc will only be NULL if data is */
        CRM_CHECK(doc != NULL, return);

        xml_buffer = xmlAllocOutputBuffer(NULL);
        CRM_ASSERT(xml_buffer != NULL);

        /* XXX we could setup custom allocation scheme for the particular
               buffer, but it's subsumed with crm_xml_init that needs to
               be invoked prior to entering this function as such, since
               its other branch vitally depends on it -- what can be done
               about this all is to have a facade parsing functions that
               would 100% mark entering libxml code for us, since we don't
               do anything as crazy as swapping out the binary form of the
               parsed tree (but those would need to be strictly used as
               opposed to libxml's raw functions) */

        xmlNodeDumpOutput(xml_buffer, doc, data, 0,
                          pcmk_is_set(options, pcmk__xml_fmt_pretty), NULL);
        /* attempt adding final NL - failing shouldn't be fatal here */
        (void) xmlOutputBufferWrite(xml_buffer, sizeof("\n") - 1, "\n");
        if (xml_buffer->buffer != NULL) {
            g_string_append(buffer,
                            (const gchar *) xmlBufContent(xml_buffer->buffer));
        }

#if (PCMK__XMLDUMP_STATS - 0)
        next = time(NULL);
        if ((now + 1) < next) {
            crm_log_xml_trace(data, "Long time");
            crm_err("xmlNodeDumpOutput() -> %lld bytes took %ds",
                    (long long) buffer->len, next - now);
        }
#endif

        /* asserted allocation before so there should be something to remove */
        (void) xmlOutputBufferClose(xml_buffer);
        return;
    }

    switch(data->type) {
        case XML_ELEMENT_NODE:
            /* Handle below */
            dump_xml_element(data, options, buffer, depth);
            break;
        case XML_TEXT_NODE:
            if (pcmk_is_set(options, pcmk__xml_fmt_text)) {
                /* @COMPAT: Remove when log_data_element() is removed. There are
                 * no other internal code paths that set pcmk__xml_fmt_text.
                 * Keep an empty case handler so that we don't log an unhandled
                 * type warning.
                 */
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
            crm_warn("Unhandled type: %d", data->type);
            break;

            /*
            XML_ATTRIBUTE_NODE = 2
            XML_ENTITY_REF_NODE = 5
            XML_ENTITY_NODE = 6
            XML_PI_NODE = 7
            XML_DOCUMENT_NODE = 9
            XML_DOCUMENT_TYPE_NODE = 10
            XML_DOCUMENT_FRAG_NODE = 11
            XML_NOTATION_NODE = 12
            XML_HTML_DOCUMENT_NODE = 13
            XML_DTD_NODE = 14
            XML_ELEMENT_DECL = 15
            XML_ATTRIBUTE_DECL = 16
            XML_ENTITY_DECL = 17
            XML_NAMESPACE_DECL = 18
            XML_XINCLUDE_START = 19
            XML_XINCLUDE_END = 20
            XML_DOCB_DOCUMENT_NODE = 21
            */
    }
}

char *
dump_xml_formatted_with_text(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    GString *g_buffer = g_string_sized_new(1024);

    pcmk__xml2text(an_xml_node, pcmk__xml_fmt_pretty|pcmk__xml_fmt_full,
                   g_buffer, 0);

    pcmk__str_update(&buffer, g_buffer->str);
    g_string_free(g_buffer, TRUE);
    return buffer;
}

char *
dump_xml_formatted(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    GString *g_buffer = g_string_sized_new(1024);

    pcmk__xml2text(an_xml_node, pcmk__xml_fmt_pretty, g_buffer, 0);

    pcmk__str_update(&buffer, g_buffer->str);
    g_string_free(g_buffer, TRUE);
    return buffer;
}

char *
dump_xml_unformatted(xmlNode * an_xml_node)
{
    char *buffer = NULL;
    GString *g_buffer = g_string_sized_new(1024);

    pcmk__xml2text(an_xml_node, 0, g_buffer, 0);

    pcmk__str_update(&buffer, g_buffer->str);
    g_string_free(g_buffer, TRUE);
    return buffer;
}

gboolean
xml_has_children(const xmlNode * xml_root)
{
    if (xml_root != NULL && xml_root->children != NULL) {
        return TRUE;
    }
    return FALSE;
}

void
xml_remove_prop(xmlNode * obj, const char *name)
{
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
save_xml_to_file(xmlNode * xml, const char *desc, const char *filename)
{
    char *f = NULL;

    if (filename == NULL) {
        char *uuid = crm_generate_uuid();

        f = crm_strdup_printf("%s/%s", pcmk__get_tmpdir(), uuid);
        filename = f;
        free(uuid);
    }

    crm_info("Saving %s to %s", desc, filename);
    write_xml_file(xml, filename, FALSE);
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
    mark_xml_node_dirty(new_xml);

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
        xmlAttr *old_attr = attr_iter;
        xmlAttr *new_attr = xmlHasProp(new_xml, attr_iter->name);
        const char *name = (const char *) attr_iter->name;
        const char *old_value = crm_element_value(old_xml, name);

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
                      attr_name, crm_element_value(new_xml, attr_name),
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
    xmlNode *candidate = add_node_copy(new_parent, old_child);

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
              new_child->name, (ID(new_child)? ID(new_child) : "<no id>"),
              p_old, p_new, new_parent->name);
    mark_xml_node_dirty(new_parent);
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
    CRM_CHECK(pcmk__str_eq(crm_element_name(old_xml), crm_element_name(new_xml), pcmk__str_casei),
              return);
    CRM_CHECK(pcmk__str_eq(ID(old_xml), ID(new_xml), pcmk__str_casei), return);

    if(xml_tracking_changes(new_xml) == FALSE) {
        xml_track_changes(new_xml, NULL, NULL, FALSE);
    }

    mark_xml_changes(old_xml, new_xml, FALSE);
}

gboolean
can_prune_leaf(xmlNode * xml_node)
{
    xmlNode *cIter = NULL;
    gboolean can_prune = TRUE;
    const char *name = crm_element_name(xml_node);

    if (pcmk__strcase_any_of(name, XML_TAG_RESOURCE_REF, XML_CIB_TAG_OBJ_REF,
                             XML_ACL_TAG_ROLE_REF, XML_ACL_TAG_ROLE_REFv1, NULL)) {
        return FALSE;
    }

    for (xmlAttrPtr a = pcmk__xe_first_attr(xml_node); a != NULL; a = a->next) {
        const char *p_name = (const char *) a->name;

        if (strcmp(p_name, XML_ATTR_ID) == 0) {
            continue;
        }
        can_prune = FALSE;
    }

    cIter = pcmk__xml_first_child(xml_node);
    while (cIter) {
        xmlNode *child = cIter;

        cIter = pcmk__xml_next(cIter);
        if (can_prune_leaf(child)) {
            free_xml(child);
        } else {
            can_prune = FALSE;
        }
    }
    return can_prune;
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
        add_node_copy(parent, update);

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

    object_name = crm_element_name(update);
    object_href_val = ID(update);
    if (object_href_val != NULL) {
        object_href = XML_ATTR_ID;
    } else {
        object_href_val = crm_element_value(update, XML_ATTR_IDREF);
        object_href = (object_href_val == NULL) ? NULL : XML_ATTR_IDREF;
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

    CRM_CHECK(pcmk__str_eq(crm_element_name(target), crm_element_name(update),
                           pcmk__str_casei),
              return);

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

    if (!pcmk__str_eq(crm_element_name(to_update), crm_element_name(child), pcmk__str_none)) {
        can_update = FALSE;

    } else if (!pcmk__str_eq(ID(to_update), ID(child), pcmk__str_none)) {
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

    if (tag != NULL && !pcmk__str_eq(tag, crm_element_name(root), pcmk__str_casei)) {

    } else if (value != NULL && !pcmk__str_eq(value, crm_element_value(root, field), pcmk__str_casei)) {

    } else {
        if (*children == NULL) {
            *children = create_xml_node(NULL, __func__);
        }
        add_node_copy(*children, root);
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

    up_id = ID(update);
    child_id = ID(child);

    if (up_id == NULL || (child_id && strcmp(child_id, up_id) == 0)) {
        can_delete = TRUE;
    }
    if (!pcmk__str_eq(crm_element_name(update), crm_element_name(child), pcmk__str_casei)) {
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
            xmlNode *tmp = copy_xml(update);
            xmlDoc *doc = tmp->doc;
            xmlNode *old = NULL;

            xml_accept_changes(tmp);
            old = xmlReplaceNode(child, tmp);

            if(xml_tracking_changes(tmp)) {
                /* Replaced sections may have included relevant ACLs */
                pcmk__apply_acl(tmp);
            }

            xml_calculate_changes(old, tmp);
            xmlDocSetRootElement(doc, old);
            free_xml(old);
        }
        child = NULL;
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
    const char *name = NULL;

    CRM_CHECK(input != NULL, return NULL);

    name = crm_element_name(input);
    CRM_CHECK(name != NULL, return NULL);

    result = create_xml_node(parent, name);
    nvpairs = pcmk_xml_attrs2nvpairs(input);
    nvpairs = pcmk_sort_nvpairs(nvpairs);
    pcmk_nvpairs2xml_attrs(nvpairs, result);
    pcmk_free_nvpairs(nvpairs);

    for (child = pcmk__xml_first_child(input); child != NULL;
         child = pcmk__xml_next(child)) {

        if (recursive) {
            sorted_xml(child, result, recursive);
        } else {
            add_node_copy(result, child);
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
        if (pcmk__str_eq(name, (const char *)match->name, pcmk__str_null_matches)) {
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
    const char *name = crm_element_name(sibling);

    while (match != NULL) {
        if (!strcmp(crm_element_name(match), name)) {
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
    const char *tag = NULL;
    const char *ref = NULL;
    xmlNode *result = input;

    if (result == NULL) {
        return NULL;

    } else if (top == NULL) {
        top = input;
    }

    tag = crm_element_name(result);
    ref = crm_element_value(result, XML_ATTR_IDREF);

    if (ref != NULL) {
        char *xpath_string = crm_strdup_printf("//%s[@" XML_ATTR_ID "='%s']",
                                               tag, ref);

        result = get_xpath_object(xpath_string, top, LOG_ERR);
        if (result == NULL) {
            char *nodePath = (char *)xmlGetNodePath(top);

            crm_err("No match for %s found in %s: Invalid configuration",
                    xpath_string, pcmk__s(nodePath, "unrecognizable path"));
            free(nodePath);
        }
        free(xpath_string);
    }
    return result;
}

char *
pcmk__xml_artefact_root(enum pcmk__xml_artefact_ns ns)
{
    static const char *base = NULL;
    char *ret = NULL;

    if (base == NULL) {
        base = getenv("PCMK_schema_directory");
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

char *
pcmk__xml_artefact_path(enum pcmk__xml_artefact_ns ns, const char *filespec)
{
    char *base = pcmk__xml_artefact_root(ns), *ret = NULL;

    switch (ns) {
        case pcmk__xml_artefact_ns_legacy_rng:
        case pcmk__xml_artefact_ns_base_rng:
            ret = crm_strdup_printf("%s/%s.rng", base, filespec);
            break;
        case pcmk__xml_artefact_ns_legacy_xslt:
        case pcmk__xml_artefact_ns_base_xslt:
            ret = crm_strdup_printf("%s/%s.xsl", base, filespec);
            break;
        default:
            crm_err("XML artefact family specified as %u not recognized", ns);
    }
    free(base);

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
        if (node->type == XML_ELEMENT_NODE &&
            pcmk__str_eq(child_element_name, (const char *) node->name, pcmk__str_null_matches)) {
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
                          ((id == NULL)? id : XML_ATTR_ID), id);
}

void
crm_destroy_xml(gpointer data)
{
    free_xml(data);
}

int
add_node_nocopy(xmlNode *parent, const char *name, xmlNode *child)
{
    add_node_copy(parent, child);
    free_xml(child);
    return 1;
}

// LCOV_EXCL_STOP
// End deprecated API

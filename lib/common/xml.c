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

#include <glib.h>                       // gboolean, GString
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlstring.h>           // xmlGetUTF8Char()

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>    // PCMK__XML_LOG_BASE, etc.
#include "crmcommon_private.h"

//! libxml2 supports only XML version 1.0, at least as of libxml2-2.12.5
#define XML_VERSION ((pcmkXmlStr) "1.0")

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

void
pcmk__set_xml_doc_flag(xmlNode *xml, enum xml_private_flags flag)
{
    if (xml != NULL) {
        xml_doc_private_t *docpriv = xml->doc->_private;

        pcmk__set_xml_flags(docpriv, flag);
    }
}

// Mark document, element, and all element's parents as changed
void
pcmk__mark_xml_node_dirty(xmlNode *xml)
{
    pcmk__set_xml_doc_flag(xml, pcmk__xf_dirty);
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

    if (!pcmk__tracking_xml_changes(xml, false)) {
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
    CRM_CHECK(node != NULL, return true);

    if (node->_private != NULL) {
        return true;
    }

    switch (node->type) {
        case XML_DOCUMENT_NODE:
            {
                xml_doc_private_t *docpriv =
                    pcmk__assert_alloc(1, sizeof(xml_doc_private_t));

                docpriv->check = PCMK__XML_DOC_PRIVATE_MAGIC;
                node->_private = docpriv;
                pcmk__set_xml_flags(docpriv, pcmk__xf_dirty|pcmk__xf_created);
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
                pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_created);

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

    if (pcmk__tracking_xml_changes(node, false)) {
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
    pcmk__xml_reset_node_flags(xml, NULL);
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
 * \brief Parse an integer score from an XML attribute
 *
 * \param[in]  xml            XML element with attribute to parse
 * \param[in]  name           Name of attribute to parse
 * \param[out] score          Where to store parsed score (can be NULL to
 *                            just validate)
 * \param[in]  default_score  What to return if the attribute value is not
 *                            present or invalid
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_get_score(const xmlNode *xml, const char *name, int *score,
                   int default_score)
{
    const char *value = NULL;

    CRM_CHECK((xml != NULL) && (name != NULL), return EINVAL);
    value = crm_element_value(xml, name);
    return pcmk_parse_score(value, score, default_score);
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
 * \c pcmk_parse_score().
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
 * \param[in]     value   New value of attribute to set (if NULL, initial value
 *                        will be left unchanged)
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
        // @TODO Maybe instead delete the attribute or set it to 0
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

            int add = 1;
            int old_value_i = 0;
            int rc = pcmk_rc_ok;

            // If we're expanding ourselves, no previous value was set; use 0
            if (old_value != value) {
                rc = pcmk_parse_score(old_value, &old_value_i, 0);
                if (rc != pcmk_rc_ok) {
                    // @TODO This is inconsistent with old_value==NULL
                    crm_trace("Using 0 before incrementing %s because '%s' "
                              "is not a score", name, old_value);
                }
            }

            /* value="X++": new value of X is old_value + 1
             * value="X+=Y": new value of X is old_value + Y (for some number Y)
             */
            if (*v != '+') {
                rc = pcmk_parse_score(++v, &add, 0);
                if (rc != pcmk_rc_ok) {
                    // @TODO We should probably skip expansion instead
                    crm_trace("Not incrementing %s because '%s' does not have "
                              "a valid increment", name, value);
                }
            }

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
 * \brief Compare two XML attributes by name
 *
 * \param[in] a  First XML attribute to compare
 * \param[in] b  Second XML attribute to compare
 *
 * \retval  negative \c a->name is \c NULL or comes before \c b->name
 *                   lexicographically
 * \retval  0        \c a->name and \c b->name are equal
 * \retval  positive \c b->name is \c NULL or comes before \c a->name
 *                   lexicographically
 */
static gint
compare_xml_attr(gconstpointer a, gconstpointer b)
{
    const xmlAttr *attr_a = a;
    const xmlAttr *attr_b = b;

    return pcmk__strcmp((const char *) attr_a->name,
                        (const char *) attr_b->name, pcmk__str_none);
}

/*!
 * \internal
 * \brief Sort an XML element's attributes by name
 *
 * This does not consider ACLs and does not mark the attributes as deleted or
 * dirty. Upon return, all attributes still exist and are set to the same values
 * as before the call. The only thing that may change is the order of the
 * attribute list.
 *
 * \param[in,out] xml  XML element whose attributes to sort
 */
void
pcmk__xe_sort_attrs(xmlNode *xml)
{
    GSList *attr_list = NULL;

    for (xmlAttr *iter = pcmk__xe_first_attr(xml); iter != NULL;
         iter = iter->next) {
        attr_list = g_slist_prepend(attr_list, iter);
    }
    attr_list = g_slist_sort(attr_list, compare_xml_attr);

    for (GSList *iter = attr_list; iter != NULL; iter = iter->next) {
        xmlNode *attr = iter->data;

        xmlUnlinkNode(attr);
        xmlAddChild(xml, attr);
    }
    g_slist_free(attr_list);
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
        pcmk__xa_remove(xmlHasProp(element, (pcmkXmlStr) name), false);
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
            if (pcmk__xa_remove(a, false) != pcmk_rc_ok) {
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

    pcmk__assert(!pcmk__str_empty(name));

    if (parent == NULL) {
        xmlDoc *doc = pcmk__xml_new_doc();

        node = xmlNewDocRawNode(doc, NULL, (pcmkXmlStr) name, NULL);
        pcmk__mem_assert(node);

        xmlDocSetRootElement(doc, node);

    } else {
        node = xmlNewChild(parent, NULL, (pcmkXmlStr) name, NULL);
        pcmk__mem_assert(node);
    }

    pcmk__xml_new_private_data(node);
    return node;
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

        /* xmlNodeSetContent() frees node->children and replaces it with new
         * text. If this function is called for a node that already has a non-
         * text child, it's a bug.
         */
        CRM_CHECK((node->children == NULL)
                  || (node->children->type == XML_TEXT_NODE),
                  return);

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
                pcmk__assert(vasprintf(&buf, format, ap) >= 0);
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
    c = xmlGetUTF8Char((pcmkXmlStr) utf8, len);
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
    c = xmlGetUTF8Char((pcmkXmlStr) utf8, len);
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
 * \brief Set a formatted string as an XML element's ID
 *
 * If the formatted string would not be a valid ID, it's first sanitized by
 * \c pcmk__xml_sanitize_id().
 *
 * \param[in,out] node    Node whose ID to set
 * \param[in]     format  <tt>printf(3)</tt>-style format string
 * \param[in]     ...     Arguments for \p format
 */
G_GNUC_PRINTF(2, 3)
void
pcmk__xe_set_id(xmlNode *node, const char *format, ...)
{
    char *id = NULL;
    va_list ap;

    pcmk__assert(!pcmk__str_empty(format));

    if (node == NULL) {
        return;
    }

    va_start(ap, format);
    pcmk__assert(vasprintf(&id, format, ap) >= 0);
    va_end(ap);

    if (!xmlValidateNameValue((pcmkXmlStr) id)) {
        pcmk__xml_sanitize_id(id);
    }
    crm_xml_add(node, PCMK_XA_ID, id);
    free(id);
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

    /* Restore the old value (without setting dirty flag recursively upwards or
     * checking ACLs)
     */
    pcmk__clear_xml_flags(docpriv, pcmk__xf_tracking);
    crm_xml_add(new_xml, attr_name, old_value);
    pcmk__set_xml_flags(docpriv, pcmk__xf_tracking);

    // Reset flags (so the attribute doesn't appear as newly created)
    attr = xmlHasProp(new_xml, (pcmkXmlStr) attr_name);
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
    char *vcopy = crm_element_value_copy(new_xml, attr_name);

    crm_trace("XML attribute %s was changed from '%s' to '%s' in %s",
              attr_name, old_value, vcopy, element);

    // Restore the original value (without checking ACLs)
    pcmk__clear_xml_flags(docpriv, pcmk__xf_tracking);
    crm_xml_add(new_xml, attr_name, old_value);
    pcmk__set_xml_flags(docpriv, pcmk__xf_tracking);

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
    pcmk__xml_tree_foreach(candidate, pcmk__xml_reset_node_flags, NULL);

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
        mark_xml_tree_dirty_created(new_xml);
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
 *
 * \note At least one of \p parent and \p target must be non-<tt>NULL</tt>.
 * \note This function is recursive. For the top-level call, \p parent is
 *       \c NULL and \p target is not \c NULL. For recursive calls, \p target is
 *       \c NULL and \p parent is not \c NULL.
 */
static void
update_xe(xmlNode *parent, xmlNode *target, xmlNode *update, uint32_t flags)
{
    // @TODO Try to refactor further, possibly using pcmk__xml_tree_foreach()
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

    pcmk__xe_copy_attrs(target, update, flags);

    for (xmlNode *child = pcmk__xml_first_child(update); child != NULL;
         child = pcmk__xml_next(child)) {

        crm_trace("Updating child of %s", pcmk__s(trace_s, update_name));
        update_xe(target, NULL, child, flags);
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
    // Pass old for its doc; it won't remain the parent of new
    new = pcmk__xml_copy(old, new);
    old = xmlReplaceNode(old, new);

    // old == NULL means memory allocation error
    pcmk__assert(old != NULL);

    // May be unnecessary but avoids slight changes to some test outputs
    pcmk__xml_tree_foreach(new, pcmk__xml_reset_node_flags, NULL);

    if (xml_tracking_changes(new)) {
        // Replaced sections may have included relevant ACLs
        pcmk__apply_acl(new);
    }
    xml_calculate_changes(old, new);
    pcmk__xml_free_node(old);
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
 * \c update_xe()).
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
    update_xe(NULL, xml, update, data->flags);

    // Found a match and replaced it; stop traversing tree
    return false;
}

/*!
 * \internal
 * \brief Search an XML tree depth-first and update the first matching element
 *
 * "Update" means to merge a source subtree into a target subtree (see
 * \c update_xe()).
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

    pcmk__assert(handler != NULL);

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

#include <crm/common/nvpair_compat.h>
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

xmlNode *
expand_idref(xmlNode *input, xmlNode *top)
{
    return pcmk__xe_resolve_idref(input, top);
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
    pcmk__assert(len > 0);

    crm_xml_sanitize_id(id);
    crm_xml_add(xml, PCMK_XA_ID, id);
    free(id);
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

// LCOV_EXCL_STOP
// End deprecated API

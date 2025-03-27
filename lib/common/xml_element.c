/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdarg.h>                     // va_start(), etc.
#include <stdint.h>                     // uint32_t
#include <stdio.h>                      // NULL, etc.
#include <stdlib.h>                     // free(), etc.
#include <string.h>                     // strchr(), etc.
#include <sys/types.h>                  // time_t, etc.

#include <libxml/tree.h>                // xmlNode, etc.
#include <libxml/valid.h>               // xmlValidateNameValue()
#include <libxml/xmlstring.h>           // xmlChar

#include <crm/crm.h>
#include <crm/common/nvpair.h>          // crm_xml_add(), etc.
#include <crm/common/results.h>         // pcmk_rc_ok, etc.
#include <crm/common/xml.h>
#include "crmcommon_private.h"

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

    CRM_CHECK((attr_v == NULL) || (attr_n != NULL), return NULL);

    if (parent == NULL) {
        return NULL;
    }

    child = parent->children;
    while ((child != NULL) && (child->type != XML_ELEMENT_NODE)) {
        child = child->next;
    }

    for (; child != NULL; child = pcmk__xe_next(child, NULL)) {
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

    if (attr_n == NULL) {
        crm_trace("%s XML has no child element of %s type",
                  (const char *) parent->name, pcmk__s(node_name, "any"));
    } else {
        crm_trace("%s XML has no child element of %s type with %s='%s'",
                  (const char *) parent->name, pcmk__s(node_name, "any"),
                  attr_n, attr_v);
    }
    return NULL;
}

/*!
 * \internal
 * \brief Return next sibling element of an XML element
 *
 * \param[in] xml           XML element to check
 * \param[in] element_name  If not NULL, get next sibling with this element name
 *
 * \return Next desired sibling of \p xml (or NULL if none)
 */
xmlNode *
pcmk__xe_next(const xmlNode *xml, const char *element_name)
{
    for (xmlNode *next = (xml == NULL)? NULL : xml->next;
         next != NULL; next = next->next) {
        if ((next->type == XML_ELEMENT_NODE)
            && ((element_name == NULL) || pcmk__xe_is(next, element_name))) {
            return next;
        }
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
        pcmk__xa_remove(xmlHasProp(element, (const xmlChar *) name), false);
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
 * \param[in]     force      If \c true, remove matching attributes immediately,
 *                           ignoring ACLs and change tracking
 * \param[in]     match      If not NULL, only remove attributes for which
 *                           this function returns true
 * \param[in,out] user_data  Data to pass to \p match
 */
void
pcmk__xe_remove_matching_attrs(xmlNode *element, bool force,
                               bool (*match)(xmlAttrPtr, void *),
                               void *user_data)
{
    xmlAttrPtr next = NULL;

    for (xmlAttrPtr a = pcmk__xe_first_attr(element); a != NULL; a = next) {
        next = a->next; // Grab now because attribute might get removed
        if ((match == NULL) || match(a, user_data)) {
            if (pcmk__xa_remove(a, force) != pcmk_rc_ok) {
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

        node = xmlNewDocRawNode(doc, NULL, (const xmlChar *) name, NULL);
        pcmk__mem_assert(node);

        xmlDocSetRootElement(doc, node);

    } else {
        node = xmlNewChild(parent, NULL, (const xmlChar *) name, NULL);
        pcmk__mem_assert(node);
    }

    pcmk__xml_new_private_data(node);
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

        xmlNodeSetContent(node, (const xmlChar *) content);
        free(buf);
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

    if (!xmlValidateNameValue((const xmlChar *) id)) {
        pcmk__xml_sanitize_id(id);
    }
    crm_xml_add(node, PCMK_XA_ID, id);
    free(id);
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
         xml = pcmk__xe_next(xml, NULL)) {

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

    if (pcmk__xml_doc_all_flags_set(new->doc, pcmk__xf_tracking)) {
        // Replaced sections may have included relevant ACLs
        pcmk__apply_acl(new);
    }
    pcmk__xml_mark_changes(old, new);
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
         xml = pcmk__xe_next(xml, NULL)) {

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

// XML attribute handling

/*!
 * \brief Create an XML attribute with specified name and value
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     value  Attribute value to set
 *
 * \return New value on success, \c NULL otherwise
 * \note This does nothing if node, name, or value are \c NULL or empty.
 */
const char *
crm_xml_add(xmlNode *node, const char *name, const char *value)
{
    // @TODO Replace with internal function that returns the new attribute
    bool dirty = FALSE;
    xmlAttr *attr = NULL;

    CRM_CHECK(node != NULL, return NULL);
    CRM_CHECK(name != NULL, return NULL);

    if (value == NULL) {
        return NULL;
    }

    if (pcmk__xml_doc_all_flags_set(node->doc, pcmk__xf_tracking)) {
        const char *old = crm_element_value(node, name);

        if (old == NULL || value == NULL || strcmp(old, value) != 0) {
            dirty = TRUE;
        }
    }

    if (dirty && (pcmk__check_acl(node, name, pcmk__xf_acl_create) == FALSE)) {
        crm_trace("Cannot add %s=%s to %s", name, value, node->name);
        return NULL;
    }

    attr = xmlSetProp(node, (const xmlChar *) name, (const xmlChar *) value);

    /* If the attribute already exists, this does nothing. Attribute values
     * don't get private data.
     */
    pcmk__xml_new_private_data((xmlNode *) attr);

    if (dirty) {
        pcmk__mark_xml_attr_dirty(attr);
    }

    CRM_CHECK(attr && attr->children && attr->children->content, return NULL);
    return (char *)attr->children->content;
}


/*!
 * \brief Create an XML attribute with specified name and integer value
 *
 * This is like \c crm_xml_add() but taking an integer value.
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     value  Attribute value to set
 *
 * \return New value as string on success, \c NULL otherwise
 * \note This does nothing if node or name are \c NULL or empty.
 */
const char *
crm_xml_add_int(xmlNode *node, const char *name, int value)
{
    char *number = pcmk__itoa(value);
    const char *added = crm_xml_add(node, name, number);

    free(number);
    return added;
}

/*!
 * \brief Create an XML attribute with specified name and unsigned value
 *
 * This is like \c crm_xml_add() but taking a guint value.
 *
 * \param[in,out] node   XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     ms     Attribute value to set
 *
 * \return New value as string on success, \c NULL otherwise
 * \note This does nothing if node or name are \c NULL or empty.
 */
const char *
crm_xml_add_ms(xmlNode *node, const char *name, guint ms)
{
    char *number = crm_strdup_printf("%u", ms);
    const char *added = crm_xml_add(node, name, number);

    free(number);
    return added;
}

// Maximum size of null-terminated string representation of 64-bit integer
// -9223372036854775808
#define LLSTRSIZE 21

/*!
 * \brief Create an XML attribute with specified name and long long int value
 *
 * This is like \c crm_xml_add() but taking a long long int value. It is a
 * useful equivalent for defined types like time_t, etc.
 *
 * \param[in,out] xml    XML node to modify
 * \param[in]     name   Attribute name to set
 * \param[in]     value  Attribute value to set
 *
 * \return New value as string on success, \c NULL otherwise
 * \note This does nothing if xml or name are \c NULL or empty.
 *       This does not support greater than 64-bit values.
 */
const char *
crm_xml_add_ll(xmlNode *xml, const char *name, long long value)
{
    char s[LLSTRSIZE] = { '\0', };

    if (snprintf(s, LLSTRSIZE, "%lld", (long long) value) == LLSTRSIZE) {
        return NULL;
    }
    return crm_xml_add(xml, name, s);
}

/*!
 * \brief Create XML attributes for seconds and microseconds
 *
 * This is like \c crm_xml_add() but taking a struct timeval.
 *
 * \param[in,out] xml        XML node to modify
 * \param[in]     name_sec   Name of XML attribute for seconds
 * \param[in]     name_usec  Name of XML attribute for microseconds (or NULL)
 * \param[in]     value      Time value to set
 *
 * \return New seconds value as string on success, \c NULL otherwise
 * \note This does nothing if xml, name_sec, or value is \c NULL.
 */
const char *
crm_xml_add_timeval(xmlNode *xml, const char *name_sec, const char *name_usec,
                    const struct timeval *value)
{
    const char *added = NULL;

    if (xml && name_sec && value) {
        added = crm_xml_add_ll(xml, name_sec, (long long) value->tv_sec);
        if (added && name_usec) {
            // Any error is ignored (we successfully added seconds)
            crm_xml_add_ll(xml, name_usec, (long long) value->tv_usec);
        }
    }
    return added;
}

/*!
 * \brief Retrieve the value of an XML attribute
 *
 * \param[in] data   XML node to check
 * \param[in] name   Attribute name to check
 *
 * \return Value of specified attribute (may be \c NULL)
 */
const char *
crm_element_value(const xmlNode *data, const char *name)
{
    xmlAttr *attr = NULL;

    if (data == NULL) {
        crm_err("Couldn't find %s in NULL", name ? name : "<null>");
        CRM_LOG_ASSERT(data != NULL);
        return NULL;

    } else if (name == NULL) {
        crm_err("Couldn't find NULL in %s", data->name);
        return NULL;
    }

    attr = xmlHasProp(data, (const xmlChar *) name);
    if (!attr || !attr->children) {
        return NULL;
    }
    return (const char *) attr->children->content;
}

/*!
 * \brief Retrieve the integer value of an XML attribute
 *
 * This is like \c crm_element_value() but getting the value as an integer.
 *
 * \param[in]  data  XML node to check
 * \param[in]  name  Attribute name to check
 * \param[out] dest  Where to store element value
 *
 * \return 0 on success, -1 otherwise
 */
int
crm_element_value_int(const xmlNode *data, const char *name, int *dest)
{
    const char *value = NULL;

    CRM_CHECK(dest != NULL, return -1);
    value = crm_element_value(data, name);
    if (value) {
        long long value_ll;
        int rc = pcmk__scan_ll(value, &value_ll, 0LL);

        *dest = PCMK__PARSE_INT_DEFAULT;
        if (rc != pcmk_rc_ok) {
            crm_warn("Using default for %s "
                     "because '%s' is not a valid integer: %s",
                     name, value, pcmk_rc_str(rc));
        } else if ((value_ll < INT_MIN) || (value_ll > INT_MAX)) {
            crm_warn("Using default for %s because '%s' is out of range",
                     name, value);
        } else {
            *dest = (int) value_ll;
            return 0;
        }
    }
    return -1;
}

/*!
 * \internal
 * \brief Retrieve a flag group from an XML attribute value
 *
 * This is like \c crm_element_value() except getting the value as a 32-bit
 * unsigned integer.
 *
 * \param[in]  xml            XML node to check
 * \param[in]  name           Attribute name to check (must not be NULL)
 * \param[out] dest           Where to store flags (may be NULL to just
 *                            validate type)
 * \param[in]  default_value  What to use for missing or invalid value
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_get_flags(const xmlNode *xml, const char *name, uint32_t *dest,
                   uint32_t default_value)
{
    const char *value = NULL;
    long long value_ll = 0LL;
    int rc = pcmk_rc_ok;

    if (dest != NULL) {
        *dest = default_value;
    }

    if (name == NULL) {
        return EINVAL;
    }
    if (xml == NULL) {
        return pcmk_rc_ok;
    }
    value = crm_element_value(xml, name);
    if (value == NULL) {
        return pcmk_rc_ok;
    }

    rc = pcmk__scan_ll(value, &value_ll, default_value);
    if ((value_ll < 0) || (value_ll > UINT32_MAX)) {
        value_ll = default_value;
        if (rc == pcmk_rc_ok) {
            rc = pcmk_rc_bad_input;
        }
    }

    if (dest != NULL) {
        *dest = (uint32_t) value_ll;
    }
    return rc;
}

/*!
 * \internal
 * \brief Retrieve a \c guint value from an XML attribute
 *
 * This is like \c crm_element_value() but returns the value as a \c guint.
 *
 * \param[in]  xml   XML element whose attribute to get
 * \param[in]  attr  Attribute name
 * \param[out] dest  Where to store attribute value (unchanged on error)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_get_guint(const xmlNode *xml, const char *attr, guint *dest)
{
    long long value_ll = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK((xml != NULL) && (attr != NULL) && (dest != NULL), return EINVAL);

    rc = pcmk__xe_get_ll(xml, attr, &value_ll);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    if ((value_ll < 0) || (value_ll > G_MAXUINT)) {
        return ERANGE;
    }
    *dest = (guint) value_ll;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Retrieve a <tt>long long</tt> value from an XML attribute
 *
 * This is like \c crm_element_value() but returns the value as a
 * <tt>long long</tt>
 *
 * \param[in]  xml   XML element whose attribute to get
 * \param[in]  attr  Attribute name
 * \param[out] dest  Where to store element value (unchanged on error)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_get_ll(const xmlNode *xml, const char *attr, long long *dest)
{
    const char *value = NULL;
    long long value_ll = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK((xml != NULL) && (attr != NULL) && (dest != NULL), return EINVAL);

    value = crm_element_value(xml, attr);
    if (value == NULL) {
        return ENXIO;
    }

    rc = pcmk__scan_ll(value, &value_ll, PCMK__PARSE_INT_DEFAULT);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    *dest = value_ll;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Retrieve a \c time_t value from an XML attribute
 *
 * This is like \c crm_element_value() but returns the value as a \c time_t.
 *
 * \param[in]  xml   XML element whose attribute to get
 * \param[in]  attr  Attribute name
 * \param[out] dest  Where to store attribute value (unchanged on error)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_get_time(const xmlNode *xml, const char *attr, time_t *dest)
{
    long long value_ll = 0;
    int rc = pcmk_rc_ok;

    CRM_CHECK((xml != NULL) && (attr != NULL) && (dest != NULL), return EINVAL);

    rc = pcmk__xe_get_ll(xml, attr, &value_ll);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    /* We don't do any bounds checking, since there are no constants provided
     * for the bounds of time_t, and calculating them isn't worth the effort. If
     * there are XML values beyond the native sizes, there will likely be worse
     * problems anyway.
     */
    *dest = (time_t) value_ll;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Retrieve the values of XML second/microsecond attributes as time
 *
 * This is like \c crm_element_value() but returns the value as a
 * <tt>struct timeval</tt>.
 *
 * \param[in]  xml        XML element whose attributes to get
 * \param[in]  sec_attr   Name of XML attribute for seconds
 * \param[in]  usec_attr  Name of XML attribute for microseconds
 * \param[out] dest       Where to store result (unchanged on error)
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xe_get_timeval(const xmlNode *xml, const char *sec_attr,
                     const char *usec_attr, struct timeval *dest)
{
    long long value_ll = 0;
    struct timeval result = { 0, 0 };
    int rc = pcmk_rc_ok;

    // Could allow one of sec_attr and usec_attr to be NULL in the future
    CRM_CHECK((xml != NULL) && (sec_attr != NULL) && (usec_attr != NULL)
              && (dest != NULL), return EINVAL);

    // No bounds checking; see comment in pcmk__xe_get_time()

    // Parse seconds
    rc = pcmk__xe_get_time(xml, sec_attr, &(result.tv_sec));
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    // Parse microseconds
    rc = pcmk__xe_get_ll(xml, usec_attr, &value_ll);
    if (rc != pcmk_rc_ok) {
        return rc;
    }
    result.tv_usec = (suseconds_t) value_ll;

    *dest = result;
    return pcmk_rc_ok;
}

/*!
 * \brief Retrieve the long long integer value of an XML attribute
 *
 * This is like \c crm_element_value() but getting the value as a long long int.
 *
 * \param[in]  data  XML node to check
 * \param[in]  name  Attribute name to check
 * \param[out] dest  Where to store element value
 *
 * \return 0 on success, -1 otherwise
 */
int
crm_element_value_ll(const xmlNode *data, const char *name, long long *dest)
{
    const char *value = NULL;

    CRM_CHECK(dest != NULL, return -1);
    value = crm_element_value(data, name);
    if (value != NULL) {
        int rc = pcmk__scan_ll(value, dest, PCMK__PARSE_INT_DEFAULT);

        if (rc == pcmk_rc_ok) {
            return 0;
        }
        crm_warn("Using default for %s "
                 "because '%s' is not a valid integer: %s",
                 name, value, pcmk_rc_str(rc));
    }
    return -1;
}

/*!
 * \internal
 * \brief Get a date/time object from an XML attribute value
 *
 * \param[in]  xml   XML with attribute to parse (from CIB)
 * \param[in]  attr  Name of attribute to parse
 * \param[out] t     Where to create date/time object
 *                   (\p *t must be NULL initially)
 *
 * \return Standard Pacemaker return code
 * \note The caller is responsible for freeing \p *t using crm_time_free().
 */
int
pcmk__xe_get_datetime(const xmlNode *xml, const char *attr, crm_time_t **t)
{
    const char *value = NULL;

    if ((t == NULL) || (*t != NULL) || (xml == NULL) || (attr == NULL)) {
        return EINVAL;
    }

    value = crm_element_value(xml, attr);
    if (value != NULL) {
        *t = crm_time_new(value);
        if (*t == NULL) {
            return pcmk_rc_unpack_error;
        }
    }
    return pcmk_rc_ok;
}

/*!
 * \brief Retrieve a copy of the value of an XML attribute
 *
 * This is like \c crm_element_value() but allocating new memory for the result.
 *
 * \param[in] data   XML node to check
 * \param[in] name   Attribute name to check
 *
 * \return Value of specified attribute (may be \c NULL)
 * \note The caller is responsible for freeing the result.
 */
char *
crm_element_value_copy(const xmlNode *data, const char *name)
{
    return pcmk__str_copy(crm_element_value(data, name));
}

/*!
 * \internal
 * \brief Add a boolean attribute to an XML node.
 *
 * \param[in,out] node  XML node to add attributes to
 * \param[in]     name  XML attribute to create
 * \param[in]     value Value to give to the attribute
 */
void
pcmk__xe_set_bool_attr(xmlNodePtr node, const char *name, bool value)
{
    crm_xml_add(node, name, pcmk__btoa(value));
}

/*!
 * \internal
 * \brief Extract a boolean attribute's value from an XML element, with
 *        error checking
 *
 * \param[in]  node  XML node to get attribute from
 * \param[in]  name  XML attribute to get
 * \param[out] value Destination for the value of the attribute
 *
 * \return EINVAL if \p name or \p value are NULL, ENODATA if \p node is
 *         NULL or the attribute does not exist, pcmk_rc_unknown_format
 *         if the attribute is not a boolean, and pcmk_rc_ok otherwise.
 *
 * \note \p value only has any meaning if the return value is pcmk_rc_ok.
 */
int
pcmk__xe_get_bool_attr(const xmlNode *node, const char *name, bool *value)
{
    const char *xml_value = NULL;
    int ret, rc;

    if (node == NULL) {
        return ENODATA;
    } else if (name == NULL || value == NULL) {
        return EINVAL;
    }

    xml_value = crm_element_value(node, name);

    if (xml_value == NULL) {
        return ENODATA;
    }

    rc = crm_str_to_boolean(xml_value, &ret);
    if (rc == 1) {
        *value = ret;
        return pcmk_rc_ok;
    } else {
        return pcmk_rc_bad_input;
    }
}

/*!
 * \internal
 * \brief Extract a boolean attribute's value from an XML element
 *
 * \param[in] node XML node to get attribute from
 * \param[in] name XML attribute to get
 *
 * \return True if the given \p name is an attribute on \p node and has
 *         the value \c PCMK_VALUE_TRUE, False in all other cases
 */
bool
pcmk__xe_attr_is_true(const xmlNode *node, const char *name)
{
    bool value = false;
    int rc;

    rc = pcmk__xe_get_bool_attr(node, name, &value);
    return rc == pcmk_rc_ok && value == true;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <glib.h>                       // gboolean, GSList

#include <crm/common/nvpair_compat.h>   // pcmk_xml_attrs2nvpairs(), etc.
#include <crm/common/xml_compat.h>      // crm_xml_sanitize_id()
#include <crm/common/xml_element_compat.h>

xmlNode *
expand_idref(xmlNode *input, xmlNode *top)
{
    return pcmk__xe_resolve_idref(input, top);
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
         child = pcmk__xe_next(child, NULL)) {

        if (recursive) {
            sorted_xml(child, result, recursive);
        } else {
            pcmk__xml_copy(result, child);
        }
    }

    return result;
}

const char *
crm_copy_xml_element(const xmlNode *obj1, xmlNode *obj2, const char *element)
{
    const char *value = crm_element_value(obj1, element);

    crm_xml_add(obj2, element, value);
    return value;
}

int
crm_element_value_timeval(const xmlNode *xml, const char *name_sec,
                          const char *name_usec, struct timeval *dest)
{
    long long value_i = 0;

    CRM_CHECK(dest != NULL, return -EINVAL);
    dest->tv_sec = 0;
    dest->tv_usec = 0;

    if (xml == NULL) {
        return pcmk_ok;
    }

    // No bounds checking; see comment in pcmk__xe_get_time()

    // Parse seconds
    errno = 0;
    if (crm_element_value_ll(xml, name_sec, &value_i) < 0) {
        return -errno;
    }
    dest->tv_sec = (time_t) value_i;

    // Parse microseconds
    if (crm_element_value_ll(xml, name_usec, &value_i) < 0) {
        return -errno;
    }
    dest->tv_usec = (suseconds_t) value_i;

    return pcmk_ok;
}

int
crm_element_value_epoch(const xmlNode *xml, const char *name, time_t *dest)
{
    long long value_ll = 0;

    if (crm_element_value_ll(xml, name, &value_ll) < 0) {
        return -1;
    }

    // No bounds checking; see comment in pcmk__xe_get_time()
    *dest = (time_t) value_ll;
    return pcmk_ok;
}

int
crm_element_value_ms(const xmlNode *data, const char *name, guint *dest)
{
    const char *value = NULL;
    long long value_ll;
    int rc = pcmk_rc_ok;

    CRM_CHECK(dest != NULL, return -1);
    *dest = 0;
    value = crm_element_value(data, name);
    rc = pcmk__scan_ll(value, &value_ll, 0LL);
    if (rc != pcmk_rc_ok) {
        crm_warn("Using default for %s "
                 "because '%s' is not valid milliseconds: %s",
                 name, value, pcmk_rc_str(rc));
        return -1;
    }
    if ((value_ll < 0) || (value_ll > G_MAXUINT)) {
        crm_warn("Using default for %s because '%s' is out of range",
                 name, value);
        return -1;
    }
    *dest = (guint) value_ll;
    return pcmk_ok;
}

// LCOV_EXCL_STOP
// End deprecated API

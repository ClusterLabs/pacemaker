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
#include <stddef.h>             // NULL
#include <stdlib.h>             // free()

#include <libxml/tree.h>        // xmlNode, etc.
#include <libxml/xmlstring.h>   // xmlChar

#include "crmcommon_private.h"

/*!
 * \internal
 * \brief Set the \c pcmk__xf_created flag on an attribute
 *
 * \param[in,out] attr       XML attribute
 * \param[in]     user_data  Ignored
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_attr().
 */
static bool
mark_attr_created(xmlAttr *attr, void *user_data)
{
    xml_node_private_t *nodepriv = attr->_private;

    pcmk__set_xml_flags(nodepriv, pcmk__xf_created);
    return true;
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
 * \param[in,out] new_xml    XML to modify
 * \param[in]     attr_name  Name of attribute that was deleted
 * \param[in]     old_value  Value of attribute that was deleted
 */
static void
mark_attr_deleted(xmlNode *new_xml, const char *attr_name,
                  const char *old_value)
{
    xmlAttr *attr = NULL;
    xml_node_private_t *nodepriv;

    /* Restore the old value (without setting dirty flag recursively upwards or
     * checking ACLs)
     */
    pcmk__xml_doc_clear_flags(new_xml->doc, pcmk__xf_tracking);
    pcmk__xe_set(new_xml, attr_name, old_value);
    pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_tracking);

    // Reset flags (so the attribute doesn't appear as newly created)
    attr = xmlHasProp(new_xml, (const xmlChar *) attr_name);
    nodepriv = attr->_private;
    nodepriv->flags = 0;

    // Check ACLs and mark restored value for later removal
    pcmk__xa_remove(attr, false);

    pcmk__trace("XML attribute %s=%s was removed from %s", attr_name, old_value,
                (const char *) new_xml->name);
}

/*
 * \internal
 * \brief Check ACLs for a changed XML attribute
 */
static void
mark_attr_changed(xmlNode *new_xml, const char *attr_name,
                  const char *old_value)
{
    char *vcopy = pcmk__xe_get_copy(new_xml, attr_name);

    pcmk__trace("XML attribute %s was changed from '%s' to '%s' in %s",
                attr_name, old_value, vcopy, (const char *) new_xml->name);

    // Restore the original value (without checking ACLs)
    pcmk__xml_doc_clear_flags(new_xml->doc, pcmk__xf_tracking);
    pcmk__xe_set(new_xml, attr_name, old_value);
    pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_tracking);

    // Change it back to the new value, to check ACLs
    pcmk__xe_set(new_xml, attr_name, vcopy);
    free(vcopy);
}

/*!
 * \internal
 * \brief Mark an XML attribute as having changed position
 *
 * \param[in,out] new_xml   XML to modify
 * \param[in,out] old_attr  Attribute that moved, in original XML
 * \param[in,out] new_attr  Attribute that moved, in \p new_xml
 * \param[in]     p_old     Ordinal position of \p old_attr in original XML
 * \param[in]     p_new     Ordinal position of \p new_attr in \p new_xml
 */
static void
mark_attr_moved(xmlNode *new_xml, xmlAttr *old_attr, xmlAttr *new_attr,
                int p_old, int p_new)
{
    xml_node_private_t *nodepriv = new_attr->_private;

    pcmk__trace("XML attribute %s moved from position %d to %d in %s",
                old_attr->name, p_old, p_new, (const char *) new_xml->name);

    // Mark document, element, and all element's parents as changed
    pcmk__mark_xml_node_dirty(new_xml);

    // Mark attribute as changed
    pcmk__set_xml_flags(nodepriv, pcmk__xf_dirty|pcmk__xf_moved);

    nodepriv = (p_old > p_new)? old_attr->_private : new_attr->_private;
    pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);
}

/*!
 * \internal
 * \brief Mark an XML attribute as deleted, changed, or moved if appropriate
 *
 * Given an attribute (from an old XML element) and a new XML element, check
 * whether the attribute has been deleted, changed, or moved between the old and
 * new elements. If so, mark the new XML element to indicate what changed.
 *
 * \param[in,out] old_attr   XML attribute from old element
 * \param[in,out] user_data  New XML element
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_attr().
 */
static bool
mark_attr_diff(xmlAttr *old_attr, void *user_data)
{
    xmlNode *new_xml = user_data;

    const char *name = (const char *) old_attr->name;

    xmlAttr *new_attr = xmlHasProp(new_xml, old_attr->name);
    xml_node_private_t *new_priv = NULL;

    const char *old_value = pcmk__xml_attr_value(old_attr);
    const char *new_value = NULL;

    int old_pos = 0;
    int new_pos = 0;

    if (new_attr == NULL) {
        mark_attr_deleted(new_xml, name, old_value);
        return true;
    }

    new_priv = new_attr->_private;
    new_value = pcmk__xe_get(new_xml, name);

    // This attribute isn't new
    pcmk__clear_xml_flags(new_priv, pcmk__xf_created);

    if (!pcmk__str_eq(old_value, new_value, pcmk__str_none)) {
        mark_attr_changed(new_xml, name, old_value);
        return true;
    }

    old_pos = pcmk__xml_position((xmlNode *) old_attr, pcmk__xf_skip);
    new_pos = pcmk__xml_position((xmlNode *) new_attr, pcmk__xf_skip);

    if ((old_pos == new_pos)
        || pcmk__xml_doc_all_flags_set(new_xml->doc,
                                       pcmk__xf_ignore_attr_pos)) {
        return true;
    }

    mark_attr_moved(new_xml, old_attr, new_attr, old_pos, new_pos);
    return true;
}

/*!
 * \internal
 * \brief Mark a new attribute dirty if ACLs allow creation, or remove otherwise
 *
 * We set the \c pcmk__xf_created flag on all attributes in the new XML at an
 * earlier stage of change calculation. Then we checked whether each attribute
 * was present in the old XML, and we cleared the flag if so. If the flag is
 * still set, then the attribute is truly new.
 *
 * Now we check whether ACLs allow the attribute's creation. If so, we "accept"
 * it: we mark the attribute as dirty and modified, and we mark all of its
 * parents as dirty. Otherwise, we reject it by removing the attribute (ignoring
 * ACLs and change tracking for the removal).
 *
 * \param[in,out] attr       XML attribute to mark dirty or remove
 * \param[in]     user_data  Ignored
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_attr().
 */
static bool
check_new_attr_acls(xmlAttr *attr, void *user_data)
{
    const char *name = (const char *) attr->name;
    const char *value = pcmk__xml_attr_value(attr);
    const xml_node_private_t *nodepriv = attr->_private;
    xmlNode *new_xml = attr->parent;
    const char *new_xml_id = pcmk__s(pcmk__xe_id(new_xml), "without ID");

    if (!pcmk__is_set(nodepriv->flags, pcmk__xf_created)) {
        return true;
    }

    /* Check ACLs (we can't use the remove-then-create trick because it
     * would modify the attribute position).
     */
    if (!pcmk__check_acl(new_xml, name, pcmk__xf_acl_write)) {
        pcmk__trace("ACLs prevent creation of attribute %s=%s in %s %s", name,
                    value, (const char *) new_xml->name, new_xml_id);
        pcmk__xa_remove(attr, true);
        return true;
    }

    pcmk__trace("Created new attribute %s=%s in %s %s", name, value,
                (const char *) new_xml->name, new_xml_id);
    pcmk__mark_xml_attr_dirty(attr);
    return true;
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
    pcmk__xe_foreach_attr(new_xml, mark_attr_created, NULL);

    pcmk__xe_foreach_attr(old_xml, mark_attr_diff, new_xml);
    pcmk__xe_foreach_attr(new_xml, check_new_attr_acls, NULL);
}

/*!
 * \internal
 * \brief Add a deleted object record for an old XML child if ACLs allow
 *
 * This is intended to be called for a child of an old XML element that is not
 * present as a child of a new XML element.
 *
 * Add a temporary copy of the old child to the new XML. Then check whether ACLs
 * would have allowed the deletion of that element. If so, add a deleted object
 * record for it to the new XML's document, and set the \c pcmk__xf_skip flag on
 * the old child.
 *
 * The temporary copy is removed before returning. The new XML and all of its
 * ancestors will have the \c pcmk__xf_dirty flag set because of the creation,
 * however.
 *
 * \param[in,out] old_child   Child of old XML
 * \param[in,out] new_parent  New XML that does not contain \p old_child
 *
 * \note The deletion is checked using the new XML's ACLs. The ACLs may have
 *       also changed between the old and new XML trees. Callers should take
 *       reasonable action if there were ACL changes that themselves would have
 *       been denied.
 */
static void
mark_child_deleted(xmlNode *old_child, xmlNode *new_parent)
{
    int pos = pcmk__xml_position(old_child, pcmk__xf_skip);

    // Re-create the child element so we can check ACLs
    xmlNode *candidate = pcmk__xml_copy(new_parent, old_child);

    // Clear flags on new child and its children
    pcmk__xml_tree_foreach(candidate, pcmk__xml_reset_node_flags, NULL);

    // pcmk__xml_free_position() will check whether ACLs allow the deletion
    pcmk__apply_acls(candidate->doc);

    /* Try to remove the child again (which will track it in document's
     * deleted_objs on success)
     */
    if (pcmk__xml_free_position(candidate, pos) != pcmk_rc_ok) {
        // ACLs denied deletion in pcmk__xml_free_position(), so free here
        pcmk__xml_free_node(candidate);
    }

    pcmk__set_xml_flags((xml_node_private_t *) old_child->_private,
                        pcmk__xf_skip);
}

/*!
 * \internal
 * \brief Mark a new child as moved and set \c pcmk__xf_skip as appropriate
 *
 * \param[in,out] old_child  Child of old XML
 * \param[in,out] new_child  Child of new XML that matches \p old_child
 * \param[in]     old_pos    Position of \p old_child among its siblings
 * \param[in]     new_pos    Position of \p new_child among its siblings
 */
static void
mark_child_moved(xmlNode *old_child, xmlNode *new_child, int old_pos,
                 int new_pos)
{
    const char *id_s = pcmk__s(pcmk__xe_id(new_child), "<no id>");
    xmlNode *new_parent = new_child->parent;
    xml_node_private_t *nodepriv = new_child->_private;

    pcmk__trace("Child element %s with " PCMK_XA_ID "='%s' moved from position "
                "%d to %d under %s",
                new_child->name, id_s, old_pos, new_pos, new_parent->name);
    pcmk__mark_xml_node_dirty(new_parent);
    pcmk__set_xml_flags(nodepriv, pcmk__xf_moved);

    /* @TODO Figure out and document why we skip the old child in future
     * position calculations if the old position is higher, and skip the new
     * child in future position calculations if the new position is higher. This
     * goes back to d028b52, and there's no explanation in the commit message.
     */
    if (old_pos > new_pos) {
        nodepriv = old_child->_private;
    }
    pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);
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
 * \brief Mark a child as created, and free it if ACLs disallow its creation
 *
 * This sets the \c pcmk__xf_skip, \c pcmk__xf_dirty, and \c pcmk__xf_created
 * flags on \p new_child, and it sets dirty flags on all ancestor nodes and the
 * document.
 *
 * \param[in,out] new_child  Newly created child of new XML node
 */
static void
mark_child_created(xmlNode *new_child)
{
    xml_node_private_t *nodepriv = new_child->_private;

    /* Setting all these flags first seems like wasted work (albeit not much) if
     * pcmk__check_creation_acls() ends up freeing new_child. It also sets dirty
     * flags on the ancestors and document even if new_child ends up getting
     * freed. We do these steps first because:
     * - Currently pcmk__check_creation_acls() does nothing for nodes that don't
     *   have the pcmk__xf_created flag set.
     * - Otherwise we have a use-after-free if new_child gets freed.
     *
     * @TODO Create a way to call pcmk__check_creation_acls() first.
     */

    // @TODO Why do we set pcmk__xf_skip here?
    pcmk__set_xml_flags(nodepriv, pcmk__xf_skip);

    // Mark all ancestors and document dirty
    pcmk__mark_xml_node_dirty(new_child);

    // Mark new_child and all descendants dirty and created
    pcmk__xml_tree_foreach(new_child, mark_xml_dirty_created, NULL);

    // Check whether creation was allowed (may free new_child)
    pcmk__check_creation_acls(new_child);
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
 * \retval \c true   if \p new_comment matches \p old_comment
 * \retval \c false  otherwise
 */
static bool
new_comment_matches(const xmlNode *old_comment, const xmlNode *new_comment)
{
    xml_node_private_t *nodepriv = new_comment->_private;

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_skip)) {
        /* @TODO Should we also return false if old_comment has pcmk__xf_skip
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
 * Two elements match if they have the same name and the same ID. (Both IDs can
 * be \c NULL.)
 *
 * For XML attributes other than \c PCMK_XA_ID, we can treat a value change as
 * an in-place modification. However, when Pacemaker applies a patchset, it uses
 * the \c PCMK_XA_ID attribute to find the node to update (modify, delete, or
 * move). If we treat two nodes with different \c PCMK_XA_ID attributes as
 * matching and then mark that attribute as changed, it can cause this lookup to
 * fail.
 *
 * There's unlikely to ever be much practical reason to treat elements with
 * different IDs as a change. Unless that changes, we'll treat them as a
 * mismatch.
 *
 * \param[in] old_element  Old XML child element
 * \param[in] new_element  New XML child element
 *
 * \retval \c true   if \p new_element matches \p old_element
 * \retval \c false  otherwise
 */
static bool
new_element_matches(const xmlNode *old_element, const xmlNode *new_element)
{
    return pcmk__xe_is(new_element, (const char *) old_element->name)
           && pcmk__str_eq(pcmk__xe_id(old_element), pcmk__xe_id(new_element),
                           pcmk__str_none);
}

/*!
 * \internal
 * \brief Check whether a new XML child node matches an old XML child node
 *
 * Node types must be the same in order to match.
 *
 * For comments, a match is a comment at the same position with the same
 * content.
 *
 * For elements, a match is an element with the same name and the same ID. (Both
 * IDs can be \c NULL.)
 *
 * For other node types, there is no match.
 *
 * \param[in] old_child  Child of old XML
 * \param[in] new_child  Child of new XML
 *
 * \retval \c true   if \p new_child matches \p old_child
 * \retval \c false  otherwise
 */
static bool
new_child_matches(const xmlNode *old_child, const xmlNode *new_child)
{
    if (old_child->type != new_child->type) {
        return false;
    }

    switch (old_child->type) {
        case XML_COMMENT_NODE:
            return new_comment_matches(old_child, new_child);
        case XML_ELEMENT_NODE:
            return new_element_matches(old_child, new_child);
        default:
            return false;
    }
}

/*!
 * \internal
 * \brief Set old and new child's \c match pointers to each other if they match
 *
 * A node that is part of a matching pair gets its <tt>_private:match</tt>
 * member set to the matching node.
 *
 * \param[in,out] new_child  New child
 * \param[in,out] user_data  Old child (<tt>xmlNode *</tt>)
 *
 * \return \c true (to continue iterating over new children) if the nodes don't
 *         match, or \c false (to stop iterating) if they do
 */
static bool
set_match_if_matching(xmlNode *new_child, void *user_data)
{
    xmlNode *old_child = user_data;
    xml_node_private_t *old_nodepriv = old_child->_private;
    xml_node_private_t *new_nodepriv = new_child->_private;

    if ((new_nodepriv == NULL) || (new_nodepriv->match != NULL)) {
        // Can't process, or this new child already matched some old child
        return true;
    }

    if (!new_child_matches(old_child, new_child)) {
        return true;
    }

    old_nodepriv->match = new_child;
    new_nodepriv->match = old_child;
    return false;
}

/*!
 * \internal
 * \brief Find a child of a new XML node that matches a child of an old node
 *
 * If a match is found, set the <tt>_private:child</tt> pointers in the matching
 * old and new children to each other.
 *
 * \param[in,out] old_child  Child of old XML node
 * \param[in,out] user_data  New XML node (<tt>xmlNode *</tt>)
 *
 * \return \c true (to continue iterating over old children)
 */
static bool
find_and_set_match(xmlNode *old_child, void *user_data)
{
    xmlNode *new_xml = user_data;
    xml_node_private_t *old_nodepriv = old_child->_private;

    if ((old_nodepriv == NULL) || (old_nodepriv->match != NULL)) {
        // Can't process, or we already found a match for this old child
        return true;
    }

    pcmk__xml_foreach_child(new_xml, set_match_if_matching, old_child);
    return true;
}

/*!
 * \internal
 * \brief Mark a child node as changed or deleted if appropriate
 *
 * If the old child has its \c match pointer set, then it's present in the new
 * XML. It may or may not have changed. We make a recursive call to
 * \c pcmk__xml_mark_changes() to mark any changes that may be present.
 *
 * Otherwise, the old child is absent from the new node, so we mark it as
 * deleted.
 *
 * \param[in,out] old_child  Child of old XML node
 * \param[in,out] user_data  New XML node (<tt>xmlNode *</tt>)
 *
 * \return \c true (to continue iterating over old children)
 */
static bool
mark_child_changed_or_deleted(xmlNode *old_child, void *user_data)
{
    xmlNode *new_xml = user_data;
    xmlNode *new_child = NULL;
    xml_node_private_t *nodepriv = old_child->_private;

    if (nodepriv == NULL) {
        return true;
    }

    if (nodepriv->match == NULL) {
        // No match in new XML means the old child was deleted
        mark_child_deleted(old_child, new_xml);
        return true;
    }

    /* Fetch the match and clear old_child->_private's match member.
     * new_child->_private's match member is handled in
     * mark_child_moved_or_created().
     */
    new_child = nodepriv->match;
    nodepriv->match = NULL;

    pcmk__assert(old_child->type == new_child->type);

    if (old_child->type == XML_COMMENT_NODE) {
        // Comments match only if their positions and contents match
        return true;
    }

    pcmk__xml_mark_changes(old_child, new_child);
    return true;
}

/*!
 * \internal
 * \brief Mark a child node as moved or created if appropriate
 *
 * If the new child has its \c match pointer set, then it's present in the old
 * XML. Any changes within the child were marked in
 * \c mark_child_changed_or_moved(). It may or may not have moved. We check for
 * that and mark the move here if so.
 *
 * Otherwise, the new child is absent from the old node, so we mark it as
 * created.
 *
 * \param[in,out] new_child  Child of new XML node
 * \param[in]     user_data  Ignored
 *
 * \return \c true (to continue iterating over new children)
 *
 * \note This frees \p new_child if it's newly created and ACLs disallow the
 *       creation.
 */
static bool
mark_child_moved_or_created(xmlNode *new_child, void *user_data)
{
    xmlNode *old_child = NULL;
    int old_pos = 0;
    int new_pos = 0;
    xml_node_private_t *nodepriv = new_child->_private;

    if (nodepriv == NULL) {
        return true;
    }

    if (nodepriv->match == NULL) {
        // No match in old XML means the new child is newly created
        mark_child_created(new_child);
        return true;
    }

    /* Fetch the match and clear new_child->_private's match member. Any changes
     * within the child were marked by mark_child_changed_or_deleted(). If the
     * child was moved, mark the move now.
     *
     * We might be able to mark the move in mark_child_changed_or_deleted(),
     * consolidating both actions. We'd have to think about whether the timing
     * of setting the pcmk__xf_skip flag makes any difference.
     */
    old_child = nodepriv->match;
    nodepriv->match = NULL;

    old_pos = pcmk__xml_position(old_child, pcmk__xf_skip);
    new_pos = pcmk__xml_position(new_child, pcmk__xf_skip);

    if (old_pos != new_pos) {
        mark_child_moved(old_child, new_child, old_pos, new_pos);
    }

    return true;
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
 * \note This function is recursive via \c mark_child_changed_or_deleted().
 */
void
pcmk__xml_mark_changes(xmlNode *old_xml, xmlNode *new_xml)
{
    /* This function may set the xml_node_private_t:match member on children of
     * old_xml and new_xml, but it clears that member before returning.
     *
     * @TODO Ensure we handle (for example, by copying) or reject user-created
     * XML that is missing xml_node_private_t at top level or in any children.
     * Similarly, check handling of node types for which we don't create private
     * data. For now, we'll skip them in the loops below.
     */
    CRM_CHECK((old_xml != NULL) && (new_xml != NULL), return);
    if ((old_xml->_private == NULL) || (new_xml->_private == NULL)) {
        return;
    }

    pcmk__xml_doc_set_flags(new_xml->doc, pcmk__xf_tracking);
    xml_diff_attrs(old_xml, new_xml);

    pcmk__xml_foreach_child(old_xml, find_and_set_match, new_xml);
    pcmk__xml_foreach_child(old_xml, mark_child_changed_or_deleted, new_xml);
    pcmk__xml_foreach_child(new_xml, mark_child_moved_or_created, NULL);
}

/*!
 * \internal
 * \brief Check whether an attribute is marked as deleted
 *
 * \param[in] attr       XML attribute
 * \param[in] user_data  Ignored
 *
 * \return \c true if \c pcmk__xf_deleted is set for \p attr, or \c false
 *         otherwise
 *
 * \note This is compatible with \c pcmk__xe_remove_matching_attrs().
 */
static bool
marked_as_deleted(const xmlAttr *attr, void *user_data)
{
    const xml_node_private_t *nodepriv = attr->_private;

    return pcmk__is_set(nodepriv->flags, pcmk__xf_deleted);
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
    pcmk__xe_remove_matching_attrs(xml, true, marked_as_deleted, NULL);
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

    if (pcmk__is_set(docpriv->flags, pcmk__xf_dirty)) {
        pcmk__xml_tree_foreach(xmlDocGetRootElement(doc), commit_attr_deletions,
                               NULL);
    }
    pcmk__xml_reset_doc_private_data(docpriv);
}

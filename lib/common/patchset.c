/*
 * Copyright 2004-2026 the Pacemaker project contributors
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

#include <libxml/tree.h>                // xmlNode

#include <crm/crm.h>
#include <crm/common/xml.h>
#include "crmcommon_private.h"

static const char *const vfields[] = {
    PCMK_XA_ADMIN_EPOCH,
    PCMK_XA_EPOCH,
    PCMK_XA_NUM_UPDATES,
};

/*!
 * \internal
 * \brief Set patchset version fields for source or target XML
 *
 * Create a child of \p version with name \p name and add version numbers from
 * \p from.
 *
 * \param[in,out] version  \c PCMK_XE_VERSION child of patchset
 * \param[in]     from     XML to get version numbers from
 * \param[in]     name     Name for new child of \p version to add fields to
 */
static void
set_version_fields(xmlNode *version, xmlNode *from, const char *name)
{
    xmlNode *child = pcmk__xe_create(version, name);

    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        const char *value = pcmk__xe_get(from, vfields[i]);

        if (value == NULL) {
            value = "1";
        }
        pcmk__xe_set(child, vfields[i], value);
    }
}

/*!
 * \internal
 * \brief Add a \c PCMK_VALUE_DELETE change to a patchset
 *
 * \param[in]     data       Deleted object
 *                           (<tt>const pcmk__deleted_xml_t *</tt>)
 * \param[in,out] user_data  XML patchset (<tt>xmlNode *</tt>)
 *
 * \note This is a \c GFunc compatible with \c g_list_foreach().
 */
static void
add_delete_change(gpointer data, gpointer user_data)
{
    const pcmk__deleted_xml_t *deleted_obj = data;
    xmlNode *patchset = user_data;

    xmlNode *change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

    pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_DELETE);
    pcmk__xe_set(change, PCMK_XA_PATH, deleted_obj->path);

    if (deleted_obj->position >= 0) {
        pcmk__xe_set_int(change, PCMK_XE_POSITION, deleted_obj->position);
    }
}

/*!
 * \internal
 * \brief Add a \c PCMK_VALUE_CREATE change to a patchset
 *
 * Given \p xml with the \c pcmk__xf_created flag set, create a
 * \c PCMK_XE_CHANGE child of \p patchset, with \c PCMK_XA_OPERATION set to
 * \c PCMK_VALUE_CREATE and with a child copy of the created node.
 *
 * \param[in]     xml       Newly created XML to add to \p patchset
 * \param[in,out] patchset  XML patchset
 */
static void
add_create_change(xmlNode *xml, xmlNode *patchset)
{
    xmlNode *change = NULL;
    GString *xpath = pcmk__element_xpath(xml->parent);

    if (xpath == NULL) {
        // @TODO This can happen only if xml->parent == NULL. Is that possible?
        return;
    }

    change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

    pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_CREATE);
    pcmk__xe_set(change, PCMK_XA_PATH, xpath->str);
    pcmk__xe_set_int(change, PCMK_XE_POSITION,
                     pcmk__xml_position(xml, pcmk__xf_deleted));
    pcmk__xml_copy(change, xml);

    g_string_free(xpath, TRUE);
}

/*!
 * \internal
 * \brief Append an attribute to a list if it has been deleted or modified
 *
 * \param[in]     attr       XML attribute
 * \param[in,out] user_data  List of changed attributes (<tt>GSList **</tt>)
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_const_attr().
 */
static bool
append_attr_if_changed(const xmlAttr *attr, void *user_data)
{
    GSList **changed_attrs = user_data;
    const xml_node_private_t *nodepriv = attr->_private;

    if (pcmk__any_flags_set(nodepriv->flags, pcmk__xf_deleted|pcmk__xf_dirty)) {
        *changed_attrs = g_slist_append(*changed_attrs, (gpointer) attr);
    }

    return true;
}

/*!
 * \internal
 * \brief Add a \c PCMK_XE_CHANGE_ATTR to a \c PCMK_XE_CHANGE_LIST
 *
 * Create a new \c PCMK_XE_CHANGE_ATTR child of a \c PCMK_XE_CHANGE_LIST and set
 * its content based on a deleted or modified XML attribute.
 *
 * \param[in]  data       XML attribute
 * \param[out] user_data  \c PCMK_XE_CHANGE_LIST element
 *
 * \note This is a \c GFunc compatible with \c g_slist_foreach().
 */
static void
add_change_attr(gpointer data, gpointer user_data)
{
    const xmlAttr *attr = data;
    xmlNode *change_list = user_data;

    const xml_node_private_t *nodepriv = attr->_private;
    xmlNode *change_attr = pcmk__xe_create(change_list, PCMK_XE_CHANGE_ATTR);

    pcmk__xe_set(change_attr, PCMK_XA_NAME, (const char *) attr->name);

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_deleted)) {
        pcmk__xe_set(change_attr, PCMK_XA_OPERATION, "unset");

    } else {
        // pcmk__xf_dirty is set
        pcmk__xe_set(change_attr, PCMK_XA_OPERATION, "set");
        pcmk__xe_set(change_attr, PCMK_XA_VALUE, pcmk__xml_attr_value(attr));
    }
}

/*!
 * \internal
 * \brief Copy an attribute to a target element if the deleted flag is not set
 *
 * \param[in]     attr       XML attribute
 * \param[in,out] user_data  Target element
 *
 * \return \c true (to continue iterating)
 *
 * \note This is compatible with \c pcmk__xe_foreach_const_attr().
 */
static bool
copy_attr_if_not_deleted(const xmlAttr *attr, void *user_data)
{
    xmlNode *target = user_data;
    const xml_node_private_t *nodepriv = attr->_private;

    if (!pcmk__is_set(nodepriv->flags, pcmk__xf_deleted)) {
        pcmk__xe_set(target, (const char *) attr->name,
                     pcmk__xml_attr_value(attr));
    }

    return true;
}

/*!
 * \internal
 * \brief Add a \c PCMK_VALUE_MODIFY change to a patchset if appropriate
 *
 * If any attributes of \p xml were deleted or modified, create a
 * \c PCMK_XE_CHANGE child of \p patchset, with \c PCMK_XA_OPERATION set to
 * \c PCMK_VALUE_MODIFY and with the following children:
 * - \c PCMK_XE_CHANGE_LIST, with a \c PCMK_XE_CHANGE_ATTR child for each
 *   deleted or modified attribute
 * - \c PCMK_XE_CHANGE_RESULT, with a child of the same type as \p xml whose
 *   attributes are set to the post-change values. Deleted attributes are not
 *   added.
 *
 * \param[in]     xml       XML whose changes to add to \p patchset
 * \param[in,out] patchset  XML patchset
 */
static void
add_modify_change(const xmlNode *xml, xmlNode *patchset)
{
    GSList *changed_attrs = NULL;
    GString *xpath = NULL;
    xmlNode *change = NULL;
    xmlNode *change_list = NULL;
    xmlNode *result = NULL;

    // Check each of the XML node's attributes for changes
    pcmk__xe_foreach_const_attr(xml, append_attr_if_changed, &changed_attrs);

    if (changed_attrs == NULL) {
        return;
    }

    xpath = pcmk__element_xpath(xml);

    change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);
    pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_MODIFY);
    pcmk__xe_set(change, PCMK_XA_PATH, xpath->str);

    change_list = pcmk__xe_create(change, PCMK_XE_CHANGE_LIST);
    g_slist_foreach(changed_attrs, add_change_attr, change_list);

    result = pcmk__xe_create(change, PCMK_XE_CHANGE_RESULT);
    result = pcmk__xe_create(result, (const char *) xml->name);
    pcmk__xe_foreach_const_attr(xml, copy_attr_if_not_deleted, result);

    g_string_free(xpath, TRUE);
    g_slist_free(changed_attrs);
}

/*!
 * \internal
 * \brief Add a \c PCMK_VALUE_MOVE change to a patchset
 *
 * Given \p xml with the \c pcmk__xf_move flag set, create a \c PCMK_XE_CHANGE
 * child of \p patchset, with \c PCMK_XA_OPERATION set to \c PCMK_VALUE_MOVE.
 *
 * \param[in]     xml       XML whose move to add to \p patchset
 * \param[in,out] patchset  XML patchset
 */
static void
add_move_change(const xmlNode *xml, xmlNode *patchset)
{
    xmlNode *change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);
    GString *xpath = pcmk__element_xpath(xml);

    pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_MOVE);
    pcmk__xe_set(change, PCMK_XA_PATH, xpath->str);
    pcmk__xe_set_int(change, PCMK_XE_POSITION,
                     pcmk__xml_position(xml, pcmk__xf_deleted));

    pcmk__trace("%s.%s moved to position %d", xml->name, pcmk__xe_id(xml),
                pcmk__xml_position(xml, pcmk__xf_skip));

    g_string_free(xpath, TRUE);
}

/* Add changes for specified XML to patchset.
 * For patchset format, refer to diff schema.
 */
static void
add_changes_to_patchset(xmlNode *xml, xmlNode *patchset)
{
    xml_node_private_t *nodepriv = xml->_private;

    if (nodepriv == NULL) {
        /* Elements that shouldn't occur in a CIB don't have _private set. They
         * should be stripped out, ignored, or have an error thrown by any code
         * that processes their parent, so we ignore any changes to them.
         */
        return;
    }

    // If this XML node is new, just report that
    if (pcmk__is_set(nodepriv->flags, pcmk__xf_created)) {
        add_create_change(xml, patchset);
        return;
    }

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_dirty)) {
        add_modify_change(xml, patchset);
    }

    // Now recursively do the same for each child node of this node
    for (xmlNode *child = pcmk__xml_first_child(xml); child != NULL;
         child = pcmk__xml_next(child)) {

        add_changes_to_patchset(child, patchset);
    }

    if (pcmk__is_set(nodepriv->flags, pcmk__xf_moved)) {
        add_move_change(xml, patchset);
    }
}

static bool
is_config_change(xmlNode *xml)
{
    GList *gIter = NULL;
    xml_node_private_t *nodepriv = NULL;
    xml_doc_private_t *docpriv;
    xmlNode *config = pcmk__xe_first_child(xml, PCMK_XE_CONFIGURATION, NULL,
                                           NULL);

    if (config) {
        nodepriv = config->_private;
    }
    if ((nodepriv != NULL) && pcmk__is_set(nodepriv->flags, pcmk__xf_dirty)) {
        return TRUE;
    }

    docpriv = xml->doc->_private;
    for (gIter = docpriv->deleted_objs; gIter; gIter = gIter->next) {
        pcmk__deleted_xml_t *deleted_obj = gIter->data;

        if (strstr(deleted_obj->path,
                   "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION) != NULL) {
            return TRUE;
        }
    }

    return FALSE;
}

static xmlNode *
xml_create_patchset_v2(xmlNode *source, xmlNode *target)
{
    xml_doc_private_t *docpriv = NULL;

    xmlNode *patchset = NULL;
    xmlNode *version = NULL;

    if (!pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty)) {
        return NULL;
    }

    pcmk__assert(target->doc != NULL);
    docpriv = target->doc->_private;

    patchset = pcmk__xe_create(NULL, PCMK_XE_DIFF);
    pcmk__xe_set_int(patchset, PCMK_XA_FORMAT, 2);

    version = pcmk__xe_create(patchset, PCMK_XE_VERSION);
    set_version_fields(version, source, PCMK_XE_SOURCE);
    set_version_fields(version, target, PCMK_XE_TARGET);

    /* Call this outside of add_changes_to_patchset(). That function is
     * recursive and all calls will use the same XML document. We don't want to
     * add duplicate delete changes to the patchset.
     */
    g_list_foreach(docpriv->deleted_objs, add_delete_change, patchset);

    add_changes_to_patchset(target, patchset);
    return patchset;
}

xmlNode *
xml_create_patchset(int format, xmlNode *source, xmlNode *target,
                    bool *config_changed, bool manage_version)
{
    bool local_config_changed = false;

    if (format == 0) {
        format = 2;
    }
    if (format != 2) {
        pcmk__err("Unknown patch format: %d", format);
        return NULL;
    }

    xml_acl_disable(target);
    if ((target == NULL)
        || !pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty)) {

        pcmk__trace("No change %d", format);
        return NULL;
    }

    if (config_changed == NULL) {
        config_changed = &local_config_changed;
    }
    *config_changed = is_config_change(target);

    if (manage_version) {
        int counter = 0;

        if (*config_changed) {
            pcmk__xe_set(target, PCMK_XA_NUM_UPDATES, "0");

            pcmk__xe_get_int(target, PCMK_XA_EPOCH, &counter);
            pcmk__xe_set_int(target, PCMK_XA_EPOCH, counter + 1);

        } else {
            pcmk__xe_get_int(target, PCMK_XA_NUM_UPDATES, &counter);
            pcmk__xe_set_int(target, PCMK_XA_NUM_UPDATES, counter + 1);
        }
    }

    return xml_create_patchset_v2(source, target);
}

/*!
 * \internal
 * \brief Add a digest of a patchset's target XML to the patchset
 *
 * \param[in,out] patchset  XML patchset
 * \param[in]     target    Target XML
 */
void
pcmk__xml_patchset_add_digest(xmlNode *patchset, const xmlNode *target)
{
    char *digest = NULL;

    CRM_CHECK((patchset != NULL) && (target != NULL), return);

    /* If tracking is enabled and the document is dirty, we could get an
     * incorrect digest. Call pcmk__xml_commit_changes() before calling this.
     */
    CRM_CHECK(!pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty),
              return);

    digest = pcmk__digest_xml(target, true);

    pcmk__xe_set(patchset, PCMK_XA_DIGEST, digest);
    free(digest);
}

/*!
 * \internal
 * \brief Get the source and target CIB versions from an XML patchset
 *
 * Each output object will contain, in order, the following version fields from
 * the source and target, respectively:
 * * \c PCMK_XA_ADMIN_EPOCH
 * * \c PCMK_XA_EPOCH
 * * \c PCMK_XA_NUM_UPDATES
 *
 * If source versions or target versions are absent from the patchset, then
 * \p source and \p target (respectively) are left unmodified. This is not
 * treated as an error. An unparsable version is an error, however.
 *
 * \param[in]  patchset  XML patchset
 * \param[out] source    Where to store versions from source CIB
 * \param[out] target    Where to store versions from target CIB
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__xml_patchset_versions(const xmlNode *patchset, int source[3],
                            int target[3])
{
    int format = 0;
    const xmlNode *version = NULL;
    const xmlNode *source_xml = NULL;
    const xmlNode *target_xml = NULL;

    CRM_CHECK((patchset != NULL) && (source != NULL) && (target != NULL),
              return EINVAL);

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        pcmk__err("Unknown patch format: %d", format);
        return EINVAL;
    }

    version = pcmk__xe_first_child(patchset, PCMK_XE_VERSION, NULL, NULL);
    source_xml = pcmk__xe_first_child(version, PCMK_XE_SOURCE, NULL, NULL);
    target_xml = pcmk__xe_first_child(version, PCMK_XE_TARGET, NULL, NULL);

    /* @COMPAT Consider requiring source_xml and target_xml to be non-NULL. As
     * of pcs version 0.10.8, pcs creates a patchset using crm_diff
     * --no-version. The behavior and documentation of the crm_diff options
     * --cib and --no-version are questionable and should be re-examined. Even
     * without --no-version, crm_diff does not update the target version in the
     * generated patchset. So a diff based on a manual CIB XML edit is likely to
     * have unchanged version numbers. (Pacemaker tools bump the CIB versions
     * automatically when editing the CIB.)
     *
     * Until then, we may be applying a patchset that has no version info. We
     * will allow either source version or target version to be missing (even
     * though both should be present or both should be missing). However, return
     * an error if any of the three vfields is missing from a source or target
     * version element that is present. That level of sanity check should be
     * okay.
     *
     * We leave the destination arrays unmodified in case of absent versions,
     * instead of setting them to some default value like { 0, 0, 0 }.
     * xml_patch_version_check() sets its own defaults in case of absent
     * versions.
     */
    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        if (source_xml != NULL) {
            if (pcmk__xe_get_int(source_xml, vfields[i],
                                 &(source[i])) != pcmk_rc_ok) {
                return EINVAL;
            }
            pcmk__trace("Got source[%s]=%d", vfields[i], source[i]);

        } else {
            pcmk__trace("No source versions found; keeping source[%s]=%d",
                        vfields[i], source[i]);
        }

        if (target_xml != NULL) {
            if (pcmk__xe_get_int(target_xml, vfields[i],
                                 &(target[i])) != pcmk_rc_ok) {
                return EINVAL;
            }
            pcmk__trace("Got target[%s]=%d", vfields[i], target[i]);

        } else {
            pcmk__trace("No target versions found; keeping target[%s]=%d",
                        vfields[i], target[i]);
        }
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Check whether patchset can be applied to current CIB
 *
 * \param[in] cib_root  Root of current CIB
 * \param[in] patchset  Patchset to check
 *
 * \return Standard Pacemaker return code
 */
static int
check_patchset_versions(const xmlNode *cib_root, const xmlNode *patchset)
{
    int current[] = { 0, 0, 0 };
    int source[] = { 0, 0, 0 };
    int target[] = { 0, 0, 0 };
    int rc = pcmk_rc_ok;

    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        /* @COMPAT We should probably fail with EINVAL for negative or invalid.
         *
         * Preserve behavior for xml_apply_patchset(). Use new behavior in a
         * future replacement.
         */
        if (pcmk__xe_get_int(cib_root, vfields[i],
                             &(current[i])) == pcmk_rc_ok) {
            pcmk__trace("Got %d for current[%s]%s", current[i], vfields[i],
                        ((current[i] < 0)? ", using 0" : ""));
        } else {
            pcmk__debug("Failed to get value for current[%s], using 0",
                        vfields[i]);
        }
        if (current[i] < 0) {
            current[i] = 0;
        }
    }

    /* Set some defaults in case nothing is present.
     *
     * @COMPAT We should probably skip this step, and fail immediately below if
     * target[i] < source[i].
     *
     * Preserve behavior for xml_apply_patchset(). Use new behavior in a future
     * replacement.
     */
    target[0] = current[0];
    target[1] = current[1];
    target[2] = current[2] + 1;
    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        source[i] = current[i];
    }

    rc = pcmk__xml_patchset_versions(patchset, source, target);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    // Ensure current version matches patchset source version
    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        if (current[i] < source[i]) {
            pcmk__debug("Current %s is too low "
                        "(%d.%d.%d < %d.%d.%d --> %d.%d.%d)",
                        vfields[i], current[0], current[1], current[2],
                        source[0], source[1], source[2],
                        target[0], target[1], target[2]);
            return pcmk_rc_diff_resync;
        }
        if (current[i] > source[i]) {
            pcmk__info("Current %s is too high "
                       "(%d.%d.%d > %d.%d.%d --> %d.%d.%d)",
                       vfields[i], current[0], current[1], current[2],
                       source[0], source[1], source[2],
                       target[0], target[1], target[2]);
            pcmk__log_xml_info(patchset, "OldPatch");
            return pcmk_rc_old_data;
        }
    }

    // Ensure target version is newer than source version
    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        if (target[i] > source[i]) {
            pcmk__debug("Can apply patch %d.%d.%d to %d.%d.%d",
                        target[0], target[1], target[2],
                        current[0], current[1], current[2]);
            return pcmk_rc_ok;
        }
    }

    pcmk__notice("Versions did not change in patch %d.%d.%d",
                 target[0], target[1], target[2]);
    return pcmk_rc_old_data;
}

// Return first child matching element name and optionally id or position
static xmlNode *
first_matching_xml_child(const xmlNode *parent, const char *name,
                         const char *id, int position)
{
    xmlNode *cIter = NULL;

    for (cIter = pcmk__xml_first_child(parent); cIter != NULL;
         cIter = pcmk__xml_next(cIter)) {
        if (strcmp((const char *) cIter->name, name) != 0) {
            continue;
        } else if (id) {
            const char *cid = pcmk__xe_id(cIter);

            if ((cid == NULL) || (strcmp(cid, id) != 0)) {
                continue;
            }
        }

        // "position" makes sense only for XML comments for now
        if ((cIter->type == XML_COMMENT_NODE)
            && (position >= 0)
            && (pcmk__xml_position(cIter, pcmk__xf_skip) != position)) {
            continue;
        }

        return cIter;
    }
    return NULL;
}

/*!
 * \internal
 * \brief Simplified, more efficient alternative to pcmk__xpath_find_one()
 *
 * \param[in] top              Root of XML to search
 * \param[in] key              Search xpath
 * \param[in] target_position  If deleting, where to delete
 *
 * \return XML child matching xpath if found, NULL otherwise
 *
 * \note This only works on simplified xpaths found in v2 patchset diffs,
 *       i.e. the only allowed search predicate is [@id='XXX'].
 */
static xmlNode *
search_v2_xpath(const xmlNode *top, const char *key, int target_position)
{
    xmlNode *target = (xmlNode *) top->doc;
    const char *current = key;
    char *section;
    char *remainder;
    char *id;
    char *tag;
    int rc;
    size_t key_len;

    CRM_CHECK(key != NULL, return NULL);
    key_len = strlen(key);

    /* These are scanned from key after a slash, so they can't be bigger
     * than key_len - 1 characters plus a null terminator.
     */

    remainder = pcmk__assert_alloc(key_len, sizeof(char));
    section = pcmk__assert_alloc(key_len, sizeof(char));
    id = pcmk__assert_alloc(key_len, sizeof(char));
    tag = pcmk__assert_alloc(key_len, sizeof(char));

    do {
        // Look for /NEXT_COMPONENT/REMAINING_COMPONENTS
        rc = sscanf(current, "/%[^/]%s", section, remainder);
        if (rc > 0) {
            // Separate FIRST_COMPONENT into TAG[@id='ID']
            int f = sscanf(section, "%[^[][@" PCMK_XA_ID "='%[^']", tag, id);
            int current_position = -1;

            /* The target position is for the final component tag, so only use
             * it if there is nothing left to search after this component.
             */
            if ((rc == 1) && (target_position >= 0)) {
                current_position = target_position;
            }

            switch (f) {
                case 1:
                    target = first_matching_xml_child(target, tag, NULL,
                                                      current_position);
                    break;
                case 2:
                    target = first_matching_xml_child(target, tag, id,
                                                      current_position);
                    break;
                default:
                    // This should not be possible
                    target = NULL;
                    break;
            }
            current = remainder;
        }

    // Continue if something remains to search, and we've matched so far
    } while ((rc == 2) && target);

    if (target) {
        pcmk__if_tracing(
            {
                char *path = (char *) xmlGetNodePath(target);

                pcmk__trace("Found %s for %s", path, key);
                free(path);
            },
            {}
        );
    } else {
        pcmk__debug("No match for %s", key);
    }

    free(remainder);
    free(section);
    free(tag);
    free(id);
    return target;
}

typedef struct xml_change_obj_s {
    const xmlNode *change;
    xmlNode *match;
} xml_change_obj_t;

static gint
sort_change_obj_by_position(gconstpointer a, gconstpointer b)
{
    const xml_change_obj_t *change_obj_a = a;
    const xml_change_obj_t *change_obj_b = b;
    int position_a = -1;
    int position_b = -1;

    pcmk__xe_get_int(change_obj_a->change, PCMK_XE_POSITION, &position_a);
    pcmk__xe_get_int(change_obj_b->change, PCMK_XE_POSITION, &position_b);

    if (position_a < position_b) {
        return -1;

    } else if (position_a > position_b) {
        return 1;
    }

    return 0;
}

/*!
 * \internal
 * \brief Apply a version 2 patchset to an XML node
 *
 * \param[in,out] xml       XML to apply patchset to
 * \param[in]     patchset  Patchset to apply
 *
 * \return Standard Pacemaker return code
 */
static int
apply_v2_patchset(xmlNode *xml, const xmlNode *patchset)
{
    int rc = pcmk_rc_ok;
    const xmlNode *change = NULL;
    GList *change_objs = NULL;
    GList *gIter = NULL;

    for (change = pcmk__xml_first_child(patchset); change != NULL;
         change = pcmk__xml_next(change)) {
        xmlNode *match = NULL;
        const char *op = pcmk__xe_get(change, PCMK_XA_OPERATION);
        const char *xpath = pcmk__xe_get(change, PCMK_XA_PATH);
        int position = -1;

        if (op == NULL) {
            continue;
        }

        pcmk__trace("Processing %s %s", change->name, op);

        /* PCMK_VALUE_DELETE changes for XML comments are generated with
         * PCMK_XE_POSITION
         */
        if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
            pcmk__xe_get_int(change, PCMK_XE_POSITION, &position);
        }
        match = search_v2_xpath(xml, xpath, position);
        pcmk__trace("Performing %s on %s with %p", op, xpath, match);

        if ((match == NULL) && (strcmp(op, PCMK_VALUE_DELETE) == 0)) {
            pcmk__debug("No %s match for %s in %p", op, xpath, xml->doc);
            continue;

        } else if (match == NULL) {
            pcmk__err("No %s match for %s in %p", op, xpath, xml->doc);
            rc = pcmk_rc_diff_failed;
            continue;

        } else if (pcmk__str_any_of(op,
                                    PCMK_VALUE_CREATE, PCMK_VALUE_MOVE, NULL)) {
            // Delay the adding of a PCMK_VALUE_CREATE object
            xml_change_obj_t *change_obj =
                pcmk__assert_alloc(1, sizeof(xml_change_obj_t));

            change_obj->change = change;
            change_obj->match = match;

            change_objs = g_list_append(change_objs, change_obj);

            if (strcmp(op, PCMK_VALUE_MOVE) == 0) {
                // Temporarily put the PCMK_VALUE_MOVE object after the last sibling
                if ((match->parent != NULL) && (match->parent->last != NULL)) {
                    xmlAddNextSibling(match->parent->last, match);
                }
            }

        } else if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
            pcmk__xml_free(match);

        } else if (strcmp(op, PCMK_VALUE_MODIFY) == 0) {
            const xmlNode *child = pcmk__xe_first_child(change,
                                                        PCMK_XE_CHANGE_RESULT,
                                                        NULL, NULL);
            const xmlNode *attrs = pcmk__xml_first_child(child);

            if (attrs == NULL) {
                rc = ENOMSG;
                continue;
            }

            // Remove all attributes
            pcmk__xe_remove_matching_attrs(match, false, NULL, NULL);

            // Copy the ones from attrs
            pcmk__xe_copy_attrs(match, attrs, pcmk__xaf_none);

        } else {
            pcmk__err("Unknown operation: %s", op);
            rc = pcmk_rc_diff_failed;
        }
    }

    // Changes should be generated in the right order. Double checking.
    change_objs = g_list_sort(change_objs, sort_change_obj_by_position);

    for (gIter = change_objs; gIter; gIter = gIter->next) {
        xml_change_obj_t *change_obj = gIter->data;
        xmlNode *match = change_obj->match;
        const char *op = NULL;
        const char *xpath = NULL;

        change = change_obj->change;

        op = pcmk__xe_get(change, PCMK_XA_OPERATION);
        xpath = pcmk__xe_get(change, PCMK_XA_PATH);

        pcmk__trace("Continue performing %s on %s with %p", op, xpath, match);

        if (strcmp(op, PCMK_VALUE_CREATE) == 0) {
            int position = 0;
            xmlNode *child = NULL;
            xmlNode *match_child = NULL;

            match_child = match->children;
            pcmk__xe_get_int(change, PCMK_XE_POSITION, &position);

            while ((match_child != NULL)
                   && (position != pcmk__xml_position(match_child, pcmk__xf_skip))) {
                match_child = match_child->next;
            }

            child = pcmk__xml_copy(match, change->children);

            if (match_child != NULL) {
                pcmk__trace("Adding %s at position %d", child->name, position);
                xmlAddPrevSibling(match_child, child);

            } else {
                pcmk__trace("Adding %s at position %d (end)", child->name,
                            position);
            }

        } else if (strcmp(op, PCMK_VALUE_MOVE) == 0) {
            int position = 0;

            pcmk__xe_get_int(change, PCMK_XE_POSITION, &position);
            if (position != pcmk__xml_position(match, pcmk__xf_skip)) {
                xmlNode *match_child = NULL;
                int p = position;

                if (p > pcmk__xml_position(match, pcmk__xf_skip)) {
                    p++; // Skip ourselves
                }

                pcmk__assert(match->parent != NULL);
                match_child = match->parent->children;

                while ((match_child != NULL)
                       && (p != pcmk__xml_position(match_child, pcmk__xf_skip))) {
                    match_child = match_child->next;
                }

                pcmk__trace("Moving %s to position %d (was %d, prev %p, %s %p)",
                            match->name, position,
                            pcmk__xml_position(match, pcmk__xf_skip),
                            match->prev,
                            ((match_child != NULL)? "next" : "last"),
                            ((match_child != NULL)? match_child
                                                  : match->parent->last));

                if (match_child) {
                    xmlAddPrevSibling(match_child, match);

                } else {
                    pcmk__assert(match->parent->last != NULL);
                    xmlAddNextSibling(match->parent->last, match);
                }

            } else {
                pcmk__trace("%s is already in position %d", match->name,
                            position);
            }

            if (position != pcmk__xml_position(match, pcmk__xf_skip)) {
                pcmk__err("Moved %s.%s to position %d instead of %d (%p)",
                          match->name, pcmk__xe_id(match),
                          pcmk__xml_position(match, pcmk__xf_skip),
                          position, match->prev);
                rc = pcmk_rc_diff_failed;
            }
        }
    }

    g_list_free_full(change_objs, free);
    return rc;
}

int
xml_apply_patchset(xmlNode *xml, const xmlNode *patchset, bool check_version)
{
    int format = 1;
    int rc = pcmk_ok;
    xmlNode *old = NULL;
    const char *digest = NULL;

    if (patchset == NULL) {
        return rc;
    }

    pcmk__log_xml_patchset(LOG_TRACE, patchset);

    if (check_version) {
        rc = pcmk_rc2legacy(check_patchset_versions(xml, patchset));
        if (rc != pcmk_ok) {
            return rc;
        }
    }

    digest = pcmk__xe_get(patchset, PCMK_XA_DIGEST);
    if (digest != NULL) {
        /* Make original XML available for logging in case result doesn't have
         * expected digest
         */
        pcmk__if_tracing(old = pcmk__xml_copy(NULL, xml), {});
    }

    if (rc == pcmk_ok) {
        pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);

        if (format != 2) {
            pcmk__err("Unknown patch format: %d", format);
            rc = -EINVAL;

        } else {
            rc = pcmk_rc2legacy(apply_v2_patchset(xml, patchset));
        }
    }

    if ((rc == pcmk_ok) && (digest != NULL)) {
        char *new_digest = NULL;

        new_digest = pcmk__digest_xml(xml, true);
        if (!pcmk__str_eq(new_digest, digest, pcmk__str_casei)) {
            pcmk__info("v%d digest mis-match: expected %s, calculated %s",
                       format, digest, new_digest);
            rc = -pcmk_err_diff_failed;
            pcmk__if_tracing(
                {
                    pcmk__xml_write_temp_file(old, "PatchDigest:input", NULL);
                    pcmk__xml_write_temp_file(xml, "PatchDigest:result", NULL);
                    pcmk__xml_write_temp_file(patchset, "PatchDigest:diff",
                                              NULL);
                },
                {}
            );

        } else {
            pcmk__trace("v%d digest matched: expected %s, calculated %s",
                        format, digest, new_digest);
        }
        free(new_digest);
    }
    pcmk__xml_free(old);
    return rc;
}

/*!
 * \internal
 * \brief Check whether a given CIB element was modified in a CIB patchset
 *
 * \param[in] patchset  CIB XML patchset
 * \param[in] element   XML tag of CIB element to check (\c NULL is equivalent
 *                      to \c PCMK_XE_CIB). Supported values include any CIB
 *                      element supported by \c pcmk__cib_abs_xpath_for().
 *
 * \retval \c true if \p element was modified
 * \retval \c false otherwise
 */
bool
pcmk__cib_element_in_patchset(const xmlNode *patchset, const char *element)
{
    const char *element_xpath = pcmk__cib_abs_xpath_for(element);
    const char *parent_xpath = pcmk_cib_parent_name_for(element);
    char *element_regex = NULL;
    bool rc = false;
    int format = 1;

    pcmk__assert(patchset != NULL);

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        pcmk__warn("Unknown patch format: %d", format);
        return false;
    }

    CRM_CHECK(element_xpath != NULL, return false); // Unsupported element

    /* Matches if and only if element_xpath is part of a changed path
     * (supported values for element never contain XML IDs with schema
     * validation enabled)
     *
     * @TODO Use POSIX word boundary instead of (/|$), if it works:
     * https://www.regular-expressions.info/wordboundaries.html.
     */
    element_regex = pcmk__assert_asprintf("^%s(/|$)", element_xpath);

    for (const xmlNode *change = pcmk__xe_first_child(patchset, PCMK_XE_CHANGE,
                                                      NULL, NULL);
         change != NULL; change = pcmk__xe_next(change, PCMK_XE_CHANGE)) {

        const char *op = pcmk__xe_get(change, PCMK_XA_OPERATION);
        const char *diff_xpath = pcmk__xe_get(change, PCMK_XA_PATH);

        if (pcmk__str_eq(diff_xpath, element_regex, pcmk__str_regex)) {
            // Change to an existing element
            rc = true;
            break;
        }

        if (pcmk__str_eq(op, PCMK_VALUE_CREATE, pcmk__str_none)
            && pcmk__str_eq(diff_xpath, parent_xpath, pcmk__str_none)
            && pcmk__xe_is(pcmk__xe_first_child(change, NULL, NULL, NULL),
                                                element)) {
            // Newly added element
            rc = true;
            break;
        }
    }

    free(element_regex);
    return rc;
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/common/xml_compat.h>

// Return value of true means failure; false means success
bool
xml_patch_versions(const xmlNode *patchset, int add[3], int del[3])
{
    const xmlNode *version = pcmk__xe_first_child(patchset, PCMK_XE_VERSION,
                                                  NULL, NULL);
    const xmlNode *source = pcmk__xe_first_child(version, PCMK_XE_SOURCE, NULL,
                                                 NULL);
    const xmlNode *target = pcmk__xe_first_child(version, PCMK_XE_TARGET, NULL,
                                                 NULL);
    int format = 1;

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        pcmk__err("Unknown patch format: %d", format);
        return true;
    }

    if (source != NULL) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            pcmk__xe_get_int(source, vfields[i], &(del[i]));
            pcmk__trace("Got %d for del[%s]", del[i], vfields[i]);
        }
    }

    if (target != NULL) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            pcmk__xe_get_int(target, vfields[i], &(add[i]));
            pcmk__trace("Got %d for add[%s]", add[i], vfields[i]);
        }
    }
    return false;
}

void
patchset_process_digest(xmlNode *patch, const xmlNode *source,
                        const xmlNode *target, bool with_digest)
{
    char *digest = NULL;

    if ((patch == NULL) || (source == NULL) || (target == NULL)
        || !with_digest) {
        return;
    }

    CRM_LOG_ASSERT(!pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty));

    digest = pcmk__digest_xml(target, true);

    pcmk__xe_set(patch, PCMK_XA_DIGEST, digest);
    free(digest);
}

// LCOV_EXCL_STOP
// End deprecated API

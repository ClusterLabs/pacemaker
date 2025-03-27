/*
 * Copyright 2004-2025 the Pacemaker project contributors
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

#include <libxml/tree.h>                // xmlNode

#include <crm/crm.h>
#include <crm/common/cib_internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>  // CRM_XML_LOG_BASE, etc.
#include "crmcommon_private.h"

static const char *const vfields[] = {
    PCMK_XA_ADMIN_EPOCH,
    PCMK_XA_EPOCH,
    PCMK_XA_NUM_UPDATES,
};

/* Add changes for specified XML to patchset.
 * For patchset format, refer to diff schema.
 */
static void
add_xml_changes_to_patchset(xmlNode *xml, xmlNode *patchset)
{
    xmlNode *cIter = NULL;
    xmlAttr *pIter = NULL;
    xmlNode *change = NULL;
    xml_node_private_t *nodepriv = xml->_private;
    const char *value = NULL;

    if (nodepriv == NULL) {
        /* Elements that shouldn't occur in a CIB don't have _private set. They
         * should be stripped out, ignored, or have an error thrown by any code
         * that processes their parent, so we ignore any changes to them.
         */
        return;
    }

    // If this XML node is new, just report that
    if (patchset && pcmk_is_set(nodepriv->flags, pcmk__xf_created)) {
        GString *xpath = pcmk__element_xpath(xml->parent);

        if (xpath != NULL) {
            int position = pcmk__xml_position(xml, pcmk__xf_deleted);

            change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

            pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_CREATE);
            pcmk__xe_set(change, PCMK_XA_PATH, (const char *) xpath->str);
            pcmk__xe_set_int(change, PCMK_XE_POSITION, position);
            pcmk__xml_copy(change, xml);
            g_string_free(xpath, TRUE);
        }

        return;
    }

    // Check each of the XML node's attributes for changes
    for (pIter = pcmk__xe_first_attr(xml); pIter != NULL;
         pIter = pIter->next) {
        xmlNode *attr = NULL;

        nodepriv = pIter->_private;
        if (!pcmk_any_flags_set(nodepriv->flags, pcmk__xf_deleted|pcmk__xf_dirty)) {
            continue;
        }

        if (change == NULL) {
            GString *xpath = pcmk__element_xpath(xml);

            if (xpath != NULL) {
                change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

                pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_MODIFY);
                pcmk__xe_set(change, PCMK_XA_PATH, (const char *) xpath->str);

                change = pcmk__xe_create(change, PCMK_XE_CHANGE_LIST);
                g_string_free(xpath, TRUE);
            }
        }

        attr = pcmk__xe_create(change, PCMK_XE_CHANGE_ATTR);

        pcmk__xe_set(attr, PCMK_XA_NAME, (const char *) pIter->name);
        if (nodepriv->flags & pcmk__xf_deleted) {
            pcmk__xe_set(attr, PCMK_XA_OPERATION, "unset");

        } else {
            pcmk__xe_set(attr, PCMK_XA_OPERATION, "set");

            value = pcmk__xml_attr_value(pIter);
            pcmk__xe_set(attr, PCMK_XA_VALUE, value);
        }
    }

    if (change) {
        xmlNode *result = NULL;

        change = pcmk__xe_create(change->parent, PCMK_XE_CHANGE_RESULT);
        result = pcmk__xe_create(change, (const char *)xml->name);

        for (pIter = pcmk__xe_first_attr(xml); pIter != NULL;
             pIter = pIter->next) {
            nodepriv = pIter->_private;
            if (!pcmk_is_set(nodepriv->flags, pcmk__xf_deleted)) {
                value = pcmk__xe_get(xml, (const char *) pIter->name);
                pcmk__xe_set(result, (const char *)pIter->name, value);
            }
        }
    }

    // Now recursively do the same for each child node of this node
    for (cIter = pcmk__xml_first_child(xml); cIter != NULL;
         cIter = pcmk__xml_next(cIter)) {
        add_xml_changes_to_patchset(cIter, patchset);
    }

    nodepriv = xml->_private;
    if (patchset && pcmk_is_set(nodepriv->flags, pcmk__xf_moved)) {
        GString *xpath = pcmk__element_xpath(xml);

        crm_trace("%s.%s moved to position %d",
                  xml->name, pcmk__xe_id(xml),
                  pcmk__xml_position(xml, pcmk__xf_skip));

        if (xpath != NULL) {
            change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

            pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_MOVE);
            pcmk__xe_set(change, PCMK_XA_PATH, (const char *) xpath->str);
            pcmk__xe_set_int(change, PCMK_XE_POSITION,
                             pcmk__xml_position(xml, pcmk__xf_deleted));
            g_string_free(xpath, TRUE);
        }
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
    if ((nodepriv != NULL) && pcmk_is_set(nodepriv->flags, pcmk__xf_dirty)) {
        return TRUE;
    }

    if ((xml->doc != NULL) && (xml->doc->_private != NULL)) {
        docpriv = xml->doc->_private;
        for (gIter = docpriv->deleted_objs; gIter; gIter = gIter->next) {
            pcmk__deleted_xml_t *deleted_obj = gIter->data;

            if (strstr(deleted_obj->path,
                       "/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION) != NULL) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

static xmlNode *
xml_create_patchset_v2(xmlNode *source, xmlNode *target)
{
    int lpc = 0;
    GList *gIter = NULL;
    xml_doc_private_t *docpriv;

    xmlNode *v = NULL;
    xmlNode *version = NULL;
    xmlNode *patchset = NULL;

    pcmk__assert(target != NULL);

    if (!pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty)) {
        return NULL;
    }

    pcmk__assert(target->doc != NULL);
    docpriv = target->doc->_private;

    patchset = pcmk__xe_create(NULL, PCMK_XE_DIFF);
    pcmk__xe_set_int(patchset, PCMK_XA_FORMAT, 2);

    version = pcmk__xe_create(patchset, PCMK_XE_VERSION);

    v = pcmk__xe_create(version, PCMK_XE_SOURCE);
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = pcmk__xe_get(source, vfields[lpc]);

        if (value == NULL) {
            value = "1";
        }
        pcmk__xe_set(v, vfields[lpc], value);
    }

    v = pcmk__xe_create(version, PCMK_XE_TARGET);
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = pcmk__xe_get(target, vfields[lpc]);

        if (value == NULL) {
            value = "1";
        }
        pcmk__xe_set(v, vfields[lpc], value);
    }

    for (gIter = docpriv->deleted_objs; gIter; gIter = gIter->next) {
        pcmk__deleted_xml_t *deleted_obj = gIter->data;
        xmlNode *change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

        pcmk__xe_set(change, PCMK_XA_OPERATION, PCMK_VALUE_DELETE);
        pcmk__xe_set(change, PCMK_XA_PATH, deleted_obj->path);
        if (deleted_obj->position >= 0) {
            pcmk__xe_set_int(change, PCMK_XE_POSITION, deleted_obj->position);
        }
    }

    add_xml_changes_to_patchset(target, patchset);
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
        crm_err("Unknown patch format: %d", format);
        return NULL;
    }

    xml_acl_disable(target);
    if ((target == NULL)
        || !pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty)) {

        crm_trace("No change %d", format);
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

    pcmk__xe_set(patchset, PCMK__XA_DIGEST, digest);
    free(digest);
}

/*!
 * \internal
 * \brief Get the source and target CIB versions from an XML patchset
 *
 * Each output object will contain, in order, the following version fields from
 * the source and target:
 * * \c PCMK_XA_ADMIN_EPOCH
 * * \c PCMK_XA_EPOCH
 * * \c PCMK_XA_NUM_UPDATES
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
    int format = 1;
    const xmlNode *version = NULL;
    const xmlNode *source_xml = NULL;
    const xmlNode *target_xml = NULL;

    CRM_CHECK((patchset != NULL) && (source != NULL) && (target != NULL),
              return EINVAL);

    pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        crm_err("Unknown patch format: %d", format);
        return EINVAL;
    }

    version = pcmk__xe_first_child(patchset, PCMK_XE_VERSION, NULL, NULL);
    source_xml = pcmk__xe_first_child(version, PCMK_XE_SOURCE, NULL, NULL);
    target_xml = pcmk__xe_first_child(version, PCMK_XE_TARGET, NULL, NULL);

    if ((source_xml == NULL) || (target_xml == NULL)) {
        return EINVAL;
    }

    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        if (pcmk__xe_get_int(source_xml, vfields[i],
                             &(source[i])) != pcmk_rc_ok) {
            return EINVAL;
        }
        crm_trace("Got %d for source[%s]", source[i], vfields[i]);

        if (pcmk__xe_get_int(target_xml, vfields[i], &(target[i]))
                             != pcmk_rc_ok) {
            return EINVAL;
        }
        crm_trace("Got %d for target[%s]", target[i], vfields[i]);
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
        /* @COMPAT We should probably fail with EINVAL for negative or invalid
         * valid reason for such values to be present.
         *
         * Preserve behavior for xml_apply_patchset(). Use new behavior in
         * libpacemaker replacement.
         */
        if (pcmk__xe_get_int(cib_root, vfields[i],
                             &(current[i])) == pcmk_rc_ok) {
            crm_trace("Got %d for current[%s]%s",
                      current[i], vfields[i],
                      ((current[i] < 0)? ", using 0" : ""));
        } else {
            crm_debug("Failed to get value for current[%s], using 0",
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
     * Preserve behavior for xml_apply_patchset(). Use new behavior in
     * libpacemaker replacement.
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
            crm_debug("Current %s is too low "
                      "(%d.%d.%d < %d.%d.%d --> %d.%d.%d)",
                      vfields[i], current[0], current[1], current[2],
                      source[0], source[1], source[2],
                      target[0], target[1], target[2]);
            return pcmk_rc_diff_resync;
        }
        if (current[i] > source[i]) {
            crm_info("Current %s is too high "
                     "(%d.%d.%d > %d.%d.%d --> %d.%d.%d)",
                     vfields[i], current[0], current[1], current[2],
                     source[0], source[1], source[2],
                     target[0], target[1], target[2]);
            crm_log_xml_info(patchset, "OldPatch");
            return pcmk_rc_old_data;
        }
    }

    // Ensure target version is newer than source version
    for (int i = 0; i < PCMK__NELEM(vfields); i++) {
        if (target[i] > source[i]) {
            crm_debug("Can apply patch %d.%d.%d to %d.%d.%d",
                      target[0], target[1], target[2],
                      current[0], current[1], current[2]);
            return pcmk_rc_ok;
        }
    }

    crm_notice("Versions did not change in patch %d.%d.%d",
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
    char *path = NULL;
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
        crm_trace("Found %s for %s",
                  (path = (char *) xmlGetNodePath(target)), key);
        free(path);
    } else {
        crm_debug("No match for %s", key);
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

        crm_trace("Processing %s %s", change->name, op);

        /* PCMK_VALUE_DELETE changes for XML comments are generated with
         * PCMK_XE_POSITION
         */
        if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
            pcmk__xe_get_int(change, PCMK_XE_POSITION, &position);
        }
        match = search_v2_xpath(xml, xpath, position);
        crm_trace("Performing %s on %s with %p", op, xpath, match);

        if ((match == NULL) && (strcmp(op, PCMK_VALUE_DELETE) == 0)) {
            crm_debug("No %s match for %s in %p", op, xpath, xml->doc);
            continue;

        } else if (match == NULL) {
            crm_err("No %s match for %s in %p", op, xpath, xml->doc);
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

            for (xmlAttrPtr pIter = pcmk__xe_first_attr(attrs); pIter != NULL;
                 pIter = pIter->next) {
                const char *name = (const char *) pIter->name;
                const char *value = pcmk__xml_attr_value(pIter);

                pcmk__xe_set(match, name, value);
            }

        } else {
            crm_err("Unknown operation: %s", op);
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

        crm_trace("Continue performing %s on %s with %p", op, xpath, match);

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
                crm_trace("Adding %s at position %d", child->name, position);
                xmlAddPrevSibling(match_child, child);

            } else {
                crm_trace("Adding %s at position %d (end)",
                          child->name, position);
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

                crm_trace("Moving %s to position %d (was %d, prev %p, %s %p)",
                          match->name, position,
                          pcmk__xml_position(match, pcmk__xf_skip),
                          match->prev, (match_child? "next":"last"),
                          (match_child? match_child : match->parent->last));

                if (match_child) {
                    xmlAddPrevSibling(match_child, match);

                } else {
                    pcmk__assert(match->parent->last != NULL);
                    xmlAddNextSibling(match->parent->last, match);
                }

            } else {
                crm_trace("%s is already in position %d",
                          match->name, position);
            }

            if (position != pcmk__xml_position(match, pcmk__xf_skip)) {
                crm_err("Moved %s.%s to position %d instead of %d (%p)",
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

    digest = pcmk__xe_get(patchset, PCMK__XA_DIGEST);
    if (digest != NULL) {
        /* Make original XML available for logging in case result doesn't have
         * expected digest
         */
        pcmk__if_tracing(old = pcmk__xml_copy(NULL, xml), {});
    }

    if (rc == pcmk_ok) {
        pcmk__xe_get_int(patchset, PCMK_XA_FORMAT, &format);

        if (format != 2) {
            crm_err("Unknown patch format: %d", format);
            rc = -EINVAL;

        } else {
            rc = pcmk_rc2legacy(apply_v2_patchset(xml, patchset));
        }
    }

    if ((rc == pcmk_ok) && (digest != NULL)) {
        char *new_digest = NULL;

        new_digest = pcmk__digest_xml(xml, true);
        if (!pcmk__str_eq(new_digest, digest, pcmk__str_casei)) {
            crm_info("v%d digest mis-match: expected %s, calculated %s",
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
            crm_trace("v%d digest matched: expected %s, calculated %s",
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
        crm_warn("Unknown patch format: %d", format);
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
    element_regex = crm_strdup_printf("^%s(/|$)", element_xpath);

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
        crm_err("Unknown patch format: %d", format);
        return true;
    }

    if (source != NULL) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            pcmk__xe_get_int(source, vfields[i], &(del[i]));
            crm_trace("Got %d for del[%s]", del[i], vfields[i]);
        }
    }

    if (target != NULL) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            pcmk__xe_get_int(target, vfields[i], &(add[i]));
            crm_trace("Got %d for add[%s]", add[i], vfields[i]);
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

    /* We should always call pcmk__xml_commit_changes() before calculating a
     * digest. Otherwise, with an on-tracking dirty target, we could get a wrong
     * digest.
     */
    CRM_LOG_ASSERT(!pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty));

    digest = pcmk__digest_xml(target, true);

    pcmk__xe_set(patch, PCMK__XA_DIGEST, digest);
    free(digest);

    return;
}

// LCOV_EXCL_STOP
// End deprecated API

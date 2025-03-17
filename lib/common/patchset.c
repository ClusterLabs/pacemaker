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

            crm_xml_add(change, PCMK_XA_OPERATION, PCMK_VALUE_CREATE);
            crm_xml_add(change, PCMK_XA_PATH, (const char *) xpath->str);
            crm_xml_add_int(change, PCMK_XE_POSITION, position);
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

                crm_xml_add(change, PCMK_XA_OPERATION, PCMK_VALUE_MODIFY);
                crm_xml_add(change, PCMK_XA_PATH, (const char *) xpath->str);

                change = pcmk__xe_create(change, PCMK_XE_CHANGE_LIST);
                g_string_free(xpath, TRUE);
            }
        }

        attr = pcmk__xe_create(change, PCMK_XE_CHANGE_ATTR);

        crm_xml_add(attr, PCMK_XA_NAME, (const char *) pIter->name);
        if (nodepriv->flags & pcmk__xf_deleted) {
            crm_xml_add(attr, PCMK_XA_OPERATION, "unset");

        } else {
            crm_xml_add(attr, PCMK_XA_OPERATION, "set");

            value = pcmk__xml_attr_value(pIter);
            crm_xml_add(attr, PCMK_XA_VALUE, value);
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
                value = crm_element_value(xml, (const char *) pIter->name);
                crm_xml_add(result, (const char *)pIter->name, value);
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

            crm_xml_add(change, PCMK_XA_OPERATION, PCMK_VALUE_MOVE);
            crm_xml_add(change, PCMK_XA_PATH, (const char *) xpath->str);
            crm_xml_add_int(change, PCMK_XE_POSITION,
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
    const char *vfields[] = {
        PCMK_XA_ADMIN_EPOCH,
        PCMK_XA_EPOCH,
        PCMK_XA_NUM_UPDATES,
    };

    pcmk__assert(target != NULL);

    if (!pcmk__xml_doc_all_flags_set(target->doc, pcmk__xf_dirty)) {
        return NULL;
    }

    pcmk__assert(target->doc != NULL);
    docpriv = target->doc->_private;

    patchset = pcmk__xe_create(NULL, PCMK_XE_DIFF);
    crm_xml_add_int(patchset, PCMK_XA_FORMAT, 2);

    version = pcmk__xe_create(patchset, PCMK_XE_VERSION);

    v = pcmk__xe_create(version, PCMK_XE_SOURCE);
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = crm_element_value(source, vfields[lpc]);

        if (value == NULL) {
            value = "1";
        }
        crm_xml_add(v, vfields[lpc], value);
    }

    v = pcmk__xe_create(version, PCMK_XE_TARGET);
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        const char *value = crm_element_value(target, vfields[lpc]);

        if (value == NULL) {
            value = "1";
        }
        crm_xml_add(v, vfields[lpc], value);
    }

    for (gIter = docpriv->deleted_objs; gIter; gIter = gIter->next) {
        pcmk__deleted_xml_t *deleted_obj = gIter->data;
        xmlNode *change = pcmk__xe_create(patchset, PCMK_XE_CHANGE);

        crm_xml_add(change, PCMK_XA_OPERATION, PCMK_VALUE_DELETE);
        crm_xml_add(change, PCMK_XA_PATH, deleted_obj->path);
        if (deleted_obj->position >= 0) {
            crm_xml_add_int(change, PCMK_XE_POSITION, deleted_obj->position);
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
            crm_xml_add(target, PCMK_XA_NUM_UPDATES, "0");

            crm_element_value_int(target, PCMK_XA_EPOCH, &counter);
            crm_xml_add_int(target, PCMK_XA_EPOCH, counter + 1);

        } else {
            crm_element_value_int(target, PCMK_XA_NUM_UPDATES, &counter);
            crm_xml_add_int(target, PCMK_XA_NUM_UPDATES, counter + 1);
        }
    }

    return xml_create_patchset_v2(source, target);
}

void
patchset_process_digest(xmlNode *patch, xmlNode *source, xmlNode *target,
                        bool with_digest)
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

    crm_xml_add(patch, PCMK__XA_DIGEST, digest);
    free(digest);

    return;
}

// Get CIB versions used for additions and deletions in a patchset
// Return value of true means failure; false means success
bool
xml_patch_versions(const xmlNode *patchset, int add[3], int del[3])
{
    static const char *const vfields[] = {
        PCMK_XA_ADMIN_EPOCH,
        PCMK_XA_EPOCH,
        PCMK_XA_NUM_UPDATES,
    };

    const xmlNode *version = pcmk__xe_first_child(patchset, PCMK_XE_VERSION,
                                                  NULL, NULL);
    const xmlNode *source = pcmk__xe_first_child(version, PCMK_XE_SOURCE, NULL,
                                                 NULL);
    const xmlNode *target = pcmk__xe_first_child(version, PCMK_XE_TARGET, NULL,
                                                 NULL);
    int format = 1;

    crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);
    if (format != 2) {
        crm_err("Unknown patch format: %d", format);
        return true;
    }

    if (source != NULL) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            crm_element_value_int(source, vfields[i], &(del[i]));
            crm_trace("Got %d for del[%s]", del[i], vfields[i]);
        }
    }

    if (target != NULL) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            crm_element_value_int(target, vfields[i], &(add[i]));
            crm_trace("Got %d for add[%s]", add[i], vfields[i]);
        }
    }
    return false;
}

/*!
 * \internal
 * \brief Check whether patchset can be applied to current CIB
 *
 * \param[in] xml       Root of current CIB
 * \param[in] patchset  Patchset to check
 *
 * \return Standard Pacemaker return code
 */
static int
xml_patch_version_check(const xmlNode *xml, const xmlNode *patchset)
{
    int lpc = 0;
    bool changed = FALSE;

    int this[] = { 0, 0, 0 };
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    const char *vfields[] = {
        PCMK_XA_ADMIN_EPOCH,
        PCMK_XA_EPOCH,
        PCMK_XA_NUM_UPDATES,
    };

    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        crm_element_value_int(xml, vfields[lpc], &(this[lpc]));
        crm_trace("Got %d for this[%s]", this[lpc], vfields[lpc]);
        if (this[lpc] < 0) {
            this[lpc] = 0;
        }
    }

    /* Set some defaults in case nothing is present */
    add[0] = this[0];
    add[1] = this[1];
    add[2] = this[2] + 1;
    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        del[lpc] = this[lpc];
    }

    xml_patch_versions(patchset, add, del);

    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        if (this[lpc] < del[lpc]) {
            crm_debug("Current %s is too low (%d.%d.%d < %d.%d.%d --> %d.%d.%d)",
                      vfields[lpc], this[0], this[1], this[2],
                      del[0], del[1], del[2], add[0], add[1], add[2]);
            return pcmk_rc_diff_resync;

        } else if (this[lpc] > del[lpc]) {
            crm_info("Current %s is too high (%d.%d.%d > %d.%d.%d --> %d.%d.%d) %p",
                     vfields[lpc], this[0], this[1], this[2],
                     del[0], del[1], del[2], add[0], add[1], add[2], patchset);
            crm_log_xml_info(patchset, "OldPatch");
            return pcmk_rc_old_data;
        }
    }

    for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
        if (add[lpc] > del[lpc]) {
            changed = TRUE;
        }
    }

    if (!changed) {
        crm_notice("Versions did not change in patch %d.%d.%d",
                   add[0], add[1], add[2]);
        return pcmk_rc_old_data;
    }

    crm_debug("Can apply patch %d.%d.%d to %d.%d.%d",
              add[0], add[1], add[2], this[0], this[1], this[2]);
    return pcmk_rc_ok;
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

    crm_element_value_int(change_obj_a->change, PCMK_XE_POSITION, &position_a);
    crm_element_value_int(change_obj_b->change, PCMK_XE_POSITION, &position_b);

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
        const char *op = crm_element_value(change, PCMK_XA_OPERATION);
        const char *xpath = crm_element_value(change, PCMK_XA_PATH);
        int position = -1;

        if (op == NULL) {
            continue;
        }

        crm_trace("Processing %s %s", change->name, op);

        /* PCMK_VALUE_DELETE changes for XML comments are generated with
         * PCMK_XE_POSITION
         */
        if (strcmp(op, PCMK_VALUE_DELETE) == 0) {
            crm_element_value_int(change, PCMK_XE_POSITION, &position);
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

                crm_xml_add(match, name, value);
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

        op = crm_element_value(change, PCMK_XA_OPERATION);
        xpath = crm_element_value(change, PCMK_XA_PATH);

        crm_trace("Continue performing %s on %s with %p", op, xpath, match);

        if (strcmp(op, PCMK_VALUE_CREATE) == 0) {
            int position = 0;
            xmlNode *child = NULL;
            xmlNode *match_child = NULL;

            match_child = match->children;
            crm_element_value_int(change, PCMK_XE_POSITION, &position);

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

            crm_element_value_int(change, PCMK_XE_POSITION, &position);
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
xml_apply_patchset(xmlNode *xml, xmlNode *patchset, bool check_version)
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
        rc = pcmk_rc2legacy(xml_patch_version_check(xml, patchset));
        if (rc != pcmk_ok) {
            return rc;
        }
    }

    digest = crm_element_value(patchset, PCMK__XA_DIGEST);
    if (digest != NULL) {
        /* Make original XML available for logging in case result doesn't have
         * expected digest
         */
        pcmk__if_tracing(old = pcmk__xml_copy(NULL, xml), {});
    }

    if (rc == pcmk_ok) {
        crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);

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
                    save_xml_to_file(old, "PatchDigest:input", NULL);
                    save_xml_to_file(xml, "PatchDigest:result", NULL);
                    save_xml_to_file(patchset, "PatchDigest:diff", NULL);
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

bool
pcmk__cib_element_in_patchset(const xmlNode *patchset, const char *element)
{
    const char *element_xpath = pcmk__cib_abs_xpath_for(element);
    const char *parent_xpath = pcmk_cib_parent_name_for(element);
    char *element_regex = NULL;
    bool rc = false;
    int format = 1;

    pcmk__assert(patchset != NULL);

    crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);
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

        const char *op = crm_element_value(change, PCMK_XA_OPERATION);
        const char *diff_xpath = crm_element_value(change, PCMK_XA_PATH);

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

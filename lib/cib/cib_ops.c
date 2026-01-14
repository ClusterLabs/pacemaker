/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // EEXIST, EINVAL, ENXIO
#include <stdbool.h>
#include <stddef.h>                 // NULL
#include <stdint.h>                 // uint32_t
#include <stdlib.h>                 // free

#include <glib.h>                   // g_*, GHashTable, gpointer
#include <libxml/tree.h>            // xmlGetNodePath, xmlNode, XML_ELEMENT_NODE
#include <libxml/xmlstring.h>       // xmlChar
#include <libxml/xpath.h>           // xmlXPathObject, xmlXPathFreeObject

#include <crm/cib.h>                // cib_*, createEmptyCib
#include <crm/cib/internal.h>       // cib__*, PCMK__CIB_*
#include <crm/common/cib.h>         // pcmk_cib_*, pcmk_find_cib_element
#include <crm/common/internal.h>    // pcmk__err, pcmk__xml_*, etc.
#include <crm/common/logging.h>     // CRM_CHECK
#include <crm/common/results.h>     // pcmk_rc_*, pcmk_legacy2rc
#include <crm/common/xml.h>         // xml_apply_patchset, PCMK_XA_, PCMK_XE_*
#include <crm/crm.h>                // CRM_OP_PING

// @TODO: Free this via crm_exit() when libcib gets merged with libcrmcommon
static GHashTable *operation_table = NULL;

static const cib__operation_t cib_ops[] = {
    {
        PCMK__CIB_REQUEST_APPLY_PATCH, cib__op_apply_patch, true
    },
    {
        PCMK__CIB_REQUEST_BUMP, cib__op_bump, true
    },
    {
        PCMK__CIB_REQUEST_COMMIT_TRANSACT, cib__op_commit_transact, true
    },
    {
        PCMK__CIB_REQUEST_CREATE, cib__op_create, true
    },
    {
        PCMK__CIB_REQUEST_DELETE, cib__op_delete, true
    },
    {
        PCMK__CIB_REQUEST_ERASE, cib__op_erase, true
    },
    {
        PCMK__CIB_REQUEST_MODIFY, cib__op_modify, true
    },
    {
        PCMK__CIB_REQUEST_NOOP, cib__op_noop, false
    },
    {
        CRM_OP_PING, cib__op_ping, false
    },
    {
        PCMK__CIB_REQUEST_PRIMARY, cib__op_primary, false
    },
    {
        PCMK__CIB_REQUEST_QUERY, cib__op_query, false
    },
    {
        PCMK__CIB_REQUEST_REPLACE, cib__op_replace, true
    },
    {
        PCMK__CIB_REQUEST_SCHEMAS, cib__op_schemas, false
    },
    {
        PCMK__CIB_REQUEST_SECONDARY, cib__op_secondary, false
    },
    {
        PCMK__CIB_REQUEST_SHUTDOWN, cib__op_shutdown, false
    },
    {
        PCMK__CIB_REQUEST_SYNC, cib__op_sync, false
    },
    {
        PCMK__CIB_REQUEST_UPGRADE, cib__op_upgrade, true
    },
};

/*!
 * \internal
 * \brief Get the \c cib__operation_t object for a given CIB operation name
 *
 * \param[in]  op         CIB operation name
 * \param[out] operation  Where to store CIB operation object
 *
 * \return Standard Pacemaker return code
 */
int
cib__get_operation(const char *op, const cib__operation_t **operation)
{
    pcmk__assert((op != NULL) && (operation != NULL));

    if (operation_table == NULL) {
        operation_table = pcmk__strkey_table(NULL, NULL);

        for (int lpc = 0; lpc < PCMK__NELEM(cib_ops); lpc++) {
            const cib__operation_t *oper = &(cib_ops[lpc]);

            g_hash_table_insert(operation_table, (gpointer) oper->name,
                                (gpointer) oper);
        }
    }

    *operation = g_hash_table_lookup(operation_table, op);
    if (*operation == NULL) {
        pcmk__err("Operation %s is invalid", op);
        return EINVAL;
    }
    return pcmk_rc_ok;
}

int
cib__process_apply_patch(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    const xmlNode *input = cib__get_calldata(req);
    int rc = xml_apply_patchset(*cib, input, true);

    return pcmk_legacy2rc(rc);
}

static void
update_counter(xmlNode *xml, const char *field, bool reset)
{
    int old_value = 0;
    bool was_set = (pcmk__xe_get_int(xml, field, &old_value) == pcmk_rc_ok);
    int new_value = (reset? 1 : (old_value + 1));

    if (was_set) {
        pcmk__trace("Updating %s from %d to %d", field, old_value, new_value);

    } else {
        pcmk__trace("Updating %s from unset to %d", field, new_value);
    }

    pcmk__xe_set_int(xml, field, new_value);
}

int
cib__process_bump(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    update_counter(*cib, PCMK_XA_EPOCH, false);
    return pcmk_rc_ok;
}

static int
add_cib_object(xmlNode *parent, xmlNode *new_obj)
{
    const char *object_name = NULL;
    const char *object_id = NULL;

    if ((parent == NULL) || (new_obj == NULL)) {
        return EINVAL;
    }

    object_name = (const char *) new_obj->name;
    if (object_name == NULL) {
        return EINVAL;
    }

    object_id = pcmk__xe_id(new_obj);
    if (pcmk__xe_first_child(parent, object_name,
                             ((object_id != NULL)? PCMK_XA_ID : NULL),
                             object_id)) {
        return EEXIST;
    }

    if (object_id != NULL) {
        pcmk__trace("Processing creation of <%s " PCMK_XA_ID "='%s'>",
                    object_name, object_id);
    } else {
        pcmk__trace("Processing creation of <%s>", object_name);
    }

    /* @COMPAT PCMK__XA_REPLACE is deprecated since 2.1.6. Due to a legacy use
     * case, PCMK__XA_REPLACE has special meaning and should not be included in
     * the newly created object until we can break behavioral backward
     * compatibility.
     *
     * At a compatibility break, drop this and drop the definition of
     * PCMK__XA_REPLACE. Treat it like any other attribute.
     */
    pcmk__xml_tree_foreach(new_obj, pcmk__xe_remove_attr_cb,
                           (void *) PCMK__XA_REPLACE);

    pcmk__xml_copy(parent, new_obj);
    return pcmk_rc_ok;
}

static void
update_results(xmlNode *failed, xmlNode *target, const char *operation, int rc)
{
    xmlNode *failed_update = pcmk__xe_create(failed, PCMK__XE_FAILED_UPDATE);

    pcmk__xml_copy(failed_update, target);

    pcmk__xe_set(failed_update, PCMK_XA_ID, pcmk__xe_id(target));
    pcmk__xe_set(failed_update, PCMK_XA_OBJECT_TYPE,
                 (const char *) target->name);
    pcmk__xe_set(failed_update, PCMK_XA_OPERATION, operation);
    pcmk__xe_set(failed_update, PCMK_XA_REASON, pcmk_rc_str(rc));

    pcmk__warn("Action %s failed: %s", operation, pcmk_rc_str(rc));
}

static int
process_create_xpath(const char *op, const char *xpath, xmlNode *input,
                     xmlNode *cib)
{
    int num_results = 0;
    int rc = pcmk_rc_ok;
    xmlXPathObject *xpath_obj = pcmk__xpath_search(cib->doc, xpath);
    xmlNode *match = NULL;
    xmlChar *path = NULL;

    num_results = pcmk__xpath_num_results(xpath_obj);
    if (num_results == 0) {
        pcmk__debug("%s: %s does not exist", op, xpath);
        rc = ENXIO;
        goto done;
    }

    match = pcmk__xpath_result(xpath_obj, 0);
    if (match == NULL) {
        goto done;
    }

    path = xmlGetNodePath(match);
    pcmk__debug("Processing %s op for %s with %s", op, xpath, path);
    free(path);

    pcmk__xml_copy(match, input);

done:
    xmlXPathFreeObject(xpath_obj);
    return rc;
}

int
cib__process_create(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    const char *op = pcmk__xe_get(req, PCMK__XA_CIB_OP);
    const char *section = pcmk__xe_get(req, PCMK__XA_CIB_SECTION);
    xmlNode *input = cib__get_calldata(req);
    xmlNode *failed = NULL;
    int rc = pcmk_rc_ok;
    xmlNode *update_section = NULL;

    if ((section != NULL) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        input = pcmk_find_cib_element(input, section);
    }

    if (input == NULL) {
        pcmk__err("Cannot perform modification with no data");
        return EINVAL;
    }

    if (pcmk__strcase_any_of(section, PCMK__XE_ALL, PCMK_XE_CIB, NULL)
        || pcmk__xe_is(input, PCMK_XE_CIB)) {

        return cib__process_modify(req, cib, answer);
    }

    // @COMPAT Deprecated since 2.1.8
    failed = pcmk__xe_create(NULL, PCMK__XE_FAILED);

    update_section = pcmk_find_cib_element(*cib, section);
    if (pcmk__xe_is(input, section)) {
        xmlNode *a_child = NULL;

        for (a_child = pcmk__xml_first_child(input); a_child != NULL;
             a_child = pcmk__xml_next(a_child)) {

            rc = add_cib_object(update_section, a_child);
            if (rc != pcmk_rc_ok) {
                update_results(failed, a_child, op, rc);
                break;
            }
        }

    } else {
        rc = add_cib_object(update_section, input);
        if (rc != pcmk_rc_ok) {
            update_results(failed, input, op, rc);
        }
    }

    if ((rc == pcmk_rc_ok) && (failed->children != NULL)) {
        rc = EINVAL;
    }

    if (rc != pcmk_rc_ok) {
        pcmk__log_xml_err(failed, "CIB Update failures");
        *answer = failed;

    } else {
        pcmk__xml_free(failed);
    }

    return rc;
}

static int
process_delete_xpath(const xmlNode *request, xmlNode *cib)
{
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *xpath = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    uint32_t options = cib_none;

    int num_results = 0;
    int rc = pcmk_rc_ok;

    xmlXPathObject *xpath_obj = pcmk__xpath_search(cib->doc, xpath);

    pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    num_results = pcmk__xpath_num_results(xpath_obj);
    if (num_results == 0) {
        pcmk__debug("%s was already removed", xpath);
        goto done;
    }

    for (int i = 0; i < num_results; i++) {
        xmlNode *match = NULL;
        xmlChar *path = NULL;

        /* If we're deleting multiple nodes, go in reverse document order.
         * If we go in forward order and the node set contains both a parent and
         * its descendant, then deleting the parent frees the descendant before
         * the loop reaches the descendant. This is a use-after-free error.
         *
         * @COMPAT cib_multiple is only ever used with delete operations. The
         * correct order to process multiple nodes for operations other than
         * query (forward) and delete (reverse) is less clear but likely should
         * be reverse. If we ever replace the CIB public API with libpacemaker
         * functions, revisit this. For now, we keep forward order for other
         * operations to preserve backward compatibility, even though external
         * callers of other ops with cib_multiple might segfault.
         *
         * For more info, see comment in xpath2.c:update_xpath_nodes() in
         * libxml2.
         */
        if (pcmk__is_set(options, cib_multiple)) {
            match = pcmk__xpath_result(xpath_obj, num_results - 1 - i);
        } else {
            match = pcmk__xpath_result(xpath_obj, i);
        }

        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        pcmk__debug("Processing %s op for %s with %s", op, xpath, path);
        free(path);

        if (match == cib) {
            pcmk__warn("Cannot perform %s for %s: the XPath is addressing the "
                       "whole /cib", op, xpath);
            rc = EINVAL;
            break;
        }

        pcmk__xml_free(match);
        if (!pcmk__is_set(options, cib_multiple)) {
            break;
        }
    }

done:
    xmlXPathFreeObject(xpath_obj);
    return rc;
}

static int
delete_child(xmlNode *child, void *userdata)
{
    xmlNode *obj_root = userdata;

    if (pcmk__xe_delete_match(obj_root, child) != pcmk_rc_ok) {
        pcmk__trace("No matching object to delete: %s=%s", child->name,
                    pcmk__xe_id(child));
    }

    return pcmk_rc_ok;
}

static int
process_delete_section(const xmlNode *request, xmlNode *cib)
{
    const char *section = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *input = cib__get_calldata(request);
    xmlNode *obj_root = NULL;

    if ((section != NULL) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        input = pcmk_find_cib_element(input, section);
    }

    if (input == NULL) {
        pcmk__err("Cannot find matching section to delete with no input data");
        return EINVAL;
    }

    obj_root = pcmk_find_cib_element(cib, section);

    if (pcmk__xe_is(input, section)) {
        pcmk__xe_foreach_child(input, NULL, delete_child, obj_root);

    } else {
        delete_child(input, obj_root);
    }

    return pcmk_rc_ok;
}

int
cib__process_delete(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    uint32_t options = cib_none;

    pcmk__xe_get_flags(req, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    if (pcmk__is_set(options, cib_xpath)) {
        return process_delete_xpath(req, *cib);
    }

    return process_delete_section(req, *cib);
}

int
cib__process_erase(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    xmlNode *empty = createEmptyCib(0);
    xmlNode *empty_config = pcmk__xe_first_child(empty, PCMK_XE_CONFIGURATION,
                                                 NULL, NULL);
    xmlNode *empty_status = pcmk__xe_first_child(empty, PCMK_XE_STATUS, NULL,
                                                 NULL);

    // Free all existing children, regardless of node type
    while ((*cib)->children != NULL) {
        pcmk__xml_free((*cib)->children);
    }

    /* Copying is wasteful here, but calling pcmk__xml_copy() adds the copy as a
     * child of the existing *cib within the same document. This reduces the
     * number of opportunities to make mistakes related to XML documents, change
     * tracking, etc., compared to calling xmlUnlinkChild(), xmlAddChild(), etc.
     */
    pcmk__xml_copy(*cib, empty_config);
    pcmk__xml_copy(*cib, empty_status);

    update_counter(*cib, PCMK_XA_ADMIN_EPOCH, false);

    pcmk__xml_free(empty);
    return pcmk_rc_ok;
}

static int
process_modify_xpath(const xmlNode *request, xmlNode *cib)
{
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *xpath = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *input = cib__get_calldata(request);
    uint32_t options = cib_none;

    int num_results = 0;
    int rc = pcmk_rc_ok;
    xmlXPathObject *xpath_obj = NULL;
    uint32_t flags = pcmk__xaf_none;

    pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &options, cib_none);
    if (pcmk__is_set(options, cib_score_update)) {
        flags = pcmk__xaf_score_update;
    }

    if (xpath == NULL) {
        xpath = pcmk__cib_abs_xpath_for(PCMK_XE_CIB);
    }

    xpath_obj = pcmk__xpath_search(cib->doc, xpath);

    num_results = pcmk__xpath_num_results(xpath_obj);
    if (num_results == 0) {
        pcmk__debug("%s: %s does not exist", op, xpath);
        rc = ENXIO;
        goto done;
    }

    for (int i = 0; i < num_results; i++) {
        xmlNode *match = NULL;
        xmlChar *path = NULL;

        match = pcmk__xpath_result(xpath_obj, i);
        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        pcmk__debug("Processing %s op for %s with %s", op, xpath, path);
        free(path);

        if (pcmk__xe_update_match(match, input, flags) != pcmk_rc_ok) {
            rc = ENXIO;

        } else if (!pcmk__is_set(options, cib_multiple)) {
            break;
        }
    }

done:
    xmlXPathFreeObject(xpath_obj);
    return rc;
}

static int
process_modify_section(const xmlNode *request, xmlNode *cib)
{
    const char *section = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *input = cib__get_calldata(request);
    uint32_t options = cib_none;

    uint32_t flags = pcmk__xaf_none;
    xmlNode *obj_root = NULL;

    pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &options, cib_none);
    if (pcmk__is_set(options, cib_score_update)) {
        flags = pcmk__xaf_score_update;
    }

    if ((section != NULL) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        input = pcmk_find_cib_element(input, section);
    }

    if (input == NULL) {
        pcmk__err("Cannot complete CIB modify request with no input data");
        return EINVAL;
    }

    obj_root = pcmk_find_cib_element(cib, section);
    if (obj_root == NULL) {
        xmlNode *tmp_section = NULL;
        const char *path = pcmk_cib_parent_name_for(section);

        if (path == NULL) {
            return EINVAL;
        }

        tmp_section = pcmk__xe_create(NULL, section);

        // @TODO This feels hacky and is the only call to process_create_xpath()
        process_create_xpath(PCMK__CIB_REQUEST_CREATE, path, tmp_section, cib);
        pcmk__xml_free(tmp_section);

        obj_root = pcmk_find_cib_element(cib, section);
    }

    // Should be impossible, as we just created this section if it didn't exist
    CRM_CHECK(obj_root != NULL, return EINVAL);

    if (pcmk__xe_update_match(obj_root, input, flags) == pcmk_rc_ok) {
        return pcmk_rc_ok;
    }

    if (!pcmk__is_set(options, cib_can_create)) {
        return ENXIO;
    }

    pcmk__xml_copy(obj_root, input);
    return pcmk_rc_ok;
}

int
cib__process_modify(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    uint32_t options = cib_none;

    pcmk__xe_get_flags(req, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    if (pcmk__is_set(options, cib_xpath)) {
        return process_modify_xpath(req, *cib);
    }

    return process_modify_section(req, *cib);
}

static int
process_query_xpath(const xmlNode *request, xmlNode *cib, xmlNode **answer)
{
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *xpath = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    uint32_t options = cib_none;

    int num_results = 0;
    int rc = pcmk_rc_ok;
    xmlXPathObject *xpath_obj = pcmk__xpath_search(cib->doc, xpath);

    pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    num_results = pcmk__xpath_num_results(xpath_obj);
    if (num_results == 0) {
        pcmk__debug("%s: %s does not exist", op, xpath);
        rc = ENXIO;
        goto done;
    }

    if (num_results > 1) {
        *answer = pcmk__xe_create(NULL, PCMK__XE_XPATH_QUERY);
    }

    for (int i = 0; i < num_results; i++) {
        xmlChar *path = NULL;
        xmlNode *match = pcmk__xpath_result(xpath_obj, i);

        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        pcmk__debug("Processing %s op for %s with %s", op, xpath, path);
        free(path);

        if (pcmk__is_set(options, cib_no_children)) {
            xmlNode *shallow = pcmk__xe_create(*answer,
                                               (const char *) match->name);

            pcmk__xe_copy_attrs(shallow, match, pcmk__xaf_none);

            if (*answer == NULL) {
                *answer = shallow;
            }

            continue;
        }

        if (pcmk__is_set(options, cib_xpath_address)) {
            // @COMPAT cib_xpath_address is deprecated since 3.0.2
            char *path = NULL;
            xmlNode *parent = match;

            while ((parent != NULL) && (parent->type == XML_ELEMENT_NODE)) {
                const char *id = pcmk__xe_get(parent, PCMK_XA_ID);
                char *new_path = NULL;

                if (id != NULL) {
                    new_path = pcmk__assert_asprintf("/%s[@" PCMK_XA_ID "='%s']"
                                                     "%s", parent->name, id,
                                                     pcmk__s(path, ""));
                } else {
                    new_path = pcmk__assert_asprintf("/%s%s", parent->name,
                                                     pcmk__s(path, ""));
                }

                free(path);
                path = new_path;
                parent = parent->parent;
            }

            pcmk__trace("Got: %s", path);

            if (*answer == NULL) {
                *answer = pcmk__xe_create(NULL, PCMK__XE_XPATH_QUERY);
            }

            parent = pcmk__xe_create(*answer, PCMK__XE_XPATH_QUERY_PATH);
            pcmk__xe_set(parent, PCMK_XA_ID, path);
            free(path);
            continue;
        }

        if (*answer != NULL) {
            pcmk__xml_copy(*answer, match);
            continue;
        }

        *answer = match;
    }

done:
    xmlXPathFreeObject(xpath_obj);
    return rc;
}

static int
process_query_section(const xmlNode *request, xmlNode *cib, xmlNode **answer)
{
    const char *section = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *obj_root = NULL;
    uint32_t options = cib_none;

    pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    if (pcmk__str_eq(PCMK__XE_ALL, section, pcmk__str_casei)) {
        section = NULL;
    }

    obj_root = pcmk_find_cib_element(cib, section);
    if (obj_root == NULL) {
        return ENXIO;
    }

    /* We make a copy in the cib_no_children case but not in the other. We may
     * be able to simplify the callers if we're able to do the same thing (copy
     * or don't copy) for both.
     */
    if (pcmk__is_set(options, cib_no_children)) {
        *answer = pcmk__xe_create(NULL, (const char *) obj_root->name);
        pcmk__xe_copy_attrs(*answer, obj_root, pcmk__xaf_none);

    } else {
        *answer = obj_root;
    }

    return pcmk_rc_ok;
}

int
cib__process_query(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    uint32_t options = cib_none;

    pcmk__xe_get_flags(req, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    if (pcmk__is_set(options, cib_xpath)) {
        return process_query_xpath(req, *cib, answer);
    }

    return process_query_section(req, *cib, answer);
}

static bool
replace_cib_digest_matches(const xmlNode *request)
{
    const char *peer = pcmk__xe_get(request, PCMK__XA_SRC);
    const char *expected = pcmk__xe_get(request, PCMK_XA_DIGEST);
    const xmlNode *input = cib__get_calldata(request);
    char *calculated = NULL;
    bool matches = false;

    if (expected == NULL) {
        // Nothing to verify
        return true;
    }

    calculated = pcmk__digest_xml(input, true);
    matches = pcmk__str_eq(calculated, expected, pcmk__str_none);

    if (matches) {
        pcmk__info("Digest matched on replace from %s: %s", peer, expected);

    } else {
        pcmk__err("Digest mismatch on replace from %s: %s vs. %s (expected)",
                  peer, calculated, expected);
    }

    free(calculated);
    return matches;
}

static int
replace_cib(xmlNode *request, xmlNode **cib)
{
    int updates = 0;
    int epoch = 0;
    int admin_epoch = 0;

    int replace_updates = 0;
    int replace_epoch = 0;
    int replace_admin_epoch = 0;

    const char *reason = NULL;
    const char *peer = pcmk__xe_get(request, PCMK__XA_SRC);
    xmlNode *input = cib__get_calldata(request);

    cib_version_details(*cib, &admin_epoch, &epoch, &updates);
    cib_version_details(input, &replace_admin_epoch, &replace_epoch,
                        &replace_updates);

    if (!replace_cib_digest_matches(request)) {
        pcmk__info("Replacement %d.%d.%d from %s not applied to %d.%d.%d: "
                   "digest mismatch", replace_admin_epoch, replace_epoch,
                   replace_updates, peer, admin_epoch, epoch, updates);
        return pcmk_rc_digest_mismatch;
    }

    if (replace_admin_epoch < admin_epoch) {
        reason = PCMK_XA_ADMIN_EPOCH;

    } else if (replace_admin_epoch > admin_epoch) {
        /* no more checks */

    } else if (replace_epoch < epoch) {
        reason = PCMK_XA_EPOCH;

    } else if (replace_epoch > epoch) {
        /* no more checks */

    } else if (replace_updates < updates) {
        reason = PCMK_XA_NUM_UPDATES;
    }

    if (reason != NULL) {
        pcmk__info("Replacement %d.%d.%d from %s not applied to %d.%d.%d: "
                   "current %s is greater than the replacement",
                   replace_admin_epoch, replace_epoch, replace_updates, peer,
                   admin_epoch, epoch, updates, reason);
        return pcmk_rc_old_data;
    }

    *cib = pcmk__xml_replace_with_copy(*cib, input);

    pcmk__info("Replaced %d.%d.%d with %d.%d.%d from %s", admin_epoch, epoch,
               updates, replace_admin_epoch, replace_epoch, replace_updates,
               peer);
    return pcmk_rc_ok;
}

static int
process_replace_xpath(xmlNode *request, xmlNode **cib)
{
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *xpath = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *input = cib__get_calldata(request);
    uint32_t options = cib_none;

    int num_results = 0;
    int rc = pcmk_rc_ok;
    xmlXPathObject *xpath_obj = pcmk__xpath_search((*cib)->doc, xpath);

    pcmk__xe_get_flags(request, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    num_results = pcmk__xpath_num_results(xpath_obj);
    if (num_results == 0) {
        pcmk__debug("%s: %s does not exist", op, xpath);
        rc = ENXIO;
        goto done;
    }

    for (int i = 0; i < num_results; i++) {
        xmlNode *match = NULL;
        xmlNode *parent = NULL;
        xmlChar *path = NULL;

        match = pcmk__xpath_result(xpath_obj, i);
        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        pcmk__debug("Processing %s op for %s with %s", op, xpath, path);
        free(path);

        if (match == *cib) {
            rc = replace_cib(request, cib);
            break;
        }

        parent = match->parent;

        pcmk__xml_free(match);
        pcmk__xml_copy(parent, input);

        if (!pcmk__is_set(options, cib_multiple)) {
            break;
        }
    }

done:
    xmlXPathFreeObject(xpath_obj);
    return rc;
}

static int
process_replace_section(xmlNode *request, xmlNode **cib)
{
    const char *section = pcmk__xe_get(request, PCMK__XA_CIB_SECTION);
    xmlNode *input = cib__get_calldata(request);

    int rc = pcmk_rc_ok;
    xmlNode *obj_root = NULL;

    if ((section != NULL) && pcmk__xe_is(input, PCMK_XE_CIB)) {
        input = pcmk_find_cib_element(input, section);
    }

    if (input == NULL) {
        pcmk__err("Cannot find matching section to replace with no input data");
        return EINVAL;
    }

    if (pcmk__xe_is(input, PCMK_XE_CIB)) {
        return replace_cib(request, cib);
    }

    if (pcmk__str_eq(PCMK__XE_ALL, section, pcmk__str_casei)
        || pcmk__xe_is(input, section)) {

        section = NULL;
    }

    obj_root = pcmk_find_cib_element(*cib, section);

    rc = pcmk__xe_replace_match(obj_root, input);
    if (rc != pcmk_rc_ok) {
        pcmk__trace("No matching object to replace");
    }

    return rc;
}

int
cib__process_replace(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    uint32_t options = cib_none;

    pcmk__xe_get_flags(req, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    if (pcmk__is_set(options, cib_xpath)) {
        return process_replace_xpath(req, cib);
    }

    return process_replace_section(req, cib);
}

int
cib__process_upgrade(xmlNode *req, xmlNode **cib, xmlNode **answer)
{
    int rc = pcmk_rc_ok;
    uint32_t options = cib_none;
    const char *max_schema = pcmk__xe_get(req, PCMK__XA_CIB_SCHEMA_MAX);
    const char *original_schema = pcmk__xe_get(*cib, PCMK_XA_VALIDATE_WITH);
    const char *new_schema = NULL;
    xmlNode *updated = pcmk__xml_copy(NULL, *cib);

    pcmk__xe_get_flags(req, PCMK__XA_CIB_CALLOPT, &options, cib_none);

    rc = pcmk__update_schema(&updated, max_schema,
                             !pcmk__is_set(options, cib_verbose));
    *cib = pcmk__xml_replace_with_copy(*cib, updated);
    pcmk__xml_free(updated);

    new_schema = pcmk__xe_get(*cib, PCMK_XA_VALIDATE_WITH);

    if (pcmk__cmp_schemas_by_name(new_schema, original_schema) > 0) {
        update_counter(*cib, PCMK_XA_ADMIN_EPOCH, false);
        update_counter(*cib, PCMK_XA_EPOCH, true);
        update_counter(*cib, PCMK_XA_NUM_UPDATES, true);
        return pcmk_rc_ok;
    }

    return rc;
}

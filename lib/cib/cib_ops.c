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
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <sys/param.h>
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>

#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

// @TODO: Free this via crm_exit() when libcib gets merged with libcrmcommon
static GHashTable *operation_table = NULL;

static const cib__operation_t cib_ops[] = {
    {
        PCMK__CIB_REQUEST_ABS_DELETE, cib__op_abs_delete,
        cib__op_attr_modifies|cib__op_attr_privileged
    },
    {
        PCMK__CIB_REQUEST_APPLY_PATCH, cib__op_apply_patch,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_BUMP, cib__op_bump,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_COMMIT_TRANSACT, cib__op_commit_transact,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_replaces
        |cib__op_attr_writes_through
    },
    {
        PCMK__CIB_REQUEST_CREATE, cib__op_create,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_DELETE, cib__op_delete,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_ERASE, cib__op_erase,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_replaces
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_IS_PRIMARY, cib__op_is_primary,
        cib__op_attr_privileged
    },
    {
        PCMK__CIB_REQUEST_MODIFY, cib__op_modify,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_NOOP, cib__op_noop, cib__op_attr_none
    },
    {
        CRM_OP_PING, cib__op_ping, cib__op_attr_none
    },
    {
        // @COMPAT: Drop cib__op_attr_modifies when we drop legacy mode support
        PCMK__CIB_REQUEST_PRIMARY, cib__op_primary,
        cib__op_attr_modifies|cib__op_attr_privileged|cib__op_attr_local
    },
    {
        PCMK__CIB_REQUEST_QUERY, cib__op_query, cib__op_attr_none
    },
    {
        PCMK__CIB_REQUEST_REPLACE, cib__op_replace,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_replaces
        |cib__op_attr_writes_through
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_SECONDARY, cib__op_secondary,
        cib__op_attr_privileged|cib__op_attr_local
    },
    {
        PCMK__CIB_REQUEST_SHUTDOWN, cib__op_shutdown, cib__op_attr_privileged
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ALL, cib__op_sync_all, cib__op_attr_privileged
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ONE, cib__op_sync_one, cib__op_attr_privileged
    },
    {
        PCMK__CIB_REQUEST_UPGRADE, cib__op_upgrade,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_writes_through
        |cib__op_attr_transaction
    },
    {
        PCMK__CIB_REQUEST_SCHEMAS, cib__op_schemas, cib__op_attr_local
    }
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
    CRM_ASSERT((op != NULL) && (operation != NULL));

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
        crm_err("Operation %s is invalid", op);
        return EINVAL;
    }
    return pcmk_rc_ok;
}

int
cib_process_query(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *obj_root = NULL;
    int result = pcmk_ok;

    crm_trace("Processing %s for %s section",
              op, pcmk__s(section, "unspecified"));

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    CRM_CHECK(*answer == NULL, pcmk__xml_free(*answer));
    *answer = NULL;

    if (pcmk__str_eq(PCMK__XE_ALL, section, pcmk__str_casei)) {
        section = NULL;
    }

    obj_root = pcmk_find_cib_element(existing_cib, section);

    if (obj_root == NULL) {
        result = -ENXIO;

    } else if (options & cib_no_children) {
        xmlNode *shallow = pcmk__xe_create(*answer,
                                           (const char *) obj_root->name);

        pcmk__xe_copy_attrs(shallow, obj_root, pcmk__xaf_none);
        *answer = shallow;

    } else {
        *answer = obj_root;
    }

    if (result == pcmk_ok && *answer == NULL) {
        crm_err("Error creating query response");
        result = -ENOMSG;
    }

    return result;
}

static int
update_counter(xmlNode *xml_obj, const char *field, bool reset)
{
    char *new_value = NULL;
    char *old_value = NULL;
    int int_value = -1;

    if (!reset && crm_element_value(xml_obj, field) != NULL) {
        old_value = crm_element_value_copy(xml_obj, field);
    }
    if (old_value != NULL) {
        int_value = atoi(old_value);
        new_value = pcmk__itoa(++int_value);
    } else {
        new_value = pcmk__str_copy("1");
    }

    crm_trace("Update %s from %s to %s",
              field, pcmk__s(old_value, "unset"), new_value);
    crm_xml_add(xml_obj, field, new_value);

    free(new_value);
    free(old_value);

    return pcmk_ok;
}

int
cib_process_erase(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int result = pcmk_ok;

    crm_trace("Processing \"%s\" event", op);

    if (*result_cib != existing_cib) {
        pcmk__xml_free(*result_cib);
    }
    *result_cib = createEmptyCib(0);
    pcmk__xe_copy_attrs(*result_cib, existing_cib, pcmk__xaf_none);
    update_counter(*result_cib, PCMK_XA_ADMIN_EPOCH, false);
    *answer = NULL;

    return result;
}

int
cib_process_upgrade(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer)
{
    int rc = 0;
    const char *max_schema = crm_element_value(req, PCMK__XA_CIB_SCHEMA_MAX);
    const char *original_schema = NULL;
    const char *new_schema = NULL;

    *answer = NULL;
    crm_trace("Processing \"%s\" event with max=%s", op, max_schema);

    original_schema = crm_element_value(existing_cib, PCMK_XA_VALIDATE_WITH);
    rc = pcmk__update_schema(result_cib, max_schema, true,
                             !pcmk_is_set(options, cib_verbose));
    rc = pcmk_rc2legacy(rc);
    new_schema = crm_element_value(*result_cib, PCMK_XA_VALIDATE_WITH);

    if (pcmk__cmp_schemas_by_name(new_schema, original_schema) > 0) {
        update_counter(*result_cib, PCMK_XA_ADMIN_EPOCH, false);
        update_counter(*result_cib, PCMK_XA_EPOCH, true);
        update_counter(*result_cib, PCMK_XA_NUM_UPDATES, true);
        return pcmk_ok;
    }

    return rc;
}

int
cib_process_bump(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int result = pcmk_ok;

    crm_trace("Processing %s for epoch='%s'", op,
              pcmk__s(crm_element_value(existing_cib, PCMK_XA_EPOCH), ""));

    *answer = NULL;
    update_counter(*result_cib, PCMK_XA_EPOCH, false);

    return result;
}

int
cib_process_replace(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer)
{
    int result = pcmk_ok;

    crm_trace("Processing %s for %s section",
              op, pcmk__s(section, "unspecified"));

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    *answer = NULL;

    if (input == NULL) {
        return -EINVAL;
    }

    if (pcmk__str_eq(PCMK__XE_ALL, section, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__xe_is(input, section)) {
        section = NULL;
    }

    if (pcmk__xe_is(input, PCMK_XE_CIB)) {
        int updates = 0;
        int epoch = 0;
        int admin_epoch = 0;

        int replace_updates = 0;
        int replace_epoch = 0;
        int replace_admin_epoch = 0;

        const char *reason = NULL;
        const char *peer = crm_element_value(req, PCMK__XA_SRC);
        const char *digest = crm_element_value(req, PCMK__XA_DIGEST);

        if (digest) {
            const char *version =
                pcmk__s(crm_element_value(req, PCMK_XA_CRM_FEATURE_SET),
                        CRM_FEATURE_SET);
            char *digest_verify = pcmk__digest_xml(input, true, version);

            if (!pcmk__str_eq(digest_verify, digest, pcmk__str_casei)) {
                crm_err("Digest mis-match on replace from %s: %s vs. %s (expected)", peer,
                        digest_verify, digest);
                reason = "digest mismatch";

            } else {
                crm_info("Digest matched on replace from %s: %s", peer, digest);
            }
            free(digest_verify);

        } else {
            crm_trace("No digest to verify");
        }

        cib_version_details(existing_cib, &admin_epoch, &epoch, &updates);
        cib_version_details(input, &replace_admin_epoch, &replace_epoch, &replace_updates);

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
            crm_info("Replacement %d.%d.%d from %s not applied to %d.%d.%d:"
                     " current %s is greater than the replacement",
                     replace_admin_epoch, replace_epoch,
                     replace_updates, peer, admin_epoch, epoch, updates, reason);
            result = -pcmk_err_old_data;
        } else {
            crm_info("Replaced %d.%d.%d with %d.%d.%d from %s",
                     admin_epoch, epoch, updates,
                     replace_admin_epoch, replace_epoch, replace_updates, peer);
        }

        if (*result_cib != existing_cib) {
            pcmk__xml_free(*result_cib);
        }
        *result_cib = pcmk__xml_copy(NULL, input);

    } else {
        xmlNode *obj_root = NULL;

        obj_root = pcmk_find_cib_element(*result_cib, section);
        result = pcmk__xe_replace_match(obj_root, input);
        result = pcmk_rc2legacy(result);
        if (result != pcmk_ok) {
            crm_trace("No matching object to replace");
        }
    }

    return result;
}

static int
delete_child(xmlNode *child, void *userdata)
{
    xmlNode *obj_root = userdata;

    if (pcmk__xe_delete_match(obj_root, child) != pcmk_rc_ok) {
        crm_trace("No matching object to delete: %s=%s",
                  child->name, pcmk__xe_id(child));
    }

    return pcmk_rc_ok;
}

int
cib_process_delete(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *obj_root = NULL;

    crm_trace("Processing \"%s\" event", op);

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    if (input == NULL) {
        crm_err("Cannot perform modification with no data");
        return -EINVAL;
    }

    obj_root = pcmk_find_cib_element(*result_cib, section);
    if (pcmk__xe_is(input, section)) {
        pcmk__xe_foreach_child(input, NULL, delete_child, obj_root);
    } else {
        delete_child(input, obj_root);
    }

    return pcmk_ok;
}

int
cib_process_modify(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *obj_root = NULL;
    uint32_t flags = pcmk__xaf_none;

    crm_trace("Processing \"%s\" event", op);

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    if (input == NULL) {
        crm_err("Cannot perform modification with no data");
        return -EINVAL;
    }

    obj_root = pcmk_find_cib_element(*result_cib, section);
    if (obj_root == NULL) {
        xmlNode *tmp_section = NULL;
        const char *path = pcmk_cib_parent_name_for(section);

        if (path == NULL) {
            return -EINVAL;
        }

        tmp_section = pcmk__xe_create(NULL, section);
        cib_process_xpath(PCMK__CIB_REQUEST_CREATE, 0, path, NULL, tmp_section,
                          NULL, result_cib, answer);
        pcmk__xml_free(tmp_section);

        obj_root = pcmk_find_cib_element(*result_cib, section);
    }

    CRM_CHECK(obj_root != NULL, return -EINVAL);

    if (pcmk_is_set(options, cib_score_update)) {
        flags |= pcmk__xaf_score_update;
    }

    if (pcmk__xe_update_match(obj_root, input, flags) != pcmk_rc_ok) {
        if (options & cib_can_create) {
            pcmk__xml_copy(obj_root, input);
        } else {
            return -ENXIO;
        }
    }

    // @COMPAT cib_mixed_update is deprecated as of 2.1.7
    if (pcmk_is_set(options, cib_mixed_update)) {
        int max = 0, lpc;
        xmlXPathObject *xpathObj = NULL;

        CRM_CHECK(*result_cib != NULL, return -ENXIO);

        xpathObj = pcmk__xpath_search((*result_cib)->doc, "//@__delete__");

        if (xpathObj) {
            max = numXpathResults(xpathObj);
            crm_log_xml_trace(*result_cib, "Mixed result");
        }

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpathObj, lpc);
            xmlChar *match_path = xmlGetNodePath(match);

            crm_debug("Destroying %s", match_path);
            free(match_path);
            pcmk__xml_free(match);
        }

        freeXpathObject(xpathObj);
    }
    return pcmk_ok;
}

static int
add_cib_object(xmlNode * parent, xmlNode * new_obj)
{
    const char *object_name = NULL;
    const char *object_id = NULL;

    if ((parent == NULL) || (new_obj == NULL)) {
        return -EINVAL;
    }

    object_name = (const char *) new_obj->name;
    if (object_name == NULL) {
        return -EINVAL;
    }

    object_id = pcmk__xe_id(new_obj);
    if (pcmk__xe_first_child(parent, object_name,
                             ((object_id != NULL)? PCMK_XA_ID : NULL),
                             object_id)) {
        return -EEXIST;
    }

    if (object_id != NULL) {
        crm_trace("Processing creation of <%s " PCMK_XA_ID "='%s'>",
                  object_name, object_id);
    } else {
        crm_trace("Processing creation of <%s>", object_name);
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
    return pcmk_ok;
}

static bool
update_results(xmlNode *failed, xmlNode *target, const char *operation,
               int return_code)
{
    xmlNode *xml_node = NULL;
    bool was_error = false;
    const char *error_msg = NULL;

    if (return_code != pcmk_ok) {
        error_msg = pcmk_strerror(return_code);

        was_error = true;
        xml_node = pcmk__xe_create(failed, PCMK__XE_FAILED_UPDATE);
        pcmk__xml_copy(xml_node, target);

        crm_xml_add(xml_node, PCMK_XA_ID, pcmk__xe_id(target));
        crm_xml_add(xml_node, PCMK_XA_OBJECT_TYPE, (const char *) target->name);
        crm_xml_add(xml_node, PCMK_XA_OPERATION, operation);
        crm_xml_add(xml_node, PCMK_XA_REASON, error_msg);

        crm_warn("Action %s failed: %s (cde=%d)",
                 operation, error_msg, return_code);
    }

    return was_error;
}

int
cib_process_create(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *failed = NULL;
    int result = pcmk_ok;
    xmlNode *update_section = NULL;

    crm_trace("Processing %s for %s section",
              op, pcmk__s(section, "unspecified"));
    if (pcmk__str_eq(PCMK__XE_ALL, section, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__str_eq(section, PCMK_XE_CIB, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__xe_is(input, PCMK_XE_CIB)) {
        section = NULL;
    }

    CRM_CHECK(strcmp(op, PCMK__CIB_REQUEST_CREATE) == 0, return -EINVAL);

    if (input == NULL) {
        crm_err("Cannot perform modification with no data");
        return -EINVAL;
    }

    if (section == NULL) {
        return cib_process_modify(op, options, section, req, input, existing_cib, result_cib,
                                  answer);
    }

    // @COMPAT Deprecated since 2.1.8
    failed = pcmk__xe_create(NULL, PCMK__XE_FAILED);

    update_section = pcmk_find_cib_element(*result_cib, section);
    if (pcmk__xe_is(input, section)) {
        xmlNode *a_child = NULL;

        for (a_child = pcmk__xml_first_child(input); a_child != NULL;
             a_child = pcmk__xml_next(a_child)) {
            result = add_cib_object(update_section, a_child);
            if (update_results(failed, a_child, op, result)) {
                break;
            }
        }

    } else {
        result = add_cib_object(update_section, input);
        update_results(failed, input, op, result);
    }

    if ((result == pcmk_ok) && (failed->children != NULL)) {
        result = -EINVAL;
    }

    if (result != pcmk_ok) {
        crm_log_xml_err(failed, "CIB Update failures");
        *answer = failed;

    } else {
        pcmk__xml_free(failed);
    }

    return result;
}

int
cib_process_diff(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    const char *originator = NULL;

    if (req != NULL) {
        originator = crm_element_value(req, PCMK__XA_SRC);
    }

    crm_trace("Processing \"%s\" event from %s%s",
              op, originator,
              (pcmk_is_set(options, cib_force_diff)? " (global update)" : ""));

    if (*result_cib != existing_cib) {
        pcmk__xml_free(*result_cib);
    }
    *result_cib = pcmk__xml_copy(NULL, existing_cib);

    return xml_apply_patchset(*result_cib, input, TRUE);
}

// @COMPAT: v1-only
bool
cib__config_changed_v1(xmlNode *last, xmlNode *next, xmlNode **diff)
{
    int lpc = 0, max = 0;
    bool config_changes = false;
    xmlXPathObject *xpathObj = NULL;
    int format = 1;

    CRM_ASSERT(diff != NULL);

    if (*diff == NULL && last != NULL && next != NULL) {
        *diff = pcmk__diff_v1_xml_object(last, next, false);
    }

    if (*diff == NULL) {
        goto done;
    }

    crm_element_value_int(*diff, PCMK_XA_FORMAT, &format);
    CRM_LOG_ASSERT(format == 1);

    xpathObj = pcmk__xpath_search((*diff)->doc, "//" PCMK_XE_CONFIGURATION);
    if (numXpathResults(xpathObj) > 0) {
        config_changes = true;
        goto done;
    }
    freeXpathObject(xpathObj);

    /*
     * Do not check PCMK__XE_DIFF_ADDED "//" PCMK_XE_CIB
     * This always contains every field and would produce a false positive
     * every time if the checked value existed
     */
    xpathObj = pcmk__xpath_search((*diff)->doc,
                                  "//" PCMK__XE_DIFF_REMOVED "//" PCMK_XE_CIB);
    max = numXpathResults(xpathObj);

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *top = getXpathResult(xpathObj, lpc);

        if (crm_element_value(top, PCMK_XA_EPOCH) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, PCMK_XA_ADMIN_EPOCH) != NULL) {
            config_changes = true;
            goto done;
        }

        if (crm_element_value(top, PCMK_XA_VALIDATE_WITH) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, PCMK_XA_CRM_FEATURE_SET) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, PCMK_XA_REMOTE_CLEAR_PORT) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, PCMK_XA_REMOTE_TLS_PORT) != NULL) {
            config_changes = true;
            goto done;
        }
    }

  done:
    freeXpathObject(xpathObj);
    return config_changes;
}

int
cib_process_xpath(const char *op, int options, const char *section,
                  const xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                  xmlNode **result_cib, xmlNode **answer)
{
    int lpc = 0;
    int max = 0;
    int rc = pcmk_ok;
    bool is_query = pcmk__str_eq(op, PCMK__CIB_REQUEST_QUERY, pcmk__str_none);

    xmlXPathObjectPtr xpathObj = NULL;

    crm_trace("Processing \"%s\" event", op);

    if (is_query) {
        CRM_CHECK(existing_cib != NULL, return EINVAL);
        xpathObj = pcmk__xpath_search(existing_cib->doc, section);
    } else {
        CRM_CHECK(*result_cib != NULL, return EINVAL);
        xpathObj = pcmk__xpath_search((*result_cib)->doc, section);
    }

    max = numXpathResults(xpathObj);

    if ((max < 1)
        && pcmk__str_eq(op, PCMK__CIB_REQUEST_DELETE, pcmk__str_none)) {
        crm_debug("%s was already removed", section);

    } else if (max < 1) {
        crm_debug("%s: %s does not exist", op, section);
        rc = -ENXIO;

    } else if (is_query) {
        if (max > 1) {
            *answer = pcmk__xe_create(NULL, PCMK__XE_XPATH_QUERY);
        }
    }

    if (pcmk_is_set(options, cib_multiple)
        && pcmk__str_eq(op, PCMK__CIB_REQUEST_DELETE, pcmk__str_none)) {
        dedupXpathResults(xpathObj);
    }

    for (lpc = 0; lpc < max; lpc++) {
        xmlChar *path = NULL;
        xmlNode *match = getXpathResult(xpathObj, lpc);

        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        crm_debug("Processing %s op for %s with %s", op, section, path);
        free(path);

        if (pcmk__str_eq(op, PCMK__CIB_REQUEST_DELETE, pcmk__str_none)) {
            if (match == *result_cib) {
                /* Attempting to delete the whole "/cib" */
                crm_warn("Cannot perform %s for %s: The xpath is addressing the whole /cib", op, section);
                rc = -EINVAL;
                break;
            }

            pcmk__xml_free(match);
            if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_MODIFY, pcmk__str_none)) {
            uint32_t flags = pcmk__xaf_none;

            if (pcmk_is_set(options, cib_score_update)) {
                flags |= pcmk__xaf_score_update;
            }

            if (pcmk__xe_update_match(match, input, flags) != pcmk_rc_ok) {
                rc = -ENXIO;
            } else if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_CREATE, pcmk__str_none)) {
            pcmk__xml_copy(match, input);
            break;

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_QUERY, pcmk__str_none)) {

            if (options & cib_no_children) {
                xmlNode *shallow = pcmk__xe_create(*answer,
                                                   (const char *) match->name);

                pcmk__xe_copy_attrs(shallow, match, pcmk__xaf_none);

                if (*answer == NULL) {
                    *answer = shallow;
                }

            } else if (options & cib_xpath_address) {
                char *path = NULL;
                xmlNode *parent = match;

                while (parent && parent->type == XML_ELEMENT_NODE) {
                    const char *id = crm_element_value(parent, PCMK_XA_ID);
                    char *new_path = NULL;

                    if (id) {
                        new_path = crm_strdup_printf("/%s[@" PCMK_XA_ID "='%s']"
                                                     "%s",
                                                     parent->name, id,
                                                     pcmk__s(path, ""));
                    } else {
                        new_path = crm_strdup_printf("/%s%s", parent->name,
                                                     pcmk__s(path, ""));
                    }
                    free(path);
                    path = new_path;
                    parent = parent->parent;
                }
                crm_trace("Got: %s", path);

                if (*answer == NULL) {
                    *answer = pcmk__xe_create(NULL, PCMK__XE_XPATH_QUERY);
                }
                parent = pcmk__xe_create(*answer, PCMK__XE_XPATH_QUERY_PATH);
                crm_xml_add(parent, PCMK_XA_ID, path);
                free(path);

            } else if (*answer) {
                pcmk__xml_copy(*answer, match);

            } else {
                *answer = match;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_REPLACE,
                                pcmk__str_none)) {
            xmlNode *parent = match->parent;

            pcmk__xml_free(match);
            pcmk__xml_copy(parent, input);

            if ((options & cib_multiple) == 0) {
                break;
            }
        }
    }

    freeXpathObject(xpathObj);
    return rc;
}

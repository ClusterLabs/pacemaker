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
#include <crm/msg_xml.h>

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

    /* PCMK__CIB_REQUEST_*_TRANSACT requests must be processed locally because
     * they depend on the client table. Requests that manage transactions on
     * other nodes would likely be problematic in many other ways as well.
     */
    {
        PCMK__CIB_REQUEST_INIT_TRANSACT, cib__op_init_transact,
        cib__op_attr_privileged|cib__op_attr_local
    },
    {
        PCMK__CIB_REQUEST_COMMIT_TRANSACT, cib__op_commit_transact,
        cib__op_attr_modifies
        |cib__op_attr_privileged
        |cib__op_attr_local
        |cib__op_attr_replaces
        |cib__op_attr_writes_through
    },
    {
        PCMK__CIB_REQUEST_DISCARD_TRANSACT, cib__op_discard_transact,
        cib__op_attr_privileged|cib__op_attr_local
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

    CRM_CHECK(*answer == NULL, free_xml(*answer));
    *answer = NULL;

    if (pcmk__str_eq(XML_CIB_TAG_SECTION_ALL, section, pcmk__str_casei)) {
        section = NULL;
    }

    obj_root = pcmk_find_cib_element(existing_cib, section);

    if (obj_root == NULL) {
        result = -ENXIO;

    } else if (options & cib_no_children) {
        xmlNode *shallow = create_xml_node(*answer,
                                           (const char *) obj_root->name);

        copy_in_properties(shallow, obj_root);
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
        new_value = strdup("1");
        CRM_ASSERT(new_value != NULL);
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
        free_xml(*result_cib);
    }
    *result_cib = createEmptyCib(0);
    copy_in_properties(*result_cib, existing_cib);
    update_counter(*result_cib, XML_ATTR_GENERATION_ADMIN, false);
    *answer = NULL;

    return result;
}

int
cib_process_upgrade(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer)
{
    int rc = 0;
    int new_version = 0;
    int current_version = 0;
    int max_version = 0;
    const char *max = crm_element_value(req, F_CIB_SCHEMA_MAX);
    const char *value = crm_element_value(existing_cib, XML_ATTR_VALIDATION);

    *answer = NULL;
    crm_trace("Processing \"%s\" event with max=%s", op, max);

    if (value != NULL) {
        current_version = get_schema_version(value);
    }

    if (max) {
        max_version = get_schema_version(max);
    }

    rc = update_validation(result_cib, &new_version, max_version, TRUE,
                           !(options & cib_verbose));
    if (new_version > current_version) {
        update_counter(*result_cib, XML_ATTR_GENERATION_ADMIN, false);
        update_counter(*result_cib, XML_ATTR_GENERATION, true);
        update_counter(*result_cib, XML_ATTR_NUMUPDATES, true);
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
              pcmk__s(crm_element_value(existing_cib, XML_ATTR_GENERATION), ""));

    *answer = NULL;
    update_counter(*result_cib, XML_ATTR_GENERATION, false);

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

    if (pcmk__str_eq(XML_CIB_TAG_SECTION_ALL, section, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__xe_is(input, section)) {
        section = NULL;
    }

    if (pcmk__xe_is(input, XML_TAG_CIB)) {
        int updates = 0;
        int epoch = 0;
        int admin_epoch = 0;

        int replace_updates = 0;
        int replace_epoch = 0;
        int replace_admin_epoch = 0;

        const char *reason = NULL;
        const char *peer = crm_element_value(req, F_ORIG);
        const char *digest = crm_element_value(req, XML_ATTR_DIGEST);

        if (digest) {
            const char *version = crm_element_value(req, XML_ATTR_CRM_VERSION);
            char *digest_verify = calculate_xml_versioned_digest(input, FALSE, TRUE,
                                                                 version ? version :
                                                                 CRM_FEATURE_SET);

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
            reason = XML_ATTR_GENERATION_ADMIN;

        } else if (replace_admin_epoch > admin_epoch) {
            /* no more checks */

        } else if (replace_epoch < epoch) {
            reason = XML_ATTR_GENERATION;

        } else if (replace_epoch > epoch) {
            /* no more checks */

        } else if (replace_updates < updates) {
            reason = XML_ATTR_NUMUPDATES;
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
            free_xml(*result_cib);
        }
        *result_cib = copy_xml(input);

    } else {
        xmlNode *obj_root = NULL;
        gboolean ok = TRUE;

        obj_root = pcmk_find_cib_element(*result_cib, section);
        ok = replace_xml_child(NULL, obj_root, input, FALSE);
        if (ok == FALSE) {
            crm_trace("No matching object to replace");
            result = -ENXIO;
        }
    }

    return result;
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
        xmlNode *child = NULL;
        for (child = pcmk__xml_first_child(input); child;
             child = pcmk__xml_next(child)) {
            if (replace_xml_child(NULL, obj_root, child, TRUE) == FALSE) {
                crm_trace("No matching object to delete: %s=%s", child->name, ID(child));
            }
        }

    } else if (replace_xml_child(NULL, obj_root, input, TRUE) == FALSE) {
            crm_trace("No matching object to delete: %s=%s", input->name, ID(input));
    }

    return pcmk_ok;
}

int
cib_process_modify(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
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
    if (obj_root == NULL) {
        xmlNode *tmp_section = NULL;
        const char *path = pcmk_cib_parent_name_for(section);

        if (path == NULL) {
            return -EINVAL;
        }

        tmp_section = create_xml_node(NULL, section);
        cib_process_xpath(PCMK__CIB_REQUEST_CREATE, 0, path, NULL, tmp_section,
                          NULL, result_cib, answer);
        free_xml(tmp_section);

        obj_root = pcmk_find_cib_element(*result_cib, section);
    }

    CRM_CHECK(obj_root != NULL, return -EINVAL);

    if (update_xml_child(obj_root, input) == FALSE) {
        if (options & cib_can_create) {
            add_node_copy(obj_root, input);
        } else {
            return -ENXIO;
        }
    }

    if(options & cib_mixed_update) {
        int max = 0, lpc;
        xmlXPathObjectPtr xpathObj = xpath_search(*result_cib, "//@__delete__");

        if (xpathObj) {
            max = numXpathResults(xpathObj);
            crm_log_xml_trace(*result_cib, "Mixed result");
        }

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpathObj, lpc);
            xmlChar *match_path = xmlGetNodePath(match);

            crm_debug("Destroying %s", match_path);
            free(match_path);
            free_xml(match);
        }

        freeXpathObject(xpathObj);
    }
    return pcmk_ok;
}

static int
update_cib_object(xmlNode * parent, xmlNode * update)
{
    int result = pcmk_ok;
    xmlNode *target = NULL;
    xmlNode *a_child = NULL;
    const char *replace = NULL;
    const char *object_id = NULL;
    const char *object_name = NULL;

    CRM_CHECK(update != NULL, return -EINVAL);
    CRM_CHECK(parent != NULL, return -EINVAL);

    object_name = crm_element_name(update);
    CRM_CHECK(object_name != NULL, return -EINVAL);

    object_id = ID(update);
    crm_trace("Processing update for <%s%s%s%s>", object_name,
              ((object_id == NULL)? "" : " " XML_ATTR_ID "='"),
              pcmk__s(object_id, ""),
              ((object_id == NULL)? "" : "'"));

    if (object_id == NULL) {
        /*  placeholder object */
        target = find_xml_node(parent, object_name, FALSE);

    } else {
        target = pcmk__xe_match(parent, object_name, XML_ATTR_ID, object_id);
    }

    if (target == NULL) {
        target = create_xml_node(parent, object_name);
    }

    crm_trace("Found node <%s%s%s%s> to update", object_name,
              ((object_id == NULL)? "" : " " XML_ATTR_ID "='"),
              pcmk__s(object_id, ""),
              ((object_id == NULL)? "" : "'"));

    // @COMPAT: XML_CIB_ATTR_REPLACE is unused internally. Remove at break.
    replace = crm_element_value(update, XML_CIB_ATTR_REPLACE);
    if (replace != NULL) {
        xmlNode *remove = NULL;
        int last = 0, lpc = 0, len = 0;

        len = strlen(replace);
        while (lpc <= len) {
            if (replace[lpc] == ',' || replace[lpc] == 0) {
                char *replace_item = NULL;

                if (last == lpc) {
                    /* nothing to do */
                    last = lpc + 1;
                    goto incr;
                }

                replace_item = strndup(replace + last, lpc - last);
                remove = find_xml_node(target, replace_item, FALSE);
                if (remove != NULL) {
                    crm_trace("Replacing node <%s> in <%s>",
                              replace_item, crm_element_name(target));
                    free_xml(remove);
                    remove = NULL;
                }
                free(replace_item);
                last = lpc + 1;
            }
  incr:
            lpc++;
        }
        xml_remove_prop(update, XML_CIB_ATTR_REPLACE);
        xml_remove_prop(target, XML_CIB_ATTR_REPLACE);
    }

    copy_in_properties(target, update);

    if (xml_acl_denied(target)) {
        crm_notice("Cannot update <%s " XML_ATTR_ID "=%s>",
                   pcmk__s(object_name, "<null>"),
                   pcmk__s(object_id, "<null>"));
        return -EACCES;
    }

    crm_trace("Processing children of <%s%s%s%s>", object_name,
              ((object_id == NULL)? "" : " " XML_ATTR_ID "='"),
              pcmk__s(object_id, ""),
              ((object_id == NULL)? "" : "'"));

    for (a_child = pcmk__xml_first_child(update); a_child != NULL;
         a_child = pcmk__xml_next(a_child)) {
        int tmp_result = 0;

        crm_trace("Updating child <%s%s%s%s>", crm_element_name(a_child),
                  ((ID(a_child) == NULL)? "" : " " XML_ATTR_ID "='"),
                  pcmk__s(ID(a_child), ""), ((ID(a_child) == NULL)? "" : "'"));

        tmp_result = update_cib_object(target, a_child);

        /*  only the first error is likely to be interesting */
        if (tmp_result != pcmk_ok) {
            crm_err("Error updating child <%s%s%s%s>",
                    crm_element_name(a_child),
                    ((ID(a_child) == NULL)? "" : " " XML_ATTR_ID "='"),
                    pcmk__s(ID(a_child), ""),
                    ((ID(a_child) == NULL)? "" : "'"));

            if (result == pcmk_ok) {
                result = tmp_result;
            }
        }
    }

    crm_trace("Finished handling update for <%s%s%s%s>", object_name,
              ((object_id == NULL)? "" : " " XML_ATTR_ID "='"),
              pcmk__s(object_id, ""),
              ((object_id == NULL)? "" : "'"));

    return result;
}

static int
add_cib_object(xmlNode * parent, xmlNode * new_obj)
{
    const char *object_name = NULL;
    const char *object_id = NULL;
    xmlNode *equiv_node = NULL;

    if ((parent == NULL) || (new_obj == NULL)) {
        return -EINVAL;
    }

    object_name = crm_element_name(new_obj);
    if (object_name == NULL) {
        return -EINVAL;
    }

    object_id = ID(new_obj);

    crm_trace("Processing creation of <%s%s%s%s>", object_name,
              ((object_id == NULL)? "" : " " XML_ATTR_ID "='"),
              pcmk__s(object_id, ""),
              ((object_id == NULL)? "" : "'"));

    if (object_id == NULL) {
        equiv_node = find_xml_node(parent, object_name, FALSE);
    } else {
        equiv_node = pcmk__xe_match(parent, object_name, XML_ATTR_ID,
                                    object_id);
    }
    if (equiv_node != NULL) {
        return -EEXIST;
    }

    return update_cib_object(parent, new_obj);
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
        xml_node = create_xml_node(failed, XML_FAIL_TAG_CIB);
        add_node_copy(xml_node, target);

        crm_xml_add(xml_node, XML_FAILCIB_ATTR_ID, ID(target));
        crm_xml_add(xml_node, XML_FAILCIB_ATTR_OBJTYPE,
                    (const char *) target->name);
        crm_xml_add(xml_node, XML_FAILCIB_ATTR_OP, operation);
        crm_xml_add(xml_node, XML_FAILCIB_ATTR_REASON, error_msg);

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
    if (pcmk__str_eq(XML_CIB_TAG_SECTION_ALL, section, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__str_eq(XML_TAG_CIB, section, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__xe_is(input, XML_TAG_CIB)) {
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

    failed = create_xml_node(NULL, XML_TAG_FAILED);

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

    if ((result == pcmk_ok) && xml_has_children(failed)) {
        result = -EINVAL;
    }

    if (result != pcmk_ok) {
        crm_log_xml_err(failed, "CIB Update failures");
        *answer = failed;

    } else {
        free_xml(failed);
    }

    return result;
}

int
cib_process_diff(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    const char *originator = NULL;

    if (req != NULL) {
        originator = crm_element_value(req, F_ORIG);
    }

    crm_trace("Processing \"%s\" event from %s%s",
              op, originator,
              (pcmk_is_set(options, cib_force_diff)? " (global update)" : ""));

    if (*result_cib != existing_cib) {
        free_xml(*result_cib);
    }
    *result_cib = copy_xml(existing_cib);

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
        *diff = diff_xml_object(last, next, FALSE);
    }

    if (*diff == NULL) {
        goto done;
    }

    crm_element_value_int(*diff, "format", &format);
    CRM_LOG_ASSERT(format == 1);

    xpathObj = xpath_search(*diff, "//" XML_CIB_TAG_CONFIGURATION);
    if (numXpathResults(xpathObj) > 0) {
        config_changes = true;
        goto done;
    }
    freeXpathObject(xpathObj);

    /*
     * Do not check XML_TAG_DIFF_ADDED "//" XML_TAG_CIB
     * This always contains every field and would produce a false positive
     * every time if the checked value existed
     */
    xpathObj = xpath_search(*diff, "//" XML_TAG_DIFF_REMOVED "//" XML_TAG_CIB);
    max = numXpathResults(xpathObj);

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *top = getXpathResult(xpathObj, lpc);

        if (crm_element_value(top, XML_ATTR_GENERATION) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, XML_ATTR_GENERATION_ADMIN) != NULL) {
            config_changes = true;
            goto done;
        }

        if (crm_element_value(top, XML_ATTR_VALIDATION) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, XML_ATTR_CRM_VERSION) != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, "remote-clear-port") != NULL) {
            config_changes = true;
            goto done;
        }
        if (crm_element_value(top, "remote-tls-port") != NULL) {
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
        xpathObj = xpath_search(existing_cib, section);
    } else {
        xpathObj = xpath_search(*result_cib, section);
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
            *answer = create_xml_node(NULL, "xpath-query");
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

            free_xml(match);
            if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_MODIFY, pcmk__str_none)) {
            if (update_xml_child(match, input) == FALSE) {
                rc = -ENXIO;
            } else if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_CREATE, pcmk__str_none)) {
            add_node_copy(match, input);
            break;

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_QUERY, pcmk__str_none)) {

            if (options & cib_no_children) {
                xmlNode *shallow = create_xml_node(*answer,
                                                   (const char *) match->name);

                copy_in_properties(shallow, match);

                if (*answer == NULL) {
                    *answer = shallow;
                }

            } else if (options & cib_xpath_address) {
                char *path = NULL;
                xmlNode *parent = match;

                while (parent && parent->type == XML_ELEMENT_NODE) {
                    const char *id = crm_element_value(parent, XML_ATTR_ID);
                    char *new_path = NULL;

                    if (id) {
                        new_path = crm_strdup_printf("/%s[@" XML_ATTR_ID "='%s']"
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
                    *answer = create_xml_node(NULL, "xpath-query");
                }
                parent = create_xml_node(*answer, "xpath-query-path");
                crm_xml_add(parent, XML_ATTR_ID, path);
                free(path);

            } else if (*answer) {
                add_node_copy(*answer, match);

            } else {
                *answer = match;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_REPLACE,
                                pcmk__str_none)) {
            xmlNode *parent = match->parent;

            free_xml(match);
            if (input != NULL) {
                add_node_copy(parent, input);
            }

            if ((options & cib_multiple) == 0) {
                break;
            }
        }
    }

    freeXpathObject(xpathObj);
    return rc;
}

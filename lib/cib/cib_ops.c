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
#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/cib/internal.h>

#include <crm/common/xml.h>

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
        PCMK__CIB_REQUEST_SYNC_TO_ALL, cib__op_sync_to_all,
        cib__op_attr_privileged
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ONE, cib__op_sync_to_one,
        cib__op_attr_privileged
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
cib__process_apply_patch(const char *op, int options, const char *section,
                         xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                         xmlNode **result_cib, xmlNode **answer)
{
    const bool force = pcmk__is_set(options, cib_force_diff);
    const char *originator = NULL;

    if (req != NULL) {
        originator = pcmk__xe_get(req, PCMK__XA_SRC);
    }

    pcmk__trace("Processing \"%s\" event from %s%s", op, originator,
                (force? " (global update)" : ""));

    if (*result_cib != existing_cib) {
        pcmk__xml_free(*result_cib);
    }
    *result_cib = pcmk__xml_copy(NULL, existing_cib);

    return xml_apply_patchset(*result_cib, input, TRUE);
}

static int
update_counter(xmlNode *xml_obj, const char *field, bool reset)
{
    char *new_value = NULL;
    char *old_value = NULL;
    int int_value = -1;

    if (!reset && pcmk__xe_get(xml_obj, field) != NULL) {
        old_value = pcmk__xe_get_copy(xml_obj, field);
    }
    if (old_value != NULL) {
        int_value = atoi(old_value);
        new_value = pcmk__itoa(++int_value);
    } else {
        new_value = pcmk__str_copy("1");
    }

    pcmk__trace("Update %s from %s to %s", field, pcmk__s(old_value, "unset"),
                new_value);
    pcmk__xe_set(xml_obj, field, new_value);

    free(new_value);
    free(old_value);

    return pcmk_ok;
}

int
cib__process_bump(const char *op, int options, const char *section,
                  xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                  xmlNode **result_cib, xmlNode **answer)
{
    int result = pcmk_ok;

    pcmk__trace("Processing %s for epoch='%s'", op,
                pcmk__s(pcmk__xe_get(existing_cib, PCMK_XA_EPOCH), ""));

    *answer = NULL;
    update_counter(*result_cib, PCMK_XA_EPOCH, false);

    return result;
}

static int
add_cib_object(xmlNode *parent, xmlNode *new_obj)
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
    return pcmk_ok;
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

int
cib__process_create(const char *op, int options, const char *section,
                    xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                    xmlNode **result_cib, xmlNode **answer)
{
    xmlNode *failed = NULL;
    int result = pcmk_ok;
    xmlNode *update_section = NULL;

    pcmk__trace("Processing %s for %s section", op,
                pcmk__s(section, "unspecified"));
    if (pcmk__str_eq(PCMK__XE_ALL, section, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__str_eq(section, PCMK_XE_CIB, pcmk__str_casei)) {
        section = NULL;

    } else if (pcmk__xe_is(input, PCMK_XE_CIB)) {
        section = NULL;
    }

    CRM_CHECK(strcmp(op, PCMK__CIB_REQUEST_CREATE) == 0, return -EINVAL);

    if (input == NULL) {
        pcmk__err("Cannot perform modification with no data");
        return -EINVAL;
    }

    if (section == NULL) {
        return cib__process_modify(op, options, section, req, input,
                                   existing_cib, result_cib, answer);
    }

    // @COMPAT Deprecated since 2.1.8
    failed = pcmk__xe_create(NULL, PCMK__XE_FAILED);

    update_section = pcmk_find_cib_element(*result_cib, section);
    if (pcmk__xe_is(input, section)) {
        xmlNode *a_child = NULL;

        for (a_child = pcmk__xml_first_child(input); a_child != NULL;
             a_child = pcmk__xml_next(a_child)) {

            result = add_cib_object(update_section, a_child);
            if (result != pcmk_ok) {
                update_results(failed, a_child, op, pcmk_legacy2rc(result));
                break;
            }
        }

    } else {
        result = add_cib_object(update_section, input);
        if (result != pcmk_ok) {
            update_results(failed, input, op, pcmk_legacy2rc(result));
        }
    }

    if ((result == pcmk_ok) && (failed->children != NULL)) {
        result = -EINVAL;
    }

    if (result != pcmk_ok) {
        pcmk__log_xml_err(failed, "CIB Update failures");
        *answer = failed;

    } else {
        pcmk__xml_free(failed);
    }

    return result;
}

/*!
 * \internal
 * \brief Query or modify a CIB
 *
 * \param[in]     op            PCMK__CIB_REQUEST_* operation to be performed
 * \param[in]     options       Flag set of \c cib_call_options
 * \param[in]     section       XPath to query or modify
 * \param[in]     req           unused
 * \param[in]     input         Portion of CIB to modify (used with
 *                              PCMK__CIB_REQUEST_CREATE,
 *                              PCMK__CIB_REQUEST_MODIFY, and
 *                              PCMK__CIB_REQUEST_REPLACE)
 * \param[in,out] existing_cib  Input CIB (used with PCMK__CIB_REQUEST_QUERY)
 * \param[in,out] result_cib    CIB copy to make changes in (used with
 *                              PCMK__CIB_REQUEST_CREATE,
 *                              PCMK__CIB_REQUEST_MODIFY,
 *                              PCMK__CIB_REQUEST_DELETE, and
 *                              PCMK__CIB_REQUEST_REPLACE)
 * \param[out]    answer        Query result (used with PCMK__CIB_REQUEST_QUERY)
 *
 * \return Legacy Pacemaker return code
 */
static int
process_xpath(const char *op, int options, const char *section,
              const xmlNode *req, xmlNode *input, xmlNode *existing_cib,
              xmlNode **result_cib, xmlNode **answer)
{
    int num_results = 0;
    int rc = pcmk_ok;
    bool is_query = pcmk__str_eq(op, PCMK__CIB_REQUEST_QUERY, pcmk__str_none);
    bool delete_multiple = pcmk__is_set(options, cib_multiple)
                           && pcmk__str_eq(op, PCMK__CIB_REQUEST_DELETE,
                                           pcmk__str_none);
    xmlXPathObject *xpathObj = NULL;

    pcmk__trace("Processing \"%s\" event", op);

    if (is_query) {
        xpathObj = pcmk__xpath_search(existing_cib->doc, section);
    } else {
        xpathObj = pcmk__xpath_search((*result_cib)->doc, section);
    }

    num_results = pcmk__xpath_num_results(xpathObj);
    if (num_results == 0) {
        if (pcmk__str_eq(op, PCMK__CIB_REQUEST_DELETE, pcmk__str_none)) {
            pcmk__debug("%s was already removed", section);

        } else {
            pcmk__debug("%s: %s does not exist", op, section);
            rc = -ENXIO;
        }
        goto done;
    }

    if (is_query && (num_results > 1)) {
        *answer = pcmk__xe_create(NULL, PCMK__XE_XPATH_QUERY);
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
        if (delete_multiple) {
            match = pcmk__xpath_result(xpathObj, num_results - 1 - i);
        } else {
            match = pcmk__xpath_result(xpathObj, i);
        }

        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        pcmk__debug("Processing %s op for %s with %s", op, section, path);
        free(path);

        if (pcmk__str_eq(op, PCMK__CIB_REQUEST_DELETE, pcmk__str_none)) {
            if (match == *result_cib) {
                /* Attempting to delete the whole "/cib" */
                pcmk__warn("Cannot perform %s for %s: The xpath is addressing "
                           "the whole /cib",
                           op, section);
                rc = -EINVAL;
                break;
            }

            pcmk__xml_free(match);
            if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (pcmk__str_eq(op, PCMK__CIB_REQUEST_MODIFY, pcmk__str_none)) {
            uint32_t flags = pcmk__xaf_none;

            if (pcmk__is_set(options, cib_score_update)) {
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
            if (match->type != XML_ELEMENT_NODE
                && pcmk__is_set(options, cib_xpath_address)) {
               /* @COMPAT cib_xpath_address is deprecated since 3.0.2
                * For a non-element, handle cib_xpath_address with its
                * corresponding element.
                */
               match = pcmk__xpath_match_element(match);
               if (match == NULL) {
                   continue;
               }

            } else if (match->type != XML_ELEMENT_NODE) {
                xmlNode *match_element = pcmk__xpath_match_element(match);
                xmlNode *brief = NULL;

                if (match_element == NULL) {
                    continue;
                }

                // Create an element with the corresponding element name
                brief = pcmk__xe_create(*answer,
                                        (const char *) match_element->name);
                pcmk__xe_set(brief, PCMK_XA_ID, pcmk__xe_id(match_element));
                pcmk__xml_copy(brief, match);

                if (*answer == NULL) {
                    *answer = brief;
                }

                continue;
            }

            if (options & cib_xpath_address) {
                // @COMPAT cib_xpath_address is deprecated since 3.0.2
                char *path = NULL;
                xmlNode *parent = match;

                while (parent && parent->type == XML_ELEMENT_NODE) {
                    const char *id = pcmk__xe_get(parent, PCMK_XA_ID);
                    char *new_path = NULL;

                    if (id) {
                        new_path =
                            pcmk__assert_asprintf("/%s[@" PCMK_XA_ID "='%s']%s",
                                                  parent->name, id,
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

            } else if (options & cib_no_children) {
                xmlNode *shallow = pcmk__xe_create(*answer,
                                                   (const char *) match->name);

                pcmk__xe_copy_attrs(shallow, match, pcmk__xaf_none);

                if (*answer == NULL) {
                    *answer = shallow;
                }

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

done:
    xmlXPathFreeObject(xpathObj);
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

int
cib__process_delete(const char *op, int options, const char *section,
                    xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                    xmlNode **result_cib, xmlNode **answer)
{
    xmlNode *obj_root = NULL;

    pcmk__trace("Processing \"%s\" event", op);

    if (options & cib_xpath) {
        return process_xpath(op, options, section, req, input, existing_cib,
                             result_cib, answer);
    }

    if (input == NULL) {
        pcmk__err("Cannot perform modification with no data");
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
cib__process_erase(const char *op, int options, const char *section,
                   xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                   xmlNode **result_cib, xmlNode **answer)
{
    int result = pcmk_ok;

    pcmk__trace("Processing \"%s\" event", op);

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
cib__process_modify(const char *op, int options, const char *section,
                    xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                    xmlNode **result_cib, xmlNode **answer)
{
    xmlNode *obj_root = NULL;
    uint32_t flags = pcmk__xaf_none;

    pcmk__trace("Processing \"%s\" event", op);

    if (options & cib_xpath) {
        return process_xpath(op, options, section, req, input, existing_cib,
                             result_cib, answer);
    }

    if (input == NULL) {
        pcmk__err("Cannot perform modification with no data");
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
        process_xpath(PCMK__CIB_REQUEST_CREATE, 0, path, NULL, tmp_section,
                      NULL, result_cib, answer);
        pcmk__xml_free(tmp_section);

        obj_root = pcmk_find_cib_element(*result_cib, section);
    }

    CRM_CHECK(obj_root != NULL, return -EINVAL);

    if (pcmk__is_set(options, cib_score_update)) {
        flags |= pcmk__xaf_score_update;
    }

    if (pcmk__xe_update_match(obj_root, input, flags) != pcmk_rc_ok) {
        if (options & cib_can_create) {
            pcmk__xml_copy(obj_root, input);
        } else {
            return -ENXIO;
        }
    }

    return pcmk_ok;
}

int
cib__process_query(const char *op, int options, const char *section,
                   xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                   xmlNode **result_cib, xmlNode **answer)
{
    xmlNode *obj_root = NULL;
    int result = pcmk_ok;

    pcmk__trace("Processing %s for %s section", op,
                pcmk__s(section, "unspecified"));

    if (options & cib_xpath) {
        return process_xpath(op, options, section, req, input, existing_cib,
                             result_cib, answer);
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
        pcmk__err("Error creating query response");
        result = -ENOMSG;
    }

    return result;
}

int
cib__process_replace(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer)
{
    int result = pcmk_ok;

    pcmk__trace("Processing %s for %s section", op,
                pcmk__s(section, "unspecified"));

    if (options & cib_xpath) {
        return process_xpath(op, options, section, req, input, existing_cib,
                             result_cib, answer);
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
        const char *peer = pcmk__xe_get(req, PCMK__XA_SRC);
        const char *digest = pcmk__xe_get(req, PCMK_XA_DIGEST);

        if (digest) {
            char *digest_verify = pcmk__digest_xml(input, true);

            if (!pcmk__str_eq(digest_verify, digest, pcmk__str_casei)) {
                pcmk__err("Digest mis-match on replace from %s: %s vs. %s "
                          "(expected)",
                          peer, digest_verify, digest);
                reason = "digest mismatch";

            } else {
                pcmk__info("Digest matched on replace from %s: %s", peer,
                           digest);
            }
            free(digest_verify);

        } else {
            pcmk__trace("No digest to verify");
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
            pcmk__info("Replacement %d.%d.%d from %s not applied to %d.%d.%d: "
                       "current %s is greater than the replacement",
                       replace_admin_epoch, replace_epoch,
                       replace_updates, peer, admin_epoch, epoch, updates,
                       reason);
            result = -pcmk_err_old_data;
        } else {
            pcmk__info("Replaced %d.%d.%d with %d.%d.%d from %s",
                       admin_epoch, epoch, updates,
                       replace_admin_epoch, replace_epoch, replace_updates,
                       peer);
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
            pcmk__trace("No matching object to replace");
        }
    }

    return result;
}

int
cib__process_upgrade(const char *op, int options, const char *section,
                     xmlNode *req, xmlNode *input, xmlNode *existing_cib,
                     xmlNode **result_cib, xmlNode **answer)
{
    int rc = 0;
    const char *max_schema = pcmk__xe_get(req, PCMK__XA_CIB_SCHEMA_MAX);
    const char *original_schema = NULL;
    const char *new_schema = NULL;

    *answer = NULL;
    pcmk__trace("Processing \"%s\" event with max=%s", op, max_schema);

    original_schema = pcmk__xe_get(existing_cib, PCMK_XA_VALIDATE_WITH);
    rc = pcmk__update_schema(result_cib, max_schema, true,
                             !pcmk__is_set(options, cib_verbose));
    rc = pcmk_rc2legacy(rc);
    new_schema = pcmk__xe_get(*result_cib, PCMK_XA_VALIDATE_WITH);

    if (pcmk__cmp_schemas_by_name(new_schema, original_schema) > 0) {
        update_counter(*result_cib, PCMK_XA_ADMIN_EPOCH, false);
        update_counter(*result_cib, PCMK_XA_EPOCH, true);
        update_counter(*result_cib, PCMK_XA_NUM_UPDATES, true);
        return pcmk_ok;
    }

    return rc;
}

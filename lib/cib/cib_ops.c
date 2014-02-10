/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>

#include <crm/common/xml.h>

int
cib_process_query(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *obj_root = NULL;
    int result = pcmk_ok;

    crm_trace("Processing \"%s\" event for section=%s", op, crm_str(section));

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    CRM_CHECK(*answer == NULL, free_xml(*answer));
    *answer = NULL;

    if (safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
        section = NULL;
    }

    obj_root = get_object_root(section, existing_cib);

    if (obj_root == NULL) {
        result = -ENXIO;

    } else if (options & cib_no_children) {
        const char *tag = TYPE(obj_root);
        xmlNode *shallow = create_xml_node(*answer, tag);

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

int
cib_process_erase(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int result = pcmk_ok;

    crm_trace("Processing \"%s\" event", op);
    *answer = NULL;
    free_xml(*result_cib);
    *result_cib = createEmptyCib();

    copy_in_properties(*result_cib, existing_cib);
    cib_update_counter(*result_cib, XML_ATTR_GENERATION, FALSE);

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

    const char *value = crm_element_value(existing_cib, XML_ATTR_VALIDATION);;

    *answer = NULL;
    crm_trace("Processing \"%s\" event", op);

    if (value != NULL) {
        current_version = get_schema_version(value);
    }

    rc = update_validation(result_cib, &new_version, TRUE, TRUE);
    if (new_version > current_version) {
        return pcmk_ok;
    }

    return rc;
}

int
cib_process_bump(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int result = pcmk_ok;

    crm_trace("Processing \"%s\" event for epoch=%s",
              op, crm_str(crm_element_value(existing_cib, XML_ATTR_GENERATION)));

    *answer = NULL;
    cib_update_counter(*result_cib, XML_ATTR_GENERATION, FALSE);

    return result;
}

int
cib_update_counter(xmlNode * xml_obj, const char *field, gboolean reset)
{
    char *new_value = NULL;
    char *old_value = NULL;
    int int_value = -1;

    if (reset == FALSE && crm_element_value(xml_obj, field) != NULL) {
        old_value = crm_element_value_copy(xml_obj, field);
    }
    if (old_value != NULL) {
        new_value = calloc(1, 128);
        int_value = atoi(old_value);
        sprintf(new_value, "%d", ++int_value);
    } else {
        new_value = strdup("1");
    }

    crm_trace("%s %d(%s)->%s", field, int_value, crm_str(old_value), crm_str(new_value));
    crm_xml_add(xml_obj, field, new_value);

    free(new_value);
    free(old_value);

    return pcmk_ok;
}

int
cib_process_replace(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer)
{
    const char *tag = NULL;
    int result = pcmk_ok;

    crm_trace("Processing \"%s\" event for section=%s", op, crm_str(section));

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    *answer = NULL;

    if (input == NULL) {
        return -EINVAL;
    }

    tag = crm_element_name(input);

    if (safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
        section = NULL;

    } else if (safe_str_eq(tag, section)) {
        section = NULL;
    }

    if (safe_str_eq(tag, XML_TAG_CIB)) {
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

            if (safe_str_neq(digest_verify, digest)) {
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
            crm_warn("Replacement %d.%d.%d from %s not applied to %d.%d.%d:"
                     " current %s is greater than the replacement",
                     replace_admin_epoch, replace_epoch,
                     replace_updates, peer, admin_epoch, epoch, updates, reason);
            result = -pcmk_err_old_data;
        } else {
            crm_info("Replaced %d.%d.%d with %d.%d.%d from %s",
                     admin_epoch, epoch, updates,
                     replace_admin_epoch, replace_epoch, replace_updates, peer);
        }

        free_xml(*result_cib);
        *result_cib = copy_xml(input);

    } else {
        xmlNode *obj_root = NULL;
        gboolean ok = TRUE;

        obj_root = get_object_root(section, *result_cib);
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

    obj_root = get_object_root(section, *result_cib);
    if(safe_str_eq(crm_element_name(input), section)) {
        xmlNode *child = NULL;
        for(child = __xml_first_child(input); child; child = __xml_next(child)) {
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

    obj_root = get_object_root(section, *result_cib);
    if (obj_root == NULL) {
        xmlNode *tmp_section = NULL;
        const char *path = get_object_parent(section);

        if (path == NULL) {
            return -EINVAL;
        }

        tmp_section = create_xml_node(NULL, section);
        cib_process_xpath(CIB_OP_CREATE, 0, path, NULL, tmp_section, NULL, result_cib, answer);
        free_xml(tmp_section);

        obj_root = get_object_root(section, *result_cib);
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
            crm_debug("Destroying %s", (char *)xmlGetNodePath(match));
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
    crm_trace("Processing: <%s id=%s>", crm_str(object_name), crm_str(object_id));

    if (object_id == NULL) {
        /*  placeholder object */
        target = find_xml_node(parent, object_name, FALSE);

    } else {
        target = find_entity(parent, object_name, object_id);
    }

    if (target == NULL) {
        target = create_xml_node(parent, object_name);
    }

    crm_trace("Found node <%s id=%s> to update", crm_str(object_name), crm_str(object_id));

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

                replace_item = calloc(1, lpc - last + 1);
                memcpy(replace_item, replace + last, lpc - last);

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

    crm_trace("Processing children of <%s id=%s>", crm_str(object_name), crm_str(object_id));

    for (a_child = __xml_first_child(update); a_child != NULL; a_child = __xml_next(a_child)) {
        int tmp_result = 0;

        crm_trace("Updating child <%s id=%s>", crm_element_name(a_child), ID(a_child));

        tmp_result = update_cib_object(target, a_child);

        /*  only the first error is likely to be interesting */
        if (tmp_result != pcmk_ok) {
            crm_err("Error updating child <%s id=%s>", crm_element_name(a_child), ID(a_child));

            if (result == pcmk_ok) {
                result = tmp_result;
            }
        }
    }

    crm_trace("Finished with <%s id=%s>", crm_str(object_name), crm_str(object_id));

    return result;
}

static int
add_cib_object(xmlNode * parent, xmlNode * new_obj)
{
    int result = pcmk_ok;
    const char *object_name = NULL;
    const char *object_id = NULL;
    xmlNode *equiv_node = NULL;

    if (new_obj != NULL) {
        object_name = crm_element_name(new_obj);
    }
    object_id = crm_element_value(new_obj, XML_ATTR_ID);

    crm_trace("Processing: <%s id=%s>", crm_str(object_name), crm_str(object_id));

    if (new_obj == NULL || object_name == NULL) {
        result = -EINVAL;

    } else if (parent == NULL) {
        result = -EINVAL;

    } else if (object_id == NULL) {
        /*  placeholder object */
        equiv_node = find_xml_node(parent, object_name, FALSE);

    } else {
        equiv_node = find_entity(parent, object_name, object_id);
    }

    if (result != pcmk_ok) {
        ;                       /* do nothing */

    } else if (equiv_node != NULL) {
        result = -ENOTUNIQ;

    } else {
        result = update_cib_object(parent, new_obj);
    }

    return result;
}

int
cib_process_create(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *failed = NULL;
    int result = pcmk_ok;
    xmlNode *update_section = NULL;

    crm_trace("Processing \"%s\" event for section=%s", op, crm_str(section));
    if (safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
        section = NULL;

    } else if (safe_str_eq(XML_TAG_CIB, section)) {
        section = NULL;

    } else if (safe_str_eq(crm_element_name(input), XML_TAG_CIB)) {
        section = NULL;
    }

    CRM_CHECK(strcasecmp(CIB_OP_CREATE, op) == 0, return -EINVAL);

    if (input == NULL) {
        crm_err("Cannot perform modification with no data");
        return -EINVAL;
    }

    if (section == NULL) {
        return cib_process_modify(op, options, section, req, input, existing_cib, result_cib,
                                  answer);
    }

    failed = create_xml_node(NULL, XML_TAG_FAILED);

    update_section = get_object_root(section, *result_cib);
    if (safe_str_eq(crm_element_name(input), section)) {
        xmlNode *a_child = NULL;

        for (a_child = __xml_first_child(input); a_child != NULL; a_child = __xml_next(a_child)) {
            result = add_cib_object(update_section, a_child);
            if (update_results(failed, a_child, op, result)) {
                break;
            }
        }

    } else {
        result = add_cib_object(update_section, input);
        update_results(failed, input, op, result);
    }

    if (xml_has_children(failed)) {
        CRM_CHECK(result != pcmk_ok, result = -EINVAL);
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

    crm_trace("Processing \"%s\" event from %s %s",
              op, originator, is_set(options, cib_force_diff)?"(global update)":"");

    free_xml(*result_cib);
    *result_cib = copy_xml(existing_cib);
    return xml_apply_patchset(*result_cib, input, TRUE);
}

gboolean
cib_config_changed(xmlNode * last, xmlNode * next, xmlNode ** diff)
{
    int lpc = 0, max = 0;
    gboolean config_changes = FALSE;
    xmlXPathObject *xpathObj = NULL;

    CRM_ASSERT(diff != NULL);

    if (*diff == NULL && last != NULL && next != NULL) {
        *diff = diff_xml_object(last, next, FALSE);
    }

    if (*diff == NULL) {
        goto done;
    }

    xpathObj = xpath_search(*diff, "//" XML_CIB_TAG_CONFIGURATION);
    if (numXpathResults(xpathObj) > 0) {
        config_changes = TRUE;
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
            config_changes = TRUE;
            goto done;
        }
        if (crm_element_value(top, XML_ATTR_GENERATION_ADMIN) != NULL) {
            config_changes = TRUE;
            goto done;
        }

        if (crm_element_value(top, XML_ATTR_VALIDATION) != NULL) {
            config_changes = TRUE;
            goto done;
        }
        if (crm_element_value(top, XML_ATTR_CRM_VERSION) != NULL) {
            config_changes = TRUE;
            goto done;
        }
        if (crm_element_value(top, "remote-clear-port") != NULL) {
            config_changes = TRUE;
            goto done;
        }
        if (crm_element_value(top, "remote-tls-port") != NULL) {
            config_changes = TRUE;
            goto done;
        }
    }

  done:
    freeXpathObject(xpathObj);
    return config_changes;
}

int
cib_process_xpath(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int lpc = 0;
    int max = 0;
    int rc = pcmk_ok;
    gboolean is_query = safe_str_eq(op, CIB_OP_QUERY);

    xmlXPathObjectPtr xpathObj = NULL;

    crm_trace("Processing \"%s\" event", op);

    if (is_query) {
        xpathObj = xpath_search(existing_cib, section);
    } else {
        xpathObj = xpath_search(*result_cib, section);
    }

    max = numXpathResults(xpathObj);

    if (max < 1 && safe_str_eq(op, CIB_OP_DELETE)) {
        crm_debug("%s was already removed", section);

    } else if (max < 1) {
        crm_debug("%s: %s does not exist", op, section);
        rc = -ENXIO;

    } else if (is_query) {
        if (max > 1) {
            *answer = create_xml_node(NULL, "xpath-query");
        }
    }

    for (lpc = 0; lpc < max; lpc++) {
        xmlChar *path = NULL;
        xmlNode *match = getXpathResult(xpathObj, lpc);

        if (match == NULL) {
            continue;
        }

        path = xmlGetNodePath(match);
        crm_debug("Processing %s op for %s (%s)", op, section, path);
        free(path);

        if (safe_str_eq(op, CIB_OP_DELETE)) {
            free_xml(match);
            if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (safe_str_eq(op, CIB_OP_MODIFY)) {
            if (update_xml_child(match, input) == FALSE) {
                rc = -ENXIO;
            } else if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (safe_str_eq(op, CIB_OP_CREATE)) {
            add_node_copy(match, input);
            break;

        } else if (safe_str_eq(op, CIB_OP_QUERY)) {

            if (options & cib_no_children) {
                const char *tag = TYPE(match);
                xmlNode *shallow = create_xml_node(*answer, tag);

                copy_in_properties(shallow, match);

                if (*answer == NULL) {
                    *answer = shallow;
                }

            } else if (options & cib_xpath_address) {

                int path_len = 0;
                char *path = NULL;
                xmlNode *parent = match;

                while (parent && parent->type == XML_ELEMENT_NODE) {
                    int extra = 1;
                    char *new_path = NULL;
                    const char *id = crm_element_value(parent, XML_ATTR_ID);

                    extra += strlen((const char *)parent->name);
                    if (id) {
                        extra += 8;     /* [@id=""] */
                        extra += strlen(id);
                    }

                    path_len += extra;
                    new_path = malloc(path_len + 1);
                    if(new_path == NULL) {
                        break;

                    } else if (id) {
                        snprintf(new_path, path_len + 1, "/%s[@id='%s']%s", parent->name, id,
                                 path ? path : "");
                    } else {
                        snprintf(new_path, path_len + 1, "/%s%s", parent->name, path ? path : "");
                    }
                    free(path);
                    path = new_path;
                    parent = parent->parent;
                }
                crm_trace("Got: %s\n", path);

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

        } else if (safe_str_eq(op, CIB_OP_REPLACE)) {
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

/* remove this function */
gboolean
update_results(xmlNode * failed, xmlNode * target, const char *operation, int return_code)
{
    xmlNode *xml_node = NULL;
    gboolean was_error = FALSE;
    const char *error_msg = NULL;

    if (return_code != pcmk_ok) {
        error_msg = pcmk_strerror(return_code);

        was_error = TRUE;
        xml_node = create_xml_node(failed, XML_FAIL_TAG_CIB);
        add_node_copy(xml_node, target);

        crm_xml_add(xml_node, XML_FAILCIB_ATTR_ID, ID(target));
        crm_xml_add(xml_node, XML_FAILCIB_ATTR_OBJTYPE, TYPE(target));
        crm_xml_add(xml_node, XML_FAILCIB_ATTR_OP, operation);
        crm_xml_add(xml_node, XML_FAILCIB_ATTR_REASON, error_msg);

        crm_warn("Action %s failed: %s (cde=%d)", operation, error_msg, return_code);
    }

    return was_error;
}

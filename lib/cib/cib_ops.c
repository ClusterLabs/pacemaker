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
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/msg.h>
#include <crm/common/xml.h>

enum cib_errors
cib_process_query(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *obj_root = NULL;
    enum cib_errors result = cib_ok;

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
        result = cib_NOTEXISTS;

    } else {
        *answer = obj_root;
    }

    if (result == cib_ok && *answer == NULL) {
        crm_err("Error creating query response");
        result = cib_output_data;
    }

    return result;
}

enum cib_errors
cib_process_erase(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    enum cib_errors result = cib_ok;

    crm_trace("Processing \"%s\" event", op);
    *answer = NULL;
    free_xml(*result_cib);
    *result_cib = createEmptyCib();

    copy_in_properties(*result_cib, existing_cib);
    cib_update_counter(*result_cib, XML_ATTR_GENERATION, FALSE);

    return result;
}

enum cib_errors
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
        return cib_ok;
    }

    return rc;
}

enum cib_errors
cib_process_bump(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    enum cib_errors result = cib_ok;

    crm_trace("Processing \"%s\" event for epoch=%s",
              op, crm_str(crm_element_value(existing_cib, XML_ATTR_GENERATION)));

    *answer = NULL;
    cib_update_counter(*result_cib, XML_ATTR_GENERATION, FALSE);

    return result;
}

enum cib_errors
cib_update_counter(xmlNode * xml_obj, const char *field, gboolean reset)
{
    char *new_value = NULL;
    char *old_value = NULL;
    int int_value = -1;

    if (reset == FALSE && crm_element_value(xml_obj, field) != NULL) {
        old_value = crm_element_value_copy(xml_obj, field);
    }
    if (old_value != NULL) {
        crm_malloc0(new_value, 128);
        int_value = atoi(old_value);
        sprintf(new_value, "%d", ++int_value);
    } else {
        new_value = crm_strdup("1");
    }

    crm_trace("%s %d(%s)->%s", field, int_value, crm_str(old_value), crm_str(new_value));
    crm_xml_add(xml_obj, field, new_value);

    crm_free(new_value);
    crm_free(old_value);

    return cib_ok;
}

enum cib_errors
cib_process_replace(const char *op, int options, const char *section, xmlNode * req,
                    xmlNode * input, xmlNode * existing_cib, xmlNode ** result_cib,
                    xmlNode ** answer)
{
    const char *tag = NULL;
    gboolean verbose = FALSE;
    enum cib_errors result = cib_ok;

    crm_trace("Processing \"%s\" event for section=%s", op, crm_str(section));

    if (options & cib_xpath) {
        return cib_process_xpath(op, options, section, req, input,
                                 existing_cib, result_cib, answer);
    }

    *answer = NULL;

    if (input == NULL) {
        return cib_NOOBJECT;
    }

    tag = crm_element_name(input);

    if (options & cib_verbose) {
        verbose = TRUE;
    }
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
            crm_warn("Replacement %d.%d.%d not applied to %d.%d.%d:"
                     " current %s is greater than the replacement",
                     replace_admin_epoch, replace_epoch,
                     replace_updates, admin_epoch, epoch, updates, reason);
            result = cib_old_data;
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
            result = cib_NOTEXISTS;
        }
    }

    return result;
}

enum cib_errors
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
        return cib_NOOBJECT;
    }

    obj_root = get_object_root(section, *result_cib);

    crm_validate_data(input);
    crm_validate_data(*result_cib);

    if (replace_xml_child(NULL, obj_root, input, TRUE) == FALSE) {
        crm_trace("No matching object to delete");
    }

    return cib_ok;
}

enum cib_errors
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
        return cib_NOOBJECT;
    }

    obj_root = get_object_root(section, *result_cib);

    crm_validate_data(input);
    crm_validate_data(*result_cib);

    if (obj_root == NULL) {
        xmlNode *tmp_section = NULL;
        const char *path = get_object_parent(section);

        if (path == NULL) {
            return cib_bad_section;
        }

        tmp_section = create_xml_node(NULL, section);
        cib_process_xpath(CIB_OP_CREATE, 0, path, NULL, tmp_section, NULL, result_cib, answer);
        free_xml(tmp_section);

        obj_root = get_object_root(section, *result_cib);
    }

    CRM_CHECK(obj_root != NULL, return cib_unknown);

    if (update_xml_child(obj_root, input) == FALSE) {
        if (options & cib_can_create) {
            add_node_copy(obj_root, input);
        } else {
            return cib_NOTEXISTS;
        }
    }

    return cib_ok;
}

static int
update_cib_object(xmlNode * parent, xmlNode * update)
{
    int result = cib_ok;
    xmlNode *target = NULL;
    xmlNode *a_child = NULL;
    const char *replace = NULL;
    const char *object_id = NULL;
    const char *object_name = NULL;

    CRM_CHECK(update != NULL, return cib_NOOBJECT);
    CRM_CHECK(parent != NULL, return cib_NOPARENT);

    object_name = crm_element_name(update);
    CRM_CHECK(object_name != NULL, return cib_NOOBJECT);

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

                crm_malloc0(replace_item, lpc - last + 1);
                strncpy(replace_item, replace + last, lpc - last);

                remove = find_xml_node(target, replace_item, FALSE);
                if (remove != NULL) {
                    crm_trace("Replacing node <%s> in <%s>",
                              replace_item, crm_element_name(target));
                    zap_xml_from_parent(target, remove);
                }
                crm_free(replace_item);
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
        if (tmp_result != cib_ok) {
            crm_err("Error updating child <%s id=%s>", crm_element_name(a_child), ID(a_child));

            if (result == cib_ok) {
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
    enum cib_errors result = cib_ok;
    const char *object_name = NULL;
    const char *object_id = NULL;
    xmlNode *equiv_node = NULL;

    if (new_obj != NULL) {
        object_name = crm_element_name(new_obj);
    }
    object_id = crm_element_value(new_obj, XML_ATTR_ID);

    crm_trace("Processing: <%s id=%s>", crm_str(object_name), crm_str(object_id));

    if (new_obj == NULL || object_name == NULL) {
        result = cib_NOOBJECT;

    } else if (parent == NULL) {
        result = cib_NOPARENT;

    } else if (object_id == NULL) {
        /*  placeholder object */
        equiv_node = find_xml_node(parent, object_name, FALSE);

    } else {
        equiv_node = find_entity(parent, object_name, object_id);
    }

    if (result != cib_ok) {
        ;                       /* do nothing */

    } else if (equiv_node != NULL) {
        result = cib_EXISTS;

    } else {
        result = update_cib_object(parent, new_obj);
    }

    return result;
}

enum cib_errors
cib_process_create(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                   xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    xmlNode *failed = NULL;
    enum cib_errors result = cib_ok;
    xmlNode *update_section = NULL;

    crm_trace("Processing \"%s\" event for section=%s", op, crm_str(section));
    if (safe_str_eq(XML_CIB_TAG_SECTION_ALL, section)) {
        section = NULL;

    } else if (safe_str_eq(XML_TAG_CIB, section)) {
        section = NULL;

    } else if (safe_str_eq(crm_element_name(input), XML_TAG_CIB)) {
        section = NULL;
    }

    CRM_CHECK(strcasecmp(CIB_OP_CREATE, op) == 0, return cib_operation);

    if (input == NULL) {
        crm_err("Cannot perform modification with no data");
        return cib_NOOBJECT;
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
        CRM_CHECK(result != cib_ok, result = cib_unknown);
    }

    if (result != cib_ok) {
        crm_log_xml_err(failed, "CIB Update failures");
        *answer = failed;

    } else {
        free_xml(failed);
    }

    return result;
}

enum cib_errors
cib_process_diff(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                 xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    unsigned int log_level = LOG_DEBUG;
    const char *reason = NULL;
    gboolean apply_diff = TRUE;
    enum cib_errors result = cib_ok;

    int this_updates = 0;
    int this_epoch = 0;
    int this_admin_epoch = 0;

    int diff_add_updates = 0;
    int diff_add_epoch = 0;
    int diff_add_admin_epoch = 0;

    int diff_del_updates = 0;
    int diff_del_epoch = 0;
    int diff_del_admin_epoch = 0;

    const char *originator = crm_element_value(req, F_ORIG);
    crm_trace("Processing \"%s\" event", op);

    cib_diff_version_details(input,
                             &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                             &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

    crm_element_value_int(existing_cib, XML_ATTR_GENERATION, &this_epoch);
    crm_element_value_int(existing_cib, XML_ATTR_NUMUPDATES, &this_updates);
    crm_element_value_int(existing_cib, XML_ATTR_GENERATION_ADMIN, &this_admin_epoch);

    if (this_epoch < 0) {
        this_epoch = 0;
    }
    if (this_updates < 0) {
        this_updates = 0;
    }
    if (this_admin_epoch < 0) {
        this_admin_epoch = 0;
    }

    if (diff_del_admin_epoch == diff_add_admin_epoch
        && diff_del_epoch == diff_add_epoch && diff_del_updates == diff_add_updates) {
        if (options & cib_force_diff) {
            apply_diff = FALSE;
            log_level = LOG_ERR;
            reason = "+ and - versions in the diff did not change in global update";
            crm_log_xml_warn(input, "Bad global update");

        } else if (diff_add_admin_epoch == -1 && diff_add_epoch == -1 && diff_add_updates == -1) {
            diff_add_epoch = this_epoch;
            diff_add_updates = this_updates + 1;
            diff_add_admin_epoch = this_admin_epoch;
            diff_del_epoch = this_epoch;
            diff_del_updates = this_updates;
            diff_del_admin_epoch = this_admin_epoch;

        } else {
            apply_diff = FALSE;
            log_level = LOG_ERR;
            reason = "+ and - versions in the diff did not change";
            log_cib_diff(LOG_ERR, input, __FUNCTION__);
        }
    }

    if (apply_diff && diff_del_admin_epoch > this_admin_epoch) {
        result = cib_diff_resync;
        apply_diff = FALSE;
        log_level = LOG_INFO;
        reason = "current \"" XML_ATTR_GENERATION_ADMIN "\" is less than required";

    } else if (apply_diff && diff_del_admin_epoch < this_admin_epoch) {
        apply_diff = FALSE;
        log_level = LOG_WARNING;
        reason = "current \"" XML_ATTR_GENERATION_ADMIN "\" is greater than required";

    } else if (apply_diff && diff_del_epoch > this_epoch) {
        result = cib_diff_resync;
        apply_diff = FALSE;
        log_level = LOG_INFO;
        reason = "current \"" XML_ATTR_GENERATION "\" is less than required";

    } else if (apply_diff && diff_del_epoch < this_epoch) {
        apply_diff = FALSE;
        log_level = LOG_WARNING;
        reason = "current \"" XML_ATTR_GENERATION "\" is greater than required";

    } else if (apply_diff && diff_del_updates > this_updates) {
        result = cib_diff_resync;
        apply_diff = FALSE;
        log_level = LOG_INFO;
        reason = "current \"" XML_ATTR_NUMUPDATES "\" is less than required";

    } else if (apply_diff && diff_del_updates < this_updates) {
        apply_diff = FALSE;
        log_level = LOG_WARNING;
        reason = "current \"" XML_ATTR_NUMUPDATES "\" is greater than required";
    }

    if (apply_diff) {
        free_xml(*result_cib);
        *result_cib = NULL;
        if (apply_xml_diff(existing_cib, input, result_cib) == FALSE) {
            log_level = LOG_NOTICE;
            reason = "Failed application of an update diff";

            if (options & cib_force_diff) {
                result = cib_diff_resync;
            }
        }
    }

    if (reason != NULL) {
        do_crm_log(log_level,
                   "Diff %d.%d.%d -> %d.%d.%d from %s not applied to %d.%d.%d: %s",
                   diff_del_admin_epoch, diff_del_epoch, diff_del_updates,
                   diff_add_admin_epoch, diff_add_epoch, diff_add_updates,
                   originator?originator:"local", this_admin_epoch, this_epoch, this_updates, reason);

        crm_log_xml_trace(input, "Discarded diff");
        if (result == cib_ok) {
            result = cib_diff_failed;
        }

    } else if (apply_diff) {
        crm_trace("Diff %d.%d.%d -> %d.%d.%d from %s was applied to %d.%d.%d",
                  diff_del_admin_epoch, diff_del_epoch, diff_del_updates,
                  diff_add_admin_epoch, diff_add_epoch, diff_add_updates,
                  originator?originator:"local", this_admin_epoch, this_epoch, this_updates);

    }
    return result;
}

gboolean
apply_cib_diff(xmlNode * old, xmlNode * diff, xmlNode ** new)
{
    gboolean result = TRUE;
    const char *value = NULL;

    int this_updates = 0;
    int this_epoch = 0;
    int this_admin_epoch = 0;

    int diff_add_updates = 0;
    int diff_add_epoch = 0;
    int diff_add_admin_epoch = 0;

    int diff_del_updates = 0;
    int diff_del_epoch = 0;
    int diff_del_admin_epoch = 0;

    CRM_CHECK(diff != NULL, return FALSE);
    CRM_CHECK(old != NULL, return FALSE);

    value = crm_element_value(old, XML_ATTR_GENERATION_ADMIN);
    this_admin_epoch = crm_parse_int(value, "0");
    crm_trace("%s=%d (%s)", XML_ATTR_GENERATION_ADMIN, this_admin_epoch, value);

    value = crm_element_value(old, XML_ATTR_GENERATION);
    this_epoch = crm_parse_int(value, "0");
    crm_trace("%s=%d (%s)", XML_ATTR_GENERATION, this_epoch, value);

    value = crm_element_value(old, XML_ATTR_NUMUPDATES);
    this_updates = crm_parse_int(value, "0");
    crm_trace("%s=%d (%s)", XML_ATTR_NUMUPDATES, this_updates, value);

    cib_diff_version_details(diff,
                             &diff_add_admin_epoch, &diff_add_epoch, &diff_add_updates,
                             &diff_del_admin_epoch, &diff_del_epoch, &diff_del_updates);

    value = NULL;
    if (result && diff_del_admin_epoch != this_admin_epoch) {
        value = XML_ATTR_GENERATION_ADMIN;
        result = FALSE;
        crm_trace("%s=%d", value, diff_del_admin_epoch);

    } else if (result && diff_del_epoch != this_epoch) {
        value = XML_ATTR_GENERATION;
        result = FALSE;
        crm_trace("%s=%d", value, diff_del_epoch);

    } else if (result && diff_del_updates != this_updates) {
        value = XML_ATTR_NUMUPDATES;
        result = FALSE;
        crm_trace("%s=%d", value, diff_del_updates);
    }

    if (result) {
        xmlNode *tmp = NULL;
        xmlNode *diff_copy = copy_xml(diff);

        tmp = find_xml_node(diff_copy, "diff-removed", TRUE);
        if (tmp != NULL) {
            xml_remove_prop(tmp, XML_ATTR_GENERATION_ADMIN);
            xml_remove_prop(tmp, XML_ATTR_GENERATION);
            xml_remove_prop(tmp, XML_ATTR_NUMUPDATES);
        }

        tmp = find_xml_node(diff_copy, "diff-added", TRUE);
        if (tmp != NULL) {
            xml_remove_prop(tmp, XML_ATTR_GENERATION_ADMIN);
            xml_remove_prop(tmp, XML_ATTR_GENERATION);
            xml_remove_prop(tmp, XML_ATTR_NUMUPDATES);
        }

        result = apply_xml_diff(old, diff_copy, new);
        free_xml(diff_copy);

    } else {
        crm_err("target and diff %s values didnt match", value);
    }

    return result;
}

gboolean
cib_config_changed(xmlNode * last, xmlNode * next, xmlNode ** diff)
{
    gboolean config_changes = FALSE;
    xmlXPathObject *xpathObj = NULL;

    CRM_ASSERT(diff != NULL);

    if (last != NULL && next != NULL) {
        *diff = diff_xml_object(last, next, FALSE);
    }
    if (*diff == NULL) {
        goto done;
    }

    xpathObj = xpath_search(*diff, "//" XML_CIB_TAG_CONFIGURATION);
    if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
        config_changes = TRUE;
        goto done;

    } else if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    xpathObj = xpath_search(*diff, "//" XML_TAG_DIFF_REMOVED "//" XML_TAG_CIB);
    if (xpathObj) {
        int lpc = 0, max = xpathObj->nodesetval->nodeNr;

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
        }
    }

  done:
    if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }
    return config_changes;
}

xmlNode *
diff_cib_object(xmlNode * old_cib, xmlNode * new_cib, gboolean suppress)
{
    char *digest = NULL;
    xmlNode *diff = NULL;
    const char *version = crm_element_value(new_cib, XML_ATTR_CRM_VERSION);
    gboolean changed = cib_config_changed(old_cib, new_cib, &diff);

    fix_cib_diff(old_cib, new_cib, diff, changed);

    digest = calculate_xml_versioned_digest(new_cib, FALSE, TRUE, version);
    crm_xml_add(diff, XML_ATTR_DIGEST, digest);

    crm_free(digest);

    return diff;
}

enum cib_errors
cib_process_xpath(const char *op, int options, const char *section, xmlNode * req, xmlNode * input,
                  xmlNode * existing_cib, xmlNode ** result_cib, xmlNode ** answer)
{
    int lpc = 0;
    int max = 0;
    int rc = cib_ok;
    gboolean is_query = safe_str_eq(op, CIB_OP_QUERY);

    xmlXPathObjectPtr xpathObj = NULL;

    crm_trace("Processing \"%s\" event", op);

    if (is_query) {
        xpathObj = xpath_search(existing_cib, section);
    } else {
        xpathObj = xpath_search(*result_cib, section);
    }

    if (xpathObj != NULL && xpathObj->nodesetval != NULL) {
        max = xpathObj->nodesetval->nodeNr;
    }

    if (max < 1 && safe_str_eq(op, CIB_OP_DELETE)) {
        crm_debug("%s was already removed", section);

    } else if (max < 1) {
        crm_debug("%s: %s does not exist", op, section);
        rc = cib_NOTEXISTS;

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
            free_xml_from_parent(NULL, match);
            if ((options & cib_multiple) == 0) {
                break;
            }

        } else if (safe_str_eq(op, CIB_OP_MODIFY)) {
            if (update_xml_child(match, input) == FALSE) {
                rc = cib_NOTEXISTS;
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

            } else if (*answer) {
                add_node_copy(*answer, match);

            } else {
                *answer = match;
            }

        } else if (safe_str_eq(op, CIB_OP_REPLACE)) {
            xmlNode *parent = match->parent;

            free_xml_from_parent(NULL, match);
            if (input != NULL) {
                add_node_copy(parent, input);
            }

            if ((options & cib_multiple) == 0) {
                break;
            }
        }
    }

    if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    return rc;
}

/* remove this function */
gboolean
update_results(xmlNode * failed, xmlNode * target, const char *operation, int return_code)
{
    xmlNode *xml_node = NULL;
    gboolean was_error = FALSE;
    const char *error_msg = NULL;

    if (return_code != cib_ok) {
        error_msg = cib_error2string(return_code);

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

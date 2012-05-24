/*
 * Copyright (c) 2004 International Business Machines
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
 *
 */
#include <crm_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/utsname.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/pengine/rules.h>

#include <lib/cib/cib_private.h>

struct config_root_s {
    const char *name;
    const char *parent;
    const char *path;
};

 /*
  * "//crm_config" will also work in place of "/cib/configuration/crm_config"
  * The / prefix means find starting from the root, whereas the // prefix means
  * find anywhere and risks multiple matches
  */
/* *INDENT-OFF* */
struct config_root_s known_paths[] = {
    { NULL,			NULL,                 "//cib" },
    { XML_TAG_CIB,		NULL,                 "//cib" },
    { XML_CIB_TAG_STATUS,       "/cib",               "//cib/status" },
    { XML_CIB_TAG_CONFIGURATION,"/cib",               "//cib/configuration" },
    { XML_CIB_TAG_CRMCONFIG,    "/cib/configuration", "//cib/configuration/crm_config" },
    { XML_CIB_TAG_NODES,        "/cib/configuration", "//cib/configuration/nodes" },
    { XML_CIB_TAG_DOMAINS,      "/cib/configuration", "//cib/configuration/domains" },
    { XML_CIB_TAG_RESOURCES,    "/cib/configuration", "//cib/configuration/resources" },
    { XML_CIB_TAG_CONSTRAINTS,  "/cib/configuration", "//cib/configuration/constraints" },
    { XML_CIB_TAG_OPCONFIG,	"/cib/configuration", "//cib/configuration/op_defaults" },
    { XML_CIB_TAG_RSCCONFIG,	"/cib/configuration", "//cib/configuration/rsc_defaults" },
    { XML_CIB_TAG_ACLS,		"/cib/configuration", "//cib/configuration/acls" },
    { XML_TAG_FENCING_TOPOLOGY,	"/cib/configuration", "//cib/configuration/fencing-topology" },
    { XML_CIB_TAG_SECTION_ALL,  NULL,                 "//cib" },
};
/* *INDENT-ON* */

const char *
cib_error2string(enum cib_errors return_code)
{
    const char *error_msg = NULL;

    switch (return_code) {
        case cib_bad_permissions:
            error_msg =
                "bad permissions for the on-disk configuration. shutdown heartbeat and repair.";
            break;
        case cib_bad_digest:
            error_msg =
                "the on-disk configuration was manually altered. shutdown heartbeat and repair.";
            break;
        case cib_bad_config:
            error_msg = "the on-disk configuration is not valid";
            break;
        case cib_msg_field_add:
            error_msg = "failed adding field to cib message";
            break;
        case cib_id_check:
            error_msg = "missing id or id-collision detected";
            break;
        case cib_operation:
            error_msg = "invalid operation";
            break;
        case cib_create_msg:
            error_msg = "couldnt create cib message";
            break;
        case cib_client_gone:
            error_msg = "client left before we could send reply";
            break;
        case cib_not_connected:
            error_msg = "not connected";
            break;
        case cib_not_authorized:
            error_msg = "not authorized";
            break;
        case cib_send_failed:
            error_msg = "send failed";
            break;
        case cib_reply_failed:
            error_msg = "reply failed";
            break;
        case cib_return_code:
            error_msg = "no return code";
            break;
        case cib_output_ptr:
            error_msg = "nowhere to store output";
            break;
        case cib_output_data:
            error_msg = "corrupt output data";
            break;
        case cib_connection:
            error_msg = "connection failed";
            break;
        case cib_callback_register:
            error_msg = "couldnt register callback channel";
            break;
        case cib_authentication:
            error_msg = "";
            break;
        case cib_registration_msg:
            error_msg = "invalid registration msg";
            break;
        case cib_callback_token:
            error_msg = "callback token not found";
            break;
        case cib_missing:
            error_msg = "cib object missing";
            break;
        case cib_variant:
            error_msg = "unknown/corrupt cib variant";
            break;
        case CIBRES_MISSING_ID:
            error_msg = "The id field is missing";
            break;
        case CIBRES_MISSING_TYPE:
            error_msg = "The type field is missing";
            break;
        case CIBRES_MISSING_FIELD:
            error_msg = "A required field is missing";
            break;
        case CIBRES_OBJTYPE_MISMATCH:
            error_msg = "CIBRES_OBJTYPE_MISMATCH";
            break;
        case cib_EXISTS:
            error_msg = "The object already exists";
            break;
        case cib_NOTEXISTS:
            error_msg = "The object/attribute does not exist";
            break;
        case CIBRES_CORRUPT:
            error_msg = "The CIB is corrupt";
            break;
        case cib_NOOBJECT:
            error_msg = "The update was empty";
            break;
        case cib_NOPARENT:
            error_msg = "The parent object does not exist";
            break;
        case cib_NODECOPY:
            error_msg = "Failed while copying update";
            break;
        case CIBRES_OTHER:
            error_msg = "CIBRES_OTHER";
            break;
        case cib_ok:
            error_msg = "ok";
            break;
        case cib_unknown:
            error_msg = "Unknown error";
            break;
        case cib_STALE:
            error_msg = "Discarded old update";
            break;
        case cib_ACTIVATION:
            error_msg = "Activation Failed";
            break;
        case cib_NOSECTION:
            error_msg = "Required section was missing";
            break;
        case cib_NOTSUPPORTED:
            error_msg = "The action/feature is not supported";
            break;
        case cib_not_master:
            error_msg = "Local service is not the master instance";
            break;
        case cib_client_corrupt:
            error_msg = "Service client not valid";
            break;
        case cib_remote_timeout:
            error_msg = "Remote node did not respond";
            break;
        case cib_master_timeout:
            error_msg = "No master service is currently active";
            break;
        case cib_revision_unsupported:
            error_msg = "The required CIB revision number is not supported";
            break;
        case cib_revision_unknown:
            error_msg = "The CIB revision number could not be determined";
            break;
        case cib_missing_data:
            error_msg = "Required data for this CIB API call not found";
            break;
        case cib_no_quorum:
            error_msg = "Write requires quorum";
            break;
        case cib_diff_failed:
            error_msg = "Application of an update diff failed";
            break;
        case cib_diff_resync:
            error_msg = "Application of an update diff failed, requesting a full refresh";
            break;
        case cib_bad_section:
            error_msg = "Invalid CIB section specified";
            break;
        case cib_old_data:
            error_msg = "Update was older than existing configuration";
            break;
        case cib_dtd_validation:
            error_msg = "Update does not conform to the configured schema/DTD";
            break;
        case cib_invalid_argument:
            error_msg = "Invalid argument";
            break;
        case cib_transform_failed:
            error_msg = "Schema transform failed";
            break;
        case cib_permission_denied:
            error_msg = "Permission Denied";
            break;
    }

    if (error_msg == NULL) {
        crm_err("Unknown CIB Error Code: %d", return_code);
        error_msg = "<unknown error>";
    }

    return error_msg;
}

int
cib_section2enum(const char *a_section)
{
    if (a_section == NULL || strcasecmp(a_section, "all") == 0) {
        return cib_section_all;

    } else if (strcasecmp(a_section, XML_CIB_TAG_NODES) == 0) {
        return cib_section_nodes;

    } else if (strcasecmp(a_section, XML_CIB_TAG_STATUS) == 0) {
        return cib_section_status;

    } else if (strcasecmp(a_section, XML_CIB_TAG_CONSTRAINTS) == 0) {
        return cib_section_constraints;

    } else if (strcasecmp(a_section, XML_CIB_TAG_RESOURCES) == 0) {
        return cib_section_resources;

    } else if (strcasecmp(a_section, XML_CIB_TAG_CRMCONFIG) == 0) {
        return cib_section_crmconfig;

    }
    crm_err("Unknown CIB section: %s", a_section);
    return cib_section_none;
}

int
cib_compare_generation(xmlNode * left, xmlNode * right)
{
    int lpc = 0;

    const char *attributes[] = {
        XML_ATTR_GENERATION_ADMIN,
        XML_ATTR_GENERATION,
        XML_ATTR_NUMUPDATES,
    };

    crm_log_xml_trace(left, "left");
    crm_log_xml_trace(right, "right");

    for (lpc = 0; lpc < DIMOF(attributes); lpc++) {
        int int_elem_l = -1;
        int int_elem_r = -1;
        const char *elem_r = NULL;
        const char *elem_l = crm_element_value(left, attributes[lpc]);

        if (right != NULL) {
            elem_r = crm_element_value(right, attributes[lpc]);
        }

        if (elem_l != NULL) {
            int_elem_l = crm_parse_int(elem_l, NULL);
        }
        if (elem_r != NULL) {
            int_elem_r = crm_parse_int(elem_r, NULL);
        }

        if (int_elem_l < int_elem_r) {
            crm_trace("%s (%s < %s)", attributes[lpc], crm_str(elem_l), crm_str(elem_r));
            return -1;

        } else if (int_elem_l > int_elem_r) {
            crm_trace("%s (%s > %s)", attributes[lpc], crm_str(elem_l), crm_str(elem_r));
            return 1;
        }
    }

    return 0;
}

xmlNode *
get_cib_copy(cib_t * cib)
{
    xmlNode *xml_cib;
    int options = cib_scope_local | cib_sync_call;

    if (cib->cmds->query(cib, NULL, &xml_cib, options) != cib_ok) {
        crm_err("Couldnt retrieve the CIB");
        return NULL;
    } else if (xml_cib == NULL) {
        crm_err("The CIB result was empty");
        return NULL;
    }

    if (safe_str_eq(crm_element_name(xml_cib), XML_TAG_CIB)) {
        return xml_cib;
    }
    free_xml(xml_cib);
    return NULL;
}

xmlNode *
cib_get_generation(cib_t * cib)
{
    xmlNode *the_cib = get_cib_copy(cib);
    xmlNode *generation = create_xml_node(NULL, XML_CIB_TAG_GENERATION_TUPPLE);

    if (the_cib != NULL) {
        copy_in_properties(generation, the_cib);
        free_xml(the_cib);
    }

    return generation;
}

void
log_cib_diff(int log_level, xmlNode * diff, const char *function)
{
    int add_updates = 0;
    int add_epoch = 0;
    int add_admin_epoch = 0;

    int del_updates = 0;
    int del_epoch = 0;
    int del_admin_epoch = 0;

    if (diff == NULL) {
        return;
    }

    cib_diff_version_details(diff, &add_admin_epoch, &add_epoch, &add_updates,
                             &del_admin_epoch, &del_epoch, &del_updates);

    if (add_updates != del_updates) {
        do_crm_log(log_level, "%s: Diff: --- %d.%d.%d", function,
                   del_admin_epoch, del_epoch, del_updates);
        do_crm_log(log_level, "%s: Diff: +++ %d.%d.%d", function,
                   add_admin_epoch, add_epoch, add_updates);
    } else if (diff != NULL) {
        do_crm_log(log_level,
                   "%s: Local-only Change: %d.%d.%d", function,
                   add_admin_epoch, add_epoch, add_updates);
    }

    log_xml_diff(log_level, diff, function);
}

gboolean
cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates)
{
    *epoch = -1;
    *updates = -1;
    *admin_epoch = -1;

    if (cib == NULL) {
        return FALSE;

    } else {
        crm_element_value_int(cib, XML_ATTR_GENERATION, epoch);
        crm_element_value_int(cib, XML_ATTR_NUMUPDATES, updates);
        crm_element_value_int(cib, XML_ATTR_GENERATION_ADMIN, admin_epoch);
    }
    return TRUE;
}

gboolean
cib_diff_version_details(xmlNode * diff, int *admin_epoch, int *epoch, int *updates,
                         int *_admin_epoch, int *_epoch, int *_updates)
{
    xmlNode *tmp = NULL;

    tmp = find_xml_node(diff, "diff-added", FALSE);
    tmp = find_xml_node(tmp, XML_TAG_CIB, FALSE);
    cib_version_details(tmp, admin_epoch, epoch, updates);

    tmp = find_xml_node(diff, "diff-removed", FALSE);
    cib_version_details(tmp, _admin_epoch, _epoch, _updates);
    return TRUE;
}

/*
 * The caller should never free the return value
 */

const char *
get_object_path(const char *object_type)
{
    int lpc = 0;
    int max = DIMOF(known_paths);

    for (; lpc < max; lpc++) {
        if ((object_type == NULL && known_paths[lpc].name == NULL)
            || safe_str_eq(object_type, known_paths[lpc].name)) {
            return known_paths[lpc].path;
        }
    }
    return NULL;
}

const char *
get_object_parent(const char *object_type)
{
    int lpc = 0;
    int max = DIMOF(known_paths);

    for (; lpc < max; lpc++) {
        if (safe_str_eq(object_type, known_paths[lpc].name)) {
            return known_paths[lpc].parent;
        }
    }
    return NULL;
}

xmlNode *
get_object_root(const char *object_type, xmlNode * the_root)
{
    const char *xpath = get_object_path(object_type);

    if (xpath == NULL) {
        return the_root;        /* or return NULL? */
    }

    return get_xpath_object(xpath, the_root, LOG_DEBUG_4);
}

xmlNode *
create_cib_fragment_adv(xmlNode * update, const char *update_section, const char *source)
{
    xmlNode *cib = NULL;
    gboolean whole_cib = FALSE;
    xmlNode *object_root = NULL;
    char *local_section = NULL;

/* 	crm_debug("Creating a blank fragment: %s", update_section); */

    if (update == NULL && update_section == NULL) {
        crm_trace("Creating a blank fragment");
        update = createEmptyCib();
        crm_xml_add(cib, XML_ATTR_ORIGIN, source);
        return update;

    } else if (update == NULL) {
        crm_err("No update to create a fragment for");
        return NULL;

    }

    CRM_CHECK(update_section != NULL, return NULL);
    if (safe_str_eq(crm_element_name(update), XML_TAG_CIB)) {
        whole_cib = TRUE;
    }

    if (whole_cib == FALSE) {
        cib = createEmptyCib();
        crm_xml_add(cib, XML_ATTR_ORIGIN, source);
        object_root = get_object_root(update_section, cib);
        add_node_copy(object_root, update);

    } else {
        cib = copy_xml(update);
        crm_xml_add(cib, XML_ATTR_ORIGIN, source);
    }

    free(local_section);
    crm_trace("Verifying created fragment");
    return cib;
}

/*
 * It is the callers responsibility to free both the new CIB (output)
 *     and the new CIB (input)
 */
xmlNode *
createEmptyCib(void)
{
    xmlNode *cib_root = NULL, *config = NULL;

    cib_root = create_xml_node(NULL, XML_TAG_CIB);

    config = create_xml_node(cib_root, XML_CIB_TAG_CONFIGURATION);
    create_xml_node(cib_root, XML_CIB_TAG_STATUS);

/* 	crm_xml_add(cib_root, "version", "1"); */
    create_xml_node(config, XML_CIB_TAG_CRMCONFIG);
    create_xml_node(config, XML_CIB_TAG_NODES);
    create_xml_node(config, XML_CIB_TAG_RESOURCES);
    create_xml_node(config, XML_CIB_TAG_CONSTRAINTS);

    return cib_root;
}

static unsigned int dtd_throttle = 0;

void
fix_cib_diff(xmlNode * last, xmlNode * next, xmlNode * local_diff, gboolean changed)
{
    xmlNode *cib = NULL;
    xmlNode *diff_child = NULL;
    const char *tag = NULL;
    const char *value = NULL;

    tag = "diff-removed";
    diff_child = find_xml_node(local_diff, tag, FALSE);
    if (diff_child == NULL) {
        diff_child = create_xml_node(local_diff, tag);
    }

    tag = XML_TAG_CIB;
    cib = find_xml_node(diff_child, tag, FALSE);
    if (cib == NULL) {
        cib = create_xml_node(diff_child, tag);
    }

    tag = XML_ATTR_GENERATION_ADMIN;
    value = crm_element_value(last, tag);
    crm_xml_add(diff_child, tag, value);
    if (changed) {
        crm_xml_add(cib, tag, value);
    }

    tag = XML_ATTR_GENERATION;
    value = crm_element_value(last, tag);
    crm_xml_add(diff_child, tag, value);
    if (changed) {
        crm_xml_add(cib, tag, value);
    }

    tag = XML_ATTR_NUMUPDATES;
    value = crm_element_value(last, tag);
    crm_xml_add(cib, tag, value);
    crm_xml_add(diff_child, tag, value);

    tag = "diff-added";
    diff_child = find_xml_node(local_diff, tag, FALSE);
    if (diff_child == NULL) {
        diff_child = create_xml_node(local_diff, tag);
    }

    tag = XML_TAG_CIB;
    cib = find_xml_node(diff_child, tag, FALSE);
    if (cib == NULL) {
        cib = create_xml_node(diff_child, tag);
    }

    if (next) {
        xmlAttrPtr xIter = NULL;

        for (xIter = next->properties; xIter; xIter = xIter->next) {
            const char *p_name = (const char *)xIter->name;
            const char *p_value = crm_element_value(next, p_name);

            xmlSetProp(cib, (const xmlChar *)p_name, (const xmlChar *)p_value);
        }
    }

    crm_log_xml_trace(local_diff, "Repaired-diff");
}

enum cib_errors
cib_perform_op(const char *op, int call_options, cib_op_t * fn, gboolean is_query,
               const char *section, xmlNode * req, xmlNode * input,
               gboolean manage_counters, gboolean * config_changed,
               xmlNode * current_cib, xmlNode ** result_cib, xmlNode ** diff, xmlNode ** output)
{

    int rc = cib_ok;
    gboolean check_dtd = TRUE;
    xmlNode *scratch = NULL;
    xmlNode *local_diff = NULL;
    const char *current_dtd = "unknown";

    CRM_CHECK(output != NULL, return cib_output_data);
    CRM_CHECK(result_cib != NULL, return cib_output_data);
    CRM_CHECK(config_changed != NULL, return cib_output_data);

    *output = NULL;
    *result_cib = NULL;
    *config_changed = FALSE;

    if (fn == NULL) {
        return cib_operation;
    }

    if (is_query) {
        rc = (*fn) (op, call_options, section, req, input, current_cib, result_cib, output);
        return rc;
    }

    scratch = copy_xml(current_cib);
    rc = (*fn) (op, call_options, section, req, input, current_cib, &scratch, output);

    CRM_CHECK(current_cib != scratch, return cib_unknown);

    if (rc == cib_ok && scratch == NULL) {
        rc = cib_unknown;
    }

    if (rc == cib_ok && scratch) {
        const char *new_version = crm_element_value(scratch, XML_ATTR_CRM_VERSION);

        if (new_version && compare_version(new_version, CRM_FEATURE_SET) > 0) {
            crm_err("Discarding update with feature set '%s' greater than our own '%s'",
                    new_version, CRM_FEATURE_SET);
            rc = cib_NOTSUPPORTED;
        }
    }

    if (rc == cib_ok && current_cib) {
        int old = 0;
        int new = 0;

        crm_element_value_int(scratch, XML_ATTR_GENERATION_ADMIN, &new);
        crm_element_value_int(current_cib, XML_ATTR_GENERATION_ADMIN, &old);

        if (old > new) {
            crm_err("%s went backwards: %d -> %d (Opts: 0x%x)",
                    XML_ATTR_GENERATION_ADMIN, old, new, call_options);
            crm_log_xml_warn(req, "Bad Op");
            crm_log_xml_warn(input, "Bad Data");
            rc = cib_old_data;

        } else if (old == new) {
            crm_element_value_int(scratch, XML_ATTR_GENERATION, &new);
            crm_element_value_int(current_cib, XML_ATTR_GENERATION, &old);
            if (old > new) {
                crm_err("%s went backwards: %d -> %d (Opts: 0x%x)",
                        XML_ATTR_GENERATION, old, new, call_options);
                crm_log_xml_warn(req, "Bad Op");
                crm_log_xml_warn(input, "Bad Data");
                rc = cib_old_data;
            }
        }
    }

    if (rc == cib_ok) {
        fix_plus_plus_recursive(scratch);
        current_dtd = crm_element_value(scratch, XML_ATTR_VALIDATION);

        if (manage_counters) {
            if (is_set(call_options, cib_inhibit_bcast) && safe_str_eq(section, XML_CIB_TAG_STATUS)) {
                /* Fast-track changes connections which wont be broadcasting anywhere */
                cib_update_counter(scratch, XML_ATTR_NUMUPDATES, FALSE);
                goto done;
            }

            /* The diff calculation in cib_config_changed() accounts for 25% of the
             * CIB's total CPU usage on the DC
             *
             * RNG validation on the otherhand, accounts for only 9%... 
             */
            *config_changed = cib_config_changed(current_cib, scratch, &local_diff);

            if (*config_changed) {
                cib_update_counter(scratch, XML_ATTR_NUMUPDATES, TRUE);
                cib_update_counter(scratch, XML_ATTR_GENERATION, FALSE);

            } else {
                /* Previously we only did this if the diff detected a change
                 *
                 * But we replies are still sent, even if nothing changes so we
                 *   don't save any network traffic and means we need to jump
                 *   through expensive hoops to detect ordering changes - see below
                 */
                cib_update_counter(scratch, XML_ATTR_NUMUPDATES, FALSE);

                if (local_diff == NULL) {
                    /* Nothing to check */
                    check_dtd = FALSE;

                    /* Create a fake diff so that notifications, which include a _digest_,
                     * will be sent to our peers
                     *
                     * This is the cheapest way to detect changes to group/set ordering
                     *
                     * Previously we compared the old and new digest in cib_config_changed(),
                     * but that accounted for 15% of the CIB's total CPU usage on the DC
                     */
                    local_diff = create_xml_node(NULL, "diff");
                    crm_xml_add(local_diff, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
                    create_xml_node(local_diff, "diff-removed");
                    create_xml_node(local_diff, "diff-added");

                    /* Usually these are attrd re-updates */
                    crm_log_xml_trace(req, "Non-change");

                } else if (dtd_throttle++ % 20) {
                    /* Throttle the amount of costly validation we perform due to status updates
                     * a) we don't really care whats in the status section
                     * b) we don't validate any of it's contents at the moment anyway
                     */
                    check_dtd = FALSE;
                }
            }
        }
    }

    if (diff != NULL && local_diff != NULL) {
        /* Only fix the diff if we'll return it... */
        fix_cib_diff(current_cib, scratch, local_diff, *config_changed);
        *diff = local_diff;
        local_diff = NULL;
    }

  done:
    if (rc == cib_ok && check_dtd && validate_xml(scratch, NULL, TRUE) == FALSE) {
        crm_warn("Updated CIB does not validate against %s schema/dtd", crm_str(current_dtd));
        rc = cib_dtd_validation;
    }

    *result_cib = scratch;
    free_xml(local_diff);
    return rc;
}

xmlNode *
cib_create_op(int call_id, const char *token, const char *op, const char *host, const char *section,
              xmlNode * data, int call_options, const char *user_name)
{
    int rc = HA_OK;
    xmlNode *op_msg = create_xml_node(NULL, "cib_command");

    CRM_CHECK(op_msg != NULL, return NULL);
    CRM_CHECK(token != NULL, return NULL);

    crm_xml_add(op_msg, F_XML_TAGNAME, "cib_command");

    crm_xml_add(op_msg, F_TYPE, T_CIB);
    crm_xml_add(op_msg, F_CIB_CALLBACK_TOKEN, token);
    crm_xml_add(op_msg, F_CIB_OPERATION, op);
    crm_xml_add(op_msg, F_CIB_HOST, host);
    crm_xml_add(op_msg, F_CIB_SECTION, section);
    crm_xml_add_int(op_msg, F_CIB_CALLID, call_id);
#if ENABLE_ACL
    if (user_name) {
        crm_xml_add(op_msg, F_CIB_USER, user_name);
    }
#endif
    crm_trace("Sending call options: %.8lx, %d", (long)call_options, call_options);
    crm_xml_add_int(op_msg, F_CIB_CALLOPTS, call_options);

    if (data != NULL) {
        add_message_xml(op_msg, F_CIB_CALLDATA, data);
    }

    if (rc != HA_OK) {
        crm_err("Failed to create CIB operation message");
        crm_log_xml_err(op_msg, "op");
        free_xml(op_msg);
        return NULL;
    }

    if (call_options & cib_inhibit_bcast) {
        CRM_CHECK((call_options & cib_scope_local), return NULL);
    }
    return op_msg;
}

void
cib_native_callback(cib_t * cib, xmlNode * msg, int call_id, int rc)
{
    xmlNode *output = NULL;
    cib_callback_client_t *blob = NULL;
    cib_callback_client_t local_blob;

    local_blob.id = NULL;
    local_blob.callback = NULL;
    local_blob.user_data = NULL;
    local_blob.only_success = FALSE;

    if (msg != NULL) {
        crm_element_value_int(msg, F_CIB_RC, &rc);
        crm_element_value_int(msg, F_CIB_CALLID, &call_id);
        output = get_message_xml(msg, F_CIB_CALLDATA);
    }

    blob = g_hash_table_lookup(cib_op_callback_table, GINT_TO_POINTER(call_id));

    if (blob != NULL) {
        local_blob = *blob;
        blob = NULL;

        remove_cib_op_callback(call_id, FALSE);

    } else {
        crm_trace("No callback found for call %d", call_id);
        local_blob.callback = NULL;
    }

    if (cib == NULL) {
        crm_debug("No cib object supplied");
    }

    if (rc == cib_diff_resync) {
        /* This is an internal value that clients do not and should not care about */
        rc = cib_ok;
    }

    if (local_blob.callback != NULL && (rc == cib_ok || local_blob.only_success == FALSE)) {
        crm_trace("Invoking callback %s for call %d", crm_str(local_blob.id), call_id);
        local_blob.callback(msg, call_id, rc, output, local_blob.user_data);

    } else if (cib && cib->op_callback == NULL && rc != cib_ok) {
        crm_warn("CIB command failed: %s", cib_error2string(rc));
        crm_log_xml_debug(msg, "Failed CIB Update");
    }

    if (cib && cib->op_callback != NULL) {
        crm_trace("Invoking global callback for call %d", call_id);
        cib->op_callback(msg, call_id, rc, output);
    }
    crm_trace("OP callback activated.");
}

void
cib_native_notify(gpointer data, gpointer user_data)
{
    xmlNode *msg = user_data;
    cib_notify_client_t *entry = data;
    const char *event = NULL;

    if (msg == NULL) {
        crm_warn("Skipping callback - NULL message");
        return;
    }

    event = crm_element_value(msg, F_SUBTYPE);

    if (entry == NULL) {
        crm_warn("Skipping callback - NULL callback client");
        return;

    } else if (entry->callback == NULL) {
        crm_warn("Skipping callback - NULL callback");
        return;

    } else if (safe_str_neq(entry->event, event)) {
        crm_trace("Skipping callback - event mismatch %p/%s vs. %s", entry, entry->event, event);
        return;
    }

    crm_trace("Invoking callback for %p/%s event...", entry, event);
    entry->callback(event, msg);
    crm_trace("Callback invoked...");
}

gboolean
determine_host(cib_t * cib_conn, char **node_uname, char **node_uuid)
{
    CRM_CHECK(node_uname != NULL, return FALSE);

    if (*node_uname == NULL) {
        struct utsname name;

        if (uname(&name) < 0) {
            crm_perror(LOG_ERR, "uname(2) call failed");
            return FALSE;
        }
        *node_uname = crm_strdup(name.nodename);
        crm_info("Detected uname: %s", *node_uname);
    }

    if (cib_conn && *node_uname != NULL && node_uuid != NULL && *node_uuid == NULL) {
        int rc = query_node_uuid(cib_conn, *node_uname, node_uuid);

        if (rc != cib_ok) {
            fprintf(stderr, "Could not map uname=%s to a UUID: %s\n",
                    *node_uname, cib_error2string(rc));
            return FALSE;
        }
        crm_info("Mapped %s to %s", *node_uname, crm_str(*node_uuid));
    }
    return TRUE;
}

pe_cluster_option cib_opts[] = {
    /* name, old-name, validate, default, description */
    {"enable-acl", NULL, "boolean", NULL, "false", &check_boolean,
     "Enable CIB ACL", NULL}
    ,
};

void
cib_metadata(void)
{
    config_metadata("Cluster Information Base", "1.0",
                    "Cluster Information Base Options",
                    "This is a fake resource that details the options that can be configured for the Cluster Information Base.",
                    cib_opts, DIMOF(cib_opts));
}

void
verify_cib_options(GHashTable * options)
{
    verify_all_options(options, cib_opts, DIMOF(cib_opts));
}

const char *
cib_pref(GHashTable * options, const char *name)
{
    return get_cluster_pref(options, cib_opts, DIMOF(cib_opts), name);
}

gboolean
cib_read_config(GHashTable * options, xmlNode * current_cib)
{
    xmlNode *config = NULL;
    ha_time_t *now = NULL;

    if (options == NULL || current_cib == NULL) {
        return FALSE;
    }

    now = new_ha_date(TRUE);

    g_hash_table_remove_all(options);

    config = get_object_root(XML_CIB_TAG_CRMCONFIG, current_cib);
    if (config) {
        unpack_instance_attributes(current_cib, config, XML_CIB_TAG_PROPSET, NULL, options,
                                   CIB_OPTIONS_FIRST, FALSE, now);
    }

    verify_cib_options(options);

    free_ha_date(now);

    return TRUE;
}

gboolean
cib_internal_config_changed(xmlNode * diff)
{
    gboolean changed = FALSE;
    const char *config_xpath =
        "//" XML_TAG_CIB "/" XML_CIB_TAG_CONFIGURATION "/" XML_CIB_TAG_CRMCONFIG;
    xmlXPathObject *xpathObj = NULL;

    if (diff == NULL) {
        return FALSE;
    }

    xpathObj = xpath_search(diff, config_xpath);
    if (xpathObj && xpathObj->nodesetval->nodeNr > 0) {
        changed = TRUE;
    }

    if (xpathObj) {
        xmlXPathFreeObject(xpathObj);
    }

    return changed;
}

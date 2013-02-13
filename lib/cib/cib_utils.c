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
#include <crm/cib/internal.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/pengine/rules.h>

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

    if (cib->cmds->query(cib, NULL, &xml_cib, options) != pcmk_ok) {
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

    const char *digest = NULL;

    if (diff == NULL) {
        return;
    }

    digest = crm_element_value(diff, XML_ATTR_DIGEST);
    cib_diff_version_details(diff, &add_admin_epoch, &add_epoch, &add_updates,
                             &del_admin_epoch, &del_epoch, &del_updates);

    if (add_updates != del_updates) {
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "Diff: --- %d.%d.%d", del_admin_epoch, del_epoch, del_updates);
        do_crm_log_alias(log_level, __FILE__, function, __LINE__,
                         "Diff: +++ %d.%d.%d %s", add_admin_epoch, add_epoch, add_updates, digest);

    } else if (diff != NULL) {
        do_crm_log(log_level,
                   "%s: Local-only Change: %d.%d.%d", function ? function : "",
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
    tmp = find_xml_node(tmp, XML_TAG_CIB, FALSE);
    cib_version_details(tmp, _admin_epoch, _epoch, _updates);

    if (*_admin_epoch < 0) {
        *_admin_epoch = *admin_epoch;
    }
    if (*_epoch < 0) {
        *_epoch = *epoch;
    }
    if (*_updates < 0) {
        *_updates = *updates;
    }
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

    create_xml_node(config, XML_CIB_TAG_CRMCONFIG);
    create_xml_node(config, XML_CIB_TAG_NODES);
    create_xml_node(config, XML_CIB_TAG_RESOURCES);
    create_xml_node(config, XML_CIB_TAG_CONSTRAINTS);

    return cib_root;
}

void
fix_cib_diff(xmlNode * last, xmlNode * next, xmlNode * local_diff, gboolean changed)
{
    xmlNode *cib = NULL;
    xmlNode *diff_child = NULL;

    const char *tag = NULL;
    const char *value = NULL;

    if (local_diff == NULL) {
        crm_trace("Nothing to do");
        return;
    }

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

    crm_log_xml_explicit(local_diff, "Repaired-diff");
}

int
cib_perform_op(const char *op, int call_options, cib_op_t * fn, gboolean is_query,
               const char *section, xmlNode * req, xmlNode * input,
               gboolean manage_counters, gboolean * config_changed,
               xmlNode * current_cib, xmlNode ** result_cib, xmlNode ** diff, xmlNode ** output)
{

    int rc = pcmk_ok;
    gboolean check_dtd = TRUE;
    xmlNode *scratch = NULL;
    xmlNode *local_diff = NULL;

    char *new_digest = NULL;
    const char *new_version = NULL;

    static char *last_digest = NULL;
    static unsigned int dtd_throttle = 0;

    crm_trace("Begin %s%s op", is_query ? "read-only " : "", op);

    CRM_CHECK(output != NULL, return -ENOMSG);
    CRM_CHECK(result_cib != NULL, return -ENOMSG);
    CRM_CHECK(config_changed != NULL, return -ENOMSG);

    *output = NULL;
    *result_cib = NULL;
    *config_changed = FALSE;

    if (fn == NULL) {
        return -EINVAL;
    }

    if (is_query) {
        rc = (*fn) (op, call_options, section, req, input, current_cib, result_cib, output);
        return rc;
    }

    scratch = copy_xml(current_cib);
    rc = (*fn) (op, call_options, section, req, input, current_cib, &scratch, output);

    CRM_CHECK(current_cib != scratch, return -EINVAL);

    if (rc == pcmk_ok && scratch == NULL) {
        rc = -EINVAL;
        goto done;

    } else if (rc != pcmk_ok) {
        goto done;
    }

    if (scratch) {
        new_version = crm_element_value(scratch, XML_ATTR_CRM_VERSION);

        if (new_version && compare_version(new_version, CRM_FEATURE_SET) > 0) {
            crm_err("Discarding update with feature set '%s' greater than our own '%s'",
                    new_version, CRM_FEATURE_SET);
            rc = -EPROTONOSUPPORT;
            goto done;
        }
    }

    if (current_cib) {
        int old = 0;
        int new = 0;

        crm_element_value_int(scratch, XML_ATTR_GENERATION_ADMIN, &new);
        crm_element_value_int(current_cib, XML_ATTR_GENERATION_ADMIN, &old);

        if (old > new) {
            crm_err("%s went backwards: %d -> %d (Opts: 0x%x)",
                    XML_ATTR_GENERATION_ADMIN, old, new, call_options);
            crm_log_xml_warn(req, "Bad Op");
            crm_log_xml_warn(input, "Bad Data");
            rc = -pcmk_err_old_data;

        } else if (old == new) {
            crm_element_value_int(scratch, XML_ATTR_GENERATION, &new);
            crm_element_value_int(current_cib, XML_ATTR_GENERATION, &old);
            if (old > new) {
                crm_err("%s went backwards: %d -> %d (Opts: 0x%x)",
                        XML_ATTR_GENERATION, old, new, call_options);
                crm_log_xml_warn(req, "Bad Op");
                crm_log_xml_warn(input, "Bad Data");
                rc = -pcmk_err_old_data;
            }
        }
    }

    crm_trace("Massaging CIB contents");
    strip_text_nodes(scratch);
    fix_plus_plus_recursive(scratch);

    /* The diff calculation in cib_config_changed() accounts for 25% of the
     * CIB's total CPU usage on the DC
     *
     * RNG validation on the otherhand, accounts for only 9%... 
     */
    *config_changed = cib_config_changed(current_cib, scratch, &local_diff);

    crm_trace("Updating version tuple: %s", manage_counters ? "true" : "false");
    if (manage_counters == FALSE) {
        if (dtd_throttle++ % 20) {
            /* Throttle the amount of costly validation we perform due to slave updates.
             * The master already validated it...
             */
            check_dtd = FALSE;
        }

    } else if (is_set(call_options, cib_inhibit_bcast) && safe_str_eq(section, XML_CIB_TAG_STATUS)) {
        /* Fast-track changes connections which wont be broadcasting anywhere */
        cib_update_counter(scratch, XML_ATTR_NUMUPDATES, FALSE);
        goto done;

    } else if (*config_changed) {
        cib_update_counter(scratch, XML_ATTR_NUMUPDATES, TRUE);
        cib_update_counter(scratch, XML_ATTR_GENERATION, FALSE);

    } else if (local_diff) {
        cib_update_counter(scratch, XML_ATTR_NUMUPDATES, FALSE);
        if (dtd_throttle++ % 20) {
            /* Throttle the amount of costly validation we perform due to status updates
             * a) we don't really care whats in the status section
             * b) we don't validate any of it's contents at the moment anyway
             */
            check_dtd = FALSE;
        }
    }

    new_digest = calculate_xml_versioned_digest(scratch, FALSE, TRUE, new_version);

    /* === scratch must not be modified after this point ===
     * Exceptions, anything in:

     static filter_t filter[] = {
     { 0, XML_ATTR_ORIGIN },
     { 0, XML_CIB_ATTR_WRITTEN },               
     { 0, XML_ATTR_UPDATE_ORIG },
     { 0, XML_ATTR_UPDATE_CLIENT },
     { 0, XML_ATTR_UPDATE_USER },
     };
     */

    if (local_diff == NULL) {
        /* 50-60% of updates will not result in a change
         *
         * We used to bump the version and pretend a change occurred,
         * this saved 15% CPU on the DC but turned out to be a bad
         * idea for the slaves which had to process hundreds of
         * "empty" updates.
         *
         * Now we only do it if the digests don't match (ie. after an
         * ordering change) and we at least cache the previous digest
         *
         */

        check_dtd = FALSE;      /* Nothing to check */

        if (last_digest == NULL) {
            crm_trace("No reference point for ordering test");

        } else if (crm_str_eq(new_digest, last_digest, TRUE) == FALSE) {

            crm_notice("Configuration ordering change detected");
            cib_update_counter(scratch, XML_ATTR_NUMUPDATES, TRUE);

            crm_trace("Old: %s, New: %s", last_digest, new_digest);
            /*
               crm_log_xml_trace(current_cib, "Old");
               crm_log_xml_trace(scratch, "New");
               crm_log_xml_trace(req, "Re-order");
               crm_write_blackbox(0, NULL);
             */

            crm_trace("Recalculating the digest now that we modified %s and %s",
                      XML_ATTR_GENERATION, XML_ATTR_NUMUPDATES);
            free(new_digest);
            new_digest = calculate_xml_versioned_digest(scratch, FALSE, TRUE, new_version);

            /* Create a fake diff so that notifications, which include a _digest_,
             * will be sent to our peers
             */
            local_diff = create_xml_node(NULL, "diff");
            crm_xml_add(local_diff, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
            create_xml_node(local_diff, "diff-removed");
            create_xml_node(local_diff, "diff-added");

        } else {
            /* Usually these are attrd re-updates */
            crm_log_xml_explicit(req, "Non-change");
        }
    }

    free(last_digest);
    last_digest = new_digest;

    if (*config_changed && is_not_set(call_options, cib_no_mtime)) {
        char *now_str = NULL;
        time_t now = time(NULL);
        const char *schema = crm_element_value(scratch, XML_ATTR_VALIDATION);

        now_str = ctime(&now);
        now_str[24] = EOS;      /* replace the newline */
        crm_xml_replace(scratch, XML_CIB_ATTR_WRITTEN, now_str);

        if (schema) {
            static int minimum_schema = 0;
            int current_schema = get_schema_version(schema);

            if (minimum_schema == 0) {
                minimum_schema = get_schema_version("pacemaker-1.1");
            }

            /* Does the CIB support the "update-*" attributes... */
            if (current_schema >= minimum_schema) {
                const char *origin = crm_element_value(req, F_ORIG);

                CRM_LOG_ASSERT(origin != NULL);
                crm_xml_replace(scratch, XML_ATTR_UPDATE_ORIG, origin);
                crm_xml_replace(scratch, XML_ATTR_UPDATE_CLIENT,
                                crm_element_value(req, F_CIB_CLIENTNAME));
#if ENABLE_ACL
                crm_xml_replace(scratch, XML_ATTR_UPDATE_USER, crm_element_value(req, F_CIB_USER));
#endif
            }
        }
    }

    if (diff != NULL && local_diff != NULL) {
        /* Only fix the diff if we'll return it... */
        crm_trace("Ensuring the diff is accurate");
        fix_cib_diff(current_cib, scratch, local_diff, *config_changed);

        crm_trace("Adding digest %s to target %p", new_digest, scratch);
        crm_xml_add(local_diff, XML_ATTR_DIGEST, new_digest);

        *diff = local_diff;
        local_diff = NULL;
    }

  done:
    crm_trace("Perform validation: %s", check_dtd ? "true" : "false");
    if (rc == pcmk_ok && check_dtd && validate_xml(scratch, NULL, TRUE) == FALSE) {
        const char *current_dtd = crm_element_value(scratch, XML_ATTR_VALIDATION);

        crm_warn("Updated CIB does not validate against %s schema/dtd", crm_str(current_dtd));
        rc = -pcmk_err_dtd_validation;
    }

    *result_cib = scratch;
    free_xml(local_diff);
    crm_trace("Done");
    return rc;
}

xmlNode *
cib_create_op(int call_id, const char *token, const char *op, const char *host, const char *section,
              xmlNode * data, int call_options, const char *user_name)
{
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

    if (rc == -pcmk_err_diff_resync) {
        /* This is an internal value that clients do not and should not care about */
        rc = pcmk_ok;
    }

    if (local_blob.callback != NULL && (rc == pcmk_ok || local_blob.only_success == FALSE)) {
        crm_trace("Invoking callback %s for call %d", crm_str(local_blob.id), call_id);
        local_blob.callback(msg, call_id, rc, output, local_blob.user_data);

    } else if (cib && cib->op_callback == NULL && rc != pcmk_ok) {
        crm_warn("CIB command failed: %s", pcmk_strerror(rc));
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
    crm_time_t *now = NULL;

    if (options == NULL || current_cib == NULL) {
        return FALSE;
    }

    now = crm_time_new(NULL);

    g_hash_table_remove_all(options);

    config = get_object_root(XML_CIB_TAG_CRMCONFIG, current_cib);
    if (config) {
        unpack_instance_attributes(current_cib, config, XML_CIB_TAG_PROPSET, NULL, options,
                                   CIB_OPTIONS_FIRST, FALSE, now);
    }

    verify_cib_options(options);

    crm_time_free(now);

    return TRUE;
}

int
cib_apply_patch_event(xmlNode * event, xmlNode * input, xmlNode ** output, int level)
{
    int rc = pcmk_err_generic;

    xmlNode *diff = NULL;

    CRM_ASSERT(event);
    CRM_ASSERT(input);
    CRM_ASSERT(output);

    crm_element_value_int(event, F_CIB_RC, &rc);
    diff = get_message_xml(event, F_CIB_UPDATE_RESULT);

    if (rc < pcmk_ok || diff == NULL) {
        return rc;
    }

    if (level > LOG_CRIT) {
        log_cib_diff(level, diff, "Config update");
    }

    if (input != NULL) {
        rc = cib_process_diff(NULL, cib_none, NULL, NULL, diff, input, output, NULL);

        if (rc != pcmk_ok) {
            crm_debug("Update didn't apply: %s", pcmk_strerror(rc));
            return rc;
        }
    }

    return rc;
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

int
cib_internal_op(cib_t * cib, const char *op, const char *host,
                const char *section, xmlNode * data,
                xmlNode ** output_data, int call_options, const char *user_name)
{
    int (*delegate) (cib_t * cib, const char *op, const char *host,
                     const char *section, xmlNode * data,
                     xmlNode ** output_data, int call_options, const char *user_name) =
        cib->delegate_fn;

    return delegate(cib, op, host, section, data, output_data, call_options, user_name);
}

/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
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
#include <crm/common/xml_internal.h>
#include <crm/pengine/rules.h>

xmlNode *
cib_get_generation(cib_t * cib)
{
    xmlNode *the_cib = NULL;
    xmlNode *generation = create_xml_node(NULL, XML_CIB_TAG_GENERATION_TUPPLE);

    cib->cmds->query(cib, NULL, &the_cib, cib_scope_local | cib_sync_call);
    if (the_cib != NULL) {
        copy_in_properties(generation, the_cib);
        free_xml(the_cib);
    }

    return generation;
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
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    xml_patch_versions(diff, add, del);

    *admin_epoch = add[0];
    *epoch = add[1];
    *updates = add[2];

    *_admin_epoch = del[0];
    *_epoch = del[1];
    *_updates = del[2];

    return TRUE;
}

/*!
 * \brief Create XML for a new (empty) CIB
 *
 * \param[in] cib_epoch   What to use as "epoch" CIB property
 *
 * \return Newly created XML for empty CIB
 * \note It is the caller's responsibility to free the result with free_xml().
 */
xmlNode *
createEmptyCib(int cib_epoch)
{
    xmlNode *cib_root = NULL, *config = NULL;

    cib_root = create_xml_node(NULL, XML_TAG_CIB);
    crm_xml_add(cib_root, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(cib_root, XML_ATTR_VALIDATION, xml_latest_schema());

    crm_xml_add_int(cib_root, XML_ATTR_GENERATION, cib_epoch);
    crm_xml_add_int(cib_root, XML_ATTR_NUMUPDATES, 0);
    crm_xml_add_int(cib_root, XML_ATTR_GENERATION_ADMIN, 0);

    config = create_xml_node(cib_root, XML_CIB_TAG_CONFIGURATION);
    create_xml_node(cib_root, XML_CIB_TAG_STATUS);

    create_xml_node(config, XML_CIB_TAG_CRMCONFIG);
    create_xml_node(config, XML_CIB_TAG_NODES);
    create_xml_node(config, XML_CIB_TAG_RESOURCES);
    create_xml_node(config, XML_CIB_TAG_CONSTRAINTS);

#if PCMK__RESOURCE_STICKINESS_DEFAULT != 0
    {
        xmlNode *rsc_defaults = create_xml_node(config, XML_CIB_TAG_RSCCONFIG);
        xmlNode *meta = create_xml_node(rsc_defaults, XML_TAG_META_SETS);
        xmlNode *nvpair = create_xml_node(meta, XML_CIB_TAG_NVPAIR);

        crm_xml_add(meta, XML_ATTR_ID, "build-resource-defaults");
        crm_xml_add(nvpair, XML_ATTR_ID, "build-" XML_RSC_ATTR_STICKINESS);
        crm_xml_add(nvpair, XML_NVPAIR_ATTR_NAME, XML_RSC_ATTR_STICKINESS);
        crm_xml_add_int(nvpair, XML_NVPAIR_ATTR_VALUE,
                        PCMK__RESOURCE_STICKINESS_DEFAULT);
    }
#endif
    return cib_root;
}

static bool
cib_acl_enabled(xmlNode *xml, const char *user)
{
    bool rc = FALSE;

    if(pcmk_acl_required(user)) {
        const char *value = NULL;
        GHashTable *options = pcmk__strkey_table(free, free);

        cib_read_config(options, xml);
        value = cib_pref(options, "enable-acl");
        rc = crm_is_true(value);
        g_hash_table_destroy(options);
    }

    crm_trace("CIB ACL is %s", rc ? "enabled" : "disabled");
    return rc;
}

int
cib_perform_op(const char *op, int call_options, cib_op_t fn, gboolean is_query,
               const char *section, xmlNode *req, xmlNode *input,
               gboolean manage_counters, gboolean *config_changed,
               xmlNode **current_cib, xmlNode **result_cib, xmlNode **diff,
               xmlNode **output)
{
    int rc = pcmk_ok;
    gboolean check_schema = TRUE;
    xmlNode *top = NULL;
    xmlNode *scratch = NULL;
    xmlNode *patchset_cib = NULL;
    xmlNode *local_diff = NULL;

    const char *new_version = NULL;
    const char *user = crm_element_value(req, F_CIB_USER);
    bool with_digest = FALSE;

    pcmk__output_t *out = NULL;
    int out_rc = pcmk_rc_no_output;

    crm_trace("Begin %s%s%s op",
              (pcmk_is_set(call_options, cib_dryrun)? "dry run of " : ""),
              (is_query? "read-only " : ""), op);

    CRM_CHECK(output != NULL, return -ENOMSG);
    CRM_CHECK(current_cib != NULL, return -ENOMSG);
    CRM_CHECK(result_cib != NULL, return -ENOMSG);
    CRM_CHECK(config_changed != NULL, return -ENOMSG);

    if(output) {
        *output = NULL;
    }

    *result_cib = NULL;
    *config_changed = FALSE;

    if (fn == NULL) {
        return -EINVAL;
    }

    if (is_query) {
        xmlNode *cib_ro = *current_cib;
        xmlNode *cib_filtered = NULL;

        if (cib_acl_enabled(cib_ro, user)
            && xml_acl_filtered_copy(user, *current_cib, *current_cib,
                                     &cib_filtered)) {

            if (cib_filtered == NULL) {
                crm_debug("Pre-filtered the entire cib");
                return -EACCES;
            }
            cib_ro = cib_filtered;
            crm_log_xml_trace(cib_ro, "filtered");
        }

        rc = (*fn) (op, call_options, section, req, input, cib_ro, result_cib, output);

        if(output == NULL || *output == NULL) {
            /* nothing */

        } else if(cib_filtered == *output) {
            cib_filtered = NULL; /* Let them have this copy */

        } else if (*output == *current_cib) {
            /* They already know not to free it */

        } else if(cib_filtered && (*output)->doc == cib_filtered->doc) {
            /* We're about to free the document of which *output is a part */
            *output = copy_xml(*output);

        } else if ((*output)->doc == (*current_cib)->doc) {
            /* Give them a copy they can free */
            *output = copy_xml(*output);
        }

        free_xml(cib_filtered);
        return rc;
    }


    if (pcmk_is_set(call_options, cib_zero_copy)) {
        /* Conditional on v2 patch style */

        scratch = *current_cib;

        // Make a copy of the top-level element to store version details
        top = create_xml_node(NULL, (const char *) scratch->name);
        copy_in_properties(top, scratch);
        patchset_cib = top;

        xml_track_changes(scratch, user, NULL, cib_acl_enabled(scratch, user));
        rc = (*fn) (op, call_options, section, req, input, scratch, &scratch, output);

        /* If scratch points to a new object now (for example, after an erase
         * operation), then *current_cib should point to the same object.
         */
        *current_cib = scratch;

    } else {
        scratch = copy_xml(*current_cib);
        patchset_cib = *current_cib;

        xml_track_changes(scratch, user, NULL, cib_acl_enabled(scratch, user));
        rc = (*fn) (op, call_options, section, req, input, *current_cib,
                    &scratch, output);

        if(scratch && xml_tracking_changes(scratch) == FALSE) {
            crm_trace("Inferring changes after %s op", op);
            xml_track_changes(scratch, user, *current_cib,
                              cib_acl_enabled(*current_cib, user));
            xml_calculate_changes(*current_cib, scratch);
        }
        CRM_CHECK(*current_cib != scratch, return -EINVAL);
    }

    xml_acl_disable(scratch); /* Allow the system to make any additional changes */

    if (rc == pcmk_ok && scratch == NULL) {
        rc = -EINVAL;
        goto done;

    } else if(rc == pcmk_ok && xml_acl_denied(scratch)) {
        crm_trace("ACL rejected part or all of the proposed changes");
        rc = -EACCES;
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

    if (patchset_cib != NULL) {
        int old = 0;
        int new = 0;

        crm_element_value_int(scratch, XML_ATTR_GENERATION_ADMIN, &new);
        crm_element_value_int(patchset_cib, XML_ATTR_GENERATION_ADMIN, &old);

        if (old > new) {
            crm_err("%s went backwards: %d -> %d (Opts: %#x)",
                    XML_ATTR_GENERATION_ADMIN, old, new, call_options);
            crm_log_xml_warn(req, "Bad Op");
            crm_log_xml_warn(input, "Bad Data");
            rc = -pcmk_err_old_data;

        } else if (old == new) {
            crm_element_value_int(scratch, XML_ATTR_GENERATION, &new);
            crm_element_value_int(patchset_cib, XML_ATTR_GENERATION, &old);
            if (old > new) {
                crm_err("%s went backwards: %d -> %d (Opts: %#x)",
                        XML_ATTR_GENERATION, old, new, call_options);
                crm_log_xml_warn(req, "Bad Op");
                crm_log_xml_warn(input, "Bad Data");
                rc = -pcmk_err_old_data;
            }
        }
    }

    crm_trace("Massaging CIB contents");
    pcmk__strip_xml_text(scratch);
    fix_plus_plus_recursive(scratch);

    if (pcmk_is_set(call_options, cib_zero_copy)) {
        /* At this point, patchset_cib is just the "cib" tag and its properties.
         *
         * The v1 format would barf on this, but we know the v2 patch
         * format only needs it for the top-level version fields
         */
        local_diff = xml_create_patchset(2, patchset_cib, scratch,
                                         (bool*) config_changed,
                                         manage_counters);

    } else {
        static time_t expires = 0;
        time_t tm_now = time(NULL);

        if (expires < tm_now) {
            expires = tm_now + 60;  /* Validate clients are correctly applying v2-style diffs at most once a minute */
            with_digest = TRUE;
        }

        local_diff = xml_create_patchset(0, patchset_cib, scratch,
                                         (bool*) config_changed,
                                         manage_counters);
    }

    // Create a log output object only if we're going to use it
    pcmk__if_tracing(
        {
            rc = pcmk_rc2legacy(pcmk__log_output_new(&out));
            CRM_CHECK(rc == pcmk_ok, goto done);

            pcmk__output_set_log_level(out, LOG_TRACE);
            out_rc = pcmk__xml_show_changes(out, scratch);
        },
        {}
    );
    xml_accept_changes(scratch);

    if(local_diff) {
        int temp_rc = pcmk_rc_no_output;

        patchset_process_digest(local_diff, patchset_cib, scratch, with_digest);

        if (out == NULL) {
            rc = pcmk_rc2legacy(pcmk__log_output_new(&out));
            CRM_CHECK(rc == pcmk_ok, goto done);
        }
        pcmk__output_set_log_level(out, LOG_INFO);
        temp_rc = out->message(out, "xml-patchset", local_diff);
        out_rc = pcmk__output_select_rc(rc, temp_rc);

        crm_log_xml_trace(local_diff, "raw patch");
    }

    if (out != NULL) {
        out->finish(out, pcmk_rc2exitc(out_rc), true, NULL);
        pcmk__output_free(out);
        out = NULL;
    }

    if (!pcmk_is_set(call_options, cib_zero_copy) && (local_diff != NULL)) {
        // Original to compare against doesn't exist
        pcmk__if_tracing(
            {
                // Validate the calculated patch set
                int test_rc = pcmk_ok;
                int format = 1;
                xmlNode *cib_copy = copy_xml(patchset_cib);

                crm_element_value_int(local_diff, "format", &format);
                test_rc = xml_apply_patchset(cib_copy, local_diff,
                                             manage_counters);

                if (test_rc != pcmk_ok) {
                    save_xml_to_file(cib_copy, "PatchApply:calculated", NULL);
                    save_xml_to_file(patchset_cib, "PatchApply:input", NULL);
                    save_xml_to_file(scratch, "PatchApply:actual", NULL);
                    save_xml_to_file(local_diff, "PatchApply:diff", NULL);
                    crm_err("v%d patchset error, patch failed to apply: %s "
                            "(%d)",
                            format, pcmk_rc_str(pcmk_legacy2rc(test_rc)),
                            test_rc);
                }
                free_xml(cib_copy);
            },
            {}
        );
    }

    if (pcmk__str_eq(section, XML_CIB_TAG_STATUS, pcmk__str_casei)) {
        /* Throttle the amount of costly validation we perform due to status updates
         * a) we don't really care whats in the status section
         * b) we don't validate any of its contents at the moment anyway
         */
        check_schema = FALSE;
    }

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

    if (*config_changed && !pcmk_is_set(call_options, cib_no_mtime)) {
        const char *schema = crm_element_value(scratch, XML_ATTR_VALIDATION);

        pcmk__xe_add_last_written(scratch);
        if (schema) {
            static int minimum_schema = 0;
            int current_schema = get_schema_version(schema);

            if (minimum_schema == 0) {
                minimum_schema = get_schema_version("pacemaker-1.2");
            }

            /* Does the CIB support the "update-*" attributes... */
            if (current_schema >= minimum_schema) {
                const char *origin = crm_element_value(req, F_ORIG);

                CRM_LOG_ASSERT(origin != NULL);
                crm_xml_replace(scratch, XML_ATTR_UPDATE_ORIG, origin);
                crm_xml_replace(scratch, XML_ATTR_UPDATE_CLIENT,
                                crm_element_value(req, F_CIB_CLIENTNAME));
                crm_xml_replace(scratch, XML_ATTR_UPDATE_USER, crm_element_value(req, F_CIB_USER));
            }
        }
    }

    crm_trace("Perform validation: %s", pcmk__btoa(check_schema));
    if ((rc == pcmk_ok) && check_schema && !validate_xml(scratch, NULL, TRUE)) {
        const char *current_schema = crm_element_value(scratch,
                                                       XML_ATTR_VALIDATION);

        crm_warn("Updated CIB does not validate against %s schema",
                 pcmk__s(current_schema, "unspecified"));
        rc = -pcmk_err_schema_validation;
    }

  done:

    *result_cib = scratch;

    /* @TODO: This may not work correctly with cib_zero_copy, since we don't
     * keep the original CIB.
     */
    if ((rc != pcmk_ok) && cib_acl_enabled(patchset_cib, user)
        && xml_acl_filtered_copy(user, patchset_cib, scratch, result_cib)) {

        if (*result_cib == NULL) {
            crm_debug("Pre-filtered the entire cib result");
        }
        free_xml(scratch);
    }

    if(diff) {
        *diff = local_diff;
    } else {
        free_xml(local_diff);
    }

    free_xml(top);
    crm_trace("Done");
    return rc;
}

xmlNode *
cib_create_op(int call_id, const char *op, const char *host,
              const char *section, xmlNode *data, int call_options,
              const char *user_name)
{
    xmlNode *op_msg = create_xml_node(NULL, "cib_command");

    CRM_CHECK(op_msg != NULL, return NULL);

    crm_xml_add(op_msg, F_XML_TAGNAME, "cib_command");

    crm_xml_add(op_msg, F_TYPE, T_CIB);
    crm_xml_add(op_msg, F_CIB_OPERATION, op);
    crm_xml_add(op_msg, F_CIB_HOST, host);
    crm_xml_add(op_msg, F_CIB_SECTION, section);
    crm_xml_add_int(op_msg, F_CIB_CALLID, call_id);
    if (user_name) {
        crm_xml_add(op_msg, F_CIB_USER, user_name);
    }
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

    if (msg != NULL) {
        crm_element_value_int(msg, F_CIB_RC, &rc);
        crm_element_value_int(msg, F_CIB_CALLID, &call_id);
        output = get_message_xml(msg, F_CIB_CALLDATA);
    }

    blob = cib__lookup_id(call_id);

    if (blob == NULL) {
        crm_trace("No callback found for call %d", call_id);
    }

    if (cib == NULL) {
        crm_debug("No cib object supplied");
    }

    if (rc == -pcmk_err_diff_resync) {
        /* This is an internal value that clients do not and should not care about */
        rc = pcmk_ok;
    }

    if (blob && blob->callback && (rc == pcmk_ok || blob->only_success == FALSE)) {
        crm_trace("Invoking callback %s for call %d",
                  pcmk__s(blob->id, "without ID"), call_id);
        blob->callback(msg, call_id, rc, output, blob->user_data);

    } else if (cib && cib->op_callback == NULL && rc != pcmk_ok) {
        crm_warn("CIB command failed: %s", pcmk_strerror(rc));
        crm_log_xml_debug(msg, "Failed CIB Update");
    }

    /* This may free user_data, so do it after the callback */
    if (blob) {
        remove_cib_op_callback(call_id, FALSE);
    }

    if (cib && cib->op_callback != NULL) {
        crm_trace("Invoking global callback for call %d", call_id);
        cib->op_callback(msg, call_id, rc, output);
    }
    crm_trace("OP callback activated for %d", call_id);
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

    } else if (!pcmk__str_eq(entry->event, event, pcmk__str_casei)) {
        crm_trace("Skipping callback - event mismatch %p/%s vs. %s", entry, entry->event, event);
        return;
    }

    crm_trace("Invoking callback for %p/%s event...", entry, event);
    entry->callback(event, msg);
    crm_trace("Callback invoked...");
}

static pcmk__cluster_option_t cib_opts[] = {
    /* name, legacy name, type, allowed values,
     * default value, validator,
     * short description,
     * long description
     */
    {
        "enable-acl", NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        N_("Enable Access Control Lists (ACLs) for the CIB"),
        NULL
    },
    {
        "cluster-ipc-limit", NULL, "integer", NULL,
        "500", pcmk__valid_positive_number,
        N_("Maximum IPC message backlog before disconnecting a cluster daemon"),
        N_("Raise this if log has \"Evicting client\" messages for cluster daemon"
            " PIDs (a good value is the number of resources in the cluster"
            " multiplied by the number of nodes).")
    },
};

void
cib_metadata(void)
{
    const char *desc_short = "Cluster Information Base manager options";
    const char *desc_long = "Cluster options used by Pacemaker's Cluster "
                            "Information Base manager";

    gchar *s = pcmk__format_option_metadata("pacemaker-based", desc_short,
                                            desc_long, cib_opts,
                                            PCMK__NELEM(cib_opts));
    printf("%s", s);
    g_free(s);
}

static void
verify_cib_options(GHashTable *options)
{
    pcmk__validate_cluster_options(options, cib_opts, PCMK__NELEM(cib_opts));
}

const char *
cib_pref(GHashTable * options, const char *name)
{
    return pcmk__cluster_option(options, cib_opts, PCMK__NELEM(cib_opts),
                                name);
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

    config = pcmk_find_cib_element(current_cib, XML_CIB_TAG_CRMCONFIG);
    if (config) {
        pe_unpack_nvpairs(current_cib, config, XML_CIB_TAG_PROPSET, NULL,
                          options, CIB_OPTIONS_FIRST, TRUE, now, NULL);
    }

    verify_cib_options(options);

    crm_time_free(now);

    return TRUE;
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

    if(user_name == NULL) {
        user_name = getenv("CIB_user");
    }

    return delegate(cib, op, host, section, data, output_data, call_options, user_name);
}

/*!
 * \brief Apply a CIB update patch to a given CIB
 *
 * \param[in]  event   CIB update patch
 * \param[in]  input   CIB to patch
 * \param[out] output  Resulting CIB after patch
 * \param[in]  level   Log the patch at this log level (unless LOG_CRIT)
 *
 * \return Legacy Pacemaker return code
 * \note sbd calls this function
 */
int
cib_apply_patch_event(xmlNode *event, xmlNode *input, xmlNode **output,
                      int level)
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
        pcmk__output_t *out = NULL;

        rc = pcmk_rc2legacy(pcmk__log_output_new(&out));
        CRM_CHECK(rc == pcmk_ok, return rc);

        pcmk__output_set_log_level(out, level);
        rc = out->message(out, "xml-patchset", diff);
        out->finish(out, pcmk_rc2exitc(rc), true, NULL);
        pcmk__output_free(out);
        rc = pcmk_ok;
    }

    if (input != NULL) {
        rc = cib_process_diff(NULL, cib_none, NULL, event, diff, input, output,
                              NULL);

        if (rc != pcmk_ok) {
            crm_debug("Update didn't apply: %s (%d) %p",
                      pcmk_strerror(rc), rc, *output);

            if (rc == -pcmk_err_old_data) {
                crm_trace("Masking error, we already have the supplied update");
                return pcmk_ok;
            }
            free_xml(*output);
            *output = NULL;
            return rc;
        }
    }
    return rc;
}

#define log_signon_query_err(out, fmt, args...) do {    \
        if (out != NULL) {                              \
            out->err(out, fmt, ##args);                 \
        } else {                                        \
            crm_err(fmt, ##args);                       \
        }                                               \
    } while (0)

int
cib__signon_query(pcmk__output_t *out, cib_t **cib, xmlNode **cib_object)
{
    int rc = pcmk_rc_ok;
    cib_t *cib_conn = NULL;

    CRM_ASSERT(cib_object != NULL);

    if (cib == NULL) {
        cib_conn = cib_new();
    } else {
        if (*cib == NULL) {
            *cib = cib_new();
        }
        cib_conn = *cib;
    }

    if (cib_conn == NULL) {
        return ENOMEM;
    }

    if (cib_conn->state == cib_disconnected) {
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
        rc = pcmk_legacy2rc(rc);
    }

    if (rc != pcmk_rc_ok) {
        log_signon_query_err(out, "Could not connect to the CIB: %s",
                             pcmk_rc_str(rc));
        goto done;
    }

    if (out != NULL) {
        out->transient(out, "Querying CIB...");
    }
    rc = cib_conn->cmds->query(cib_conn, NULL, cib_object,
                               cib_scope_local|cib_sync_call);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        log_signon_query_err(out, "CIB query failed: %s", pcmk_rc_str(rc));
    }

done:
    if (cib == NULL) {
        cib__clean_up_connection(&cib_conn);
    }

    if ((rc == pcmk_rc_ok) && (*cib_object == NULL)) {
        return pcmk_rc_no_input;
    }
    return rc;
}

int
cib__clean_up_connection(cib_t **cib)
{
    int rc;

    if (*cib == NULL) {
        return pcmk_rc_ok;
    }

    rc = (*cib)->cmds->signoff(*cib);
    cib_delete(*cib);
    *cib = NULL;
    return pcmk_legacy2rc(rc);
}

// Deprecated functions kept only for backward API compatibility
// LCOV_EXCL_START

#include <crm/cib/util_compat.h>

const char *
get_object_path(const char *object_type)
{
    return pcmk_cib_xpath_for(object_type);
}

const char *
get_object_parent(const char *object_type)
{
    return pcmk_cib_parent_name_for(object_type);
}

xmlNode *
get_object_root(const char *object_type, xmlNode *the_root)
{
    return pcmk_find_cib_element(the_root, object_type);
}

// LCOV_EXCL_STOP
// End deprecated API

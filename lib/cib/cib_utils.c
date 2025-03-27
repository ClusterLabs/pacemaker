/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2025 the Pacemaker project contributors
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
#include <crm/common/cib_internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

gboolean
cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates)
{
    *epoch = -1;
    *updates = -1;
    *admin_epoch = -1;

    if (cib == NULL) {
        return FALSE;

    } else {
        crm_element_value_int(cib, PCMK_XA_EPOCH, epoch);
        crm_element_value_int(cib, PCMK_XA_NUM_UPDATES, updates);
        crm_element_value_int(cib, PCMK_XA_ADMIN_EPOCH, admin_epoch);
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
 * \internal
 * \brief Get the XML patchset from a CIB diff notification
 *
 * \param[in]  msg       CIB diff notification
 * \param[out] patchset  Where to store XML patchset
 *
 * \return Standard Pacemaker return code
 */
int
cib__get_notify_patchset(const xmlNode *msg, const xmlNode **patchset)
{
    int rc = pcmk_err_generic;
    xmlNode *wrapper = NULL;

    pcmk__assert(patchset != NULL);
    *patchset = NULL;

    if (msg == NULL) {
        crm_err("CIB diff notification received with no XML");
        return ENOMSG;
    }

    if ((crm_element_value_int(msg, PCMK__XA_CIB_RC, &rc) != 0)
        || (rc != pcmk_ok)) {

        crm_warn("Ignore failed CIB update: %s " QB_XS " rc=%d",
                 pcmk_strerror(rc), rc);
        crm_log_xml_debug(msg, "failed");
        return pcmk_legacy2rc(rc);
    }

    wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT, NULL, NULL);
    *patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if (*patchset == NULL) {
        crm_err("CIB diff notification received with no patchset");
        return ENOMSG;
    }
    return pcmk_rc_ok;
}

/*!
 * \brief Create XML for a new (empty) CIB
 *
 * \param[in] cib_epoch  What to use as \c PCMK_XA_EPOCH CIB attribute
 *
 * \return Newly created XML for empty CIB
 *
 * \note It is the caller's responsibility to free the result with
 *       \c pcmk__xml_free().
 */
xmlNode *
createEmptyCib(int cib_epoch)
{
    xmlNode *cib_root = NULL, *config = NULL;

    cib_root = pcmk__xe_create(NULL, PCMK_XE_CIB);
    crm_xml_add(cib_root, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    crm_xml_add(cib_root, PCMK_XA_VALIDATE_WITH, pcmk__highest_schema_name());

    crm_xml_add_int(cib_root, PCMK_XA_EPOCH, cib_epoch);
    crm_xml_add_int(cib_root, PCMK_XA_NUM_UPDATES, 0);
    crm_xml_add_int(cib_root, PCMK_XA_ADMIN_EPOCH, 0);

    config = pcmk__xe_create(cib_root, PCMK_XE_CONFIGURATION);
    pcmk__xe_create(cib_root, PCMK_XE_STATUS);

    pcmk__xe_create(config, PCMK_XE_CRM_CONFIG);
    pcmk__xe_create(config, PCMK_XE_NODES);
    pcmk__xe_create(config, PCMK_XE_RESOURCES);
    pcmk__xe_create(config, PCMK_XE_CONSTRAINTS);

#if PCMK__RESOURCE_STICKINESS_DEFAULT != 0
    {
        xmlNode *rsc_defaults = pcmk__xe_create(config, PCMK_XE_RSC_DEFAULTS);
        xmlNode *meta = pcmk__xe_create(rsc_defaults, PCMK_XE_META_ATTRIBUTES);
        xmlNode *nvpair = pcmk__xe_create(meta, PCMK_XE_NVPAIR);

        crm_xml_add(meta, PCMK_XA_ID, "build-resource-defaults");
        crm_xml_add(nvpair, PCMK_XA_ID, "build-" PCMK_META_RESOURCE_STICKINESS);
        crm_xml_add(nvpair, PCMK_XA_NAME, PCMK_META_RESOURCE_STICKINESS);
        crm_xml_add_int(nvpair, PCMK_XA_VALUE,
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
        value = pcmk__cluster_option(options, PCMK_OPT_ENABLE_ACL);
        rc = crm_is_true(value);
        g_hash_table_destroy(options);
    }

    crm_trace("CIB ACL is %s", rc ? "enabled" : "disabled");
    return rc;
}

/*!
 * \internal
 * \brief Determine whether to perform operations on a scratch copy of the CIB
 *
 * \param[in] op            CIB operation
 * \param[in] section       CIB section
 * \param[in] call_options  CIB call options
 *
 * \return \p true if we should make a copy of the CIB, or \p false otherwise
 */
static bool
should_copy_cib(const char *op, const char *section, int call_options)
{
    if (pcmk_is_set(call_options, cib_dryrun)) {
        // cib_dryrun implies a scratch copy by definition; no side effects
        return true;
    }

    if (pcmk__str_eq(op, PCMK__CIB_REQUEST_COMMIT_TRANSACT, pcmk__str_none)) {
        /* Commit-transaction must make a copy for atomicity. We must revert to
         * the original CIB if the entire transaction cannot be applied
         * successfully.
         */
        return true;
    }

    if (pcmk_is_set(call_options, cib_transaction)) {
        /* If cib_transaction is set, then we're in the process of committing a
         * transaction. The commit-transaction request already made a scratch
         * copy, and we're accumulating changes in that copy.
         */
        return false;
    }

    if (pcmk__str_eq(section, PCMK_XE_STATUS, pcmk__str_none)) {
        /* Copying large CIBs accounts for a huge percentage of our CIB usage,
         * and this avoids some of it.
         *
         * @TODO: Is this safe? See discussion at
         * https://github.com/ClusterLabs/pacemaker/pull/3094#discussion_r1211400690.
         */
        return false;
    }

    // Default behavior is to operate on a scratch copy
    return true;
}

int
cib_perform_op(cib_t *cib, const char *op, uint32_t call_options,
               cib__op_fn_t fn, bool is_query, const char *section,
               xmlNode *req, xmlNode *input, bool manage_counters,
               bool *config_changed, xmlNode **current_cib,
               xmlNode **result_cib, xmlNode **diff, xmlNode **output)
{
    int rc = pcmk_ok;
    bool check_schema = true;
    bool make_copy = true;
    xmlNode *top = NULL;
    xmlNode *scratch = NULL;
    xmlNode *patchset_cib = NULL;
    xmlNode *local_diff = NULL;

    const char *user = crm_element_value(req, PCMK__XA_CIB_USER);
    bool with_digest = false;

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
    *config_changed = false;

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
            *output = pcmk__xml_copy(NULL, *output);

        } else if ((*output)->doc == (*current_cib)->doc) {
            /* Give them a copy they can free */
            *output = pcmk__xml_copy(NULL, *output);
        }

        pcmk__xml_free(cib_filtered);
        return rc;
    }

    make_copy = should_copy_cib(op, section, call_options);

    if (!make_copy) {
        /* Conditional on v2 patch style */

        scratch = *current_cib;

        // Make a copy of the top-level element to store version details
        top = pcmk__xe_create(NULL, (const char *) scratch->name);
        pcmk__xe_copy_attrs(top, scratch, pcmk__xaf_none);
        patchset_cib = top;

        xml_track_changes(scratch, user, NULL, cib_acl_enabled(scratch, user));
        rc = (*fn) (op, call_options, section, req, input, scratch, &scratch, output);

        /* If scratch points to a new object now (for example, after an erase
         * operation), then *current_cib should point to the same object.
         */
        *current_cib = scratch;

    } else {
        scratch = pcmk__xml_copy(NULL, *current_cib);
        patchset_cib = *current_cib;

        xml_track_changes(scratch, user, NULL, cib_acl_enabled(scratch, user));
        rc = (*fn) (op, call_options, section, req, input, *current_cib,
                    &scratch, output);

        if (!pcmk__xml_doc_all_flags_set(scratch->doc, pcmk__xf_tracking)) {
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

    /* If the CIB is from a file, we don't need to check that the feature set is
     * supported.  All we care about in that case is the schema version, which
     * is checked elsewhere.
     */
    if (scratch && (cib == NULL || cib->variant != cib_file)) {
        const char *new_version = crm_element_value(scratch, PCMK_XA_CRM_FEATURE_SET);

        rc = pcmk__check_feature_set(new_version);
        if (rc != pcmk_rc_ok) {
            crm_err("Discarding update with feature set '%s' greater than "
                    "our own '%s'", new_version, CRM_FEATURE_SET);
            rc = pcmk_rc2legacy(rc);
            goto done;
        }
    }

    if (patchset_cib != NULL) {
        int old = 0;
        int new = 0;

        crm_element_value_int(scratch, PCMK_XA_ADMIN_EPOCH, &new);
        crm_element_value_int(patchset_cib, PCMK_XA_ADMIN_EPOCH, &old);

        if (old > new) {
            crm_err("%s went backwards: %d -> %d (Opts: %#x)",
                    PCMK_XA_ADMIN_EPOCH, old, new, call_options);
            crm_log_xml_warn(req, "Bad Op");
            crm_log_xml_warn(input, "Bad Data");
            rc = -pcmk_err_old_data;

        } else if (old == new) {
            crm_element_value_int(scratch, PCMK_XA_EPOCH, &new);
            crm_element_value_int(patchset_cib, PCMK_XA_EPOCH, &old);
            if (old > new) {
                crm_err("%s went backwards: %d -> %d (Opts: %#x)",
                        PCMK_XA_EPOCH, old, new, call_options);
                crm_log_xml_warn(req, "Bad Op");
                crm_log_xml_warn(input, "Bad Data");
                rc = -pcmk_err_old_data;
            }
        }
    }

    crm_trace("Massaging CIB contents");
    pcmk__strip_xml_text(scratch);

    if (make_copy) {
        static time_t expires = 0;
        time_t tm_now = time(NULL);

        if (expires < tm_now) {
            expires = tm_now + 60;  /* Validate clients are correctly applying v2-style diffs at most once a minute */
            with_digest = true;
        }
    }

    local_diff = xml_create_patchset(0, patchset_cib, scratch,
                                     config_changed, manage_counters);

    pcmk__log_xml_changes(LOG_TRACE, scratch);
    pcmk__xml_commit_changes(scratch->doc);

    if(local_diff) {
        patchset_process_digest(local_diff, patchset_cib, scratch, with_digest);
        pcmk__log_xml_patchset(LOG_INFO, local_diff);
        crm_log_xml_trace(local_diff, "raw patch");
    }

    if (make_copy && (local_diff != NULL)) {
        // Original to compare against doesn't exist
        pcmk__if_tracing(
            {
                // Validate the calculated patch set
                int test_rc = pcmk_ok;
                int format = 1;
                xmlNode *cib_copy = pcmk__xml_copy(NULL, patchset_cib);

                crm_element_value_int(local_diff, PCMK_XA_FORMAT, &format);
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
                pcmk__xml_free(cib_copy);
            },
            {}
        );
    }

    if (pcmk__str_eq(section, PCMK_XE_STATUS, pcmk__str_casei)) {
        /* Throttle the amount of costly validation we perform due to status updates
         * a) we don't really care whats in the status section
         * b) we don't validate any of its contents at the moment anyway
         */
        check_schema = false;
    }

    /* === scratch must not be modified after this point ===
     * Exceptions, anything in:

     static filter_t filter[] = {
     { 0, PCMK_XA_CRM_DEBUG_ORIGIN },
     { 0, PCMK_XA_CIB_LAST_WRITTEN },
     { 0, PCMK_XA_UPDATE_ORIGIN },
     { 0, PCMK_XA_UPDATE_CLIENT },
     { 0, PCMK_XA_UPDATE_USER },
     };
     */

    if (*config_changed && !pcmk_is_set(call_options, cib_no_mtime)) {
        const char *schema = crm_element_value(scratch, PCMK_XA_VALIDATE_WITH);

        if (schema == NULL) {
            rc = -pcmk_err_cib_corrupt;
        }

        pcmk__xe_add_last_written(scratch);
        pcmk__warn_if_schema_deprecated(schema);

        /* Make values of origin, client, and user in scratch match
         * the ones in req (if the schema allows the attributes)
         */
        if (pcmk__cmp_schemas_by_name(schema, "pacemaker-1.2") >= 0) {
            const char *origin = crm_element_value(req, PCMK__XA_SRC);
            const char *client = crm_element_value(req,
                                                   PCMK__XA_CIB_CLIENTNAME);

            if (origin != NULL) {
                crm_xml_add(scratch, PCMK_XA_UPDATE_ORIGIN, origin);
            } else {
                pcmk__xe_remove_attr(scratch, PCMK_XA_UPDATE_ORIGIN);
            }

            if (client != NULL) {
                crm_xml_add(scratch, PCMK_XA_UPDATE_CLIENT, user);
            } else {
                pcmk__xe_remove_attr(scratch, PCMK_XA_UPDATE_CLIENT);
            }

            if (user != NULL) {
                crm_xml_add(scratch, PCMK_XA_UPDATE_USER, user);
            } else {
                pcmk__xe_remove_attr(scratch, PCMK_XA_UPDATE_USER);
            }
        }
    }

    crm_trace("Perform validation: %s", pcmk__btoa(check_schema));
    if ((rc == pcmk_ok) && check_schema
        && !pcmk__configured_schema_validates(scratch)) {
        rc = -pcmk_err_schema_validation;
    }

  done:

    *result_cib = scratch;

    /* @TODO: This may not work correctly with !make_copy, since we don't
     * keep the original CIB.
     */
    if ((rc != pcmk_ok) && cib_acl_enabled(patchset_cib, user)
        && xml_acl_filtered_copy(user, patchset_cib, scratch, result_cib)) {

        if (*result_cib == NULL) {
            crm_debug("Pre-filtered the entire cib result");
        }
        pcmk__xml_free(scratch);
    }

    if(diff) {
        *diff = local_diff;
    } else {
        pcmk__xml_free(local_diff);
    }

    pcmk__xml_free(top);
    crm_trace("Done");
    return rc;
}

int
cib__create_op(cib_t *cib, const char *op, const char *host,
               const char *section, xmlNode *data, int call_options,
               const char *user_name, const char *client_name,
               xmlNode **op_msg)
{
    CRM_CHECK((cib != NULL) && (op_msg != NULL), return -EPROTO);

    *op_msg = pcmk__xe_create(NULL, PCMK__XE_CIB_COMMAND);

    cib->call_id++;
    if (cib->call_id < 1) {
        cib->call_id = 1;
    }

    crm_xml_add(*op_msg, PCMK__XA_T, PCMK__VALUE_CIB);
    crm_xml_add(*op_msg, PCMK__XA_CIB_OP, op);
    crm_xml_add(*op_msg, PCMK__XA_CIB_HOST, host);
    crm_xml_add(*op_msg, PCMK__XA_CIB_SECTION, section);
    crm_xml_add(*op_msg, PCMK__XA_CIB_USER, user_name);
    crm_xml_add(*op_msg, PCMK__XA_CIB_CLIENTNAME, client_name);
    crm_xml_add_int(*op_msg, PCMK__XA_CIB_CALLID, cib->call_id);

    crm_trace("Sending call options: %.8lx, %d", (long)call_options, call_options);
    crm_xml_add_int(*op_msg, PCMK__XA_CIB_CALLOPT, call_options);

    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(*op_msg, PCMK__XE_CIB_CALLDATA);

        pcmk__xml_copy(wrapper, data);
    }

    return pcmk_ok;
}

/*!
 * \internal
 * \brief Check whether a CIB request is supported in a transaction
 *
 * \param[in] request  CIB request
 *
 * \return Standard Pacemaker return code
 */
static int
validate_transaction_request(const xmlNode *request)
{
    const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
    const char *host = crm_element_value(request, PCMK__XA_CIB_HOST);
    const cib__operation_t *operation = NULL;
    int rc = cib__get_operation(op, &operation);

    if (rc != pcmk_rc_ok) {
        // cib__get_operation() logs error
        return rc;
    }

    if (!pcmk_is_set(operation->flags, cib__op_attr_transaction)) {
        crm_err("Operation %s is not supported in CIB transactions", op);
        return EOPNOTSUPP;
    }

    if (host != NULL) {
        crm_err("Operation targeting a specific node (%s) is not supported in "
                "a CIB transaction",
                host);
        return EOPNOTSUPP;
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Append a CIB request to a CIB transaction
 *
 * \param[in,out] cib      CIB client whose transaction to extend
 * \param[in,out] request  Request to add to transaction
 *
 * \return Legacy Pacemaker return code
 */
int
cib__extend_transaction(cib_t *cib, xmlNode *request)
{
    int rc = pcmk_rc_ok;

    pcmk__assert((cib != NULL) && (request != NULL));

    rc = validate_transaction_request(request);

    if ((rc == pcmk_rc_ok) && (cib->transaction == NULL)) {
        rc = pcmk_rc_no_transaction;
    }

    if (rc == pcmk_rc_ok) {
        pcmk__xml_copy(cib->transaction, request);

    } else {
        const char *op = crm_element_value(request, PCMK__XA_CIB_OP);
        const char *client_id = NULL;

        cib->cmds->client_id(cib, NULL, &client_id);
        crm_err("Failed to add '%s' operation to transaction for client %s: %s",
                op, pcmk__s(client_id, "(unidentified)"), pcmk_rc_str(rc));
        crm_log_xml_info(request, "failed");
    }
    return pcmk_rc2legacy(rc);
}

void
cib_native_callback(cib_t * cib, xmlNode * msg, int call_id, int rc)
{
    xmlNode *output = NULL;
    cib_callback_client_t *blob = NULL;

    if (msg != NULL) {
        xmlNode *wrapper = NULL;

        crm_element_value_int(msg, PCMK__XA_CIB_RC, &rc);
        crm_element_value_int(msg, PCMK__XA_CIB_CALLID, &call_id);
        wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_CALLDATA, NULL, NULL);
        output = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);
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

    } else if ((cib != NULL) && (rc != pcmk_ok)) {
        crm_warn("CIB command failed: %s", pcmk_strerror(rc));
        crm_log_xml_debug(msg, "Failed CIB Update");
    }

    /* This may free user_data, so do it after the callback */
    if (blob) {
        remove_cib_op_callback(call_id, FALSE);
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

    event = crm_element_value(msg, PCMK__XA_SUBT);

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

    config = pcmk_find_cib_element(current_cib, PCMK_XE_CRM_CONFIG);
    if (config) {
        pcmk_rule_input_t rule_input = {
            .now = now,
        };

        pcmk_unpack_nvpair_blocks(config, PCMK_XE_CLUSTER_PROPERTY_SET,
                                  PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, &rule_input,
                                  options, NULL);
    }

    pcmk__validate_cluster_options(options);

    crm_time_free(now);

    return TRUE;
}

int
cib_internal_op(cib_t * cib, const char *op, const char *host,
                const char *section, xmlNode * data,
                xmlNode ** output_data, int call_options, const char *user_name)
{
    int (*delegate)(cib_t *cib, const char *op, const char *host,
                    const char *section, xmlNode *data, xmlNode **output_data,
                    int call_options, const char *user_name) = NULL;

    if (cib == NULL) {
        return -EINVAL;
    }

    delegate = cib->delegate_fn;
    if (delegate == NULL) {
        return -EPROTONOSUPPORT;
    }
    if (user_name == NULL) {
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

    xmlNode *wrapper = NULL;
    xmlNode *diff = NULL;

    pcmk__assert((event != NULL) && (input != NULL) && (output != NULL));

    crm_element_value_int(event, PCMK__XA_CIB_RC, &rc);
    wrapper = pcmk__xe_first_child(event, PCMK__XE_CIB_UPDATE_RESULT, NULL,
                                   NULL);
    diff = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if (rc < pcmk_ok || diff == NULL) {
        return rc;
    }

    if (level > LOG_CRIT) {
        pcmk__log_xml_patchset(level, diff);
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
            pcmk__xml_free(*output);
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

    pcmk__assert(cib_object != NULL);

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
    rc = cib_conn->cmds->query(cib_conn, NULL, cib_object, cib_sync_call);
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
cib__signon_attempts(cib_t *cib, enum cib_conn_type type, int attempts)
{
    int rc = pcmk_rc_ok;

    crm_trace("Attempting connection to CIB manager (up to %d time%s)",
              attempts, pcmk__plural_s(attempts));

    for (int remaining = attempts - 1; remaining >= 0; --remaining) {
        rc = cib->cmds->signon(cib, crm_system_name, type);

        if ((rc == pcmk_rc_ok)
            || (remaining == 0)
            || ((errno != EAGAIN) && (errno != EALREADY))) {
            break;
        }

        // Retry after soft error (interrupted by signal, etc.)
        pcmk__sleep_ms((attempts - remaining) * 500);
        crm_debug("Re-attempting connection to CIB manager (%d attempt%s remaining)",
                  remaining, pcmk__plural_s(remaining));
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

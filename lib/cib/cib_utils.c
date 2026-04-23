/*
 * Original copyright 2004 International Business Machines
 * Later changes copyright 2008-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#include <crm_internal.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/utsname.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/common/xml.h>

gboolean
cib_version_details(xmlNode * cib, int *admin_epoch, int *epoch, int *updates)
{
    *epoch = -1;
    *updates = -1;
    *admin_epoch = -1;

    if (cib == NULL) {
        return FALSE;
    }

    pcmk__xe_get_int(cib, PCMK_XA_EPOCH, epoch);
    pcmk__xe_get_int(cib, PCMK_XA_NUM_UPDATES, updates);
    pcmk__xe_get_int(cib, PCMK_XA_ADMIN_EPOCH, admin_epoch);
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
        pcmk__err("CIB diff notification received with no XML");
        return ENOMSG;
    }

    if ((pcmk__xe_get_int(msg, PCMK__XA_CIB_RC, &rc) != pcmk_rc_ok)
        || (rc != pcmk_ok)) {

        pcmk__warn("Ignore failed CIB update: %s " QB_XS " rc=%d",
                   pcmk_strerror(rc), rc);
        pcmk__log_xml_debug(msg, "failed");
        return pcmk_legacy2rc(rc);
    }

    wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_UPDATE_RESULT, NULL, NULL);
    *patchset = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if (*patchset == NULL) {
        pcmk__err("CIB diff notification received with no patchset");
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
    pcmk__xe_set(cib_root, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    pcmk__xe_set(cib_root, PCMK_XA_VALIDATE_WITH, pcmk__highest_schema_name());

    pcmk__xe_set_int(cib_root, PCMK_XA_ADMIN_EPOCH, 0);
    pcmk__xe_set_int(cib_root, PCMK_XA_EPOCH, cib_epoch);
    pcmk__xe_set_int(cib_root, PCMK_XA_NUM_UPDATES, 0);

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

        pcmk__xe_set(meta, PCMK_XA_ID, "build-resource-defaults");
        pcmk__xe_set(nvpair, PCMK_XA_ID,
                     "build-" PCMK_META_RESOURCE_STICKINESS);
        pcmk__xe_set(nvpair, PCMK_XA_NAME, PCMK_META_RESOURCE_STICKINESS);
        pcmk__xe_set_int(nvpair, PCMK_XA_VALUE,
                         PCMK__RESOURCE_STICKINESS_DEFAULT);
    }
#endif
    return cib_root;
}

static void
read_config(GHashTable *options, xmlNode *current_cib)
{
    crm_time_t *now = NULL;
    pcmk_rule_input_t rule_input = { 0, };
    xmlNode *config = pcmk_find_cib_element(current_cib, PCMK_XE_CRM_CONFIG);

    if (config == NULL) {
        return;
    }

    now = crm_time_new(NULL);
    rule_input.now = now;

    pcmk_unpack_nvpair_blocks(config, PCMK_XE_CLUSTER_PROPERTY_SET,
                              PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, &rule_input,
                              options, NULL);
    crm_time_free(now);
}

static bool
cib_acl_enabled(xmlNode *xml, const char *user)
{
    const char *value = NULL;
    GHashTable *options = NULL;
    bool rc = false;

    if ((xml == NULL) || !pcmk_acl_required(user)) {
        return false;
    }

    options = pcmk__strkey_table(free, free);
    read_config(options, xml);
    value = pcmk__cluster_option(options, PCMK_OPT_ENABLE_ACL);

    rc = pcmk__is_true(value);
    g_hash_table_destroy(options);
    return rc;
}

int
cib__perform_query(const char *op, uint32_t call_options, cib__op_fn_t fn,
                   const char *section, xmlNode *req, xmlNode *input,
                   xmlNode **current_cib, xmlNode **output)
{
    int rc = pcmk_rc_ok;
    const char *user = NULL;

    xmlNode *cib = NULL;
    xmlNode *cib_filtered = NULL;

    pcmk__assert((op != NULL) && (fn != NULL) && (req != NULL)
                 && (current_cib != NULL) && (*current_cib != NULL)
                 && (output != NULL) && (*output == NULL));

    user = pcmk__xe_get(req, PCMK__XA_CIB_USER);
    cib = *current_cib;

    if (cib_acl_enabled(*current_cib, user)
        && xml_acl_filtered_copy(user, *current_cib, *current_cib,
                                 &cib_filtered)) {

        if (cib_filtered == NULL) {
            pcmk__debug("Pre-filtered the entire cib");
            return EACCES;
        }
        cib = cib_filtered;
        pcmk__log_xml_trace(cib, "filtered");
    }

    pcmk__trace("Processing %s for section '%s', user '%s'", op,
                pcmk__s(section, "(null)"), pcmk__s(user, "(null)"));
    pcmk__log_xml_trace(req, "request");

    rc = fn(op, call_options, section, req, input, &cib, output);

    if (*output == NULL) {
        // Do nothing

    } else if (cib_filtered == *output) {
        // Let them have this copy
        cib_filtered = NULL;

    } else if (*output == *current_cib) {
        // They already know not to free it

    } else if ((cib_filtered != NULL)
               && ((*output)->doc == cib_filtered->doc)) {
        // We're about to free the document of which *output is a part
        *output = pcmk__xml_copy(NULL, *output);

    } else if ((*output)->doc == (*current_cib)->doc) {
        // Give them a copy they can free
        *output = pcmk__xml_copy(NULL, *output);
    }

    pcmk__xml_free(cib_filtered);
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
    if (pcmk__is_set(call_options, cib_dryrun)) {
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

    if (pcmk__is_set(call_options, cib_transaction)) {
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

/*!
 * \internal
 * \brief Validate that a new CIB's feature set is not newer than ours
 *
 * Return an error if the new CIB's feature set is newer than ours.
 *
 * \param[in] new_cib  Result CIB after performing operation
 *
 * \return Standard Pacemaker return code
 */
static int
check_new_feature_set(const xmlNode *new_cib)
{
    const char *new_version = pcmk__xe_get(new_cib, PCMK_XA_CRM_FEATURE_SET);
    int rc = pcmk__check_feature_set(new_version);

    if (rc == pcmk_rc_ok) {
        return pcmk_rc_ok;
    }

    pcmk__err("Discarding update with feature set %s greater than our own (%s)",
              new_version, CRM_FEATURE_SET);
    return rc;
}

/*!
 * \internal
 * \brief Validate that a new CIB has a newer version attribute than an old CIB
 *
 * Return an error if the value of the given attribute is higher in the old CIB
 * than in the new CIB.
 *
 * \param[in] attr     Name of version attribute to check
 * \param[in] old_cib  \c PCMK_XE_CIB element before performing operation
 * \param[in] new_cib  \c PCMK_XE_CIB element from result of operation
 * \param[in] request  CIB request
 * \param[in] input    Input data for CIB request
 *
 * \return Standard Pacemaker return code
 *
 * \note \p old_cib only has to contain the top-level \c PCMK_XE_CIB element. It
 *       might not be a full CIB.
 */
static int
check_cib_version_attr(const char *attr, const xmlNode *old_cib,
                       const xmlNode *new_cib, const xmlNode *request,
                       const xmlNode *input)
{
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    int old_version = 0;
    int new_version = 0;

    pcmk__xe_get_int(old_cib, attr, &old_version);
    pcmk__xe_get_int(new_cib, attr, &new_version);

    if (old_version < new_version) {
        return pcmk_rc_ok;
    }

    if (old_version == new_version) {
        return pcmk_rc_undetermined;
    }

    pcmk__err("%s went backwards in %s request: %d -> %d", attr, op,
              old_version, new_version);
    pcmk__log_xml_warn(request, "bad-request");
    pcmk__log_xml_warn(input, "bad-input");

    return pcmk_rc_old_data;
}

/*!
 * \internal
 * \brief Validate that a new CIB has newer versions than an old CIB
 *
 * Return an error if:
 * - \c PCMK_XA_ADMIN_EPOCH is newer in the old CIB than in the new CIB; or
 * - The \c PCMK_XA_ADMIN_EPOCH attributes are equal and \c PCMK_XA_EPOCH is
 *   newer in the old CIB than in the new CIB.
 *
 * \param[in] old_cib  \c PCMK_XE_CIB element before performing operation
 * \param[in] new_cib  \c PCMK_XE_CIB element from result of operation
 * \param[in] request  CIB request
 * \param[in] input    Input data for CIB request
 *
 * \return Standard Pacemaker return code
 *
 * \note \p old_cib only has to contain the top-level \c PCMK_XE_CIB element. It
 *       might not be a full CIB.
 */
static int
check_cib_versions(const xmlNode *old_cib, const xmlNode *new_cib,
                   const xmlNode *request, const xmlNode *input)
{
    int rc = check_cib_version_attr(PCMK_XA_ADMIN_EPOCH, old_cib, new_cib,
                                    request, input);

    if (rc != pcmk_rc_undetermined) {
        return rc;
    }

    // @TODO Why aren't we checking PCMK_XA_NUM_UPDATES if epochs are equal?
    rc = check_cib_version_attr(PCMK_XA_EPOCH, old_cib, new_cib, request,
                                input);
    if (rc == pcmk_rc_undetermined) {
        rc = pcmk_rc_ok;
    }

    return rc;
}

/*!
 * \internal
 * \brief Set values for update origin host, client, and user in new CIB
 *
 * \param[in,out] new_cib  Result CIB after performing operation
 * \param[in]     request  CIB request (source of origin info)
 *
 * \return Standard Pacemaker return code
 */
static int
set_update_origin(xmlNode *new_cib, const xmlNode *request)
{
    const char *origin = pcmk__xe_get(request, PCMK__XA_SRC);
    const char *client = pcmk__xe_get(request, PCMK__XA_CIB_CLIENTNAME);
    const char *user = pcmk__xe_get(request, PCMK__XA_CIB_USER);
    const char *schema = pcmk__xe_get(new_cib, PCMK_XA_VALIDATE_WITH);

    if (schema == NULL) {
        return pcmk_rc_cib_corrupt;
    }

    pcmk__xe_add_last_written(new_cib);
    pcmk__warn_if_schema_deprecated(schema);

    // pacemaker-1.2 is the earliest schema version that allow these attributes
    if (pcmk__cmp_schemas_by_name(schema, "pacemaker-1.2") < 0) {
        return pcmk_rc_ok;
    }

    if (origin != NULL) {
        pcmk__xe_set(new_cib, PCMK_XA_UPDATE_ORIGIN, origin);
    } else {
        pcmk__xe_remove_attr(new_cib, PCMK_XA_UPDATE_ORIGIN);
    }

    if (client != NULL) {
        pcmk__xe_set(new_cib, PCMK_XA_UPDATE_CLIENT, client);
    } else {
        pcmk__xe_remove_attr(new_cib, PCMK_XA_UPDATE_CLIENT);
    }

    if (user != NULL) {
        pcmk__xe_set(new_cib, PCMK_XA_UPDATE_USER, user);
    } else {
        pcmk__xe_remove_attr(new_cib, PCMK_XA_UPDATE_USER);
    }

    return pcmk_rc_ok;
}

int
cib_perform_op(enum cib_variant variant, const char *op, uint32_t call_options,
               cib__op_fn_t fn, const char *section, xmlNode *req,
               xmlNode *input, bool manage_counters, bool *config_changed,
               xmlNode **current_cib, xmlNode **result_cib, xmlNode **diff,
               xmlNode **output)
{
    int rc = pcmk_rc_ok;

    /* PCMK_XE_CIB element containing version numbers from before the operation.
     * This may or may not point to a full CIB XML tree. Do not free, as this
     * will be used as an alias for another pointer.
     */
    xmlNode *old_versions = NULL;

    xmlNode *top = NULL;
    xmlNode *working_cib = NULL;

    const char *user = NULL;
    bool enable_acl = false;

    pcmk__assert((op != NULL) && (fn != NULL) && (req != NULL)
                 && (config_changed != NULL) && (!*config_changed)
                 && (current_cib != NULL) && (*current_cib != NULL)
                 && (result_cib != NULL) && (*result_cib == NULL)
                 && (diff != NULL) && (*diff == NULL)
                 && (output != NULL) && (*output == NULL));

    user = pcmk__xe_get(req, PCMK__XA_CIB_USER);
    enable_acl = cib_acl_enabled(*current_cib, user);

    if (!should_copy_cib(op, section, call_options)) {
        // Make a copy of the top-level element to store version details
        top = pcmk__xe_create(NULL, (const char *) (*current_cib)->name);
        pcmk__xe_copy_attrs(top, *current_cib, pcmk__xaf_none);
        old_versions = top;

        pcmk__xml_commit_changes((*current_cib)->doc);
        pcmk__xml_doc_set_flags((*current_cib)->doc, pcmk__xf_tracking);
        if (enable_acl) {
            pcmk__enable_acls((*current_cib)->doc, (*current_cib)->doc, user);
        }

        pcmk__trace("Processing %s for section '%s', user '%s'", op,
                    pcmk__s(section, "(null)"), pcmk__s(user, "(null)"));
        pcmk__log_xml_trace(req, "request");

        rc = fn(op, call_options, section, req, input, current_cib, output);

        /* Set working_cib to *current_cib after fn(), in case *current_cib
         * points somewhere else now (for example, after a erase or full-CIB
         * replace op).
         */
        working_cib = *current_cib;

        /* @TODO Enable tracking and ACLs and calculate changes? If working_cib
         * and *current_cib point to a new object, then change tracking and
         * unpacked ACLs didn't carry over to it.
         */

    } else {
        working_cib = pcmk__xml_copy(NULL, *current_cib);
        old_versions = *current_cib;

        pcmk__xml_doc_set_flags(working_cib->doc, pcmk__xf_tracking);
        if (enable_acl) {
            pcmk__enable_acls((*current_cib)->doc, working_cib->doc, user);
        }

        pcmk__trace("Processing %s for section '%s', user '%s'", op,
                    pcmk__s(section, "(null)"), pcmk__s(user, "(null)"));
        pcmk__log_xml_trace(req, "request");

        rc = fn(op, call_options, section, req, input, &working_cib, output);

        /* @TODO This appears to be a hack to determine whether working_cib
         * points to a new object now, without saving the old pointer (which may
         * be invalid now) for comparison. Confirm this, and check more clearly.
         */
        if (!pcmk__xml_doc_all_flags_set(working_cib->doc, pcmk__xf_tracking)) {
            pcmk__trace("Inferring changes after %s op", op);
            pcmk__xml_commit_changes(working_cib->doc);
            if (enable_acl) {
                pcmk__enable_acls((*current_cib)->doc, working_cib->doc, user);
            }
            pcmk__xml_mark_changes(*current_cib, working_cib);
        }

        pcmk__assert(*current_cib != working_cib);
    }

    // Allow ourselves to make any additional necessary changes
    xml_acl_disable(working_cib);

    if (rc != pcmk_rc_ok) {
        goto done;
    }

    if (working_cib == NULL) {
        rc = EINVAL;
        goto done;
    }

    if (xml_acl_denied(working_cib)) {
        pcmk__trace("ACL rejected part or all of the proposed changes");
        rc = EACCES;
        goto done;
    }

    /* If the CIB is from a file, we don't need to check that the feature set is
     * supported.  All we care about in that case is the schema version, which
     * is checked elsewhere.
     */
    if (variant != cib_file) {
        rc = check_new_feature_set(working_cib);
        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

    rc = check_cib_versions(old_versions, working_cib, req, input);

    pcmk__strip_xml_text(working_cib);

    /* If we didn't make a copy, the diff will only be accurate for the
     * top-level PCMK_XE_CIB element
     */
    *diff = xml_create_patchset(0, old_versions, working_cib, config_changed,
                                manage_counters);

    /* pcmk__xml_commit_changes() resets document private data, so call it even
     * if there were no changes.
     */
    pcmk__xml_commit_changes(working_cib->doc);

    if (*diff == NULL) {
        goto done;
    }

    pcmk__log_xml_patchset(LOG_INFO, *diff);

    /* working_cib must not be modified after this point, except for the
     * attributes for which pcmk__xa_filterable() returns true
     */

    if (*config_changed && !pcmk__is_set(call_options, cib_no_mtime)) {
        rc = set_update_origin(working_cib, req);
        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

    // Skip validation for status-only updates, since we allow anything there
    if ((rc == pcmk_rc_ok)
        && !pcmk__str_eq(section, PCMK_XE_STATUS, pcmk__str_casei)
        && !pcmk__configured_schema_validates(working_cib)) {

        rc = pcmk_rc_schema_validation;
    }

done:
    *result_cib = working_cib;

    /* @TODO This may not work correctly when !should_copy_cib(), since we don't
     * keep the original CIB.
     */
    if ((rc != pcmk_rc_ok) && cib_acl_enabled(old_versions, user)
        && xml_acl_filtered_copy(user, old_versions, working_cib, result_cib)) {

        if (*result_cib == NULL) {
            pcmk__debug("Pre-filtered the entire cib result");
        }
        pcmk__xml_free(working_cib);
    }

    pcmk__xml_free(top);
    pcmk__trace("Done");
    return rc;
}

int
cib__create_op(cib_t *cib, const char *op, const char *host,
               const char *section, xmlNode *data, int call_options,
               const char *user_name, const char *client_name,
               xmlNode **op_msg)
{
    CRM_CHECK((cib != NULL) && (op_msg != NULL), return EPROTO);

    *op_msg = pcmk__xe_create(NULL, PCMK__XE_CIB_COMMAND);

    cib->call_id++;
    if (cib->call_id < 1) {
        cib->call_id = 1;
    }

    pcmk__xe_set(*op_msg, PCMK__XA_T, PCMK__VALUE_CIB);
    pcmk__xe_set(*op_msg, PCMK__XA_CIB_OP, op);
    pcmk__xe_set(*op_msg, PCMK__XA_CIB_HOST, host);
    pcmk__xe_set(*op_msg, PCMK__XA_CIB_SECTION, section);
    pcmk__xe_set(*op_msg, PCMK__XA_CIB_USER, user_name);
    pcmk__xe_set(*op_msg, PCMK__XA_CIB_CLIENTNAME, client_name);
    pcmk__xe_set_int(*op_msg, PCMK__XA_CIB_CALLID, cib->call_id);

    pcmk__trace("Sending call options: %.8lx, %d", (long) call_options,
                call_options);
    pcmk__xe_set_int(*op_msg, PCMK__XA_CIB_CALLOPT, call_options);

    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(*op_msg, PCMK__XE_CIB_CALLDATA);

        pcmk__xml_copy(wrapper, data);
    }

    return pcmk_rc_ok;
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
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *host = pcmk__xe_get(request, PCMK__XA_CIB_HOST);
    const cib__operation_t *operation = NULL;
    int rc = cib__get_operation(op, &operation);

    if (rc != pcmk_rc_ok) {
        // cib__get_operation() logs error
        return rc;
    }

    if (!pcmk__is_set(operation->flags, cib__op_attr_transaction)) {
        pcmk__err("Operation %s is not supported in CIB transactions", op);
        return EOPNOTSUPP;
    }

    if (host != NULL) {
        pcmk__err("Operation targeting a specific node (%s) is not supported "
                  "in a CIB transaction",
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
 * \return Standard Pacemaker return code
 */
int
cib__extend_transaction(cib_t *cib, xmlNode *request)
{
    const char *op = pcmk__xe_get(request, PCMK__XA_CIB_OP);
    const char *client_id = NULL;
    int rc = pcmk_rc_ok;

    pcmk__assert((cib != NULL) && (request != NULL));

    rc = validate_transaction_request(request);

    if ((rc == pcmk_rc_ok) && (cib->transaction == NULL)) {
        rc = pcmk_rc_no_transaction;
    }

    if (rc == pcmk_rc_ok) {
        pcmk__xml_copy(cib->transaction, request);
        return pcmk_rc_ok;
    }

    cib->cmds->client_id(cib, NULL, &client_id);

    pcmk__err("Failed to add '%s' operation to transaction for client %s: %s",
              op, pcmk__s(client_id, "(unidentified)"), pcmk_rc_str(rc));
    pcmk__log_xml_info(request, "failed");

    return rc;
}

void
cib_native_callback(cib_t * cib, xmlNode * msg, int call_id, int rc)
{
    xmlNode *output = NULL;
    cib_callback_client_t *blob = NULL;

    if (msg != NULL) {
        xmlNode *wrapper = NULL;

        pcmk__xe_get_int(msg, PCMK__XA_CIB_RC, &rc);
        pcmk__xe_get_int(msg, PCMK__XA_CIB_CALLID, &call_id);
        wrapper = pcmk__xe_first_child(msg, PCMK__XE_CIB_CALLDATA, NULL, NULL);
        output = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);
    }

    blob = cib__lookup_id(call_id);

    if (blob == NULL) {
        pcmk__trace("No callback found for call %d", call_id);
    }

    if (cib == NULL) {
        pcmk__debug("No cib object supplied");
    }

    if (blob && blob->callback && (rc == pcmk_ok || blob->only_success == FALSE)) {
        pcmk__trace("Invoking callback %s for call %d",
                    pcmk__s(blob->id, "without ID"), call_id);
        blob->callback(msg, call_id, rc, output, blob->user_data);

    } else if ((cib != NULL) && (rc != pcmk_ok)) {
        pcmk__warn("CIB command failed: %s", pcmk_strerror(rc));
        pcmk__log_xml_debug(msg, "Failed CIB Update");
    }

    /* This may free user_data, so do it after the callback */
    if (blob) {
        remove_cib_op_callback(call_id, FALSE);
    }

    pcmk__trace("OP callback activated for %d", call_id);
}

void
cib_native_notify(gpointer data, gpointer user_data)
{
    xmlNode *msg = user_data;
    cib_notify_client_t *entry = data;
    const char *event = NULL;

    if (msg == NULL) {
        pcmk__warn("Skipping callback - NULL message");
        return;
    }

    event = pcmk__xe_get(msg, PCMK__XA_SUBT);

    if (entry == NULL) {
        pcmk__warn("Skipping callback - NULL callback client");
        return;

    } else if (entry->callback == NULL) {
        pcmk__warn("Skipping callback - NULL callback");
        return;

    } else if (!pcmk__str_eq(entry->event, event, pcmk__str_casei)) {
        pcmk__trace("Skipping callback - event mismatch %p/%s vs. %s", entry,
                    entry->event, event);
        return;
    }

    pcmk__trace("Invoking callback for %p/%s event...", entry, event);
    entry->callback(event, msg);
    pcmk__trace("Callback invoked...");
}

int
cib_internal_op(cib_t * cib, const char *op, const char *host,
                const char *section, xmlNode * data,
                xmlNode ** output_data, int call_options, const char *user_name)
{
    /* Note: *output_data gets set only for create and query requests. There are
     * a lot of opportunities to clean up, clarify, check/enforce things, etc.
     */
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

    pcmk__xe_get_int(event, PCMK__XA_CIB_RC, &rc);
    wrapper = pcmk__xe_first_child(event, PCMK__XE_CIB_UPDATE_RESULT, NULL,
                                   NULL);
    diff = pcmk__xe_first_child(wrapper, NULL, NULL, NULL);

    if ((rc < pcmk_ok) || (diff == NULL)) {
        return rc;
    }

    if (level > LOG_CRIT) {
        pcmk__log_xml_patchset(level, diff);
    }

    if (input == NULL) {
        return rc;
    }

    if (*output != input) {
        pcmk__xml_free(*output);
        *output = pcmk__xml_copy(NULL, input);
    }

    rc = cib__process_apply_patch(NULL, cib_none, NULL, event, diff, output,
                                  NULL);
    rc = pcmk_rc2legacy(rc);
    if (rc == pcmk_ok) {
        return pcmk_ok;
    }

    pcmk__debug("Update didn't apply: %s (%d)", pcmk_strerror(rc), rc);

    if (rc == -pcmk_err_old_data) {
        // Mask this error, since it means we already have the supplied update
        return pcmk_ok;
    }

    // Some other error
    g_clear_pointer(output, pcmk__xml_free);
    return rc;
}

#define log_signon_query_err(out, fmt, args...) do {    \
        if (out != NULL) {                              \
            out->err(out, fmt, ##args);                 \
        } else {                                        \
            pcmk__err(fmt, ##args);                     \
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

/*!
 * \internal
 * \brief Create a new CIB connection object and connect to the CIB API
 *
 * This function attempts to connect up to 5 times.
 *
 * \param[out] cib  Where to store CIB connection object
 *
 * \return Standard Pacemaker return code
 *
 * \note The caller is responsible for signing off and freeing the newly
 *       allocated CIB connection object using the \c signoff() method and
 *       \c cib_delete().
 */
int
cib__create_signon(cib_t **cib)
{
    static const int attempts = 5;
    int rc = pcmk_rc_ok;

    pcmk__assert((cib != NULL) && (*cib == NULL));

    *cib = cib_new();
    if (*cib == NULL) {
        return ENOMEM;
    }

    pcmk__trace("Attempting connection to CIB API (up to %d time%s)", attempts,
                pcmk__plural_s(attempts));

    for (int remaining = attempts - 1; remaining >= 0; --remaining) {
        rc = (*cib)->cmds->signon(*cib, crm_system_name, cib_command);

        if ((rc == pcmk_ok)
            || (remaining == 0)
            || ((errno != EAGAIN) && (errno != EALREADY))) {
            break;
        }

        // Retry after soft error (interrupted by signal, etc.)
        pcmk__sleep_ms((attempts - remaining) * 500);
        pcmk__debug("Re-attempting connection to CIB manager (%d attempt%s "
                    "remaining)",
                    remaining, pcmk__plural_s(remaining));
    }

    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        cib__clean_up_connection(cib);
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

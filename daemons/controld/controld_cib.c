/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <unistd.h>  /* sleep */

#include <crm/common/xml.h>
#include <crm/crm.h>
#include <crm/lrmd_internal.h>

#include <pacemaker-controld.h>

// Call ID of the most recent in-progress CIB resource update (or 0 if none)
static int pending_rsc_update = 0;

/*!
 * \internal
 * \brief Respond to a dropped CIB connection
 *
 * \param[in] user_data  CIB connection that dropped
 */
static void
handle_cib_disconnect(gpointer user_data)
{
    CRM_LOG_ASSERT(user_data == controld_globals.cib_conn);

    controld_trigger_fsa();
    controld_globals.cib_conn->state = cib_disconnected;

    if (pcmk__is_set(controld_globals.fsa_input_register, R_CIB_CONNECTED)) {
        // @TODO This should trigger a reconnect, not a shutdown
        pcmk__crit("Lost connection to the CIB manager, shutting down");
        controld_fsa_append(C_FSA_INTERNAL, I_ERROR, NULL);
        controld_clear_fsa_input_flags(R_CIB_CONNECTED);

    } else { // Expected
        pcmk__info("Disconnected from the CIB manager");
    }
}

static void
do_cib_updated(const char *event, xmlNode * msg)
{
    const xmlNode *patchset = NULL;
    const char *client_name = NULL;

    pcmk__debug("Received CIB diff notification: DC=%s", pcmk__btoa(AM_I_DC));

    if (cib__get_notify_patchset(msg, &patchset) != pcmk_rc_ok) {
        return;
    }

    if (pcmk__cib_element_in_patchset(patchset, PCMK_XE_ALERTS)
        || pcmk__cib_element_in_patchset(patchset, PCMK_XE_CRM_CONFIG)) {

        controld_trigger_config();
    }

    if (!AM_I_DC) {
        // We're not in control of the join sequence
        return;
    }

    client_name = pcmk__xe_get(msg, PCMK__XA_CIB_CLIENTNAME);
    if (!cib__client_triggers_refresh(client_name)) {
        // The CIB is still accurate
        return;
    }

    if (pcmk__cib_element_in_patchset(patchset, PCMK_XE_NODES)
        || pcmk__cib_element_in_patchset(patchset, PCMK_XE_STATUS)) {

        /* An unsafe client modified the PCMK_XE_NODES or PCMK_XE_STATUS
         * section. Ensure the node list is up-to-date, and start the join
         * process again so we get everyone's current resource history.
         */
        if (client_name == NULL) {
            client_name = pcmk__xe_get(msg, PCMK__XA_CIB_CLIENTID);
        }
        pcmk__notice("Populating nodes and starting an election after %s event "
                     "triggered by %s",
                     event, pcmk__s(client_name, "(unidentified client)"));

        populate_cib_nodes(controld_node_update_quick|controld_node_update_all,
                           __func__);
        controld_fsa_append(C_FSA_INTERNAL, I_ELECTION, NULL);
    }
}

void
controld_disconnect_cib_manager(void)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    pcmk__assert(cib_conn != NULL);

    pcmk__debug("Disconnecting from the CIB manager");

    controld_clear_fsa_input_flags(R_CIB_CONNECTED);

    cib_conn->cmds->del_notify_callback(cib_conn, PCMK__VALUE_CIB_DIFF_NOTIFY,
                                        do_cib_updated);
    cib_free_callbacks(cib_conn);

    if (cib_conn->state != cib_disconnected) {
        cib_conn->cmds->set_secondary(cib_conn, cib_discard_reply);
        cib_conn->cmds->signoff(cib_conn);
    }
}

// A_CIB_STOP, A_CIB_START, O_CIB_RESTART
void
do_cib_control(long long action, enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
               fsa_data_t *msg_data)
{
    static int cib_retries = 0;

    cib_t *cib_conn = controld_globals.cib_conn;

    void (*dnotify_fn)(gpointer user_data) = handle_cib_disconnect;
    void (*update_cb)(const char *event, xmlNodePtr msg) = do_cib_updated;

    int rc = pcmk_ok;

    pcmk__assert(cib_conn != NULL);

    if (pcmk__is_set(action, A_CIB_STOP)) {
        if ((cib_conn->state != cib_disconnected)
            && (pending_rsc_update != 0)) {

            pcmk__info("Waiting for resource update %d to complete",
                       pending_rsc_update);
            controld_fsa_stall(msg_data, action);
            return;
        }
        controld_disconnect_cib_manager();
    }

    if (!pcmk__is_set(action, A_CIB_START)) {
        return;
    }

    if (cur_state == S_STOPPING) {
        pcmk__err("Ignoring request to connect to the CIB manager after "
                  "shutdown");
        return;
    }

    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        // A short wait that usually avoids stalling the FSA
        sleep(1);
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    }

    if (rc != pcmk_ok) {
        pcmk__info("Could not connect to the CIB manager: %s",
                   pcmk_strerror(rc));

    } else if (cib_conn->cmds->set_connection_dnotify(cib_conn,
                                                      dnotify_fn) != pcmk_ok) {
        pcmk__err("Could not set dnotify callback");

    } else if (cib_conn->cmds->add_notify_callback(cib_conn,
                                                   PCMK__VALUE_CIB_DIFF_NOTIFY,
                                                   update_cb) != pcmk_ok) {
        pcmk__err("Could not set CIB notification callback (update)");

    } else {
        controld_set_fsa_input_flags(R_CIB_CONNECTED);
        cib_retries = 0;
    }

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_CIB_CONNECTED)) {
        cib_retries++;

        if (cib_retries < 30) {
            pcmk__warn("Couldn't complete CIB registration %d times... pause "
                       "and retry",
                       cib_retries);
            controld_start_wait_timer();
            controld_fsa_stall(msg_data, action);

        } else {
            pcmk__err("Could not complete CIB registration %d times... "
                      "hard error", cib_retries);
            register_fsa_error(I_ERROR, msg_data);
        }
    }
}

#define MIN_CIB_OP_TIMEOUT (30)

/*!
 * \internal
 * \brief Get the timeout (in seconds) that should be used with CIB operations
 *
 * \return The maximum of 30 seconds, the value of the PCMK_cib_timeout
 *         environment variable, or 10 seconds times one more than the number of
 *         nodes in the cluster.
 */
unsigned int
cib_op_timeout(void)
{
    unsigned int calculated_timeout = 10U * (pcmk__cluster_num_active_nodes()
                                             + pcmk__cluster_num_remote_nodes()
                                             + 1U);

    calculated_timeout = QB_MAX(calculated_timeout, MIN_CIB_OP_TIMEOUT);
    pcmk__trace("Calculated timeout: %s",
                pcmk__readable_interval(calculated_timeout * 1000));

    if (controld_globals.cib_conn) {
        controld_globals.cib_conn->call_timeout = calculated_timeout;
    }
    return calculated_timeout;
}

/*!
 * \internal
 * \brief Get CIB call options to use local scope if primary is unavailable
 *
 * \return CIB call options
 */
int
crmd_cib_smart_opt(void)
{
    int call_opt = cib_none;

    if ((controld_globals.fsa_state == S_ELECTION)
        || (controld_globals.fsa_state == S_PENDING)) {
        pcmk__info("Sending update to local CIB in state: %s",
                   fsa_state2string(controld_globals.fsa_state));
        cib__set_call_options(call_opt, "update", cib_none);
    }
    return call_opt;
}

static void
cib_delete_callback(xmlNode *msg, int call_id, int rc, xmlNode *output,
                    void *user_data)
{
    char *desc = user_data;

    if (rc == 0) {
        pcmk__debug("Deletion of %s (via CIB call %d) succeeded", desc,
                    call_id);
    } else {
        pcmk__warn("Deletion of %s (via CIB call %d) failed: %s "
                   QB_XS " rc=%d",
                   desc, call_id, pcmk_strerror(rc), rc);
    }
}

// Searches for various portions of PCMK__XE_NODE_STATE to delete

// Match a particular node's PCMK__XE_NODE_STATE (takes node name 1x)
#define XPATH_NODE_STATE "//" PCMK__XE_NODE_STATE "[@" PCMK_XA_UNAME "='%s']"

// Node's lrm section (name 1x)
#define XPATH_NODE_LRM XPATH_NODE_STATE "/" PCMK__XE_LRM

/* Node's PCMK__XE_LRM_RSC_OP entries and PCMK__XE_LRM_RESOURCE entries without
 * unexpired lock
 * (name 2x, (seconds_since_epoch - PCMK_OPT_SHUTDOWN_LOCK_LIMIT) 1x)
 */
#define XPATH_NODE_LRM_UNLOCKED XPATH_NODE_STATE "//" PCMK__XE_LRM_RSC_OP   \
                                "|" XPATH_NODE_STATE                        \
                                "//" PCMK__XE_LRM_RESOURCE                  \
                                "[not(@" PCMK_OPT_SHUTDOWN_LOCK ") "        \
                                    "or " PCMK_OPT_SHUTDOWN_LOCK "<%lld]"

/*!
 * \internal
 * \brief Get the XPath and description of resource history to be deleted
 *
 * \param[in]  uname          Name of node to delete resource history for
 * \param[in]  unlocked_only  If true, delete history of only unlocked resources
 * \param[out] xpath          Where to store XPath for history deletion
 * \param[out] desc           If not NULL, where to store loggable description
 */
void
controld_node_history_deletion_strings(const char *uname, bool unlocked_only,
                                       char **xpath, char **desc)
{
    const char *desc_pre = NULL;

    // Shutdown locks that started before this time are expired
    long long expire = (long long) time(NULL)
                       - controld_globals.shutdown_lock_limit;

    if (unlocked_only) {
        *xpath = pcmk__assert_asprintf(XPATH_NODE_LRM_UNLOCKED,
                                       uname, uname, expire);
        desc_pre = "resource history (other than shutdown locks)";
    } else {
        *xpath = pcmk__assert_asprintf(XPATH_NODE_LRM, uname);
        desc_pre = "resource history";
    }

    if (desc != NULL) {
        *desc = pcmk__assert_asprintf("%s for node %s", desc_pre, uname);
    }
}

/*!
 * \internal
 * \brief Delete a node's resource history from the CIB
 *
 * \param[in] uname          Name of node to delete resource history for
 * \param[in] unlocked_only  If true, delete history of only unlocked resources
 * \param[in] options        CIB call options to use
 */
void
controld_delete_node_history(const char *uname, bool unlocked_only, int options)
{
    cib_t *cib = controld_globals.cib_conn;
    char *xpath = NULL;
    char *desc = NULL;
    int cib_rc = pcmk_ok;

    pcmk__assert((uname != NULL) && (cib != NULL));

    controld_node_history_deletion_strings(uname, unlocked_only, &xpath, &desc);
    cib__set_call_options(options, "node state deletion",
                          cib_xpath|cib_multiple);
    cib_rc = cib->cmds->remove(cib, xpath, NULL, options);
    fsa_register_cib_callback(cib_rc, desc, cib_delete_callback);
    pcmk__info("Deleting %s (via CIB call %d) " QB_XS " xpath=%s", desc, cib_rc,
               xpath);

    // CIB library handles freeing desc
    free(xpath);
}

// Takes node name and resource ID
#define XPATH_RESOURCE_HISTORY "//" PCMK__XE_NODE_STATE                 \
                               "[@" PCMK_XA_UNAME "='%s']/"             \
                               PCMK__XE_LRM "/" PCMK__XE_LRM_RESOURCES  \
                               "/" PCMK__XE_LRM_RESOURCE                \
                               "[@" PCMK_XA_ID "='%s']"
// @TODO could add "and @PCMK_OPT_SHUTDOWN_LOCK" to limit to locks

/*!
 * \internal
 * \brief Clear resource history from CIB for a given resource and node
 *
 * \param[in]  rsc_id        ID of resource to be cleared
 * \param[in]  node          Node whose resource history should be cleared
 * \param[in]  user_name     ACL user name to use
 * \param[in]  call_options  CIB call options
 *
 * \return Standard Pacemaker return code
 */
int
controld_delete_resource_history(const char *rsc_id, const char *node,
                                 const char *user_name, int call_options)
{
    char *desc = NULL;
    char *xpath = NULL;
    int rc = pcmk_rc_ok;
    cib_t *cib = controld_globals.cib_conn;

    CRM_CHECK((rsc_id != NULL) && (node != NULL), return EINVAL);

    desc = pcmk__assert_asprintf("resource history for %s on %s", rsc_id, node);
    if (cib == NULL) {
        pcmk__err("Unable to clear %s: no CIB connection", desc);
        free(desc);
        return ENOTCONN;
    }

    // Ask CIB to delete the entry
    xpath = pcmk__assert_asprintf(XPATH_RESOURCE_HISTORY, node, rsc_id);

    cib->cmds->set_user(cib, user_name);
    rc = cib->cmds->remove(cib, xpath, NULL, call_options|cib_xpath);
    cib->cmds->set_user(cib, NULL);

    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        pcmk__err("Could not delete resource status of %s on %s%s%s: %s "
                  QB_XS " rc=%d",
                  rsc_id, node, ((user_name != NULL)? " for user " : ""),
                  pcmk__s(user_name, ""), pcmk_rc_str(rc), rc);
        free(desc);
        free(xpath);
        return rc;
    }

    if (pcmk__is_set(call_options, cib_sync_call)) {
        if (pcmk__is_set(call_options, cib_dryrun)) {
            pcmk__debug("Deletion of %s would succeed", desc);
        } else {
            pcmk__debug("Deletion of %s succeeded", desc);
        }
        free(desc);

    } else {
        pcmk__info("Clearing %s (via CIB call %d) " QB_XS " xpath=%s", desc, rc,
                   xpath);
        fsa_register_cib_callback(rc, desc, cib_delete_callback);
        // CIB library handles freeing desc
    }

    free(xpath);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Build XML and string of parameters meeting some criteria, for digest
 *
 * \param[in]  op          Executor event with parameter table to use
 * \param[in]  metadata    Parsed meta-data for executed resource agent
 * \param[in]  param_type  Flag used for selection criteria
 * \param[out] result      Will be set to newly created XML with selected
 *                         parameters as attributes
 *
 * \return Newly allocated space-separated string of parameter names
 * \note Selection criteria varies by param_type: for the restart digest, we
 *       want parameters that are *not* marked reloadable (OCF 1.1) or that
 *       *are* marked unique (pre-1.1), for both string and XML results; for the
 *       secure digest, we want parameters that *are* marked private for the
 *       string, but parameters that are *not* marked private for the XML.
 * \note It is the caller's responsibility to free the string return value with
 *       \p g_string_free() and the XML result with \p pcmk__xml_free().
 */
static GString *
build_parameter_list(const lrmd_event_data_t *op,
                     const struct ra_metadata_s *metadata,
                     enum ra_param_flags_e param_type, xmlNode **result)
{
    GString *list = NULL;

    *result = pcmk__xe_create(NULL, PCMK_XE_PARAMETERS);

    /* Consider all parameters only except private ones to be consistent with
     * what scheduler does with calculate_secure_digest().
     */
    if ((param_type == ra_param_private)
        && (pcmk__compare_versions(controld_globals.dc_version,
                                   "3.16.0") >= 0)) {
        g_hash_table_foreach(op->params, hash2field, *result);
        pcmk__filter_op_for_digest(*result);
    }

    for (GList *iter = metadata->ra_params; iter != NULL; iter = iter->next) {
        struct ra_param_s *param = (struct ra_param_s *) iter->data;

        bool accept_for_list = false;
        bool accept_for_xml = false;

        switch (param_type) {
            case ra_param_reloadable:
                accept_for_list = !pcmk__is_set(param->rap_flags, param_type);
                accept_for_xml = accept_for_list;
                break;

            case ra_param_unique:
                accept_for_list = pcmk__is_set(param->rap_flags, param_type);
                accept_for_xml = accept_for_list;
                break;

            case ra_param_private:
                accept_for_list = pcmk__is_set(param->rap_flags, param_type);
                accept_for_xml = !accept_for_list;
                break;
        }

        if (accept_for_list) {
            pcmk__trace("Attr %s is %s", param->rap_name,
                        ra_param_flag2text(param_type));

            if (list == NULL) {
                // We will later search for " WORD ", so start list with a space
                pcmk__add_word(&list, 256, " ");
            }
            pcmk__add_word(&list, 0, param->rap_name);

        } else {
            pcmk__trace("Rejecting %s for %s", param->rap_name,
                        ra_param_flag2text(param_type));
        }

        if (accept_for_xml) {
            const char *v = g_hash_table_lookup(op->params, param->rap_name);

            if (v != NULL) {
                pcmk__trace("Adding attr %s=%s to the xml result",
                            param->rap_name, v);
                pcmk__xe_set(*result, param->rap_name, v);
            }

        } else {
            pcmk__trace("Removing attr %s from the xml result",
                        param->rap_name);
            pcmk__xe_remove_attr(*result, param->rap_name);
        }
    }

    if (list != NULL) {
        // We will later search for " WORD ", so end list with a space
        pcmk__add_word(&list, 0, " ");
    }
    return list;
}

static void
append_restart_list(lrmd_event_data_t *op, struct ra_metadata_s *metadata,
                    xmlNode *update, const char *version)
{
    GString *list = NULL;
    char *digest = NULL;
    xmlNode *restart = NULL;

    CRM_LOG_ASSERT(op->params != NULL);

    if (op->interval_ms > 0) {
        /* monitors are not reloadable */
        return;
    }

    if (pcmk__is_set(metadata->ra_flags, ra_supports_reload_agent)) {
        /* Add parameters not marked reloadable to the PCMK__XA_OP_FORCE_RESTART
         * list
         */
        list = build_parameter_list(op, metadata, ra_param_reloadable,
                                    &restart);

    } else if (pcmk__is_set(metadata->ra_flags, ra_supports_legacy_reload)) {
        /* @COMPAT pre-OCF-1.1 resource agents
         *
         * Before OCF 1.1, Pacemaker abused "unique=0" to indicate
         * reloadability. Add any parameters with unique="1" to the
         * PCMK__XA_OP_FORCE_RESTART list.
         */
        list = build_parameter_list(op, metadata, ra_param_unique, &restart);

    } else {
        // Resource does not support agent reloads
        return;
    }

    digest = pcmk__digest_op_params(restart);
    /* Add PCMK__XA_OP_FORCE_RESTART and PCMK__XA_OP_RESTART_DIGEST to indicate
     * the resource supports reload, no matter if it actually supports any
     * reloadable parameters
     */
    pcmk__xe_set(update, PCMK__XA_OP_FORCE_RESTART,
                 (list == NULL)? "" : (const char *) list->str);
    pcmk__xe_set(update, PCMK__XA_OP_RESTART_DIGEST, digest);

    if ((list != NULL) && (list->len > 0)) {
        pcmk__trace("%s: %s, %s", op->rsc_id, digest, list->str);
    } else {
        pcmk__trace("%s: %s", op->rsc_id, digest);
    }

    if (list != NULL) {
        g_string_free(list, TRUE);
    }
    pcmk__xml_free(restart);
    free(digest);
}

static void
append_secure_list(lrmd_event_data_t *op, struct ra_metadata_s *metadata,
                   xmlNode *update, const char *version)
{
    GString *list = NULL;
    char *digest = NULL;
    xmlNode *secure = NULL;

    CRM_LOG_ASSERT(op->params != NULL);

    /* To keep PCMK__XA_OP_SECURE_PARAMS short, we want it to contain the secure
     * parameters but PCMK__XA_OP_SECURE_DIGEST to be based on the insecure ones
     */
    list = build_parameter_list(op, metadata, ra_param_private, &secure);

    if (list != NULL) {
        digest = pcmk__digest_op_params(secure);
        pcmk__xe_set(update, PCMK__XA_OP_SECURE_PARAMS, list->str);
        pcmk__xe_set(update, PCMK__XA_OP_SECURE_DIGEST, digest);

        pcmk__trace("%s: %s, %s", op->rsc_id, digest, list->str);
        g_string_free(list, TRUE);
    } else {
        pcmk__trace("%s: no secure parameters", op->rsc_id);
    }

    pcmk__xml_free(secure);
    free(digest);
}

/*!
 * \internal
 * \brief Create XML for a resource history entry
 *
 * \param[in]     func       Function name of caller
 * \param[in,out] parent     XML to add entry to
 * \param[in]     rsc        Affected resource
 * \param[in,out] op         Action to add an entry for (or NULL to do nothing)
 * \param[in]     node_name  Node where action occurred
 */
void
controld_add_resource_history_xml_as(const char *func, xmlNode *parent,
                                     const lrmd_rsc_info_t *rsc,
                                     lrmd_event_data_t *op,
                                     const char *node_name)
{
    int target_rc = 0;
    xmlNode *xml_op = NULL;
    struct ra_metadata_s *metadata = NULL;
    const char *caller_version = NULL;
    lrm_state_t *lrm_state = NULL;

    if (op == NULL) {
        return;
    }

    target_rc = rsc_op_expected_rc(op);

    caller_version = g_hash_table_lookup(op->params, PCMK_XA_CRM_FEATURE_SET);
    CRM_CHECK(caller_version != NULL, caller_version = CRM_FEATURE_SET);

    xml_op = pcmk__create_history_xml(parent, op, caller_version, target_rc,
                                      controld_globals.cluster->priv->node_name,
                                      func);
    if (xml_op == NULL) {
        return;
    }

    if ((rsc == NULL) || (op->params == NULL)
        || !crm_op_needs_metadata(rsc->standard, op->op_type)) {

        pcmk__trace("No digests needed for %s action on %s (params=%p rsc=%p)",
                    op->op_type, op->rsc_id, op->params, rsc);
        return;
    }

    lrm_state = controld_get_executor_state(node_name, false);
    if (lrm_state == NULL) {
        pcmk__warn("Cannot calculate digests for operation " PCMK__OP_FMT
                   " because we have no connection to executor for %s",
                   op->rsc_id, op->op_type, op->interval_ms, node_name);
        return;
    }

    /* Ideally the metadata is cached, and the agent is just a fallback.
     *
     * @TODO Go through all callers and ensure they get metadata asynchronously
     * first.
     */
    metadata = controld_get_rsc_metadata(lrm_state, rsc,
                                         controld_metadata_from_agent
                                         |controld_metadata_from_cache);
    if (metadata == NULL) {
        return;
    }

    pcmk__trace("Including additional digests for %s:%s:%s", rsc->standard,
                rsc->provider, rsc->type);
    append_restart_list(op, metadata, xml_op, caller_version);
    append_secure_list(op, metadata, xml_op, caller_version);
}

/*!
 * \internal
 * \brief Record an action as pending in the CIB, if appropriate
 *
 * \param[in]     node_name  Node where the action is pending
 * \param[in]     rsc        Resource that action is for
 * \param[in,out] op         Pending action
 *
 * \return true if action was recorded in CIB, otherwise false
 */
bool
controld_record_pending_op(const char *node_name, const lrmd_rsc_info_t *rsc,
                           lrmd_event_data_t *op)
{
    const char *record_pending = NULL;

    CRM_CHECK((node_name != NULL) && (rsc != NULL) && (op != NULL),
              return false);

    // Never record certain operation types as pending
    if ((op->op_type == NULL) || (op->params == NULL)
        || !controld_action_is_recordable(op->op_type)) {
        return false;
    }

    // Check action's PCMK_META_RECORD_PENDING meta-attribute (defaults to true)
    record_pending = crm_meta_value(op->params, PCMK_META_RECORD_PENDING);
    if ((record_pending != NULL) && !pcmk__is_true(record_pending)) {
        pcmk__warn_once(pcmk__wo_record_pending,
                        "The " PCMK_META_RECORD_PENDING " option (for example, "
                        "for the %s resource's %s operation) is deprecated and "
                        "will be removed in a future release",
                        rsc->id, op->op_type);
        return false;
    }

    op->call_id = -1;
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;

    lrmd__set_result(op, PCMK_OCF_UNKNOWN, PCMK_EXEC_PENDING, NULL);

    pcmk__debug("Recording pending %s-interval %s for %s on %s in the CIB",
                pcmk__readable_interval(op->interval_ms), op->op_type,
                op->rsc_id, node_name);
    controld_update_resource_history(node_name, rsc, op, 0);
    return true;
}

static void
cib_rsc_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc == pcmk_ok) {
        pcmk__trace("Resource history update completed (call=%d rc=%d)",
                    call_id, rc);

    } else if (call_id > 0) {
        pcmk__warn("Resource history update %d failed: %s " QB_XS " rc=%d",
                   call_id, pcmk_strerror(rc), rc);
    } else {
        pcmk__warn("Resource history update failed: %s " QB_XS " rc=%d",
                   pcmk_strerror(rc), rc);
    }

    if (call_id == pending_rsc_update) {
        pending_rsc_update = 0;
        controld_trigger_fsa();
    }
}

/* Only successful stops, and probes that found the resource inactive, get locks
 * recorded in the history. This ensures the resource stays locked to the node
 * until it is active there again after the node comes back up.
 */
static bool
should_preserve_lock(lrmd_event_data_t *op)
{
    if (!pcmk__is_set(controld_globals.flags, controld_shutdown_lock_enabled)) {
        return false;
    }
    if (!strcmp(op->op_type, PCMK_ACTION_STOP) && (op->rc == PCMK_OCF_OK)) {
        return true;
    }
    if (!strcmp(op->op_type, PCMK_ACTION_MONITOR)
        && (op->rc == PCMK_OCF_NOT_RUNNING)) {
        return true;
    }
    return false;
}

/*!
 * \internal
 * \brief Request a CIB update
 *
 * \param[in]     section    Section of CIB to update
 * \param[in]     data       New XML of CIB section to update
 * \param[in]     options    CIB call options
 * \param[in]     callback   If not \c NULL, set this as the operation callback
 *
 * \return Standard Pacemaker return code
 *
 * \note If \p callback is \p cib_rsc_callback(), the CIB update's call ID is
 *       stored in \p pending_rsc_update on success.
 */
int
controld_update_cib(const char *section, xmlNode *data, int options,
                    void (*callback)(xmlNode *, int, int, xmlNode *, void *))
{
    cib_t *cib = controld_globals.cib_conn;
    int cib_rc = -ENOTCONN;

    pcmk__assert(data != NULL);

    if (cib != NULL) {
        cib_rc = cib->cmds->modify(cib, section, data, options);
        if (cib_rc >= 0) {
            pcmk__debug("Submitted CIB update %d for %s section", cib_rc,
                        section);
        }
    }

    if (callback == NULL) {
        if (cib_rc < 0) {
            pcmk__err("Failed to update CIB %s section: %s", section,
                      pcmk_rc_str(pcmk_legacy2rc(cib_rc)));
        }

    } else {
        if ((cib_rc >= 0) && (callback == cib_rsc_callback)) {
            /* Checking for a particular callback is a little hacky, but it
             * didn't seem worth adding an output argument for cib_rc for just
             * one use case.
             */
            pending_rsc_update = cib_rc;
        }
        fsa_register_cib_callback(cib_rc, NULL, callback);
    }

    return (cib_rc >= 0)? pcmk_rc_ok : pcmk_legacy2rc(cib_rc);
}

/*!
 * \internal
 * \brief Update resource history entry in CIB
 *
 * \param[in]     node_name  Node where action occurred
 * \param[in]     rsc        Resource that action is for
 * \param[in,out] op         Action to record
 * \param[in]     lock_time  If nonzero, when resource was locked to node
 *
 * \note On success, the CIB update's call ID will be stored in
 *       pending_rsc_update.
 */
void
controld_update_resource_history(const char *node_name,
                                 const lrmd_rsc_info_t *rsc,
                                 lrmd_event_data_t *op, time_t lock_time)
{
    xmlNode *update = NULL;
    xmlNode *xml = NULL;
    int call_opt = crmd_cib_smart_opt();
    const char *node_id = NULL;
    const char *container = NULL;

    CRM_CHECK((node_name != NULL) && (op != NULL), return);

    if (rsc == NULL) {
        pcmk__warn("Resource %s no longer exists in the executor", op->rsc_id);
        controld_ack_event_directly(NULL, NULL, rsc, op, op->rsc_id);
        return;
    }

    // <status>
    update = pcmk__xe_create(NULL, PCMK_XE_STATUS);

    //   <node_state ...>
    xml = pcmk__xe_create(update, PCMK__XE_NODE_STATE);
    if (controld_is_local_node(node_name)) {
        node_id = controld_globals.our_uuid;
    } else {
        node_id = node_name;
        pcmk__xe_set_bool(xml, PCMK_XA_REMOTE_NODE, true);
    }
    pcmk__xe_set(xml, PCMK_XA_ID, node_id);
    pcmk__xe_set(xml, PCMK_XA_UNAME, node_name);
    pcmk__xe_set(xml, PCMK_XA_CRM_DEBUG_ORIGIN, __func__);

    //     <lrm ...>
    xml = pcmk__xe_create(xml, PCMK__XE_LRM);
    pcmk__xe_set(xml, PCMK_XA_ID, node_id);

    //       <lrm_resources>
    xml = pcmk__xe_create(xml, PCMK__XE_LRM_RESOURCES);

    //         <lrm_resource ...>
    xml = pcmk__xe_create(xml, PCMK__XE_LRM_RESOURCE);
    pcmk__xe_set(xml, PCMK_XA_ID, op->rsc_id);
    pcmk__xe_set(xml, PCMK_XA_CLASS, rsc->standard);
    pcmk__xe_set(xml, PCMK_XA_PROVIDER, rsc->provider);
    pcmk__xe_set(xml, PCMK_XA_TYPE, rsc->type);
    if (lock_time != 0) {
        /* Actions on a locked resource should either preserve the lock by
         * recording it with the action result, or clear it.
         */
        if (!should_preserve_lock(op)) {
            lock_time = 0;
        }
        pcmk__xe_set_time(xml, PCMK_OPT_SHUTDOWN_LOCK, lock_time);
    }
    if (op->params != NULL) {
        container = g_hash_table_lookup(op->params,
                                        CRM_META "_" PCMK__META_CONTAINER);
        if (container != NULL) {
            pcmk__trace("Resource %s is a part of container resource %s",
                        op->rsc_id, container);
            pcmk__xe_set(xml, PCMK__META_CONTAINER, container);
        }
    }

    //           <lrm_resource_op ...> (possibly more than one)
    controld_add_resource_history_xml(xml, rsc, op, node_name);

    /* Update CIB asynchronously. Even if it fails, the resource state should be
     * discovered during the next election. Worst case, the node is wrongly
     * fenced for running a resource it isn't.
     */
    pcmk__log_xml_trace(update, __func__);
    controld_update_cib(PCMK_XE_STATUS, update, call_opt, cib_rsc_callback);
    pcmk__xml_free(update);
}

/*!
 * \internal
 * \brief Erase an LRM history entry from the CIB, given the operation data
 *
 * \param[in] op         Operation whose history should be deleted
 */
void
controld_delete_action_history(const lrmd_event_data_t *op)
{
    xmlNode *xml_top = NULL;

    CRM_CHECK(op != NULL, return);

    xml_top = pcmk__xe_create(NULL, PCMK__XE_LRM_RSC_OP);
    pcmk__xe_set_int(xml_top, PCMK__XA_CALL_ID, op->call_id);
    pcmk__xe_set(xml_top, PCMK__XA_TRANSITION_KEY, op->user_data);

    if (op->interval_ms > 0) {
        char *op_id = pcmk__op_key(op->rsc_id, op->op_type, op->interval_ms);

        /* Avoid deleting last_failure too (if it was a result of this recurring op failing) */
        pcmk__xe_set(xml_top, PCMK_XA_ID, op_id);
        free(op_id);
    }

    pcmk__debug("Erasing resource operation history for " PCMK__OP_FMT
                " (call=%d)",
                op->rsc_id, op->op_type, op->interval_ms, op->call_id);

    controld_globals.cib_conn->cmds->remove(controld_globals.cib_conn,
                                            PCMK_XE_STATUS, xml_top, cib_none);
    pcmk__log_xml_trace(xml_top, "op:cancel");
    pcmk__xml_free(xml_top);
}

/* Define xpath to find LRM resource history entry by node and resource */
#define XPATH_HISTORY                                   \
    "/" PCMK_XE_CIB "/" PCMK_XE_STATUS                  \
    "/" PCMK__XE_NODE_STATE "[@" PCMK_XA_UNAME "='%s']" \
    "/" PCMK__XE_LRM "/" PCMK__XE_LRM_RESOURCES         \
    "/" PCMK__XE_LRM_RESOURCE "[@" PCMK_XA_ID "='%s']"  \
    "/" PCMK__XE_LRM_RSC_OP

/* ... and also by operation key */
#define XPATH_HISTORY_ID XPATH_HISTORY "[@" PCMK_XA_ID "='%s']"

/* ... and also by operation key and operation call ID */
#define XPATH_HISTORY_CALL XPATH_HISTORY \
    "[@" PCMK_XA_ID "='%s' and @" PCMK__XA_CALL_ID "='%d']"

/* ... and also by operation key and original operation key */
#define XPATH_HISTORY_ORIG XPATH_HISTORY \
    "[@" PCMK_XA_ID "='%s' and @" PCMK__XA_OPERATION_KEY "='%s']"

/*!
 * \internal
 * \brief Delete a last_failure resource history entry from the CIB
 *
 * \param[in] rsc_id       Name of resource to clear history for
 * \param[in] node         Name of node to clear history for
 * \param[in] action       If specified, delete only if this was failed action
 * \param[in] interval_ms  If \p action is specified, it has this interval
 */
void
controld_cib_delete_last_failure(const char *rsc_id, const char *node,
                                 const char *action, guint interval_ms)
{
    char *xpath = NULL;
    char *last_failure_key = NULL;
    CRM_CHECK((rsc_id != NULL) && (node != NULL), return);

    // Generate XPath to match desired entry
    last_failure_key = pcmk__op_key(rsc_id, "last_failure", 0);
    if (action == NULL) {
        xpath = pcmk__assert_asprintf(XPATH_HISTORY_ID, node, rsc_id,
                                      last_failure_key);
    } else {
        char *action_key = pcmk__op_key(rsc_id, action, interval_ms);

        xpath = pcmk__assert_asprintf(XPATH_HISTORY_ORIG, node, rsc_id,
                                      last_failure_key, action_key);
        free(action_key);
    }
    free(last_failure_key);

    controld_globals.cib_conn->cmds->remove(controld_globals.cib_conn, xpath,
                                            NULL, cib_xpath);
    free(xpath);
}

/*!
 * \internal
 * \brief Delete resource history entry from the CIB, given operation key
 *
 * \param[in] rsc_id     Name of resource to clear history for
 * \param[in] node       Name of node to clear history for
 * \param[in] key        Operation key of operation to clear history for
 * \param[in] call_id    If specified, delete entry only if it has this call ID
 */
void
controld_delete_action_history_by_key(const char *rsc_id, const char *node,
                                      const char *key, int call_id)
{
    char *xpath = NULL;

    CRM_CHECK((rsc_id != NULL) && (node != NULL) && (key != NULL), return);

    if (call_id > 0) {
        xpath = pcmk__assert_asprintf(XPATH_HISTORY_CALL, node, rsc_id, key,
                                     call_id);
    } else {
        xpath = pcmk__assert_asprintf(XPATH_HISTORY_ID, node, rsc_id, key);
    }
    controld_globals.cib_conn->cmds->remove(controld_globals.cib_conn, xpath,
                                            NULL, cib_xpath);
    free(xpath);
}

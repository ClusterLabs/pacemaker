/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <unistd.h>  /* sleep */

#include <crm/common/alerts_internal.h>
#include <crm/common/xml.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>

#include <pacemaker-controld.h>

static int cib_retries = 0;

void
do_cib_updated(const char *event, xmlNode * msg)
{
    if (pcmk__alert_in_patchset(msg, TRUE)) {
        controld_trigger_config();
    }
}

void
do_cib_replaced(const char *event, xmlNode * msg)
{
    uint32_t change_section = cib_change_section_nodes
                              |cib_change_section_status;
    long long value = 0;

    crm_debug("Updating the CIB after a replace: DC=%s", pcmk__btoa(AM_I_DC));
    if (AM_I_DC == FALSE) {
        return;

    } else if ((controld_globals.fsa_state == S_FINALIZE_JOIN)
               && pcmk_is_set(controld_globals.fsa_input_register,
                              R_CIB_ASKED)) {
        /* no need to restart the join - we asked for this replace op */
        return;
    }

    if ((crm_element_value_ll(msg, F_CIB_CHANGE_SECTION, &value) < 0)
        || (value < 0) || (value > UINT32_MAX)) {

        crm_trace("Couldn't parse '%s' from message", F_CIB_CHANGE_SECTION);
    } else {
        change_section = (uint32_t) value;
    }

    if (pcmk_any_flags_set(change_section, cib_change_section_nodes
                                           |cib_change_section_status)) {

        /* start the join process again so we get everyone's LRM status */
        populate_cib_nodes(node_update_quick|node_update_all, __func__);

        register_fsa_input(C_FSA_INTERNAL, I_ELECTION, NULL);
    }
}

void
controld_disconnect_cib_manager(void)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    CRM_ASSERT(cib_conn != NULL);

    crm_info("Disconnecting from the CIB manager");

    controld_clear_fsa_input_flags(R_CIB_CONNECTED);

    cib_conn->cmds->del_notify_callback(cib_conn, T_CIB_REPLACE_NOTIFY,
                                        do_cib_replaced);
    cib_conn->cmds->del_notify_callback(cib_conn, T_CIB_DIFF_NOTIFY,
                                        do_cib_updated);
    cib_free_callbacks(cib_conn);

    if (cib_conn->state != cib_disconnected) {
        cib_conn->cmds->set_secondary(cib_conn,
                                      cib_scope_local|cib_discard_reply);
        cib_conn->cmds->signoff(cib_conn);
    }

    crm_notice("Disconnected from the CIB manager");
}

/* A_CIB_STOP, A_CIB_START, O_CIB_RESTART */
void
do_cib_control(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    void (*dnotify_fn) (gpointer user_data) = crmd_cib_connection_destroy;
    void (*replace_cb) (const char *event, xmlNodePtr msg) = do_cib_replaced;
    void (*update_cb) (const char *event, xmlNodePtr msg) = do_cib_updated;

    int rc = pcmk_ok;

    CRM_ASSERT(cib_conn != NULL);

    if (pcmk_is_set(action, A_CIB_STOP)) {
        if ((cib_conn->state != cib_disconnected)
            && (last_resource_update != 0)) {

            crm_info("Waiting for resource update %d to complete",
                     last_resource_update);
            crmd_fsa_stall(FALSE);
            return;
        }
        controld_disconnect_cib_manager();
    }

    if (!pcmk_is_set(action, A_CIB_START)) {
        return;
    }

    if (cur_state == S_STOPPING) {
        crm_err("Ignoring request to connect to the CIB manager after "
                "shutdown");
        return;
    }

    rc = cib_conn->cmds->signon(cib_conn, CRM_SYSTEM_CRMD,
                                cib_command_nonblocking);

    if (rc != pcmk_ok) {
        // A short wait that usually avoids stalling the FSA
        sleep(1);
        rc = cib_conn->cmds->signon(cib_conn, CRM_SYSTEM_CRMD,
                                    cib_command_nonblocking);
    }

    if (rc != pcmk_ok) {
        crm_info("Could not connect to the CIB manager: %s", pcmk_strerror(rc));

    } else if (cib_conn->cmds->set_connection_dnotify(cib_conn,
                                                      dnotify_fn) != pcmk_ok) {
        crm_err("Could not set dnotify callback");

    } else if (cib_conn->cmds->add_notify_callback(cib_conn,
                                                   T_CIB_REPLACE_NOTIFY,
                                                   replace_cb) != pcmk_ok) {
        crm_err("Could not set CIB notification callback (replace)");

    } else if (cib_conn->cmds->add_notify_callback(cib_conn,
                                                   T_CIB_DIFF_NOTIFY,
                                                   update_cb) != pcmk_ok) {
        crm_err("Could not set CIB notification callback (update)");

    } else {
        controld_set_fsa_input_flags(R_CIB_CONNECTED);
        cib_retries = 0;
    }

    if (!pcmk_is_set(controld_globals.fsa_input_register, R_CIB_CONNECTED)) {
        cib_retries++;

        if (cib_retries < 30) {
            crm_warn("Couldn't complete CIB registration %d times... "
                     "pause and retry", cib_retries);
            controld_start_timer(wait_timer);
            crmd_fsa_stall(FALSE);

        } else {
            crm_err("Could not complete CIB registration %d times... "
                    "hard error", cib_retries);
            register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        }
    }
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
    int call_opt = cib_quorum_override;

    if ((controld_globals.fsa_state == S_ELECTION)
        || (controld_globals.fsa_state == S_PENDING)) {
        crm_info("Sending update to local CIB in state: %s",
                 fsa_state2string(controld_globals.fsa_state));
        cib__set_call_options(call_opt, "update", cib_scope_local);
    }
    return call_opt;
}

/*!
 * \internal
 * \brief Check whether an action type should be recorded in the CIB
 *
 * \param[in] action  Action type
 *
 * \return TRUE if action should be recorded, FALSE otherwise
 */
bool
controld_action_is_recordable(const char *action)
{
    return !pcmk__strcase_any_of(action, CRMD_ACTION_CANCEL, CRMD_ACTION_DELETE,
                            CRMD_ACTION_NOTIFY, CRMD_ACTION_METADATA, NULL);
}

static void
cib_delete_callback(xmlNode *msg, int call_id, int rc, xmlNode *output,
                    void *user_data)
{
    char *desc = user_data;

    if (rc == 0) {
        crm_debug("Deletion of %s (via CIB call %d) succeeded", desc, call_id);
    } else {
        crm_warn("Deletion of %s (via CIB call %d) failed: %s " CRM_XS " rc=%d",
                 desc, call_id, pcmk_strerror(rc), rc);
    }
}

// Searches for various portions of node_state to delete

// Match a particular node's node_state (takes node name 1x)
#define XPATH_NODE_STATE        "//" XML_CIB_TAG_STATE "[@" XML_ATTR_UNAME "='%s']"

// Node's lrm section (name 1x)
#define XPATH_NODE_LRM          XPATH_NODE_STATE "/" XML_CIB_TAG_LRM

// Node's lrm_rsc_op entries and lrm_resource entries without lock (name 2x)
#define XPATH_NODE_LRM_UNLOCKED XPATH_NODE_STATE "//" XML_LRM_TAG_RSC_OP    \
                                "|" XPATH_NODE_STATE                        \
                                "//" XML_LRM_TAG_RESOURCE                   \
                                "[not(@" XML_CONFIG_ATTR_SHUTDOWN_LOCK ")]"

// Node's transient_attributes section (name 1x)
#define XPATH_NODE_ATTRS        XPATH_NODE_STATE "/" XML_TAG_TRANSIENT_NODEATTRS

// Everything under node_state (name 1x)
#define XPATH_NODE_ALL          XPATH_NODE_STATE "/*"

// Unlocked history + transient attributes (name 3x)
#define XPATH_NODE_ALL_UNLOCKED XPATH_NODE_LRM_UNLOCKED "|" XPATH_NODE_ATTRS

/*!
 * \internal
 * \brief Delete subsection of a node's CIB node_state
 *
 * \param[in] uname    Desired node
 * \param[in] section  Subsection of node_state to delete
 * \param[in] options  CIB call options to use
 */
void
controld_delete_node_state(const char *uname, enum controld_section_e section,
                           int options)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    char *xpath = NULL;
    char *desc = NULL;

    CRM_CHECK(uname != NULL, return);
    switch (section) {
        case controld_section_lrm:
            xpath = crm_strdup_printf(XPATH_NODE_LRM, uname);
            desc = crm_strdup_printf("resource history for node %s", uname);
            break;
        case controld_section_lrm_unlocked:
            xpath = crm_strdup_printf(XPATH_NODE_LRM_UNLOCKED, uname, uname);
            desc = crm_strdup_printf("resource history (other than shutdown "
                                     "locks) for node %s", uname);
            break;
        case controld_section_attrs:
            xpath = crm_strdup_printf(XPATH_NODE_ATTRS, uname);
            desc = crm_strdup_printf("transient attributes for node %s", uname);
            break;
        case controld_section_all:
            xpath = crm_strdup_printf(XPATH_NODE_ALL, uname);
            desc = crm_strdup_printf("all state for node %s", uname);
            break;
        case controld_section_all_unlocked:
            xpath = crm_strdup_printf(XPATH_NODE_ALL_UNLOCKED,
                                      uname, uname, uname);
            desc = crm_strdup_printf("all state (other than shutdown locks) "
                                     "for node %s", uname);
            break;
    }

    if (cib_conn == NULL) {
        crm_warn("Unable to delete %s: no CIB connection", desc);
        free(desc);
    } else {
        int call_id;

        cib__set_call_options(options, "node state deletion",
                              cib_quorum_override|cib_xpath|cib_multiple);
        call_id = cib_conn->cmds->remove(cib_conn, xpath, NULL, options);
        crm_info("Deleting %s (via CIB call %d) " CRM_XS " xpath=%s",
                 desc, call_id, xpath);
        fsa_register_cib_callback(call_id, FALSE, desc, cib_delete_callback);
        // CIB library handles freeing desc
    }
    free(xpath);
}

// Takes node name and resource ID
#define XPATH_RESOURCE_HISTORY "//" XML_CIB_TAG_STATE                       \
                               "[@" XML_ATTR_UNAME "='%s']/"                \
                               XML_CIB_TAG_LRM "/" XML_LRM_TAG_RESOURCES    \
                               "/" XML_LRM_TAG_RESOURCE                     \
                               "[@" XML_ATTR_ID "='%s']"
// @TODO could add "and @XML_CONFIG_ATTR_SHUTDOWN_LOCK" to limit to locks

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

    CRM_CHECK((rsc_id != NULL) && (node != NULL), return EINVAL);

    desc = crm_strdup_printf("resource history for %s on %s", rsc_id, node);
    if (controld_globals.cib_conn == NULL) {
        crm_err("Unable to clear %s: no CIB connection", desc);
        free(desc);
        return ENOTCONN;
    }

    // Ask CIB to delete the entry
    xpath = crm_strdup_printf(XPATH_RESOURCE_HISTORY, node, rsc_id);
    rc = cib_internal_op(controld_globals.cib_conn, PCMK__CIB_REQUEST_DELETE,
                         NULL, xpath, NULL, NULL, call_options|cib_xpath,
                         user_name);

    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        crm_err("Could not delete resource status of %s on %s%s%s: %s "
                CRM_XS " rc=%d", rsc_id, node,
                (user_name? " for user " : ""), (user_name? user_name : ""),
                pcmk_rc_str(rc), rc);
        free(desc);
        free(xpath);
        return rc;
    }

    if (pcmk_is_set(call_options, cib_sync_call)) {
        if (pcmk_is_set(call_options, cib_dryrun)) {
            crm_debug("Deletion of %s would succeed", desc);
        } else {
            crm_debug("Deletion of %s succeeded", desc);
        }
        free(desc);

    } else {
        crm_info("Clearing %s (via CIB call %d) " CRM_XS " xpath=%s",
                 desc, rc, xpath);
        fsa_register_cib_callback(rc, FALSE, desc, cib_delete_callback);
        // CIB library handles freeing desc
    }

    free(xpath);
    return pcmk_rc_ok;
}

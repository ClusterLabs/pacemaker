/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <unistd.h>  /* pid_t, sleep, ssize_t */

#include <crm/cib.h>
#include <crm/cluster.h>
#include <crm/common/xml.h>
#include <crm/crm.h>
#include <crm/common/xml_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_schedulerd.h>

#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <pacemaker-controld.h>

static void handle_disconnect(void);

static pcmk_ipc_api_t *schedulerd_api = NULL;

/*!
 * \internal
 * \brief Close any scheduler connection and free associated memory
 */
void
controld_shutdown_schedulerd_ipc(void)
{
    controld_clear_fsa_input_flags(R_PE_REQUIRED);
    pcmk_disconnect_ipc(schedulerd_api);
    handle_disconnect();

    pcmk_free_ipc_api(schedulerd_api);
    schedulerd_api = NULL;
}

/*!
 * \internal
 * \brief Save CIB query result to file, raising FSA error
 *
 * \param[in] msg        Ignored
 * \param[in] call_id    Call ID of CIB query
 * \param[in] rc         Return code of CIB query
 * \param[in] output     Result of CIB query
 * \param[in] user_data  Unique identifier for filename
 *
 * \note This is intended to be called after a scheduler connection fails.
 */
static void
save_cib_contents(xmlNode *msg, int call_id, int rc, xmlNode *output,
                  void *user_data)
{
    const char *id = user_data;

    register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __func__);
    CRM_CHECK(id != NULL, return);

    if (rc == pcmk_ok) {
        char *filename = crm_strdup_printf(PCMK_SCHEDULER_INPUT_DIR "/pe-core-%s.bz2", id);

        if (pcmk__xml_write_file(output, filename, true) != pcmk_rc_ok) {
            crm_err("Could not save Cluster Information Base to %s after scheduler crash",
                    filename);
        } else {
            crm_notice("Saved Cluster Information Base to %s after scheduler crash",
                       filename);
        }
        free(filename);
    }
}

/*!
 * \internal
 * \brief Respond to scheduler connection failure
 */
static void
handle_disconnect(void)
{
    // If we aren't connected to the scheduler, we can't expect a reply
    controld_expect_sched_reply(NULL);

    if (pcmk_is_set(controld_globals.fsa_input_register, R_PE_REQUIRED)) {
        int rc = pcmk_ok;
        char *uuid_str = crm_generate_uuid();

        crm_crit("Lost connection to the scheduler "
                 QB_XS " CIB will be saved to " PCMK_SCHEDULER_INPUT_DIR "/pe-core-%s.bz2",
                 uuid_str);

        /*
         * The scheduler died...
         *
         * Save the current CIB so that we have a chance of
         * figuring out what killed it.
         *
         * Delay raising the I_ERROR until the query below completes or
         * 5s is up, whichever comes first.
         *
         */
        rc = controld_globals.cib_conn->cmds->query(controld_globals.cib_conn,
                                                    NULL, NULL, cib_none);
        fsa_register_cib_callback(rc, uuid_str, save_cib_contents);
    }

    controld_clear_fsa_input_flags(R_PE_CONNECTED);
    controld_trigger_fsa();
    return;
}

static void
handle_reply(pcmk_schedulerd_api_reply_t *reply)
{
    const char *msg_ref = NULL;

    if (!AM_I_DC) {
        return;
    }

    msg_ref = reply->data.graph.reference;

    if (msg_ref == NULL) {
        crm_err("%s - Ignoring calculation with no reference", CRM_OP_PECALC);

    } else if (pcmk__str_eq(msg_ref, controld_globals.fsa_pe_ref,
                            pcmk__str_none)) {
        ha_msg_input_t fsa_input;
        xmlNode *crm_data_node;

        controld_stop_sched_timer();

        /* do_te_invoke (which will eventually process the fsa_input we are constructing
         * here) requires that fsa_input.xml be non-NULL.  That will only happen if
         * copy_ha_msg_input (which is called by register_fsa_input_adv) sees the
         * fsa_input.msg that it is expecting. The scheduler's IPC dispatch function
         * gave us the values we need, we just need to put them into XML.
         *
         * The name of the top level element here is irrelevant.  Nothing checks it.
         */
        fsa_input.msg = pcmk__xe_create(NULL, "dummy-reply");
        crm_xml_add(fsa_input.msg, PCMK_XA_REFERENCE, msg_ref);
        crm_xml_add(fsa_input.msg, PCMK__XA_CRM_TGRAPH_IN,
                    reply->data.graph.input);

        crm_data_node = pcmk__xe_create(fsa_input.msg, PCMK__XE_CRM_XML);
        pcmk__xml_copy(crm_data_node, reply->data.graph.tgraph);
        register_fsa_input_later(C_IPC_MESSAGE, I_PE_SUCCESS, &fsa_input);

        pcmk__xml_free(fsa_input.msg);

    } else {
        crm_info("%s calculation %s is obsolete", CRM_OP_PECALC, msg_ref);
    }
}

static void
scheduler_event_callback(pcmk_ipc_api_t *api, enum pcmk_ipc_event event_type,
                         crm_exit_t status, void *event_data, void *user_data)
{
    pcmk_schedulerd_api_reply_t *reply = event_data;

    switch (event_type) {
        case pcmk_ipc_event_disconnect:
            handle_disconnect();
            break;

        case pcmk_ipc_event_reply:
            handle_reply(reply);
            break;

        default:
            break;
    }
}

static bool
new_schedulerd_ipc_connection(void)
{
    int rc;

    controld_set_fsa_input_flags(R_PE_REQUIRED);

    if (schedulerd_api == NULL) {
        rc = pcmk_new_ipc_api(&schedulerd_api, pcmk_ipc_schedulerd);

        if (rc != pcmk_rc_ok) {
            crm_err("Error connecting to the scheduler: %s", pcmk_rc_str(rc));
            return false;
        }
    }

    pcmk_register_ipc_callback(schedulerd_api, scheduler_event_callback, NULL);

    rc = pcmk__connect_ipc(schedulerd_api, pcmk_ipc_dispatch_main, 3);
    if (rc != pcmk_rc_ok) {
        crm_err("Error connecting to %s: %s",
                pcmk_ipc_name(schedulerd_api, true), pcmk_rc_str(rc));
        return false;
    }

    controld_set_fsa_input_flags(R_PE_CONNECTED);
    return true;
}

static void do_pe_invoke_callback(xmlNode *msg, int call_id, int rc,
                                  xmlNode *output, void *user_data);

/*	 A_PE_START, A_PE_STOP, O_PE_RESTART	*/
void
do_pe_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    if (pcmk_is_set(action, A_PE_STOP)) {
        controld_clear_fsa_input_flags(R_PE_REQUIRED);
        pcmk_disconnect_ipc(schedulerd_api);
        handle_disconnect();
    }
    if (pcmk_is_set(action, A_PE_START)
        && !pcmk_is_set(controld_globals.fsa_input_register, R_PE_CONNECTED)) {

        if (cur_state == S_STOPPING) {
            crm_info("Ignoring request to connect to scheduler while shutting down");

        } else if (!new_schedulerd_ipc_connection()) {
            crm_warn("Could not connect to scheduler");
            register_fsa_error(C_FSA_INTERNAL, I_FAIL, NULL);
        }
    }
}

static int fsa_pe_query = 0;
static mainloop_timer_t *controld_sched_timer = NULL;

// @TODO Make this a configurable cluster option if there's demand for it
#define SCHED_TIMEOUT_MS (120000)

/*!
 * \internal
 * \brief Handle a timeout waiting for scheduler reply
 *
 * \param[in] user_data  Ignored
 *
 * \return FALSE (indicating that timer should not be restarted)
 */
static gboolean
controld_sched_timeout(gpointer user_data)
{
    if (AM_I_DC) {
        /* If this node is the DC but can't communicate with the scheduler, just
         * exit (and likely get fenced) so this node doesn't interfere with any
         * further DC elections.
         *
         * @TODO We could try something less drastic first, like disconnecting
         * and reconnecting to the scheduler, but something is likely going
         * seriously wrong, so perhaps it's better to just fail as quickly as
         * possible.
         */
        crmd_exit(CRM_EX_FATAL);
    }
    return FALSE;
}

void
controld_stop_sched_timer(void)
{
    if ((controld_sched_timer != NULL)
        && (controld_globals.fsa_pe_ref != NULL)) {
        crm_trace("Stopping timer for scheduler reply %s",
                  controld_globals.fsa_pe_ref);
    }
    mainloop_timer_stop(controld_sched_timer);
}

/*!
 * \internal
 * \brief Set the scheduler request currently being waited on
 *
 * \param[in] ref  Request to expect reply to (or NULL for none)
 *
 * \note This function takes ownership of \p ref.
 */
void
controld_expect_sched_reply(char *ref)
{
    if (ref) {
        if (controld_sched_timer == NULL) {
            controld_sched_timer = mainloop_timer_add("scheduler_reply_timer",
                                                      SCHED_TIMEOUT_MS, FALSE,
                                                      controld_sched_timeout,
                                                      NULL);
        }
        mainloop_timer_start(controld_sched_timer);
    } else {
        controld_stop_sched_timer();
    }
    free(controld_globals.fsa_pe_ref);
    controld_globals.fsa_pe_ref = ref;
}

/*!
 * \internal
 * \brief Free the scheduler reply timer
 */
void
controld_free_sched_timer(void)
{
    if (controld_sched_timer != NULL) {
        mainloop_timer_del(controld_sched_timer);
        controld_sched_timer = NULL;
    }
}

/*	 A_PE_INVOKE	*/
void
do_pe_invoke(long long action,
             enum crmd_fsa_cause cause,
             enum crmd_fsa_state cur_state,
             enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    if (AM_I_DC == FALSE) {
        crm_err("Not invoking scheduler because not DC: %s",
                fsa_action2string(action));
        return;
    }

    if (!pcmk_is_set(controld_globals.fsa_input_register, R_PE_CONNECTED)) {
        if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
            crm_err("Cannot shut down gracefully without the scheduler");
            register_fsa_input_before(C_FSA_INTERNAL, I_TERMINATE, NULL);

        } else {
            crm_info("Waiting for the scheduler to connect");
            crmd_fsa_stall(FALSE);
            controld_set_fsa_action_flags(A_PE_START);
            controld_trigger_fsa();
        }
        return;
    }

    if (cur_state != S_POLICY_ENGINE) {
        crm_notice("Not invoking scheduler because in state %s",
                   fsa_state2string(cur_state));
        return;
    }
    if (!pcmk_is_set(controld_globals.fsa_input_register, R_HAVE_CIB)) {
        crm_err("Attempted to invoke scheduler without consistent Cluster Information Base!");

        /* start the join from scratch */
        register_fsa_input_before(C_FSA_INTERNAL, I_ELECTION, NULL);
        return;
    }

    fsa_pe_query = cib_conn->cmds->query(cib_conn, NULL, NULL, cib_none);

    crm_debug("Query %d: Requesting the current CIB: %s", fsa_pe_query,
              fsa_state2string(controld_globals.fsa_state));

    controld_expect_sched_reply(NULL);
    fsa_register_cib_callback(fsa_pe_query, NULL, do_pe_invoke_callback);
}

static void
force_local_option(xmlNode *xml, const char *attr_name, const char *attr_value)
{
    int max = 0;
    int lpc = 0;
    const char *xpath_base = NULL;
    char *xpath_string = NULL;
    xmlXPathObject *xpathObj = NULL;

    xpath_base = pcmk_cib_xpath_for(PCMK_XE_CRM_CONFIG);
    if (xpath_base == NULL) {
        crm_err(PCMK_XE_CRM_CONFIG " CIB element not known (bug?)");
        return;
    }

    xpath_string = crm_strdup_printf("%s//%s//nvpair[@name='%s']",
                                     xpath_base, PCMK_XE_CLUSTER_PROPERTY_SET,
                                     attr_name);
    xpathObj = pcmk__xpath_search(xml->doc, xpath_string);
    max = pcmk__xpath_num_results(xpathObj);
    free(xpath_string);

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *match = pcmk__xpath_result(xpathObj, lpc);

        if (match == NULL) {
            continue;
        }
        crm_trace("Forcing %s/%s = %s",
                  pcmk__xe_id(match), attr_name, attr_value);
        crm_xml_add(match, PCMK_XA_VALUE, attr_value);
    }

    if(max == 0) {
        xmlNode *configuration = NULL;
        xmlNode *crm_config = NULL;
        xmlNode *cluster_property_set = NULL;

        crm_trace("Creating %s-%s for %s=%s",
                  PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, attr_name, attr_name,
                  attr_value);

        configuration = pcmk__xe_first_child(xml, PCMK_XE_CONFIGURATION, NULL,
                                             NULL);
        if (configuration == NULL) {
            configuration = pcmk__xe_create(xml, PCMK_XE_CONFIGURATION);
        }

        crm_config = pcmk__xe_first_child(configuration, PCMK_XE_CRM_CONFIG,
                                          NULL, NULL);
        if (crm_config == NULL) {
            crm_config = pcmk__xe_create(configuration, PCMK_XE_CRM_CONFIG);
        }

        cluster_property_set =
            pcmk__xe_first_child(crm_config, PCMK_XE_CLUSTER_PROPERTY_SET, NULL,
                                 NULL);
        if (cluster_property_set == NULL) {
            cluster_property_set =
                pcmk__xe_create(crm_config, PCMK_XE_CLUSTER_PROPERTY_SET);
            crm_xml_add(cluster_property_set, PCMK_XA_ID,
                        PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS);
        }

        xml = pcmk__xe_create(cluster_property_set, PCMK_XE_NVPAIR);

        pcmk__xe_set_id(xml, "%s-%s",
                        PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, attr_name);
        crm_xml_add(xml, PCMK_XA_NAME, attr_name);
        crm_xml_add(xml, PCMK_XA_VALUE, attr_value);
    }
    xmlXPathFreeObject(xpathObj);
}

static void
do_pe_invoke_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    char *ref = NULL;
    pid_t watchdog = pcmk__locate_sbd();

    if (rc != pcmk_ok) {
        crm_err("Could not retrieve the Cluster Information Base: %s "
                QB_XS " rc=%d call=%d", pcmk_strerror(rc), rc, call_id);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __func__);
        return;

    } else if (call_id != fsa_pe_query) {
        crm_trace("Skipping superseded CIB query: %d (current=%d)", call_id, fsa_pe_query);
        return;

    } else if (!AM_I_DC
               || !pcmk_is_set(controld_globals.fsa_input_register,
                               R_PE_CONNECTED)) {
        crm_debug("No need to invoke the scheduler anymore");
        return;

    } else if (controld_globals.fsa_state != S_POLICY_ENGINE) {
        crm_debug("Discarding scheduler request in state: %s",
                  fsa_state2string(controld_globals.fsa_state));
        return;

    /* this callback counts as 1 */
    } else if (num_cib_op_callbacks() > 1) {
        crm_debug("Re-asking for the CIB: %d other peer updates still pending",
                  (num_cib_op_callbacks() - 1));
        sleep(1);
        controld_set_fsa_action_flags(A_PE_INVOKE);
        controld_trigger_fsa();
        return;
    }

    CRM_LOG_ASSERT(output != NULL);

    /* Refresh the remote node cache and the known node cache when the
     * scheduler is invoked */
    pcmk__refresh_node_caches_from_cib(output);

    crm_xml_add(output, PCMK_XA_DC_UUID, controld_globals.our_uuid);
    pcmk__xe_set_bool_attr(output, PCMK_XA_HAVE_QUORUM,
                           pcmk_is_set(controld_globals.flags,
                                       controld_has_quorum));

    force_local_option(output, PCMK_OPT_HAVE_WATCHDOG, pcmk__btoa(watchdog));

    if (pcmk_is_set(controld_globals.flags, controld_ever_had_quorum)
        && !pcmk__cluster_has_quorum()) {

        pcmk__xe_set_int(output, PCMK_XA_NO_QUORUM_PANIC, 1);
    }

    rc = pcmk_schedulerd_api_graph(schedulerd_api, output, &ref);
    if (rc != pcmk_rc_ok) {
        free(ref);
        crm_err("Could not contact the scheduler: %s " QB_XS " rc=%d",
                pcmk_rc_str(rc), rc);
        register_fsa_error_adv(C_FSA_INTERNAL, I_ERROR, NULL, NULL, __func__);
    } else {
        pcmk__assert(ref != NULL);
        controld_expect_sched_reply(ref);
        crm_debug("Invoking the scheduler: query=%d, ref=%s, seq=%llu, "
                  "quorate=%s",
                  fsa_pe_query, controld_globals.fsa_pe_ref,
                  controld_globals.peer_seq,
                  pcmk__flag_text(controld_globals.flags, controld_has_quorum));
    }
}

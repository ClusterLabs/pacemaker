/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/pengine/rules.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/ipc_internal.h>

#include <pacemaker-controld.h>

static qb_ipcs_service_t *ipcs = NULL;

static crm_trigger_t *config_read_trigger = NULL;

#if SUPPORT_COROSYNC
extern gboolean crm_connect_corosync(pcmk_cluster_t *cluster);
#endif

static void crm_shutdown(int nsig);
static gboolean crm_read_options(gpointer user_data);

/*	 A_HA_CONNECT	*/
void
do_ha_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean registered = FALSE;
    static pcmk_cluster_t *cluster = NULL;

    if (cluster == NULL) {
        cluster = pcmk_cluster_new();
    }

    if (action & A_HA_DISCONNECT) {
        pcmk_cluster_disconnect(cluster);
        crm_info("Disconnected from the cluster");

        controld_set_fsa_input_flags(R_HA_DISCONNECTED);
    }

    if (action & A_HA_CONNECT) {
        pcmk__cluster_set_status_callback(&peer_update_callback);
        pcmk__cluster_set_autoreap(false);

#if SUPPORT_COROSYNC
        if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
            registered = crm_connect_corosync(cluster);
        }
#endif // SUPPORT_COROSYNC

        if (registered) {
            controld_election_init(cluster->uname);
            controld_globals.our_nodename = cluster->uname;
            controld_globals.our_uuid = cluster->uuid;
            if(cluster->uuid == NULL) {
                crm_err("Could not obtain local uuid");
                registered = FALSE;
            }
        }

        if (!registered) {
            controld_set_fsa_input_flags(R_HA_DISCONNECTED);
            register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
            return;
        }

        populate_cib_nodes(node_update_none, __func__);
        controld_clear_fsa_input_flags(R_HA_DISCONNECTED);
        crm_info("Connected to the cluster");
    }

    if (action & ~(A_HA_CONNECT | A_HA_DISCONNECT)) {
        crm_err("Unexpected action %s in %s", fsa_action2string(action),
                __func__);
    }
}

/*	 A_SHUTDOWN	*/
void
do_shutdown(long long action,
            enum crmd_fsa_cause cause,
            enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    /* just in case */
    controld_set_fsa_input_flags(R_SHUTDOWN);
    controld_disconnect_fencer(FALSE);
}

/*	 A_SHUTDOWN_REQ	*/
void
do_shutdown_req(long long action,
                enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    xmlNode *msg = NULL;

    controld_set_fsa_input_flags(R_SHUTDOWN);
    //controld_set_fsa_input_flags(R_STAYDOWN);
    crm_info("Sending shutdown request to all peers (DC is %s)",
             pcmk__s(controld_globals.dc_name, "not set"));
    msg = create_request(CRM_OP_SHUTDOWN_REQ, NULL, NULL, CRM_SYSTEM_CRMD, CRM_SYSTEM_CRMD, NULL);

    if (!pcmk__cluster_send_message(NULL, crm_msg_crmd, msg)) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
    pcmk__xml_free(msg);
}

void
crmd_fast_exit(crm_exit_t exit_code)
{
    if (pcmk_is_set(controld_globals.fsa_input_register, R_STAYDOWN)) {
        crm_warn("Inhibiting respawn "CRM_XS" remapping exit code %d to %d",
                 exit_code, CRM_EX_FATAL);
        exit_code = CRM_EX_FATAL;

    } else if ((exit_code == CRM_EX_OK)
               && pcmk_is_set(controld_globals.fsa_input_register,
                              R_IN_RECOVERY)) {
        crm_err("Could not recover from internal error");
        exit_code = CRM_EX_ERROR;
    }

    if (controld_globals.logger_out != NULL) {
        controld_globals.logger_out->finish(controld_globals.logger_out,
                                            exit_code, true, NULL);
        pcmk__output_free(controld_globals.logger_out);
        controld_globals.logger_out = NULL;
    }

    crm_exit(exit_code);
}

crm_exit_t
crmd_exit(crm_exit_t exit_code)
{
    GMainLoop *mloop = controld_globals.mainloop;

    static bool in_progress = FALSE;

    if (in_progress && (exit_code == CRM_EX_OK)) {
        crm_debug("Exit is already in progress");
        return exit_code;

    } else if(in_progress) {
        crm_notice("Error during shutdown process, exiting now with status %d (%s)",
                   exit_code, crm_exit_str(exit_code));
        crm_write_blackbox(SIGTRAP, NULL);
        crmd_fast_exit(exit_code);
    }

    in_progress = TRUE;
    crm_trace("Preparing to exit with status %d (%s)",
              exit_code, crm_exit_str(exit_code));

    /* Suppress secondary errors resulting from us disconnecting everything */
    controld_set_fsa_input_flags(R_HA_DISCONNECTED);

/* Close all IPC servers and clients to ensure any and all shared memory files are cleaned up */

    if(ipcs) {
        crm_trace("Closing IPC server");
        mainloop_del_ipc_server(ipcs);
        ipcs = NULL;
    }

    controld_close_attrd_ipc();
    controld_shutdown_schedulerd_ipc();
    controld_disconnect_fencer(TRUE);

    if ((exit_code == CRM_EX_OK) && (controld_globals.mainloop == NULL)) {
        crm_debug("No mainloop detected");
        exit_code = CRM_EX_ERROR;
    }

    /* On an error, just get out.
     *
     * Otherwise, make the effort to have mainloop exit gracefully so
     * that it (mostly) cleans up after itself and valgrind has less
     * to report on - allowing real errors stand out
     */
    if (exit_code != CRM_EX_OK) {
        crm_notice("Forcing immediate exit with status %d (%s)",
                   exit_code, crm_exit_str(exit_code));
        crm_write_blackbox(SIGTRAP, NULL);
        crmd_fast_exit(exit_code);
    }

/* Clean up as much memory as possible for valgrind */

    for (GList *iter = controld_globals.fsa_message_queue; iter != NULL;
         iter = iter->next) {
        fsa_data_t *fsa_data = (fsa_data_t *) iter->data;

        crm_info("Dropping %s: [ state=%s cause=%s origin=%s ]",
                 fsa_input2string(fsa_data->fsa_input),
                 fsa_state2string(controld_globals.fsa_state),
                 fsa_cause2string(fsa_data->fsa_cause), fsa_data->origin);
        delete_fsa_input(fsa_data);
    }

    controld_clear_fsa_input_flags(R_MEMBERSHIP);

    g_list_free(controld_globals.fsa_message_queue);
    controld_globals.fsa_message_queue = NULL;

    controld_free_node_pending_timers();
    controld_election_fini();

    /* Tear down the CIB manager connection, but don't free it yet -- it could
     * be used when we drain the mainloop later.
     */

    controld_disconnect_cib_manager();

    verify_stopped(controld_globals.fsa_state, LOG_WARNING);
    controld_clear_fsa_input_flags(R_LRM_CONNECTED);
    lrm_state_destroy_all();

    mainloop_destroy_trigger(config_read_trigger);
    config_read_trigger = NULL;

    controld_destroy_fsa_trigger();
    controld_destroy_transition_trigger();

    pcmk__client_cleanup();
    pcmk__cluster_destroy_node_caches();

    controld_free_fsa_timers();
    te_cleanup_stonith_history_sync(NULL, TRUE);
    controld_free_sched_timer();

    free(controld_globals.our_nodename);
    controld_globals.our_nodename = NULL;

    free(controld_globals.our_uuid);
    controld_globals.our_uuid = NULL;

    free(controld_globals.dc_name);
    controld_globals.dc_name = NULL;

    free(controld_globals.dc_version);
    controld_globals.dc_version = NULL;

    free(controld_globals.cluster_name);
    controld_globals.cluster_name = NULL;

    free(controld_globals.te_uuid);
    controld_globals.te_uuid = NULL;

    free_max_generation();
    controld_destroy_failed_sync_table();
    controld_destroy_outside_events_table();

    mainloop_destroy_signal(SIGPIPE);
    mainloop_destroy_signal(SIGUSR1);
    mainloop_destroy_signal(SIGTERM);
    mainloop_destroy_signal(SIGTRAP);
    /* leave SIGCHLD engaged as we might still want to drain some service-actions */

    if (mloop) {
        GMainContext *ctx = g_main_loop_get_context(controld_globals.mainloop);

        /* Don't re-enter this block */
        controld_globals.mainloop = NULL;

        /* no signals on final draining anymore */
        mainloop_destroy_signal(SIGCHLD);

        crm_trace("Draining mainloop %d %d", g_main_loop_is_running(mloop), g_main_context_pending(ctx));

        {
            int lpc = 0;

            while((g_main_context_pending(ctx) && lpc < 10)) {
                lpc++;
                crm_trace("Iteration %d", lpc);
                g_main_context_dispatch(ctx);
            }
        }

        crm_trace("Closing mainloop %d %d", g_main_loop_is_running(mloop), g_main_context_pending(ctx));
        g_main_loop_quit(mloop);

        /* Won't do anything yet, since we're inside it now */
        g_main_loop_unref(mloop);
    } else {
        mainloop_destroy_signal(SIGCHLD);
    }

    cib_delete(controld_globals.cib_conn);
    controld_globals.cib_conn = NULL;

    throttle_fini();

    /* Graceful */
    crm_trace("Done preparing for exit with status %d (%s)",
              exit_code, crm_exit_str(exit_code));
    return exit_code;
}

/*	 A_EXIT_0, A_EXIT_1	*/
void
do_exit(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    crm_exit_t exit_code = CRM_EX_OK;

    if (pcmk_is_set(action, A_EXIT_1)) {
        exit_code = CRM_EX_ERROR;
        crm_err("Exiting now due to errors");
    }
    verify_stopped(cur_state, LOG_ERR);
    crmd_exit(exit_code);
}

static void sigpipe_ignore(int nsig) { return; }

/*	 A_STARTUP	*/
void
do_startup(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    crm_debug("Registering Signal Handlers");
    mainloop_add_signal(SIGTERM, crm_shutdown);
    mainloop_add_signal(SIGPIPE, sigpipe_ignore);

    config_read_trigger = mainloop_add_trigger(G_PRIORITY_HIGH,
                                               crm_read_options, NULL);

    controld_init_fsa_trigger();
    controld_init_transition_trigger();

    crm_debug("Creating CIB manager and executor objects");
    controld_globals.cib_conn = cib_new();

    lrm_state_init_local();
    if (controld_init_fsa_timers() == FALSE) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
}

// \return libqb error code (0 on success, -errno on error)
static int32_t
accept_controller_client(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crm_trace("Accepting new IPC client connection");
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

// \return libqb error code (0 on success, -errno on error)
static int32_t
dispatch_controller_ipc(qb_ipcs_connection_t * c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);

    xmlNode *msg = pcmk__client_data2xml(client, data, &id, &flags);

    if (msg == NULL) {
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_PROTOCOL);
        return 0;
    }
    pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                       CRM_EX_INDETERMINATE);

    CRM_ASSERT(client->user != NULL);
    pcmk__update_acl_user(msg, PCMK__XA_CRM_USER, client->user);

    crm_xml_add(msg, PCMK__XA_CRM_SYS_FROM, client->id);
    if (controld_authorize_ipc_message(msg, client, NULL)) {
        crm_trace("Processing IPC message from client %s",
                  pcmk__client_name(client));
        route_message(C_IPC_MESSAGE, msg);
    }

    controld_trigger_fsa();
    pcmk__xml_free(msg);
    return 0;
}

static int32_t
ipc_client_disconnected(qb_ipcs_connection_t *c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client) {
        crm_trace("Disconnecting %sregistered client %s (%p/%p)",
                  (client->userdata? "" : "un"), pcmk__client_name(client),
                  c, client);
        free(client->userdata);
        pcmk__free_client(client);
        controld_trigger_fsa();
    }
    return 0;
}

static void
ipc_connection_destroyed(qb_ipcs_connection_t *c)
{
    crm_trace("Connection %p", c);
    ipc_client_disconnected(c);
}

/*	 A_STOP	*/
void
do_stop(long long action,
        enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    crm_trace("Closing IPC server");
    mainloop_del_ipc_server(ipcs); ipcs = NULL;
    register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

/*	 A_STARTED	*/
void
do_started(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    static struct qb_ipcs_service_handlers crmd_callbacks = {
        .connection_accept = accept_controller_client,
        .connection_created = NULL,
        .msg_process = dispatch_controller_ipc,
        .connection_closed = ipc_client_disconnected,
        .connection_destroyed = ipc_connection_destroyed
    };

    if (cur_state != S_STARTING) {
        crm_err("Start cancelled... %s", fsa_state2string(cur_state));
        return;

    } else if (!pcmk_is_set(controld_globals.fsa_input_register,
                            R_MEMBERSHIP)) {
        crm_info("Delaying start, no membership data (%.16llx)", R_MEMBERSHIP);

        crmd_fsa_stall(TRUE);
        return;

    } else if (!pcmk_is_set(controld_globals.fsa_input_register,
                            R_LRM_CONNECTED)) {
        crm_info("Delaying start, not connected to executor (%.16llx)", R_LRM_CONNECTED);

        crmd_fsa_stall(TRUE);
        return;

    } else if (!pcmk_is_set(controld_globals.fsa_input_register,
                            R_CIB_CONNECTED)) {
        crm_info("Delaying start, CIB not connected (%.16llx)", R_CIB_CONNECTED);

        crmd_fsa_stall(TRUE);
        return;

    } else if (!pcmk_is_set(controld_globals.fsa_input_register,
                            R_READ_CONFIG)) {
        crm_info("Delaying start, Config not read (%.16llx)", R_READ_CONFIG);

        crmd_fsa_stall(TRUE);
        return;

    } else if (!pcmk_is_set(controld_globals.fsa_input_register, R_PEER_DATA)) {

        crm_info("Delaying start, No peer data (%.16llx)", R_PEER_DATA);
        crmd_fsa_stall(TRUE);
        return;
    }

    crm_debug("Init server comms");
    ipcs = pcmk__serve_controld_ipc(&crmd_callbacks);
    if (ipcs == NULL) {
        crm_err("Failed to create IPC server: shutting down and inhibiting respawn");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    } else {
        crm_notice("Pacemaker controller successfully started and accepting connections");
    }
    controld_set_fsa_input_flags(R_ST_REQUIRED);
    controld_timer_fencer_connect(GINT_TO_POINTER(TRUE));

    controld_clear_fsa_input_flags(R_STARTING);
    register_fsa_input(msg_data->fsa_cause, I_PENDING, NULL);
}

/*	 A_RECOVER	*/
void
do_recover(long long action,
           enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    controld_set_fsa_input_flags(R_IN_RECOVERY);
    crm_warn("Fast-tracking shutdown in response to errors");

    register_fsa_input(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

static void
config_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    const char *value = NULL;
    GHashTable *config_hash = NULL;
    crm_time_t *now = crm_time_new(NULL);
    xmlNode *crmconfig = NULL;
    xmlNode *alerts = NULL;

    if (rc != pcmk_ok) {
        fsa_data_t *msg_data = NULL;

        crm_err("Local CIB query resulted in an error: %s", pcmk_strerror(rc));
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);

        if (rc == -EACCES || rc == -pcmk_err_schema_validation) {
            crm_err("The cluster is mis-configured - shutting down and staying down");
            controld_set_fsa_input_flags(R_STAYDOWN);
        }
        goto bail;
    }

    crmconfig = output;
    if ((crmconfig != NULL) && !pcmk__xe_is(crmconfig, PCMK_XE_CRM_CONFIG)) {
        crmconfig = pcmk__xe_first_child(crmconfig, PCMK_XE_CRM_CONFIG, NULL,
                                         NULL);
    }
    if (!crmconfig) {
        fsa_data_t *msg_data = NULL;

        crm_err("Local CIB query for " PCMK_XE_CRM_CONFIG " section failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        goto bail;
    }

    crm_debug("Call %d : Parsing CIB options", call_id);
    config_hash = pcmk__strkey_table(free, free);
    pe_unpack_nvpairs(crmconfig, crmconfig, PCMK_XE_CLUSTER_PROPERTY_SET, NULL,
                      config_hash, PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, FALSE, now,
                      NULL);

    // Validate all options, and use defaults if not already present in hash
    pcmk__validate_cluster_options(config_hash);

    /* Validate the watchdog timeout in the context of the local node
     * environment. If invalid, the controller will exit with a fatal error.
     *
     * We do this via a wrapper in the controller, so that we call
     * pcmk__valid_stonith_watchdog_timeout() only if watchdog fencing is
     * enabled for the local node. Otherwise, we may exit unnecessarily.
     *
     * A validator function in libcrmcommon can't act as such a wrapper, because
     * it doesn't have a stonith API connection or the local node name.
     */
    value = g_hash_table_lookup(config_hash, PCMK_OPT_STONITH_WATCHDOG_TIMEOUT);
    controld_verify_stonith_watchdog_timeout(value);

    value = g_hash_table_lookup(config_hash, PCMK_OPT_NO_QUORUM_POLICY);
    if (pcmk__str_eq(value, PCMK_VALUE_FENCE_LEGACY, pcmk__str_casei)
        && (pcmk__locate_sbd() != 0)) {
        controld_set_global_flags(controld_no_quorum_suicide);
    }

    value = g_hash_table_lookup(config_hash, PCMK_OPT_SHUTDOWN_LOCK);
    if (crm_is_true(value)) {
        controld_set_global_flags(controld_shutdown_lock_enabled);
    } else {
        controld_clear_global_flags(controld_shutdown_lock_enabled);
    }

    value = g_hash_table_lookup(config_hash, PCMK_OPT_SHUTDOWN_LOCK_LIMIT);
    pcmk_parse_interval_spec(value, &controld_globals.shutdown_lock_limit);
    controld_globals.shutdown_lock_limit /= 1000;

    value = g_hash_table_lookup(config_hash, PCMK_OPT_NODE_PENDING_TIMEOUT);
    pcmk_parse_interval_spec(value, &controld_globals.node_pending_timeout);
    controld_globals.node_pending_timeout /= 1000;

    value = g_hash_table_lookup(config_hash, PCMK_OPT_CLUSTER_NAME);
    pcmk__str_update(&(controld_globals.cluster_name), value);

    // Let subcomponents initialize their own static variables
    controld_configure_election(config_hash);
    controld_configure_fencing(config_hash);
    controld_configure_fsa_timers(config_hash);
    controld_configure_throttle(config_hash);

    alerts = pcmk__xe_first_child(output, PCMK_XE_ALERTS, NULL, NULL);
    crmd_unpack_alerts(alerts);

    controld_set_fsa_input_flags(R_READ_CONFIG);
    controld_trigger_fsa();

    g_hash_table_destroy(config_hash);
  bail:
    crm_time_free(now);
}

/*!
 * \internal
 * \brief Trigger read and processing of the configuration
 *
 * \param[in] fn    Calling function name
 * \param[in] line  Line number where call occurred
 */
void
controld_trigger_config_as(const char *fn, int line)
{
    if (config_read_trigger != NULL) {
        crm_trace("%s:%d - Triggered config processing", fn, line);
        mainloop_set_trigger(config_read_trigger);
    }
}

gboolean
crm_read_options(gpointer user_data)
{
    cib_t *cib_conn = controld_globals.cib_conn;
    int call_id = cib_conn->cmds->query(cib_conn,
                                        "//" PCMK_XE_CRM_CONFIG
                                        " | //" PCMK_XE_ALERTS,
                                        NULL, cib_xpath|cib_scope_local);

    fsa_register_cib_callback(call_id, NULL, config_query_callback);
    crm_trace("Querying the CIB... call %d", call_id);
    return TRUE;
}

/*	 A_READCONFIG	*/
void
do_read_config(long long action,
               enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state,
               enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    throttle_init();
    controld_trigger_config();
}

static void
crm_shutdown(int nsig)
{
    const char *value = NULL;
    guint default_period_ms = 0;

    if ((controld_globals.mainloop == NULL)
        || !g_main_loop_is_running(controld_globals.mainloop)) {
        crmd_exit(CRM_EX_OK);
        return;
    }

    if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        crm_err("Escalating shutdown");
        register_fsa_input_before(C_SHUTDOWN, I_ERROR, NULL);
        return;
    }

    controld_set_fsa_input_flags(R_SHUTDOWN);
    register_fsa_input(C_SHUTDOWN, I_SHUTDOWN, NULL);

    /* If shutdown timer doesn't have a period set, use the default
     *
     * @TODO: Evaluate whether this is still necessary. As long as
     * config_query_callback() has been run at least once, it doesn't look like
     * anything could have changed the timer period since then.
     */
    value = pcmk__cluster_option(NULL, PCMK_OPT_SHUTDOWN_ESCALATION);
    pcmk_parse_interval_spec(value, &default_period_ms);
    controld_shutdown_start_countdown(default_period_ms);
}

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
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>

#include <pacemaker-controld.h>

static qb_ipcs_service_t *ipcs = NULL;

static crm_trigger_t *config_read_trigger = NULL;

#if SUPPORT_COROSYNC
extern gboolean crm_connect_corosync(pcmk_cluster_t *cluster);
#endif

static void crm_shutdown(int nsig);
static gboolean crm_read_options(gpointer user_data);

// A_HA_CONNECT
void
do_ha_control(long long action, enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
              fsa_data_t *msg_data)
{
    bool connected = false;

    if (controld_globals.cluster == NULL) {
        controld_globals.cluster = pcmk_cluster_new();
    }

    if (pcmk__is_set(action, A_HA_DISCONNECT)) {
        pcmk_cluster_disconnect(controld_globals.cluster);
        controld_set_fsa_input_flags(R_HA_DISCONNECTED);
        pcmk__info("Disconnected from the cluster");
    }

    if (pcmk__is_set(action, A_HA_CONNECT)) {
        pcmk__cluster_set_status_callback(&peer_update_callback);
        pcmk__cluster_set_autoreap(false);

#if SUPPORT_COROSYNC
        if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
            connected = crm_connect_corosync(controld_globals.cluster);
        }
#endif // SUPPORT_COROSYNC

        if (connected) {
            pcmk__node_status_t *node = controld_get_local_node_status();

            controld_election_init();

            pcmk__str_update(&(controld_globals.our_uuid),
                             pcmk__cluster_get_xml_id(node));

            if (controld_globals.our_uuid == NULL) {
                pcmk__err("Could not obtain local node UUID");
                connected = false;
            }
        }

        if (!connected) {
            controld_set_fsa_input_flags(R_HA_DISCONNECTED);
            register_fsa_error(I_ERROR, msg_data);
            return;
        }

        populate_cib_nodes(controld_node_update_none, __func__);
        controld_clear_fsa_input_flags(R_HA_DISCONNECTED);
        pcmk__info("Connected to the cluster");
    }

    if ((action & ~(A_HA_CONNECT|A_HA_DISCONNECT)) != 0) {
        pcmk__err("Unexpected action %s in %s", fsa_action2string(action),
                  __func__);
    }
}

// A_SHUTDOWN
void
do_shutdown(long long action, enum crmd_fsa_cause cause,
            enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
            fsa_data_t *msg_data)
{
    // Just in case
    controld_set_fsa_input_flags(R_SHUTDOWN);
    controld_disconnect_fencer(false);
}

// A_SHUTDOWN_REQ
void
do_shutdown_req(long long action, enum crmd_fsa_cause cause,
                enum crmd_fsa_state cur_state,
                enum crmd_fsa_input current_input, fsa_data_t *msg_data)
{
    xmlNode *msg = NULL;

    pcmk__info("Sending shutdown request to all peers (DC is %s)",
               pcmk__s(controld_globals.dc_name, "not set"));

    controld_set_fsa_input_flags(R_SHUTDOWN);
    msg = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_CRMD, NULL,
                            CRM_SYSTEM_CRMD, CRM_OP_SHUTDOWN_REQ, NULL);

    if (!pcmk__cluster_send_message(NULL, pcmk_ipc_controld, msg)) {
        register_fsa_error(I_ERROR, msg_data);
    }
    pcmk__xml_free(msg);
}

void
crmd_fast_exit(crm_exit_t exit_code)
{
    if (pcmk__is_set(controld_globals.fsa_input_register, R_STAYDOWN)) {
        pcmk__warn("Inhibiting respawn " QB_XS " remapping exit code %d to %d",
                   exit_code, CRM_EX_FATAL);
        exit_code = CRM_EX_FATAL;

    } else if ((exit_code == CRM_EX_OK)
               && pcmk__is_set(controld_globals.fsa_input_register,
                               R_IN_RECOVERY)) {
        pcmk__err("Could not recover from internal error");
        exit_code = CRM_EX_ERROR;
    }

    if (controld_globals.logger_out != NULL) {
        controld_globals.logger_out->finish(controld_globals.logger_out,
                                            exit_code, true, NULL);
        g_clear_pointer(&controld_globals.logger_out, pcmk__output_free);
    }

    crm_exit(exit_code);
}

crm_exit_t
crmd_exit(crm_exit_t exit_code)
{
    GMainLoop *mloop = controld_globals.mainloop;

    static bool in_progress = FALSE;

    if (in_progress && (exit_code == CRM_EX_OK)) {
        pcmk__debug("Exit is already in progress");
        return exit_code;

    } else if(in_progress) {
        pcmk__notice("Error during shutdown process, exiting now with status "
                     "%d (%s)",
                     exit_code, crm_exit_str(exit_code));
        crm_write_blackbox(SIGTRAP, NULL);
        crmd_fast_exit(exit_code);
    }

    in_progress = TRUE;
    pcmk__trace("Preparing to exit with status %d (%s)", exit_code,
                crm_exit_str(exit_code));

    /* Suppress secondary errors resulting from us disconnecting everything */
    controld_set_fsa_input_flags(R_HA_DISCONNECTED);

/* Close all IPC servers and clients to ensure any and all shared memory files are cleaned up */

    if(ipcs) {
        pcmk__trace("Closing IPC server");
        g_clear_pointer(&ipcs, mainloop_del_ipc_server);
    }

    controld_close_attrd_ipc();
    controld_shutdown_schedulerd_ipc();
    controld_disconnect_fencer(TRUE);

    if ((exit_code == CRM_EX_OK) && (controld_globals.mainloop == NULL)) {
        pcmk__debug("No mainloop detected");
        exit_code = CRM_EX_ERROR;
    }

    /* On an error, just get out.
     *
     * Otherwise, make the effort to have mainloop exit gracefully so
     * that it (mostly) cleans up after itself and valgrind has less
     * to report on - allowing real errors stand out
     */
    if (exit_code != CRM_EX_OK) {
        pcmk__notice("Forcing immediate exit with status %d (%s)", exit_code,
                     crm_exit_str(exit_code));
        crm_write_blackbox(SIGTRAP, NULL);
        crmd_fast_exit(exit_code);
    }

/* Clean up as much memory as possible for valgrind */

    controld_clear_fsa_input_flags(R_MEMBERSHIP);

    g_queue_free_full(controld_globals.fsa_message_queue,
                      (GDestroyNotify) delete_fsa_input);
    controld_globals.fsa_message_queue = NULL;

    controld_free_node_pending_timers();
    election_reset(controld_globals.cluster); // Stop any election timer

    /* Tear down the CIB manager connection, but don't free it yet -- it could
     * be used when we drain the mainloop later.
     */

    controld_disconnect_cib_manager();

    verify_stopped(controld_globals.fsa_state, LOG_WARNING);
    controld_clear_fsa_input_flags(R_LRM_CONNECTED);
    lrm_state_destroy_all();

    g_clear_pointer(&config_read_trigger, mainloop_destroy_trigger);

    controld_destroy_fsa_trigger();
    controld_destroy_transition_trigger();

    pcmk__client_cleanup();
    pcmk__cluster_destroy_node_caches();

    controld_free_fsa_timers();
    controld_cleanup_fencing_history_sync(NULL, true);
    controld_free_sched_timer();

    g_clear_pointer(&controld_globals.our_uuid, free);
    g_clear_pointer(&controld_globals.dc_name, free);
    g_clear_pointer(&controld_globals.dc_version, free);
    g_clear_pointer(&controld_globals.cluster_name, free);
    g_clear_pointer(&controld_globals.te_uuid, free);

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

        pcmk__trace("Draining mainloop %d %d", g_main_loop_is_running(mloop),
                    g_main_context_pending(ctx));

        {
            int lpc = 0;

            while((g_main_context_pending(ctx) && lpc < 10)) {
                lpc++;
                pcmk__trace("Iteration %d", lpc);
                g_main_context_dispatch(ctx);
            }
        }

        pcmk__trace("Closing mainloop %d %d", g_main_loop_is_running(mloop),
                    g_main_context_pending(ctx));
        g_main_loop_quit(mloop);

    } else {
        mainloop_destroy_signal(SIGCHLD);
    }

    g_clear_pointer(&controld_globals.cib_conn, cib_delete);

    throttle_fini();

    g_clear_pointer(&controld_globals.cluster, pcmk_cluster_free);

    /* Graceful */
    pcmk__trace("Done preparing for exit with status %d (%s)", exit_code,
                crm_exit_str(exit_code));
    return exit_code;
}

// A_EXIT_0, A_EXIT_1
void
do_exit(long long action, enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
        fsa_data_t *msg_data)
{
    crm_exit_t exit_code = CRM_EX_OK;

    if (pcmk__is_set(action, A_EXIT_1)) {
        exit_code = CRM_EX_ERROR;
        pcmk__err("Exiting now due to errors");
    }
    verify_stopped(cur_state, LOG_ERR);
    crmd_exit(exit_code);
}

// A_STARTUP
void
do_startup(long long action, enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
           fsa_data_t *msg_data)
{
    mainloop_add_signal(SIGTERM, crm_shutdown);
    mainloop_add_signal(SIGPIPE, NULL); // Ignore SIGPIPE

    config_read_trigger = mainloop_add_trigger(G_PRIORITY_HIGH,
                                               crm_read_options, NULL);
    controld_init_fsa_trigger();
    controld_init_transition_trigger();

    controld_globals.cib_conn = cib_new();

    lrm_state_init_local();
    if (!controld_init_fsa_timers()) {
        register_fsa_error(I_ERROR, msg_data);
    }
}

// \return libqb error code (0 on success, -errno on error)
static int32_t
accept_controller_client(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    pcmk__trace("Accepting new IPC client connection");
    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

// \return libqb error code (0 on success, -errno on error)
static int32_t
dispatch_controller_ipc(qb_ipcs_connection_t * c, void *data, size_t size)
{
    int rc = pcmk_rc_ok;
    uint32_t id = 0;
    uint32_t flags = 0;
    pcmk__client_t *client = pcmk__find_client(c);
    xmlNode *msg = NULL;

    // Sanity-check, and parse XML from IPC data
    CRM_CHECK(client != NULL, return 0);
    if (data == NULL) {
        pcmk__debug("No IPC data from PID %d", pcmk__client_pid(c));
        return 0;
    }

    rc = pcmk__ipc_msg_append(&client->buffer, data);

    if (rc == pcmk_rc_ipc_more) {
        /* We haven't read the complete message yet, so just return. */
        return 0;

    } else if (rc == pcmk_rc_ok) {
        /* We've read the complete message and there's already a header on
         * the front.  Pass it off for processing.
         */
        msg = pcmk__client_data2xml(client, &id, &flags);
        g_byte_array_free(client->buffer, TRUE);
        client->buffer = NULL;

    } else {
        /* Some sort of error occurred reassembling the message.  All we can
         * do is clean up, log an error and return.
         */
        pcmk__err("Error when reading IPC message: %s", pcmk_rc_str(rc));

        if (client->buffer != NULL) {
            g_byte_array_free(client->buffer, TRUE);
            client->buffer = NULL;
        }

        return 0;
    }

    if (msg == NULL) {
        pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                           CRM_EX_PROTOCOL);
        return 0;
    }
    pcmk__ipc_send_ack(client, id, flags, PCMK__XE_ACK, NULL,
                       CRM_EX_INDETERMINATE);

    pcmk__assert(client->user != NULL);
    pcmk__update_acl_user(msg, PCMK__XA_CRM_USER, client->user);

    pcmk__xe_set(msg, PCMK__XA_CRM_SYS_FROM, client->id);
    if (controld_authorize_ipc_message(msg, client, NULL)) {
        pcmk__trace("Processing IPC message from client %s",
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
        pcmk__trace("Disconnecting %sregistered client %s (%p/%p)",
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
    pcmk__trace("Connection %p", c);
    ipc_client_disconnected(c);
}

// A_STOP
void
do_stop(long long action, enum crmd_fsa_cause cause,
        enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
        fsa_data_t *msg_data)
{
    pcmk__trace("Stopping IPC server");
    g_clear_pointer(&ipcs, mainloop_del_ipc_server);
    controld_fsa_append(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

// A_STARTED
void
do_started(long long action, enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
           fsa_data_t *msg_data)
{
    static struct qb_ipcs_service_handlers crmd_callbacks = {
        .connection_accept = accept_controller_client,
        .connection_created = NULL,
        .msg_process = dispatch_controller_ipc,
        .connection_closed = ipc_client_disconnected,
        .connection_destroyed = ipc_connection_destroyed,
    };

    if (cur_state != S_STARTING) {
        pcmk__err("Start cancelled: current state is %s",
                  fsa_state2string(cur_state));
        return;
    }

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_MEMBERSHIP)) {
        pcmk__info("Delaying start: no membership data (%.16" PRIx64 ")",
                   R_MEMBERSHIP);
        controld_fsa_stall(NULL, action);
        return;
    }

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_LRM_CONNECTED)) {
        pcmk__info("Delaying start: not connected to executor (%.16" PRIx64 ")",
                   R_LRM_CONNECTED);
        controld_fsa_stall(NULL, action);
        return;
    }

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_CIB_CONNECTED)) {
        pcmk__info("Delaying start: not connected to CIB manager "
                   "(%.16" PRIx64 ")",
                   R_CIB_CONNECTED);
        controld_fsa_stall(NULL, action);
        return;
    }

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_READ_CONFIG)) {
        pcmk__info("Delaying start: config not read (%.16" PRIx64 ")",
                   R_READ_CONFIG);
        controld_fsa_stall(NULL, action);
        return;
    }

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_PEER_DATA)) {
        pcmk__info("Delaying start: no peer data (%.16" PRIx64 ")",
                   R_PEER_DATA);
        controld_fsa_stall(NULL, action);
        return;
    }

    pcmk__debug("Initializing IPC server");
    ipcs = pcmk__serve_controld_ipc(&crmd_callbacks);

    if (ipcs == NULL) {
        pcmk__err("Failed to create IPC server: shutting down and inhibiting "
                  "respawn");
        register_fsa_error(I_ERROR, msg_data);

    } else {
        pcmk__notice("Pacemaker controller successfully started and accepting "
                     "connections");
    }
    controld_set_fsa_input_flags(R_ST_REQUIRED);
    controld_timer_fencer_connect(GINT_TO_POINTER(TRUE));

    controld_fsa_append(msg_data->fsa_cause, I_PENDING, NULL);
}

// A_RECOVER
void
do_recover(long long action, enum crmd_fsa_cause cause,
           enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
           fsa_data_t *msg_data)
{
    pcmk__warn("Fast-tracking shutdown in response to errors");
    controld_set_fsa_input_flags(R_IN_RECOVERY);
    controld_fsa_append(C_FSA_INTERNAL, I_TERMINATE, NULL);
}

static void
config_query_callback(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    const char *value = NULL;
    GHashTable *config_hash = NULL;
    crm_time_t *now = crm_time_new(NULL);
    xmlNode *crmconfig = NULL;
    xmlNode *alerts = NULL;
    pcmk_rule_input_t rule_input = {
        .now = now,
    };

    if (rc != pcmk_ok) {
        pcmk__err("Local CIB query resulted in an error: %s",
                  pcmk_strerror(rc));
        register_fsa_error(I_ERROR, NULL);

        if (rc == -EACCES || rc == -pcmk_err_schema_validation) {
            pcmk__err("The cluster is mis-configured - shutting down and "
                      "staying down");
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
        pcmk__err("Local CIB query for " PCMK_XE_CRM_CONFIG " section failed");
        register_fsa_error(I_ERROR, NULL);
        goto bail;
    }

    pcmk__debug("Call %d : Parsing CIB options", call_id);
    config_hash = pcmk__strkey_table(free, free);
    pcmk_unpack_nvpair_blocks(crmconfig, PCMK_XE_CLUSTER_PROPERTY_SET,
                              PCMK_VALUE_CIB_BOOTSTRAP_OPTIONS, &rule_input,
                              config_hash, NULL);

    // Validate all options, and use defaults if not already present in hash
    pcmk__validate_cluster_options(config_hash);

    /* Validate the watchdog timeout in the context of the local node
     * environment. If invalid, the controller will exit with a fatal error.
     *
     * We do this via a wrapper in the controller, so that we call
     * pcmk__valid_fencing_watchdog_timeout() only if watchdog fencing is
     * enabled for the local node. Otherwise, we may exit unnecessarily.
     *
     * A validator function in libcrmcommon can't act as such a wrapper, because
     * it doesn't have a fencer API connection or the local node name.
     */
    value = g_hash_table_lookup(config_hash, PCMK_OPT_FENCING_WATCHDOG_TIMEOUT);
    controld_validate_fencing_watchdog_timeout(value);

    value = g_hash_table_lookup(config_hash, PCMK_OPT_NO_QUORUM_POLICY);
    if (pcmk__strcase_any_of(value, PCMK_VALUE_FENCE, PCMK_VALUE_FENCE_LEGACY,
                             NULL)
        && (pcmk__locate_sbd() != 0)) {
        controld_set_global_flags(controld_no_quorum_panic);
    }

    value = g_hash_table_lookup(config_hash, PCMK_OPT_SHUTDOWN_LOCK);
    if (pcmk__is_true(value)) {
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
        pcmk__trace("%s:%d - Triggered config processing", fn, line);
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
                                        NULL, cib_xpath);

    fsa_register_cib_callback(call_id, NULL, config_query_callback);
    pcmk__trace("Querying the CIB... call %d", call_id);
    return TRUE;
}

// A_READCONFIG
void
do_read_config(long long action, enum crmd_fsa_cause cause,
               enum crmd_fsa_state cur_state, enum crmd_fsa_input current_input,
               fsa_data_t *msg_data)
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

    if (pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        pcmk__err("Escalating shutdown");
        controld_fsa_prepend(C_SHUTDOWN, I_ERROR, NULL);
        return;
    }

    controld_set_fsa_input_flags(R_SHUTDOWN);
    controld_fsa_append(C_SHUTDOWN, I_SHUTDOWN, NULL);

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

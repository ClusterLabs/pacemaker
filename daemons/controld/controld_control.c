/*
 * Copyright 2004-2023 the Pacemaker project contributors
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
#include <crm/msg_xml.h>
#include <crm/pengine/rules.h>
#include <crm/cluster/internal.h>
#include <crm/cluster/election_internal.h>
#include <crm/common/ipc_internal.h>

#include <pacemaker-controld.h>

static qb_ipcs_service_t *ipcs = NULL;

static crm_trigger_t *config_read_trigger = NULL;

#if SUPPORT_COROSYNC
extern gboolean crm_connect_corosync(crm_cluster_t * cluster);
#endif

void crm_shutdown(int nsig);
static gboolean crm_read_options(gpointer user_data);

/*	 A_HA_CONNECT	*/
void
do_ha_control(long long action,
              enum crmd_fsa_cause cause,
              enum crmd_fsa_state cur_state,
              enum crmd_fsa_input current_input, fsa_data_t * msg_data)
{
    gboolean registered = FALSE;
    static crm_cluster_t *cluster = NULL;

    if (cluster == NULL) {
        cluster = pcmk_cluster_new();
    }

    if (action & A_HA_DISCONNECT) {
        crm_cluster_disconnect(cluster);
        crm_info("Disconnected from the cluster");

        controld_set_fsa_input_flags(R_HA_DISCONNECTED);
    }

    if (action & A_HA_CONNECT) {
        crm_set_status_callback(&peer_update_callback);
        crm_set_autoreap(FALSE);

#if SUPPORT_COROSYNC
        if (is_corosync_cluster()) {
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

    if (send_cluster_message(NULL, crm_msg_crmd, msg, TRUE) == FALSE) {
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
    }
    free_xml(msg);
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
    crm_peer_destroy();

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
    int log_level = LOG_INFO;
    const char *exit_type = "gracefully";

    if (action & A_EXIT_1) {
        log_level = LOG_ERR;
        exit_type = "forcefully";
        exit_code = CRM_EX_ERROR;
    }

    verify_stopped(cur_state, LOG_ERR);
    do_crm_log(log_level, "Performing %s - %s exiting the controller",
               fsa_action2string(action), exit_type);

    crm_info("[%s] stopped (%d)", crm_system_name, exit_code);
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
        return -EIO;
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
        pcmk__ipc_send_ack(client, id, flags, "ack", NULL, CRM_EX_PROTOCOL);
        return 0;
    }
    pcmk__ipc_send_ack(client, id, flags, "ack", NULL, CRM_EX_INDETERMINATE);

    CRM_ASSERT(client->user != NULL);
    pcmk__update_acl_user(msg, F_CRM_USER, client->user);

    crm_xml_add(msg, F_CRM_SYS_FROM, client->id);
    if (controld_authorize_ipc_message(msg, client, NULL)) {
        crm_trace("Processing IPC message from client %s",
                  pcmk__client_name(client));
        route_message(C_IPC_MESSAGE, msg);
    }

    controld_trigger_fsa();
    free_xml(msg);
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
    controld_trigger_fencer_connect();

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

static pcmk__cluster_option_t controller_options[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * short description,
     * long description
     */
    {
        "dc-version", NULL, "string", NULL, PCMK__VALUE_NONE, NULL,
        N_("Pacemaker version on cluster node elected Designated Controller (DC)"),
        N_("Includes a hash which identifies the exact changeset the code was "
            "built from. Used for diagnostic purposes.")
    },
    {
        "cluster-infrastructure", NULL, "string", NULL, "corosync", NULL,
        N_("The messaging stack on which Pacemaker is currently running"),
        N_("Used for informational and diagnostic purposes.")
    },
    {
        "cluster-name", NULL, "string", NULL, NULL, NULL,
        N_("An arbitrary name for the cluster"),
        N_("This optional value is mostly for users' convenience as desired "
            "in administration, but may also be used in Pacemaker "
            "configuration rules via the #cluster-name node attribute, and "
            "by higher-level tools and resource agents.")
    },
    {
        XML_CONFIG_ATTR_DC_DEADTIME, NULL, "time",
        NULL, "20s", pcmk__valid_interval_spec,
        N_("How long to wait for a response from other nodes during start-up"),
        N_("The optimal value will depend on the speed and load of your network "
            "and the type of switches used.")
    },
    {
        XML_CONFIG_ATTR_RECHECK, NULL, "time",
        N_("Zero disables polling, while positive values are an interval in seconds"
            "(unless other units are specified, for example \"5min\")"),
        "15min", pcmk__valid_interval_spec,
        N_("Polling interval to recheck cluster state and evaluate rules "
            "with date specifications"),
        N_("Pacemaker is primarily event-driven, and looks ahead to know when to "
            "recheck cluster state for failure timeouts and most time-based "
            "rules. However, it will also recheck the cluster after this "
            "amount of inactivity, to evaluate rules with date specifications "
            "and serve as a fail-safe for certain types of scheduler bugs.")
    },
    {
        "load-threshold", NULL, "percentage", NULL,
        "80%", pcmk__valid_percentage,
        N_("Maximum amount of system load that should be used by cluster nodes"),
        N_("The cluster will slow down its recovery process when the amount of "
            "system resources used (currently CPU) approaches this limit"),
    },
    {
        "node-action-limit", NULL, "integer", NULL,
        "0", pcmk__valid_number,
        N_("Maximum number of jobs that can be scheduled per node "
            "(defaults to 2x cores)")
    },
    { XML_CONFIG_ATTR_FENCE_REACTION, NULL, "string", NULL, "stop", NULL,
        N_("How a cluster node should react if notified of its own fencing"),
        N_("A cluster node may receive notification of its own fencing if fencing "
        "is misconfigured, or if fabric fencing is in use that doesn't cut "
        "cluster communication. Allowed values are \"stop\" to attempt to "
        "immediately stop Pacemaker and stay stopped, or \"panic\" to attempt "
        "to immediately reboot the local node, falling back to stop on failure.")
    },
    {
        XML_CONFIG_ATTR_ELECTION_FAIL, NULL, "time", NULL,
        "2min", pcmk__valid_interval_spec,
        "*** Advanced Use Only ***",
        N_("Declare an election failed if it is not decided within this much "
            "time. If you need to adjust this value, it probably indicates "
            "the presence of a bug.")
    },
    {
        XML_CONFIG_ATTR_FORCE_QUIT, NULL, "time", NULL,
        "20min", pcmk__valid_interval_spec,
        "*** Advanced Use Only ***",
        N_("Exit immediately if shutdown does not complete within this much "
            "time. If you need to adjust this value, it probably indicates "
            "the presence of a bug.")
    },
    {
        "join-integration-timeout", "crmd-integration-timeout", "time", NULL,
        "3min", pcmk__valid_interval_spec,
        "*** Advanced Use Only ***",
        N_("If you need to adjust this value, it probably indicates "
            "the presence of a bug.")
    },
    {
        "join-finalization-timeout", "crmd-finalization-timeout", "time", NULL,
        "30min", pcmk__valid_interval_spec,
        "*** Advanced Use Only ***",
        N_("If you need to adjust this value, it probably indicates "
            "the presence of a bug.")
    },
    {
        "transition-delay", "crmd-transition-delay", "time", NULL,
        "0s", pcmk__valid_interval_spec,
        N_("*** Advanced Use Only *** Enabling this option will slow down "
            "cluster recovery under all conditions"),
        N_("Delay cluster recovery for this much time to allow for additional "
            "events to occur. Useful if your configuration is sensitive to "
            "the order in which ping updates arrive.")
    },
    {
        "stonith-watchdog-timeout", NULL, "time", NULL,
        "0", controld_verify_stonith_watchdog_timeout,
        N_("How long before nodes can be assumed to be safely down when "
           "watchdog-based self-fencing via SBD is in use"),
        N_("If this is set to a positive value, lost nodes are assumed to "
           "self-fence using watchdog-based SBD within this much time. This "
           "does not require a fencing resource to be explicitly configured, "
           "though a fence_watchdog resource can be configured, to limit use "
           "to specific nodes. If this is set to 0 (the default), the cluster "
           "will never assume watchdog-based self-fencing. If this is set to a "
           "negative value, the cluster will use twice the local value of the "
           "`SBD_WATCHDOG_TIMEOUT` environment variable if that is positive, "
           "or otherwise treat this as 0. WARNING: When used, this timeout "
           "must be larger than `SBD_WATCHDOG_TIMEOUT` on all nodes that use "
           "watchdog-based SBD, and Pacemaker will refuse to start on any of "
           "those nodes where this is not true for the local value or SBD is "
           "not active. When this is set to a negative value, "
           "`SBD_WATCHDOG_TIMEOUT` must be set to the same value on all nodes "
           "that use SBD, otherwise data corruption or loss could occur.")
    },
    {
        "stonith-max-attempts", NULL, "integer", NULL,
        "10", pcmk__valid_positive_number,
        N_("How many times fencing can fail before it will no longer be "
            "immediately re-attempted on a target")
    },

    // Already documented in libpe_status (other values must be kept identical)
    {
        "no-quorum-policy", NULL, "select",
        "stop, freeze, ignore, demote, suicide", "stop", pcmk__valid_quorum,
        "What to do when the cluster does not have quorum", NULL
    },
    {
        XML_CONFIG_ATTR_SHUTDOWN_LOCK, NULL, "boolean", NULL,
        "false", pcmk__valid_boolean,
        "Whether to lock resources to a cleanly shut down node",
        "When true, resources active on a node when it is cleanly shut down "
            "are kept \"locked\" to that node (not allowed to run elsewhere) "
            "until they start again on that node after it rejoins (or for at "
            "most shutdown-lock-limit, if set). Stonith resources and "
            "Pacemaker Remote connections are never locked. Clone and bundle "
            "instances and the promoted role of promotable clones are currently"
            " never locked, though support could be added in a future release."
    },
};

void
crmd_metadata(void)
{
    const char *desc_short = "Pacemaker controller options";
    const char *desc_long = "Cluster options used by Pacemaker's controller";

    gchar *s = pcmk__format_option_metadata("pacemaker-controld", desc_short,
                                            desc_long, controller_options,
                                            PCMK__NELEM(controller_options));
    printf("%s", s);
    g_free(s);
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
    if ((crmconfig) &&
        (crm_element_name(crmconfig)) &&
        (strcmp(crm_element_name(crmconfig), XML_CIB_TAG_CRMCONFIG) != 0)) {
        crmconfig = first_named_child(crmconfig, XML_CIB_TAG_CRMCONFIG);
    }
    if (!crmconfig) {
        fsa_data_t *msg_data = NULL;

        crm_err("Local CIB query for " XML_CIB_TAG_CRMCONFIG " section failed");
        register_fsa_error(C_FSA_INTERNAL, I_ERROR, NULL);
        goto bail;
    }

    crm_debug("Call %d : Parsing CIB options", call_id);
    config_hash = pcmk__strkey_table(free, free);
    pe_unpack_nvpairs(crmconfig, crmconfig, XML_CIB_TAG_PROPSET, NULL,
                      config_hash, CIB_OPTIONS_FIRST, FALSE, now, NULL);

    // Validate all options, and use defaults if not already present in hash
    pcmk__validate_cluster_options(config_hash, controller_options,
                                   PCMK__NELEM(controller_options));

    value = g_hash_table_lookup(config_hash, "no-quorum-policy");
    if (pcmk__str_eq(value, "suicide", pcmk__str_casei) && pcmk__locate_sbd()) {
        controld_set_global_flags(controld_no_quorum_suicide);
    }

    value = g_hash_table_lookup(config_hash, XML_CONFIG_ATTR_SHUTDOWN_LOCK);
    if (crm_is_true(value)) {
        controld_set_global_flags(controld_shutdown_lock_enabled);
    } else {
        controld_clear_global_flags(controld_shutdown_lock_enabled);
    }

    value = g_hash_table_lookup(config_hash, "cluster-name");
    pcmk__str_update(&(controld_globals.cluster_name), value);

    // Let subcomponents initialize their own static variables
    controld_configure_election(config_hash);
    controld_configure_fencing(config_hash);
    controld_configure_fsa_timers(config_hash);
    controld_configure_throttle(config_hash);

    alerts = first_named_child(output, XML_CIB_TAG_ALERTS);
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
                                        "//" XML_CIB_TAG_CRMCONFIG
                                        " | //" XML_CIB_TAG_ALERTS,
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

void
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
    value = pcmk__cluster_option(NULL, controller_options,
                                 PCMK__NELEM(controller_options),
                                 XML_CONFIG_ATTR_FORCE_QUIT);
    default_period_ms = crm_parse_interval_spec(value);
    controld_shutdown_start_countdown(default_period_ms);
}

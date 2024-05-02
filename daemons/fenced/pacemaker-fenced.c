/*
 * Copyright 2009-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>  // PRIu32, PRIx32

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/output_internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <crm/common/mainloop.h>

#include <crm/cib/internal.h>

#include <pacemaker-fenced.h>

#define SUMMARY "daemon for executing fencing devices in a Pacemaker cluster"

char *stonith_our_uname = NULL;
long long stonith_watchdog_timeout_ms = 0;
GList *stonith_watchdog_targets = NULL;

static GMainLoop *mainloop = NULL;

gboolean stand_alone = FALSE;
gboolean stonith_shutdown_flag = FALSE;

static qb_ipcs_service_t *ipcs = NULL;
static pcmk__output_t *out = NULL;

pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static struct {
    bool no_cib_connect;
    gchar **log_files;
} options;

crm_exit_t exit_code = CRM_EX_OK;

static void stonith_cleanup(void);

static int32_t
st_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    if (stonith_shutdown_flag) {
        crm_info("Ignoring new client [%d] during shutdown",
                 pcmk__client_pid(c));
        return -ECONNREFUSED;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -ENOMEM;
    }
    return 0;
}

/* Exit code means? */
static int32_t
st_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    int call_options = 0;
    xmlNode *request = NULL;
    pcmk__client_t *c = pcmk__find_client(qbc);
    const char *op = NULL;

    if (c == NULL) {
        crm_info("Invalid client: %p", qbc);
        return 0;
    }

    request = pcmk__client_data2xml(c, data, &id, &flags);
    if (request == NULL) {
        pcmk__ipc_send_ack(c, id, flags, PCMK__XE_NACK, NULL, CRM_EX_PROTOCOL);
        return 0;
    }


    op = crm_element_value(request, PCMK__XA_CRM_TASK);
    if(pcmk__str_eq(op, CRM_OP_RM_NODE_CACHE, pcmk__str_casei)) {
        crm_xml_add(request, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
        crm_xml_add(request, PCMK__XA_ST_OP, op);
        crm_xml_add(request, PCMK__XA_ST_CLIENTID, c->id);
        crm_xml_add(request, PCMK__XA_ST_CLIENTNAME, pcmk__client_name(c));
        crm_xml_add(request, PCMK__XA_ST_CLIENTNODE, stonith_our_uname);

        send_cluster_message(NULL, crm_msg_stonith_ng, request, FALSE);
        free_xml(request);
        return 0;
    }

    if (c->name == NULL) {
        const char *value = crm_element_value(request, PCMK__XA_ST_CLIENTNAME);

        c->name = crm_strdup_printf("%s.%u", pcmk__s(value, "unknown"), c->pid);
    }

    crm_element_value_int(request, PCMK__XA_ST_CALLOPT, &call_options);
    crm_trace("Flags %#08" PRIx32 "/%#08x for command %" PRIu32
              " from client %s", flags, call_options, id, pcmk__client_name(c));

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_ASSERT(flags & crm_ipc_client_response);
        CRM_LOG_ASSERT(c->request_id == 0);     /* This means the client has two synchronous events in-flight */
        c->request_id = id;     /* Reply only to the last one */
    }

    crm_xml_add(request, PCMK__XA_ST_CLIENTID, c->id);
    crm_xml_add(request, PCMK__XA_ST_CLIENTNAME, pcmk__client_name(c));
    crm_xml_add(request, PCMK__XA_ST_CLIENTNODE, stonith_our_uname);

    crm_log_xml_trace(request, "ipc-received");
    stonith_command(c, id, flags, request, NULL);

    free_xml(request);
    return 0;
}

/* Error code means? */
static int32_t
st_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }

    crm_trace("Connection %p closed", c);
    pcmk__free_client(client);

    /* 0 means: yes, go ahead and destroy the connection */
    return 0;
}

static void
st_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p destroyed", c);
    st_ipc_closed(c);
}

static void
stonith_peer_callback(xmlNode * msg, void *private_data)
{
    const char *remote_peer = crm_element_value(msg, PCMK__XA_SRC);
    const char *op = crm_element_value(msg, PCMK__XA_ST_OP);

    if (pcmk__str_eq(op, STONITH_OP_POKE, pcmk__str_none)) {
        return;
    }

    crm_log_xml_trace(msg, "Peer[inbound]");
    stonith_command(NULL, 0, 0, msg, remote_peer);
}

#if SUPPORT_COROSYNC
static void
stonith_peer_ais_callback(cpg_handle_t handle,
                          const struct cpg_name *groupName,
                          uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk__cpg_message_data(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }
    if (kind == crm_class_cluster) {
        xml = pcmk__xml_parse(data);
        if (xml == NULL) {
            crm_err("Invalid XML: '%.120s'", data);
            free(data);
            return;
        }
        crm_xml_add(xml, PCMK__XA_SRC, from);
        stonith_peer_callback(xml, NULL);
    }

    free_xml(xml);
    free(data);
    return;
}

static void
stonith_peer_cs_destroy(gpointer user_data)
{
    crm_crit("Lost connection to cluster layer, shutting down");
    stonith_shutdown(0);
}
#endif

void
do_local_reply(const xmlNode *notify_src, pcmk__client_t *client,
               int call_options)
{
    /* send callback to originating child */
    int local_rc = pcmk_rc_ok;
    int rid = 0;
    uint32_t ipc_flags = crm_ipc_server_event;

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_LOG_ASSERT(client->request_id);
        rid = client->request_id;
        client->request_id = 0;
        ipc_flags = crm_ipc_flags_none;
    }

    local_rc = pcmk__ipc_send_xml(client, rid, notify_src, ipc_flags);
    if (local_rc == pcmk_rc_ok) {
        crm_trace("Sent response %d to client %s",
                  rid, pcmk__client_name(client));
    } else {
        crm_warn("%synchronous reply to client %s failed: %s",
                 (pcmk_is_set(call_options, st_opt_sync_call)? "S" : "As"),
                 pcmk__client_name(client), pcmk_rc_str(local_rc));
    }
}

uint64_t
get_stonith_flag(const char *name)
{
    if (pcmk__str_eq(name, PCMK__VALUE_ST_NOTIFY_FENCE, pcmk__str_none)) {
        return st_callback_notify_fence;

    } else if (pcmk__str_eq(name, STONITH_OP_DEVICE_ADD, pcmk__str_casei)) {
        return st_callback_device_add;

    } else if (pcmk__str_eq(name, STONITH_OP_DEVICE_DEL, pcmk__str_casei)) {
        return st_callback_device_del;

    } else if (pcmk__str_eq(name, PCMK__VALUE_ST_NOTIFY_HISTORY,
                            pcmk__str_none)) {
        return st_callback_notify_history;

    } else if (pcmk__str_eq(name, PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED,
                            pcmk__str_none)) {
        return st_callback_notify_history_synced;

    }
    return st_callback_unknown;
}

static void
stonith_notify_client(gpointer key, gpointer value, gpointer user_data)
{

    const xmlNode *update_msg = user_data;
    pcmk__client_t *client = value;
    const char *type = NULL;

    CRM_CHECK(client != NULL, return);
    CRM_CHECK(update_msg != NULL, return);

    type = crm_element_value(update_msg, PCMK__XA_SUBT);
    CRM_CHECK(type != NULL, crm_log_xml_err(update_msg, "notify"); return);

    if (client->ipcs == NULL) {
        crm_trace("Skipping client with NULL channel");
        return;
    }

    if (pcmk_is_set(client->flags, get_stonith_flag(type))) {
        int rc = pcmk__ipc_send_xml(client, 0, update_msg,
                                    crm_ipc_server_event);

        if (rc != pcmk_rc_ok) {
            crm_warn("%s notification of client %s failed: %s "
                     CRM_XS " id=%.8s rc=%d", type, pcmk__client_name(client),
                     pcmk_rc_str(rc), client->id, rc);
        } else {
            crm_trace("Sent %s notification to client %s",
                      type, pcmk__client_name(client));
        }
    }
}

void
do_stonith_async_timeout_update(const char *client_id, const char *call_id, int timeout)
{
    pcmk__client_t *client = NULL;
    xmlNode *notify_data = NULL;

    if (!timeout || !call_id || !client_id) {
        return;
    }

    client = pcmk__find_client_by_id(client_id);
    if (!client) {
        return;
    }

    notify_data = pcmk__xe_create(NULL, PCMK__XE_ST_ASYNC_TIMEOUT_VALUE);
    crm_xml_add(notify_data, PCMK__XA_T, PCMK__VALUE_ST_ASYNC_TIMEOUT_VALUE);
    crm_xml_add(notify_data, PCMK__XA_ST_CALLID, call_id);
    crm_xml_add_int(notify_data, PCMK__XA_ST_TIMEOUT, timeout);

    crm_trace("timeout update is %d for client %s and call id %s", timeout, client_id, call_id);

    if (client) {
        pcmk__ipc_send_xml(client, 0, notify_data, crm_ipc_server_event);
    }

    free_xml(notify_data);
}

/*!
 * \internal
 * \brief Notify relevant IPC clients of a fencing operation result
 *
 * \param[in] type     Notification type
 * \param[in] result   Result of fencing operation (assume success if NULL)
 * \param[in] data     If not NULL, add to notification as call data
 */
void
fenced_send_notification(const char *type, const pcmk__action_result_t *result,
                         xmlNode *data)
{
    /* TODO: Standardize the contents of data */
    xmlNode *update_msg = pcmk__xe_create(NULL, PCMK__XE_NOTIFY);

    CRM_LOG_ASSERT(type != NULL);

    crm_xml_add(update_msg, PCMK__XA_T, PCMK__VALUE_ST_NOTIFY);
    crm_xml_add(update_msg, PCMK__XA_SUBT, type);
    crm_xml_add(update_msg, PCMK__XA_ST_OP, type);
    stonith__xe_set_result(update_msg, result);

    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(update_msg, PCMK__XE_ST_CALLDATA);

        pcmk__xml_copy(wrapper, data);
    }

    crm_trace("Notifying clients");
    pcmk__foreach_ipc_client(stonith_notify_client, update_msg);
    free_xml(update_msg);
    crm_trace("Notify complete");
}

/*!
 * \internal
 * \brief Send notifications for a configuration change to subscribed clients
 *
 * \param[in] op      Notification type (\c STONITH_OP_DEVICE_ADD,
 *                    \c STONITH_OP_DEVICE_DEL, \c STONITH_OP_LEVEL_ADD, or
 *                    \c STONITH_OP_LEVEL_DEL)
 * \param[in] result  Operation result
 * \param[in] desc    Description of what changed (either device ID or string
 *                    representation of level
 *                    (<tt><target>[<level_index>]</tt>))
 */
void
fenced_send_config_notification(const char *op,
                                const pcmk__action_result_t *result,
                                const char *desc)
{
    xmlNode *notify_data = pcmk__xe_create(NULL, op);

    crm_xml_add(notify_data, PCMK__XA_ST_DEVICE_ID, desc);

    fenced_send_notification(op, result, notify_data);
    free_xml(notify_data);
}

/*!
 * \internal
 * \brief Check whether a node does watchdog-fencing
 *
 * \param[in] node    Name of node to check
 *
 * \return TRUE if node found in stonith_watchdog_targets
 *         or stonith_watchdog_targets is empty indicating
 *         all nodes are doing watchdog-fencing
 */
gboolean
node_does_watchdog_fencing(const char *node)
{
    return ((stonith_watchdog_targets == NULL) ||
            pcmk__str_in_list(node, stonith_watchdog_targets, pcmk__str_casei));
}

void
stonith_shutdown(int nsig)
{
    crm_info("Terminating with %d clients", pcmk__ipc_client_count());
    stonith_shutdown_flag = TRUE;
    if (mainloop != NULL && g_main_loop_is_running(mainloop)) {
        g_main_loop_quit(mainloop);
    }
}

static void
stonith_cleanup(void)
{
    fenced_cib_cleanup();
    if (ipcs) {
        qb_ipcs_destroy(ipcs);
    }

    pcmk__cluster_destroy_node_caches();
    pcmk__client_cleanup();
    free_stonith_remote_op_list();
    free_topology_list();
    free_device_list();
    free_metadata_cache();
    fenced_unregister_handlers();

    free(stonith_our_uname);
    stonith_our_uname = NULL;
}

static gboolean
stand_alone_cpg_cb(const gchar *option_name, const gchar *optarg, gpointer data,
                   GError **error)
{
    stand_alone = FALSE;
    options.no_cib_connect = true;
    return TRUE;
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = st_ipc_accept,
    .connection_created = NULL,
    .msg_process = st_ipc_dispatch,
    .connection_closed = st_ipc_closed,
    .connection_destroyed = st_ipc_destroy
};

/*!
 * \internal
 * \brief Callback for peer status changes
 *
 * \param[in] type  What changed
 * \param[in] node  What peer had the change
 * \param[in] data  Previous value of what changed
 */
static void
st_peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    if ((type != crm_status_processes)
        && !pcmk_is_set(node->flags, crm_remote_node)) {
        /*
         * This is a hack until we can send to a nodeid and/or we fix node name lookups
         * These messages are ignored in stonith_peer_callback()
         */
        xmlNode *query = pcmk__xe_create(NULL, PCMK__XE_STONITH_COMMAND);

        crm_xml_add(query, PCMK__XA_T, PCMK__VALUE_STONITH_NG);
        crm_xml_add(query, PCMK__XA_ST_OP, STONITH_OP_POKE);

        crm_debug("Broadcasting our uname because of node %u", node->id);
        send_cluster_message(NULL, crm_msg_stonith_ng, query, FALSE);

        free_xml(query);
    }
}

/* @COMPAT Deprecated since 2.1.8. Use pcmk_list_fence_attrs() or
 * crm_resource --list-options=fencing instead of querying daemon metadata.
 */
static int
fencer_metadata(void)
{
    const char *name = "pacemaker-fenced";
    const char *desc_short = N_("Instance attributes available for all "
                                "\"stonith\"-class resources");
    const char *desc_long = N_("Instance attributes available for all "
                               "\"stonith\"-class resources and used by "
                               "Pacemaker's fence daemon, formerly known as "
                               "stonithd");

    return pcmk__daemon_metadata(out, name, desc_short, desc_long,
                                 pcmk__opt_fencing);
}

static GOptionEntry entries[] = {
    { "stand-alone", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &stand_alone,
      N_("Deprecated (will be removed in a future release)"), NULL },

    { "stand-alone-w-cpg", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      stand_alone_cpg_cb, N_("Intended for use in regression testing only"), NULL },

    { "logfile", 'l', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME_ARRAY,
      &options.log_files, N_("Send logs to the additional named logfile"), NULL },

    { NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    pcmk_cluster_t *cluster = NULL;
    crm_ipc_t *old_instance = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "l");
    GOptionContext *context = build_arg_context(args, &output_group);

    crm_log_preinit(NULL, argc, argv);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if ((g_strv_length(processed_args) >= 2)
        && pcmk__str_eq(processed_args[1], "metadata", pcmk__str_none)) {

        rc = fencer_metadata();
        if (rc != pcmk_rc_ok) {
            exit_code = CRM_EX_FATAL;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Unable to display metadata: %s", pcmk_rc_str(rc));
        }
        goto done;
    }

    // Open additional log files
    pcmk__add_logfiles(options.log_files, out);

    crm_log_init(NULL, LOG_INFO + args->verbosity, TRUE,
                 (args->verbosity > 0), argc, argv, FALSE);

    crm_notice("Starting Pacemaker fencer");

    old_instance = crm_ipc_new("stonith-ng", 0);
    if (old_instance == NULL) {
        /* crm_ipc_new() will have already logged an error message with
         * crm_err()
         */
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    if (pcmk__connect_generic_ipc(old_instance) == pcmk_rc_ok) {
        // IPC endpoint already up
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("pacemaker-fenced is already active, aborting startup");
        goto done;
    } else {
        // Not up or not authentic, we'll proceed either way
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    mainloop_add_signal(SIGTERM, stonith_shutdown);

    pcmk__cluster_init_node_caches();

    rc = fenced_scheduler_init();
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error initializing scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }

    cluster = pcmk_cluster_new();

    if (!stand_alone) {
#if SUPPORT_COROSYNC
        if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
            pcmk_cluster_set_destroy_fn(cluster, stonith_peer_cs_destroy);
            pcmk_cpg_set_deliver_fn(cluster, stonith_peer_ais_callback);
            pcmk_cpg_set_confchg_fn(cluster, pcmk__cpg_confchg_cb);
        }
#endif // SUPPORT_COROSYNC

        crm_set_status_callback(&st_peer_update_callback);

        if (pcmk_cluster_connect(cluster) != pcmk_rc_ok) {
            exit_code = CRM_EX_FATAL;
            crm_crit("Cannot sign in to the cluster... terminating");
            goto done;
        }
        pcmk__str_update(&stonith_our_uname, cluster->uname);

        if (!options.no_cib_connect) {
            setup_cib();
        }

    } else {
        pcmk__str_update(&stonith_our_uname, "localhost");
        crm_warn("Stand-alone mode is deprecated and will be removed "
                 "in a future release");
    }

    init_device_list();
    init_topology_list();

    pcmk__serve_fenced_ipc(&ipcs, &ipc_callbacks);

    // Create the mainloop and run it...
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker fencer successfully started and accepting connections");
    g_main_loop_run(mainloop);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_strfreev(options.log_files);

    stonith_cleanup();
    pcmk_cluster_free(cluster);
    fenced_scheduler_cleanup();

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

/*
 * Copyright 2009-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdbool.h>
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
#include <crm/common/ipc.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <crm/common/mainloop.h>

#include <crm/cib/internal.h>

#include <pacemaker-fenced.h>

#define SUMMARY "daemon for executing fencing devices in a Pacemaker cluster"

// @TODO This should be guint
long long fencing_watchdog_timeout_ms = 0;

GList *stonith_watchdog_targets = NULL;

static GMainLoop *mainloop = NULL;

gboolean stonith_shutdown_flag = FALSE;

static pcmk__output_t *out = NULL;

pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static struct {
    gboolean stand_alone;
    gchar **log_files;
} options;

crm_exit_t exit_code = CRM_EX_OK;

static void stonith_cleanup(void);

void
do_local_reply(const xmlNode *notify_src, pcmk__client_t *client,
               int call_options)
{
    /* send callback to originating child */
    int local_rc = pcmk_rc_ok;
    int rid = 0;
    uint32_t ipc_flags = crm_ipc_server_event;

    if (pcmk__is_set(call_options, st_opt_sync_call)) {
        CRM_LOG_ASSERT(client->request_id);
        rid = client->request_id;
        client->request_id = 0;
        ipc_flags = crm_ipc_flags_none;
    }

    local_rc = pcmk__ipc_send_xml(client, rid, notify_src, ipc_flags);
    if (local_rc == pcmk_rc_ok) {
        pcmk__trace("Sent response %d to client %s", rid,
                    pcmk__client_name(client));
    } else {
        pcmk__warn("%synchronous reply to client %s failed: %s",
                   (pcmk__is_set(call_options, st_opt_sync_call)? "S" : "As"),
                   pcmk__client_name(client), pcmk_rc_str(local_rc));
    }
}

/*!
 * \internal
 * \brief Parse a fencer client notification type string to a flag
 *
 * \param[in] type  Notification type string
 *
 * \return Flag corresponding to \p type, or \c fenced_nf_none if none exists
 */
enum fenced_notify_flags
fenced_parse_notify_flag(const char *type)
{
    if (pcmk__str_eq(type, PCMK__VALUE_ST_NOTIFY_FENCE, pcmk__str_none)) {
        return fenced_nf_fence_result;
    }
    if (pcmk__str_eq(type, STONITH_OP_DEVICE_ADD, pcmk__str_none)) {
        return fenced_nf_device_registered;
    }
    if (pcmk__str_eq(type, STONITH_OP_DEVICE_DEL, pcmk__str_none)) {
        return fenced_nf_device_removed;
    }
    if (pcmk__str_eq(type, PCMK__VALUE_ST_NOTIFY_HISTORY, pcmk__str_none)) {
        return fenced_nf_history_changed;
    }
    if (pcmk__str_eq(type, PCMK__VALUE_ST_NOTIFY_HISTORY_SYNCED,
                     pcmk__str_none)) {
        return fenced_nf_history_synced;
    }
    return fenced_nf_none;
}

static void
stonith_notify_client(gpointer key, gpointer value, gpointer user_data)
{

    const xmlNode *update_msg = user_data;
    pcmk__client_t *client = value;
    const char *type = NULL;

    CRM_CHECK(client != NULL, return);
    CRM_CHECK(update_msg != NULL, return);

    type = pcmk__xe_get(update_msg, PCMK__XA_SUBT);
    CRM_CHECK(type != NULL, pcmk__log_xml_err(update_msg, "notify"); return);

    if (client->ipcs == NULL) {
        pcmk__trace("Skipping client with NULL channel");
        return;
    }

    if (pcmk__is_set(client->flags, fenced_parse_notify_flag(type))) {
        int rc = pcmk__ipc_send_xml(client, 0, update_msg,
                                    crm_ipc_server_event);

        if (rc != pcmk_rc_ok) {
            pcmk__warn("%s notification of client %s failed: %s "
                       QB_XS " id=%.8s rc=%d",
                       type, pcmk__client_name(client), pcmk_rc_str(rc),
                       client->id, rc);
        } else {
            pcmk__trace("Sent %s notification to client %s", type,
                        pcmk__client_name(client));
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
    pcmk__xe_set(notify_data, PCMK__XA_T, PCMK__VALUE_ST_ASYNC_TIMEOUT_VALUE);
    pcmk__xe_set(notify_data, PCMK__XA_ST_CALLID, call_id);
    pcmk__xe_set_int(notify_data, PCMK__XA_ST_TIMEOUT, timeout);

    pcmk__trace("timeout update is %d for client %s and call id %s", timeout,
                client_id, call_id);

    if (client) {
        pcmk__ipc_send_xml(client, 0, notify_data, crm_ipc_server_event);
    }

    pcmk__xml_free(notify_data);
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

    pcmk__xe_set(update_msg, PCMK__XA_T, PCMK__VALUE_ST_NOTIFY);
    pcmk__xe_set(update_msg, PCMK__XA_SUBT, type);
    pcmk__xe_set(update_msg, PCMK__XA_ST_OP, type);
    stonith__xe_set_result(update_msg, result);

    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(update_msg, PCMK__XE_ST_CALLDATA);

        pcmk__xml_copy(wrapper, data);
    }

    pcmk__trace("Notifying clients");
    pcmk__foreach_ipc_client(stonith_notify_client, update_msg);
    pcmk__xml_free(update_msg);
    pcmk__trace("Notify complete");
}

/*!
 * \internal
 * \brief Send notifications for a configuration change to subscribed clients
 *
 * \param[in] op      Notification type (\c STONITH_OP_DEVICE_ADD or
 *                    \c STONITH_OP_DEVICE_DEL)
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

    pcmk__xe_set(notify_data, PCMK__XA_ST_DEVICE_ID, desc);

    fenced_send_notification(op, result, notify_data);
    pcmk__xml_free(notify_data);
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
    pcmk__info("Terminating with %d clients", pcmk__ipc_client_count());
    stonith_shutdown_flag = TRUE;
    if (mainloop != NULL && g_main_loop_is_running(mainloop)) {
        g_main_loop_quit(mainloop);
    }
}

static void
stonith_cleanup(void)
{
    fenced_cib_cleanup();
    fenced_ipc_cleanup();
    pcmk__cluster_destroy_node_caches();
    free_stonith_remote_op_list();
    free_topology_list();
    fenced_free_device_table();
    free_metadata_cache();
}

/* @COMPAT Deprecated since 2.1.8. Use pcmk_list_fence_attrs() or
 * crm_resource --list-options=fencing instead of querying daemon metadata.
 *
 * NOTE: pcs (as of at least 0.11.8) uses this
 */
static int
fencer_metadata(void)
{
    const char *name = PCMK__SERVER_FENCED;
    const char *desc_short = N_("Instance attributes available for all "
                                "\"stonith\"-class resources");
    const char *desc_long = N_("Instance attributes available for all "
                               "\"stonith\"-class resources and used by "
                               "Pacemaker's fence daemon");

    return pcmk__daemon_metadata(out, name, desc_short, desc_long,
                                 pcmk__opt_fencing);
}

static GOptionEntry entries[] = {
    { "stand-alone", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.stand_alone, N_("Intended for use in regression testing only"),
      NULL },

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

static bool
ipc_already_running(void)
{
    crm_ipc_t *old_instance = NULL;
    int rc = pcmk_rc_ok;

    old_instance = crm_ipc_new("stonith-ng", 0);
    if (old_instance == NULL) {
        /* This is an error - memory allocation failed, etc. - but crm_ipc_new
         * will have already logged an error message.
         */
        return false;
    }

    rc = pcmk__connect_generic_ipc(old_instance);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("No existing stonith-ng instance found: %s",
                    pcmk_rc_str(rc));
        crm_ipc_destroy(old_instance);
        return false;
    }

    crm_ipc_close(old_instance);
    crm_ipc_destroy(old_instance);
    return true;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;

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

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
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

    pcmk__notice("Starting Pacemaker fencer");

    if (ipc_already_running()) {
        exit_code = CRM_EX_OK;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Aborting start-up because a fencer instance is already active");
        pcmk__crit("%s", error->message);
        goto done;
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

    if (fenced_cluster_connect() != pcmk_rc_ok) {
        exit_code = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to the cluster");
        goto done;
    }

    pcmk__info("Cluster connection active");

    fenced_set_local_node(fenced_cluster->priv->node_name);

    if (!options.stand_alone) {
        setup_cib();
    }

    fenced_init_device_table();
    init_topology_list();
    fenced_ipc_init();

    // Create the mainloop and run it...
    mainloop = g_main_loop_new(NULL, FALSE);
    pcmk__notice("Pacemaker fencer successfully started and accepting "
                 "connections");
    g_main_loop_run(mainloop);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_strfreev(options.log_files);

    stonith_cleanup();
    fenced_cluster_disconnect();
    fenced_unregister_handlers();
    fenced_scheduler_cleanup();

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <bzlib.h>
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib/internal.h>
#include <crm/cluster/internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/mainloop.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml.h>

#include <pacemaker-based.h>

#define SUMMARY "daemon for managing the configuration of a Pacemaker cluster"

extern int init_remote_listener(int port, gboolean encrypted);
gboolean cib_shutdown_flag = FALSE;
int cib_status = pcmk_ok;

pcmk_cluster_t *crm_cluster = NULL;

GMainLoop *mainloop = NULL;
gchar *cib_root = NULL;
static gboolean preserve_status = FALSE;

gboolean cib_writes_enabled = TRUE;
gboolean stand_alone = FALSE;

int remote_fd = 0;
int remote_tls_fd = 0;

GHashTable *config_hash = NULL;

static void cib_init(void);
void cib_shutdown(int nsig);
static bool startCib(const char *filename);
extern int write_cib_contents(gpointer p);

static crm_exit_t exit_code = CRM_EX_OK;

static void
cib_enable_writes(int nsig)
{
    crm_info("(Re)enabling disk writes");
    cib_writes_enabled = TRUE;
}

/*!
 * \internal
 * \brief Set up options, users, and groups for stand-alone mode
 *
 * \param[out] error  GLib error object
 *
 * \return Standard Pacemaker return code
 */
static int
setup_stand_alone(GError **error)
{
    int rc = 0;
    struct passwd *pwentry = NULL;

    preserve_status = TRUE;
    cib_writes_enabled = FALSE;

    errno = 0;
    pwentry = getpwnam(CRM_DAEMON_USER);
    if (pwentry == NULL) {
        exit_code = CRM_EX_FATAL;
        if (errno != 0) {
            g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                        "Error getting password DB entry for %s: %s",
                        CRM_DAEMON_USER, strerror(errno));
            return errno;
        }
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Password DB entry for '%s' not found", CRM_DAEMON_USER);
        return ENXIO;
    }

    rc = setgid(pwentry->pw_gid);
    if (rc < 0) {
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not set group to %d: %s",
                    pwentry->pw_gid, strerror(errno));
        return errno;
    }

    rc = initgroups(CRM_DAEMON_USER, pwentry->pw_gid);
    if (rc < 0) {
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not setup groups for user %d: %s",
                    pwentry->pw_uid, strerror(errno));
        return errno;
    }

    rc = setuid(pwentry->pw_uid);
    if (rc < 0) {
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not set user to %d: %s",
                    pwentry->pw_uid, strerror(errno));
        return errno;
    }
    return pcmk_rc_ok;
}

/* @COMPAT Deprecated since 2.1.8. Use pcmk_list_cluster_options() or
 * crm_attribute --list-options=cluster instead of querying daemon metadata.
 *
 * NOTE: pcs (as of at least 0.11.8) uses this
 */
static int
based_metadata(pcmk__output_t *out)
{
    return pcmk__daemon_metadata(out, PCMK__SERVER_BASED,
                                 "Cluster Information Base manager options",
                                 "Cluster options used by Pacemaker's Cluster "
                                 "Information Base manager",
                                 pcmk__opt_based);
}

static GOptionEntry entries[] = {
    { "stand-alone", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &stand_alone,
      "(Advanced use only) Run in stand-alone mode", NULL },

    { "disk-writes", 'w', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &cib_writes_enabled,
      "(Advanced use only) Enable disk writes (enabled by default unless in "
      "stand-alone mode)", NULL },

    { "cib-root", 'r', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME, &cib_root,
      "(Advanced use only) Directory where the CIB XML file should be located "
      "(default: " CRM_CONFIG_DIR ")", NULL },

    { NULL }
};

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
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
    crm_ipc_t *old_instance = NULL;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "r");
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

    mainloop_add_signal(SIGTERM, cib_shutdown);
    mainloop_add_signal(SIGPIPE, cib_enable_writes);

    cib_writer = mainloop_add_trigger(G_PRIORITY_LOW, write_cib_contents, NULL);

    if ((g_strv_length(processed_args) >= 2)
        && pcmk__str_eq(processed_args[1], "metadata", pcmk__str_none)) {

        rc = based_metadata(out);
        if (rc != pcmk_rc_ok) {
            exit_code = CRM_EX_FATAL;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Unable to display metadata: %s", pcmk_rc_str(rc));
        }
        goto done;
    }

    pcmk__cli_init_logging(PCMK__SERVER_BASED, args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_notice("Starting Pacemaker CIB manager");

    old_instance = crm_ipc_new(PCMK__SERVER_BASED_RO, 0);
    if (old_instance == NULL) {
        /* crm_ipc_new() will have already logged an error message with
         * crm_err()
         */
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    if (pcmk__connect_generic_ipc(old_instance) == pcmk_rc_ok) {
        /* IPC end-point already up */
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_crit("Aborting start-up because another CIB manager instance is "
                 "already active");
        goto done;
    } else {
        /* not up or not authentic, we'll proceed either way */
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    if (stand_alone) {
        rc = setup_stand_alone(&error);
        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

    if (cib_root == NULL) {
        cib_root = g_strdup(CRM_CONFIG_DIR);
    } else {
        crm_notice("Using custom config location: %s", cib_root);
    }

    if (!pcmk__daemon_can_write(cib_root, NULL)) {
        exit_code = CRM_EX_FATAL;
        crm_err("Terminating due to bad permissions on %s", cib_root);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bad permissions on %s (see logs for details)", cib_root);
        goto done;
    }

    pcmk__cluster_init_node_caches();

    // Read initial CIB, connect to cluster, and start IPC servers
    cib_init();

    // Run the main loop
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker CIB manager successfully started and accepting connections");
    g_main_loop_run(mainloop);

    /* If main loop returned, clean up and exit. We disconnect in case
     * terminate_cib(-1) was called.
     */
    pcmk_cluster_disconnect(crm_cluster);
    pcmk__stop_based_ipc(ipcs_ro, ipcs_rw, ipcs_shm);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__cluster_destroy_node_caches();

    if (config_hash != NULL) {
        g_hash_table_destroy(config_hash);
    }
    pcmk__client_cleanup();
    pcmk_cluster_free(crm_cluster);
    g_free(cib_root);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(exit_code);
}

#if SUPPORT_COROSYNC
static void
cib_cs_dispatch(cpg_handle_t handle,
                 const struct cpg_name *groupName,
                 uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk__cpg_message_data(handle, nodeid, pid, msg, &from);

    if(data == NULL) {
        return;
    }

    xml = pcmk__xml_parse(data);
    if (xml == NULL) {
        crm_err("Invalid XML: '%.120s'", data);
        free(data);
        return;
    }
    crm_xml_add(xml, PCMK__XA_SRC, from);
    cib_peer_callback(xml, NULL);

    pcmk__xml_free(xml);
    free(data);
}

static void
cib_cs_destroy(gpointer user_data)
{
    if (cib_shutdown_flag) {
        crm_info("Corosync disconnection complete");
    } else {
        crm_crit("Exiting immediately after losing connection "
                 "to cluster layer");
        terminate_cib(CRM_EX_DISCONNECT);
    }
}
#endif

static void
cib_peer_update_callback(enum pcmk__node_update type,
                         pcmk__node_status_t *node, const void *data)
{
    switch (type) {
        case pcmk__node_update_name:
        case pcmk__node_update_state:
            if (cib_shutdown_flag && (pcmk__cluster_num_active_nodes() < 2)
                && (pcmk__ipc_client_count() == 0)) {

                crm_info("Exiting after no more peers or clients remain");
                terminate_cib(-1);
            }
            break;

        default:
            break;
    }
}

static void
cib_init(void)
{
    crm_cluster = pcmk_cluster_new();

#if SUPPORT_COROSYNC
    if (pcmk_get_cluster_layer() == pcmk_cluster_layer_corosync) {
        pcmk_cluster_set_destroy_fn(crm_cluster, cib_cs_destroy);
        pcmk_cpg_set_deliver_fn(crm_cluster, cib_cs_dispatch);
        pcmk_cpg_set_confchg_fn(crm_cluster, pcmk__cpg_confchg_cb);
    }
#endif // SUPPORT_COROSYNC

    config_hash = pcmk__strkey_table(free, free);

    if (startCib("cib.xml") == FALSE) {
        crm_crit("Cannot start CIB... terminating");
        crm_exit(CRM_EX_NOINPUT);
    }

    if (!stand_alone) {
        pcmk__cluster_set_status_callback(&cib_peer_update_callback);

        if (pcmk_cluster_connect(crm_cluster) != pcmk_rc_ok) {
            crm_crit("Cannot sign in to the cluster... terminating");
            crm_exit(CRM_EX_FATAL);
        }
    }

    pcmk__serve_based_ipc(&ipcs_ro, &ipcs_rw, &ipcs_shm, &ipc_ro_callbacks,
                          &ipc_rw_callbacks);

    if (stand_alone) {
        based_is_primary = true;
    }
}

static bool
startCib(const char *filename)
{
    gboolean active = FALSE;
    xmlNode *cib = readCibXmlFile(cib_root, filename, !preserve_status);

    if (activateCibXml(cib, TRUE, "start") == 0) {
        int port = 0;

        active = TRUE;

        cib_read_config(config_hash, cib);

        pcmk__scan_port(crm_element_value(cib, PCMK_XA_REMOTE_TLS_PORT), &port);
        if (port >= 0) {
            remote_tls_fd = init_remote_listener(port, TRUE);
        }

        pcmk__scan_port(crm_element_value(cib, PCMK_XA_REMOTE_CLEAR_PORT),
                        &port);
        if (port >= 0) {
            remote_fd = init_remote_listener(port, FALSE);
        }
    }
    return active;
}

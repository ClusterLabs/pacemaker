/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>                  // errno
#include <grp.h>                    // initgroups
#include <signal.h>                 // SIGTERM
#include <stdbool.h>
#include <stddef.h>                 // NULL, size_t
#include <syslog.h>                 // LOG_INFO
#include <sys/types.h>              // gid_t, uid_t
#include <unistd.h>                 // setgid, setuid

#include <glib.h>                   // g_*, G_*, etc.
#include <libxml/tree.h>            // xmlNode

#include <crm_config.h>             // CRM_CONFIG_DIR, CRM_DAEMON_USER
#include <crm/cluster/internal.h>   // pcmk__node_update, etc.
#include <crm/common/internal.h>    // PCMK__EXITC_ERROR, pcmk__err, etc.
#include <crm/common/ipc.h>         // crm_ipc_*
#include <crm/common/logging.h>     // crm_log_*
#include <crm/common/mainloop.h>    // mainloop_add_signal
#include <crm/common/results.h>     // CRM_EX_*, crm_exit_t, pcmk_rc_*

#include "pacemaker-based.h"

#define SUMMARY "daemon for managing the configuration of a Pacemaker cluster"

/*
 * \internal
 * \brief The CIB manager's global, in-memory copy of the current CIB
 *
 * This should reflect our most current, authoritative view of the cluster
 * state. It may point to a tentative, "working" CIB copy while committing a
 * transaction, but transactions are atomic. Either the transaction succeeds and
 * we replace \c based_cib with the resulting CIB, or the transaction fails and
 * we restore a saved version of the pre-transaction CIB.
 *
 * We write this in-memory CIB to disk during CIB manager startup and after a
 * successful CIB operation that modifies the \c PCMK_XE_CONFIGURATION section.
 */
xmlNode *based_cib = NULL;

int cib_status = pcmk_rc_ok;
gchar *cib_root = NULL;

static bool local_node_dc = false;
static bool shutting_down = false;
static gboolean stand_alone = FALSE;
static crm_exit_t exit_code = CRM_EX_OK;
static GMainLoop *mainloop = NULL;

/*!
 * \internal
 * \brief Check whether local node is DC
 *
 * \return \c true if local node is DC, or \c false otherwise
 */
bool
based_get_local_node_dc(void)
{
    return local_node_dc;
}

/*!
 * \internal
 * \brief Record whether local node is DC
 *
 * \param[in] value  \c true if local node is DC, or \c false otherwise
 */
void
based_set_local_node_dc(bool value)
{
    local_node_dc = value;
}

/*!
 * \internal
 * \brief Check whether local CIB manager is shutting down
 *
 * \return \c true if local CIB manager has begun shutting down, or \c false
 *         otherwise
 */
bool
based_shutting_down(void)
{
    return shutting_down;
}

/*!
 * \internal
 * \brief Check whether local CIB manager is running in stand-alone mode
 *
 * \return \c true if local CIB manager is in stand-alone mode, or \c false
 *         otherwise
 */
bool
based_stand_alone(void)
{
    return stand_alone;
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
    uid_t uid = 0;
    gid_t gid = 0;
    int rc = pcmk_rc_ok;

    based_set_local_node_dc(true);

    rc = pcmk__daemon_user(&uid, &gid);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not find user " CRM_DAEMON_USER ": %s",
                    pcmk_rc_str(rc));
        return rc;
    }

    rc = setgid(gid);
    if (rc < 0) {
        rc = errno;
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not set group to %lld: %s", (long long) gid,
                    pcmk_rc_str(rc));
        return rc;
    }

    rc = initgroups(CRM_DAEMON_USER, gid);
    if (rc < 0) {
        rc = errno;
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not set up groups for user %lld: %s",
                    (long long) uid, pcmk_rc_str(rc));
        return rc;
    }

    rc = setuid(uid);
    if (rc < 0) {
        rc = errno;
        exit_code = CRM_EX_FATAL;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not set user to %lld: %s", (long long) uid,
                    pcmk_rc_str(rc));
        return rc;
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

static gboolean
disk_writes_cb(const gchar *option_name, const gchar *optarg, gpointer data,
               GError **error)
{
    based_enable_writes(0);
    return TRUE;
}

static GOptionEntry entries[] = {
    { "stand-alone", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &stand_alone,
      "(Advanced use only) Run in stand-alone mode", NULL },

    { "disk-writes", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      disk_writes_cb,
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

/*!
 * \internal
 * \brief Clean up CIB manager data structures
 */
static void
based_cleanup(void)
{
    based_callbacks_cleanup();
    based_cluster_disconnect();
    based_io_cleanup();
    based_ipc_cleanup();
    based_remote_cleanup();

    g_clear_pointer(&based_cib, pcmk__xml_free);
    g_clear_pointer(&cib_root, g_free);
}

/*!
 * \internal
 * \brief Set an exit code and quit the main loop
 *
 * \param[in] ec  Exit code
 */
void
based_quit_main_loop(crm_exit_t ec)
{
    if (shutting_down) {
        return;
    }

    shutting_down = true;
    exit_code = ec;

    // There should be no way to get here without the main loop running
    CRM_CHECK((mainloop != NULL) && g_main_loop_is_running(mainloop),
              crm_exit(exit_code));

    g_main_loop_quit(mainloop);
}

/*!
 * \internal
 * \brief Quit the main loop and set the exit code to \c CRM_EX_OK
 *
 * \param[in] nsig  Ignored
 *
 * \note This is a main loop signal handler function.
 */
static void
based_shutdown(int nsig)
{
    based_quit_main_loop(CRM_EX_OK);
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
        out->version(out);
        goto done;
    }

    mainloop_add_signal(SIGTERM, based_shutdown);

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
    pcmk__notice("Starting Pacemaker CIB manager");

    old_instance = crm_ipc_new(PCMK__SERVER_BASED_RW, 0);
    if (old_instance == NULL) {
        /* crm_ipc_new() will have already logged an error message with
         * pcmk__err()
         */
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    if (pcmk__connect_generic_ipc(old_instance) == pcmk_rc_ok) {
        /* IPC end-point already up */
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        pcmk__crit("Aborting start-up because another CIB manager instance is "
                   "already active");
        goto done;
    } else {
        /* not up or not authentic, we'll proceed either way */
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    if (based_stand_alone()) {
        rc = setup_stand_alone(&error);
        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

    if (cib_root == NULL) {
        cib_root = g_strdup(CRM_CONFIG_DIR);
    } else {
        pcmk__notice("Using custom config location: %s", cib_root);
    }

    if (!pcmk__daemon_can_write(cib_root, NULL)) {
        exit_code = CRM_EX_FATAL;
        pcmk__err("Terminating due to bad permissions on %s", cib_root);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bad permissions on %s (see logs for details)", cib_root);
        goto done;
    }

    based_io_init();

    /* Read initial CIB. based_read_cib() returns new, non-NULL XML, so this
     * should always succeed.
     */
    if (based_activate_cib(based_read_cib(), true, "start") != pcmk_rc_ok) {
        exit_code = CRM_EX_SOFTWARE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bug: failed to activate CIB. Terminating %s.",
                    pcmk__server_log_name(pcmk_ipc_based));
        goto done;
    }

    based_ipc_init();
    based_remote_init();

    if (!based_stand_alone()) {
        if (based_cluster_connect() != pcmk_rc_ok) {
            exit_code = CRM_EX_FATAL;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not connect to the cluster");
            goto done;
        }

        pcmk__info("Cluster connection active");
    }

    // Run the main loop
    mainloop = g_main_loop_new(NULL, FALSE);
    pcmk__notice("Pacemaker CIB manager successfully started and accepting "
                 "connections");
    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    based_cleanup();

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(exit_code);
}

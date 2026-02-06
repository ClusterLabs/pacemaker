/*
 * Copyright 2013-2026 the Pacemaker project contributors
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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/common/iso8601.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/cluster/internal.h>

#include "pacemaker-attrd.h"

#define SUMMARY "daemon for managing Pacemaker node attributes"

gboolean stand_alone = FALSE;
gchar **log_files = NULL;

static GOptionEntry entries[] = {
    { "stand-alone", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &stand_alone,
      "(Advanced use only) Run in stand-alone mode", NULL },

    { "logfile", 'l', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME_ARRAY,
      &log_files, "Send logs to the additional named logfile", NULL },

    { NULL }
};

static pcmk__output_t *out = NULL;

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

lrmd_t *the_lrmd = NULL;
crm_trigger_t *attrd_config_read = NULL;
crm_exit_t attrd_exit_status = CRM_EX_OK;

static bool
ipc_already_running(void)
{
    pcmk_ipc_api_t *old_instance = NULL;
    int rc = pcmk_rc_ok;

    rc = pcmk_new_ipc_api(&old_instance, pcmk_ipc_attrd);
    if (rc != pcmk_rc_ok) {
        return false;
    }

    rc = pcmk__connect_ipc(old_instance, pcmk_ipc_dispatch_sync, 2);
    if (rc != pcmk_rc_ok) {
        pcmk__debug("No existing %s instance found: %s",
                    pcmk_ipc_name(old_instance, true), pcmk_rc_str(rc));
        pcmk_free_ipc_api(old_instance);
        return false;
    }

    pcmk_disconnect_ipc(old_instance);
    pcmk_free_ipc_api(old_instance);
    return true;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;

    GError *error = NULL;
    bool initialized = false;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    attrd_init_mainloop();
    crm_log_preinit(NULL, argc, argv);
    mainloop_add_signal(SIGTERM, attrd_shutdown);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        attrd_exit_status = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        attrd_exit_status = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, attrd_exit_status,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    // Open additional log files
    pcmk__add_logfiles(log_files, out);

    crm_log_init(PCMK__VALUE_ATTRD, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    pcmk__notice("Starting Pacemaker node attribute manager%s",
                 (stand_alone ? " in standalone mode" : ""));

    if (ipc_already_running()) {
        attrd_exit_status = CRM_EX_OK;
        g_set_error(&error, PCMK__EXITC_ERROR, attrd_exit_status,
                    "Aborting start-up because an attribute manager "
                    "instance is already active");
        pcmk__crit("%s", error->message);
        goto done;
    }

    initialized = true;

    attributes = pcmk__strkey_table(NULL, attrd_free_attribute);

    /* Connect to the CIB before connecting to the cluster or listening for IPC.
     * This allows us to assume the CIB is connected whenever we process a
     * cluster or IPC message (which also avoids start-up race conditions).
     */
    if (!stand_alone) {
        if (attrd_cib_connect(30) != pcmk_ok) {
            attrd_exit_status = CRM_EX_FATAL;
            g_set_error(&error, PCMK__EXITC_ERROR, attrd_exit_status,
                        "Could not connect to the CIB");
            goto done;
        }
        pcmk__info("CIB connection active");
    }

    if (attrd_cluster_connect() != pcmk_rc_ok) {
        attrd_exit_status = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, attrd_exit_status,
                    "Could not connect to the cluster");
        goto done;
    }

    pcmk__info("Cluster connection active");

    // Initialization that requires the cluster to be connected
    attrd_election_init();

    if (!stand_alone) {
        attrd_cib_init();
    }

    /* Set a private attribute for ourselves with the protocol version we
     * support. This lets all nodes determine the minimum supported version
     * across all nodes. It also ensures that the writer learns our node name,
     * so it can send our attributes to the CIB.
     */
    attrd_send_protocol(NULL);

    attrd_ipc_init();
    pcmk__notice("Pacemaker node attribute manager successfully started and "
                 "accepting connections");
    attrd_run_mainloop();

  done:
    if (initialized) {
        pcmk__info("Shutting down attribute manager");

        attrd_ipc_cleanup();
        attrd_lrmd_disconnect();

        if (!stand_alone) {
            attrd_cib_disconnect();
        }

        attrd_free_removed_peers();
        attrd_free_waitlist();
        attrd_cluster_disconnect();
        attrd_unregister_handlers();
        g_hash_table_destroy(attributes);
    }

    attrd_cleanup_xml_ids();

    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_strfreev(log_files);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, attrd_exit_status, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();
    crm_exit(attrd_exit_status);
}

/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <signal.h>                     // SIGTERM
#include <stdbool.h>                    // true
#include <stddef.h>                     // NULL
#include <syslog.h>                     // LOG_INFO

#include <glib.h>                       // g_*, etc.
#include <qb/qblog.h>                   // LOG_TRACE

#include <crm_config.h>                 // PCMK_SCHEDULER_INPUT_DIR
#include <crm/common/logging.h>         // crm_log_init, crm_log_preinit
#include <crm/common/mainloop.h>        // mainloop_add_signal
#include <crm/common/results.h>         // crm_exit_t, CRM_EX_*, pcmk_rc_*
#include <crm/pengine/internal.h>       // pe__register_messages
#include <pacemaker-internal.h>         // pcmk__register_lib_messages

#include "pacemaker-schedulerd.h"

#define SUMMARY PCMK__SERVER_SCHEDULERD " - daemon for calculating a " \
                "Pacemaker cluster's response to events"

static pcmk__daemon_t schedulerd = {
    .type = pcmk_ipc_schedulerd,
    .ec = CRM_EX_OK,
};

pcmk__output_t *logger_out = NULL;

static pcmk__output_t *out = NULL;
static gchar **processed_args = NULL;
static GOptionContext *context = NULL;
static gchar **remainder = NULL;

pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

/* @COMPAT Deprecated since 2.1.8. Use pcmk_list_cluster_options() or
 * crm_attribute --list-options=cluster instead of querying daemon metadata.
 *
 * NOTE: pcs (as of at least 0.11.8) uses this
 */
static int
scheduler_metadata(pcmk__output_t *out)
{
    return pcmk__daemon_metadata(out, PCMK__SERVER_SCHEDULERD,
                                 "Pacemaker scheduler options",
                                 "Cluster options used by Pacemaker's "
                                 "scheduler",
                                 pcmk__opt_schedulerd);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { G_OPTION_REMAINING, 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING_ARRAY, &remainder,
          NULL,
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, extra_prog_entries);
    return context;
}

static void
schedulerd_cleanup_cmdline(void)
{
    g_clear_pointer(&processed_args, g_strfreev);
    g_clear_pointer(&context, g_option_context_free);
    g_clear_pointer(&remainder, g_strfreev);
}

static void
schedulerd_cleanup(void)
{
    schedulerd_ipc_cleanup();
    schedulerd_unregister_handlers();
}

static void
schedulerd_shutdown(int nsig)
{
    pcmk__daemon_quit(&schedulerd, CRM_EX_OK);
}

int
main(int argc, char **argv)
{
    GError *error = NULL;
    int rc = pcmk_rc_ok;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = NULL;

    atexit(schedulerd_cleanup_cmdline);

    args = pcmk__new_common_args(SUMMARY);
    processed_args = pcmk__cmdline_preproc(argv, NULL);
    context = build_arg_context(args, &output_group);

    crm_log_preinit(NULL, argc, argv);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        schedulerd.ec = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        schedulerd.ec = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, schedulerd.ec,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    if (remainder != NULL) {
        if (g_strv_length(remainder) == 1 &&
            pcmk__str_eq("metadata", remainder[0], pcmk__str_casei)) {

            rc = scheduler_metadata(out);
            if (rc != pcmk_rc_ok) {
                schedulerd.ec = CRM_EX_FATAL;
                g_set_error(&error, PCMK__EXITC_ERROR, schedulerd.ec,
                            "Unable to display metadata: %s", pcmk_rc_str(rc));
            }

        } else {
            schedulerd.ec = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, schedulerd.ec,
                        "Unsupported extra command line parameters");
        }
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    pcmk__cli_init_logging(PCMK__SERVER_SCHEDULERD, args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    pcmk__notice("Starting Pacemaker scheduler");

    if (pcmk__daemon_can_write(PCMK_SCHEDULER_INPUT_DIR, NULL) == FALSE) {
        pcmk__err("Terminating due to bad permissions on "
                  PCMK_SCHEDULER_INPUT_DIR);
        schedulerd.ec = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, schedulerd.ec,
                    "ERROR: Bad permissions on %s (see logs for details)",
                    PCMK_SCHEDULER_INPUT_DIR);
        goto done;
    }

    schedulerd_ipc_init();

    if (pcmk__log_output_new(&logger_out) != pcmk_rc_ok) {
        schedulerd.ec = CRM_EX_FATAL;
        goto done;
    }
    pe__register_messages(logger_out);
    pcmk__register_lib_messages(logger_out);
    pcmk__output_set_log_level(logger_out, LOG_TRACE);

    rc = pcmk__daemon_init(&schedulerd);
    if (rc != pcmk_rc_ok) {
        schedulerd.ec = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, schedulerd.ec,
                    "Error initializing daemon object: %s",
                    pcmk_rc_str(rc));
        goto done;
    }

    mainloop_add_signal(SIGTERM, schedulerd_shutdown);

    pcmk__daemon_run(&schedulerd);

done:
    schedulerd_cleanup();

    pcmk__output_and_clear_error(&error, out);

    if (logger_out != NULL) {
        logger_out->finish(logger_out, schedulerd.ec, true, NULL);
        g_clear_pointer(&logger_out, pcmk__output_free);
    }

    if (out != NULL) {
        out->finish(out, schedulerd.ec, true, NULL);
        g_clear_pointer(&out, pcmk__output_free);
    }

    pcmk__unregister_formats();
    crm_exit(schedulerd.ec);
}

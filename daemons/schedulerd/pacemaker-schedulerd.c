/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <stdio.h>
#include <stdbool.h>

#include <stdlib.h>
#include <errno.h>

#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/mainloop.h>
#include <crm/pengine/internal.h>
#include <pacemaker-internal.h>

#include "pacemaker-schedulerd.h"

#define SUMMARY "pacemaker-schedulerd - daemon for calculating a Pacemaker cluster's response to events"

struct {
    gchar **remainder;
} options;

pe_working_set_t *sched_data_set = NULL;
pcmk__output_t *logger_out = NULL;
pcmk__output_t *out = NULL;

static GMainLoop *mainloop = NULL;
static qb_ipcs_service_t *ipcs = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

void pengine_shutdown(int nsig);

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { G_OPTION_REMAINING, 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING_ARRAY, &options.remainder,
          NULL,
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    pcmk__add_main_args(context, extra_prog_entries);
    return context;
}

int
main(int argc, char **argv)
{
    GError *error = NULL;
    int rc = pcmk_rc_ok;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args, &output_group);

    crm_log_preinit(NULL, argc, argv);
    mainloop_add_signal(SIGTERM, pengine_shutdown);

    pcmk__register_formats(NULL, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if ((rc != pcmk_rc_ok) || (out == NULL)) {
        exit_code = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pe__register_messages(out);
    pcmk__register_lib_messages(out);

    if (options.remainder) {
        if (g_strv_length(options.remainder) == 1 &&
            pcmk__str_eq("metadata", options.remainder[0], pcmk__str_casei)) {
            pe_metadata(out);
            goto done;
        } else {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Unsupported extra command line parameters");
            goto done;
        }
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    pcmk__cli_init_logging("pacemaker-schedulerd", args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_notice("Starting Pacemaker scheduler");

    if (pcmk__daemon_can_write(PE_STATE_DIR, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on " PE_STATE_DIR);
        exit_code = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "ERROR: Bad permissions on %s (see logs for details)", PE_STATE_DIR);
        goto done;
    }

    ipcs = pcmk__serve_schedulerd_ipc(&ipc_callbacks);
    if (ipcs == NULL) {
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Failed to create pacemaker-schedulerd server: exiting and inhibiting respawn");
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    logger_out = pcmk__new_logger();
    if (logger_out == NULL) {
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    pcmk__output_set_log_level(logger_out, LOG_TRACE);

    /* Create the mainloop and run it... */
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker scheduler successfully started and accepting connections");
    g_main_loop_run(mainloop);

done:
    g_strfreev(options.remainder);
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, out);
    pengine_shutdown(0);
}

void
pengine_shutdown(int nsig)
{
    if (ipcs != NULL) {
        crm_trace("Closing IPC server");
        mainloop_del_ipc_server(ipcs);
        ipcs = NULL;
    }

    if (sched_data_set != NULL) {
        pe_free_working_set(sched_data_set);
        sched_data_set = NULL;
    }

    if (logger_out != NULL) {
        logger_out->finish(logger_out, exit_code, true, NULL);
        pcmk__output_free(logger_out);
        logger_out = NULL;
    }

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
        out = NULL;
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

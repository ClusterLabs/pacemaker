/*
 * Copyright 2004-2026 the Pacemaker project contributors
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
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

#define SUMMARY "daemon for coordinating a Pacemaker cluster's response "   \
                "to events"

controld_globals_t controld_globals = {
    // Automatic initialization to 0, false, or NULL is fine for most members
    .fsa_state = S_STARTING,
    .fsa_actions = A_NOTHING,
};

static pcmk__supported_format_t formats[] = {
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
controld_metadata(pcmk__output_t *out)
{
    return pcmk__daemon_metadata(out, PCMK__SERVER_CONTROLD,
                                 "Pacemaker controller options",
                                 "Cluster options used by Pacemaker's "
                                 "controller",
                                 pcmk__opt_controld);
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    return pcmk__build_arg_context(args, "text (default), xml", group, NULL);
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;
    bool initialize = true;
    enum crmd_fsa_state state;

    crm_ipc_t *old_instance = NULL;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
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
        initialize = false;
        goto done;
    }

    if ((g_strv_length(processed_args) >= 2)
        && pcmk__str_eq(processed_args[1], "metadata", pcmk__str_none)) {

        initialize = false;
        rc = controld_metadata(out);
        if (rc != pcmk_rc_ok) {
            exit_code = CRM_EX_FATAL;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Unable to display metadata: %s", pcmk_rc_str(rc));
        }
        goto done;
    }

    pcmk__cli_init_logging(PCMK__SERVER_CONTROLD, args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    pcmk__notice("Starting Pacemaker controller");

    old_instance = crm_ipc_new(CRM_SYSTEM_CRMD, 0);
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
        pcmk__crit("Aborting start-up because another controller instance is "
                   "already active");
        initialize = false;
        goto done;

    } else {
        /* not up or not authentic, we'll proceed either way */
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    if (pcmk__daemon_can_write(PCMK_SCHEDULER_INPUT_DIR, NULL) == FALSE) {
        exit_code = CRM_EX_FATAL;
        pcmk__err("Terminating due to bad permissions on "
                  PCMK_SCHEDULER_INPUT_DIR);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bad permissions on " PCMK_SCHEDULER_INPUT_DIR
                    " (see logs for details)");
        goto done;

    } else if (pcmk__daemon_can_write(CRM_CONFIG_DIR, NULL) == FALSE) {
        exit_code = CRM_EX_FATAL;
        pcmk__err("Terminating due to bad permissions on " CRM_CONFIG_DIR);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bad permissions on " CRM_CONFIG_DIR
                    " (see logs for details)");
        goto done;
    }

    if (pcmk__log_output_new(&(controld_globals.logger_out)) != pcmk_rc_ok) {
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    pcmk__output_set_log_level(controld_globals.logger_out, LOG_TRACE);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    // We no longer need output
    pcmk__output_and_clear_error(&error, out);
    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    pcmk__unregister_formats();

    // Exit on error or command-line queries
    if ((exit_code != CRM_EX_OK) || !initialize) {
        crm_exit(exit_code);
    }

    // Initialize FSA
    controld_fsa_append(C_STARTUP, I_STARTUP, NULL);
    pcmk__cluster_init_node_caches();
    state = s_crmd_fsa(C_STARTUP);
    if ((state != S_PENDING) && (state != S_STARTING)) {
        pcmk__err("Controller startup failed " QB_XS " FSA state %s",
                  crm_system_name, fsa_state2string(state));
        crmd_fast_exit(CRM_EX_ERROR); // Does not return
    }

    // Run mainloop
    controld_globals.mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(controld_globals.mainloop);
    g_main_loop_unref(controld_globals.mainloop);

    if (pcmk__is_set(controld_globals.fsa_input_register, R_STAYDOWN)) {
        pcmk__info("Inhibiting automated respawn");
        exit_code = CRM_EX_FATAL;
    }
    crmd_fast_exit(exit_code);
}

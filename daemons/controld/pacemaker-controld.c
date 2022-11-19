/*
 * Copyright 2004-2022 the Pacemaker project contributors
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

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

#define SUMMARY "daemon for coordinating a Pacemaker cluster's response "   \
                "to events"

_Noreturn void crmd_init(void);
extern void init_dotfile(void);

controld_globals_t controld_globals = {
    // Automatic initialization to 0, false, or NULL is fine for most members
    .fsa_state = S_STARTING,
    .fsa_actions = A_NOTHING,
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args)
{
    return pcmk__build_arg_context(args, NULL, NULL, "[metadata]");
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    bool initialize = true;

    crm_ipc_t *old_instance = NULL;

    GError *error = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, NULL);
    GOptionContext *context = build_arg_context(args);

    controld_globals.mainloop = g_main_loop_new(NULL, FALSE);
    crm_log_preinit(NULL, argc, argv);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);

        /* FIXME: When pacemaker-attrd is converted to use formatted output,
         * this can go.
         */
        pcmk__cli_help('v', CRM_EX_OK);
    }

    if ((g_strv_length(processed_args) >= 2)
        && pcmk__str_eq(processed_args[1], "metadata", pcmk__str_none)) {
        crmd_metadata();
        initialize = false;
        goto done;
    }

    pcmk__cli_init_logging("pacemaker-controld", args->verbosity);
    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_notice("Starting Pacemaker controller");

    old_instance = crm_ipc_new(CRM_SYSTEM_CRMD, 0);
    if (old_instance == NULL) {
        /* crm_ipc_new will have already printed an error message with crm_err. */
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    if (crm_ipc_connect(old_instance)) {
        /* IPC end-point already up */
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("pacemaker-controld is already active, aborting startup");
        initialize = false;
        goto done;

    } else {
        /* not up or not authentic, we'll proceed either way */
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    if (pcmk__daemon_can_write(PE_STATE_DIR, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on " PE_STATE_DIR);
        fprintf(stderr,
                "ERROR: Bad permissions on " PE_STATE_DIR " (see logs for details)\n");
        fflush(stderr);
        exit_code = CRM_EX_FATAL;
        goto done;

    } else if (pcmk__daemon_can_write(CRM_CONFIG_DIR, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on " CRM_CONFIG_DIR);
        fprintf(stderr,
                "ERROR: Bad permissions on " CRM_CONFIG_DIR " (see logs for details)\n");
        fflush(stderr);
        exit_code = CRM_EX_FATAL;
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

    pcmk__output_and_clear_error(error, NULL);

    if ((exit_code == CRM_EX_OK) && initialize) {
        // Does not return
        crmd_init();
    }
    crm_exit(exit_code);
}

void
crmd_init(void)
{
    crm_exit_t exit_code = CRM_EX_OK;
    enum crmd_fsa_state state;

    init_dotfile();
    register_fsa_input(C_STARTUP, I_STARTUP, NULL);

    crm_peer_init();
    state = s_crmd_fsa(C_STARTUP);

    if (state == S_PENDING || state == S_STARTING) {
        /* Create the mainloop and run it... */
        crm_trace("Starting %s's mainloop", crm_system_name);
        g_main_loop_run(controld_globals.mainloop);
        if (pcmk_is_set(controld_globals.fsa_input_register, R_STAYDOWN)) {
            crm_info("Inhibiting automated respawn");
            exit_code = CRM_EX_FATAL;
        }

    } else {
        crm_err("Startup of %s failed.  Current state: %s",
                crm_system_name, fsa_state2string(state));
        exit_code = CRM_EX_ERROR;
    }

    crm_info("%s[%lu] exiting with status %d (%s)",
             crm_system_name, (unsigned long) getpid(), exit_code,
             crm_exit_str(exit_code));

    crmd_fast_exit(exit_code);
}

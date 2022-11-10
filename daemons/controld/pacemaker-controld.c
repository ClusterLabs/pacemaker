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
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

#define OPTARGS	"hV"

void usage(const char *cmd, int exit_status);
_Noreturn void crmd_init(void);
void crmd_hamsg_callback(const xmlNode * msg, void *private_data);
extern void init_dotfile(void);

GMainLoop *crmd_mainloop = NULL;

pcmk__output_t *logger_out = NULL;

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

int
main(int argc, char **argv)
{
    int flag;
    int index = 0;
    int argerr = 0;
    crm_ipc_t *old_instance = NULL;

    crmd_mainloop = g_main_loop_new(NULL, FALSE);
    crm_log_preinit(NULL, argc, argv);
    pcmk__set_cli_options(NULL, "[options]", long_options,
                          "daemon for coordinating a Pacemaker cluster's "
                          "response to events");

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'h':          /* Help message */
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && pcmk__str_eq("metadata", argv[optind], pcmk__str_casei)) {
        crmd_metadata();
        return CRM_EX_OK;
    } else if (argc - optind == 1 && pcmk__str_eq("version", argv[optind], pcmk__str_casei)) {
        fprintf(stdout, "CRM Version: %s (%s)\n", PACEMAKER_VERSION, BUILD_VERSION);
        return CRM_EX_OK;
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    crm_notice("Starting Pacemaker controller");

    old_instance = crm_ipc_new(CRM_SYSTEM_CRMD, 0);
    if (old_instance == NULL) {
        /* crm_ipc_new will have already printed an error message with crm_err. */
        return CRM_EX_FATAL;
    }

    if (crm_ipc_connect(old_instance)) {
        /* IPC end-point already up */
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("pacemaker-controld is already active, aborting startup");
        crm_exit(CRM_EX_OK);
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
        return CRM_EX_FATAL;

    } else if (pcmk__daemon_can_write(CRM_CONFIG_DIR, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on " CRM_CONFIG_DIR);
        fprintf(stderr,
                "ERROR: Bad permissions on " CRM_CONFIG_DIR " (see logs for details)\n");
        fflush(stderr);
        return CRM_EX_FATAL;
    }

    if (pcmk__log_output_new(&logger_out) != pcmk_rc_ok) {
        return CRM_EX_FATAL;
    }

    pcmk__output_set_log_level(logger_out, LOG_TRACE);

    crmd_init();
    return 0; // not reachable
}

static void
log_deprecation_warnings(void)
{
    // Add deprecations here as needed
}

void
crmd_init(void)
{
    crm_exit_t exit_code = CRM_EX_OK;
    enum crmd_fsa_state state;

    log_deprecation_warnings();

    fsa_state = S_STARTING;
    fsa_input_register = 0;     /* zero out the regester */

    init_dotfile();
    register_fsa_input(C_STARTUP, I_STARTUP, NULL);

    crm_peer_init();
    state = s_crmd_fsa(C_STARTUP);

    if (state == S_PENDING || state == S_STARTING) {
        /* Create the mainloop and run it... */
        crm_trace("Starting %s's mainloop", crm_system_name);
        g_main_loop_run(crmd_mainloop);
        if (pcmk_is_set(fsa_input_register, R_STAYDOWN)) {
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

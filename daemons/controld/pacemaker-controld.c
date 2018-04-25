/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
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
#include <controld_fsa.h>
#include <controld_messages.h>

#define OPTARGS	"hV"

void usage(const char *cmd, int exit_status);
int crmd_init(void);
void crmd_hamsg_callback(const xmlNode * msg, void *private_data);
extern void init_dotfile(void);

GMainLoop *crmd_mainloop = NULL;

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int flag;
    int index = 0;
    int argerr = 0;

    crmd_mainloop = g_main_loop_new(NULL, FALSE);
    crm_log_preinit(NULL, argc, argv);
    crm_set_options(NULL, "[options]", long_options,
                    "Daemon for aggregating resource and node failures as well as co-ordinating the cluster's response");

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'h':          /* Help message */
                crm_help(flag, CRM_EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        crmd_metadata();
        return CRM_EX_OK;
    } else if (argc - optind == 1 && safe_str_eq("version", argv[optind])) {
        fprintf(stdout, "CRM Version: %s (%s)\n", PACEMAKER_VERSION, BUILD_VERSION);
        return CRM_EX_OK;
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_info("CRM Git Version: %s (%s)", PACEMAKER_VERSION, BUILD_VERSION);

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    if (crm_is_writable(PE_STATE_DIR, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) == FALSE) {
        crm_err("Bad permissions on " PE_STATE_DIR ". Terminating");
        fprintf(stderr, "ERROR: Bad permissions on " PE_STATE_DIR ". See logs for details\n");
        fflush(stderr);
        return CRM_EX_FATAL;

    } else if (crm_is_writable(CRM_CONFIG_DIR, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) ==
               FALSE) {
        crm_err("Bad permissions on " CRM_CONFIG_DIR ". Terminating");
        fprintf(stderr, "ERROR: Bad permissions on " CRM_CONFIG_DIR ". See logs for details\n");
        fflush(stderr);
        return CRM_EX_FATAL;
    }

    return crmd_init();
}

static void
log_deprecation_warnings()
{
    // Add deprecations here as needed
}

int
crmd_init(void)
{
    crm_exit_t exit_code = CRM_EX_OK;
    enum crmd_fsa_state state;

    log_deprecation_warnings();

    fsa_state = S_STARTING;
    fsa_input_register = 0;     /* zero out the regester */

    init_dotfile();
    crm_debug("Starting %s", crm_system_name);
    register_fsa_input(C_STARTUP, I_STARTUP, NULL);

    crm_peer_init();
    state = s_crmd_fsa(C_STARTUP);

    if (state == S_PENDING || state == S_STARTING) {
        /* Create the mainloop and run it... */
        crm_trace("Starting %s's mainloop", crm_system_name);

#ifdef REALTIME_SUPPORT
        static int crm_realtime = 1;

        if (crm_realtime == 1) {
            cl_enable_realtime();
        } else if (crm_realtime == 0) {
            cl_disable_realtime();
        }
        cl_make_realtime(SCHED_RR, 5, 64, 64);
#endif
        g_main_loop_run(crmd_mainloop);
        if (is_set(fsa_input_register, R_STAYDOWN)) {
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
    return crmd_fast_exit(exit_code);
}

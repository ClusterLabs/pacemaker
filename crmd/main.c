/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
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

#include <crmd.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>

#define OPTARGS	"hV"

void usage(const char *cmd, int exit_status);
int crmd_init(void);
void crmd_hamsg_callback(const xmlNode * msg, void *private_data);
extern void init_dotfile(void);

GMainLoop *crmd_mainloop = NULL;

int
main(int argc, char **argv)
{
    int flag;
    int argerr = 0;

    crm_system_name = CRM_SYSTEM_CRMD;

    while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'h':          /* Help message */
                usage(crm_system_name, EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        crmd_metadata();
        return 0;
    } else if (argc - optind == 1 && safe_str_eq("version", argv[optind])) {
        fprintf(stdout, "CRM Version: ");
        fprintf(stdout, "%s (%s)\n", VERSION, BUILD_VERSION);
        return 0;
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);

    crm_notice("CRM Git Version: %s\n", BUILD_VERSION);

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        usage(crm_system_name, EX_USAGE);
    }

    if (crm_is_writable(PE_STATE_DIR, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) == FALSE) {
        crm_err("Bad permissions on " PE_STATE_DIR ". Terminating");
        fprintf(stderr, "ERROR: Bad permissions on " PE_STATE_DIR ". See logs for details\n");
        fflush(stderr);
        return 100;

    } else if (crm_is_writable(CRM_CONFIG_DIR, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) ==
               FALSE) {
        crm_err("Bad permissions on " CRM_CONFIG_DIR ". Terminating");
        fprintf(stderr, "ERROR: Bad permissions on " CRM_CONFIG_DIR ". See logs for details\n");
        fflush(stderr);
        return 100;
    }

    return crmd_init();
}

int
crmd_init(void)
{
    int exit_code = 0;
    enum crmd_fsa_state state;

    fsa_state = S_STARTING;
    fsa_input_register = 0;     /* zero out the regester */

    init_dotfile();
    crm_debug("Starting %s", crm_system_name);
    register_fsa_input(C_STARTUP, I_STARTUP, NULL);

    crm_peer_init();
    state = s_crmd_fsa(C_STARTUP);

    if (state == S_PENDING || state == S_STARTING) {
        /* Create the mainloop and run it... */
        crmd_mainloop = g_main_new(FALSE);
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
        g_main_run(crmd_mainloop);
        if (is_set(fsa_input_register, R_STAYDOWN)) {
            crm_info("Inhibiting respawn by Heartbeat");
            exit_code = 100;
        }

    } else {
        crm_err("Startup of %s failed.  Current state: %s",
                crm_system_name, fsa_state2string(state));
        exit_code = 1;
    }

    crm_info("[%s] stopped (%d)", crm_system_name, exit_code);
    qb_log_fini();

    return exit_code;
}

void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s [-V] [-h|version|metadata]\n", cmd);
    fprintf(stream, "\t-h\t: this help message\n");
    fprintf(stream, "\t-V\t: increase verbosity\n");
    fprintf(stream, "\tmetadata\t: show configurable crmd options\n");
    fprintf(stream, "\tversion\t\t: show version information and quit\n");
    fflush(stream);

    exit(exit_status);
}

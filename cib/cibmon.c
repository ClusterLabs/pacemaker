
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

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/mainloop.h>
#include <crm/cib/internal.h>

#include <crm/common/ipc.h>
#include <crm/pengine/status.h>
#include <../lib/pengine/unpack.h>

#include <crm/cib.h>

#ifdef HAVE_GETOPT_H
#  include <getopt.h>
#endif

int max_failures = 30;
int exit_code = pcmk_ok;

gboolean log_diffs = FALSE;
gboolean log_updates = FALSE;

GMainLoop *mainloop = NULL;
void usage(const char *cmd, int exit_status);
void cib_connection_destroy(gpointer user_data);

void cibmon_shutdown(int nsig);
void cibmon_diff(const char *event, xmlNode * msg);

cib_t *cib = NULL;
xmlNode *cib_copy = NULL;

#define OPTARGS	"V?m:du"

int
main(int argc, char **argv)
{
    int argerr = 0;
    int flag;
    int attempts = 0;

#ifdef HAVE_GETOPT_H
    int option_index = 0;

    static struct option long_options[] = {
        /* Top-level Options */
        {"verbose", 0, 0, 'V'},
        {"help", 0, 0, '?'},
        {"log-diffs", 0, 0, 'd'},
        {"log-updates", 0, 0, 'u'},
        {"max-conn-fail", 1, 0, 'm'},
        {0, 0, 0, 0}
    };
#endif

    crm_log_cli_init("cibmon");

    crm_signal(SIGTERM, cibmon_shutdown);

    while (1) {
#ifdef HAVE_GETOPT_H
        flag = getopt_long(argc, argv, OPTARGS, long_options, &option_index);
#else
        flag = getopt(argc, argv, OPTARGS);
#endif
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '?':
                usage(crm_system_name, EX_OK);
                break;
            case 'd':
                log_diffs = TRUE;
                break;
            case 'u':
                log_updates = TRUE;
                break;
            case 'm':
                max_failures = crm_parse_int(optarg, "30");
                break;
            default:
                printf("Argument code 0%o (%c)" " is not (?yet?) supported\n", flag, flag);
                ++argerr;
                break;
        }
    }

    if (optind < argc) {
        printf("non-option ARGV-elements: ");
        while (optind < argc)
            printf("%s ", argv[optind++]);
        printf("\n");
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        usage(crm_system_name, EX_USAGE);
    }

    cib = cib_new();

    do {
        sleep(1);
        exit_code = cib->cmds->signon(cib, crm_system_name, cib_query);

    } while (exit_code == -ENOTCONN && attempts++ < max_failures);

    if (exit_code != pcmk_ok) {
        crm_err("Signon to CIB failed: %s", pcmk_strerror(exit_code));
    }

    if (exit_code == pcmk_ok) {
        crm_debug("Setting dnotify");
        exit_code = cib->cmds->set_connection_dnotify(cib, cib_connection_destroy);
    }

    crm_debug("Setting diff callback");
    exit_code = cib->cmds->add_notify_callback(cib, T_CIB_DIFF_NOTIFY, cibmon_diff);

    if (exit_code != pcmk_ok) {
        crm_err("Failed to set %s callback: %s", T_CIB_DIFF_NOTIFY, pcmk_strerror(exit_code));
    }

    if (exit_code != pcmk_ok) {
        crm_err("Setup failed, could not monitor CIB actions");
        return -exit_code;
    }

    mainloop = g_main_new(FALSE);
    crm_info("Starting mainloop");
    g_main_run(mainloop);
    crm_trace("%s exiting normally", crm_system_name);
    fflush(stderr);
    return -exit_code;
}

void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status != 0 ? stderr : stdout;
    fflush(stream);

    exit(exit_status);
}

void
cib_connection_destroy(gpointer user_data)
{
    cib_t *conn = user_data;
    crm_err("Connection to the CIB terminated... exiting");
    conn->cmds->signoff(conn); /* Ensure IPC is cleaned up */
    g_main_quit(mainloop);
    return;
}

void
cibmon_diff(const char *event, xmlNode * msg)
{
    int rc = -1;
    const char *op = NULL;
    unsigned int log_level = LOG_INFO;

    xmlNode *diff = NULL;
    xmlNode *cib_last = NULL;
    xmlNode *update = get_message_xml(msg, F_CIB_UPDATE);

    if (msg == NULL) {
        crm_err("NULL update");
        return;
    }

    crm_element_value_int(msg, F_CIB_RC, &rc);
    op = crm_element_value(msg, F_CIB_OPERATION);
    diff = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    if (rc < pcmk_ok) {
        log_level = LOG_WARNING;
        do_crm_log(log_level, "[%s] %s ABORTED: %s", event, op, pcmk_strerror(rc));
        return;
    }

    if (log_diffs) {
        log_cib_diff(log_level, diff, op);
    }

    if (log_updates && update != NULL) {
        crm_log_xml_trace(update, "raw_update");
    }

    if (cib_copy != NULL) {
        cib_last = cib_copy;
        cib_copy = NULL;
        rc = cib_process_diff(op, cib_force_diff, NULL, NULL, diff, cib_last, &cib_copy, NULL);

        if (rc != pcmk_ok) {
            crm_debug("Update didn't apply, requesting full copy: %s", pcmk_strerror(rc));
            free_xml(cib_copy);
            cib_copy = NULL;
        }
    }

    if (cib_copy == NULL) {
        cib_copy = get_cib_copy(cib);
    }

    free_xml(cib_last);
}

void
cibmon_shutdown(int nsig)
{
    exit(EX_OK);
}

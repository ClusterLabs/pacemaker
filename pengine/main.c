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

#include <crm/crm.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/common/ipc.h>
#include <crm/common/mainloop.h>
#include <crm/pengine/common.h>

#if HAVE_LIBXML2
#  include <libxml/parser.h>
#endif

#define OPTARGS	"hVc"

char *ipc_server = NULL;
GMainLoop *mainloop = NULL;

void usage(const char *cmd, int exit_status);
void pengine_shutdown(int nsig);
extern gboolean process_pe_message(xmlNode * msg, xmlNode * xml_data, IPC_Channel * sender);

static gboolean
pe_msg_callback(IPC_Channel * client, gpointer user_data)
{
    xmlNode *msg = NULL;
    gboolean stay_connected = TRUE;

    while (IPC_ISRCONN(client)) {
        if (client->ops->is_message_pending(client) == 0) {
            break;
        }

        msg = xmlfromIPC(client, MAX_IPC_DELAY);
        if (msg != NULL) {
            xmlNode *data = get_message_xml(msg, F_CRM_DATA);

            process_pe_message(msg, data, client);
            free_xml(msg);
        }
    }

    if (client->ch_status != IPC_CONNECT) {
        stay_connected = FALSE;
    }

    return stay_connected;
}

static void
pe_connection_destroy(gpointer user_data)
{
    return;
}

static gboolean
pe_client_connect(IPC_Channel * client, gpointer user_data)
{
    crm_trace("Invoked");
    if (client == NULL) {
        crm_err("Channel was NULL");

    } else if (client->ch_status == IPC_DISCONNECT) {
        crm_err("Channel was disconnected");

    } else {
        client->ops->set_recv_qlen(client, 1024);
        client->ops->set_send_qlen(client, 1024);
        G_main_add_IPC_Channel(G_PRIORITY_LOW, client, FALSE, pe_msg_callback, NULL,
                               pe_connection_destroy);
    }

    return TRUE;
}

int
main(int argc, char **argv)
{
    int flag;
    int argerr = 0;
    gboolean allow_cores = TRUE;
    IPC_Channel *old_instance = NULL;

    crm_system_name = CRM_SYSTEM_PENGINE;
    mainloop_add_signal(SIGTERM, pengine_shutdown);

    while ((flag = getopt(argc, argv, OPTARGS)) != EOF) {
        switch (flag) {
            case 'V':
                crm_bump_log_level();
                break;
            case 'h':          /* Help message */
                usage(crm_system_name, LSB_EXIT_OK);
                break;
            case 'c':
                allow_cores = TRUE;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        pe_metadata();
        return 0;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        usage(crm_system_name, LSB_EXIT_GENERIC);
    }

    crm_log_init(NULL, LOG_NOTICE, TRUE, FALSE, argc, argv);

    if (crm_is_writable(PE_STATE_DIR, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) == FALSE) {
        crm_err("Bad permissions on " PE_STATE_DIR ". Terminating");
        fprintf(stderr, "ERROR: Bad permissions on " PE_STATE_DIR ". See logs for details\n");
        fflush(stderr);
        return 100;
    }

    ipc_server = crm_strdup(CRM_SYSTEM_PENGINE);

    /* find any previous instances and shut them down */
    crm_debug("Checking for old instances of %s", crm_system_name);
    old_instance = init_client_ipc_comms_nodispatch(CRM_SYSTEM_PENGINE);
    while (old_instance != NULL) {
        xmlNode *cmd =
            create_request(CRM_OP_QUIT, NULL, NULL, CRM_SYSTEM_PENGINE, CRM_SYSTEM_PENGINE, NULL);

        crm_warn("Terminating previous PE instance");
        send_ipc_message(old_instance, cmd);
        free_xml(cmd);

        sleep(2);

        old_instance->ops->destroy(old_instance);
        old_instance = init_client_ipc_comms_nodispatch(CRM_SYSTEM_PENGINE);
    }

    crm_debug("Init server comms");
    if (init_server_ipc_comms(ipc_server, pe_client_connect, default_ipc_connection_destroy)) {
        crm_err("Couldn't start IPC server");
        return 1;
    }

    /* Create the mainloop and run it... */
    crm_info("Starting %s", crm_system_name);

    mainloop = g_main_new(FALSE);
    g_main_run(mainloop);

#if HAVE_LIBXML2
    crm_xml_cleanup();
#endif

    crm_info("Exiting %s", crm_system_name);
    return 0;
}

void
usage(const char *cmd, int exit_status)
{
    FILE *stream;

    stream = exit_status ? stderr : stdout;

    fprintf(stream, "usage: %s [-srkh]" "[-c configure file]\n", cmd);
/* 	fprintf(stream, "\t-d\tsets debug level\n"); */
/* 	fprintf(stream, "\t-s\tgets daemon status\n"); */
/* 	fprintf(stream, "\t-r\trestarts daemon\n"); */
/* 	fprintf(stream, "\t-k\tstops daemon\n"); */
/* 	fprintf(stream, "\t-h\thelp message\n"); */
    fflush(stream);

    exit(exit_status);
}

void
pengine_shutdown(int nsig)
{
    crm_free(ipc_server);
    exit(LSB_EXIT_OK);
}

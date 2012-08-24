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
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>

#if HAVE_LIBXML2
#  include <libxml/parser.h>
#endif

#define OPTARGS	"hVc"

GMainLoop *mainloop = NULL;
qb_ipcs_service_t *ipcs = NULL;

void usage(const char *cmd, int exit_status);
void pengine_shutdown(int nsig);

static int32_t
pe_ipc_accept(qb_ipcs_connection_t *c, uid_t uid, gid_t gid)
{
    crm_trace("Connecting %p for uid=%d gid=%d", c, uid, gid);
    return 0;
}

static void
pe_ipc_created(qb_ipcs_connection_t *c)
{
}

gboolean process_pe_message(xmlNode * msg, xmlNode * xml_data, qb_ipcs_connection_t* sender);

static int32_t
pe_ipc_dispatch(qb_ipcs_connection_t *c, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    xmlNode *msg = crm_ipcs_recv(c, data, size, &id, &flags);

    if(flags & crm_ipc_client_response) {
        crm_ipcs_send_ack(c, id, "ack", __FUNCTION__, __LINE__);
    }

    if (msg != NULL) {
        xmlNode *data = get_message_xml(msg, F_CRM_DATA);
        
        process_pe_message(msg, data, c);
        free_xml(msg);
    }
    return 0;
}

/* Error code means? */
static int32_t
pe_ipc_closed(qb_ipcs_connection_t *c) 
{
    return 0;
}

static void
pe_ipc_destroy(qb_ipcs_connection_t *c) 
{
    crm_trace("Disconnecting %p", c);
}

struct qb_ipcs_service_handlers ipc_callbacks = 
{
    .connection_accept = pe_ipc_accept,
    .connection_created = pe_ipc_created,
    .msg_process = pe_ipc_dispatch,
    .connection_closed = pe_ipc_closed,
    .connection_destroyed = pe_ipc_destroy
};

int
main(int argc, char **argv)
{
    int flag;
    int argerr = 0;
    crm_ipc_t *old_instance = NULL;

    crm_system_name = CRM_SYSTEM_PENGINE;
    mainloop_add_signal(SIGTERM, pengine_shutdown);

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
        pe_metadata();
        return 0;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        usage(crm_system_name, EX_USAGE);
    }

    crm_log_init(NULL, LOG_NOTICE, TRUE, FALSE, argc, argv, FALSE);

    if (crm_is_writable(PE_STATE_DIR, NULL, CRM_DAEMON_USER, CRM_DAEMON_GROUP, FALSE) == FALSE) {
        crm_err("Bad permissions on " PE_STATE_DIR ". Terminating");
        fprintf(stderr, "ERROR: Bad permissions on " PE_STATE_DIR ". See logs for details\n");
        fflush(stderr);
        return 100;
    }

    /* find any previous instances and shut them down */
    crm_debug("Checking for old instances of %s", CRM_SYSTEM_PENGINE);
    old_instance = crm_ipc_new(CRM_SYSTEM_PENGINE, 0);
    crm_ipc_connect(old_instance);
    
    crm_debug("Terminating previous instance");
    while (crm_ipc_connected(old_instance)) {
        xmlNode *cmd = create_request(CRM_OP_QUIT, NULL, NULL, CRM_SYSTEM_PENGINE, CRM_SYSTEM_PENGINE, NULL);
        crm_debug(".");
        crm_ipc_send(old_instance, cmd, 0, 0, NULL);
        free_xml(cmd);
        
        sleep(2);
    }
    crm_ipc_close(old_instance);
    crm_ipc_destroy(old_instance);

    crm_debug("Init server comms");
    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_PENGINE, QB_IPC_SHM, &ipc_callbacks);
    if (ipcs == NULL) {
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
    qb_log_fini();
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
    mainloop_del_ipc_server(ipcs);
    exit(EX_OK);
}

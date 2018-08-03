/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libxml/parser.h>

#include <crm/common/ipcs.h>
#include <crm/common/mainloop.h>
#include <crm/pengine/internal.h>
#include <crm/msg_xml.h>

#define OPTARGS	"hVc"

static GMainLoop *mainloop = NULL;
static qb_ipcs_service_t *ipcs = NULL;

void pengine_shutdown(int nsig);

static int32_t
pe_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    crm_trace("Connection %p", c);
    if (crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
pe_ipc_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
}

gboolean process_pe_message(xmlNode * msg, xmlNode * xml_data, crm_client_t * sender);

static int32_t
pe_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    crm_client_t *c = crm_client_get(qbc);
    xmlNode *msg = crm_ipcs_recv(c, data, size, &id, &flags);

    crm_ipcs_send_ack(c, id, flags, "ack", __FUNCTION__, __LINE__);
    if (msg != NULL) {
        xmlNode *data_xml = get_message_xml(msg, F_CRM_DATA);

        process_pe_message(msg, data_xml, c);
        free_xml(msg);
    }
    return 0;
}

/* Error code means? */
static int32_t
pe_ipc_closed(qb_ipcs_connection_t * c)
{
    crm_client_t *client = crm_client_get(c);

    if (client == NULL) {
        return 0;
    }
    crm_trace("Connection %p", c);
    crm_client_destroy(client);
    return 0;
}

static void
pe_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p", c);
    pe_ipc_closed(c);
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = pe_ipc_accept,
    .connection_created = pe_ipc_created,
    .msg_process = pe_ipc_dispatch,
    .connection_closed = pe_ipc_closed,
    .connection_destroyed = pe_ipc_destroy
};

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

    crm_log_preinit(NULL, argc, argv);
    crm_set_options(NULL, "[options]",
                    long_options, "Daemon for calculating the cluster's response to events");

    mainloop_add_signal(SIGTERM, pengine_shutdown);

    while (1) {
        flag = crm_get_option(argc, argv, &index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 'h':          /* Help message */
                crm_help('?', CRM_EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        pe_metadata();
        return CRM_EX_OK;
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    if (pcmk__daemon_can_write(PE_STATE_DIR, NULL) == FALSE) {
        crm_err("Terminating due to bad permissions on " PE_STATE_DIR);
        fprintf(stderr,
                "ERROR: Bad permissions on " PE_STATE_DIR " (see logs for details)\n");
        fflush(stderr);
        return CRM_EX_FATAL;
    }

    crm_debug("Init server comms");
    ipcs = mainloop_add_ipc_server(CRM_SYSTEM_PENGINE, QB_IPC_SHM, &ipc_callbacks);
    if (ipcs == NULL) {
        crm_err("Failed to create IPC server: shutting down and inhibiting respawn");
        crm_exit(CRM_EX_FATAL);
    }

    /* Create the mainloop and run it... */
    crm_info("Starting %s", crm_system_name);

    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);

    crm_info("Exiting %s", crm_system_name);
    return crm_exit(CRM_EX_OK);
}

void
pengine_shutdown(int nsig)
{
    mainloop_del_ipc_server(ipcs);
    crm_exit(CRM_EX_OK);
}

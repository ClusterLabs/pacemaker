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
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <libgen.h>             /* for basename() */

#include <crm/crm.h>
#include <crm/cluster/internal.h>
#include <crm/common/mainloop.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crm/attrd.h>

static int command = 0;
static char *pid_s = NULL;
static const char *target_uname = NULL;
static GMainLoop *mainloop = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",       0, 0, '?', "\tThis text"},
    {"version",    0, 0, '$', "\tVersion information"  },
    {"verbose",    0, 0, 'V', "\tIncrease debug output"},
    {"quiet",      0, 0, 'Q', "\tEssential output only"},

    {"-spacer-",   1, 0, '-', "\nStack:"},
#if SUPPORT_COROSYNC
    {"corosync",   0, 0, 'C', "\tOnly try connecting to an Corosync-based cluster"},
#endif

    {"-spacer-",      1, 0, '-', "\nCommands:"},
    {"name",	      0, 0, 'n', "\tDisplay the name used by the cluster for this node"},
    {"name-for-id",   1, 0, 'N', "\tDisplay the name used by the cluster for the node with the specified id"},
    {"quorum",        0, 0, 'q', "\tDisplay a 1 if our partition has quorum, 0 if not"},
    {"list",          0, 0, 'l', "\tDisplay all known members (past and present) of this cluster"},
    {"partition",     0, 0, 'p', "Display the members of this partition"},
    {"cluster-id",    0, 0, 'i', "Display this node's cluster id"},
    {"remove",        1, 0, 'R', "(Advanced) Remove the (stopped) node with the specified name from Pacemaker's configuration and caches"},
    {"-spacer-",      1, 0, '-', "(the node must already have been removed from the underlying cluster stack configuration)"},

    {"-spacer-", 1, 0, '-', "\nAdditional Options:"},
    {"force",	 0, 0, 'f'},
    // @TODO add timeout option for when IPC replies are needed

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

/*!
 * \internal
 * \brief Exit crm_node
 * Clean up memory, and either quit mainloop (if running) or exit
 *
 * \param[in] value  Exit status
 */
static void
crm_node_exit(crm_exit_t value)
{
    if (pid_s) {
        free(pid_s);
        pid_s = NULL;
    }

    exit_code = value;

    if (mainloop && g_main_loop_is_running(mainloop)) {
        g_main_loop_quit(mainloop);
    } else {
        crm_exit(exit_code);
    }
}

static void
exit_disconnect(gpointer user_data)
{
    fprintf(stderr, "error: Lost connection to cluster\n");
    crm_node_exit(CRM_EX_DISCONNECT);
}

typedef int (*ipc_dispatch_fn) (const char *buffer, ssize_t length,
                                gpointer userdata);

static crm_ipc_t *
new_mainloop_for_ipc(const char *system, ipc_dispatch_fn dispatch)
{
    mainloop_io_t *source = NULL;
    crm_ipc_t *ipc = NULL;

    struct ipc_client_callbacks ipc_callbacks = {
        .dispatch = dispatch,
        .destroy = exit_disconnect
    };

    mainloop = g_main_loop_new(NULL, FALSE);
    source = mainloop_add_ipc_client(system, G_PRIORITY_DEFAULT, 0,
                                     NULL, &ipc_callbacks);
    ipc = mainloop_get_ipc_client(source);
    if (ipc == NULL) {
        fprintf(stderr,
                "error: Could not connect to cluster (is it running?)\n");
        crm_node_exit(CRM_EX_DISCONNECT);
    }
    return ipc;
}

static void
run_mainloop_and_exit()
{
    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);
    mainloop = NULL;
    crm_node_exit(exit_code);
}

static int
cib_remove_node(uint32_t id, const char *name)
{
    int rc;
    cib_t *cib = NULL;
    xmlNode *node = NULL;
    xmlNode *node_state = NULL;

    crm_trace("Removing %s from the CIB", name);

    if(name == NULL && id == 0) {
        return -ENOTUNIQ;
    }

    node = create_xml_node(NULL, XML_CIB_TAG_NODE);
    node_state = create_xml_node(NULL, XML_CIB_TAG_STATE);

    crm_xml_add(node, XML_ATTR_UNAME, name);
    crm_xml_add(node_state, XML_ATTR_UNAME, name);
    if(id) {
        crm_xml_set_id(node, "%u", id);
        crm_xml_add(node_state, XML_ATTR_ID, ID(node));
    }

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);

    rc = cib->cmds->remove(cib, XML_CIB_TAG_NODES, node, cib_sync_call);
    if (rc != pcmk_ok) {
        printf("Could not remove %s/%u from " XML_CIB_TAG_NODES ": %s", name, id, pcmk_strerror(rc));
    }
    rc = cib->cmds->remove(cib, XML_CIB_TAG_STATUS, node_state, cib_sync_call);
    if (rc != pcmk_ok) {
        printf("Could not remove %s/%u from " XML_CIB_TAG_STATUS ": %s", name, id, pcmk_strerror(rc));
    }

    cib->cmds->signoff(cib);
    cib_delete(cib);
    return rc;
}

static int
tools_remove_node_cache(const char *node, const char *target)
{
    int n = 0;
    int rc = -1;
    char *name = NULL;
    char *admin_uuid = NULL;
    crm_ipc_t *conn = crm_ipc_new(target, 0);
    xmlNode *cmd = NULL;
    xmlNode *hello = NULL;
    char *endptr = NULL;

    if (!conn) {
        return -ENOTCONN;
    }

    if (!crm_ipc_connect(conn)) {
        crm_perror(LOG_ERR, "Connection to %s failed", target);
        crm_ipc_destroy(conn);
        return -ENOTCONN;
    }

    if(safe_str_eq(target, CRM_SYSTEM_CRMD)) {
        admin_uuid = crm_getpid_s();

        hello = create_hello_message(admin_uuid, "crm_node", "0", "1");
        rc = crm_ipc_send(conn, hello, 0, 0, NULL);

        free_xml(hello);
        if (rc < 0) {
            free(admin_uuid);
            return rc;
        }
    }


    errno = 0;
    n = strtol(node, &endptr, 10);
    if (errno != 0 || endptr == node || *endptr != '\0') {
        /* Argument was not a nodeid */
        n = 0;
        name = strdup(node);
    } else {
        name = get_node_name(n);
    }

    crm_trace("Removing %s aka. %s (%u) from the membership cache", name, node, n);

    if(safe_str_eq(target, T_ATTRD)) {
        cmd = create_xml_node(NULL, __FUNCTION__);

        crm_xml_add(cmd, F_TYPE, T_ATTRD);
        crm_xml_add(cmd, F_ORIG, crm_system_name);

        crm_xml_add(cmd, F_ATTRD_TASK, ATTRD_OP_PEER_REMOVE);
        crm_xml_add(cmd, F_ATTRD_HOST, name);

        if (n) {
            char buffer[64];
            if(snprintf(buffer, 63, "%d", n) > 0) {
                crm_xml_add(cmd, F_ATTRD_HOST_ID, buffer);
            }
        }

    } else {
        cmd = create_request(CRM_OP_RM_NODE_CACHE,
                             NULL, NULL, target, crm_system_name, admin_uuid);
        if (n) {
            crm_xml_set_id(cmd, "%u", n);
        }
        crm_xml_add(cmd, XML_ATTR_UNAME, name);
    }

    rc = crm_ipc_send(conn, cmd, 0, 0, NULL);
    crm_debug("%s peer cache cleanup for %s (%u): %d", target, name, n, rc);

    if (rc > 0) {
        rc = cib_remove_node(n, name);
    }

    if (conn) {
        crm_ipc_close(conn);
        crm_ipc_destroy(conn);
    }
    free(admin_uuid);
    free_xml(cmd);
    free(name);
    return rc > 0 ? 0 : rc;
}

static gint
compare_node_uname(gconstpointer a, gconstpointer b)
{
    const crm_node_t *a_node = a;
    const crm_node_t *b_node = b;
    return strcmp(a_node->uname?a_node->uname:"", b_node->uname?b_node->uname:"");
}

static int
node_mcp_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    xmlNode *msg = string2xml(buffer);

    if (msg) {
        xmlNode *node = NULL;
        GListPtr nodes = NULL;
        GListPtr iter = NULL;
        const char *quorate = crm_element_value(msg, "quorate");

        crm_log_xml_trace(msg, "message");
        if (command == 'q' && quorate != NULL) {
            fprintf(stdout, "%s\n", quorate);
            crm_node_exit(CRM_EX_OK);

        } else if(command == 'q') {
            crm_node_exit(CRM_EX_ERROR);
        }

        for (node = __xml_first_child(msg); node != NULL; node = __xml_next(node)) {
            crm_node_t *peer = calloc(1, sizeof(crm_node_t));

            nodes = g_list_insert_sorted(nodes, peer, compare_node_uname);
            peer->uname = (char*)crm_element_value_copy(node, "uname");
            peer->state = (char*)crm_element_value_copy(node, "state");
            crm_element_value_int(node, "id", (int*)&peer->id);
        }

        for(iter = nodes; iter; iter = iter->next) {
            crm_node_t *peer = iter->data;
            if (command == 'l') {
                fprintf(stdout, "%u %s %s\n",
                        peer->id, peer->uname, (peer->state? peer->state : ""));

            } else if (command == 'p') {
                if(safe_str_eq(peer->state, CRM_NODE_MEMBER)) {
                    fprintf(stdout, "%s ", peer->uname);
                }

            } else if (command == 'i') {
                if(safe_str_eq(peer->state, CRM_NODE_MEMBER)) {
                    fprintf(stdout, "%u ", peer->id);
                }
            }
        }

        g_list_free_full(nodes, free);
        free_xml(msg);

        if (command == 'p') {
            fprintf(stdout, "\n");
        }

        crm_node_exit(CRM_EX_OK);
    }

    return 0;
}

static void
try_pacemaker(int command, enum cluster_type_e stack)
{
    switch (command) {
        case 'R':
            {
                int lpc = 0;
                const char *daemons[] = {
                    CRM_SYSTEM_CRMD,
                    "stonith-ng",
                    T_ATTRD,
                    CRM_SYSTEM_MCP,
                };

                for(lpc = 0; lpc < DIMOF(daemons); lpc++) {
                    if (tools_remove_node_cache(target_uname, daemons[lpc])) {
                        crm_err("Failed to connect to %s to remove node '%s'", daemons[lpc], target_uname);
                        crm_node_exit(CRM_EX_ERROR);
                    }
                }
                crm_node_exit(CRM_EX_OK);
            }
            break;

        case 'i':
        case 'l':
        case 'q':
        case 'p':
            /* Go to pacemakerd */
            {
                crm_ipc_t *ipc = NULL;
                xmlNode *poke = NULL;

                ipc = new_mainloop_for_ipc(CRM_SYSTEM_MCP, node_mcp_dispatch);

                // Sending anything will get us a list of nodes
                poke = create_xml_node(NULL, "poke");
                crm_ipc_send(ipc, poke, 0, 0, NULL);
                free_xml(poke);

                // Handle reply via node_mcp_dispatch()
                run_mainloop_and_exit();
            }
            break;
    }
}

#if SUPPORT_COROSYNC
#  include <corosync/quorum.h>
#  include <corosync/cpg.h>

static void
try_corosync(int command, enum cluster_type_e stack)
{
    int rc = 0;
    int quorate = 0;
    uint32_t quorum_type = 0;
    unsigned int nodeid = 0;
    cpg_handle_t c_handle = 0;
    quorum_handle_t q_handle = 0;

    switch (command) {
        case 'q':
            /* Go direct to the Quorum API */
            rc = quorum_initialize(&q_handle, NULL, &quorum_type);
            if (rc != CS_OK) {
                crm_err("Could not connect to the Quorum API: %d", rc);
                return;
            }

            rc = quorum_getquorate(q_handle, &quorate);
            if (rc != CS_OK) {
                crm_err("Could not obtain the current Quorum API state: %d", rc);
                return;
            }

            printf("%d\n", quorate);
            quorum_finalize(q_handle);
            crm_node_exit(CRM_EX_OK);

        case 'i':
            /* Go direct to the CPG API */
            rc = cpg_initialize(&c_handle, NULL);
            if (rc != CS_OK) {
                crm_err("Could not connect to the Cluster Process Group API: %d", rc);
                return;
            }

            rc = cpg_local_get(c_handle, &nodeid);
            if (rc != CS_OK) {
                crm_err("Could not get local node id from the CPG API");
                return;
            }

            printf("%u\n", nodeid);
            cpg_finalize(c_handle);
            crm_node_exit(CRM_EX_OK);

        default:
            break;
    }
}
#endif

int set_cluster_type(enum cluster_type_e type);

int
main(int argc, char **argv)
{
    int flag = 0;
    int argerr = 0;
    uint32_t nodeid = 0;
    gboolean force_flag = FALSE;
    gboolean dangerous_cmd = FALSE;
    enum cluster_type_e try_stack = pcmk_cluster_unknown;

    int option_index = 0;

    crm_peer_init();
    crm_log_cli_init("crm_node");
    crm_set_options(NULL, "command [options]", long_options,
                    "Tool for displaying low-level node information");

    while (flag >= 0) {
        flag = crm_get_option(argc, argv, &option_index);
        switch (flag) {
            case -1:
                break;
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, CRM_EX_OK);
                break;
            case 'Q':
                // currently unused
                break;
            case 'C':
                set_cluster_type(pcmk_cluster_corosync);
                break;
            case 'f':
                force_flag = TRUE;
                break;
            case 'R':
                command = flag;
                dangerous_cmd = TRUE;
                target_uname = optarg;
                break;
            case 'N':
                command = flag;
                nodeid = crm_parse_int(optarg, NULL);
                break;
            case 'p':
            case 'q':
            case 'i':
            case 'l':
            case 'n':
                command = flag;
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    if (dangerous_cmd && force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        crm_node_exit(CRM_EX_USAGE);
    }

    if (command == 'n') {
        const char *name = getenv("OCF_RESKEY_" CRM_META "_" XML_LRM_ATTR_TARGET);
        if(name == NULL) {
            name = get_local_node_name();
        }
        fprintf(stdout, "%s\n", name);
        crm_node_exit(CRM_EX_OK);

    } else if (command == 'N') {
        fprintf(stdout, "%s\n", get_node_name(nodeid));
        crm_node_exit(CRM_EX_OK);
    }

    try_stack = get_cluster_type();
    crm_debug("Attempting to process -%c command for cluster type: %s", command,
              name_for_cluster_type(try_stack));

#if SUPPORT_COROSYNC
    if (try_stack == pcmk_cluster_corosync) {
        try_corosync(command, try_stack);
    }
#endif

    try_pacemaker(command, try_stack);

    // We only get here if command hasn't been handled
    crm_node_exit(CRM_EX_ERROR);
}

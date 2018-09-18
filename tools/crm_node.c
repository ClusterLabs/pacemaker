/*
 * Copyright 2004-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/mainloop.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crm/attrd.h>

static int command = 0;
static char *pid_s = NULL;
static GMainLoop *mainloop = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",       0, 0, '?', "\tThis text"},
    {"version",    0, 0, '$', "\tVersion information"  },
    {"verbose",    0, 0, 'V', "\tIncrease debug output"},
    {"quiet",      0, 0, 'Q', "\tEssential output only"},

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
#if SUPPORT_COROSYNC
    { "corosync",   0, 0, 'C', NULL, pcmk_option_hidden },
#endif

    // @TODO add timeout option for when IPC replies are needed

    {0, 0, 0, 0}
};

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
send_controller_hello(crm_ipc_t *controller)
{
    xmlNode *hello = NULL;
    int rc;

    pid_s = crm_getpid_s();
    hello = create_hello_message(pid_s, crm_system_name, "1", "0");
    rc = crm_ipc_send(controller, hello, 0, 0, NULL);
    free_xml(hello);
    return (rc < 0)? rc : 0;
}

static int
send_node_info_request(crm_ipc_t *controller, uint32_t nodeid)
{
    xmlNode *ping = NULL;
    int rc;

    ping = create_request(CRM_OP_NODE_INFO, NULL, NULL, CRM_SYSTEM_CRMD,
                          crm_system_name, pid_s);
    if (nodeid > 0) {
        crm_xml_add_int(ping, XML_ATTR_ID, nodeid);
    }
    rc = crm_ipc_send(controller, ping, 0, 0, NULL);
    free_xml(ping);
    return (rc < 0)? rc : 0;
}

static int
dispatch_controller(const char *buffer, ssize_t length, gpointer userdata)
{
    xmlNode *message = string2xml(buffer);
    xmlNode *data = NULL;
    const char *value = NULL;

    if (message == NULL) {
        fprintf(stderr, "error: Could not understand reply from controller\n");
        crm_node_exit(CRM_EX_PROTOCOL);
        return 0;
    }
    crm_log_xml_trace(message, "controller reply");

    exit_code = CRM_EX_PROTOCOL;

    // Validate reply
    value = crm_element_value(message, F_CRM_MSG_TYPE);
    if (safe_str_neq(value, XML_ATTR_RESPONSE)) {
        fprintf(stderr, "error: Message from controller was not a reply\n");
        goto done;
    }
    value = crm_element_value(message, XML_ATTR_REFERENCE);
    if (value == NULL) {
        fprintf(stderr, "error: Controller reply did not specify original message\n");
        goto done;
    }
    data = get_message_xml(message, F_CRM_DATA);
    if (data == NULL) {
        fprintf(stderr, "error: Controller reply did not contain any data\n");
        goto done;
    }

    switch (command) {
        case 'i':
            value = crm_element_value(data, XML_ATTR_ID);
            if (value == NULL) {
                fprintf(stderr, "error: Controller reply did not contain node ID\n");
            } else {
                printf("%s\n", value);
                exit_code = CRM_EX_OK;
            }
            break;

        case 'n':
        case 'N':
            value = crm_element_value(data, XML_ATTR_UNAME);
            if (value == NULL) {
                fprintf(stderr, "Node is not known to cluster\n");
                exit_code = CRM_EX_NOHOST;
            } else {
                printf("%s\n", value);
                exit_code = CRM_EX_OK;
            }
            break;

        case 'q':
            value = crm_element_value(data, XML_ATTR_HAVE_QUORUM);
            if (value == NULL) {
                fprintf(stderr, "error: Controller reply did not contain quorum status\n");
            } else {
                bool quorum = crm_is_true(value);

                printf("%d\n", quorum);
                exit_code = quorum? CRM_EX_OK : CRM_EX_QUORUM;
            }
            break;

        default:
            fprintf(stderr, "internal error: Controller reply not expected\n");
            exit_code = CRM_EX_SOFTWARE;
            break;
    }

done:
    free_xml(message);
    crm_node_exit(exit_code);
    return 0;
}

static void
run_controller_mainloop(uint32_t nodeid)
{
    crm_ipc_t *controller = NULL;
    int rc;

    controller = new_mainloop_for_ipc(CRM_SYSTEM_CRMD, dispatch_controller);

    rc = send_controller_hello(controller);
    if (rc < 0) {
        fprintf(stderr, "error: Could not register with controller: %s\n",
                pcmk_strerror(rc));
        crm_node_exit(crm_errno2exit(rc));
    }

    rc = send_node_info_request(controller, nodeid);
    if (rc < 0) {
        fprintf(stderr, "error: Could not ping controller: %s\n",
                pcmk_strerror(rc));
        crm_node_exit(crm_errno2exit(rc));
    }

    // Run main loop to get controller reply via dispatch_controller()
    run_mainloop_and_exit();
}

static void
print_node_name()
{
    // Check environment first (i.e. when called by resource agent)
    const char *name = getenv("OCF_RESKEY_" CRM_META "_" XML_LRM_ATTR_TARGET);

    if (name != NULL) {
        printf("%s\n", name);
        crm_node_exit(CRM_EX_OK);

    } else {
        // Otherwise ask the controller
        run_controller_mainloop(0);
    }
}

static int
cib_remove_node(long id, const char *name)
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
    if (id > 0) {
        crm_xml_set_id(node, "%ld", id);
        crm_xml_add(node_state, XML_ATTR_ID, ID(node));
    }

    cib = cib_new();
    cib->cmds->signon(cib, crm_system_name, cib_command);

    rc = cib->cmds->remove(cib, XML_CIB_TAG_NODES, node, cib_sync_call);
    if (rc != pcmk_ok) {
        printf("Could not remove %s[%ld] from " XML_CIB_TAG_NODES ": %s",
                name, id, pcmk_strerror(rc));
    }
    rc = cib->cmds->remove(cib, XML_CIB_TAG_STATUS, node_state, cib_sync_call);
    if (rc != pcmk_ok) {
        printf("Could not remove %s[%ld] from " XML_CIB_TAG_STATUS ": %s",
                name, id, pcmk_strerror(rc));
    }

    cib->cmds->signoff(cib);
    cib_delete(cib);
    return rc;
}

static int
tools_remove_node_cache(const char *node_name, long nodeid, const char *target)
{
    int rc = -1;
    crm_ipc_t *conn = crm_ipc_new(target, 0);
    xmlNode *cmd = NULL;

    if (!conn) {
        return -ENOTCONN;
    }

    if (!crm_ipc_connect(conn)) {
        crm_perror(LOG_ERR, "Connection to %s failed", target);
        crm_ipc_destroy(conn);
        return -ENOTCONN;
    }

    if(safe_str_eq(target, CRM_SYSTEM_CRMD)) {
        // The controller requires a hello message before sending a request
        rc = send_controller_hello(conn);
        if (rc < 0) {
            fprintf(stderr, "error: Could not register with controller: %s\n",
                    pcmk_strerror(rc));
            return rc;
        }
    }

    crm_trace("Removing %s[%ld] from the %s membership cache",
              node_name, nodeid, target);

    if(safe_str_eq(target, T_ATTRD)) {
        cmd = create_xml_node(NULL, __FUNCTION__);

        crm_xml_add(cmd, F_TYPE, T_ATTRD);
        crm_xml_add(cmd, F_ORIG, crm_system_name);

        crm_xml_add(cmd, F_ATTRD_TASK, ATTRD_OP_PEER_REMOVE);
        crm_xml_add(cmd, F_ATTRD_HOST, node_name);

        if (nodeid > 0) {
            crm_xml_add_int(cmd, F_ATTRD_HOST_ID, (int) nodeid);
        }

    } else {
        cmd = create_request(CRM_OP_RM_NODE_CACHE,
                             NULL, NULL, target, crm_system_name, pid_s);
        if (nodeid > 0) {
            crm_xml_set_id(cmd, "%ld", nodeid);
        }
        crm_xml_add(cmd, XML_ATTR_UNAME, node_name);
    }

    rc = crm_ipc_send(conn, cmd, 0, 0, NULL);
    crm_debug("%s peer cache cleanup for %s (%ld): %d",
              target, node_name, nodeid, rc);

    if (rc > 0) {
        rc = cib_remove_node(nodeid, node_name);
    }

    if (conn) {
        crm_ipc_close(conn);
        crm_ipc_destroy(conn);
    }
    free_xml(cmd);
    return rc > 0 ? 0 : rc;
}

static void
remove_node(const char *target_uname)
{
    int d = 0;
    long nodeid = 0;
    const char *node_name = NULL;
    char *endptr = NULL;
    const char *daemons[] = {
        CRM_SYSTEM_CRMD,
        "stonith-ng",
        T_ATTRD,
        CRM_SYSTEM_MCP,
    };

    // Check whether node was specified by name or numeric ID
    errno = 0;
    nodeid = strtol(target_uname, &endptr, 10);
    if ((errno != 0) || (endptr == target_uname) || (*endptr != '\0')
        || (nodeid <= 0)) {
        // It's not a positive integer, so assume it's a node name
        nodeid = 0;
        node_name = target_uname;
    }

    for (d = 0; d < DIMOF(daemons); d++) {
        if (tools_remove_node_cache(node_name, nodeid, daemons[d])) {
            crm_err("Failed to connect to %s to remove node '%s'",
                    daemons[d], target_uname);
            crm_node_exit(CRM_EX_ERROR);
            return;
        }
    }
    crm_node_exit(CRM_EX_OK);
}

static gint
compare_node_xml(gconstpointer a, gconstpointer b)
{
    const char *a_name = crm_element_value((xmlNode*) a, "uname");
    const char *b_name = crm_element_value((xmlNode*) b, "uname");

    return strcmp((a_name? a_name : ""), (b_name? b_name : ""));
}

static int
node_mcp_dispatch(const char *buffer, ssize_t length, gpointer userdata)
{
    GList *nodes = NULL;
    xmlNode *node = NULL;
    xmlNode *msg = string2xml(buffer);
    const char *uname;
    const char *state;

    if (msg == NULL) {
        fprintf(stderr, "error: Could not understand pacemakerd response\n");
        crm_node_exit(CRM_EX_PROTOCOL);
        return 0;
    }

    crm_log_xml_trace(msg, "message");

    for (node = __xml_first_child(msg); node != NULL; node = __xml_next(node)) {
        nodes = g_list_insert_sorted(nodes, node, compare_node_xml);
    }

    for (GList *iter = nodes; iter; iter = iter->next) {
        node = (xmlNode*) iter->data;
        uname = crm_element_value(node, "uname");
        state = crm_element_value(node, "state");

        if (command == 'l') {
            int id = 0;

            crm_element_value_int(node, "id", &id);
            printf("%d %s %s\n", id, (uname? uname : ""), (state? state : ""));

        // This is CRM_NODE_MEMBER but we don't want to include cluster header
        } else if ((command == 'p') && safe_str_eq(state, "member")) {
            printf("%s ", (uname? uname : ""));
        }
    }
    if (command == 'p') {
        fprintf(stdout, "\n");
    }

    free_xml(msg);
    crm_node_exit(CRM_EX_OK);
    return 0;
}

static void
run_pacemakerd_mainloop()
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

int
main(int argc, char **argv)
{
    int flag = 0;
    int argerr = 0;
    uint32_t nodeid = 0;
    gboolean force_flag = FALSE;
    gboolean dangerous_cmd = FALSE;
    int option_index = 0;
    const char *target_uname = NULL;

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
                return crm_help(flag, CRM_EX_OK);
                break;
            case 'Q':
                // currently unused
                break;
            case 'C':
                // unused and deprecated
                break;
            case 'f':
                force_flag = TRUE;
                break;
            case 'R':
                command = flag;
                dangerous_cmd = TRUE;
                target_uname = optarg;
                if (optarg == NULL) {
                    ++argerr;
                }
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
        return crm_help('?', CRM_EX_USAGE);
    }

    if (dangerous_cmd && force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        crm_node_exit(CRM_EX_USAGE);
    }

    switch (command) {
        case 'n':
            print_node_name();
            break;
        case 'R':
            remove_node(target_uname);
            break;
        case 'i':
        case 'q':
        case 'N':
            run_controller_mainloop(nodeid);
            break;
        case 'l':
        case 'p':
            run_pacemakerd_mainloop();
            break;
        default:
            break;
    }

    fprintf(stderr, "error: Must specify a command option\n");
    crm_node_exit(CRM_EX_USAGE);
    return CRM_EX_USAGE;
}

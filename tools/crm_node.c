/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
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
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/mainloop.h>
#include <crm/msg_xml.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/attrd_internal.h>

#define SUMMARY "crm_node - Tool for displaying low-level node information"

struct {
    gboolean corosync;
    gboolean dangerous_cmd;
    gboolean force_flag;
    char command;
    int nodeid;
    char *target_uname;
} options = {
    .command = '\0',
    .force_flag = FALSE
};

gboolean command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean name_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean remove_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GMainLoop *mainloop = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

#define INDENT "                           "

static GOptionEntry command_entries[] = {
    { "cluster-id", 'i', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display this node's cluster id",
      NULL },
    { "list", 'l', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display all known members (past and present) of this cluster",
      NULL },
    { "name", 'n', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the name used by the cluster for this node",
      NULL },
    { "partition", 'p', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the members of this partition",
      NULL },
    { "quorum", 'q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display a 1 if our partition has quorum, 0 if not",
      NULL },
    { "name-for-id", 'N', 0, G_OPTION_ARG_CALLBACK, name_cb,
      "Display the name used by the cluster for the node with the specified ID",
      "ID" },
    { "remove", 'R', 0, G_OPTION_ARG_CALLBACK, remove_cb,
      "(Advanced) Remove the (stopped) node with the specified name from Pacemaker's\n"
      INDENT "configuration and caches (the node must already have been removed from\n"
      INDENT "the underlying cluster stack configuration",
      "NAME" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "force", 'f', 0, G_OPTION_ARG_NONE, &options.force_flag,
      NULL,
      NULL },
#if SUPPORT_COROSYNC
    /* Unused and deprecated */
    { "corosync", 'C', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.corosync,
      NULL,
      NULL },
#endif

    // @TODO add timeout option for when IPC replies are needed

    { NULL }
};

gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_eq("-i", option_name, pcmk__str_casei) || pcmk__str_eq("--cluster-id", option_name, pcmk__str_casei)) {
        options.command = 'i';
    } else if (pcmk__str_eq("-l", option_name, pcmk__str_casei) || pcmk__str_eq("--list", option_name, pcmk__str_casei)) {
        options.command = 'l';
    } else if (pcmk__str_eq("-n", option_name, pcmk__str_casei) || pcmk__str_eq("--name", option_name, pcmk__str_casei)) {
        options.command = 'n';
    } else if (pcmk__str_eq("-p", option_name, pcmk__str_casei) || pcmk__str_eq("--partition", option_name, pcmk__str_casei)) {
        options.command = 'p';
    } else if (pcmk__str_eq("-q", option_name, pcmk__str_casei) || pcmk__str_eq("--quorum", option_name, pcmk__str_casei)) {
        options.command = 'q';
    } else {
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "Unknown param passed to command_cb: %s\n", option_name);
        return FALSE;
    }

    return TRUE;
}

gboolean
name_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.command = 'N';
    pcmk__scan_min_int(optarg, &(options.nodeid), 0);
    return TRUE;
}

gboolean
remove_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (optarg == NULL) {
        crm_err("-R option requires an argument");
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_INVALID_PARAM, "-R option requires an argument");
        return FALSE;
    }

    options.command = 'R';
    options.dangerous_cmd = TRUE;
    options.target_uname = strdup(optarg);
    return TRUE;
}

static gint
sort_node(gconstpointer a, gconstpointer b)
{
    const pcmk_controld_api_node_t *node_a = a;
    const pcmk_controld_api_node_t *node_b = b;

    return pcmk__numeric_strcasecmp((node_a->uname? node_a->uname : ""),
                                    (node_b->uname? node_b->uname : ""));
}

static void
controller_event_cb(pcmk_ipc_api_t *controld_api,
                    enum pcmk_ipc_event event_type, crm_exit_t status,
                    void *event_data, void *user_data)
{
    pcmk_controld_api_reply_t *reply = event_data;

    switch (event_type) {
        case pcmk_ipc_event_disconnect:
            if (exit_code == CRM_EX_DISCONNECT) { // Unexpected
                fprintf(stderr, "error: Lost connection to controller\n");
            }
            goto done;
            break;

        case pcmk_ipc_event_reply:
            break;

        default:
            return;
    }

    if (status != CRM_EX_OK) {
        fprintf(stderr, "error: Bad reply from controller: %s\n",
                crm_exit_str(status));
        goto done;
    }

    // Parse desired info from reply and display to user
    switch (options.command) {
        case 'i':
            if (reply->reply_type != pcmk_controld_reply_info) {
                fprintf(stderr,
                        "error: Unknown reply type %d from controller\n",
                        reply->reply_type);
                goto done;
            }
            if (reply->data.node_info.id == 0) {
                fprintf(stderr,
                        "error: Controller reply did not contain node ID\n");
                exit_code = CRM_EX_PROTOCOL;
                goto done;
            }
            printf("%d\n", reply->data.node_info.id);
            break;

        case 'n':
        case 'N':
            if (reply->reply_type != pcmk_controld_reply_info) {
                fprintf(stderr,
                        "error: Unknown reply type %d from controller\n",
                        reply->reply_type);
                goto done;
            }
            if (reply->data.node_info.uname == NULL) {
                fprintf(stderr, "Node is not known to cluster\n");
                exit_code = CRM_EX_NOHOST;
                goto done;
            }
            printf("%s\n", reply->data.node_info.uname);
            break;

        case 'q':
            if (reply->reply_type != pcmk_controld_reply_info) {
                fprintf(stderr,
                        "error: Unknown reply type %d from controller\n",
                        reply->reply_type);
                goto done;
            }
            printf("%d\n", reply->data.node_info.have_quorum);
            if (!(reply->data.node_info.have_quorum)) {
                exit_code = CRM_EX_QUORUM;
                goto done;
            }
            break;

        case 'l':
        case 'p':
            if (reply->reply_type != pcmk_controld_reply_nodes) {
                fprintf(stderr,
                        "error: Unknown reply type %d from controller\n",
                        reply->reply_type);
                goto done;
            }
            reply->data.nodes = g_list_sort(reply->data.nodes, sort_node);
            for (GList *node_iter = reply->data.nodes;
                 node_iter != NULL; node_iter = node_iter->next) {

                pcmk_controld_api_node_t *node = node_iter->data;
                const char *uname = (node->uname? node->uname : "");
                const char *state = (node->state? node->state : "");

                if (options.command == 'l') {
                    printf("%lu %s %s\n",
                           (unsigned long) node->id, uname, state);

                // i.e. CRM_NODE_MEMBER, but we don't want to include cluster.h
                } else if (!strcmp(state, "member")) {
                    printf("%s ", uname);
                }
            }
            if (options.command == 'p') {
                printf("\n");
            }
            break;

        default:
            fprintf(stderr, "internal error: Controller reply not expected\n");
            exit_code = CRM_EX_SOFTWARE;
            goto done;
    }

    // Success
    exit_code = CRM_EX_OK;
done:
    pcmk_disconnect_ipc(controld_api);
    pcmk_quit_main_loop(mainloop, 10);
}

static void
run_controller_mainloop(uint32_t nodeid, bool list_nodes)
{
    pcmk_ipc_api_t *controld_api = NULL;
    int rc;

    // Set disconnect exit code to handle unexpected disconnects
    exit_code = CRM_EX_DISCONNECT;

    // Create controller IPC object
    rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to controller: %s\n",
                pcmk_rc_str(rc));
        return;
    }
    pcmk_register_ipc_callback(controld_api, controller_event_cb, NULL);

    // Connect to controller
    rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_main);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to controller: %s\n",
                pcmk_rc_str(rc));
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    if (list_nodes) {
        rc = pcmk_controld_api_list_nodes(controld_api);
    } else {
        rc = pcmk_controld_api_node_info(controld_api, nodeid);
    }
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not ping controller: %s\n",
                pcmk_rc_str(rc));
        pcmk_disconnect_ipc(controld_api);
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    // Run main loop to get controller reply via controller_event_cb()
    mainloop = g_main_loop_new(NULL, FALSE);
    g_main_loop_run(mainloop);
    g_main_loop_unref(mainloop);
    mainloop = NULL;
    pcmk_free_ipc_api(controld_api);
}

static void
print_node_name(void)
{
    // Check environment first (i.e. when called by resource agent)
    const char *name = getenv("OCF_RESKEY_" CRM_META "_" XML_LRM_ATTR_TARGET);

    if (name != NULL) {
        printf("%s\n", name);
        exit_code = CRM_EX_OK;
        return;

    } else {
        // Otherwise ask the controller
        run_controller_mainloop(0, false);
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

    cib__clean_up_connection(&cib);
    return rc;
}

static int
controller_remove_node(const char *node_name, long nodeid)
{
    pcmk_ipc_api_t *controld_api = NULL;
    int rc;

    // Create controller IPC object
    rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to controller: %s\n",
                pcmk_rc_str(rc));
        return ENOTCONN;
    }

    // Connect to controller (without main loop)
    rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_sync);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Could not connect to controller: %s\n",
                pcmk_rc_str(rc));
        pcmk_free_ipc_api(controld_api);
        return rc;
    }

    rc = pcmk_ipc_purge_node(controld_api, node_name, nodeid);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr,
                "error: Could not clear node from controller's cache: %s\n",
                pcmk_rc_str(rc));
    }

    pcmk_free_ipc_api(controld_api);
    return pcmk_rc_ok;
}

static int
tools_remove_node_cache(const char *node_name, long nodeid, const char *target)
{
    int rc = -1;
    crm_ipc_t *conn = NULL;
    xmlNode *cmd = NULL;

    conn = crm_ipc_new(target, 0);
    if (!conn) {
        return -ENOTCONN;
    }
    if (!crm_ipc_connect(conn)) {
        crm_perror(LOG_ERR, "Connection to %s failed", target);
        crm_ipc_destroy(conn);
        return -ENOTCONN;
    }

    crm_trace("Removing %s[%ld] from the %s membership cache",
              node_name, nodeid, target);

    if(pcmk__str_eq(target, T_ATTRD, pcmk__str_casei)) {
        cmd = create_xml_node(NULL, __func__);

        crm_xml_add(cmd, F_TYPE, T_ATTRD);
        crm_xml_add(cmd, F_ORIG, crm_system_name);

        crm_xml_add(cmd, PCMK__XA_TASK, PCMK__ATTRD_CMD_PEER_REMOVE);
        crm_xml_add(cmd, PCMK__XA_ATTR_NODE_NAME, node_name);

        if (nodeid > 0) {
            crm_xml_add_int(cmd, PCMK__XA_ATTR_NODE_ID, (int) nodeid);
        }

    } else { // Fencer or pacemakerd
        cmd = create_request(CRM_OP_RM_NODE_CACHE, NULL, NULL, target,
                             crm_system_name, NULL);
        if (nodeid > 0) {
            crm_xml_set_id(cmd, "%ld", nodeid);
        }
        crm_xml_add(cmd, XML_ATTR_UNAME, node_name);
    }

    rc = crm_ipc_send(conn, cmd, 0, 0, NULL);
    crm_debug("%s peer cache cleanup for %s (%ld): %d",
              target, node_name, nodeid, rc);

    if (rc > 0) {
        // @TODO Should this be done just once after all the rest?
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
    int rc;
    int d = 0;
    long nodeid = 0;
    const char *node_name = NULL;
    char *endptr = NULL;
    const char *daemons[] = {
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

    rc = controller_remove_node(node_name, nodeid);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        return;
    }

    for (d = 0; d < PCMK__NELEM(daemons); d++) {
        if (tools_remove_node_cache(node_name, nodeid, daemons[d])) {
            crm_err("Failed to connect to %s to remove node '%s'",
                    daemons[d], target_uname);
            exit_code = CRM_EX_ERROR;
            return;
        }
    }
    exit_code = CRM_EX_OK;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup *group) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'Q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Be less descriptive in output.",
          NULL },

        { NULL }
    };

    context = pcmk__build_arg_context(args, NULL, &group, NULL);

    /* Add the -q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command help", command_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "NR");
    GOptionContext *context = build_arg_context(args, output_group);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_node", args->verbosity);

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When crm_node is converted to use formatted output, this can go. */
        pcmk__cli_help('v', CRM_EX_OK);
    }

    if (options.command == 0) {
        char *help = g_option_context_get_help(context, TRUE, NULL);

        fprintf(stderr, "%s", help);
        g_free(help);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.dangerous_cmd && options.force_flag == FALSE) {
        fprintf(stderr, "The supplied command is considered dangerous."
                "  To prevent accidental destruction of the cluster,"
                " the --force flag is required in order to proceed.\n");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    switch (options.command) {
        case 'n':
            print_node_name();
            break;
        case 'R':
            remove_node(options.target_uname);
            break;
        case 'i':
        case 'q':
        case 'N':
            run_controller_mainloop(options.nodeid, false);
            break;
        case 'l':
        case 'p':
            run_controller_mainloop(0, true);
            break;
        default:
            break;
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(error, NULL);
    return crm_exit(exit_code);
}

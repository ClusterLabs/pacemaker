/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>             // atoi()

#include <glib.h>               // gboolean, GMainLoop, etc.
#include <libxml/tree.h>        // xmlNode

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc_controld.h>
#include <crm/common/mainloop.h>

#define DEFAULT_MESSAGE_TIMEOUT_MS 30000

static guint message_timer_id = 0;
static guint message_timeout_ms = DEFAULT_MESSAGE_TIMEOUT_MS;
static GMainLoop *mainloop = NULL;

bool do_work(pcmk_ipc_api_t *api);
void do_find_node_list(xmlNode *xml_node);
gboolean admin_message_timeout(gpointer data);

static enum {
    cmd_none,
    cmd_shutdown,
    cmd_health,
    cmd_elect_dc,
    cmd_whois_dc,
    cmd_list_nodes,
} command = cmd_none;

static gboolean BE_VERBOSE = FALSE;
static gboolean BASH_EXPORT = FALSE;
static gboolean BE_SILENT = FALSE;
static char *dest_node = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\tThis text", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\tVersion information", pcmk__option_default
    },
    {
        "quiet", no_argument, NULL, 'q',
        "\tDisplay only the essential query information", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\tIncrease debug output", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nCommands:", pcmk__option_default
    },
    /* daemon options */
    {
        "status", required_argument, NULL, 'S',
        "Display the status of the specified node.", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\n\tResult is state of node's internal finite state machine, which "
            "can be useful for debugging\n",
        pcmk__option_default
    },
    {
        "dc_lookup", no_argument, NULL, 'D',
        "Display the uname of the node co-ordinating the cluster.",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\n\tThis is an internal detail rarely useful to administrators "
            "except when deciding on which node to examine the logs.\n",
        pcmk__option_default
    },
    {
        "nodes", no_argument, NULL, 'N',
        "\tDisplay the uname of all member nodes", pcmk__option_default
    },
    {
        "election", no_argument, NULL, 'E',
        "(Advanced) Start an election for the cluster co-ordinator",
        pcmk__option_default
    },
    {
        "kill", required_argument, NULL, 'K',
        "(Advanced) Stop controller (not rest of cluster stack) on "
            "specified node", pcmk__option_default
    },
    {
        "health", no_argument, NULL, 'H',
        NULL, pcmk__option_hidden
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdditional Options:", pcmk__option_default
    },
    {
        XML_ATTR_TIMEOUT, required_argument, NULL, 't',
        "Time (in milliseconds) to wait before declaring the operation failed",
        pcmk__option_default
    },
    {
        "bash-export", no_argument, NULL, 'B',
        "Display nodes as shell commands of the form 'export uname=uuid' "
            "(valid with -N/--nodes)'\n",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "Notes:", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "The -K and -E commands do not work and may be removed in a future "
            "version.",
        pcmk__option_default
    },
    { 0, 0, 0, 0 }
};

static void
quit_main_loop(crm_exit_t ec)
{
    exit_code = ec;
    if (mainloop != NULL) {
        GMainLoop *mloop = mainloop;

        mainloop = NULL; // Don't re-enter this block
        pcmk_quit_main_loop(mloop, 10);
        g_main_loop_unref(mloop);
    }
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

    if (message_timer_id != 0) {
        g_source_remove(message_timer_id);
        message_timer_id = 0;
    }

    if (status != CRM_EX_OK) {
        fprintf(stderr, "error: Bad reply from controller: %s",
                crm_exit_str(status));
        exit_code = status;
        goto done;
    }

    if (reply->reply_type != pcmk_controld_reply_ping) {
        fprintf(stderr, "error: Unknown reply type %d from controller\n",
                reply->reply_type);
        goto done;
    }

    // Parse desired information from reply
    switch (command) {
        case cmd_health:
            printf("Status of %s@%s: %s (%s)\n",
                   reply->data.ping.sys_from,
                   reply->host_from,
                   reply->data.ping.fsa_state,
                   reply->data.ping.result);
            if (BE_SILENT && (reply->data.ping.fsa_state != NULL)) {
                fprintf(stderr, "%s\n", reply->data.ping.fsa_state);
            }
            exit_code = CRM_EX_OK;
            break;

        case cmd_whois_dc:
            printf("Designated Controller is: %s\n", reply->host_from);
            if (BE_SILENT && (reply->host_from != NULL)) {
                fprintf(stderr, "%s\n", reply->host_from);
            }
            exit_code = CRM_EX_OK;
            break;

        default: // Not really possible here
            exit_code = CRM_EX_SOFTWARE;
            break;
    }

done:
    pcmk_disconnect_ipc(controld_api);
    quit_main_loop(exit_code);
}

// \return Standard Pacemaker return code
static int
list_nodes()
{
    cib_t *the_cib = cib_new();
    xmlNode *output = NULL;
    int rc;

    if (the_cib == NULL) {
        return ENOMEM;
    }
    rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        return pcmk_legacy2rc(rc);
    }

    rc = the_cib->cmds->query(the_cib, NULL, &output,
                              cib_scope_local | cib_sync_call);
    if (rc == pcmk_ok) {
        do_find_node_list(output);
        free_xml(output);
    }
    the_cib->cmds->signoff(the_cib);
    return pcmk_legacy2rc(rc);
}

int
main(int argc, char **argv)
{
    int option_index = 0;
    int argerr = 0;
    int flag;
    int rc;
    pcmk_ipc_api_t *controld_api = NULL;
    bool need_controld_api = true;

    crm_log_cli_init("crmadmin");
    pcmk__set_cli_options(NULL, "<command> [options]", long_options,
                          "query and manage the Pacemaker controller");
    if (argc < 2) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, NULL);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                BE_VERBOSE = TRUE;
                crm_bump_log_level(argc, argv);
                break;
            case 't':
                message_timeout_ms = (guint) atoi(optarg);
                if (message_timeout_ms < 1) {
                    message_timeout_ms = DEFAULT_MESSAGE_TIMEOUT_MS;
                }
                break;

            case '$':
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
                break;
            case 'D':
                command = cmd_whois_dc;
                break;
            case 'B':
                BASH_EXPORT = TRUE;
                break;
            case 'K':
                command = cmd_shutdown;
                crm_trace("Option %c => %s", flag, optarg);
                if (dest_node != NULL) {
                    free(dest_node);
                }
                dest_node = strdup(optarg);
                break;
            case 'q':
                BE_SILENT = TRUE;
                break;
            case 'S':
                command = cmd_health;
                crm_trace("Option %c => %s", flag, optarg);
                if (dest_node != NULL) {
                    free(dest_node);
                }
                dest_node = strdup(optarg);
                break;
            case 'E':
                command = cmd_elect_dc;
                break;
            case 'N':
                command = cmd_list_nodes;
                need_controld_api = false;
                break;
            case 'H':
                fprintf(stderr, "Cluster-wide health option not supported\n");
                ++argerr;
                break;
            default:
                printf("Argument code 0%o (%c) is not (?yet?) supported\n", flag, flag);
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

    if (command == cmd_none) {
        fprintf(stderr, "error: Must specify a command option\n\n");
        ++argerr;
    }

    if (argerr) {
        pcmk__cli_help('?', CRM_EX_USAGE);
    }

    // Connect to the controller if needed
    if (need_controld_api) {
        rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
        if (controld_api == NULL) {
            fprintf(stderr, "error: Could not connect to controller: %s\n",
                    pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
        pcmk_register_ipc_callback(controld_api, controller_event_cb, NULL);
        rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_main);
        if (rc != pcmk_rc_ok) {
            fprintf(stderr, "error: Could not connect to controller: %s\n",
                    pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
    }

    if (do_work(controld_api)) {
        // A reply is needed from controller, so run main loop to get it
        exit_code = CRM_EX_DISCONNECT; // For unexpected disconnects
        mainloop = g_main_loop_new(NULL, FALSE);
        message_timer_id = g_timeout_add(message_timeout_ms,
                                         admin_message_timeout, NULL);
        g_main_loop_run(mainloop);
    }

done:
    if (controld_api != NULL) {
        pcmk_ipc_api_t *capi = controld_api;

        controld_api = NULL; // Ensure we can't free this twice
        pcmk_free_ipc_api(capi);
    }
    if (mainloop != NULL) {
        g_main_loop_unref(mainloop);
        mainloop = NULL;
    }
    return crm_exit(exit_code);
}

// \return True if reply from controller is needed
bool
do_work(pcmk_ipc_api_t *controld_api)
{
    bool need_reply = false;
    int rc = pcmk_rc_ok;

    switch (command) {
        case cmd_shutdown:
            rc = pcmk_controld_api_shutdown(controld_api, dest_node);
            break;

        case cmd_health:    // dest_node != NULL
        case cmd_whois_dc:  // dest_node == NULL
            rc = pcmk_controld_api_ping(controld_api, dest_node);
            need_reply = true;
            break;

        case cmd_elect_dc:
            rc = pcmk_controld_api_start_election(controld_api);
            break;

        case cmd_list_nodes:
            rc = list_nodes();
            break;

        case cmd_none: // not actually possible here
            break;
    }
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "error: Command failed: %s", pcmk_rc_str(rc));
        exit_code = pcmk_rc2exitc(rc);
    }
    return need_reply;
}

gboolean
admin_message_timeout(gpointer data)
{
    fprintf(stderr,
            "error: No reply received from controller before timeout (%dms)\n",
            message_timeout_ms);
    message_timer_id = 0;
    quit_main_loop(CRM_EX_TIMEOUT);
    return FALSE; // Tells glib to remove source
}

void
do_find_node_list(xmlNode * xml_node)
{
    int found = 0;
    xmlNode *node = NULL;
    xmlNode *nodes = get_object_root(XML_CIB_TAG_NODES, xml_node);

    for (node = first_named_child(nodes, XML_CIB_TAG_NODE); node != NULL;
         node = crm_next_same_xml(node)) {

        if (BASH_EXPORT) {
            printf("export %s=%s\n",
                   crm_element_value(node, XML_ATTR_UNAME),
                   crm_element_value(node, XML_ATTR_ID));
        } else {
            const char *node_type = crm_element_value(node, XML_ATTR_TYPE);

            if (node_type == NULL) {
                node_type = "member";
            }
            printf("%s node: %s (%s)\n", node_type,
                   crm_element_value(node, XML_ATTR_UNAME),
                   crm_element_value(node, XML_ATTR_ID));
        }
        found++;
    }
    // @TODO List Pacemaker Remote nodes that don't have a <node> entry

    if (found == 0) {
        printf("No nodes configured\n");
    }
}

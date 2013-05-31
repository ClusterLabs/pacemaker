
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
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <crm/common/mainloop.h>

#include <crm/cib.h>

int message_timer_id = -1;
int message_timeout_ms = 30 * 1000;

GMainLoop *mainloop = NULL;
crm_ipc_t *crmd_channel = NULL;
char *admin_uuid = NULL;

void usage(const char *cmd, int exit_status);
gboolean do_init(void);
int do_work(void);
void crmadmin_ipc_connection_destroy(gpointer user_data);

int admin_msg_callback(const char *buffer, ssize_t length, gpointer userdata);
char *pluralSection(const char *a_section);
xmlNode *handleCibMod(void);
int do_find_node_list(xmlNode * xml_node);
gboolean admin_message_timeout(gpointer data);
gboolean is_node_online(xmlNode * node_state);

enum debug {
    debug_none,
    debug_dec,
    debug_inc
};

gboolean BE_VERBOSE = FALSE;
int expected_responses = 1;

gboolean BASH_EXPORT = FALSE;
gboolean DO_HEALTH = FALSE;
gboolean DO_RESET = FALSE;
gboolean DO_RESOURCE = FALSE;
gboolean DO_ELECT_DC = FALSE;
gboolean DO_WHOIS_DC = FALSE;
gboolean DO_NODE_LIST = FALSE;
gboolean BE_SILENT = FALSE;
gboolean DO_RESOURCE_LIST = FALSE;
enum debug DO_DEBUG = debug_none;
const char *crmd_operation = NULL;

xmlNode *msg_options = NULL;

const char *standby_on_off = "on";
const char *admin_verbose = XML_BOOLEAN_FALSE;
char *id = NULL;
char *disconnect = NULL;
char *dest_node = NULL;
char *rsc_name = NULL;
char *crm_option = NULL;

int operation_status = 0;
const char *sys_to = NULL;

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {"help",    0, 0, '?', "\tThis text"},
    {"version", 0, 0, '$', "\tVersion information"  },
    {"quiet",   0, 0, 'q', "\tDisplay only the essential query information"},
    {"verbose", 0, 0, 'V', "\tIncrease debug output"},
    
    {"-spacer-",	1, 0, '-', "\nCommands:"},
    /* daemon options */
    {"debug_inc", 1, 0, 'i', "Increase the crmd's debug level on the specified host"},
    {"debug_dec", 1, 0, 'd', "Decrease the crmd's debug level on the specified host"},
    {"status",    1, 0, 'S', "Display the status of the specified node." },
    {"-spacer-",  1, 0, '-', "\n\tResult is the node's internal FSM state which can be useful for debugging\n"},
    {"dc_lookup", 0, 0, 'D', "Display the uname of the node co-ordinating the cluster."},
    {"-spacer-",  1, 0, '-', "\n\tThis is an internal detail and is rarely useful to administrators except when deciding on which node to examine the logs.\n"},
    {"nodes",     0, 0, 'N', "\tDisplay the uname of all member nodes"},
    {"election",  0, 0, 'E', "(Advanced) Start an election for the cluster co-ordinator"},
    {"kill",      1, 0, 'K', "(Advanced) Shut down the crmd (not the rest of the clusterstack ) on the specified node"},
    {"health",    0, 0, 'H', NULL, 1},
    
    {"-spacer-",	1, 0, '-', "\nAdditional Options:"},
    {XML_ATTR_TIMEOUT, 1, 0, 't', "Time (in milliseconds) to wait before declaring the operation failed"},
    {"bash-export", 0, 0, 'B', "Create Bash export entries of the form 'export uname=uuid'\n"},

    {"-spacer-",  1, 0, '-', "Notes:"},
    {"-spacer-",  1, 0, '-', " The -i,-d,-K and -E commands are rarely used and may be removed in future versions."},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    int option_index = 0;
    int argerr = 0;
    int flag;

    crm_log_cli_init("crmadmin");
    crm_set_options(NULL, "command [options]", long_options,
                    "Development tool for performing some crmd-specific commands."
                    "\n  Likely to be replaced by crm_node in the future");
    if (argc < 2) {
        crm_help('?', EX_USAGE);
    }

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1)
            break;

        switch (flag) {
            case 'V':
                BE_VERBOSE = TRUE;
                admin_verbose = XML_BOOLEAN_TRUE;
                crm_bump_log_level(argc, argv);
                break;
            case 't':
                message_timeout_ms = atoi(optarg);
                if (message_timeout_ms < 1) {
                    message_timeout_ms = 30 * 1000;
                }
                break;

            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'D':
                DO_WHOIS_DC = TRUE;
                break;
            case 'B':
                BASH_EXPORT = TRUE;
                break;
            case 'K':
                DO_RESET = TRUE;
                crm_trace("Option %c => %s", flag, optarg);
                dest_node = strdup(optarg);
                crmd_operation = CRM_OP_LOCAL_SHUTDOWN;
                break;
            case 'q':
                BE_SILENT = TRUE;
                break;
            case 'i':
                DO_DEBUG = debug_inc;
                crm_trace("Option %c => %s", flag, optarg);
                dest_node = strdup(optarg);
                break;
            case 'd':
                DO_DEBUG = debug_dec;
                crm_trace("Option %c => %s", flag, optarg);
                dest_node = strdup(optarg);
                break;
            case 'S':
                DO_HEALTH = TRUE;
                crm_trace("Option %c => %s", flag, optarg);
                dest_node = strdup(optarg);
                break;
            case 'E':
                DO_ELECT_DC = TRUE;
                break;
            case 'N':
                DO_NODE_LIST = TRUE;
                break;
            case 'H':
                DO_HEALTH = TRUE;
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

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    if (do_init()) {
        int res = 0;

        res = do_work();
        if (res > 0) {
            /* wait for the reply by creating a mainloop and running it until
             * the callbacks are invoked...
             */
            mainloop = g_main_new(FALSE);
            crm_trace("Waiting for %d replies from the local CRM", expected_responses);

            message_timer_id = g_timeout_add(message_timeout_ms, admin_message_timeout, NULL);

            g_main_run(mainloop);

        } else if (res < 0) {
            crm_err("No message to send");
            operation_status = -1;
        }
    } else {
        crm_warn("Init failed, could not perform requested operations");
        operation_status = -2;
    }

    crm_trace("%s exiting normally", crm_system_name);
    return operation_status;
}

int
do_work(void)
{
    int ret = 1;

    /* construct the request */
    xmlNode *msg_data = NULL;
    gboolean all_is_good = TRUE;

    msg_options = create_xml_node(NULL, XML_TAG_OPTIONS);
    crm_xml_add(msg_options, XML_ATTR_VERBOSE, admin_verbose);
    crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

    if (DO_HEALTH == TRUE) {
        crm_trace("Querying the system");

        sys_to = CRM_SYSTEM_DC;

        if (dest_node != NULL) {
            sys_to = CRM_SYSTEM_CRMD;
            crmd_operation = CRM_OP_PING;

            if (BE_VERBOSE) {
                expected_responses = 1;
            }

            crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

        } else {
            crm_info("Cluster-wide health not available yet");
            all_is_good = FALSE;
        }

    } else if (DO_ELECT_DC) {
        /* tell the local node to initiate an election */

        dest_node = NULL;
        sys_to = CRM_SYSTEM_CRMD;
        crmd_operation = CRM_OP_VOTE;

        crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");
        ret = 0;                /* no return message */

    } else if (DO_WHOIS_DC) {
        dest_node = NULL;
        sys_to = CRM_SYSTEM_DC;
        crmd_operation = CRM_OP_PING;
        crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

    } else if (DO_NODE_LIST) {

        cib_t *the_cib = cib_new();
        xmlNode *output = NULL;

        int rc = the_cib->cmds->signon(the_cib, crm_system_name, cib_command);

        if (rc != pcmk_ok) {
            return -1;
        }

        output = get_cib_copy(the_cib);
        do_find_node_list(output);

        free_xml(output);
        the_cib->cmds->signoff(the_cib);
        crm_exit(rc);

    } else if (DO_RESET) {
        /* tell dest_node to initiate the shutdown proceedure
         *
         * if dest_node is NULL, the request will be sent to the
         *   local node
         */
        sys_to = CRM_SYSTEM_CRMD;
        crm_xml_add(msg_options, XML_ATTR_TIMEOUT, "0");

        ret = 0;                /* no return message */

    } else if (DO_DEBUG == debug_inc) {
        /* tell dest_node to increase its debug level
         *
         * if dest_node is NULL, the request will be sent to the
         *   local node
         */
        sys_to = CRM_SYSTEM_CRMD;
        crmd_operation = CRM_OP_DEBUG_UP;

        ret = 0;                /* no return message */

    } else if (DO_DEBUG == debug_dec) {
        /* tell dest_node to increase its debug level
         *
         * if dest_node is NULL, the request will be sent to the
         *   local node
         */
        sys_to = CRM_SYSTEM_CRMD;
        crmd_operation = CRM_OP_DEBUG_DOWN;

        ret = 0;                /* no return message */

    } else {
        crm_err("Unknown options");
        all_is_good = FALSE;
    }

    if (all_is_good == FALSE) {
        crm_err("Creation of request failed.  No message to send");
        return -1;
    }

/* send it */
    if (crmd_channel == NULL) {
        crm_err("The IPC connection is not valid, cannot send anything");
        return -1;
    }

    if (sys_to == NULL) {
        if (dest_node != NULL) {
            sys_to = CRM_SYSTEM_CRMD;
        } else {
            sys_to = CRM_SYSTEM_DC;
        }
    }

    {
        xmlNode *cmd = create_request(crmd_operation, msg_data, dest_node, sys_to,
                                      crm_system_name, admin_uuid);

        crm_ipc_send(crmd_channel, cmd, 0, 0, NULL);
        free_xml(cmd);
    }

    return ret;
}

void
crmadmin_ipc_connection_destroy(gpointer user_data)
{
    crm_err("Connection to CRMd was terminated");
    if (mainloop) {
        g_main_quit(mainloop);
    } else {
        crm_exit(ENOTCONN);
    }
}

struct ipc_client_callbacks crm_callbacks = {
    .dispatch = admin_msg_callback,
    .destroy = crmadmin_ipc_connection_destroy
};

gboolean
do_init(void)
{
    mainloop_io_t *source =
        mainloop_add_ipc_client(CRM_SYSTEM_CRMD, G_PRIORITY_DEFAULT, 0, NULL, &crm_callbacks);

    admin_uuid = calloc(1, 11);
    if (admin_uuid != NULL) {
        snprintf(admin_uuid, 10, "%d", getpid());
        admin_uuid[10] = '\0';
    }

    crmd_channel = mainloop_get_ipc_client(source);

    if (DO_RESOURCE || DO_RESOURCE_LIST || DO_NODE_LIST) {
        return TRUE;

    } else if (crmd_channel != NULL) {
        xmlNode *xml = create_hello_message(admin_uuid, crm_system_name, "0", "1");

        crm_ipc_send(crmd_channel, xml, 0, 0, NULL);
        return TRUE;
    }
    return FALSE;
}

static bool
validate_crm_message(xmlNode * msg, const char *sys, const char *uuid, const char *msg_type)
{
    const char *type = NULL;
    const char *crm_msg_reference = NULL;

    if (msg == NULL) {
        return FALSE;
    }

    type = crm_element_value(msg, F_CRM_MSG_TYPE);
    crm_msg_reference = crm_element_value(msg, XML_ATTR_REFERENCE);

    if (type == NULL) {
        crm_info("No message type defined.");
        return FALSE;

    } else if (msg_type != NULL && strcasecmp(msg_type, type) != 0) {
        crm_info("Expecting a (%s) message but received a (%s).", msg_type, type);
        return FALSE;
    }

    if (crm_msg_reference == NULL) {
        crm_info("No message crm_msg_reference defined.");
        return FALSE;
    }

    return TRUE;
}

int
admin_msg_callback(const char *buffer, ssize_t length, gpointer userdata)
{
    static int received_responses = 0;
    const char *result = NULL;
    xmlNode *xml = string2xml(buffer);

    received_responses++;
    g_source_remove(message_timer_id);

    crm_log_xml_trace(xml, "ipc");

    if (xml == NULL) {
        crm_info("XML in IPC message was not valid... " "discarding.");

    } else if (validate_crm_message(xml, crm_system_name, admin_uuid, XML_ATTR_RESPONSE) == FALSE) {
        crm_trace("Message was not a CRM response. Discarding.");

    } else {
        result = crm_element_value(xml, XML_ATTR_RESULT);
        if (result == NULL || strcasecmp(result, "ok") == 0) {
            result = "pass";

        } else {
            result = "fail";
        }

        if (DO_HEALTH) {
            xmlNode *data = get_message_xml(xml, F_CRM_DATA);
            const char *state = crm_element_value(data, "crmd_state");

            printf("Status of %s@%s: %s (%s)\n",
                   crm_element_value(data, XML_PING_ATTR_SYSFROM),
                   crm_element_value(xml, F_CRM_HOST_FROM),
                   state, crm_element_value(data, XML_PING_ATTR_STATUS));

            if (BE_SILENT && state != NULL) {
                fprintf(stderr, "%s\n", state);
            }

        } else if (DO_WHOIS_DC) {
            const char *dc = crm_element_value(xml, F_CRM_HOST_FROM);

            printf("Designated Controller is: %s\n", dc);
            if (BE_SILENT && dc != NULL) {
                fprintf(stderr, "%s\n", dc);
            }
            crm_exit(pcmk_ok);
        }
    }

    free_xml(xml);

    if (received_responses >= expected_responses) {
        crm_trace("Received expected number (%d) of messages from Heartbeat."
                  "  Exiting normally.", expected_responses);
        crm_exit(pcmk_ok);
    }

    message_timer_id = g_timeout_add(message_timeout_ms, admin_message_timeout, NULL);
    return 0;
}

gboolean
admin_message_timeout(gpointer data)
{
    fprintf(stderr, "No messages received in %d seconds.. aborting\n",
            (int)message_timeout_ms / 1000);
    crm_err("No messages received in %d seconds", (int)message_timeout_ms / 1000);
    operation_status = -3;
    g_main_quit(mainloop);
    return FALSE;
}

gboolean
is_node_online(xmlNode * node_state)
{
    const char *uname = crm_element_value(node_state, XML_ATTR_UNAME);
    const char *join_state = crm_element_value(node_state, XML_NODE_JOIN_STATE);
    const char *exp_state = crm_element_value(node_state, XML_NODE_EXPECTED);
    const char *crm_state = crm_element_value(node_state, XML_NODE_IS_PEER);
    const char *ccm_state = crm_element_value(node_state, XML_NODE_IN_CLUSTER);

    if (safe_str_neq(join_state, CRMD_JOINSTATE_DOWN)
        && crm_is_true(ccm_state)
        && safe_str_eq(crm_state, "online")) {
        crm_trace("Node %s is online", uname);
        return TRUE;
    }
    crm_trace("Node %s: ccm=%s join=%s exp=%s crm=%s",
              uname, crm_str(ccm_state),
              crm_str(join_state), crm_str(exp_state), crm_str(crm_state));
    crm_trace("Node %s is offline", uname);
    return FALSE;
}

int
do_find_node_list(xmlNode * xml_node)
{
    int found = 0;
    xmlNode *node = NULL;
    xmlNode *nodes = get_object_root(XML_CIB_TAG_NODES, xml_node);

    for (node = __xml_first_child(nodes); node != NULL; node = __xml_next(node)) {
        if (crm_str_eq((const char *)node->name, XML_CIB_TAG_NODE, TRUE)) {

            if (BASH_EXPORT) {
                printf("export %s=%s\n",
                       crm_element_value(node, XML_ATTR_UNAME),
                       crm_element_value(node, XML_ATTR_ID));
            } else {
                printf("%s node: %s (%s)\n",
                       crm_element_value(node, XML_ATTR_TYPE),
                       crm_element_value(node, XML_ATTR_UNAME),
                       crm_element_value(node, XML_ATTR_ID));
            }
            found++;
        }
    }

    if (found == 0) {
        printf("NO nodes configured\n");
    }

    return found;
}

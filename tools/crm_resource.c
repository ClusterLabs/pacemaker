
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

#include <crm_resource.h>

#include <sys/param.h>

#include <crm/crm.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>

bool BE_QUIET = FALSE;
bool scope_master = FALSE;
int cib_options = cib_sync_call;

GMainLoop *mainloop = NULL;

#define message_timeout_ms 60*1000

static gboolean
resource_ipc_timeout(gpointer data)
{
    fprintf(stderr, "No messages received in %d seconds.. aborting\n",
            (int)message_timeout_ms / 1000);
    crm_err("No messages received in %d seconds", (int)message_timeout_ms / 1000);
    return crm_exit(-1);
}

static void
resource_ipc_connection_destroy(gpointer user_data)
{
    crm_info("Connection to CRMd was terminated");
    crm_exit(1);
}

static void
start_mainloop(void)
{
    if (crmd_replies_needed == 0) {
        return;
    }

    mainloop = g_main_new(FALSE);
    fprintf(stderr, "Waiting for %d replies from the CRMd", crmd_replies_needed);
    crm_debug("Waiting for %d replies from the CRMd", crmd_replies_needed);

    g_timeout_add(message_timeout_ms, resource_ipc_timeout, NULL);
    g_main_run(mainloop);
}

static int
resource_ipc_callback(const char *buffer, ssize_t length, gpointer userdata)
{
    xmlNode *msg = string2xml(buffer);

    fprintf(stderr, ".");
    crm_log_xml_trace(msg, "[inbound]");

    crmd_replies_needed--;
    if (crmd_replies_needed == 0) {
        fprintf(stderr, " OK\n");
        crm_debug("Got all the replies we expected");
        return crm_exit(pcmk_ok);
    }

    free_xml(msg);
    return 0;
}

struct ipc_client_callbacks crm_callbacks = {
    .dispatch = resource_ipc_callback,
    .destroy = resource_ipc_connection_destroy,
};


/* short option letters still available: eEJkKXyYZ */

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    /* Top-level Options */
    {
        "help", 0, 0, '?',
        "\t\tDisplay this text and exit"
    },
    {
        "version", 0, 0, '$',
        "\t\tDisplay version information and exit"
    },
    {
        "verbose", 0, 0, 'V',
        "\t\tIncrease debug output (may be specified multiple times)"
    },
    {
        "quiet", 0, 0, 'Q',
        "\t\tBe less descriptive in results"
    },
    {
        "resource", 1, 0, 'r',
        "\tResource ID"
    },

    {"-spacer-",1, 0, '-', "\nQueries:"},
    {"list",       0, 0, 'L', "\t\tList all cluster resources with status"},
    {
        "list-raw", 0, 0, 'l',
        "\t\tList IDs of all instantiated resources (individual members rather than groups etc.)"
    },
    {"list-cts",   0, 0, 'c', NULL, pcmk_option_hidden},
    {
        "list-operations", 0, 0, 'O',
        "\tList active resource operations, optionally filtered by --resource and/or --node"
    },
    {
        "list-all-operations", 0, 0, 'o',
        "List all resource operations, optionally filtered by --resource and/or --node"
    },
    {"pending",    0, 0, 'j', "\t\tDisplay pending state if 'record-pending' is enabled", pcmk_option_hidden},

    {"list-standards",        0, 0, 0, "\tList supported standards"},
    {"list-ocf-providers",    0, 0, 0, "List all available OCF providers"},
    {"list-agents",           1, 0, 0, "List all agents available for the named standard and/or provider."},
    {"list-ocf-alternatives", 1, 0, 0, "List all available providers for the named OCF agent"},
    {"show-metadata",         1, 0, 0, "Show the metadata for the named class:provider:agent"},

    {
        "query-xml", 0, 0, 'q',
        "\tShow XML configuration of resource (after any template expansion)"
    },
    {
        "query-xml-raw", 0, 0, 'w',
        "\tShow XML configuration of resource (before any template expansion)"
    },
    {
        "get-parameter", 1, 0, 'g',
        "Display named parameter for resource.\n"
        "\t\t\t\tUse instance attribute unless --meta or --utilization is specified"
    },
    {
        "get-property", 1, 0, 'G',
        "Display named property of resource ('class', 'type', or 'provider') (requires --resource)",
        pcmk_option_hidden
    },
    {
        "locate", 0, 0, 'W',
        "\t\tShow node(s) currently running resource"
    },
    {"stack",      0, 0, 'A', "\t\tDisplay the prerequisites and dependents of a resource"},
    {"constraints",0, 0, 'a', "\tDisplay the (co)location constraints that apply to a resource"},
    {
        "why", 0, 0, 'Y',
        "\t\tShow why resources are not running, optionally filtered by --resource and/or --node"
    },
    {"-spacer-", 1, 0, '-', "\nCommands:"},
    {"validate",   0, 0, 0, "\t\tCall the validate-all action of the local given resource"},
    {
        "cleanup", 0, 0, 'C',
        "\t\tDelete resource's history (including failures) so its current state is rechecked.\n"
        "\t\t\t\tOptionally filtered by --resource, --node, --operation, and --interval (otherwise all).\n"
        "\t\t\t\tUnless --force is specified, resource's group or clone (if any) will also be cleaned"
    },
    {
        "set-parameter", 1, 0, 'p',
        "Set named parameter for resource (requires -v).\n"
        "\t\t\t\tUse instance attribute unless --meta or --utilization is specified."
    },
    {
        "delete-parameter", 1, 0, 'd',
        "Delete named parameter for resource.\n"
        "\t\t\t\tUse instance attribute unless --meta or --utilization is specified."
    },
    {
        "set-property", 1, 0, 'S',
        "Set named property of resource ('class', 'type', or 'provider') (requires -r, -t, -v)",
        pcmk_option_hidden
    },

    {"-spacer-", 1, 0, '-', "\nResource location:"},
    {
        "move",    0, 0, 'M',
        "\t\tCreate a constraint to move resource. If --node is specified, the constraint\n"
        "\t\t\t\twill be to move to that node, otherwise it will be to ban the current node.\n"
        "\t\t\t\tUnless --force is specified, this will return an error if the resource is\n"
        "\t\t\t\talready running on the specified node. If --force is specified, this will\n"
        "\t\t\t\talways ban the current node. Optional: --lifetime, --master.\n"
        "\t\t\t\tNOTE: This may prevent the resource from running on its previous location\n"
        "\t\t\t\tuntil the implicit constraint expires or is removed with --clear."
    },
    {
        "ban",    0, 0, 'B',
        "\t\tCreate a constraint to keep resource off a node. Optional: --node, --lifetime, --master.\n"
        "\t\t\t\tNOTE: This will prevent the resource from running on the affected node\n"
        "\t\t\t\tuntil the implicit constraint expires or is removed with --clear.\n"
        "\t\t\t\tIf --node is not specified, it defaults to the node currently running the resource\n"
        "\t\t\t\tfor primitives and groups, or the master for master/slave clones with master-max=1\n"
        "\t\t\t\t(all other situations result in an error as there is no sane default).\n"
    },
    {
        "clear", 0, 0, 'U',
        "\t\tRemove all constraints created by the --ban and/or --move commands.\n"
        "\t\t\t\tRequires: --resource. Optional: --node, --master.\n"
        "\t\t\t\tIf --node is not specified, all constraints created by --ban and --move\n"
        "\t\t\t\twill be removed for the named resource. If --node and --force are specified,\n"
        "\t\t\t\tany constraint created by --move will be cleared, even if it is not for the specified node."
    },
    {
        "lifetime", 0, 0, 'u',
        "\tLifespan (as ISO 8601 duration) of constraints created by the --ban and --move commands\n"
        "\t\t\t\t(see https://en.wikipedia.org/wiki/ISO_8601#Durations)"
    },
    {
        "master",  0, 0,  0,
        "\t\tLimit the scope of the --ban, --move, and --clear commands to the Master role.\n"
        "\t\t\t\tFor --ban and --move, the previous master may remain active in the Slave role."
    },

    {"-spacer-",   1, 0, '-', "\nAdvanced Commands:"},
    {"delete",     0, 0, 'D', "\t\t(Advanced) Delete a resource from the CIB. Required: -t"},
    {"fail",       0, 0, 'F', "\t\t(Advanced) Tell the cluster this resource has failed"},
    {"restart",    0, 0,  0,  "\t\t(Advanced) Tell the cluster to restart this resource and anything that depends on it"},
    {"wait",       0, 0,  0,  "\t\t(Advanced) Wait until the cluster settles into a stable state"},
    {
        "force-demote", 0, 0, 0,
        "\t(Advanced) Bypass the cluster and demote a resource on the local node.\n"
        "\t\t\t\tUnless --force is specified, this will refuse to do so if the cluster\n"
        "\t\t\t\tbelieves the resource is a clone instance already running on the local node."
    },
    {
        "force-stop", 0, 0, 0,
        "\t(Advanced) Bypass the cluster and stop a resource on the local node."
    },
    {
        "force-start", 0, 0, 0,
        "\t(Advanced) Bypass the cluster and start a resource on the local node.\n"
        "\t\t\t\tUnless --force is specified, this will refuse to do so if the cluster\n"
        "\t\t\t\tbelieves the resource is a clone instance already running on the local node."
    },
    {
        "force-promote", 0, 0, 0,
        "\t(Advanced) Bypass the cluster and promote a resource on the local node.\n"
        "\t\t\t\tUnless --force is specified, this will refuse to do so if the cluster\n"
        "\t\t\t\tbelieves the resource is a clone instance already running on the local node."
    },
    {
        "force-check", 0, 0, 0,
        "\t(Advanced) Bypass the cluster and check the state of a resource on the local node."
    },

    {"-spacer-", 1, 0, '-', "\nAdditional Options:"},
    {
        "node", 1, 0, 'N',
        "\tNode name"
    },
    {"recursive",       0, 0,  0,  "\tFollow colocation chains when using --set-parameter"},
    {
        "resource-type", 1, 0, 't',
        "Resource XML element (primitive, group, etc.) (with -D)"
    },
    {"parameter-value", 1, 0, 'v', "Value to use with -p"},
    {
        "meta", 0, 0, 'm',
        "\t\tUse resource meta-attribute instead of instance attribute (with -p, -g, -d)"
    },
    {
        "utilization", 0, 0, 'z',
        "\tUse resource utilization attribute instead of instance attribute (with -p, -g, -d)"
    },
    {
        "operation",      required_argument, NULL, 'n',
        "\tOperation to clear instead of all (with -C -r)"
    },
    {
        "interval",       required_argument, NULL, 'I',
        "\tInterval of operation to clear (default 0) (with -C -r -n)"
    },
    {
        "set-name", 1, 0, 's',
        "\t(Advanced) XML ID of attributes element to use (with -p, -d)"
    },
    {
        "nvpair", 1, 0, 'i',
        "\t(Advanced) XML ID of nvpair element to use (with -p, -d)"
    },
    {
        "timeout", 1, 0, 'T',
        "\t(Advanced) Abort if command does not finish in this time (with --restart, --wait)"
    },
    {
        "force", 0, 0, 'f',
        "\t\tIf making CIB changes, do so regardless of quorum.\n"
        "\t\t\t\tSee help for individual commands for additional behavior.\n"
    },

    {"xml-file", 1, 0, 'x', NULL, pcmk_option_hidden},

    /* legacy options */
    {"host-uname", 1, 0, 'H', NULL, pcmk_option_hidden},
    {"migrate",    0, 0, 'M', NULL, pcmk_option_hidden},
    {"un-migrate", 0, 0, 'U', NULL, pcmk_option_hidden},
    {"un-move",    0, 0, 'U', NULL, pcmk_option_hidden},

    {"refresh",    0, 0, 'R', NULL, pcmk_option_hidden},
    {"reprobe",    0, 0, 'P', NULL, pcmk_option_hidden},

    {"-spacer-", 1, 0, '-', "\nExamples:", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', "List the available OCF agents:", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --list-agents ocf", pcmk_option_example},
    {"-spacer-", 1, 0, '-', "List the available OCF agents from the linux-ha project:", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --list-agents ocf:heartbeat", pcmk_option_example},
    {"-spacer-", 1, 0, '-', "Move 'myResource' to a specific node:", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --resource myResource --move --node altNode", pcmk_option_example},
    {"-spacer-", 1, 0, '-', "Allow (but not force) 'myResource' to move back to its original location:", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --resource myResource --clear", pcmk_option_example},
    {"-spacer-", 1, 0, '-', "Stop 'myResource' (and anything that depends on it):", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --resource myResource --set-parameter target-role --meta --parameter-value Stopped", pcmk_option_example},
    {"-spacer-", 1, 0, '-', "Tell the cluster not to manage 'myResource':", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', "The cluster will not attempt to start or stop the resource under any circumstances."},
    {"-spacer-", 1, 0, '-', "Useful when performing maintenance tasks on a resource.", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --resource myResource --set-parameter is-managed --meta --parameter-value false", pcmk_option_example},
    {"-spacer-", 1, 0, '-', "Erase the operation history of 'myResource' on 'aNode':", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', "The cluster will 'forget' the existing resource state (including any errors) and attempt to recover the resource."},
    {"-spacer-", 1, 0, '-', "Useful when a resource had failed permanently and has been repaired by an administrator.", pcmk_option_paragraph},
    {"-spacer-", 1, 0, '-', " crm_resource --resource myResource --cleanup --node aNode", pcmk_option_example},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

int
main(int argc, char **argv)
{
    char rsc_cmd = 'L';

    const char *rsc_id = NULL;
    const char *host_uname = NULL;
    const char *prop_name = NULL;
    const char *prop_value = NULL;
    const char *rsc_type = NULL;
    const char *prop_id = NULL;
    const char *prop_set = NULL;
    const char *rsc_long_cmd = NULL;
    const char *longname = NULL;
    const char *operation = NULL;
    const char *interval = NULL;
    GHashTable *override_params = NULL;

    char *xml_file = NULL;
    crm_ipc_t *crmd_channel = NULL;
    pe_working_set_t data_set;
    cib_t *cib_conn = NULL;
    bool recursive = FALSE;
    char *our_pid = NULL;

    bool require_resource = TRUE; /* whether command requires that resource be specified */
    bool require_dataset = TRUE;  /* whether command requires populated dataset instance */
    bool require_crmd = FALSE;    /* whether command requires connection to CRMd */

    int rc = pcmk_ok;
    int option_index = 0;
    int timeout_ms = 0;
    int argerr = 0;
    int flag;

    crm_log_cli_init("crm_resource");
    crm_set_options(NULL, "(query|command) [options]", long_options,
                    "Perform tasks related to cluster resources.\nAllows resources to be queried (definition and location), modified, and moved around the cluster.\n");

    while (1) {
        flag = crm_get_option_long(argc, argv, &option_index, &longname);
        if (flag == -1)
            break;

        switch (flag) {
            case 0: /* long options with no short equivalent */
                if (safe_str_eq("master", longname)) {
                    scope_master = TRUE;

                } else if(safe_str_eq(longname, "recursive")) {
                    recursive = TRUE;

                } else if (safe_str_eq("wait", longname)) {
                    rsc_cmd = flag;
                    rsc_long_cmd = longname;
                    require_resource = FALSE;
                    require_dataset = FALSE;

                } else if (
                    safe_str_eq("validate", longname)
                    || safe_str_eq("restart", longname)
                    || safe_str_eq("force-demote",  longname)
                    || safe_str_eq("force-stop",    longname)
                    || safe_str_eq("force-start",   longname)
                    || safe_str_eq("force-promote", longname)
                    || safe_str_eq("force-check",   longname)) {
                    rsc_cmd = flag;
                    rsc_long_cmd = longname;
                    crm_log_args(argc, argv);

                } else if (safe_str_eq("list-ocf-providers", longname)
                           || safe_str_eq("list-ocf-alternatives", longname)
                           || safe_str_eq("list-standards", longname)) {
                    const char *text = NULL;
                    lrmd_list_t *list = NULL;
                    lrmd_list_t *iter = NULL;
                    lrmd_t *lrmd_conn = lrmd_api_new();

                    if (safe_str_eq("list-ocf-providers", longname)
                        || safe_str_eq("list-ocf-alternatives", longname)) {
                        rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, optarg, &list);
                        text = "OCF providers";

                    } else if (safe_str_eq("list-standards", longname)) {
                        rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);
                        text = "standards";
                    }

                    if (rc > 0) {
                        rc = 0;
                        for (iter = list; iter != NULL; iter = iter->next) {
                            rc++;
                            printf("%s\n", iter->val);
                        }
                        lrmd_list_freeall(list);

                    } else if (optarg) {
                        fprintf(stderr, "No %s found for %s\n", text, optarg);
                    } else {
                        fprintf(stderr, "No %s found\n", text);
                    }

                    lrmd_api_delete(lrmd_conn);
                    return crm_exit(rc);

                } else if (safe_str_eq("show-metadata", longname)) {
                    char *standard = NULL;
                    char *provider = NULL;
                    char *type = NULL;
                    char *metadata = NULL;
                    lrmd_t *lrmd_conn = lrmd_api_new();

                    rc = crm_parse_agent_spec(optarg, &standard, &provider, &type);
                    if (rc == pcmk_ok) {
                        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard,
                                                           provider, type,
                                                           &metadata, 0);
                    } else {
                        fprintf(stderr,
                                "'%s' is not a valid agent specification\n",
                                optarg);
                    }

                    if (metadata) {
                        printf("%s\n", metadata);
                    } else {
                        fprintf(stderr, "Metadata query for %s failed: %s\n",
                                optarg, pcmk_strerror(rc));
                    }
                    lrmd_api_delete(lrmd_conn);
                    return crm_exit(rc);

                } else if (safe_str_eq("list-agents", longname)) {
                    lrmd_list_t *list = NULL;
                    lrmd_list_t *iter = NULL;
                    char *provider = strchr (optarg, ':');
                    lrmd_t *lrmd_conn = lrmd_api_new();

                    if (provider) {
                        *provider++ = 0;
                    }
                    rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, optarg, provider);

                    if (rc > 0) {
                        rc = 0;
                        for (iter = list; iter != NULL; iter = iter->next) {
                            printf("%s\n", iter->val);
                            rc++;
                        }
                        lrmd_list_freeall(list);
                        rc = 0;
                    } else {
                        fprintf(stderr, "No agents found for standard=%s, provider=%s\n",
                                optarg, (provider? provider : "*"));
                        rc = -1;
                    }
                    lrmd_api_delete(lrmd_conn);
                    return crm_exit(rc);

                } else {
                    crm_err("Unhandled long option: %s", longname);
                }
                break;
            case 'V':
                do_trace = TRUE;
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            case 'x':
                xml_file = strdup(optarg);
                break;
            case 'Q':
                BE_QUIET = TRUE;
                break;
            case 'm':
                attr_set_type = XML_TAG_META_SETS;
                break;
            case 'z':
                attr_set_type = XML_TAG_UTILIZATION;
                break;
            case 'u':
                move_lifetime = strdup(optarg);
                break;
            case 'f':
                do_force = TRUE;
                crm_log_args(argc, argv);
                break;
            case 'i':
                prop_id = optarg;
                break;
            case 's':
                prop_set = optarg;
                break;
            case 'r':
                rsc_id = optarg;
                break;
            case 'v':
                prop_value = optarg;
                break;
            case 't':
                rsc_type = optarg;
                break;
            case 'T':
                timeout_ms = crm_get_msec(optarg);
                break;

            case 'C':
            case 'R':
            case 'P':
                crm_log_args(argc, argv);
                require_resource = FALSE;
                require_crmd = TRUE;
                rsc_cmd = 'C';
                break;

            case 'n':
                operation = optarg;
                break;

            case 'I':
                interval = optarg;
                break;
            
            case 'D':
                require_dataset = FALSE; 
                crm_log_args(argc, argv);
                rsc_cmd = flag;
                break;

            case 'F':
                require_crmd = TRUE;
            case 'U':
            case 'B':
            case 'M':
                crm_log_args(argc, argv);
                rsc_cmd = flag;
                break;

            case 'c':
            case 'L':
            case 'l':
            case 'O':
            case 'o':
            case 'Y':
                 require_resource = FALSE;
            case 'q':
            case 'w':
            case 'W':
            case 'A':
            case 'a':
                rsc_cmd = flag;
                break;

            case 'j':
                print_pending = TRUE;
                break;
            case 'S':
                require_dataset = FALSE;  
            case 'p':
            case 'd':
                crm_log_args(argc, argv);
                prop_name = optarg;
                rsc_cmd = flag;
                break;
            case 'G':
            case 'g':
                prop_name = optarg;
                rsc_cmd = flag;
                break;
            case 'h':
            case 'H':
            case 'N':
                crm_trace("Option %c => %s", flag, optarg);
                host_uname = optarg;
                break;

            default:
                CMD_ERR("Argument code 0%o (%c) is not (?yet?) supported", flag, flag);
                ++argerr;
                break;
        }
    }

    // Catch the case where the user didn't specify a command
    if (rsc_cmd == 'L') {
        require_resource = FALSE;
    }

    if (optind < argc
        && argv[optind] != NULL
        && rsc_cmd == 0
        && rsc_long_cmd) {

        override_params = crm_str_table_new();
        while (optind < argc && argv[optind] != NULL) {
            char *name = calloc(1, strlen(argv[optind]));
            char *value = calloc(1, strlen(argv[optind]));
            int rc = sscanf(argv[optind], "%[^=]=%s", name, value);

            if(rc == 2) {
                g_hash_table_replace(override_params, name, value);

            } else {
                CMD_ERR("Error parsing '%s' as a name=value pair for --%s", argv[optind], rsc_long_cmd);
                free(value);
                free(name);
                argerr++;
            }
            optind++;
        }

    } else if (optind < argc && argv[optind] != NULL && rsc_cmd == 0) {
        CMD_ERR("non-option ARGV-elements: ");
        while (optind < argc && argv[optind] != NULL) {
            CMD_ERR("[%d of %d] %s ", optind, argc, argv[optind]);
            optind++;
            argerr++;
        }
    }

    if (optind > argc) {
        ++argerr;
    }

    if (argerr) {
        CMD_ERR("Invalid option(s) supplied, use --help for valid usage");
        return crm_exit(EX_USAGE);
    }

    our_pid = crm_getpid_s();

    if (do_force) {
        crm_debug("Forcing...");
        cib_options |= cib_quorum_override;
    }

    data_set.input = NULL; /* make clean-up easier */
 
    /* If user specified resource, look for it, even if it's optional for command */
    if (rsc_id) {
        require_resource = TRUE;
    }

    /* We need a dataset to find a resource, even if command doesn't need it */
    if (require_resource) {
        require_dataset = TRUE;
    }
    
    if(require_resource && rsc_id == NULL)
    {
        CMD_ERR("Must supply a resource id with -r");
        rc = -ENXIO;
        goto bail;
    }

    /* Establish a connection to the CIB */
    cib_conn = cib_new();
    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        CMD_ERR("Error signing on to the CIB service: %s", pcmk_strerror(rc));
        goto bail;
    }

    /* Populate working set from XML file if specified or CIB query otherwise */
    if (require_dataset) {
        xmlNode *cib_xml_copy = NULL;

        if (xml_file != NULL) {
            cib_xml_copy = filename2xml(xml_file);

        } else {
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
        }

        if(rc != pcmk_ok) {
            goto bail;
        }

        /* Populate the working set instance */
        set_working_set_defaults(&data_set);
        rc = update_working_set_xml(&data_set, &cib_xml_copy);
        if (rc != pcmk_ok) {
            goto bail;
        }
        cluster_status(&data_set);

        /* Set rc to -ENXIO if no resource matching rsc_id is found.
         * This does not bail, but is handled later for certain commands.
         * That handling could be done here instead if all flags above set
         * require_resource appropriately. */
        if (require_resource && rsc_id && (find_rsc_or_clone(rsc_id, &data_set) == NULL)) {
            rc = -ENXIO;
        }
    }
    
    /* Establish a connection to the CRMd if needed */
    if (getenv("CIB_file") == NULL && require_crmd) {
        xmlNode *xml = NULL;
        mainloop_io_t *source =
            mainloop_add_ipc_client(CRM_SYSTEM_CRMD, G_PRIORITY_DEFAULT, 0, NULL, &crm_callbacks);
        crmd_channel = mainloop_get_ipc_client(source);

        if (crmd_channel == NULL) {
            CMD_ERR("Error signing on to the CRMd service");
            rc = -ENOTCONN;
            goto bail;
        }

        xml = create_hello_message(our_pid, crm_system_name, "0", "1");
        crm_ipc_send(crmd_channel, xml, 0, 0, NULL);
        free_xml(xml);
    }

    /* Handle rsc_cmd appropriately */
    if (rsc_cmd == 'L') {
        rc = pcmk_ok;
        cli_resource_print_list(&data_set, FALSE);

    } else if (rsc_cmd == 'l') {
        int found = 0;
        GListPtr lpc = NULL;

        rc = pcmk_ok;
        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *rsc = (resource_t *) lpc->data;

            found++;
            cli_resource_print_raw(rsc);
        }

        if (found == 0) {
            printf("NO resources configured\n");
            rc = -ENXIO;
        }

    } else if (rsc_cmd == 0 && rsc_long_cmd && safe_str_eq(rsc_long_cmd, "restart")) {
        resource_t *rsc = NULL;

        rsc = pe_find_resource(data_set.resources, rsc_id);

        rc = -EINVAL;
        if (rsc == NULL) {
            CMD_ERR("Resource '%s' not restarted: unknown", rsc_id);
            goto bail;
        }

        rc = cli_resource_restart(rsc, host_uname, timeout_ms, cib_conn);

    } else if (rsc_cmd == 0 && rsc_long_cmd && safe_str_eq(rsc_long_cmd, "wait")) {
        rc = wait_till_stable(timeout_ms, cib_conn);

    } else if (rsc_cmd == 0 && rsc_long_cmd) { /* validate or force-(stop|start|check) */
        rc = cli_resource_execute(rsc_id, rsc_long_cmd, override_params, cib_conn, &data_set);

    } else if (rsc_cmd == 'A' || rsc_cmd == 'a') {
        GListPtr lpc = NULL;
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set.input);

        if (rsc == NULL) {
            CMD_ERR("Must supply a resource id with -r");
            rc = -ENXIO;
            goto bail;
        }

        unpack_constraints(cib_constraints, &data_set);

        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *r = (resource_t *) lpc->data;

            clear_bit(r->flags, pe_rsc_allocating);
        }

        cli_resource_print_colocation(rsc, TRUE, rsc_cmd == 'A', 1);

        fprintf(stdout, "* %s\n", rsc->id);
        cli_resource_print_location(rsc, NULL);

        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *r = (resource_t *) lpc->data;

            clear_bit(r->flags, pe_rsc_allocating);
        }

        cli_resource_print_colocation(rsc, FALSE, rsc_cmd == 'A', 1);

    } else if (rsc_cmd == 'c') {
        int found = 0;
        GListPtr lpc = NULL;

        rc = pcmk_ok;
        for (lpc = data_set.resources; lpc != NULL; lpc = lpc->next) {
            resource_t *rsc = (resource_t *) lpc->data;

            cli_resource_print_cts(rsc);
            found++;
        }
        cli_resource_print_cts_constraints(&data_set);

    } else if (rsc_cmd == 'F') {
        rc = cli_resource_fail(crmd_channel, host_uname, rsc_id, &data_set);
        if (rc == pcmk_ok) {
            start_mainloop();
        }

    } else if (rsc_cmd == 'O') {
        rc = cli_resource_print_operations(rsc_id, host_uname, TRUE, &data_set);

    } else if (rsc_cmd == 'o') {
        rc = cli_resource_print_operations(rsc_id, host_uname, FALSE, &data_set);

    /* All remaining commands require that resource exist */
    } else if (rc == -ENXIO) {
        CMD_ERR("Resource '%s' not found: %s", crm_str(rsc_id), pcmk_strerror(rc));

    } else if (rsc_cmd == 'W') {
        rc = cli_resource_search(rsc_id, &data_set);
        if (rc >= 0) {
            rc = pcmk_ok;
        }

    } else if (rsc_cmd == 'q') {
        rc = cli_resource_print(rsc_id, &data_set, TRUE);

    } else if (rsc_cmd == 'w') {
        rc = cli_resource_print(rsc_id, &data_set, FALSE);

    } else if(rsc_cmd == 'Y') {
        node_t *dest = NULL;
        if (host_uname) {
            dest = pe_find_node(data_set.nodes, host_uname);
            if (dest == NULL) {
                CMD_ERR("Unknown node: %s", host_uname);
                rc = -ENXIO;
                goto bail;
            }
        }
        cli_resource_why(cib_conn,data_set.resources,rsc_id,dest);
    } else if (rsc_cmd == 'U') {
        node_t *dest = NULL;

        if (host_uname) {
            dest = pe_find_node(data_set.nodes, host_uname);
            if (dest == NULL) {
                CMD_ERR("Unknown node: %s", host_uname);
                rc = -ENXIO;
                goto bail;
            }
            rc = cli_resource_clear(rsc_id, dest->details->uname, NULL, cib_conn);

        } else {
            rc = cli_resource_clear(rsc_id, NULL, data_set.nodes, cib_conn);
        }

    } else if (rsc_cmd == 'M' && host_uname) {
        rc = cli_resource_move(rsc_id, host_uname, cib_conn, &data_set);

    } else if (rsc_cmd == 'B' && host_uname) {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        node_t *dest = pe_find_node(data_set.nodes, host_uname);

        rc = -ENXIO;
        if(rsc == NULL) {
            CMD_ERR("Resource '%s' not moved: unknown", rsc_id);
            goto bail;

        } else if (dest == NULL) {
            CMD_ERR("Error performing operation: node '%s' is unknown", host_uname);
            goto bail;
        }
        rc = cli_resource_ban(rsc_id, dest->details->uname, NULL, cib_conn);

    } else if (rsc_cmd == 'B' || rsc_cmd == 'M') {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        rc = -EINVAL;
        if(rsc == NULL) {
            CMD_ERR("Resource '%s' not moved: unknown", rsc_id);

        } else if(g_list_length(rsc->running_on) == 1) {
            node_t *current = rsc->running_on->data;
            rc = cli_resource_ban(rsc_id, current->details->uname, NULL, cib_conn);

        } else if(rsc->variant == pe_master) {
            int count = 0;
            GListPtr iter = NULL;
            node_t *current = NULL;

            for(iter = rsc->children; iter; iter = iter->next) {
                resource_t *child = (resource_t *)iter->data;
                enum rsc_role_e child_role = child->fns->state(child, TRUE);

                if(child_role == RSC_ROLE_MASTER) {
                    count++;
                    current = child->running_on->data;
                }
            }

            if(count == 1 && current) {
                rc = cli_resource_ban(rsc_id, current->details->uname, NULL, cib_conn);

            } else {
                CMD_ERR("Resource '%s' not moved: active in %d locations (promoted in %d).", rsc_id, g_list_length(rsc->running_on), count);
                CMD_ERR("You can prevent '%s' from running on a specific location with: --ban --node <name>", rsc_id);
                CMD_ERR("You can prevent '%s' from being promoted at a specific location with:"
                        " --ban --master --node <name>", rsc_id);
            }

        } else {
            CMD_ERR("Resource '%s' not moved: active in %d locations.", rsc_id, g_list_length(rsc->running_on));
            CMD_ERR("You can prevent '%s' from running on a specific location with: --ban --node <name>", rsc_id);
        }

    } else if (rsc_cmd == 'G') {
        rc = cli_resource_print_property(rsc_id, prop_name, &data_set);

    } else if (rsc_cmd == 'S') {
        xmlNode *msg_data = NULL;

        if ((rsc_type == NULL) || !strlen(rsc_type)) {
            CMD_ERR("Must specify -t with resource type");
            rc = -ENXIO;
            goto bail;

        } else if ((prop_value == NULL) || !strlen(prop_value)) {
            CMD_ERR("Must supply -v with new value");
            rc = -EINVAL;
            goto bail;
        }

        CRM_LOG_ASSERT(prop_name != NULL);

        msg_data = create_xml_node(NULL, rsc_type);
        crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);
        crm_xml_add(msg_data, prop_name, prop_value);

        rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
        free_xml(msg_data);

    } else if (rsc_cmd == 'g') {
        rc = cli_resource_print_attribute(rsc_id, prop_name, &data_set);

    } else if (rsc_cmd == 'p') {
        if (prop_value == NULL || strlen(prop_value) == 0) {
            CMD_ERR("You need to supply a value with the -v option");
            rc = -EINVAL;
            goto bail;
        }

        /* coverity[var_deref_model] False positive */
        rc = cli_resource_update_attribute(rsc_id, prop_set, prop_id, prop_name,
                               prop_value, recursive, cib_conn, &data_set);

    } else if (rsc_cmd == 'd') {
        /* coverity[var_deref_model] False positive */
        rc = cli_resource_delete_attribute(rsc_id, prop_set, prop_id, prop_name, cib_conn, &data_set);
    } else if ((rsc_cmd == 'C') && (rsc_id)) {
        resource_t *rsc = pe_find_resource(data_set.resources, rsc_id);
        if(do_force == FALSE) {
            rsc = uber_parent(rsc);
        }

        if(rsc) {
            crm_debug("Re-checking the state of %s (%s requested) on %s",
                      rsc->id, rsc_id, host_uname);
            crmd_replies_needed = 0;
            rc = cli_resource_delete(crmd_channel, host_uname, rsc, operation,
                                     interval, &data_set);
        } else {
            rc = -ENODEV;
        }

        if(rc == pcmk_ok && BE_QUIET == FALSE) {
            /* Now check XML_RSC_ATTR_TARGET_ROLE and XML_RSC_ATTR_MANAGED */
            cli_resource_check(cib_conn, rsc);
        }

        if (rc == pcmk_ok) {
            start_mainloop();
        }

    } else if (rsc_cmd == 'C') {
#if HAVE_ATOMIC_ATTRD
        const char *router_node = host_uname;
        xmlNode *msg_data = NULL;
        xmlNode *cmd = NULL;
        int attr_options = attrd_opt_none;

        if (host_uname) {
            node_t *node = pe_find_node(data_set.nodes, host_uname);

            if (node && is_remote_node(node)) {
                if (node->details->remote_rsc == NULL || node->details->remote_rsc->running_on == NULL) {
                    CMD_ERR("No lrmd connection detected to remote node %s", host_uname);
                    rc = -ENXIO;
                    goto bail;
                }
                node = node->details->remote_rsc->running_on->data;
                router_node = node->details->uname;
                attr_options |= attrd_opt_remote;
            }
        }

        msg_data = create_xml_node(NULL, "crm-resource-reprobe-op");
        crm_xml_add(msg_data, XML_LRM_ATTR_TARGET, host_uname);
        if (safe_str_neq(router_node, host_uname)) {
            crm_xml_add(msg_data, XML_LRM_ATTR_ROUTER_NODE, router_node);
        }

        cmd = create_request(CRM_OP_REPROBE, msg_data, router_node,
                             CRM_SYSTEM_CRMD, crm_system_name, our_pid);
        free_xml(msg_data);

        crm_debug("Re-checking the state of all resources on %s", host_uname?host_uname:"all nodes");

        rc = attrd_clear_delegate(NULL, host_uname, NULL, NULL, NULL, NULL,
                                  attr_options);

        if (crm_ipc_send(crmd_channel, cmd, 0, 0, NULL) > 0) {
            start_mainloop();
        }

        free_xml(cmd);
#else
        GListPtr rIter = NULL;

        crmd_replies_needed = 0;
        for (rIter = data_set.resources; rIter; rIter = rIter->next) {
            resource_t *rsc = rIter->data;
            cli_resource_delete(crmd_channel, host_uname, rsc, NULL, NULL,
                                &data_set);
        }

        start_mainloop();
#endif

    } else if (rsc_cmd == 'D') {
        xmlNode *msg_data = NULL;

        if (rsc_type == NULL) {
            CMD_ERR("You need to specify a resource type with -t");
            rc = -ENXIO;
            goto bail;
        }

        msg_data = create_xml_node(NULL, rsc_type);
        crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);

        rc = cib_conn->cmds->delete(cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
        free_xml(msg_data);

    } else {
        CMD_ERR("Unknown command: %c", rsc_cmd);
    }

  bail:

    free(our_pid);

    if (data_set.input != NULL) {
        cleanup_alloc_calculations(&data_set);
    }
    if (cib_conn != NULL) {
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
    }

    if (rc == -pcmk_err_no_quorum) {
        CMD_ERR("Error performing operation: %s", pcmk_strerror(rc));
        CMD_ERR("Try using -f");

    } else if (rc != pcmk_ok) {
        CMD_ERR("Error performing operation: %s", pcmk_strerror(rc));
    }

    return crm_exit(rc);
}

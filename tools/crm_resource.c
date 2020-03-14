/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_resource.h>
#include <pacemaker-internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/stonith-ng.h>

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

static GMainLoop *mainloop = NULL;

// Things that should be cleaned up on exit
static cib_t *cib_conn = NULL;
static pcmk_controld_api_t *controld_api = NULL;
static pe_working_set_t *data_set = NULL;

#define MESSAGE_TIMEOUT_S 60

// Clean up and exit
static void
bye(crm_exit_t exit_code)
{
    static bool crm_resourece_shutdown_flag = FALSE;

    if (crm_resourece_shutdown_flag) {
        return;
    }
    crm_resourece_shutdown_flag = TRUE;

    if (cib_conn != NULL) {
        cib_conn->cmds->signoff(cib_conn);
        cib_delete(cib_conn);
        cib_conn = NULL;
    }
    if (controld_api != NULL) {
        pcmk_free_controld_api(controld_api);
    }
    pe_free_working_set(data_set);
    data_set = NULL;
    crm_exit(exit_code);
    return;
}

static gboolean
resource_ipc_timeout(gpointer data)
{
    fprintf(stderr, "Aborting because no messages received in %d seconds\n",
            MESSAGE_TIMEOUT_S);
    crm_err("No messages received in %d seconds", MESSAGE_TIMEOUT_S);
    bye(CRM_EX_TIMEOUT);
    return FALSE;
}

static void
handle_controller_reply(pcmk_controld_api_t *capi, void *api_data,
                        void *user_data)
{
    fprintf(stderr, ".");
    if ((capi->replies_expected(capi) == 0)
        && mainloop && g_main_loop_is_running(mainloop)) {
        fprintf(stderr, " OK\n");
        crm_debug("Got all the replies we expected");
        bye(CRM_EX_OK);
    }
}

static void
handle_controller_drop(pcmk_controld_api_t *capi, void *api_data,
                       void *user_data)
{
    crm_info("Connection to controller was terminated");
    bye(CRM_EX_DISCONNECT);
}

static void
start_mainloop(pcmk_controld_api_t *capi)
{
    if (capi->replies_expected(capi) > 0) {
        unsigned int count = capi->replies_expected(capi);

        fprintf(stderr, "Waiting for %d %s from the controller",
                count, pcmk__plural_alt(count, "reply", "replies"));
        mainloop = g_main_loop_new(NULL, FALSE);
        g_timeout_add(MESSAGE_TIMEOUT_S * 1000, resource_ipc_timeout, NULL);
        g_main_loop_run(mainloop);
    }
}

static int
compare_id(gconstpointer a, gconstpointer b)
{
    return strcmp((const char *)a, (const char *)b);
}

static GListPtr
build_constraint_list(xmlNode *root)
{
    GListPtr retval = NULL;
    xmlNode *cib_constraints = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int ndx = 0;

    cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, root);
    xpathObj = xpath_search(cib_constraints, "//" XML_CONS_TAG_RSC_LOCATION);

    for (ndx = 0; ndx < numXpathResults(xpathObj); ndx++) {
        xmlNode *match = getXpathResult(xpathObj, ndx);
        retval = g_list_insert_sorted(retval, (gpointer) ID(match), compare_id);
    }

    freeXpathObject(xpathObj);
    return retval;
}

/* short option letters still available: eEJkKXyYZ */

static pcmk__cli_option_t long_options[] = {
    // long option, argument type, storage, short option, description, flags
    {
        "help", no_argument, NULL, '?',
        "\t\tDisplay this text and exit", pcmk__option_default
    },
    {
        "version", no_argument, NULL, '$',
        "\t\tDisplay version information and exit", pcmk__option_default
    },
    {
        "verbose", no_argument, NULL, 'V',
        "\t\tIncrease debug output (may be specified multiple times)",
        pcmk__option_default
    },
    {
        "quiet", no_argument, NULL, 'Q',
        "\t\tBe less descriptive in results", pcmk__option_default
    },
    {
        "resource", required_argument, NULL, 'r',
        "\tResource ID", pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nQueries:", pcmk__option_default
    },
    {
        "list", no_argument, NULL, 'L',
        "\t\tList all cluster resources with status", pcmk__option_default
    },
    {
        "list-raw", no_argument, NULL, 'l',
        "\t\tList IDs of all instantiated resources (individual members rather "
            "than groups etc.)",
        pcmk__option_default
    },
    {
        "list-cts", no_argument, NULL, 'c',
        NULL, pcmk__option_hidden
    },
    {
        "list-operations", no_argument, NULL, 'O',
        "\tList active resource operations, optionally filtered by --resource "
            "and/or --node",
        pcmk__option_default
    },
    {
        "list-all-operations", no_argument, NULL, 'o',
        "List all resource operations, optionally filtered by --resource "
            "and/or --node",
        pcmk__option_default
    },
    {
        "list-standards", no_argument, NULL, 0,
        "\tList supported standards", pcmk__option_default
    },
    {
        "list-ocf-providers", no_argument, NULL, 0,
        "List all available OCF providers", pcmk__option_default
    },
    {
        "list-agents", required_argument, NULL, 0,
        "List all agents available for the named standard and/or provider",
        pcmk__option_default
    },
    {
        "list-ocf-alternatives", required_argument, NULL, 0,
        "List all available providers for the named OCF agent",
        pcmk__option_default
    },
    {
        "show-metadata", required_argument, NULL, 0,
        "Show the metadata for the named class:provider:agent",
        pcmk__option_default
    },
    {
        "query-xml", no_argument, NULL, 'q',
        "\tShow XML configuration of resource (after any template expansion)",
        pcmk__option_default
    },
    {
        "query-xml-raw", no_argument, NULL, 'w',
        "\tShow XML configuration of resource (before any template expansion)",
        pcmk__option_default
    },
    {
        "get-parameter", required_argument, NULL, 'g',
        "Display named parameter for resource (use instance attribute unless "
            "--meta or --utilization is specified)",
        pcmk__option_default
    },
    {
        "get-property", required_argument, NULL, 'G',
        "Display named property of resource ('class', 'type', or 'provider') "
            "(requires --resource)",
        pcmk__option_hidden
    },
    {
        "locate", no_argument, NULL, 'W',
        "\t\tShow node(s) currently running resource",
        pcmk__option_default
    },
    {
        "stack", no_argument, NULL, 'A',
        "\t\tDisplay the prerequisites and dependents of a resource",
        pcmk__option_default
    },
    {
        "constraints", no_argument, NULL, 'a',
        "\tDisplay the (co)location constraints that apply to a resource",
        pcmk__option_default
    },
    {
        "why", no_argument, NULL, 'Y',
        "\t\tShow why resources are not running, optionally filtered by "
            "--resource and/or --node",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nCommands:", pcmk__option_default
    },
    {
        "validate", no_argument, NULL, 0,
        "\t\tValidate resource configuration by calling agent's validate-all "
            "action. The configuration may be specified either by giving an "
            "existing resource name with -r, or by specifying --class, "
            "--agent, and --provider arguments, along with any number of "
            "--option arguments.",
        pcmk__option_default
    },
    {
        "cleanup", no_argument, NULL, 'C',
        "\t\tIf resource has any past failures, clear its history and "
            "fail count. Optionally filtered by --resource, --node, "
            "--operation, and --interval (otherwise all). --operation and "
            "--interval apply to fail counts, but entire history is always "
            "cleared, to allow current state to be rechecked. If the named "
            "resource is part of a group, or one numbered instance of a clone "
            "or bundled resource, the clean-up applies to the whole collective "
            "resource unless --force is given.",
        pcmk__option_default
    },
    {
        "refresh", no_argument, NULL, 'R',
        "\t\tDelete resource's history (including failures) so its current "
            "state is rechecked. Optionally filtered by --resource and --node "
            "(otherwise all). If the named resource is part of a group, or one "
            "numbered instance of a clone or bundled resource, the clean-up "
            "applies to the whole collective resource unless --force is given.",
        pcmk__option_default
    },
    {
        "set-parameter", required_argument, NULL, 'p',
        "Set named parameter for resource (requires -v). Use instance "
            "attribute unless --meta or --utilization is specified.",
        pcmk__option_default
    },
    {
        "delete-parameter", required_argument, NULL, 'd',
        "Delete named parameter for resource. Use instance attribute unless "
            "--meta or --utilization is specified.",
        pcmk__option_default
    },
    {
        "set-property", required_argument, NULL, 'S',
        "Set named property of resource ('class', 'type', or 'provider') "
            "(requires -r, -t, -v)",
        pcmk__option_hidden
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nResource location:", pcmk__option_default
    },
    {
        "move", no_argument, NULL, 'M',
        "\t\tCreate a constraint to move resource. If --node is specified, the "
            "constraint will be to move to that node, otherwise it will be to "
            "ban the current node. Unless --force is specified, this will "
            "return an error if the resource is already running on the "
            "specified node. If --force is specified, this will always ban the "
            "current node. Optional: --lifetime, --master. NOTE: This may "
            "prevent the resource from running on its previous location until "
            "the implicit constraint expires or is removed with --clear.",
        pcmk__option_default
    },
    {
        "ban", no_argument, NULL, 'B',
        "\t\tCreate a constraint to keep resource off a node. Optional: "
            "--node, --lifetime, --master. NOTE: This will prevent the "
            "resource from running on the affected node until the implicit "
            "constraint expires or is removed with --clear. If --node is not "
            "specified, it defaults to the node currently running the resource "
            "for primitives and groups, or the master for promotable clones "
            "with promoted-max=1 (all other situations result in an error as "
            "there is no sane default).",
        pcmk__option_default
    },
    {
        "clear", no_argument, NULL, 'U',
        "\t\tRemove all constraints created by the --ban and/or --move "
            "commands. Requires: --resource. Optional: --node, --master, "
            "--expired. If --node is not specified, all constraints created "
            "by --ban and --move will be removed for the named resource. If "
            "--node and --force are specified, any constraint created by "
            "--move will be cleared, even if it is not for the specified node. "
            "If --expired is specified, only those constraints whose lifetimes "
            "have expired will be removed.",
        pcmk__option_default
    },
    {
        "expired", no_argument, NULL, 'e',
        "\t\tModifies the --clear argument to remove constraints with "
            "expired lifetimes.",
        pcmk__option_default
    },
    {
        "lifetime", required_argument, NULL, 'u',
        "\tLifespan (as ISO 8601 duration) of created constraints (with -B, "
            "-M) (see https://en.wikipedia.org/wiki/ISO_8601#Durations)",
        pcmk__option_default
    },
    {
        "master", no_argument, NULL, 0,
        "\t\tLimit scope of command to Master role (with -B, -M, -U). For -B "
            "and -M, the previous master may remain active in the Slave role.",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdvanced Commands:", pcmk__option_default
    },
    {
        "delete", no_argument, NULL, 'D',
        "\t\t(Advanced) Delete a resource from the CIB. Required: -t",
        pcmk__option_default
    },
    {
        "fail", no_argument, NULL, 'F',
        "\t\t(Advanced) Tell the cluster this resource has failed",
        pcmk__option_default
    },
    {
        "restart", no_argument, NULL, 0,
        "\t\t(Advanced) Tell the cluster to restart this resource and "
            "anything that depends on it",
        pcmk__option_default
    },
    {
        "wait", no_argument, NULL, 0,
        "\t\t(Advanced) Wait until the cluster settles into a stable state",
        pcmk__option_default
    },
    {
        "force-demote", no_argument, NULL, 0,
        "\t(Advanced) Bypass the cluster and demote a resource on the local "
            "node. Unless --force is specified, this will refuse to do so if "
            "the cluster believes the resource is a clone instance already "
            "running on the local node.",
        pcmk__option_default
    },
    {
        "force-stop", no_argument, NULL, 0,
        "\t(Advanced) Bypass the cluster and stop a resource on the local node",
        pcmk__option_default
    },
    {
        "force-start", no_argument, NULL, 0,
        "\t(Advanced) Bypass the cluster and start a resource on the local "
            "node. Unless --force is specified, this will refuse to do so if "
            "the cluster believes the resource is a clone instance already "
            "running on the local node.",
        pcmk__option_default
    },
    {
        "force-promote", no_argument, NULL, 0,
        "\t(Advanced) Bypass the cluster and promote a resource on the local "
            "node. Unless --force is specified, this will refuse to do so if "
            "the cluster believes the resource is a clone instance already "
            "running on the local node.",
        pcmk__option_default
    },
    {
        "force-check", no_argument, NULL, 0,
        "\t(Advanced) Bypass the cluster and check the state of a resource on "
            "the local node",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nValidate Options:", pcmk__option_default
    },
    {
        "class", required_argument, NULL, 0,
        "\tThe standard the resource agent confirms to (for example, ocf). "
            "Use with --agent, --provider, --option, and --validate.",
        pcmk__option_default
    },
    {
        "agent", required_argument, NULL, 0,
        "\tThe agent to use (for example, IPaddr). Use with --class, "
            "--provider, --option, and --validate.",
        pcmk__option_default
    },
    {
        "provider", required_argument, NULL, 0,
        "\tThe vendor that supplies the resource agent (for example, "
            "heartbeat). Use with --class, --agent, --option, and --validate.",
        pcmk__option_default
    },
    {
        "option", required_argument, NULL, 0,
        "\tSpecify a device configuration parameter as NAME=VALUE (may be "
            "specified multiple times). Use with --validate and without the "
            "-r option.",
        pcmk__option_default
    },
    {
        "-spacer-", no_argument, NULL, '-',
        "\nAdditional Options:", pcmk__option_default
    },
    {
        "node", required_argument, NULL, 'N',
        "\tNode name", pcmk__option_default
    },
    {
        "recursive", no_argument, NULL, 0,
        "\tFollow colocation chains when using --set-parameter",
        pcmk__option_default
    },
    {
        "resource-type", required_argument, NULL, 't',
        "Resource XML element (primitive, group, etc.) (with -D)",
        pcmk__option_default
    },
    {
        "parameter-value", required_argument, NULL, 'v',
        "Value to use with -p", pcmk__option_default
    },
    {
        "meta", no_argument, NULL, 'm',
        "\t\tUse resource meta-attribute instead of instance attribute "
            "(with -p, -g, -d)",
        pcmk__option_default
    },
    {
        "utilization", no_argument, NULL, 'z',
        "\tUse resource utilization attribute instead of instance attribute "
            "(with -p, -g, -d)",
        pcmk__option_default
    },
    {
        "operation", required_argument, NULL, 'n',
        "\tOperation to clear instead of all (with -C -r)",
        pcmk__option_default
    },
    {
        "interval", required_argument, NULL, 'I',
        "\tInterval of operation to clear (default 0) (with -C -r -n)",
        pcmk__option_default
    },
    {
        "set-name", required_argument, NULL, 's',
        "\t(Advanced) XML ID of attributes element to use (with -p, -d)",
        pcmk__option_default
    },
    {
        "nvpair", required_argument, NULL, 'i',
        "\t(Advanced) XML ID of nvpair element to use (with -p, -d)",
        pcmk__option_default
    },
    {
        "timeout", required_argument, NULL, 'T',
        "\t(Advanced) Abort if command does not finish in this time (with "
            "--restart, --wait, --force-*)",
        pcmk__option_default
    },
    {
        "force", no_argument, NULL, 'f',
        "\t\tIf making CIB changes, do so regardless of quorum. See help for "
            "individual commands for additional behavior.",
        pcmk__option_default
    },
    {
        "xml-file", required_argument, NULL, 'x',
        NULL, pcmk__option_hidden
    },

    /* legacy options */
    {
        "host-uname", required_argument, NULL, 'H',
        NULL, pcmk__option_hidden
    },

    {
        "-spacer-", 1, NULL, '-',
        "\nExamples:", pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        "List the available OCF agents:", pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --list-agents ocf", pcmk__option_example
    },
    {
        "-spacer-", 1, NULL, '-',
        "List the available OCF agents from the linux-ha project:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --list-agents ocf:heartbeat", pcmk__option_example
    },
    {
        "-spacer-", 1, NULL, '-',
        "Move 'myResource' to a specific node:", pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --resource myResource --move --node altNode",
        pcmk__option_example
    },
    {
        "-spacer-", 1, NULL, '-',
        "Allow (but not force) 'myResource' to move back to its original "
            "location:",
        pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --resource myResource --clear", pcmk__option_example
    },
    {
        "-spacer-", 1, NULL, '-',
        "Stop 'myResource' (and anything that depends on it):",
        pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --resource myResource --set-parameter target-role "
            "--meta --parameter-value Stopped",
        pcmk__option_example
    },
    {
        "-spacer-", 1, NULL, '-',
        "Tell the cluster not to manage 'myResource' (the cluster will not "
            "attempt to start or stop the resource under any circumstances; "
            "useful when performing maintenance tasks on a resource):",
        pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --resource myResource --set-parameter is-managed "
            "--meta --parameter-value false",
        pcmk__option_example
    },
    {
        "-spacer-", 1, NULL, '-',
        "Erase the operation history of 'myResource' on 'aNode' (the cluster "
            "will 'forget' the existing resource state, including any "
            "errors, and attempt to recover the resource; useful when a "
            "resource had failed permanently and has been repaired "
            "by an administrator):",
        pcmk__option_paragraph
    },
    {
        "-spacer-", 1, NULL, '-',
        " crm_resource --resource myResource --cleanup --node aNode",
        pcmk__option_example
    },
    { 0, 0, 0, 0 }
};


int
main(int argc, char **argv)
{
    char rsc_cmd = 'L';

    const char *v_class = NULL;
    const char *v_agent = NULL;
    const char *v_provider = NULL;
    char *name = NULL;
    char *value = NULL;
    GHashTable *validate_options = NULL;

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
    const char *interval_spec = NULL;
    const char *cib_file = getenv("CIB_file");
    GHashTable *override_params = NULL;

    char *xml_file = NULL;
    xmlNode *cib_xml_copy = NULL;
    resource_t *rsc = NULL;
    bool recursive = FALSE;

    bool validate_cmdline = FALSE; /* whether we are just validating based on command line options */
    bool require_resource = TRUE; /* whether command requires that resource be specified */
    bool require_dataset = TRUE;  /* whether command requires populated dataset instance */
    bool require_crmd = FALSE;    // whether command requires controller connection
    bool clear_expired = FALSE;

    int rc = pcmk_ok;
    int is_ocf_rc = 0;
    int option_index = 0;
    int timeout_ms = 0;
    int argerr = 0;
    int flag;
    int find_flags = 0;           // Flags to use when searching for resource
    crm_exit_t exit_code = CRM_EX_OK;

    crm_log_cli_init("crm_resource");
    pcmk__set_cli_options(NULL, "<query>|<command> [options]", long_options,
                          "perform tasks related to Pacemaker "
                          "cluster resources");

    validate_options = crm_str_table_new();

    while (1) {
        flag = pcmk__next_cli_option(argc, argv, &option_index, &longname);
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
                    find_flags = pe_find_renamed|pe_find_anon;
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
                        for (iter = list; iter != NULL; iter = iter->next) {
                            printf("%s\n", iter->val);
                        }
                        lrmd_list_freeall(list);

                    } else if (optarg) {
                        fprintf(stderr, "No %s found for %s\n", text, optarg);
                        exit_code = CRM_EX_NOSUCH;

                    } else {
                        fprintf(stderr, "No %s found\n", text);
                        exit_code = CRM_EX_NOSUCH;
                    }

                    lrmd_api_delete(lrmd_conn);
                    bye(exit_code);

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
                        rc = -ENXIO;
                    }

                    if (metadata) {
                        printf("%s\n", metadata);
                    } else {
                        fprintf(stderr, "Metadata query for %s failed: %s\n",
                                optarg, pcmk_strerror(rc));
                        exit_code = crm_errno2exit(rc);
                    }
                    lrmd_api_delete(lrmd_conn);
                    bye(exit_code);

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
                        for (iter = list; iter != NULL; iter = iter->next) {
                            printf("%s\n", iter->val);
                        }
                        lrmd_list_freeall(list);
                    } else {
                        fprintf(stderr, "No agents found for standard=%s, provider=%s\n",
                                optarg, (provider? provider : "*"));
                        exit_code = CRM_EX_NOSUCH;
                    }
                    lrmd_api_delete(lrmd_conn);
                    bye(exit_code);

                } else if (safe_str_eq("class", longname)) {
                    if (!(pcmk_get_ra_caps(optarg) & pcmk_ra_cap_params)) {
                        if (BE_QUIET == FALSE) {
                            fprintf(stdout, "Standard %s does not support parameters\n",
                                    optarg);
                        }

                        bye(exit_code);
                    } else {
                        v_class = optarg;
                    }

                    validate_cmdline = TRUE;
                    require_resource = FALSE;

                } else if (safe_str_eq("agent", longname)) {
                    validate_cmdline = TRUE;
                    require_resource = FALSE;
                    v_agent = optarg;

                } else if (safe_str_eq("provider", longname)) {
                    validate_cmdline = TRUE;
                    require_resource = FALSE;
                    v_provider = optarg;

                } else if (safe_str_eq("option", longname)) {
                    crm_info("Scanning: --option %s", optarg);
                    rc = pcmk_scan_nvpair(optarg, &name, &value);
                    if (rc != 2) {
                        fprintf(stderr, "Invalid option: --option %s: %s", optarg, pcmk_strerror(rc));
                        argerr++;
                    } else {
                        crm_info("Got: '%s'='%s'", name, value);
                    }

                    g_hash_table_replace(validate_options, name, value);

                } else {
                    crm_err("Unhandled long option: %s", longname);
                }
                break;
            case 'V':
                resource_verbose++;
                crm_bump_log_level(argc, argv);
                break;
            case '$':
            case '?':
                pcmk__cli_help(flag, CRM_EX_OK);
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
            case 'e':
                clear_expired = TRUE;
                require_resource = FALSE;
                break;

            case 'C':
            case 'R':
                crm_log_args(argc, argv);
                require_resource = FALSE;
                if (cib_file == NULL) {
                    require_crmd = TRUE;
                }
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_anon;
                break;

            case 'n':
                operation = optarg;
                break;

            case 'I':
                interval_spec = optarg;
                break;

            case 'D':
                require_dataset = FALSE;
                crm_log_args(argc, argv);
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_any;
                break;

            case 'F':
                require_crmd = TRUE;
                crm_log_args(argc, argv);
                rsc_cmd = flag;
                break;

            case 'U':
            case 'B':
            case 'M':
                crm_log_args(argc, argv);
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_anon;
                break;

            case 'c':
            case 'L':
            case 'l':
            case 'O':
            case 'o':
                require_resource = FALSE;
                rsc_cmd = flag;
                break;

            case 'Y':
                require_resource = FALSE;
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_anon;
                break;

            case 'q':
            case 'w':
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_any;
                break;

            case 'W':
            case 'A':
            case 'a':
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_anon;
                break;

            case 'S':
                require_dataset = FALSE;
                crm_log_args(argc, argv);
                prop_name = optarg;
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_any;
                break;

            case 'p':
            case 'd':
                crm_log_args(argc, argv);
                prop_name = optarg;
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_any;
                break;

            case 'G':
            case 'g':
                prop_name = optarg;
                rsc_cmd = flag;
                find_flags = pe_find_renamed|pe_find_any;
                break;

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

    // --expired without --clear/-U doesn't make sense
    if (clear_expired == TRUE && rsc_cmd != 'U') {
        CMD_ERR("--expired requires --clear or -U");
        argerr++;
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

    // Sanity check validating from command line parameters.  If everything checks out,
    // go ahead and run the validation.  This way we don't need a CIB connection.
    if (validate_cmdline == TRUE) {
        // -r cannot be used with any of --class, --agent, or --provider
        if (rsc_id != NULL) {
            CMD_ERR("--resource cannot be used with --class, --agent, and --provider");
            argerr++;

        // If --class, --agent, or --provider are given, --validate must also be given.
        } else if (!safe_str_eq(rsc_long_cmd, "validate")) {
            CMD_ERR("--class, --agent, and --provider require --validate");
            argerr++;

        // Not all of --class, --agent, and --provider need to be given.  Not all
        // classes support the concept of a provider.  Check that what we were given
        // is valid.
        } else if (crm_str_eq(v_class, "stonith", TRUE)) {
            if (v_provider != NULL) {
                CMD_ERR("stonith does not support providers");
                argerr++;

            } else if (stonith_agent_exists(v_agent, 0) == FALSE) {
                CMD_ERR("%s is not a known stonith agent", v_agent ? v_agent : "");
                argerr++;
            }

        } else if (resources_agent_exists(v_class, v_provider, v_agent) == FALSE) {
            CMD_ERR("%s:%s:%s is not a known resource",
                    v_class ? v_class : "",
                    v_provider ? v_provider : "",
                    v_agent ? v_agent : "");
            argerr++;
        }

        if (argerr == 0) {
            rc = cli_resource_execute_from_params("test", v_class, v_provider, v_agent,
                                                  "validate-all", validate_options,
                                                  override_params, timeout_ms);
            exit_code = crm_errno2exit(rc);
            bye(exit_code);
        }
    }

    if (argerr) {
        CMD_ERR("Invalid option(s) supplied, use --help for valid usage");
        bye(CRM_EX_USAGE);
    }

    if (do_force) {
        crm_debug("Forcing...");
        cib_options |= cib_quorum_override;
    }

    if (require_resource && !rsc_id) {
        CMD_ERR("Must supply a resource id with -r");
        rc = -ENXIO;
        goto bail;
    }

    if (find_flags && rsc_id) {
        require_dataset = TRUE;
    }

    /* Establish a connection to the CIB manager */
    cib_conn = cib_new();
    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    if (rc != pcmk_ok) {
        CMD_ERR("Error connecting to the CIB manager: %s", pcmk_strerror(rc));
        goto bail;
    }

    /* Populate working set from XML file if specified or CIB query otherwise */
    if (require_dataset) {
        if (xml_file != NULL) {
            cib_xml_copy = filename2xml(xml_file);

        } else {
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
        }

        if(rc != pcmk_ok) {
            goto bail;
        }

        /* Populate the working set instance */
        data_set = pe_new_working_set();
        if (data_set == NULL) {
            rc = -ENOMEM;
            goto bail;
        }
        set_bit(data_set->flags, pe_flag_no_counts);
        set_bit(data_set->flags, pe_flag_no_compat);
        rc = update_working_set_xml(data_set, &cib_xml_copy);
        if (rc != pcmk_ok) {
            goto bail;
        }
        cluster_status(data_set);
    }

    // If command requires that resource exist if specified, find it
    if (find_flags && rsc_id) {
        rsc = pe_find_resource_with_flags(data_set->resources, rsc_id,
                                          find_flags);
        if (rsc == NULL) {
            CMD_ERR("Resource '%s' not found", rsc_id);
            rc = -ENXIO;
            goto bail;
        }
    }

    // Establish a connection to the controller if needed
    if (require_crmd) {
        char *client_uuid;
        pcmk_controld_api_cb_t dispatch_cb = {
            handle_controller_reply, NULL
        };
        pcmk_controld_api_cb_t destroy_cb = {
            handle_controller_drop, NULL
        };


        client_uuid = pcmk__getpid_s();
        controld_api = pcmk_new_controld_api(crm_system_name, client_uuid);
        free(client_uuid);

        rc = controld_api->connect(controld_api, true, &dispatch_cb,
                                   &destroy_cb);
        if (rc != pcmk_rc_ok) {
            CMD_ERR("Error connecting to the controller: %s", pcmk_rc_str(rc));
            rc = pcmk_rc2legacy(rc);
            goto bail;
        }
    }

    /* Handle rsc_cmd appropriately */
    if (rsc_cmd == 'L') {
        rc = pcmk_ok;
        cli_resource_print_list(data_set, FALSE);

    } else if (rsc_cmd == 'l') {
        int found = 0;
        GListPtr lpc = NULL;

        rc = pcmk_ok;
        for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
            rsc = (resource_t *) lpc->data;

            found++;
            cli_resource_print_raw(rsc);
        }

        if (found == 0) {
            printf("NO resources configured\n");
            rc = -ENXIO;
        }

    } else if (rsc_cmd == 0 && rsc_long_cmd && safe_str_eq(rsc_long_cmd, "restart")) {
        /* We don't pass data_set because rsc needs to stay valid for the entire
         * lifetime of cli_resource_restart(), but it will reset and update the
         * working set multiple times, so it needs to use its own copy.
         */
        rc = cli_resource_restart(rsc, host_uname, timeout_ms, cib_conn);

    } else if (rsc_cmd == 0 && rsc_long_cmd && safe_str_eq(rsc_long_cmd, "wait")) {
        rc = wait_till_stable(timeout_ms, cib_conn);

    } else if (rsc_cmd == 0 && rsc_long_cmd) {
        // validate, force-(stop|start|demote|promote|check)
        rc = cli_resource_execute(rsc, rsc_id, rsc_long_cmd, override_params,
                                  timeout_ms, cib_conn, data_set);
        if (rc >= 0) {
            is_ocf_rc = 1;
        }

    } else if (rsc_cmd == 'A' || rsc_cmd == 'a') {
        GListPtr lpc = NULL;
        xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                                   data_set->input);

        unpack_constraints(cib_constraints, data_set);

        // Constraints apply to group/clone, not member/instance
        rsc = uber_parent(rsc);

        for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
            resource_t *r = (resource_t *) lpc->data;

            clear_bit(r->flags, pe_rsc_allocating);
        }

        cli_resource_print_colocation(rsc, TRUE, rsc_cmd == 'A', 1);

        fprintf(stdout, "* %s\n", rsc->id);
        cli_resource_print_location(rsc, NULL);

        for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
            resource_t *r = (resource_t *) lpc->data;

            clear_bit(r->flags, pe_rsc_allocating);
        }

        cli_resource_print_colocation(rsc, FALSE, rsc_cmd == 'A', 1);

    } else if (rsc_cmd == 'c') {
        GListPtr lpc = NULL;

        rc = pcmk_ok;
        for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
            rsc = (resource_t *) lpc->data;
            cli_resource_print_cts(rsc);
        }
        cli_resource_print_cts_constraints(data_set);

    } else if (rsc_cmd == 'F') {
        rc = cli_resource_fail(controld_api, host_uname, rsc_id, data_set);
        if (rc == pcmk_rc_ok) {
            start_mainloop(controld_api);
        }
        rc = pcmk_rc2legacy(rc);

    } else if (rsc_cmd == 'O') {
        rc = cli_resource_print_operations(rsc_id, host_uname, TRUE, data_set);

    } else if (rsc_cmd == 'o') {
        rc = cli_resource_print_operations(rsc_id, host_uname, FALSE, data_set);

    } else if (rsc_cmd == 'W') {
        rc = cli_resource_search(rsc, rsc_id, data_set);
        if (rc >= 0) {
            rc = pcmk_ok;
        }

    } else if (rsc_cmd == 'q') {
        rc = cli_resource_print(rsc, data_set, TRUE);

    } else if (rsc_cmd == 'w') {
        rc = cli_resource_print(rsc, data_set, FALSE);

    } else if (rsc_cmd == 'Y') {
        node_t *dest = NULL;

        if (host_uname) {
            dest = pe_find_node(data_set->nodes, host_uname);
            if (dest == NULL) {
                rc = -pcmk_err_node_unknown;
                goto bail;
            }
        }
        cli_resource_why(cib_conn, data_set->resources, rsc, dest);
        rc = pcmk_ok;

    } else if (rsc_cmd == 'U') {
        GListPtr before = NULL;
        GListPtr after = NULL;
        GListPtr remaining = NULL;
        GListPtr ele = NULL;
        node_t *dest = NULL;

        if (BE_QUIET == FALSE) {
            before = build_constraint_list(data_set->input);
        }

        if (clear_expired == TRUE) {
            rc = cli_resource_clear_all_expired(data_set->input, cib_conn, rsc_id, host_uname, scope_master);

        } else if (host_uname) {
            dest = pe_find_node(data_set->nodes, host_uname);
            if (dest == NULL) {
                rc = -pcmk_err_node_unknown;
                if (BE_QUIET == FALSE) {
                    g_list_free(before);
                }
                goto bail;
            }
            rc = cli_resource_clear(rsc_id, dest->details->uname, NULL, cib_conn, TRUE);

        } else {
            rc = cli_resource_clear(rsc_id, NULL, data_set->nodes, cib_conn, TRUE);
        }

        if (BE_QUIET == FALSE) {
            rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml_copy, cib_scope_local | cib_sync_call);
            if (rc != pcmk_ok) {
                CMD_ERR("Could not get modified CIB: %s\n", pcmk_strerror(rc));
                g_list_free(before);
                goto bail;
            }

            data_set->input = cib_xml_copy;
            cluster_status(data_set);

            after = build_constraint_list(data_set->input);
            remaining = subtract_lists(before, after, (GCompareFunc) strcmp);

            for (ele = remaining; ele != NULL; ele = ele->next) {
                printf("Removing constraint: %s\n", (char *) ele->data);
            }

            g_list_free(before);
            g_list_free(after);
            g_list_free(remaining);
        }

    } else if (rsc_cmd == 'M' && host_uname) {
        rc = cli_resource_move(rsc, rsc_id, host_uname, cib_conn, data_set);

    } else if (rsc_cmd == 'B' && host_uname) {
        node_t *dest = pe_find_node(data_set->nodes, host_uname);

        if (dest == NULL) {
            rc = -pcmk_err_node_unknown;
            goto bail;
        }
        rc = cli_resource_ban(rsc_id, dest->details->uname, NULL, cib_conn);

    } else if (rsc_cmd == 'B' || rsc_cmd == 'M') {
        pe_node_t *current = NULL;
        unsigned int nactive = 0;

        current = pe__find_active_requires(rsc, &nactive);

        if (nactive == 1) {
            rc = cli_resource_ban(rsc_id, current->details->uname, NULL, cib_conn);

        } else if (is_set(rsc->flags, pe_rsc_promotable)) {
            int count = 0;
            GListPtr iter = NULL;

            current = NULL;
            for(iter = rsc->children; iter; iter = iter->next) {
                resource_t *child = (resource_t *)iter->data;
                enum rsc_role_e child_role = child->fns->state(child, TRUE);

                if(child_role == RSC_ROLE_MASTER) {
                    count++;
                    current = pe__current_node(child);
                }
            }

            if(count == 1 && current) {
                rc = cli_resource_ban(rsc_id, current->details->uname, NULL, cib_conn);

            } else {
                rc = -EINVAL;
                exit_code = CRM_EX_USAGE;
                CMD_ERR("Resource '%s' not moved: active in %d locations (promoted in %d).",
                        rsc_id, nactive, count);
                CMD_ERR("To prevent '%s' from running on a specific location, "
                        "specify a node.", rsc_id);
                CMD_ERR("To prevent '%s' from being promoted at a specific "
                        "location, specify a node and the master option.",
                        rsc_id);
            }

        } else {
            rc = -EINVAL;
            exit_code = CRM_EX_USAGE;
            CMD_ERR("Resource '%s' not moved: active in %d locations.", rsc_id, nactive);
            CMD_ERR("To prevent '%s' from running on a specific location, "
                    "specify a node.", rsc_id);
        }

    } else if (rsc_cmd == 'G') {
        rc = cli_resource_print_property(rsc, prop_name, data_set);

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
        rc = cli_resource_print_attribute(rsc, prop_name, data_set);

    } else if (rsc_cmd == 'p') {
        if (prop_value == NULL || strlen(prop_value) == 0) {
            CMD_ERR("You need to supply a value with the -v option");
            rc = -EINVAL;
            goto bail;
        }

        /* coverity[var_deref_model] False positive */
        rc = cli_resource_update_attribute(rsc, rsc_id, prop_set, prop_id,
                                           prop_name, prop_value, recursive,
                                           cib_conn, data_set);

    } else if (rsc_cmd == 'd') {
        /* coverity[var_deref_model] False positive */
        rc = cli_resource_delete_attribute(rsc, rsc_id, prop_set, prop_id,
                                           prop_name, cib_conn, data_set);

    } else if ((rsc_cmd == 'C') && rsc) {
        if (do_force == FALSE) {
            rsc = uber_parent(rsc);
        }

        crm_debug("Erasing failures of %s (%s requested) on %s",
                  rsc->id, rsc_id, (host_uname? host_uname: "all nodes"));
        rc = cli_resource_delete(controld_api, host_uname, rsc, operation,
                                 interval_spec, TRUE, data_set);

        if ((rc == pcmk_ok) && !BE_QUIET) {
            // Show any reasons why resource might stay stopped
            cli_resource_check(cib_conn, rsc);
        }

        if (rc == pcmk_ok) {
            start_mainloop(controld_api);
        }

    } else if (rsc_cmd == 'C') {
        rc = cli_cleanup_all(controld_api, host_uname, operation, interval_spec,
                             data_set);
        if (rc == pcmk_ok) {
            start_mainloop(controld_api);
        }

    } else if ((rsc_cmd == 'R') && rsc) {
        if (do_force == FALSE) {
            rsc = uber_parent(rsc);
        }

        crm_debug("Re-checking the state of %s (%s requested) on %s",
                  rsc->id, rsc_id, (host_uname? host_uname: "all nodes"));
        rc = cli_resource_delete(controld_api, host_uname, rsc, NULL, 0, FALSE,
                                 data_set);

        if ((rc == pcmk_ok) && !BE_QUIET) {
            // Show any reasons why resource might stay stopped
            cli_resource_check(cib_conn, rsc);
        }

        if (rc == pcmk_ok) {
            start_mainloop(controld_api);
        }

    } else if (rsc_cmd == 'R') {
        const char *router_node = host_uname;
        int attr_options = pcmk__node_attr_none;

        if (host_uname) {
            node_t *node = pe_find_node(data_set->nodes, host_uname);

            if (pe__is_guest_or_remote_node(node)) {
                node = pe__current_node(node->details->remote_rsc);
                if (node == NULL) {
                    CMD_ERR("No cluster connection to Pacemaker Remote node %s detected",
                            host_uname);
                    rc = -ENXIO;
                    goto bail;
                }
                router_node = node->details->uname;
                attr_options |= pcmk__node_attr_remote;
            }
        }

        if (controld_api == NULL) {
            printf("Dry run: skipping clean-up of %s due to CIB_file\n",
                   host_uname? host_uname : "all nodes");
            rc = pcmk_ok;
            goto bail;
        }

        crm_debug("Re-checking the state of all resources on %s", host_uname?host_uname:"all nodes");

        rc = pcmk_rc2legacy(pcmk__node_attr_request_clear(NULL, host_uname,
                                                          NULL, NULL, NULL,
                                                          NULL, attr_options));

        if (controld_api->reprobe(controld_api, host_uname,
                                  router_node) == pcmk_rc_ok) {
            start_mainloop(controld_api);
        }

    } else if (rsc_cmd == 'D') {
        xmlNode *msg_data = NULL;

        if (rsc_type == NULL) {
            CMD_ERR("You need to specify a resource type with -t");
            rc = -ENXIO;
            goto bail;
        }

        msg_data = create_xml_node(NULL, rsc_type);
        crm_xml_add(msg_data, XML_ATTR_ID, rsc_id);

        rc = cib_conn->cmds->remove(cib_conn, XML_CIB_TAG_RESOURCES, msg_data, cib_options);
        free_xml(msg_data);

    } else {
        CMD_ERR("Unknown command: %c", rsc_cmd);
    }

  bail:

    if (is_ocf_rc) {
        exit_code = rc;

    } else if (rc != pcmk_ok) {
        CMD_ERR("Error performing operation: %s", pcmk_strerror(rc));
        if (rc == -pcmk_err_no_quorum) {
            CMD_ERR("To ignore quorum, use the force option");
        }
        if (exit_code == CRM_EX_OK) {
            exit_code = crm_errno2exit(rc);
        }
    }

    bye(exit_code);
}

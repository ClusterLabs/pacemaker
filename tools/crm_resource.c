/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_resource.h>
#include <crm/common/cmdline_internal.h>
#include <pacemaker-internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/common/ipc_controld.h>

#define SUMMARY "crm_resource - perform tasks related to Pacemaker cluster resources"

struct {
    const char *attr_set_type;
    int cib_options;
    gboolean clear_expired;
    char *extra_arg;
    char *extra_option;
    int find_flags;             /* Flags to use when searching for resource */
    gboolean force;
    char *host_uname;
    char *interval_spec;
    char *operation;
    GHashTable *override_params;
    char *prop_id;
    char *prop_name;
    char *prop_set;
    char *prop_value;
    gboolean recursive;
    gchar **remainder;
    gboolean require_crmd;          /* whether command requires controller connection */
    gboolean require_dataset;       /* whether command requires populated dataset instance */
    gboolean require_resource;      /* whether command requires that resource be specified */
    int resource_verbose;
    char rsc_cmd;
    char *rsc_id;
    char *rsc_long_cmd;
    char *rsc_type;
    gboolean promoted_role_only;
    int timeout_ms;
    char *v_agent;
    char *v_class;
    char *v_provider;
    gboolean validate_cmdline;      /* whether we are just validating based on command line options */
    GHashTable *validate_options;
    char *xml_file;
} options = {
    .attr_set_type = XML_TAG_ATTR_SETS,
    .cib_options = cib_sync_call,
    .require_dataset = TRUE,
    .require_resource = TRUE,
    .rsc_cmd = 'L'
};

gboolean agent_provider_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean attr_set_type_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean class_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean cleanup_refresh_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean delete_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean expired_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean extra_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean flag_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean get_param_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean list_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean set_delete_param_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean set_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean timeout_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean validate_restart_force_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean wait_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean why_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

bool BE_QUIET = FALSE;
static crm_exit_t exit_code = CRM_EX_OK;

// Things that should be cleaned up on exit
static GError *error = NULL;
static GMainLoop *mainloop = NULL;
static cib_t *cib_conn = NULL;
static pcmk_ipc_api_t *controld_api = NULL;
static pe_working_set_t *data_set = NULL;

#define MESSAGE_TIMEOUT_S 60

#define INDENT "                                    "

// Clean up and exit
static crm_exit_t
bye(crm_exit_t ec)
{
    if (error != NULL) {
        fprintf(stderr, "%s\n", error->message);
        g_clear_error(&error);
    }

    if (cib_conn != NULL) {
        cib_t *save_cib_conn = cib_conn;

        cib_conn = NULL; // Ensure we can't free this twice
        save_cib_conn->cmds->signoff(save_cib_conn);
        cib_delete(save_cib_conn);
    }
    if (controld_api != NULL) {
        pcmk_ipc_api_t *save_controld_api = controld_api;

        controld_api = NULL; // Ensure we can't free this twice
        pcmk_free_ipc_api(save_controld_api);
    }
    if (mainloop != NULL) {
        g_main_loop_unref(mainloop);
        mainloop = NULL;
    }
    pe_free_working_set(data_set);
    data_set = NULL;
    crm_exit(ec);
    return ec;
}

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

static gboolean
resource_ipc_timeout(gpointer data)
{
    // Start with newline because "Waiting for ..." message doesn't have one
    if (error != NULL) {
        g_clear_error(&error);
    }

    g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_TIMEOUT,
                "\nAborting because no messages received in %d seconds", MESSAGE_TIMEOUT_S);

    quit_main_loop(CRM_EX_TIMEOUT);
    return FALSE;
}

static void
controller_event_callback(pcmk_ipc_api_t *api, enum pcmk_ipc_event event_type,
                          crm_exit_t status, void *event_data, void *user_data)
{
    switch (event_type) {
        case pcmk_ipc_event_disconnect:
            if (exit_code == CRM_EX_DISCONNECT) { // Unexpected
                crm_info("Connection to controller was terminated");
            }
            quit_main_loop(exit_code);
            break;

        case pcmk_ipc_event_reply:
            if (status != CRM_EX_OK) {
                fprintf(stderr, "\nError: bad reply from controller: %s\n",
                        crm_exit_str(status));
                pcmk_disconnect_ipc(api);
                quit_main_loop(status);
            } else {
                fprintf(stderr, ".");
                if ((pcmk_controld_api_replies_expected(api) == 0)
                    && mainloop && g_main_loop_is_running(mainloop)) {
                    fprintf(stderr, " OK\n");
                    crm_debug("Got all the replies we expected");
                    pcmk_disconnect_ipc(api);
                    quit_main_loop(CRM_EX_OK);
                }
            }
            break;

        default:
            break;
    }
}

static void
start_mainloop(pcmk_ipc_api_t *capi)
{
    unsigned int count = pcmk_controld_api_replies_expected(capi);

    if (count > 0) {
        fprintf(stderr, "Waiting for %d %s from the controller",
                count, pcmk__plural_alt(count, "reply", "replies"));
        exit_code = CRM_EX_DISCONNECT; // For unexpected disconnects
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

static GOptionEntry query_entries[] = {
    { "list", 'L', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, list_cb,
      "List all cluster resources with status",
      NULL },
    { "list-raw", 'l', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, list_cb,
      "List IDs of all instantiated resources (individual members\n"
      INDENT "rather than groups etc.)",
      NULL },
    { "list-cts", 'c', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, list_cb,
      NULL,
      NULL },
    { "list-operations", 'O', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, list_cb,
      "List active resource operations, optionally filtered by\n"
      INDENT "--resource and/or --node",
      NULL },
    { "list-all-operations", 'o', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, list_cb,
      "List all resource operations, optionally filtered by\n"
      INDENT "--resource and/or --node",
      NULL },
    { "list-standards", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, extra_cb,
      "List supported standards",
      NULL },
    { "list-ocf-providers", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, extra_cb,
      "List all available OCF providers",
      NULL },
    { "list-agents", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, extra_cb,
      "List all agents available for the named standard and/or provider",
      "STD/PROV" },
    { "list-ocf-alternatives", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, extra_cb,
      "List all available providers for the named OCF agent",
      "AGENT" },
    { "show-metadata", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, extra_cb,
      "Show the metadata for the named class:provider:agent",
      "SPEC" },
    { "query-xml", 'q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Show XML configuration of resource (after any template expansion)",
      NULL },
    { "query-xml-raw", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Show XML configuration of resource (before any template expansion)",
      NULL },
    { "get-parameter", 'g', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, get_param_prop_cb,
      "Display named parameter for resource (use instance attribute\n"
      INDENT "unless --meta or --utilization is specified)",
      "PARAM" },
    { "get-property", 'G', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, get_param_prop_cb,
      "Display named property of resource ('class', 'type', or 'provider') "
      "(requires --resource)",
      "PROPERTY" },
    { "locate", 'W', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Show node(s) currently running resource",
      NULL },
    { "stack", 'A', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Display the prerequisites and dependents of a resource",
      NULL },
    { "constraints", 'a', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Display the (co)location constraints that apply to a resource",
      NULL },
    { "why", 'Y', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, why_cb,
      "Show why resources are not running, optionally filtered by\n"
      INDENT "--resource and/or --node",
      NULL },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "validate", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "Validate resource configuration by calling agent's validate-all\n"
      INDENT "action. The configuration may be specified either by giving an\n"
      INDENT "existing resource name with -r, or by specifying --class,\n"
      INDENT "--agent, and --provider arguments, along with any number of\n"
      INDENT "--option arguments.",
      NULL },
    { "cleanup", 'C', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, cleanup_refresh_cb,
      "If resource has any past failures, clear its history and fail\n"
      INDENT "count. Optionally filtered by --resource, --node, --operation\n"
      INDENT "and --interval (otherwise all). --operation and --interval\n"
      INDENT "apply to fail counts, but entire history is always clear, to\n"
      INDENT "allow current state to be rechecked. If the named resource is\n"
      INDENT "part of a group, or one numbered instance of a clone or bundled\n"
      INDENT "resource, the clean-up applies to the whole collective resource\n"
      INDENT "unless --force is given.",
      NULL },
    { "refresh", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, cleanup_refresh_cb,
      "Delete resource's history (including failures) so its current state\n"
      INDENT "is rechecked. Optionally filtered by --resource and --node\n"
      INDENT "(otherwise all). If the named resource is part of a group, or one\n"
      INDENT "numbered instance of a clone or bundled resource, the refresh\n"
      INDENT "applies to the whole collective resource unless --force is given.",
      NULL },
    { "set-parameter", 'p', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, set_delete_param_cb,
      "Set named parameter for resource (requires -v). Use instance\n"
      INDENT "attribute unless --meta or --utilization is specified.",
      "PARAM" },
    { "delete-parameter", 'd', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, set_delete_param_cb,
      "Delete named parameter for resource. Use instance attribute\n"
      INDENT "unless --meta or --utilization is specified.",
      "PARAM" },
    { "set-property", 'S', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_CALLBACK, set_prop_cb,
      "Set named property of resource ('class', 'type', or 'provider') "
      "(requires -r, -t, -v)",
      "PROPERTY" },

    { NULL }
};

static GOptionEntry location_entries[] = {
    { "move", 'M', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Create a constraint to move resource. If --node is specified,\n"
      INDENT "the constraint will be to move to that node, otherwise it\n"
      INDENT "will be to ban the current node. Unless --force is specified\n"
      INDENT "this will return an error if the resource is already running\n"
      INDENT "on the specified node. If --force is specified, this will\n"
      INDENT "always ban the current node.\n"
      INDENT "Optional: --lifetime, --master. NOTE: This may prevent the\n"
      INDENT "resource from running on its previous location until the\n"
      INDENT "implicit constraint expires or is removed with --clear.",
      NULL },
    { "ban", 'B', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Create a constraint to keep resource off a node.\n"
      INDENT "Optional: --node, --lifetime, --master.\n"
      INDENT "NOTE: This will prevent the resource from running on the\n"
      INDENT "affected node until the implicit constraint expires or is\n"
      INDENT "removed with --clear. If --node is not specified, it defaults\n"
      INDENT "to the node currently running the resource for primitives\n"
      INDENT "and groups, or the master for promotable clones with\n"
      INDENT "promoted-max=1 (all other situations result in an error as\n"
      INDENT "there is no sane default).",
      NULL },
    { "clear", 'U', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Remove all constraints created by the --ban and/or --move\n"
      INDENT "commands. Requires: --resource. Optional: --node, --master,\n"
      INDENT "--expired. If --node is not specified, all constraints created\n"
      INDENT "by --ban and --move will be removed for the named resource. If\n"
      INDENT "--node and --force are specified, any constraint created by\n"
      INDENT "--move will be cleared, even if it is not for the specified\n"
      INDENT "node. If --expired is specified, only those constraints whose\n"
      INDENT "lifetimes have expired will be removed.",
      NULL },
    { "expired", 'e', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, expired_cb,
      "Modifies the --clear argument to remove constraints with\n"
      INDENT "expired lifetimes.",
      NULL },
    { "lifetime", 'u', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &move_lifetime,
      "Lifespan (as ISO 8601 duration) of created constraints (with\n"
      INDENT "-B, -M) see https://en.wikipedia.org/wiki/ISO_8601#Durations)",
      "TIMESPEC" },
    { "master", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.promoted_role_only,
      "Limit scope of command to Master role (with -B, -M, -U). For\n"
      INDENT "-B and -M the previous master may remain active in the Slave role.",
      NULL },

    { NULL }
};

static GOptionEntry advanced_entries[] = {
    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, delete_cb,
      "(Advanced) Delete a resource from the CIB. Required: -t",
      NULL },
    { "fail", 'F', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, fail_cb,
      "(Advanced) Tell the cluster this resource has failed",
      NULL },
    { "restart", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "(Advanced) Tell the cluster to restart this resource and\n"
      INDENT "anything that depends on it",
      NULL },
    { "wait", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, wait_cb,
      "(Advanced) Wait until the cluster settles into a stable state",
      NULL },
    { "force-demote", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "(Advanced) Bypass the cluster and demote a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-stop", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "(Advanced) Bypass the cluster and stop a resource on the local node",
      NULL },
    { "force-start", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "(Advanced) Bypass the cluster and start a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-promote", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "(Advanced) Bypass the cluster and promote a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-check", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, validate_restart_force_cb,
      "(Advanced) Bypass the cluster and check the state of a resource on\n"
      INDENT "the local node",
      NULL },

    { NULL }
};

static GOptionEntry validate_entries[] = {
    { "class", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, class_cb,
      "The standard the resource agent confirms to (for example, ocf).\n"
      INDENT "Use with --agent, --provider, --option, and --validate.",
      "CLASS" },
    { "agent", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, agent_provider_cb,
      "The agent to use (for example, IPaddr). Use with --class,\n"
      INDENT "--provider, --option, and --validate.",
      "AGENT" },
    { "provider", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, agent_provider_cb,
      "The vendor that supplies the resource agent (for example,\n"
      INDENT "heartbeat). Use with --class, --agent, --option, and --validate.",
      "PROVIDER" },
    { "option", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, extra_cb,
      "Specify a device configuration parameter as NAME=VALUE (may be\n"
      INDENT "specified multiple times). Use with --validate and without the\n"
      INDENT "-r option.",
      "PARAM" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "node", 'N', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.host_uname,
      "Node name",
      "NAME" },
    { "recursive", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.recursive,
      "Follow colocation chains when using --set-parameter",
      NULL },
    { "resource-type", 't', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.rsc_type,
      "Resource XML element (primitive, group, etc.) (with -D)",
      "ELEMENT" },
    { "parameter-value", 'v', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.prop_value,
      "Value to use with -p",
      "PARAM" },
    { "meta", 'm', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, attr_set_type_cb,
      "Use resource meta-attribute instead of instance attribute\n"
      INDENT "(with -p, -g, -d)",
      NULL },
    { "utilization", 'z', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, attr_set_type_cb,
      "Use resource utilization attribute instead of instance attribute\n"
      INDENT "(with -p, -g, -d)",
      NULL },
    { "operation", 'n', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.operation,
      "Operation to clear instead of all (with -C -r)",
      "OPERATION" },
    { "interval", 'I', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.interval_spec,
      "Interval of operation to clear (default 0) (with -C -r -n)",
      "N" },
    { "set-name", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.prop_set,
      "(Advanced) XML ID of attributes element to use (with -p, -d)",
      "ID" },
    { "nvpair", 'i', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.prop_id,
      "(Advanced) XML ID of nvpair element to use (with -p, -d)",
      "ID" },
    { "timeout", 'T', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, timeout_cb,
      "(Advanced) Abort if command does not finish in this time (with\n"
      INDENT "--restart, --wait, --force-*)",
      "N" },
    { "force", 'f', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.force,
      "If making CIB changes, do so regardless of quorum. See help for\n"
      INDENT "individual commands for additional behavior.",
      NULL },
    { "xml-file", 'x', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &options.xml_file,
      NULL,
      "FILE" },
    { "host-uname", 'H', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.host_uname,
      NULL,
      "HOST" },

    { NULL }
};

gboolean
agent_provider_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.validate_cmdline = TRUE;
    options.require_resource = FALSE;

    if(pcmk__str_eq(option_name, "--provider", pcmk__str_casei) == TRUE) {
        if (options.v_provider) {
           free(options.v_provider);
        }
        options.v_provider = strdup(optarg);
    } else {
        if (options.v_agent) {
           free(options.v_agent);
        }
        options.v_agent = strdup(optarg);
    }

    return TRUE;
}

gboolean
attr_set_type_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (crm_str_eq(option_name, "-m", TRUE) || crm_str_eq(option_name, "--meta", TRUE)) {
        options.attr_set_type = XML_TAG_META_SETS;
    } else if (crm_str_eq(option_name, "-z", TRUE) || crm_str_eq(option_name, "--utilization", TRUE)) {
        options.attr_set_type = XML_TAG_UTILIZATION;
    }

    return TRUE;
}

gboolean
class_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (!(pcmk_get_ra_caps(optarg) & pcmk_ra_cap_params)) {
        if (BE_QUIET == FALSE) {
            g_set_error(error, G_OPTION_ERROR, CRM_EX_INVALID_PARAM,
                        "Standard %s does not support parameters\n", optarg);
        }
        return FALSE;

    } else {
        if (options.v_class != NULL) {
            free(options.v_class);
        }

        options.v_class = strdup(optarg);
    }

    options.validate_cmdline = TRUE;
    options.require_resource = FALSE;
    return TRUE;
}

gboolean
cleanup_refresh_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (crm_str_eq(option_name, "-C", TRUE) || crm_str_eq(option_name, "--cleanup", TRUE)) {
        options.rsc_cmd = 'C';
    } else {
        options.rsc_cmd = 'R';
    }

    options.require_resource = FALSE;
    if (getenv("CIB_file") == NULL) {
        options.require_crmd = TRUE;
    }
    options.find_flags = pe_find_renamed|pe_find_anon;
    return TRUE;
}

gboolean
delete_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.require_dataset = FALSE;
    options.rsc_cmd = 'D';
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
expired_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.clear_expired = TRUE;
    options.require_resource = FALSE;
    return TRUE;
}

gboolean
extra_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (options.extra_option) {
        free(options.extra_option);
    }

    if (options.extra_arg) {
        free(options.extra_arg);
    }

    options.extra_option = strdup(option_name);

    if (optarg) {
        options.extra_arg = strdup(optarg);
    }

    return TRUE;
}

gboolean
fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.require_crmd = TRUE;
    options.rsc_cmd = 'F';
    return TRUE;
}

gboolean
flag_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (crm_str_eq(option_name, "-U", TRUE) || crm_str_eq(option_name, "--clear", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_anon;
        options.rsc_cmd = 'U';
    } else if (crm_str_eq(option_name, "-B", TRUE) || crm_str_eq(option_name, "--ban", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_anon;
        options.rsc_cmd = 'B';
    } else if (crm_str_eq(option_name, "-M", TRUE) || crm_str_eq(option_name, "--move", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_anon;
        options.rsc_cmd = 'M';
    } else if (crm_str_eq(option_name, "-q", TRUE) || crm_str_eq(option_name, "--query-xml", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_any;
        options.rsc_cmd = 'q';
    } else if (crm_str_eq(option_name, "-w", TRUE) || crm_str_eq(option_name, "--query-xml-raw", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_any;
        options.rsc_cmd = 'w';
    } else if (crm_str_eq(option_name, "-W", TRUE) || crm_str_eq(option_name, "--locate", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_anon;
        options.rsc_cmd = 'W';
    } else if (crm_str_eq(option_name, "-A", TRUE) || crm_str_eq(option_name, "--stack", TRUE)) {
        options.find_flags = pe_find_renamed|pe_find_anon;
        options.rsc_cmd = 'A';
    } else {
        options.find_flags = pe_find_renamed|pe_find_anon;
        options.rsc_cmd = 'a';
    }

    return TRUE;
}

gboolean
get_param_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (crm_str_eq(option_name, "-g", TRUE) || crm_str_eq(option_name, "--get-parameter", TRUE)) {
        options.rsc_cmd = 'g';
    } else {
        options.rsc_cmd = 'G';
    }

    if (options.prop_name) {
        free(options.prop_name);
    }

    options.prop_name = strdup(optarg);
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
list_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (crm_str_eq(option_name, "-c", TRUE) || crm_str_eq(option_name, "--list-cts", TRUE)) {
        options.rsc_cmd = 'c';
    } else if (crm_str_eq(option_name, "-L", TRUE) || crm_str_eq(option_name, "--list", TRUE)) {
        options.rsc_cmd = 'L';
    } else if (crm_str_eq(option_name, "-l", TRUE) || crm_str_eq(option_name, "--list-raw", TRUE)) {
        options.rsc_cmd = 'l';
    } else if (crm_str_eq(option_name, "-O", TRUE) || crm_str_eq(option_name, "--list-operations", TRUE)) {
        options.rsc_cmd = 'O';
    } else {
        options.rsc_cmd = 'o';
    }

    options.require_resource = FALSE;
    return TRUE;
}

gboolean
set_delete_param_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (crm_str_eq(option_name, "-p", TRUE) || crm_str_eq(option_name, "--set-parameter", TRUE)) {
        options.rsc_cmd = 'p';
    } else {
        options.rsc_cmd = 'd';
    }

    if (options.prop_name) {
        free(options.prop_name);
    }

    options.prop_name = strdup(optarg);
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
set_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.require_dataset = FALSE;

    if (options.prop_name) {
        free(options.prop_name);
    }

    options.prop_name = strdup(optarg);
    options.rsc_cmd = 'S';
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
timeout_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.timeout_ms = crm_get_msec(optarg);
    return TRUE;
}

gboolean
validate_restart_force_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.rsc_cmd = 0;
    if (options.rsc_long_cmd) {
        free(options.rsc_long_cmd);
    }
    options.rsc_long_cmd = strdup(option_name+2);
    options.find_flags = pe_find_renamed|pe_find_anon;
    return TRUE;
}

gboolean
wait_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.rsc_cmd = 0;
    if (options.rsc_long_cmd) {
        free(options.rsc_long_cmd);
    }
    options.rsc_long_cmd = strdup("wait");
    options.require_resource = FALSE;
    options.require_dataset = FALSE;
    return TRUE;
}

gboolean
why_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.require_resource = FALSE;
    options.rsc_cmd = 'Y';
    options.find_flags = pe_find_renamed|pe_find_anon;
    return TRUE;
}

static int
ban_or_move(pe_resource_t *rsc, crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    pe_node_t *current = NULL;
    unsigned int nactive = 0;

    current = pe__find_active_requires(rsc, &nactive);

    if (nactive == 1) {
        rc = cli_resource_ban(options.rsc_id, current->details->uname, NULL,
                              cib_conn, options.cib_options, options.promoted_role_only);

    } else if (is_set(rsc->flags, pe_rsc_promotable)) {
        int count = 0;
        GListPtr iter = NULL;

        current = NULL;
        for(iter = rsc->children; iter; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *)iter->data;
            enum rsc_role_e child_role = child->fns->state(child, TRUE);

            if(child_role == RSC_ROLE_MASTER) {
                count++;
                current = pe__current_node(child);
            }
        }

        if(count == 1 && current) {
            rc = cli_resource_ban(options.rsc_id, current->details->uname, NULL,
                                  cib_conn, options.cib_options, options.promoted_role_only);

        } else {
            rc = EINVAL;
            *exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, *exit_code,
                        "Resource '%s' not moved: active in %d locations (promoted in %d).\n"
                        "To prevent '%s' from running on a specific location, "
                        "specify a node."
                        "To prevent '%s' from being promoted at a specific "
                        "location, specify a node and the master option.",
                        options.rsc_id, nactive, count, options.rsc_id, options.rsc_id);
        }

    } else {
        rc = EINVAL;
        *exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, *exit_code,
                    "Resource '%s' not moved: active in %d locations.\n"
                    "To prevent '%s' from running on a specific location, "
                    "specify a node.",
                    options.rsc_id, nactive, options.rsc_id);
    }

    return rc;
}

static void
cleanup(pe_resource_t *rsc)
{
    int rc = pcmk_rc_ok;

    if (options.force == FALSE) {
        rsc = uber_parent(rsc);
    }

    crm_debug("Erasing failures of %s (%s requested) on %s",
              rsc->id, options.rsc_id, (options.host_uname? options.host_uname: "all nodes"));
    rc = cli_resource_delete(controld_api, options.host_uname, rsc, options.operation,
                             options.interval_spec, TRUE, data_set, options.force);

    if ((rc == pcmk_rc_ok) && !BE_QUIET) {
        // Show any reasons why resource might stay stopped
        cli_resource_check(cib_conn, rsc);
    }

    if (rc == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }
}

static int
clear_constraints(xmlNodePtr *cib_xml_copy)
{
    GListPtr before = NULL;
    GListPtr after = NULL;
    GListPtr remaining = NULL;
    GListPtr ele = NULL;
    pe_node_t *dest = NULL;
    int rc = pcmk_rc_ok;

    if (BE_QUIET == FALSE) {
        before = build_constraint_list(data_set->input);
    }

    if (options.clear_expired) {
        rc = cli_resource_clear_all_expired(data_set->input, cib_conn, options.cib_options,
                                            options.rsc_id, options.host_uname,
                                            options.promoted_role_only);

    } else if (options.host_uname) {
        dest = pe_find_node(data_set->nodes, options.host_uname);
        if (dest == NULL) {
            rc = pcmk_rc_node_unknown;
            if (BE_QUIET == FALSE) {
                g_list_free(before);
            }
            return rc;
        }
        rc = cli_resource_clear(options.rsc_id, dest->details->uname, NULL,
                                cib_conn, options.cib_options, TRUE, options.force);

    } else {
        rc = cli_resource_clear(options.rsc_id, NULL, data_set->nodes,
                                cib_conn, options.cib_options, TRUE, options.force);
    }

    if (BE_QUIET == FALSE) {
        rc = cib_conn->cmds->query(cib_conn, NULL, cib_xml_copy, cib_scope_local | cib_sync_call);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not get modified CIB: %s\n", pcmk_strerror(rc));
            g_list_free(before);
            return rc;
        }

        data_set->input = *cib_xml_copy;
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

    return rc;
}

static int
delete()
{
    int rc = pcmk_rc_ok;
    xmlNode *msg_data = NULL;

    if (options.rsc_type == NULL) {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "You need to specify a resource type with -t");
        return rc;
    }

    msg_data = create_xml_node(NULL, options.rsc_type);
    crm_xml_add(msg_data, XML_ATTR_ID, options.rsc_id);

    rc = cib_conn->cmds->remove(cib_conn, XML_CIB_TAG_RESOURCES, msg_data,
                                options.cib_options);
    rc = pcmk_legacy2rc(rc);
    free_xml(msg_data);
    return rc;
}

static int
list_agents(const char *spec, crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    lrmd_list_t *list = NULL;
    lrmd_list_t *iter = NULL;
    char *provider = strchr (spec, ':');
    lrmd_t *lrmd_conn = lrmd_api_new();

    if (provider) {
        *provider++ = 0;
    }
    rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, spec, provider);

    if (rc > 0) {
        for (iter = list; iter != NULL; iter = iter->next) {
            printf("%s\n", iter->val);
        }
        lrmd_list_freeall(list);
        rc = pcmk_rc_ok;
    } else {
        *exit_code = CRM_EX_NOSUCH;
        rc = pcmk_rc_error;
        g_set_error(&error, PCMK__EXITC_ERROR, *exit_code,
                    "No agents found for standard=%s, provider=%s",
                    spec, (provider? provider : "*"));
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

static int
list_providers(const char *command, const char *spec, crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    const char *text = NULL;
    lrmd_list_t *list = NULL;
    lrmd_list_t *iter = NULL;
    lrmd_t *lrmd_conn = lrmd_api_new();

    if (pcmk__str_any_of(command, "--list-ocf-providers",
                        "--list-ocf-alternatives", NULL)) {
        rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, spec, &list);
        text = "OCF providers";

    } else if (pcmk__str_eq("--list-standards", command, pcmk__str_casei)) {
        rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);
        text = "standards";
    }

    if (rc > 0) {
        for (iter = list; iter != NULL; iter = iter->next) {
            printf("%s\n", iter->val);
        }
        lrmd_list_freeall(list);
        rc = pcmk_rc_ok;

    } else if (spec) {
        *exit_code = CRM_EX_NOSUCH;
        rc = pcmk_rc_error;
        g_set_error(&error, PCMK__EXITC_ERROR, *exit_code,
                    "No %s found for %s", text, spec);

    } else {
        *exit_code = CRM_EX_NOSUCH;
        rc = pcmk_rc_error;
        g_set_error(&error, PCMK__EXITC_ERROR, *exit_code,
                    "No %s found", text);
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

static int
list_raw()
{
    int rc = pcmk_rc_ok;
    int found = 0;
    GListPtr lpc = NULL;

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *rsc = (pe_resource_t *) lpc->data;

        found++;
        cli_resource_print_raw(rsc);
    }

    if (found == 0) {
        printf("NO resources configured\n");
        rc = ENXIO;
    }

    return rc;
}

static void
list_stacks_and_constraints(pe_resource_t *rsc)
{
    GListPtr lpc = NULL;
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS,
                                               data_set->input);

    unpack_constraints(cib_constraints, data_set);

    // Constraints apply to group/clone, not member/instance
    rsc = uber_parent(rsc);

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;

        clear_bit(r->flags, pe_rsc_allocating);
    }

    cli_resource_print_colocation(rsc, TRUE, options.rsc_cmd == 'A', 1);

    fprintf(stdout, "* %s\n", rsc->id);
    cli_resource_print_location(rsc, NULL);

    for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
        pe_resource_t *r = (pe_resource_t *) lpc->data;

        clear_bit(r->flags, pe_rsc_allocating);
    }

    cli_resource_print_colocation(rsc, FALSE, options.rsc_cmd == 'A', 1);
}

static int
populate_working_set(xmlNodePtr *cib_xml_copy)
{
    int rc = pcmk_rc_ok;

    if (options.xml_file != NULL) {
        *cib_xml_copy = filename2xml(options.xml_file);
    } else {
        rc = cib_conn->cmds->query(cib_conn, NULL, cib_xml_copy, cib_scope_local | cib_sync_call);
        rc = pcmk_legacy2rc(rc);
    }

    if(rc != pcmk_rc_ok) {
        return rc;
    }

    /* Populate the working set instance */
    data_set = pe_new_working_set();
    if (data_set == NULL) {
        rc = ENOMEM;
        return rc;
    }

    set_bit(data_set->flags, pe_flag_no_counts);
    set_bit(data_set->flags, pe_flag_no_compat);

    rc = update_working_set_xml(data_set, cib_xml_copy);
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    cluster_status(data_set);
    return rc;
}

static int
refresh()
{
    int rc = pcmk_rc_ok;
    const char *router_node = options.host_uname;
    int attr_options = pcmk__node_attr_none;

    if (options.host_uname) {
        pe_node_t *node = pe_find_node(data_set->nodes, options.host_uname);

        if (pe__is_guest_or_remote_node(node)) {
            node = pe__current_node(node->details->remote_rsc);
            if (node == NULL) {
                rc = ENXIO;
                g_set_error(&error, PCMK__RC_ERROR, rc,
                            "No cluster connection to Pacemaker Remote node %s detected",
                            options.host_uname);
                return rc;
            }
            router_node = node->details->uname;
            attr_options |= pcmk__node_attr_remote;
        }
    }

    if (controld_api == NULL) {
        printf("Dry run: skipping clean-up of %s due to CIB_file\n",
               options.host_uname? options.host_uname : "all nodes");
        rc = pcmk_rc_ok;
        return rc;
    }

    crm_debug("Re-checking the state of all resources on %s", options.host_uname?options.host_uname:"all nodes");

    rc = pcmk__node_attr_request_clear(NULL, options.host_uname,
                                       NULL, NULL, NULL,
                                       NULL, attr_options);

    if (pcmk_controld_api_reprobe(controld_api, options.host_uname,
                                  router_node) == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }

    return rc;
}

static void
refresh_resource(pe_resource_t *rsc)
{
    int rc = pcmk_rc_ok;

    if (options.force == FALSE) {
        rsc = uber_parent(rsc);
    }

    crm_debug("Re-checking the state of %s (%s requested) on %s",
              rsc->id, options.rsc_id, (options.host_uname? options.host_uname: "all nodes"));
    rc = cli_resource_delete(controld_api, options.host_uname, rsc, NULL, 0, FALSE,
                             data_set, options.force);

    if ((rc == pcmk_rc_ok) && !BE_QUIET) {
        // Show any reasons why resource might stay stopped
        cli_resource_check(cib_conn, rsc);
    }

    if (rc == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }
}

static int
set_option(const char *arg)
{
    int rc = pcmk_rc_ok;
    char *name = NULL;
    char *value = NULL;

    crm_info("Scanning: --option %s", arg);
    rc = pcmk_scan_nvpair(arg, &name, &value);

    if (rc != 2) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Invalid option: --option %s: %s", arg, pcmk_strerror(rc));
    } else {
        crm_info("Got: '%s'='%s'", name, value);
        g_hash_table_replace(options.validate_options, name, value);
    }

    return rc;
}

static int
set_property()
{
    int rc = pcmk_rc_ok;
    xmlNode *msg_data = NULL;

    if (pcmk__str_empty(options.rsc_type)) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Must specify -t with resource type");
        rc = ENXIO;
        return rc;

    } else if (pcmk__str_empty(options.prop_value)) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Must supply -v with new value");
        rc = EINVAL;
        return rc;
    }

    CRM_LOG_ASSERT(options.prop_name != NULL);

    msg_data = create_xml_node(NULL, options.rsc_type);
    crm_xml_add(msg_data, XML_ATTR_ID, options.rsc_id);
    crm_xml_add(msg_data, options.prop_name, options.prop_value);

    rc = cib_conn->cmds->modify(cib_conn, XML_CIB_TAG_RESOURCES, msg_data,
                                options.cib_options);
    rc = pcmk_legacy2rc(rc);
    free_xml(msg_data);

    return rc;
}

static int
show_metadata(const char *spec, crm_exit_t *exit_code)
{
    int rc = pcmk_rc_ok;
    char *standard = NULL;
    char *provider = NULL;
    char *type = NULL;
    char *metadata = NULL;
    lrmd_t *lrmd_conn = lrmd_api_new();

    rc = crm_parse_agent_spec(spec, &standard, &provider, &type);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard,
                                           provider, type,
                                           &metadata, 0);
        rc = pcmk_legacy2rc(rc);

        if (metadata) {
            printf("%s\n", metadata);
        } else {
            *exit_code = crm_errno2exit(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, *exit_code,
                        "Metadata query for %s failed: %s", spec, pcmk_rc_str(rc));
        }
    } else {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "'%s' is not a valid agent specification", spec);
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

static void
validate_cmdline(crm_exit_t *exit_code)
{
    // -r cannot be used with any of --class, --agent, or --provider
    if (options.rsc_id != NULL) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "--resource cannot be used with --class, --agent, and --provider");

    // If --class, --agent, or --provider are given, --validate must also be given.
    } else if (!pcmk__str_eq(options.rsc_long_cmd, "validate", pcmk__str_casei)) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "--class, --agent, and --provider require --validate");

    // Not all of --class, --agent, and --provider need to be given.  Not all
    // classes support the concept of a provider.  Check that what we were given
    // is valid.
    } else if (crm_str_eq(options.v_class, "stonith", TRUE)) {
        if (options.v_provider != NULL) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        "stonith does not support providers");

        } else if (stonith_agent_exists(options.v_agent, 0) == FALSE) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        "%s is not a known stonith agent", options.v_agent ? options.v_agent : "");
        }

    } else if (resources_agent_exists(options.v_class, options.v_provider, options.v_agent) == FALSE) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "%s:%s:%s is not a known resource",
                    options.v_class ? options.v_class : "",
                    options.v_provider ? options.v_provider : "",
                    options.v_agent ? options.v_agent : "");
    }

    if (error == NULL) {
        *exit_code = cli_resource_execute_from_params("test", options.v_class, options.v_provider, options.v_agent,
                                                      "validate-all", options.validate_options,
                                                      options.override_params, options.timeout_ms,
                                                      options.resource_verbose, options.force);
    }
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args) {
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'Q', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &(args->quiet),
          "Be less descriptive in output.",
          NULL },
        { "resource", 'r', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.rsc_id,
          "Resource ID",
          "ID" },
        { G_OPTION_REMAINING, 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING_ARRAY, &options.remainder,
          NULL,
          NULL },

        { NULL }
    };

    const char *description = "Examples:\n\n"
                              "List the available OCF agents:\n\n"
                              "\t# crm_resource --list-agents ocf\n\n"
                              "List the available OCF agents from the linux-ha project:\n\n"
                              "\t# crm_resource --list-agents ocf:heartbeat\n\n"
                              "Move 'myResource' to a specific node:\n\n"
                              "\t# crm_resource --resource myResource --move --node altNode\n\n"
                              "Allow (but not force) 'myResource' to move back to its original "
                              "location:\n\n"
                              "\t# crm_resource --resource myResource --clear\n\n"
                              "Stop 'myResource' (and anything that depends on it):\n\n"
                              "\t# crm_resource --resource myResource --set-parameter target-role "
                              "--meta --parameter-value Stopped\n\n"
                              "Tell the cluster not to manage 'myResource' (the cluster will not "
                              "attempt to start or stop the\n"
                              "resource under any circumstances; useful when performing maintenance "
                              "tasks on a resource):\n\n"
                              "\t# crm_resource --resource myResource --set-parameter is-managed "
                              "--meta --parameter-value false\n\n"
                              "Erase the operation history of 'myResource' on 'aNode' (the cluster "
                              "will 'forget' the existing\n"
                              "resource state, including any errors, and attempt to recover the"
                              "resource; useful when a resource\n"
                              "had failed permanently and has been repaired by an administrator):\n\n"
                              "\t# crm_resource --resource myResource --cleanup --node aNode\n\n";

    context = pcmk__build_arg_context(args, NULL, NULL, NULL);
    g_option_context_set_description(context, description);

    /* Add the -Q option, which cannot be part of the globally supported options
     * because some tools use that flag for something else.
     */
    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "queries", "Queries:",
                        "Show query help", query_entries);
    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command help", command_entries);
    pcmk__add_arg_group(context, "locations", "Locations:",
                        "Show location help", location_entries);
    pcmk__add_arg_group(context, "validate", "Validate:",
                        "Show validate help", validate_entries);
    pcmk__add_arg_group(context, "advanced", "Advanced:",
                        "Show advanced option help", advanced_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    xmlNode *cib_xml_copy = NULL;
    pe_resource_t *rsc = NULL;

    int rc = pcmk_rc_ok;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    GOptionContext *context = NULL;
    gchar **processed_args = NULL;

    context = build_arg_context(args);
    crm_log_cli_init("crm_resource");

    processed_args = pcmk__cmdline_preproc(argv, "GINSTdginpstuv");

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        fprintf(stderr, "%s: %s\n", g_get_prgname(), error->message);
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (pcmk__str_any_of(options.extra_option, "--list-ocf-providers", "--list-ocf-alternatives",
                         "--list-standards", NULL)) {
        rc = list_providers(options.extra_option, options.extra_arg, &exit_code);
        goto done;
    } else if (pcmk__str_eq(options.extra_option, "--show-metadata", pcmk__str_casei)) {
        rc = show_metadata(options.extra_arg, &exit_code);
        goto done;
    } else if (pcmk__str_eq(options.extra_option, "--list-agents", pcmk__str_casei)) {
        rc = list_agents(options.extra_arg, &exit_code);
        goto done;
    } else if (pcmk__str_eq(options.extra_option, "--option", pcmk__str_casei)) {
        rc = set_option(options.extra_arg);
        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

    for (int i = 0; i < args->verbosity; i++) {
        crm_bump_log_level(argc, argv);
    }

    options.resource_verbose = args->verbosity;
    BE_QUIET = args->quiet;

    options.validate_options = crm_str_table_new();
    crm_log_args(argc, argv);

    if (options.host_uname) {
        crm_trace("Option host => %s", options.host_uname);
    }

    // Catch the case where the user didn't specify a command
    if (options.rsc_cmd == 'L') {
        options.require_resource = FALSE;
    }

    // --expired without --clear/-U doesn't make sense
    if (options.clear_expired && options.rsc_cmd != 'U') {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE, "--expired requires --clear or -U");
        goto done;
    }

    if (options.remainder && options.rsc_cmd == 0 && options.rsc_long_cmd) {
        options.override_params = crm_str_table_new();

        for (gchar **s = options.remainder; *s; s++) {
            char *name = calloc(1, strlen(*s));
            char *value = calloc(1, strlen(*s));
            int rc = sscanf(*s, "%[^=]=%s", name, value);

            if (rc == 2) {
                g_hash_table_replace(options.override_params, name, value);

            } else {
                g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                            "Error parsing '%s' as a name=value pair for --%s", argv[optind], options.rsc_long_cmd);
                free(value);
                free(name);
                goto done;
            }
        }

    } else if (options.remainder && options.rsc_cmd == 0) {
        gchar **strv = NULL;
        gchar *msg = NULL;
        int i = 1;
        int len = 0;

        for (gchar **s = options.remainder; *s; s++) {
            len++;
        }

        strv = calloc(len, sizeof(char *));
        strv[0] = strdup("non-option ARGV-elements:");

        for (gchar **s = options.remainder; *s; s++) {
            strv[i] = crm_strdup_printf("[%d of %d] %s\n", i, len, *s);
            i++;
        }

        msg = g_strjoinv("", strv);
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE, "%s", msg);

        for(i = 0; i < len; i++) {
            free(strv[i]);
        }

        g_free(msg);
        g_free(strv);
        goto done;
    }

    if (args->version) {
        /* FIXME:  When crm_resource is converted to use formatted output, this can go. */
        pcmk__cli_help('v', CRM_EX_USAGE);
    }

    if (optind > argc) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Invalid option(s) supplied, use --help for valid usage");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    // Sanity check validating from command line parameters.  If everything checks out,
    // go ahead and run the validation.  This way we don't need a CIB connection.
    if (options.validate_cmdline) {
        validate_cmdline(&exit_code);
        goto done;
    }

    if (error != NULL) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.force) {
        crm_debug("Forcing...");
        options.cib_options |= cib_quorum_override;
    }

    if (options.require_resource && !options.rsc_id) {
        rc = ENXIO;
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Must supply a resource id with -r");
        goto done;
    }

    if (options.find_flags && options.rsc_id) {
        options.require_dataset = TRUE;
    }

    // Establish a connection to the CIB
    cib_conn = cib_new();
    if ((cib_conn == NULL) || (cib_conn->cmds == NULL)) {
        rc = pcmk_rc_error;
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_DISCONNECT,
                    "Could not create CIB connection");
        goto done;
    }
    rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not connect to the CIB: %s", pcmk_rc_str(rc));
        goto done;
    }

    /* Populate working set from XML file if specified or CIB query otherwise */
    if (options.require_dataset) {
        rc = populate_working_set(&cib_xml_copy);
        if (rc != pcmk_rc_ok) {
            goto done;
        }
    }

    // If command requires that resource exist if specified, find it
    if (options.find_flags && options.rsc_id) {
        rsc = pe_find_resource_with_flags(data_set->resources, options.rsc_id,
                                          options.find_flags);
        if (rsc == NULL) {
            rc = ENXIO;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Resource '%s' not found", options.rsc_id);
            goto done;
        }
    }

    // Establish a connection to the controller if needed
    if (options.require_crmd) {
        rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
        if (rc != pcmk_rc_ok) {
            CMD_ERR("Error connecting to the controller: %s", pcmk_rc_str(rc));
            goto done;
        }
        pcmk_register_ipc_callback(controld_api, controller_event_callback,
                                   NULL);
        rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_main);
        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Error connecting to the controller: %s", pcmk_rc_str(rc));
            goto done;
        }
    }

    /* Handle rsc_cmd appropriately */
    if (options.rsc_cmd == 'L') {
        rc = pcmk_rc_ok;
        cli_resource_print_list(data_set, FALSE);

    } else if (options.rsc_cmd == 'l') {
        rc = list_raw();

    } else if (options.rsc_cmd == 0 && options.rsc_long_cmd && pcmk__str_eq(options.rsc_long_cmd, "restart", pcmk__str_casei)) {
        /* We don't pass data_set because rsc needs to stay valid for the entire
         * lifetime of cli_resource_restart(), but it will reset and update the
         * working set multiple times, so it needs to use its own copy.
         */
        rc = cli_resource_restart(rsc, options.host_uname, options.timeout_ms,
                                  cib_conn, options.cib_options, options.promoted_role_only,
                                  options.force);

    } else if (options.rsc_cmd == 0 && options.rsc_long_cmd && pcmk__str_eq(options.rsc_long_cmd, "wait", pcmk__str_casei)) {
        rc = wait_till_stable(options.timeout_ms, cib_conn);

    } else if (options.rsc_cmd == 0 && options.rsc_long_cmd) {
        // validate, force-(stop|start|demote|promote|check)
        exit_code = cli_resource_execute(rsc, options.rsc_id, options.rsc_long_cmd, options.override_params,
                                         options.timeout_ms, cib_conn, data_set, options.resource_verbose,
                                         options.force);

    } else if (options.rsc_cmd == 'A' || options.rsc_cmd == 'a') {
        list_stacks_and_constraints(rsc);

    } else if (options.rsc_cmd == 'c') {
        GListPtr lpc = NULL;

        rc = pcmk_rc_ok;
        for (lpc = data_set->resources; lpc != NULL; lpc = lpc->next) {
            rsc = (pe_resource_t *) lpc->data;
            cli_resource_print_cts(rsc);
        }
        cli_resource_print_cts_constraints(data_set);

    } else if (options.rsc_cmd == 'F') {
        rc = cli_resource_fail(controld_api, options.host_uname, options.rsc_id, data_set);
        if (rc == pcmk_rc_ok) {
            start_mainloop(controld_api);
        }

    } else if (options.rsc_cmd == 'O') {
        rc = cli_resource_print_operations(options.rsc_id, options.host_uname, TRUE, data_set);

    } else if (options.rsc_cmd == 'o') {
        rc = cli_resource_print_operations(options.rsc_id, options.host_uname, FALSE, data_set);

    } else if (options.rsc_cmd == 'W') {
        rc = cli_resource_search(rsc, options.rsc_id, data_set);
        if (rc >= 0) {
            rc = pcmk_rc_ok;
        }

    } else if (options.rsc_cmd == 'q') {
        rc = cli_resource_print(rsc, data_set, TRUE);

    } else if (options.rsc_cmd == 'w') {
        rc = cli_resource_print(rsc, data_set, FALSE);

    } else if (options.rsc_cmd == 'Y') {
        pe_node_t *dest = NULL;

        if (options.host_uname) {
            dest = pe_find_node(data_set->nodes, options.host_uname);
            if (dest == NULL) {
                rc = pcmk_rc_node_unknown;
                goto done;
            }
        }
        cli_resource_why(cib_conn, data_set->resources, rsc, dest);
        rc = pcmk_rc_ok;

    } else if (options.rsc_cmd == 'U') {
        rc = clear_constraints(&cib_xml_copy);

    } else if (options.rsc_cmd == 'M' && options.host_uname) {
        rc = cli_resource_move(rsc, options.rsc_id, options.host_uname, cib_conn,
                               options.cib_options, data_set, options.promoted_role_only,
                               options.force);

    } else if (options.rsc_cmd == 'B' && options.host_uname) {
        pe_node_t *dest = pe_find_node(data_set->nodes, options.host_uname);

        if (dest == NULL) {
            rc = pcmk_rc_node_unknown;
            goto done;
        }
        rc = cli_resource_ban(options.rsc_id, dest->details->uname, NULL,
                              cib_conn, options.cib_options, options.promoted_role_only);

    } else if (options.rsc_cmd == 'B' || options.rsc_cmd == 'M') {
        rc = ban_or_move(rsc, &exit_code);

    } else if (options.rsc_cmd == 'G') {
        rc = cli_resource_print_property(rsc, options.prop_name, data_set);

    } else if (options.rsc_cmd == 'S') {
        rc = set_property();

    } else if (options.rsc_cmd == 'g') {
        rc = cli_resource_print_attribute(rsc, options.prop_name, options.attr_set_type, data_set);

    } else if (options.rsc_cmd == 'p') {
        if (pcmk__str_empty(options.prop_value)) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        "You need to supply a value with the -v option");
            rc = EINVAL;
            goto done;
        }

        /* coverity[var_deref_model] False positive */
        rc = cli_resource_update_attribute(rsc, options.rsc_id, options.prop_set, options.attr_set_type,
                                           options.prop_id, options.prop_name, options.prop_value,
                                           options.recursive, cib_conn, options.cib_options, data_set,
                                           options.force);

    } else if (options.rsc_cmd == 'd') {
        /* coverity[var_deref_model] False positive */
        rc = cli_resource_delete_attribute(rsc, options.rsc_id, options.prop_set, options.attr_set_type,
                                           options.prop_id, options.prop_name, cib_conn,
                                           options.cib_options, data_set, options.force);

    } else if ((options.rsc_cmd == 'C') && rsc) {
        cleanup(rsc);

    } else if (options.rsc_cmd == 'C') {
        rc = cli_cleanup_all(controld_api, options.host_uname, options.operation, options.interval_spec,
                             data_set);
        if (rc == pcmk_rc_ok) {
            start_mainloop(controld_api);
        }

    } else if ((options.rsc_cmd == 'R') && rsc) {
        refresh_resource(rsc);

    } else if (options.rsc_cmd == 'R') {
        rc = refresh();

    } else if (options.rsc_cmd == 'D') {
        rc = delete();

    } else {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Unknown command: %c", options.rsc_cmd);
    }

done:
    if (rc != pcmk_rc_ok) {
        if (rc == pcmk_rc_no_quorum) {
            g_prefix_error(&error, "To ignore quorum, use the force option.\n");
        }

        if (error != NULL) {
            char *msg = crm_strdup_printf("%s\nError performing operation: %s",
                                          error->message, pcmk_rc_str(rc));
            g_clear_error(&error);
            g_set_error(&error, PCMK__RC_ERROR, rc, "%s", msg);
            free(msg);
        } else {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Error performing operation: %s", pcmk_rc_str(rc));
        }

        if (exit_code == CRM_EX_OK) {
            exit_code = pcmk_rc2exitc(rc);
        }
    }

    free(options.extra_arg);
    free(options.extra_option);
    free(options.host_uname);
    free(options.interval_spec);
    free(options.operation);
    free(options.prop_id);
    free(options.prop_name);
    free(options.prop_set);
    free(options.prop_value);
    free(options.rsc_id);
    free(options.rsc_long_cmd);
    free(options.rsc_type);
    free(options.v_agent);
    free(options.v_class);
    free(options.v_provider);
    free(options.xml_file);

    if (options.remainder) {
        for (gchar **s = options.remainder; *s; s++) {
            g_free(*s);
        }
    }

    if (options.override_params != NULL) {
        g_hash_table_destroy(options.override_params);
    }

    /* options.validate_options does not need to be destroyed here.  See the
     * comments in cli_resource_execute_from_params.
     */

    g_strfreev(processed_args);
    g_option_context_free(context);

    return bye(exit_code);
}

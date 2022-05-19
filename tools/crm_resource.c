/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm_resource.h>
#include <crm/lrmd_internal.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/lists_internal.h>
#include <crm/common/output.h>
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
#include <crm/cib/internal.h>

#define SUMMARY "crm_resource - perform tasks related to Pacemaker cluster resources"

enum rsc_command {
    cmd_none = 0,           // No command option given (yet)
    cmd_ban,
    cmd_cleanup,
    cmd_clear,
    cmd_colocations,
    cmd_colocations_deep,
    cmd_cts,
    cmd_delete,
    cmd_delete_param,
    cmd_digests,
    cmd_execute_agent,
    cmd_fail,
    cmd_get_param,
    cmd_get_property,
    cmd_list_active_ops,
    cmd_list_agents,
    cmd_list_all_ops,
    cmd_list_alternatives,
    cmd_list_instances,
    cmd_list_providers,
    cmd_list_resources,
    cmd_list_standards,
    cmd_locate,
    cmd_metadata,
    cmd_move,
    cmd_query_raw_xml,
    cmd_query_xml,
    cmd_refresh,
    cmd_restart,
    cmd_set_param,
    cmd_set_property,
    cmd_wait,
    cmd_why,
};

struct {
    enum rsc_command rsc_cmd;     // crm_resource command to perform

    // Infrastructure that given command needs to work
    gboolean require_cib;         // Whether command requires CIB IPC
    int cib_options;              // Options to use with CIB IPC calls
    gboolean require_crmd;        // Whether command requires controller IPC
    gboolean require_dataset;     // Whether command requires populated data set
    gboolean require_resource;    // Whether command requires resource specified
    gboolean require_node;        // Whether command requires node specified
    int find_flags;               // Flags to use when searching for resource

    // Command-line option values
    gchar *rsc_id;                // Value of --resource
    gchar *rsc_type;              // Value of --resource-type
    gboolean force;               // --force was given
    gboolean clear_expired;       // --expired was given
    gboolean recursive;           // --recursive was given
    gboolean promoted_role_only;  // --promoted was given
    gchar *host_uname;            // Value of --node
    gchar *interval_spec;         // Value of --interval
    gchar *move_lifetime;         // Value of --lifetime
    gchar *operation;             // Value of --operation
    const char *attr_set_type;    // Instance, meta, or utilization attribute
    gchar *prop_id;               // --nvpair (attribute XML ID)
    char *prop_name;              // Attribute name
    gchar *prop_set;              // --set-name (attribute block XML ID)
    gchar *prop_value;            // --parameter-value (attribute value)
    int timeout_ms;               // Parsed from --timeout value
    char *agent_spec;             // Standard and/or provider and/or agent
    gchar *xml_file;              // Value of (deprecated) --xml-file
    int check_level;              // Optional value of --validate or --force-check

    // Resource configuration specified via command-line arguments
    gboolean cmdline_config;      // Resource configuration was via arguments
    char *v_agent;                // Value of --agent
    char *v_class;                // Value of --class
    char *v_provider;             // Value of --provider
    GHashTable *cmdline_params;   // Resource parameters specified

    // Positional command-line arguments
    gchar **remainder;            // Positional arguments as given
    GHashTable *override_params;  // Resource parameter values that override config
} options = {
    .attr_set_type = XML_TAG_ATTR_SETS,
    .check_level = -1,
    .cib_options = cib_sync_call,
    .require_cib = TRUE,
    .require_dataset = TRUE,
    .require_resource = TRUE,
};

#if 0
// @COMPAT @TODO enable this at next backward compatibility break
#define SET_COMMAND(cmd) do {                                               \
        if (options.rsc_cmd != cmd_none) {                                  \
            g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_USAGE,             \
                        "Only one command option may be specified");        \
            return FALSE;                                                   \
        }                                                                   \
        options.rsc_cmd = (cmd);                                            \
    } while (0)
#else
#define SET_COMMAND(cmd) do {                                               \
        if (options.rsc_cmd != cmd_none) {                                  \
            reset_options();                                                \
        }                                                                   \
        options.rsc_cmd = (cmd);                                            \
    } while (0)
#endif

gboolean agent_provider_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean attr_set_type_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean class_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean cleanup_refresh_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean delete_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean expired_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean list_agents_cb(const gchar *option_name, const gchar *optarg,
                        gpointer data, GError **error);
gboolean list_providers_cb(const gchar *option_name, const gchar *optarg,
                           gpointer data, GError **error);
gboolean list_standards_cb(const gchar *option_name, const gchar *optarg,
                           gpointer data, GError **error);
gboolean list_alternatives_cb(const gchar *option_name, const gchar *optarg,
                              gpointer data, GError **error);
gboolean metadata_cb(const gchar *option_name, const gchar *optarg,
                     gpointer data, GError **error);
gboolean option_cb(const gchar *option_name, const gchar *optarg,
                   gpointer data, GError **error);
gboolean fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean flag_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean get_param_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean list_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean set_delete_param_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean set_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean timeout_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean validate_or_force_cb(const gchar *option_name, const gchar *optarg,
                              gpointer data, GError **error);
gboolean restart_cb(const gchar *option_name, const gchar *optarg,
                    gpointer data, GError **error);
gboolean digests_cb(const gchar *option_name, const gchar *optarg,
                    gpointer data, GError **error);
gboolean wait_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean why_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static crm_exit_t exit_code = CRM_EX_OK;
static pcmk__output_t *out = NULL;
static pcmk__common_args_t *args = NULL;

// Things that should be cleaned up on exit
static GError *error = NULL;
static GMainLoop *mainloop = NULL;
static cib_t *cib_conn = NULL;
static pcmk_ipc_api_t *controld_api = NULL;
static pe_working_set_t *data_set = NULL;

#define MESSAGE_TIMEOUT_S 60

#define INDENT "                                    "

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

// Clean up and exit
static crm_exit_t
bye(crm_exit_t ec)
{
    pcmk__output_and_clear_error(error, out);

    if (out != NULL) {
        out->finish(out, ec, true, NULL);
        pcmk__output_free(out);
    }

    if (cib_conn != NULL) {
        cib_t *save_cib_conn = cib_conn;

        cib_conn = NULL; // Ensure we can't free this twice
        cib__clean_up_connection(&save_cib_conn);
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
                "Aborting because no messages received in %d seconds", MESSAGE_TIMEOUT_S);

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
                out->err(out, "Error: bad reply from controller: %s",
                         crm_exit_str(status));
                pcmk_disconnect_ipc(api);
                quit_main_loop(status);
            } else {
                if ((pcmk_controld_api_replies_expected(api) == 0)
                    && mainloop && g_main_loop_is_running(mainloop)) {
                    out->info(out, "... got reply (done)");
                    crm_debug("Got all the replies we expected");
                    pcmk_disconnect_ipc(api);
                    quit_main_loop(CRM_EX_OK);
                } else {
                    out->info(out, "... got reply");
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
        out->info(out, "Waiting for %u %s from the controller",
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

static GList *
build_constraint_list(xmlNode *root)
{
    GList *retval = NULL;
    xmlNode *cib_constraints = NULL;
    xmlXPathObjectPtr xpathObj = NULL;
    int ndx = 0;

    cib_constraints = pcmk_find_cib_element(root, XML_CIB_TAG_CONSTRAINTS);
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
    { "list-standards", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      list_standards_cb,
      "List supported standards",
      NULL },
    { "list-ocf-providers", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      list_providers_cb,
      "List all available OCF providers",
      NULL },
    { "list-agents", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
      list_agents_cb,
      "List all agents available for the named standard and/or provider",
      "STD:PROV" },
    { "list-ocf-alternatives", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
      list_alternatives_cb,
      "List all available providers for the named OCF agent",
      "AGENT" },
    { "show-metadata", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
      metadata_cb,
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
      "Display the (co)location constraints that apply to a resource\n"
      INDENT "and the resources is it colocated with",
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
    { "validate", 0, G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
      validate_or_force_cb,
      "Validate resource configuration by calling agent's validate-all\n"
      INDENT "action. The configuration may be specified either by giving an\n"
      INDENT "existing resource name with -r, or by specifying --class,\n"
      INDENT "--agent, and --provider arguments, along with any number of\n"
      INDENT "--option arguments. An optional LEVEL argument can be given\n"
      INDENT "to control the level of checking performed.",
      "LEVEL" },
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
      INDENT "Optional: --lifetime, --promoted. NOTE: This may prevent the\n"
      INDENT "resource from running on its previous location until the\n"
      INDENT "implicit constraint expires or is removed with --clear.",
      NULL },
    { "ban", 'B', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Create a constraint to keep resource off a node.\n"
      INDENT "Optional: --node, --lifetime, --promoted.\n"
      INDENT "NOTE: This will prevent the resource from running on the\n"
      INDENT "affected node until the implicit constraint expires or is\n"
      INDENT "removed with --clear. If --node is not specified, it defaults\n"
      INDENT "to the node currently running the resource for primitives\n"
      INDENT "and groups, or the promoted instance of promotable clones with\n"
      INDENT "promoted-max=1 (all other situations result in an error as\n"
      INDENT "there is no sane default).",
      NULL },
    { "clear", 'U', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, flag_cb,
      "Remove all constraints created by the --ban and/or --move\n"
      INDENT "commands. Requires: --resource. Optional: --node, --promoted,\n"
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
    { "lifetime", 'u', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.move_lifetime,
      "Lifespan (as ISO 8601 duration) of created constraints (with\n"
      INDENT "-B, -M) see https://en.wikipedia.org/wiki/ISO_8601#Durations)",
      "TIMESPEC" },
    { "promoted", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.promoted_role_only,
      "Limit scope of command to promoted role (with -B, -M, -U). For\n"
      INDENT "-B and -M, previously promoted instances may remain\n"
      INDENT "active in the unpromoted role.",
      NULL },

    // Deprecated since 2.1.0
    { "master", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.promoted_role_only,
      "Deprecated: Use --promoted instead", NULL },

    { NULL }
};

static GOptionEntry advanced_entries[] = {
    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, delete_cb,
      "(Advanced) Delete a resource from the CIB. Required: -t",
      NULL },
    { "fail", 'F', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, fail_cb,
      "(Advanced) Tell the cluster this resource has failed",
      NULL },
    { "restart", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, restart_cb,
      "(Advanced) Tell the cluster to restart this resource and\n"
      INDENT "anything that depends on it",
      NULL },
    { "wait", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, wait_cb,
      "(Advanced) Wait until the cluster settles into a stable state",
      NULL },
    { "digests", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, digests_cb,
      "(Advanced) Show parameter hashes that Pacemaker uses to detect\n"
      INDENT "configuration changes (only accurate if there is resource\n"
      INDENT "history on the specified node). Required: --resource, --node.\n"
      INDENT "Optional: any NAME=VALUE parameters will be used to override\n"
      INDENT "the configuration (to see what the hash would be with those\n"
      INDENT "changes).",
      NULL },
    { "force-demote", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      validate_or_force_cb,
      "(Advanced) Bypass the cluster and demote a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-stop", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      validate_or_force_cb,
      "(Advanced) Bypass the cluster and stop a resource on the local node",
      NULL },
    { "force-start", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      validate_or_force_cb,
      "(Advanced) Bypass the cluster and start a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-promote", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      validate_or_force_cb,
      "(Advanced) Bypass the cluster and promote a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-check", 0, G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
      validate_or_force_cb,
      "(Advanced) Bypass the cluster and check the state of a resource on\n"
      INDENT "the local node. An optional LEVEL argument can be given\n"
      INDENT "to control the level of checking performed.",
      "LEVEL" },

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
    { "class", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, class_cb,
      "The standard the resource agent conforms to (for example, ocf).\n"
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
    { "option", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, option_cb,
      "Specify a device configuration parameter as NAME=VALUE (may be\n"
      INDENT "specified multiple times). Use with --validate and without the\n"
      INDENT "-r option.",
      "PARAM" },
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

static void
reset_options(void) {
    options.require_crmd = FALSE;
    options.require_node = FALSE;

    options.require_cib = TRUE,
    options.require_dataset = TRUE,
    options.require_resource = TRUE,

    options.find_flags = 0;
}

gboolean
agent_provider_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.cmdline_config = TRUE;
    options.require_resource = FALSE;

    if (pcmk__str_eq(option_name, "--provider", pcmk__str_casei)) {
        pcmk__str_update(&options.v_provider, optarg);
    } else {
        pcmk__str_update(&options.v_agent, optarg);
    }

    return TRUE;
}

gboolean
attr_set_type_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-m", "--meta", NULL)) {
        options.attr_set_type = XML_TAG_META_SETS;
    } else if (pcmk__str_any_of(option_name, "-z", "--utilization", NULL)) {
        options.attr_set_type = XML_TAG_UTILIZATION;
    }

    return TRUE;
}

gboolean
class_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    pcmk__str_update(&options.v_class, optarg);
    options.cmdline_config = TRUE;
    options.require_resource = FALSE;
    return TRUE;
}

gboolean
cleanup_refresh_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-C", "--cleanup", NULL)) {
        SET_COMMAND(cmd_cleanup);
    } else {
        SET_COMMAND(cmd_refresh);
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
    SET_COMMAND(cmd_delete);
    options.require_dataset = FALSE;
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
expired_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.clear_expired = TRUE;
    options.require_resource = FALSE;
    return TRUE;
}

static void
get_agent_spec(const gchar *optarg)
{
    options.require_cib = FALSE;
    options.require_dataset = FALSE;
    options.require_resource = FALSE;
    pcmk__str_update(&options.agent_spec, optarg);
}

gboolean
list_agents_cb(const gchar *option_name, const gchar *optarg, gpointer data,
               GError **error)
{
    SET_COMMAND(cmd_list_agents);
    get_agent_spec(optarg);
    return TRUE;
}

gboolean
list_providers_cb(const gchar *option_name, const gchar *optarg, gpointer data,
                  GError **error)
{
    SET_COMMAND(cmd_list_providers);
    get_agent_spec(optarg);
    return TRUE;
}

gboolean
list_standards_cb(const gchar *option_name, const gchar *optarg, gpointer data,
                  GError **error)
{
    SET_COMMAND(cmd_list_standards);
    options.require_cib = FALSE;
    options.require_dataset = FALSE;
    options.require_resource = FALSE;
    return TRUE;
}

gboolean
list_alternatives_cb(const gchar *option_name, const gchar *optarg,
                     gpointer data, GError **error)
{
    SET_COMMAND(cmd_list_alternatives);
    get_agent_spec(optarg);
    return TRUE;
}

gboolean
metadata_cb(const gchar *option_name, const gchar *optarg, gpointer data,
            GError **error)
{
    SET_COMMAND(cmd_metadata);
    get_agent_spec(optarg);
    return TRUE;
}

gboolean
option_cb(const gchar *option_name, const gchar *optarg, gpointer data,
          GError **error)
{
    char *name = NULL;
    char *value = NULL;

    if (pcmk__scan_nvpair(optarg, &name, &value) != 2) {
        return FALSE;
    }
    if (options.cmdline_params == NULL) {
        options.cmdline_params = pcmk__strkey_table(free, free);
    }
    g_hash_table_replace(options.cmdline_params, name, value);
    return TRUE;
}

gboolean
fail_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    SET_COMMAND(cmd_fail);
    options.require_crmd = TRUE;
    options.require_node = TRUE;
    return TRUE;
}

gboolean
flag_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-U", "--clear", NULL)) {
        SET_COMMAND(cmd_clear);
        options.find_flags = pe_find_renamed|pe_find_anon;
    } else if (pcmk__str_any_of(option_name, "-B", "--ban", NULL)) {
        SET_COMMAND(cmd_ban);
        options.find_flags = pe_find_renamed|pe_find_anon;
    } else if (pcmk__str_any_of(option_name, "-M", "--move", NULL)) {
        SET_COMMAND(cmd_move);
        options.find_flags = pe_find_renamed|pe_find_anon;
    } else if (pcmk__str_any_of(option_name, "-q", "--query-xml", NULL)) {
        SET_COMMAND(cmd_query_xml);
        options.find_flags = pe_find_renamed|pe_find_any;
    } else if (pcmk__str_any_of(option_name, "-w", "--query-xml-raw", NULL)) {
        SET_COMMAND(cmd_query_raw_xml);
        options.find_flags = pe_find_renamed|pe_find_any;
    } else if (pcmk__str_any_of(option_name, "-W", "--locate", NULL)) {
        SET_COMMAND(cmd_locate);
        options.find_flags = pe_find_renamed|pe_find_anon;
    } else if (pcmk__str_any_of(option_name, "-A", "--stack", NULL)) {
        SET_COMMAND(cmd_colocations_deep);
        options.find_flags = pe_find_renamed|pe_find_anon;
    } else {
        SET_COMMAND(cmd_colocations);
        options.find_flags = pe_find_renamed|pe_find_anon;
    }

    return TRUE;
}

gboolean
get_param_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-g", "--get-parameter", NULL)) {
        SET_COMMAND(cmd_get_param);
    } else {
        SET_COMMAND(cmd_get_property);
    }

    pcmk__str_update(&options.prop_name, optarg);
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
list_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-c", "--list-cts", NULL)) {
        SET_COMMAND(cmd_cts);
    } else if (pcmk__str_any_of(option_name, "-L", "--list", NULL)) {
        SET_COMMAND(cmd_list_resources);
    } else if (pcmk__str_any_of(option_name, "-l", "--list-raw", NULL)) {
        SET_COMMAND(cmd_list_instances);
    } else if (pcmk__str_any_of(option_name, "-O", "--list-operations", NULL)) {
        SET_COMMAND(cmd_list_active_ops);
    } else {
        SET_COMMAND(cmd_list_all_ops);
    }

    options.require_resource = FALSE;
    return TRUE;
}

gboolean
set_delete_param_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    if (pcmk__str_any_of(option_name, "-p", "--set-parameter", NULL)) {
        SET_COMMAND(cmd_set_param);
    } else {
        SET_COMMAND(cmd_delete_param);
    }

    pcmk__str_update(&options.prop_name, optarg);
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
set_prop_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    SET_COMMAND(cmd_set_property);
    options.require_dataset = FALSE;
    pcmk__str_update(&options.prop_name, optarg);
    options.find_flags = pe_find_renamed|pe_find_any;
    return TRUE;
}

gboolean
timeout_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.timeout_ms = crm_get_msec(optarg);
    return TRUE;
}

gboolean
validate_or_force_cb(const gchar *option_name, const gchar *optarg,
                     gpointer data, GError **error)
{
    SET_COMMAND(cmd_execute_agent);
    if (options.operation) {
        g_free(options.operation);
    }
    options.operation = g_strdup(option_name + 2); // skip "--"
    options.find_flags = pe_find_renamed|pe_find_anon;
    if (options.override_params == NULL) {
        options.override_params = pcmk__strkey_table(free, free);
    }

    if (optarg != NULL) {
        if (pcmk__scan_min_int(optarg, &options.check_level, 0) != pcmk_rc_ok) {
            g_set_error(error, G_OPTION_ERROR, CRM_EX_INVALID_PARAM,
                        "Invalid check level setting: %s", optarg);
            return FALSE;
        }
    }

    return TRUE;
}

gboolean
restart_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    SET_COMMAND(cmd_restart);
    options.find_flags = pe_find_renamed|pe_find_anon;
    return TRUE;
}

gboolean
digests_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    SET_COMMAND(cmd_digests);
    options.find_flags = pe_find_renamed|pe_find_anon;
    if (options.override_params == NULL) {
        options.override_params = pcmk__strkey_table(free, free);
    }
    options.require_node = TRUE;
    options.require_dataset = TRUE;
    return TRUE;
}

gboolean
wait_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    SET_COMMAND(cmd_wait);
    options.require_resource = FALSE;
    options.require_dataset = FALSE;
    return TRUE;
}

gboolean
why_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    SET_COMMAND(cmd_why);
    options.require_resource = FALSE;
    options.find_flags = pe_find_renamed|pe_find_anon;
    return TRUE;
}

static int
ban_or_move(pcmk__output_t *out, pe_resource_t *rsc, const char *move_lifetime)
{
    int rc = pcmk_rc_ok;
    pe_node_t *current = NULL;
    unsigned int nactive = 0;

    CRM_CHECK(rsc != NULL, return EINVAL);

    current = pe__find_active_requires(rsc, &nactive);

    if (nactive == 1) {
        rc = cli_resource_ban(out, options.rsc_id, current->details->uname, move_lifetime, NULL,
                              cib_conn, options.cib_options, options.promoted_role_only);

    } else if (pcmk_is_set(rsc->flags, pe_rsc_promotable)) {
        int count = 0;
        GList *iter = NULL;

        current = NULL;
        for(iter = rsc->children; iter; iter = iter->next) {
            pe_resource_t *child = (pe_resource_t *)iter->data;
            enum rsc_role_e child_role = child->fns->state(child, TRUE);

            if (child_role == RSC_ROLE_PROMOTED) {
                count++;
                current = pe__current_node(child);
            }
        }

        if(count == 1 && current) {
            rc = cli_resource_ban(out, options.rsc_id, current->details->uname, move_lifetime, NULL,
                                  cib_conn, options.cib_options, options.promoted_role_only);

        } else {
            rc = EINVAL;
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        "Resource '%s' not moved: active in %d locations (promoted in %d).\n"
                        "To prevent '%s' from running on a specific location, "
                        "specify a node."
                        "To prevent '%s' from being promoted at a specific "
                        "location, specify a node and the --promoted option.",
                        options.rsc_id, nactive, count, options.rsc_id, options.rsc_id);
        }

    } else {
        rc = EINVAL;
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Resource '%s' not moved: active in %d locations.\n"
                    "To prevent '%s' from running on a specific location, "
                    "specify a node.",
                    options.rsc_id, nactive, options.rsc_id);
    }

    return rc;
}

static void
cleanup(pcmk__output_t *out, pe_resource_t *rsc)
{
    int rc = pcmk_rc_ok;

    if (options.force == FALSE) {
        rsc = uber_parent(rsc);
    }

    crm_debug("Erasing failures of %s (%s requested) on %s",
              rsc->id, options.rsc_id, (options.host_uname? options.host_uname: "all nodes"));
    rc = cli_resource_delete(controld_api, options.host_uname, rsc, options.operation,
                             options.interval_spec, TRUE, data_set, options.force);

    if ((rc == pcmk_rc_ok) && !out->is_quiet(out)) {
        // Show any reasons why resource might stay stopped
        cli_resource_check(out, cib_conn, rsc);
    }

    if (rc == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }
}

static int
clear_constraints(pcmk__output_t *out, xmlNodePtr *cib_xml_copy)
{
    GList *before = NULL;
    GList *after = NULL;
    GList *remaining = NULL;
    GList *ele = NULL;
    pe_node_t *dest = NULL;
    int rc = pcmk_rc_ok;

    if (!out->is_quiet(out)) {
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
            if (!out->is_quiet(out)) {
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

    if (!out->is_quiet(out)) {
        rc = cib_conn->cmds->query(cib_conn, NULL, cib_xml_copy, cib_scope_local | cib_sync_call);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not get modified CIB: %s\n", pcmk_strerror(rc));
            g_list_free(before);
            free_xml(*cib_xml_copy);
            *cib_xml_copy = NULL;
            return rc;
        }

        data_set->input = *cib_xml_copy;
        cluster_status(data_set);

        after = build_constraint_list(data_set->input);
        remaining = pcmk__subtract_lists(before, after, (GCompareFunc) strcmp);

        for (ele = remaining; ele != NULL; ele = ele->next) {
            out->info(out, "Removing constraint: %s", (char *) ele->data);
        }

        g_list_free(before);
        g_list_free(after);
        g_list_free(remaining);
    }

    return rc;
}

static int
delete(void)
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
list_agents(pcmk__output_t *out, const char *agent_spec)
{
    int rc = pcmk_rc_ok;
    char *provider = strchr(agent_spec, ':');
    lrmd_t *lrmd_conn = NULL;
    lrmd_list_t *list = NULL;

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        goto error;
    }

    if (provider) {
        *provider++ = 0;
    }

    rc = lrmd_conn->cmds->list_agents(lrmd_conn, &list, agent_spec, provider);

    if (rc > 0) {
        rc = out->message(out, "agents-list", list, agent_spec, provider);
    } else {
        rc = pcmk_rc_error;
    }

error:
    if (rc != pcmk_rc_ok) {
        if (provider == NULL) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "No agents found for standard '%s'", agent_spec);
        } else {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "No agents found for standard '%s' and provider '%s'",
                        agent_spec, provider);
        }
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

static int
list_providers(pcmk__output_t *out, const char *agent_spec)
{
    int rc;
    const char *text = NULL;
    lrmd_t *lrmd_conn = NULL;
    lrmd_list_t *list = NULL;

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        goto error;
    }

    switch (options.rsc_cmd) {
        case cmd_list_alternatives:
            rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, agent_spec, &list);

            if (rc > 0) {
                rc = out->message(out, "alternatives-list", list, agent_spec);
            } else {
                rc = pcmk_rc_error;
            }

            text = "OCF providers";
            break;
        case cmd_list_standards:
            rc = lrmd_conn->cmds->list_standards(lrmd_conn, &list);

            if (rc > 0) {
                rc = out->message(out, "standards-list", list);
            } else {
                rc = pcmk_rc_error;
            }

            text = "standards";
            break;
        case cmd_list_providers:
            rc = lrmd_conn->cmds->list_ocf_providers(lrmd_conn, agent_spec, &list);

            if (rc > 0) {
                rc = out->message(out, "providers-list", list, agent_spec);
            } else {
                rc = pcmk_rc_error;
            }

            text = "OCF providers";
            break;
        default:
            g_set_error(&error, PCMK__RC_ERROR, pcmk_rc_error, "Bug");
            lrmd_api_delete(lrmd_conn);
            return pcmk_rc_error;
    }

error:
    if (rc != pcmk_rc_ok) {
        if (agent_spec != NULL) {
            rc = ENXIO;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "No %s found for %s", text, agent_spec);

        } else {
            rc = ENXIO;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "No %s found", text);
        }
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

static int
populate_working_set(xmlNodePtr *cib_xml_copy)
{
    int rc = pcmk_rc_ok;

    if (options.xml_file != NULL) {
        *cib_xml_copy = filename2xml(options.xml_file);
        if (*cib_xml_copy == NULL) {
            rc = pcmk_rc_cib_corrupt;
        }
    } else {
        rc = cib_conn->cmds->query(cib_conn, NULL, cib_xml_copy, cib_scope_local | cib_sync_call);
        rc = pcmk_legacy2rc(rc);
    }

    if (rc == pcmk_rc_ok) {
        data_set = pe_new_working_set();
        if (data_set == NULL) {
            rc = ENOMEM;
        } else {
            pe__set_working_set_flags(data_set,
                                      pe_flag_no_counts|pe_flag_no_compat);
            data_set->priv = out;
            rc = update_working_set_xml(data_set, cib_xml_copy);
        }
    }

    if (rc != pcmk_rc_ok) {
        free_xml(*cib_xml_copy);
        *cib_xml_copy = NULL;
        return rc;
    }

    cluster_status(data_set);
    return pcmk_rc_ok;
}

static int
refresh(pcmk__output_t *out)
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
        out->info(out, "Dry run: skipping clean-up of %s due to CIB_file",
                  options.host_uname? options.host_uname : "all nodes");
        rc = pcmk_rc_ok;
        return rc;
    }

    crm_debug("Re-checking the state of all resources on %s", options.host_uname?options.host_uname:"all nodes");

    rc = pcmk__attrd_api_clear_failures(NULL, options.host_uname, NULL,
                                        NULL, NULL, NULL, attr_options);

    if (pcmk_controld_api_reprobe(controld_api, options.host_uname,
                                  router_node) == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }

    return rc;
}

static void
refresh_resource(pcmk__output_t *out, pe_resource_t *rsc)
{
    int rc = pcmk_rc_ok;

    if (options.force == FALSE) {
        rsc = uber_parent(rsc);
    }

    crm_debug("Re-checking the state of %s (%s requested) on %s",
              rsc->id, options.rsc_id, (options.host_uname? options.host_uname: "all nodes"));
    rc = cli_resource_delete(controld_api, options.host_uname, rsc, NULL, 0,
                             FALSE, data_set, options.force);

    if ((rc == pcmk_rc_ok) && !out->is_quiet(out)) {
        // Show any reasons why resource might stay stopped
        cli_resource_check(out, cib_conn, rsc);
    }

    if (rc == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }
}

static int
set_property(void)
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
        rc = ENXIO;
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
show_metadata(pcmk__output_t *out, const char *agent_spec)
{
    int rc = pcmk_rc_ok;
    char *standard = NULL;
    char *provider = NULL;
    char *type = NULL;
    char *metadata = NULL;
    lrmd_t *lrmd_conn = NULL;

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not create executor connection");
        lrmd_api_delete(lrmd_conn);
        return rc;
    }

    rc = crm_parse_agent_spec(agent_spec, &standard, &provider, &type);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard,
                                           provider, type,
                                           &metadata, 0);
        rc = pcmk_legacy2rc(rc);

        if (metadata) {
            out->output_xml(out, "metadata", metadata);
            free(metadata);
        } else {
            /* We were given a validly formatted spec, but it doesn't necessarily
             * match up with anything that exists.  Use ENXIO as the return code
             * here because that maps to an exit code of CRM_EX_NOSUCH, which
             * probably is the most common reason to get here.
             */
            rc = ENXIO;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        _("Metadata query for %s failed: %s"),
                        agent_spec, pcmk_rc_str(rc));
        }
    } else {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    _("'%s' is not a valid agent specification"), agent_spec);
    }

    lrmd_api_delete(lrmd_conn);
    return rc;
}

static void
validate_cmdline_config(void)
{
    // Cannot use both --resource and command-line resource configuration
    if (options.rsc_id != NULL) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "--resource cannot be used with --class, --agent, and --provider");

    // Not all commands support command-line resource configuration
    } else if (options.rsc_cmd != cmd_execute_agent) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "--class, --agent, and --provider can only be used with "
                    "--validate and --force-*");

    // Not all of --class, --agent, and --provider need to be given.  Not all
    // classes support the concept of a provider.  Check that what we were given
    // is valid.
    } else if (pcmk__str_eq(options.v_class, "stonith", pcmk__str_none)) {
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

    if (error != NULL) {
        return;
    }

    if (options.cmdline_params == NULL) {
        options.cmdline_params = pcmk__strkey_table(free, free);
    }
    options.require_resource = FALSE;
    options.require_dataset = FALSE;
    options.require_cib = FALSE;
}

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
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

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
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
    pe_node_t *node = NULL;
    int rc = pcmk_rc_ok;

    GOptionGroup *output_group = NULL;
    gchar **processed_args = NULL;
    GOptionContext *context = NULL;

    /*
     * Parse command line arguments
     */

    args = pcmk__new_common_args(SUMMARY);
    processed_args = pcmk__cmdline_preproc(argv, "GHINSTdginpstuvx");
    context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_resource", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    pe__register_messages(out);
    crm_resource_register_messages(out);
    lrmd__register_messages(out);
    pcmk__register_lib_messages(out);

    out->quiet = args->quiet;

    crm_log_args(argc, argv);

    /*
     * Validate option combinations
     */

    // If the user didn't explicitly specify a command, list resources
    if (options.rsc_cmd == cmd_none) {
        options.rsc_cmd = cmd_list_resources;
        options.require_resource = FALSE;
    }

    // --expired without --clear/-U doesn't make sense
    if (options.clear_expired && (options.rsc_cmd != cmd_clear)) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "--expired requires --clear or -U");
        goto done;
    }

    if ((options.remainder != NULL) && (options.override_params != NULL)) {
        // Commands that use positional arguments will create override_params
        for (gchar **s = options.remainder; *s; s++) {
            char *name = calloc(1, strlen(*s));
            char *value = calloc(1, strlen(*s));
            int rc = sscanf(*s, "%[^=]=%s", name, value);

            if (rc == 2) {
                g_hash_table_replace(options.override_params, name, value);

            } else {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Error parsing '%s' as a name=value pair",
                            argv[optind]);
                free(value);
                free(name);
                goto done;
            }
        }

    } else if (options.remainder != NULL) {
        gchar **strv = NULL;
        gchar *msg = NULL;
        int i = 1;
        int len = 0;

        for (gchar **s = options.remainder; *s; s++) {
            len++;
        }

        CRM_ASSERT(len > 0);

        strv = calloc(len, sizeof(char *));
        strv[0] = strdup("non-option ARGV-elements:");

        for (gchar **s = options.remainder; *s; s++) {
            strv[i] = crm_strdup_printf("[%d of %d] %s\n", i, len, *s);
            i++;
        }

        exit_code = CRM_EX_USAGE;
        msg = g_strjoinv("", strv);
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "%s", msg);
        g_free(msg);

        for(i = 0; i < len; i++) {
            free(strv[i]);
        }
        free(strv);

        goto done;
    }

    if (pcmk__str_eq(args->output_ty, "xml", pcmk__str_none)) {
        /* Kind of a hack to display XML lists using a real tag instead of <list>.  This just
         * saves from having to write custom messages to build the lists around all these things
         */
        switch (options.rsc_cmd) {
            case cmd_execute_agent:
            case cmd_list_resources:
            case cmd_query_xml:
            case cmd_query_raw_xml:
            case cmd_list_active_ops:
            case cmd_list_all_ops:
            case cmd_colocations:
            case cmd_colocations_deep:
                pcmk__force_args(context, &error, "%s --xml-simple-list --xml-substitute", g_get_prgname());
                break;

            default:
                pcmk__force_args(context, &error, "%s --xml-substitute", g_get_prgname());
                break;
        }
    } else if (pcmk__str_eq(args->output_ty, "text", pcmk__str_null_matches)) {
        if (options.rsc_cmd == cmd_colocations || options.rsc_cmd == cmd_colocations_deep ||
            options.rsc_cmd == cmd_list_resources) {
            pcmk__force_args(context, &error, "%s --text-fancy", g_get_prgname());
        }
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (options.cmdline_config) {
        /* A resource configuration was given on the command line. Sanity-check
         * the values and set error if they don't make sense.
         */
        validate_cmdline_config();
        if (error != NULL) {
            exit_code = CRM_EX_USAGE;
            goto done;
        }

    } else if (options.cmdline_params != NULL) {
        // @COMPAT @TODO error out here when we can break backward compatibility
        g_hash_table_destroy(options.cmdline_params);
        options.cmdline_params = NULL;
    }

    if (options.require_resource && (options.rsc_id == NULL)) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Must supply a resource id with -r");
        goto done;
    }
    if (options.require_node && (options.host_uname == NULL)) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Must supply a node name with -N");
        goto done;
    }

    /*
     * Set up necessary connections
     */

    if (options.force) {
        crm_debug("Forcing...");
        cib__set_call_options(options.cib_options, crm_system_name,
                              cib_quorum_override);
    }

    if (options.find_flags && options.rsc_id) {
        options.require_dataset = TRUE;
    }

    // Establish a connection to the CIB if needed
    if (options.require_cib) {
        cib_conn = cib_new();
        if ((cib_conn == NULL) || (cib_conn->cmds == NULL)) {
            exit_code = CRM_EX_DISCONNECT;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not create CIB connection");
            goto done;
        }
        rc = cib_conn->cmds->signon(cib_conn, crm_system_name, cib_command);
        rc = pcmk_legacy2rc(rc);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not connect to the CIB: %s", pcmk_rc_str(rc));
            goto done;
        }
    }

    /* Populate working set from XML file if specified or CIB query otherwise */
    if (options.require_dataset) {
        rc = populate_working_set(&cib_xml_copy);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
    }

    // If command requires that resource exist if specified, find it
    if (options.find_flags && options.rsc_id) {
        rsc = pe_find_resource_with_flags(data_set->resources, options.rsc_id,
                                          options.find_flags);
        if (rsc == NULL) {
            exit_code = CRM_EX_NOSUCH;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Resource '%s' not found", options.rsc_id);
            goto done;
        }

        /* The --ban, --clear, --move, and --restart commands do not work with
         * instances of clone resourcs.
         */
        if (strchr(options.rsc_id, ':') != NULL && pe_rsc_is_clone(rsc->parent) &&
            (options.rsc_cmd == cmd_ban || options.rsc_cmd == cmd_clear ||
             options.rsc_cmd == cmd_move || options.rsc_cmd == cmd_restart)) {
            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Cannot operate on clone resource instance '%s'", options.rsc_id);
            goto done;
        }
    }

    // If user supplied a node name, check whether it exists
    if ((options.host_uname != NULL) && (data_set != NULL)) {
        node = pe_find_node(data_set->nodes, options.host_uname);

        if (node == NULL) {
            exit_code = CRM_EX_NOSUCH;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Node '%s' not found", options.host_uname);
            goto done;
        }
    }

    // Establish a connection to the controller if needed
    if (options.require_crmd) {
        rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error connecting to the controller: %s", pcmk_rc_str(rc));
            goto done;
        }
        pcmk_register_ipc_callback(controld_api, controller_event_callback,
                                   NULL);
        rc = pcmk_connect_ipc(controld_api, pcmk_ipc_dispatch_main);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error connecting to the controller: %s", pcmk_rc_str(rc));
            goto done;
        }
    }

    /*
     * Handle requested command
     */

    switch (options.rsc_cmd) {
        case cmd_list_resources: {
            GList *all = NULL;
            all = g_list_prepend(all, (gpointer) "*");
            rc = out->message(out, "resource-list", data_set,
                              pcmk_show_inactive_rscs | pcmk_show_rsc_only | pcmk_show_pending,
                              TRUE, all, all, FALSE);
            g_list_free(all);

            if (rc == pcmk_rc_no_output) {
                rc = ENXIO;
            }
            break;
        }

        case cmd_list_instances:
            rc = out->message(out, "resource-names-list", data_set->resources);

            if (rc != pcmk_rc_ok) {
                rc = ENXIO;
            }

            break;

        case cmd_list_standards:
        case cmd_list_providers:
        case cmd_list_alternatives:
            rc = list_providers(out, options.agent_spec);
            break;

        case cmd_list_agents:
            rc = list_agents(out, options.agent_spec);
            break;

        case cmd_metadata:
            rc = show_metadata(out, options.agent_spec);
            break;

        case cmd_restart:
            /* We don't pass data_set because rsc needs to stay valid for the
             * entire lifetime of cli_resource_restart(), but it will reset and
             * update the working set multiple times, so it needs to use its own
             * copy.
             */
            rc = cli_resource_restart(out, rsc, node, options.move_lifetime,
                                      options.timeout_ms, cib_conn,
                                      options.cib_options, options.promoted_role_only,
                                      options.force);
            break;

        case cmd_wait:
            rc = wait_till_stable(out, options.timeout_ms, cib_conn);
            break;

        case cmd_execute_agent:
            if (options.cmdline_config) {
                exit_code = cli_resource_execute_from_params(out, NULL,
                    options.v_class, options.v_provider, options.v_agent,
                    options.operation, options.cmdline_params,
                    options.override_params, options.timeout_ms,
                    args->verbosity, options.force, options.check_level);
            } else {
                exit_code = cli_resource_execute(rsc, options.rsc_id,
                    options.operation, options.override_params,
                    options.timeout_ms, cib_conn, data_set,
                    args->verbosity, options.force, options.check_level);
            }
            goto done;

        case cmd_digests:
            node = pe_find_node(data_set->nodes, options.host_uname);
            if (node == NULL) {
                rc = pcmk_rc_node_unknown;
            } else {
                rc = pcmk__resource_digests(out, rsc, node,
                                            options.override_params, data_set);
            }
            break;

        case cmd_colocations:
            rc = out->message(out, "stacks-constraints", rsc, data_set, false);
            break;

        case cmd_colocations_deep:
            rc = out->message(out, "stacks-constraints", rsc, data_set, true);
            break;

        case cmd_cts:
            rc = pcmk_rc_ok;
            g_list_foreach(data_set->resources, (GFunc) cli_resource_print_cts, out);
            cli_resource_print_cts_constraints(data_set);
            break;

        case cmd_fail:
            rc = cli_resource_fail(controld_api, options.host_uname,
                                   options.rsc_id, data_set);
            if (rc == pcmk_rc_ok) {
                start_mainloop(controld_api);
            }
            break;

        case cmd_list_active_ops:
            rc = cli_resource_print_operations(options.rsc_id,
                                               options.host_uname, TRUE,
                                               data_set);
            break;

        case cmd_list_all_ops:
            rc = cli_resource_print_operations(options.rsc_id,
                                               options.host_uname, FALSE,
                                               data_set);
            break;

        case cmd_locate: {
            GList *nodes = cli_resource_search(rsc, options.rsc_id, data_set);
            rc = out->message(out, "resource-search-list", nodes, options.rsc_id);
            g_list_free_full(nodes, free);
            break;
        }

        case cmd_query_xml:
            rc = cli_resource_print(rsc, data_set, TRUE);
            break;

        case cmd_query_raw_xml:
            rc = cli_resource_print(rsc, data_set, FALSE);
            break;

        case cmd_why:
            if ((options.host_uname != NULL) && (node == NULL)) {
                rc = pcmk_rc_node_unknown;
            } else {
                rc = out->message(out, "resource-reasons-list", cib_conn,
                                  data_set->resources, rsc, node);
            }
            break;

        case cmd_clear:
            rc = clear_constraints(out, &cib_xml_copy);
            break;

        case cmd_move:
            if (options.host_uname == NULL) {
                rc = ban_or_move(out, rsc, options.move_lifetime);
            } else {
                rc = cli_resource_move(rsc, options.rsc_id, options.host_uname,
                                       options.move_lifetime, cib_conn,
                                       options.cib_options, data_set,
                                       options.promoted_role_only,
                                       options.force);
            }

            if (rc == EINVAL) {
                exit_code = CRM_EX_USAGE;
                goto done;
            }

            break;

        case cmd_ban:
            if (options.host_uname == NULL) {
                rc = ban_or_move(out, rsc, options.move_lifetime);
            } else if (node == NULL) {
                rc = pcmk_rc_node_unknown;
            } else {
                rc = cli_resource_ban(out, options.rsc_id, node->details->uname,
                                      options.move_lifetime, NULL, cib_conn,
                                      options.cib_options,
                                      options.promoted_role_only);
            }

            if (rc == EINVAL) {
                exit_code = CRM_EX_USAGE;
                goto done;
            }

            break;

        case cmd_get_property:
            rc = out->message(out, "property-list", rsc, options.prop_name);
            if (rc == pcmk_rc_no_output) {
                rc = ENXIO;
            }

            break;

        case cmd_set_property:
            rc = set_property();
            break;

        case cmd_get_param: {
            unsigned int count = 0;
            GHashTable *params = NULL;
            pe_node_t *current = pe__find_active_on(rsc, &count, NULL);
            bool free_params = true;

            if (count > 1) {
                out->err(out, "%s is active on more than one node,"
                         " returning the default value for %s", rsc->id, crm_str(options.prop_name));
                current = NULL;
            }

            crm_debug("Looking up %s in %s", options.prop_name, rsc->id);

            if (pcmk__str_eq(options.attr_set_type, XML_TAG_ATTR_SETS, pcmk__str_casei)) {
                params = pe_rsc_params(rsc, current, data_set);
                free_params = false;

            } else if (pcmk__str_eq(options.attr_set_type, XML_TAG_META_SETS, pcmk__str_casei)) {
                params = pcmk__strkey_table(free, free);
                get_meta_attributes(params, rsc, current, data_set);

            } else {
                params = pcmk__strkey_table(free, free);
                pe__unpack_dataset_nvpairs(rsc->xml, XML_TAG_UTILIZATION, NULL, params,
                                           NULL, FALSE, data_set);
            }

            rc = out->message(out, "attribute-list", rsc, options.prop_name, params);
            if (free_params) {
                g_hash_table_destroy(params);
            }
            break;
        }

        case cmd_set_param:
            if (pcmk__str_empty(options.prop_value)) {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "You need to supply a value with the -v option");
                goto done;
            }

            /* coverity[var_deref_model] False positive */
            rc = cli_resource_update_attribute(rsc, options.rsc_id,
                                               options.prop_set,
                                               options.attr_set_type,
                                               options.prop_id,
                                               options.prop_name,
                                               options.prop_value,
                                               options.recursive, cib_conn,
                                               options.cib_options, data_set,
                                               options.force);
            break;

        case cmd_delete_param:
            /* coverity[var_deref_model] False positive */
            rc = cli_resource_delete_attribute(rsc, options.rsc_id,
                                               options.prop_set,
                                               options.attr_set_type,
                                               options.prop_id,
                                               options.prop_name, cib_conn,
                                               options.cib_options, data_set,
                                               options.force);
            break;

        case cmd_cleanup:
            if (rsc == NULL) {
                rc = cli_cleanup_all(controld_api, options.host_uname,
                                     options.operation, options.interval_spec,
                                     data_set);
                if (rc == pcmk_rc_ok) {
                    start_mainloop(controld_api);
                }
            } else {
                cleanup(out, rsc);
            }
            break;

        case cmd_refresh:
            if (rsc == NULL) {
                rc = refresh(out);
            } else {
                refresh_resource(out, rsc);
            }
            break;

        case cmd_delete:
            rc = delete();
            break;

        default:
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Unimplemented command: %d", (int) options.rsc_cmd);
            goto done;
    }

    /* Convert rc into an exit code. */
    if (rc != pcmk_rc_ok && rc != pcmk_rc_no_output) {
        if (rc == pcmk_rc_no_quorum) {
            g_prefix_error(&error, "To ignore quorum, use the force option.\n");
        }

        exit_code = pcmk_rc2exitc(rc);
    }

    /*
     * Clean up and exit
     */

done:
    /* When we get here, exit_code has been set one of two ways - either at one of
     * the spots where there's a "goto done" (which itself could have happened either
     * directly or by calling pcmk_rc2exitc), or just up above after any of the break
     * statements.
     *
     * Thus, we can use just exit_code here to decide what to do.
     */
    if (exit_code != CRM_EX_OK && exit_code != CRM_EX_USAGE) {
        if (error != NULL) {
            char *msg = crm_strdup_printf("%s\nError performing operation: %s",
                                          error->message, crm_exit_str(exit_code));
            g_clear_error(&error);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "%s", msg);
            free(msg);
        } else {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Error performing operation: %s", crm_exit_str(exit_code));
        }
    }

    g_free(options.host_uname);
    g_free(options.interval_spec);
    g_free(options.move_lifetime);
    g_free(options.operation);
    g_free(options.prop_id);
    free(options.prop_name);
    g_free(options.prop_set);
    g_free(options.prop_value);
    g_free(options.rsc_id);
    g_free(options.rsc_type);
    free(options.agent_spec);
    free(options.v_agent);
    free(options.v_class);
    free(options.v_provider);
    g_free(options.xml_file);
    g_strfreev(options.remainder);

    if (options.override_params != NULL) {
        g_hash_table_destroy(options.override_params);
    }

    /* options.cmdline_params does not need to be destroyed here.  See the
     * comments in cli_resource_execute_from_params.
     */

    g_strfreev(processed_args);
    g_option_context_free(context);

    return bye(exit_code);
}

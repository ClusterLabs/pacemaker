/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm_resource.h>
#include <crm/lrmd_internal.h>
#include <crm/common/output.h>
#include <crm/fencing/internal.h>           // stonith__agent_exists()
#include <pacemaker-internal.h>

#include <sys/param.h>
#include <stdbool.h>                        // bool, true, false
#include <stdint.h>                         // uint32_t
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <time.h>

#include <libxml/xpath.h>                   // xmlXPathObject, etc.

#include <crm/crm.h>
#include <crm/stonith-ng.h>
#include <crm/common/agents.h>          // PCMK_RESOURCE_CLASS_*
#include <crm/common/ipc_controld.h>
#include <crm/cib/internal.h>

#define SUMMARY "crm_resource - perform tasks related to Pacemaker cluster resources"

enum rsc_command {
    cmd_ban,
    cmd_cleanup,
    cmd_clear,
    cmd_colocations,
    cmd_cts,
    cmd_delete,
    cmd_delete_param,
    cmd_digests,
    cmd_execute_agent,
    cmd_fail,
    cmd_get_param,
    cmd_list_active_ops,
    cmd_list_agents,
    cmd_list_all_ops,
    cmd_list_alternatives,
    cmd_list_instances,
    cmd_list_options,
    cmd_list_providers,
    cmd_list_resources,
    cmd_list_standards,
    cmd_locate,
    cmd_metadata,
    cmd_move,
    cmd_query_xml,
    cmd_query_xml_raw,
    cmd_refresh,
    cmd_restart,
    cmd_set_param,
    cmd_wait,
    cmd_why,

    // Update this when adding new commands
    cmd_max = cmd_why,
};

/*!
 * \internal
 * \brief Handler function for a crm_resource command
 */
typedef crm_exit_t (*crm_resource_fn_t)(pcmk_resource_t *, pcmk_node_t *,
                                        cib_t *, pcmk_scheduler_t *,
                                        pcmk_ipc_api_t *, xmlNode *);

/*!
 * \internal
 * \brief Flags to define attributes of a given command
 *
 * These attributes may include required command-line options, how to look up a
 * resource in the scheduler data, whether the command supports clone instances,
 * etc.
 */
enum crm_rsc_flags {
    //! Use \c pcmk_rsc_match_anon_basename when looking up a resource
    crm_rsc_find_match_anon_basename = (UINT32_C(1) << 0),

    //! Use \c pcmk_rsc_match_basename when looking up a resource
    crm_rsc_find_match_basename      = (UINT32_C(1) << 1),

    //! Use \c pcmk_rsc_match_history when looking up a resource
    crm_rsc_find_match_history       = (UINT32_C(1) << 2),

    //! Fail if \c --resource refers to a particular clone instance
    crm_rsc_rejects_clone_instance   = (UINT32_C(1) << 3),

    //! Require CIB connection unless resource is specified by agent
    crm_rsc_requires_cib             = (UINT32_C(1) << 4),

    //! Require controller connection
    crm_rsc_requires_controller      = (UINT32_C(1) << 5),

    //! Require \c --node argument
    crm_rsc_requires_node            = (UINT32_C(1) << 6),

    //! Require \c --resource argument
    crm_rsc_requires_resource        = (UINT32_C(1) << 7),

    //! Require scheduler data unless resource is specified by agent
    crm_rsc_requires_scheduler       = (UINT32_C(1) << 8),
};

/*!
 * \internal
 * \brief Handler function and flags for a given command
 */
typedef struct {
    crm_resource_fn_t fn;   //!< Command handler function
    uint32_t flags;         //!< Group of <tt>enum crm_rsc_flags</tt>
} crm_resource_cmd_info_t;

struct {
    enum rsc_command rsc_cmd;     // crm_resource command to perform

    // Command-line option values
    gchar *rsc_id;                // Value of --resource
    gchar *rsc_type;              // Value of --resource-type
    gboolean all;                 // --all was given
    gboolean force;               // --force was given
    gboolean clear_expired;       // --expired was given
    gboolean recursive;           // --recursive was given
    gboolean promoted_role_only;  // --promoted was given
    gchar *host_uname;            // Value of --node
    gchar *interval_spec;         // Value of --interval
    gchar *move_lifetime;         // Value of --lifetime
    gchar *operation;             // Value of --operation
    enum pcmk__opt_flags opt_list;  // Parsed from --list-options
    const char *attr_set_type;    // Instance, meta, utilization, or element attribute
    gchar *prop_id;               // --nvpair (attribute XML ID)
    char *prop_name;              // Attribute name
    gchar *prop_set;              // --set-name (attribute block XML ID)
    gchar *prop_value;            // --parameter-value (attribute value)
    guint timeout_ms;             // Parsed from --timeout value
    char *agent_spec;             // Standard and/or provider and/or agent
    int check_level;              // Optional value of --validate or --force-check

    // Resource configuration specified via command-line arguments
    gchar *agent;                 // Value of --agent
    gchar *class;                 // Value of --class
    gchar *provider;              // Value of --provider
    GHashTable *cmdline_params;   // Resource parameters specified

    // Positional command-line arguments
    gchar **remainder;            // Positional arguments as given
    GHashTable *override_params;  // Resource parameter values that override config
} options = {
    .attr_set_type = PCMK_XE_INSTANCE_ATTRIBUTES,
    .check_level = -1,
    .rsc_cmd = cmd_list_resources,  // List all resources if no command given
};

static crm_exit_t exit_code = CRM_EX_OK;
static pcmk__output_t *out = NULL;
static pcmk__common_args_t *args = NULL;

// Things that should be cleaned up on exit
static GError *error = NULL;
static GMainLoop *mainloop = NULL;

#define MESSAGE_TIMEOUT_S 60

#define INDENT "                                    "

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
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

static gboolean
resource_ipc_timeout(gpointer data)
{
    // Start with newline because "Waiting for ..." message doesn't have one
    if (error != NULL) {
        g_clear_error(&error);
    }

    g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_TIMEOUT,
                _("Aborting because no messages received in %d seconds"), MESSAGE_TIMEOUT_S);

    quit_main_loop(CRM_EX_TIMEOUT);
    return FALSE;
}

static void
controller_event_callback(pcmk_ipc_api_t *api, enum pcmk_ipc_event event_type,
                          crm_exit_t status, void *event_data, void *user_data)
{
    crm_exit_t *ec = user_data;

    pcmk__assert(ec != NULL);

    switch (event_type) {
        case pcmk_ipc_event_disconnect:
            if (exit_code == CRM_EX_DISCONNECT) { // Unexpected
                pcmk__info("Connection to controller was terminated");
            }

            *ec = exit_code;
            quit_main_loop(*ec);
            break;

        case pcmk_ipc_event_reply:
            if (status != CRM_EX_OK) {
                out->err(out, "Error: bad reply from controller: %s",
                         crm_exit_str(status));
                pcmk_disconnect_ipc(api);

                *ec = status;
                quit_main_loop(*ec);

            } else {
                if ((pcmk_controld_api_replies_expected(api) == 0)
                    && (mainloop != NULL)
                    && g_main_loop_is_running(mainloop)) {

                    out->info(out, "... got reply (done)");
                    pcmk__debug("Got all the replies we expected");
                    pcmk_disconnect_ipc(api);

                    *ec = CRM_EX_OK;
                    quit_main_loop(*ec);

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
    // @TODO See if we can avoid setting exit_code as a global variable
    unsigned int count = pcmk_controld_api_replies_expected(capi);

    if (count > 0) {
        out->info(out, "Waiting for %u %s from the controller",
                  count, pcmk__plural_alt(count, "reply", "replies"));
        exit_code = CRM_EX_DISCONNECT; // For unexpected disconnects
        mainloop = g_main_loop_new(NULL, FALSE);
        pcmk__create_timer(MESSAGE_TIMEOUT_S * 1000, resource_ipc_timeout, NULL);
        g_main_loop_run(mainloop);
    }
}

static GList *
build_constraint_list(xmlNode *root)
{
    GList *retval = NULL;
    xmlNode *cib_constraints = NULL;
    xmlXPathObject *xpathObj = NULL;
    int ndx = 0;
    int num_results = 0;

    cib_constraints = pcmk_find_cib_element(root, PCMK_XE_CONSTRAINTS);
    xpathObj = pcmk__xpath_search(cib_constraints->doc,
                                  "//" PCMK_XE_RSC_LOCATION);
    num_results = pcmk__xpath_num_results(xpathObj);

    for (ndx = 0; ndx < num_results; ndx++) {
        xmlNode *match = pcmk__xpath_result(xpathObj, ndx);

        if (match != NULL) {
            retval = g_list_insert_sorted(retval, (gpointer) pcmk__xe_id(match),
                                          (GCompareFunc) g_strcmp0);
        }
    }

    xmlXPathFreeObject(xpathObj);
    return retval;
}

static gboolean
validate_opt_list(const gchar *optarg)
{
    if (pcmk__str_eq(optarg, PCMK_VALUE_FENCING, pcmk__str_none)) {
        options.opt_list = pcmk__opt_fencing;

    } else if (pcmk__str_eq(optarg, PCMK__VALUE_PRIMITIVE, pcmk__str_none)) {
        options.opt_list = pcmk__opt_primitive;

    } else {
        return FALSE;
    }

    return TRUE;
}

// GOptionArgFunc callback functions

static gboolean
attr_set_type_cb(const gchar *option_name, const gchar *optarg, gpointer data,
                 GError **error) {
    if (pcmk__str_any_of(option_name, "-m", "--meta", NULL)) {
        options.attr_set_type = PCMK_XE_META_ATTRIBUTES;
    } else if (pcmk__str_any_of(option_name, "-z", "--utilization", NULL)) {
        options.attr_set_type = PCMK_XE_UTILIZATION;
    } else if (pcmk__str_eq(option_name, "--element", pcmk__str_none)) {
        options.attr_set_type = ATTR_SET_ELEMENT;
    }
    return TRUE;
}

/*!
 * \internal
 * \brief Process options that set the command
 *
 * Nothing else should set \c options.rsc_cmd.
 *
 * \param[in]  option_name  Name of the option being parsed
 * \param[in]  optarg       Value to be parsed
 * \param[in]  data         Ignored
 * \param[out] error        Where to store recoverable error, if any
 *
 * \return \c TRUE if the option was successfully parsed, or \c FALSE if an
 *         error occurred, in which case \p *error is set
 */
static gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    // Sorted by enum rsc_command name
    if (pcmk__str_any_of(option_name, "-B", "--ban", NULL)) {
        options.rsc_cmd = cmd_ban;

    } else if (pcmk__str_any_of(option_name, "-C", "--cleanup", NULL)) {
        options.rsc_cmd = cmd_cleanup;

    } else if (pcmk__str_any_of(option_name, "-U", "--clear", NULL)) {
        options.rsc_cmd = cmd_clear;

    } else if (pcmk__str_any_of(option_name, "-a", "--constraints", NULL)) {
        options.rsc_cmd = cmd_colocations;

    } else if (pcmk__str_any_of(option_name, "-A", "--stack", NULL)) {
        options.rsc_cmd = cmd_colocations;
        options.recursive = TRUE;

    } else if (pcmk__str_any_of(option_name, "-c", "--list-cts", NULL)) {
        options.rsc_cmd = cmd_cts;

    } else if (pcmk__str_any_of(option_name, "-D", "--delete", NULL)) {
        options.rsc_cmd = cmd_delete;

    } else if (pcmk__str_any_of(option_name, "-d", "--delete-parameter",
                                NULL)) {
        options.rsc_cmd = cmd_delete_param;
        pcmk__str_update(&options.prop_name, optarg);

    } else if (pcmk__str_eq(option_name, "--digests", pcmk__str_none)) {
        options.rsc_cmd = cmd_digests;

        if (options.override_params == NULL) {
            options.override_params = pcmk__strkey_table(g_free, g_free);
        }

    } else if (pcmk__str_any_of(option_name,
                                "--force-demote", "--force-promote",
                                "--force-start", "--force-stop",
                                "--force-check", "--validate", NULL)) {
        options.rsc_cmd = cmd_execute_agent;

        g_free(options.operation);
        options.operation = g_strdup(option_name + 2);  // skip "--"

        if (options.override_params == NULL) {
            options.override_params = pcmk__strkey_table(g_free, g_free);
        }

        if (optarg != NULL) {
            if (pcmk__scan_min_int(optarg, &options.check_level,
                                   0) != pcmk_rc_ok) {
                g_set_error(error, G_OPTION_ERROR, CRM_EX_INVALID_PARAM,
                            _("Invalid check level setting: %s"), optarg);
                return FALSE;
            }
        }

    } else if (pcmk__str_any_of(option_name, "-F", "--fail", NULL)) {
        options.rsc_cmd = cmd_fail;

    } else if (pcmk__str_any_of(option_name, "-g", "--get-parameter", NULL)) {
        options.rsc_cmd = cmd_get_param;
        pcmk__str_update(&options.prop_name, optarg);

    } else if (pcmk__str_any_of(option_name, "-O", "--list-operations", NULL)) {
        options.rsc_cmd = cmd_list_active_ops;

    } else if (pcmk__str_eq(option_name, "--list-agents", pcmk__str_none)) {
        options.rsc_cmd = cmd_list_agents;
        pcmk__str_update(&options.agent_spec, optarg);

    } else if (pcmk__str_any_of(option_name, "-o", "--list-all-operations",
                                NULL)) {
        options.rsc_cmd = cmd_list_all_ops;

    } else if (pcmk__str_eq(option_name, "--list-ocf-alternatives",
                            pcmk__str_none)) {
        options.rsc_cmd = cmd_list_alternatives;
        pcmk__str_update(&options.agent_spec, optarg);

    } else if (pcmk__str_eq(option_name, "--list-options", pcmk__str_none)) {
        options.rsc_cmd = cmd_list_options;
        return validate_opt_list(optarg);

    } else if (pcmk__str_any_of(option_name, "-l", "--list-raw", NULL)) {
        options.rsc_cmd = cmd_list_instances;

    } else if (pcmk__str_eq(option_name, "--list-ocf-providers",
                            pcmk__str_none)) {
        options.rsc_cmd = cmd_list_providers;
        pcmk__str_update(&options.agent_spec, optarg);

    } else if (pcmk__str_any_of(option_name, "-L", "--list", NULL)) {
        options.rsc_cmd = cmd_list_resources;

    } else if (pcmk__str_eq(option_name, "--list-standards", pcmk__str_none)) {
        options.rsc_cmd = cmd_list_standards;

    } else if (pcmk__str_any_of(option_name, "-W", "--locate", NULL)) {
        options.rsc_cmd = cmd_locate;

    } else if (pcmk__str_eq(option_name, "--show-metadata", pcmk__str_none)) {
        options.rsc_cmd = cmd_metadata;
        pcmk__str_update(&options.agent_spec, optarg);

    } else if (pcmk__str_any_of(option_name, "-M", "--move", NULL)) {
        options.rsc_cmd = cmd_move;

    } else if (pcmk__str_any_of(option_name, "-q", "--query-xml", NULL)) {
        options.rsc_cmd = cmd_query_xml;

    } else if (pcmk__str_any_of(option_name, "-w", "--query-xml-raw", NULL)) {
        options.rsc_cmd = cmd_query_xml_raw;

    } else if (pcmk__str_any_of(option_name, "-R", "--refresh", NULL)) {
        options.rsc_cmd = cmd_refresh;

    } else if (pcmk__str_eq(option_name, "--restart", pcmk__str_none)) {
        options.rsc_cmd = cmd_restart;

    } else if (pcmk__str_any_of(option_name, "-p", "--set-parameter", NULL)) {
        options.rsc_cmd = cmd_set_param;
        pcmk__str_update(&options.prop_name, optarg);

    } else if (pcmk__str_eq(option_name, "--wait", pcmk__str_none)) {
        options.rsc_cmd = cmd_wait;

    } else if (pcmk__str_any_of(option_name, "-Y", "--why", NULL)) {
        options.rsc_cmd = cmd_why;
    }

    return TRUE;
}

static gboolean
option_cb(const gchar *option_name, const gchar *optarg, gpointer data,
          GError **error)
{
    gchar *name = NULL;
    gchar *value = NULL;

    if (pcmk__scan_nvpair(optarg, &name, &value) != pcmk_rc_ok) {
        return FALSE;
    }

    /* services__create_resource_action() ultimately takes ownership of
     * options.cmdline_params. It's not worth trying to ensure that the entire
     * call path uses (gchar *) strings and g_free(). So create the table for
     * (char *) strings, and duplicate the (gchar *) strings when inserting.
     */
    if (options.cmdline_params == NULL) {
        options.cmdline_params = pcmk__strkey_table(free, free);
    }
    pcmk__insert_dup(options.cmdline_params, name, value);
    g_free(name);
    g_free(value);
    return TRUE;
}

static gboolean
timeout_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    long long timeout_ms = 0;

    if ((pcmk__parse_ms(optarg, &timeout_ms) != pcmk_rc_ok)
        || (timeout_ms < 0)) {
        return FALSE;
    }
    options.timeout_ms = (guint) QB_MIN(timeout_ms, UINT_MAX);
    return TRUE;
}

// Command line option specification

/* short option letters still available: eEJkKXyYZ */

static GOptionEntry query_entries[] = {
    { "list", 'L', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "List all cluster resources with status",
      NULL },
    { "list-raw", 'l', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "List IDs of all instantiated resources (individual members\n"
      INDENT "rather than groups etc.)",
      NULL },
    { "list-cts", 'c', G_OPTION_FLAG_HIDDEN|G_OPTION_FLAG_NO_ARG,
          G_OPTION_ARG_CALLBACK, command_cb,
      NULL,
      NULL },
    { "list-operations", 'O', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "List active resource operations, optionally filtered by\n"
      INDENT "--resource and/or --node",
      NULL },
    { "list-all-operations", 'o', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "List all resource operations, optionally filtered by\n"
      INDENT "--resource and/or --node",
      NULL },
    { "list-options", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "List all available options of the given type.\n"
      INDENT "Allowed values:\n"
      INDENT PCMK__VALUE_PRIMITIVE " (primitive resource meta-attributes),\n"
      INDENT PCMK_VALUE_FENCING " (parameters common to all fencing resources)",
      "TYPE" },
    { "list-standards", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "List supported standards",
      NULL },
    { "list-ocf-providers", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "List all available OCF providers",
      NULL },
    { "list-agents", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          command_cb,
      "List all agents available for the named standard and/or provider",
      "STD:PROV" },
    { "list-ocf-alternatives", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          command_cb,
      "List all available providers for the named OCF agent",
      "AGENT" },
    { "show-metadata", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "Show the metadata for the named class:provider:agent",
      "SPEC" },
    { "query-xml", 'q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Show XML configuration of resource (after any template expansion)",
      NULL },
    { "query-xml-raw", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "Show XML configuration of resource (before any template expansion)",
      NULL },
    { "get-parameter", 'g', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          command_cb,
      "Display named parameter for resource (use instance attribute\n"
      INDENT "unless --element, --meta, or --utilization is specified)",
      "PARAM" },
    { "locate", 'W', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Show node(s) currently running resource",
      NULL },
    { "constraints", 'a', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "Display the location and colocation constraints that apply to a\n"
      INDENT "resource, and if --recursive is specified, to the resources\n"
      INDENT "directly or indirectly involved in those colocations.\n"
      INDENT "If the named resource is part of a group, or a clone or\n"
      INDENT "bundle instance, constraints for the collective resource\n"
      INDENT "will be shown unless --force is given.",
      NULL },
    { "stack", 'A', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Equivalent to --constraints --recursive",
      NULL },
    { "why", 'Y', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Show why resources are not running, optionally filtered by\n"
      INDENT "--resource and/or --node",
      NULL },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "validate", 0, G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "Validate resource configuration by calling agent's validate-all\n"
      INDENT "action. The configuration may be specified either by giving an\n"
      INDENT "existing resource name with -r, or by specifying --class,\n"
      INDENT "--agent, and --provider arguments, along with any number of\n"
      INDENT "--option arguments. An optional LEVEL argument can be given\n"
      INDENT "to control the level of checking performed.",
      "LEVEL" },
    { "cleanup", 'C', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "If resource has any past failures, clear its history and fail\n"
      INDENT "count. Optionally filtered by --resource, --node, --operation\n"
      INDENT "and --interval (otherwise all). --operation and --interval\n"
      INDENT "apply to fail counts, but entire history is always clear, to\n"
      INDENT "allow current state to be rechecked. If the named resource is\n"
      INDENT "part of a group, or one numbered instance of a clone or bundled\n"
      INDENT "resource, the clean-up applies to the whole collective resource\n"
      INDENT "unless --force is given.",
      NULL },
    { "refresh", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Delete resource's history (including failures) so its current state\n"
      INDENT "is rechecked. Optionally filtered by --resource and --node\n"
      INDENT "(otherwise all). If the named resource is part of a group, or one\n"
      INDENT "numbered instance of a clone or bundled resource, the refresh\n"
      INDENT "applies to the whole collective resource unless --force is given.",
      NULL },
    { "set-parameter", 'p', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          command_cb,
      "Set named parameter for resource (requires -v). Use instance\n"
      INDENT "attribute unless --element, --meta, or --utilization is "
      "specified.",
      "PARAM" },
    { "delete-parameter", 'd', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          command_cb,
      "Delete named parameter for resource. Use instance attribute\n"
      INDENT "unless --element, --meta or, --utilization is specified.",
      "PARAM" },

    { NULL }
};

static GOptionEntry location_entries[] = {
    { "move", 'M', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
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
    { "ban", 'B', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Create a constraint to keep resource off a node.\n"
      INDENT "Optional: --node, --lifetime, --promoted.\n"
      INDENT "NOTE: This will prevent the resource from running on the\n"
      INDENT "affected node until the implicit constraint expires or is\n"
      INDENT "removed with --clear. If --node is not specified, it defaults\n"
      INDENT "to the node currently running the resource for primitives\n"
      INDENT "and groups, or the promoted instance of promotable clones with\n"
      INDENT PCMK_META_PROMOTED_MAX "=1 (all other situations result in an\n"
      INDENT "error as there is no sane default).",
      NULL },
    { "clear", 'U', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Remove all constraints created by the --ban and/or --move\n"
      INDENT "commands. Requires: --resource. Optional: --node, --promoted,\n"
      INDENT "--expired. If --node is not specified, all constraints created\n"
      INDENT "by --ban and --move will be removed for the named resource. If\n"
      INDENT "--node and --force are specified, any constraint created by\n"
      INDENT "--move will be cleared, even if it is not for the specified\n"
      INDENT "node. If --expired is specified, only those constraints whose\n"
      INDENT "lifetimes have expired will be removed.",
      NULL },
    { "expired", 'e', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
          &options.clear_expired,
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
    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Delete a resource from the CIB. Required: -t",
      NULL },
    { "fail", 'F', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Tell the cluster this resource has failed",
      NULL },
    { "restart", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Tell the cluster to restart this resource and\n"
      INDENT "anything that depends on it. This temporarily modifies\n"
      INDENT "the CIB, and other CIB modifications should be avoided\n"
      INDENT "while this is in progress. If a node is fenced because\n"
      INDENT "the stop portion of the restart fails, CIB modifications\n"
      INDENT "such as target-role may remain.",
      NULL },
    { "wait", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Wait until the cluster settles into a stable state",
      NULL },
    { "digests", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Show parameter hashes that Pacemaker uses to detect\n"
      INDENT "configuration changes (only accurate if there is resource\n"
      INDENT "history on the specified node). Required: --resource, --node.\n"
      INDENT "Optional: any NAME=VALUE parameters will be used to override\n"
      INDENT "the configuration (to see what the hash would be with those\n"
      INDENT "changes).",
      NULL },
    { "force-demote", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "(Advanced) Bypass the cluster and demote a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-stop", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Bypass the cluster and stop a resource on the local node",
      NULL },
    { "force-start", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Bypass the cluster and start a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-promote", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
      "(Advanced) Bypass the cluster and promote a resource on the local\n"
      INDENT "node. Unless --force is specified, this will refuse to do so if\n"
      INDENT "the cluster believes the resource is a clone instance already\n"
      INDENT "running on the local node.",
      NULL },
    { "force-check", 0, G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
          command_cb,
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
      "Follow colocation chains when using --set-parameter or --constraints",
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
    { "element", 0, G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, attr_set_type_cb,
      "Use resource element attribute instead of instance attribute\n"
      INDENT "(with -p, -g, -d)",
      NULL },
    { "operation", 'n', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.operation,
      "Operation to clear instead of all (with -C -r)",
      "OPERATION" },
    { "interval", 'I', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.interval_spec,
      "Interval of operation to clear (default 0s) (with -C -r -n)",
      "N" },
    { "class", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.class,
      "The standard the resource agent conforms to (for example, ocf).\n"
      INDENT "Use with --agent, --provider, --option, and --validate.",
      "CLASS" },
    { "agent", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.agent,
      "The agent to use (for example, IPaddr). Use with --class,\n"
      INDENT "--provider, --option, and --validate.",
      "AGENT" },
    { "provider", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.provider,
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
      INDENT "--restart, --wait, --force-*). The --restart command uses a\n"
      INDENT "two-second granularity and the --wait command uses a one-second\n"
      INDENT "granularity, with rounding.",
      "N" },
    { "all", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.all,
      "List all options, including advanced and deprecated (with\n"
      INDENT "--list-options)",
      NULL },
    { "force", 'f', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.force,
      "Force the action to be performed. See help for individual commands for\n"
      INDENT "additional behavior.",
      NULL },

    // @COMPAT Used in resource-agents prior to v4.2.0
    { "host-uname", 'H', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &options.host_uname,
      NULL,
      "HOST" },

    { NULL }
};

static int
ban_or_move(pcmk__output_t *out, pcmk_resource_t *rsc, cib_t *cib_conn,
            const char *move_lifetime)
{
    int rc = pcmk_rc_ok;
    pcmk_node_t *current = NULL;
    unsigned int nactive = 0;

    CRM_CHECK(rsc != NULL, return EINVAL);

    current = pe__find_active_requires(rsc, &nactive);

    if (nactive == 1) {
        rc = cli_resource_ban(out, options.rsc_id, current->priv->name,
                              move_lifetime, cib_conn,
                              options.promoted_role_only, PCMK_ROLE_PROMOTED);

    } else if (pcmk__is_set(rsc->flags, pcmk__rsc_promotable)) {
        int count = 0;
        GList *iter = NULL;

        current = NULL;
        for (iter = rsc->priv->children; iter != NULL; iter = iter->next) {
            pcmk_resource_t *child = (pcmk_resource_t *)iter->data;
            enum rsc_role_e child_role = child->priv->fns->state(child, true);

            if (child_role == pcmk_role_promoted) {
                count++;
                current = pcmk__current_node(child);
            }
        }

        if(count == 1 && current) {
            rc = cli_resource_ban(out, options.rsc_id, current->priv->name,
                                  move_lifetime, cib_conn,
                                  options.promoted_role_only,
                                  PCMK_ROLE_PROMOTED);

        } else {
            rc = EINVAL;
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("Resource '%s' not moved: active in %d locations (promoted in %d).\n"
                        "To prevent '%s' from running on a specific location, "
                        "specify a node."
                        "To prevent '%s' from being promoted at a specific "
                        "location, specify a node and the --promoted option."),
                        options.rsc_id, nactive, count, options.rsc_id, options.rsc_id);
        }

    } else {
        rc = EINVAL;
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    _("Resource '%s' not moved: active in %d locations.\n"
                    "To prevent '%s' from running on a specific location, "
                    "specify a node."),
                    options.rsc_id, nactive, options.rsc_id);
    }

    return rc;
}

static void
cleanup(pcmk__output_t *out, pcmk_resource_t *rsc, pcmk_node_t *node,
        pcmk_ipc_api_t *controld_api)
{
    int rc = pcmk_rc_ok;

    if (options.force == FALSE) {
        rsc = uber_parent(rsc);
    }

    pcmk__debug("Erasing failures of %s (%s requested) on %s", rsc->id,
                options.rsc_id,
                ((node != NULL)? pcmk__node_name(node) : "all nodes"));
    rc = cli_resource_delete(controld_api, rsc, node, options.operation,
                             options.interval_spec, true, options.force);

    if ((rc == pcmk_rc_ok) && !out->is_quiet(out)) {
        // Show any reasons why resource might stay stopped
        cli_resource_check(out, rsc, node);
    }

    /* @FIXME The mainloop functions in this file set exit_code. What happens to
     * exit_code if rc != pcmk_rc_ok here?
     */
    if (rc == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }
}

/*!
 * \internal
 * \brief Allocate a scheduler data object and initialize it from the CIB
 *
 * We transform the queried CIB XML to the latest schema version before using it
 * to populate the scheduler data.
 *
 * \param[out] scheduler     Where to store scheduler data
 * \param[in]  cib_conn      CIB connection
 * \param[in]  out           Output object for new scheduler data object
 * \param[out] cib_xml_orig  Where to store queried CIB XML from before any
 *                           schema upgrades
 *
 * \return Standard Pacemaker return code
 *
 * \note \p *scheduler and \p *cib_xml_orig must be \c NULL when this function
 *       is called.
 * \note The caller is responsible for freeing \p *scheduler using
 *       \c pcmk_free_scheduler.
 */
static int
initialize_scheduler_data(pcmk_scheduler_t **scheduler, cib_t *cib_conn,
                          pcmk__output_t *out, xmlNode **cib_xml_orig)
{
    int rc = pcmk_rc_ok;

    pcmk__assert((scheduler != NULL) && (*scheduler == NULL)
                 && (cib_conn != NULL) && (out != NULL)
                 && (cib_xml_orig != NULL) && (*cib_xml_orig == NULL));

    *scheduler = pcmk_new_scheduler();
    if (*scheduler == NULL) {
        return ENOMEM;
    }

    pcmk__set_scheduler_flags(*scheduler, pcmk__sched_no_counts);
    (*scheduler)->priv->out = out;

    rc = update_scheduler_input(out, *scheduler, cib_conn, cib_xml_orig);
    if (rc != pcmk_rc_ok) {
        pcmk_free_scheduler(*scheduler);
        *scheduler = NULL;
        return rc;
    }

    cluster_status(*scheduler);
    return pcmk_rc_ok;
}

static crm_exit_t
refresh(pcmk__output_t *out, const pcmk_node_t *node,
        pcmk_ipc_api_t *controld_api)
{
    const char *node_name = NULL;
    const char *log_node_name = "all nodes";
    const char *router_node = NULL;
    int attr_options = pcmk__node_attr_none;
    int rc = pcmk_rc_ok;

    if (node != NULL) {
        node_name = node->priv->name;
        log_node_name = pcmk__node_name(node);
        router_node = node->priv->name;
    }

    if (pcmk__is_pacemaker_remote_node(node)) {
        const pcmk_node_t *conn_host = pcmk__current_node(node->priv->remote);

        if (conn_host == NULL) {
            rc = ENXIO;
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        _("No cluster connection to Pacemaker Remote node %s "
                          "detected"),
                        log_node_name);
            return pcmk_rc2exitc(rc);
        }
        router_node = conn_host->priv->name;
        pcmk__set_node_attr_flags(attr_options, pcmk__node_attr_remote);
    }

    if (controld_api == NULL) {
        out->info(out, "Dry run: skipping clean-up of %s due to CIB_file",
                  log_node_name);
        return CRM_EX_OK;
    }

    pcmk__debug("Re-checking the state of all resources on %s", log_node_name);

    // @FIXME We shouldn't discard rc here
    rc = pcmk__attrd_api_clear_failures(NULL, node_name, NULL, NULL, NULL, NULL,
                                        attr_options);

    /* @FIXME The mainloop functions in this file set exit_code. What happens to
     * exit_code if pcmk_controld_api_reprobe() doesn't return pcmk_rc_ok?
     */
    if (pcmk_controld_api_reprobe(controld_api, node_name,
                                  router_node) == pcmk_rc_ok) {
        start_mainloop(controld_api);
        return exit_code;
    }

    return pcmk_rc2exitc(rc);
}

static void
refresh_resource(pcmk__output_t *out, pcmk_resource_t *rsc, pcmk_node_t *node,
                 pcmk_ipc_api_t *controld_api)
{
    int rc = pcmk_rc_ok;

    if (options.force == FALSE) {
        rsc = uber_parent(rsc);
    }

    pcmk__debug("Re-checking the state of %s (%s requested) on %s", rsc->id,
                options.rsc_id,
                ((node != NULL)? pcmk__node_name(node) : "all nodes"));
    rc = cli_resource_delete(controld_api, rsc, node, NULL, 0, false,
                             options.force);

    if ((rc == pcmk_rc_ok) && !out->is_quiet(out)) {
        // Show any reasons why resource might stay stopped
        cli_resource_check(out, rsc, node);
    }

    /* @FIXME The mainloop functions in this file set exit_code. What happens to
     * exit_code if rc != pcmk_rc_ok here?
     */
    if (rc == pcmk_rc_ok) {
        start_mainloop(controld_api);
    }
}

/*!
 * \internal
 * \brief Check whether a command-line resource configuration was given
 *
 * \return \c true if \c --class, \c --provider, or \c --agent was specified, or
 *         \c false otherwise
 */
static inline bool
has_cmdline_config(void)
{
    return ((options.class != NULL) || (options.provider != NULL)
            || (options.agent != NULL));
}

static void
validate_cmdline_config(void)
{
    bool is_ocf = pcmk__str_eq(options.class, PCMK_RESOURCE_CLASS_OCF,
                               pcmk__str_none);

    // Sanity check before throwing any errors
    if (!has_cmdline_config()) {
        return;
    }

    // Cannot use both --resource and command-line resource configuration
    if (options.rsc_id != NULL) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    _("--class, --agent, and --provider cannot be used with "
                      "-r/--resource"));
        return;
    }

    /* Check whether command supports command-line resource configuration
     *
     * @FIXME According to the help text, these options can only be used with
     * --validate. The --force-* commands are documented for resources that are
     * configured in Pacemaker. So this is a bug. We have two choices:
     * * Throw an error if --force-* commands are used with these options.
     * * Document that --force-* commands can be used with these options.
     *
     * An error seems safer. If a user really wants to run a non-trivial
     * resource action based on CLI parameters, they can do so by executing the
     * resource agent directly. It's unsafe to do so if Pacemaker is managing
     * the resource that's specified via --class, --option, etc.
     *
     * On the other hand, besides safety concerns, running other actions is
     * exactly the same as running a validate action, and the implementation is
     * already in place.
     */
    if (options.rsc_cmd != cmd_execute_agent) {
        g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    _("--class, --agent, and --provider can only be used with "
                      "--validate and --force-*"));
        return;
    }

    // Check for a valid combination of --class, --agent, and --provider
    if (is_ocf) {
        if ((options.provider == NULL) || (options.agent == NULL)) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("--provider and --agent are required with "
                          "--class=ocf"));
            return;
        }

    } else {
        if (options.provider != NULL) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("--provider is supported only with --class=ocf"));
            return;
        }

        // Either --class or --agent was given
        if (options.agent == NULL) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("--agent is required with --class"));
            return;
        }
        if (options.class == NULL) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("--class is required with --agent"));
            return;
        }
    }

    // Check whether agent exists
    if (pcmk__str_eq(options.class, PCMK_RESOURCE_CLASS_STONITH,
                     pcmk__str_none)) {
        if (!stonith__agent_exists(options.agent)) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("%s is not a known fencing agent"), options.agent);
            return;
        }

    } else if (!resources_agent_exists(options.class, options.provider,
                                       options.agent)) {
        if (is_ocf) {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("%s:%s:%s is not a known resource agent"),
                        options.class, options.provider, options.agent);
        } else {
            g_set_error(&error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                        _("%s:%s is not a known resource agent"),
                        options.class, options.agent);
        }
        return;
    }

    if (options.cmdline_params == NULL) {
        options.cmdline_params = pcmk__strkey_table(free, free);
    }
}

static crm_exit_t
handle_ban(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
           pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
           xmlNode *cib_xml_orig)
{
    int rc = pcmk_rc_ok;

    if (node == NULL) {
        rc = ban_or_move(out, rsc, cib_conn, options.move_lifetime);
    } else {
        rc = cli_resource_ban(out, options.rsc_id, node->priv->name,
                              options.move_lifetime, cib_conn,
                              options.promoted_role_only, PCMK_ROLE_PROMOTED);
    }

    if (rc == EINVAL) {
        return CRM_EX_USAGE;
    }
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_cleanup(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
               pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
               xmlNode *cib_xml_orig)
{
    if (rsc == NULL) {
        int rc = cli_cleanup_all(controld_api, node, options.operation,
                                 options.interval_spec, scheduler);

        if (rc == pcmk_rc_ok) {
            start_mainloop(controld_api);
        }

    } else {
        cleanup(out, rsc, node, controld_api);
    }

    /* @FIXME Both of the blocks above are supposed to set exit_code via
     * start_mainloop(). But if cli_cleanup_all() or cli_resource_delete()
     * fails, we never start the mainloop. It looks as if we exit with CRM_EX_OK
     * in those cases.
     */
    return exit_code;
}

static crm_exit_t
handle_clear(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
             pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
             xmlNode *cib_xml_orig)
{
    const char *node_name = (node != NULL)? node->priv->name : NULL;
    GList *before = NULL;
    GList *after = NULL;
    GList *remaining = NULL;
    int rc = pcmk_rc_ok;

    if (!out->is_quiet(out)) {
        before = build_constraint_list(scheduler->input);
    }

    if (options.clear_expired) {
        rc = cli_resource_clear_all_expired(scheduler->input, cib_conn,
                                            options.rsc_id, node_name,
                                            options.promoted_role_only);

    } else if (node != NULL) {
        rc = cli_resource_clear(options.rsc_id, node_name, NULL, cib_conn, true,
                                options.force);

    } else {
        rc = cli_resource_clear(options.rsc_id, NULL, scheduler->nodes,
                                cib_conn, true, options.force);
    }

    if (!out->is_quiet(out)) {
        xmlNode *cib_xml = NULL;

        rc = cib_conn->cmds->query(cib_conn, NULL, &cib_xml, cib_sync_call);
        rc = pcmk_legacy2rc(rc);

        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        _("Could not get modified CIB: %s"), pcmk_rc_str(rc));
            g_list_free(before);
            pcmk__xml_free(cib_xml);
            return pcmk_rc2exitc(rc);
        }

        scheduler->input = cib_xml;
        cluster_status(scheduler);

        after = build_constraint_list(scheduler->input);
        remaining = pcmk__subtract_lists(before, after, (GCompareFunc) strcmp);

        for (const GList *iter = remaining; iter != NULL; iter = iter->next) {
            const char *constraint = iter->data;

            out->info(out, "Removing constraint: %s", constraint);
        }

        g_list_free(before);
        g_list_free(after);
        g_list_free(remaining);
    }

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_colocations(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                   pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                   xmlNode *cib_xml_orig)
{
    int rc = out->message(out, "locations-and-colocations", rsc,
                          options.recursive, options.force);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_cts(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
           pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
           xmlNode *cib_xml_orig)
{
    g_list_foreach(scheduler->priv->resources, (GFunc) cli_resource_print_cts,
                   out);
    cli_resource_print_cts_constraints(scheduler);
    return CRM_EX_OK;
}

static crm_exit_t
handle_delete(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
              pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
              xmlNode *cib_xml_orig)
{
    /* rsc_id was already checked for NULL much earlier when validating command
     * line arguments
     */
    int rc = pcmk_rc_ok;

    if (options.rsc_type == NULL) {
        crm_exit_t ec = CRM_EX_USAGE;

        g_set_error(&error, PCMK__EXITC_ERROR, ec,
                    _("You need to specify a resource type with -t"));
        return ec;
    }

    rc = pcmk__resource_delete(cib_conn, cib_sync_call, options.rsc_id,
                               options.rsc_type);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    _("Could not delete resource %s: %s"),
                    options.rsc_id, pcmk_rc_str(rc));
    }
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_delete_param(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                    pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                    xmlNode *cib_xml_orig)
{
    int rc = cli_resource_delete_attribute(rsc, options.rsc_id,
                                           options.prop_set,
                                           options.attr_set_type,
                                           options.prop_id,
                                           options.prop_name, cib_conn,
                                           cib_xml_orig, options.force);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_digests(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
               pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
               xmlNode *cib_xml_orig)
{
    int rc = pcmk__resource_digests(out, rsc, node, options.override_params);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_execute_agent(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                     pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                     xmlNode *cib_xml_orig)
{
    if (has_cmdline_config()) {
        return cli_resource_execute_from_params(out, NULL, options.class,
                                                options.provider, options.agent,
                                                options.operation,
                                                options.cmdline_params,
                                                options.override_params,
                                                options.timeout_ms,
                                                args->verbosity, options.force,
                                                options.check_level);
    }
    return cli_resource_execute(rsc, options.rsc_id, options.operation,
                                options.override_params, options.timeout_ms,
                                cib_conn, args->verbosity, options.force,
                                options.check_level);
}

static crm_exit_t
handle_fail(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
            pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
            xmlNode *cib_xml_orig)
{
    int rc = cli_resource_fail(controld_api, rsc, options.rsc_id, node);

    if (rc == pcmk_rc_ok) {
        // start_mainloop() sets exit_code
        start_mainloop(controld_api);
        return exit_code;
    }
    return pcmk_rc2exitc(rc);;
}

static crm_exit_t
handle_get_param(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                 pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                 xmlNode *cib_xml_orig)
{
    unsigned int count = 0;
    GHashTable *params = NULL;
    pcmk_node_t *current = rsc->priv->fns->active_node(rsc, &count, NULL);
    bool free_params = true;
    const char *value = NULL;
    int rc = pcmk_rc_ok;

    if (count > 1) {
        out->err(out,
                 "%s is active on more than one node, returning the default "
                 "value for %s",
                 rsc->id, pcmk__s(options.prop_name, "unspecified property"));
        current = NULL;
    }

    pcmk__debug("Looking up %s in %s", options.prop_name, rsc->id);

    if (pcmk__str_eq(options.attr_set_type, PCMK_XE_INSTANCE_ATTRIBUTES,
                     pcmk__str_none)) {
        params = pe_rsc_params(rsc, current, scheduler);
        free_params = false;

        value = g_hash_table_lookup(params, options.prop_name);

    } else if (pcmk__str_eq(options.attr_set_type, PCMK_XE_META_ATTRIBUTES,
                            pcmk__str_none)) {
        params = pcmk__strkey_table(free, free);
        get_meta_attributes(params, rsc, NULL, scheduler);

        value = g_hash_table_lookup(params, options.prop_name);

    } else if (pcmk__str_eq(options.attr_set_type, ATTR_SET_ELEMENT,
                            pcmk__str_none)) {
        value = pcmk__xe_get(rsc->priv->xml, options.prop_name);
        free_params = false;

    } else {
        const pcmk_rule_input_t rule_input = {
            .now = scheduler->priv->now,
        };

        params = pcmk__strkey_table(free, free);
        pe__unpack_dataset_nvpairs(rsc->priv->xml, PCMK_XE_UTILIZATION,
                                   &rule_input, params, NULL, scheduler);

        value = g_hash_table_lookup(params, options.prop_name);
    }

    rc = out->message(out, "attribute-list", rsc, options.prop_name, value);
    if (free_params) {
        g_hash_table_destroy(params);
    }

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_active_ops(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                       pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                       xmlNode *cib_xml_orig)
{
    const char *node_name = (node != NULL)? node->priv->name : NULL;
    int rc = cli_resource_print_operations(options.rsc_id, node_name, true,
                                           scheduler);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_agents(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                   pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                   xmlNode *cib_xml_orig)
{
    int rc = pcmk__list_agents(out, options.agent_spec);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_all_ops(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                    pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                    xmlNode *cib_xml_orig)
{
    const char *node_name = (node != NULL)? node->priv->name : NULL;
    int rc = cli_resource_print_operations(options.rsc_id, node_name, false,
                                           scheduler);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_alternatives(pcmk_resource_t *rsc, pcmk_node_t *node,
                         cib_t *cib_conn, pcmk_scheduler_t *scheduler,
                         pcmk_ipc_api_t *controld_api, xmlNode *cib_xml_orig)
{
    int rc = pcmk__list_alternatives(out, options.agent_spec);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_instances(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                      pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                      xmlNode *cib_xml_orig)
{
    int rc = out->message(out, "resource-names-list",
                          scheduler->priv->resources);

    if (rc == pcmk_rc_no_output) {
        // @COMPAT It seems wrong to return an error because there no resources
        return CRM_EX_NOSUCH;
    }
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_options(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                    pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                    xmlNode *cib_xml_orig)
{
    crm_exit_t ec = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    switch (options.opt_list) {
        case pcmk__opt_fencing:
            rc = pcmk__list_fencing_params(out, options.all);
            return pcmk_rc2exitc(rc);

        case pcmk__opt_primitive:
            rc = pcmk__list_primitive_meta(out, options.all);
            return pcmk_rc2exitc(rc);

        default:
            ec = CRM_EX_SOFTWARE;
            g_set_error(&error, PCMK__EXITC_ERROR, ec,
                        "Bug: Invalid option list type");
            return ec;
    }
}

static crm_exit_t
handle_list_providers(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                      pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                      xmlNode *cib_xml_orig)
{
    int rc = pcmk__list_providers(out, options.agent_spec);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_resources(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                      pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                      xmlNode *cib_xml_orig)
{
    GList *all = g_list_prepend(NULL, (gpointer) "*");
    int rc = out->message(out, "resource-list", scheduler,
                          pcmk_show_inactive_rscs
                          |pcmk_show_rsc_only
                          |pcmk_show_pending,
                          true, all, all, false);

    g_list_free(all);

    if (rc == pcmk_rc_no_output) {
        // @COMPAT It seems wrong to return an error because there no resources
        return CRM_EX_NOSUCH;
    }
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_list_standards(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                      pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                      xmlNode *cib_xml_orig)
{
    int rc = pcmk__list_standards(out);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_locate(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
              pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
              xmlNode *cib_xml_orig)
{
    GList *nodes = cli_resource_search(rsc, options.rsc_id);
    int rc = out->message(out, "resource-search-list", nodes, options.rsc_id);

    g_list_free_full(nodes, free);
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_metadata(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                xmlNode *cib_xml_orig)
{
    int rc = pcmk_rc_ok;
    char *standard = NULL;
    char *provider = NULL;
    char *type = NULL;
    lrmd_t *lrmd_conn = NULL;

    rc = lrmd__new(&lrmd_conn, NULL, NULL, 0);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    _("Could not create executor connection"));
        lrmd_api_delete(lrmd_conn);
        return pcmk_rc2exitc(rc);
    }

    rc = crm_parse_agent_spec(options.agent_spec, &standard, &provider, &type);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        char *metadata = NULL;

        rc = lrmd_conn->cmds->get_metadata(lrmd_conn, standard,
                                           provider, type,
                                           &metadata, 0);
        rc = pcmk_legacy2rc(rc);

        if (metadata != NULL) {
            out->output_xml(out, PCMK_XE_METADATA, metadata);
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
                        options.agent_spec, pcmk_rc_str(rc));
        }
    } else {
        rc = ENXIO;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    _("'%s' is not a valid agent specification"),
                    options.agent_spec);
    }

    free(standard);
    free(provider);
    free(type);
    lrmd_api_delete(lrmd_conn);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_move(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
            pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
            xmlNode *cib_xml_orig)
{
    int rc = pcmk_rc_ok;

    if (node == NULL) {
        rc = ban_or_move(out, rsc, cib_conn, options.move_lifetime);
    } else {
        rc = cli_resource_move(rsc, options.rsc_id, node, options.move_lifetime,
                               cib_conn, options.promoted_role_only,
                               options.force);
    }

    if (rc == EINVAL) {
        return CRM_EX_USAGE;
    }
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_query_xml(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                 pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                 xmlNode *cib_xml_orig)
{
    int rc = cli_resource_print(rsc, true);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_query_xml_raw(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                     pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                     xmlNode *cib_xml_orig)
{
    int rc = cli_resource_print(rsc, false);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_refresh(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
               pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
               xmlNode *cib_xml_orig)
{
    if (rsc == NULL) {
        return refresh(out, node, controld_api);
    }
    refresh_resource(out, rsc, node, controld_api);

    /* @FIXME Both of the calls above are supposed to set exit_code via
     * start_mainloop(). But there appear to be cases in which we can return
     * from refresh() or refresh_resource() without starting the mainloop or
     * returning an error code. It looks as if we exit with CRM_EX_OK in those
     * cases.
     */
    return exit_code;
}

static crm_exit_t
handle_restart(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
               pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
               xmlNode *cib_xml_orig)
{
    /* We don't pass scheduler because rsc needs to stay valid for the entire
     * lifetime of cli_resource_restart(), but it will reset and update the
     * scheduler data multiple times, so it needs to use its own copy.
     */
    int rc = cli_resource_restart(out, rsc, node, options.move_lifetime,
                                  options.timeout_ms, cib_conn,
                                  options.promoted_role_only, options.force);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_set_param(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
                 pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
                 xmlNode *cib_xml_orig)
{
    int rc = pcmk_rc_ok;

    if (pcmk__str_empty(options.prop_value)) {
        crm_exit_t ec = CRM_EX_USAGE;

        g_set_error(&error, PCMK__EXITC_ERROR, ec,
                    _("You need to supply a value with the -v option"));
        return ec;
    }

    rc = cli_resource_update_attribute(rsc, options.rsc_id, options.prop_set,
                                       options.attr_set_type, options.prop_id,
                                       options.prop_name, options.prop_value,
                                       options.recursive, cib_conn,
                                       cib_xml_orig, options.force);
    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_wait(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
            pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
            xmlNode *cib_xml_orig)
{
    int rc = wait_till_stable(out, options.timeout_ms, cib_conn);

    return pcmk_rc2exitc(rc);
}

static crm_exit_t
handle_why(pcmk_resource_t *rsc, pcmk_node_t *node, cib_t *cib_conn,
           pcmk_scheduler_t *scheduler, pcmk_ipc_api_t *controld_api,
           xmlNode *cib_xml_orig)
{
    int rc = out->message(out, "resource-reasons-list",
                          scheduler->priv->resources, rsc, node);

    return pcmk_rc2exitc(rc);
}

static const crm_resource_cmd_info_t crm_resource_command_info[] = {
    [cmd_ban]               = {
        handle_ban,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_rejects_clone_instance
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_cleanup]           = {
        handle_cleanup,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_controller
        |crm_rsc_requires_scheduler,
    },
    [cmd_clear]             = {
        handle_clear,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_rejects_clone_instance
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource          // Unless options.clear_expired
        |crm_rsc_requires_scheduler,
    },
    [cmd_colocations]       = {
        handle_colocations,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_cts]               = {
        handle_cts,
        crm_rsc_requires_cib
        |crm_rsc_requires_scheduler,
    },
    [cmd_delete]            = {
        handle_delete,
        crm_rsc_rejects_clone_instance
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource,
    },
    [cmd_delete_param]      = {
        handle_delete_param,
        crm_rsc_find_match_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_digests]           = {
        handle_digests,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_node
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_execute_agent]     = {
        handle_execute_agent,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_fail]              = {
        handle_fail,
        crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_controller
        |crm_rsc_requires_node
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_get_param]         = {
        handle_get_param,
        crm_rsc_find_match_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_list_active_ops]   = {
        handle_list_active_ops,
        crm_rsc_requires_cib
        |crm_rsc_requires_scheduler,
    },
    [cmd_list_agents]       = {
        handle_list_agents,
        0,
    },
    [cmd_list_all_ops]      = {
        handle_list_all_ops,
        crm_rsc_requires_cib
        |crm_rsc_requires_scheduler,
    },
    [cmd_list_alternatives] = {
        handle_list_alternatives,
        0,
    },
    [cmd_list_instances]    = {
        handle_list_instances,
        crm_rsc_requires_cib
        |crm_rsc_requires_scheduler,
    },
    [cmd_list_options]      = {
        handle_list_options,
        0,
    },
    [cmd_list_providers]    = {
        handle_list_providers,
        0,
    },
    [cmd_list_resources]    = {
        handle_list_resources,
        crm_rsc_requires_cib
        |crm_rsc_requires_scheduler,
    },
    [cmd_list_standards]    = {
        handle_list_standards,
        0,
    },
    [cmd_locate]            = {
        handle_locate,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_metadata]          = {
        handle_metadata,
        0,
    },
    [cmd_move]              = {
        handle_move,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_rejects_clone_instance
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_query_xml]         = {
        handle_query_xml,
        crm_rsc_find_match_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_query_xml_raw]     = {
        handle_query_xml_raw,
        crm_rsc_find_match_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_refresh]           = {
        handle_refresh,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_controller
        |crm_rsc_requires_scheduler,
    },
    [cmd_restart]           = {
        handle_restart,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_rejects_clone_instance
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_set_param]         = {
        handle_set_param,
        crm_rsc_find_match_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_resource
        |crm_rsc_requires_scheduler,
    },
    [cmd_wait]              = {
        handle_wait,
        crm_rsc_requires_cib,
    },
    [cmd_why]               = {
        handle_why,
        crm_rsc_find_match_anon_basename
        |crm_rsc_find_match_history
        |crm_rsc_requires_cib
        |crm_rsc_requires_scheduler,
    },
};

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
                              "\t# crm_resource --resource myResource --set-parameter "
                              PCMK_META_TARGET_ROLE "--meta --parameter-value Stopped\n\n"
                              "Tell the cluster not to manage 'myResource' (the cluster will not "
                              "attempt to start or stop the\n"
                              "resource under any circumstances; useful when performing maintenance "
                              "tasks on a resource):\n\n"
                              "\t# crm_resource --resource myResource --set-parameter "
                              PCMK_META_IS_MANAGED "--meta --parameter-value false\n\n"
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
    const crm_resource_cmd_info_t *command_info = NULL;
    pcmk_resource_t *rsc = NULL;
    pcmk_node_t *node = NULL;
    cib_t *cib_conn = NULL;
    pcmk_scheduler_t *scheduler = NULL;
    pcmk_ipc_api_t *controld_api = NULL;
    xmlNode *cib_xml_orig = NULL;
    uint32_t find_flags = 0;
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

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, _("Error creating output format %s: %s"),
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

    // --expired without --clear/-U doesn't make sense
    if (options.clear_expired && (options.rsc_cmd != cmd_clear)) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, _("--expired requires --clear or -U"));
        goto done;
    }

    if (options.remainder != NULL) {
        // Commands that use positional arguments will create override_params
        if (options.override_params == NULL) {
            GString *msg = g_string_sized_new(128);
            guint len = g_strv_length(options.remainder);

            g_string_append(msg, "non-option ARGV-elements:");

            for (int i = 0; i < len; i++) {
                g_string_append_printf(msg, "\n[%d of %u] %s",
                                       i + 1, len, options.remainder[i]);
            }
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "%s", msg->str);
            g_string_free(msg, TRUE);
            goto done;
        }

        for (const char *const *arg = (const char *const *) options.remainder;
             *arg != NULL; arg++) {

            gchar *name = NULL;
            gchar *value = NULL;
            int rc = pcmk__scan_nvpair(*arg, &name, &value);

            if (rc != pcmk_rc_ok) {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            _("Error parsing '%s' as a name=value pair"), *arg);
                goto done;
            }

            g_hash_table_insert(options.override_params, name, value);
        }
    }

    if (pcmk__str_eq(args->output_ty, "xml", pcmk__str_none)) {
        switch (options.rsc_cmd) {
            /* These are the only commands that have historically used the <list>
             * elements in their XML schema.  For all others, use the simple list
             * argument.
             */
            case cmd_get_param:
            case cmd_list_instances:
            case cmd_list_standards:
                pcmk__output_enable_list_element(out);
                break;

            default:
                break;
        }

    } else if (pcmk__str_eq(args->output_ty, "text", pcmk__str_null_matches)) {
        switch (options.rsc_cmd) {
            case cmd_colocations:
            case cmd_list_resources:
                pcmk__output_text_set_fancy(out, true);
                break;
            default:
                break;
        }
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    // Ensure command is in valid range and has a handler function
    if ((options.rsc_cmd >= 0) && (options.rsc_cmd <= cmd_max)) {
        command_info = &crm_resource_command_info[options.rsc_cmd];
    }
    if ((command_info == NULL) || (command_info->fn == NULL)) {
        exit_code = CRM_EX_SOFTWARE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    _("Bug: Unimplemented command: %d"), (int) options.rsc_cmd);
        goto done;
    }

    /* If a command-line resource agent specification was given, validate it.
     * Otherwise, ensure --option was not given.
     */
    if (has_cmdline_config()) {
        validate_cmdline_config();
        if (error != NULL) {
            exit_code = CRM_EX_USAGE;
            goto done;
        }

    } else if (options.cmdline_params != NULL) {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    _("--option must be used with --validate and without -r"));
        g_hash_table_destroy(options.cmdline_params);
        goto done;
    }

    // Ensure --resource is set if it's required
    if (pcmk__is_set(command_info->flags, crm_rsc_requires_resource)
        && !has_cmdline_config()
        && !options.clear_expired
        && (options.rsc_id == NULL)) {

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    _("Must supply a resource ID with -r/--resource"));
        goto done;
    }

    // Ensure --node is set if it's required
    if (pcmk__is_set(command_info->flags, crm_rsc_requires_node)
        && (options.host_uname == NULL)) {

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    _("Must supply a node name with -N/--node"));
        goto done;
    }

    // Establish a connection to the CIB if needed
    if (pcmk__is_set(command_info->flags, crm_rsc_requires_cib)
        && !has_cmdline_config()) {

        rc = cib__create_signon(&cib_conn);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Could not connect to the CIB: %s"), pcmk_rc_str(rc));
            goto done;
        }
    }

    // Populate scheduler data from CIB query if needed
    if (pcmk__is_set(command_info->flags, crm_rsc_requires_scheduler)
        && !has_cmdline_config()) {

        rc = initialize_scheduler_data(&scheduler, cib_conn, out,
                                       &cib_xml_orig);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            goto done;
        }
    }

    // Establish a connection to the controller if needed
    if (pcmk__is_set(command_info->flags, crm_rsc_requires_controller)
        && (getenv("CIB_file") == NULL)) {

        rc = pcmk_new_ipc_api(&controld_api, pcmk_ipc_controld);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Error connecting to the controller: %s"), pcmk_rc_str(rc));
            goto done;
        }

        pcmk_register_ipc_callback(controld_api, controller_event_callback,
                                   &exit_code);

        rc = pcmk__connect_ipc(controld_api, pcmk_ipc_dispatch_main, 5);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Error connecting to %s: %s"),
                        pcmk_ipc_name(controld_api, true), pcmk_rc_str(rc));
            goto done;
        }
    }

    /* Find node if --node was given.
     *
     * @TODO Consider stricter validation. Currently we ignore the --node
     * argument for commands that don't require scheduler data, since we have no
     * way to find the node in that case. This is really a usage error, but we
     * don't validate strictly. We allow multiple commands (and in some cases
     * their options like --node) to be specified, and we use the last one in
     * case of conflicts.
     *
     * This isn't universally true. --expired results in a usage error unless
     * the final command is --clear.
     */
    if (options.host_uname != NULL) {
        node = pcmk_find_node(scheduler, options.host_uname);

        if (node == NULL) {
            exit_code = CRM_EX_NOSUCH;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Node '%s' not found"), options.host_uname);
            goto done;
        }
    }

    /* Find resource if --resource was given and any find flags are set.
     *
     * @TODO Consider stricter validation. See comment above for --node.
     * @TODO Setter macro for tracing?
     */
    if (pcmk__is_set(command_info->flags, crm_rsc_find_match_anon_basename)) {
        find_flags |= pcmk_rsc_match_anon_basename;
    }
    if (pcmk__is_set(command_info->flags, crm_rsc_find_match_basename)) {
        find_flags |= pcmk_rsc_match_basename;
    }
    if (pcmk__is_set(command_info->flags, crm_rsc_find_match_history)) {
        find_flags |= pcmk_rsc_match_history;
    }
    if ((find_flags != 0) && (options.rsc_id != NULL)) {
        pcmk__assert(scheduler != NULL);

        rsc = pe_find_resource_with_flags(scheduler->priv->resources,
                                          options.rsc_id, find_flags);
        if (rsc == NULL) {
            exit_code = CRM_EX_NOSUCH;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Resource '%s' not found"), options.rsc_id);
            goto done;
        }

        if (pcmk__is_set(command_info->flags, crm_rsc_rejects_clone_instance)
            && pcmk__is_clone(rsc->priv->parent)
            && (strchr(options.rsc_id, ':') != NULL)) {

            exit_code = CRM_EX_INVALID_PARAM;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Cannot operate on clone resource instance '%s'"),
                        options.rsc_id);
            goto done;
        }
    }

    exit_code = command_info->fn(rsc, node, cib_conn, scheduler, controld_api,
                                 cib_xml_orig);

done:
    // For CRM_EX_USAGE, error is already set satisfactorily
    if ((exit_code != CRM_EX_OK) && (exit_code != CRM_EX_USAGE)) {
        if (error != NULL) {
            char *msg = pcmk__assert_asprintf("%s\nError performing operation: "
                                              "%s",
                                              error->message,
                                              crm_exit_str(exit_code));
            g_clear_error(&error);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "%s", msg);
            free(msg);
        } else {
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        _("Error performing operation: %s"), crm_exit_str(exit_code));
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
    g_free(options.agent);
    g_free(options.class);
    g_free(options.provider);
    if (options.override_params != NULL) {
        g_hash_table_destroy(options.override_params);
    }
    g_strfreev(options.remainder);

    // Don't destroy options.cmdline_params here. See comment in option_cb().

    g_strfreev(processed_args);
    g_option_context_free(context);

    pcmk__xml_free(cib_xml_orig);
    cib__clean_up_connection(&cib_conn);
    pcmk_free_ipc_api(controld_api);
    pcmk_free_scheduler(scheduler);
    if (mainloop != NULL) {
        g_main_loop_unref(mainloop);
    }

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    return crm_exit(exit_code);
}

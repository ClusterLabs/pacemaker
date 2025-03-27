/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdio.h>
#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/cib/internal.h>

#include <pacemaker-internal.h>

#define SUMMARY "query and edit the Pacemaker configuration"

#define INDENT "                                "

enum cibadmin_section_type {
    cibadmin_section_all = 0,
    cibadmin_section_scope,
    cibadmin_section_xpath,
};

static cib_t *the_cib = NULL;
static crm_exit_t exit_code = CRM_EX_OK;

static struct {
    const char *cib_action;
    int cmd_options;
    enum cibadmin_section_type section_type;
    char *cib_section;
    char *validate_with;
    gint message_timeout_sec;
    enum pcmk__acl_render_how acl_render_mode;
    gchar *cib_user;
    gchar *dest_node;
    gchar *input_file;
    gchar *input_xml;
    gboolean input_stdin;
    bool delete_all;
    gboolean allow_create;
    gboolean force;
    gboolean get_node_path;
    gboolean no_children;
    gboolean score_update;

    /* @COMPAT: For "-!" version option. Not advertised nor marked as
     * deprecated, but accepted.
     */
    gboolean extended_version;

    // @COMPAT Deprecated since 3.0.0
    gboolean local;

    // @COMPAT Deprecated since 3.0.1
    gboolean sync_call;
} options = {
    .cmd_options = cib_sync_call,
};

int do_init(void);
static int do_work(xmlNode *input, xmlNode **output);

static void
print_xml_output(xmlNode * xml)
{
    if (!xml) {
        return;
    } else if (xml->type != XML_ELEMENT_NODE) {
        return;
    }

    if (pcmk_is_set(options.cmd_options, cib_xpath_address)) {
        const char *id = pcmk__xe_get(xml, PCMK_XA_ID);

        if (pcmk__xe_is(xml, PCMK__XE_XPATH_QUERY)) {
            xmlNode *child = NULL;

            for (child = xml->children; child; child = child->next) {
                print_xml_output(child);
            }

        } else if (id) {
            printf("%s\n", id);
        }

    } else {
        GString *buf = g_string_sized_new(1024);

        pcmk__xml_string(xml, pcmk__xml_fmt_pretty, buf, 0);

        fprintf(stdout, "%s", buf->str);
        g_string_free(buf, TRUE);
    }
}

// Upgrade requested but already at latest schema
static void
report_schema_unchanged(void)
{
    const char *err = pcmk_rc_str(pcmk_rc_schema_unchanged);

    crm_info("Upgrade unnecessary: %s\n", err);
    printf("Upgrade unnecessary: %s\n", err);
    exit_code = CRM_EX_OK;
}

/*!
 * \internal
 * \brief Check whether the current CIB action is dangerous
 * \return true if \p options.cib_action is dangerous, or false otherwise
 */
static inline bool
cib_action_is_dangerous(void)
{
    /* @TODO Ideally, --upgrade wouldn't be considered dangerous if the CIB
     * already uses the latest schema.
     */
    return options.delete_all
           || pcmk__str_any_of(options.cib_action,
                               PCMK__CIB_REQUEST_UPGRADE,
                               PCMK__CIB_REQUEST_ERASE,
                               NULL);
}

/*!
 * \internal
 * \brief Determine whether the given CIB scope is valid for \p cibadmin
 *
 * \param[in] scope  Scope to validate
 *
 * \return true if \p scope is valid, or false otherwise
 * \note An invalid scope applies the operation to the entire CIB.
 */
static inline bool
scope_is_valid(const char *scope)
{
    return pcmk__str_any_of(scope,
                            PCMK_XE_CONFIGURATION,
                            PCMK_XE_NODES,
                            PCMK_XE_RESOURCES,
                            PCMK_XE_CONSTRAINTS,
                            PCMK_XE_CRM_CONFIG,
                            PCMK_XE_RSC_DEFAULTS,
                            PCMK_XE_OP_DEFAULTS,
                            PCMK_XE_ACLS,
                            PCMK_XE_FENCING_TOPOLOGY,
                            PCMK_XE_TAGS,
                            PCMK_XE_ALERTS,
                            PCMK_XE_STATUS,
                            NULL);
}

static gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    options.delete_all = false;

    if (pcmk__str_any_of(option_name, "-u", "--upgrade", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_UPGRADE;

    } else if (pcmk__str_any_of(option_name, "-Q", "--query", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_QUERY;

    } else if (pcmk__str_any_of(option_name, "-E", "--erase", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_ERASE;

    } else if (pcmk__str_any_of(option_name, "-B", "--bump", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_BUMP;

    } else if (pcmk__str_any_of(option_name, "-C", "--create", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_CREATE;

    } else if (pcmk__str_any_of(option_name, "-M", "--modify", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_MODIFY;

    } else if (pcmk__str_any_of(option_name, "-P", "--patch", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_APPLY_PATCH;

    } else if (pcmk__str_any_of(option_name, "-R", "--replace", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_REPLACE;

    } else if (pcmk__str_any_of(option_name, "-D", "--delete", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_DELETE;

    } else if (pcmk__str_any_of(option_name, "-d", "--delete-all", NULL)) {
        options.cib_action = PCMK__CIB_REQUEST_DELETE;
        options.delete_all = true;

    } else if (pcmk__str_any_of(option_name, "-a", "--empty", NULL)) {
        options.cib_action = "empty";
        pcmk__str_update(&options.validate_with, optarg);

    } else if (pcmk__str_any_of(option_name, "-5", "--md5-sum", NULL)) {
        options.cib_action = "md5-sum";

    } else if (pcmk__str_any_of(option_name, "-6", "--md5-sum-versioned",
                                NULL)) {
        options.cib_action = "md5-sum-versioned";

    } else {
        // Should be impossible
        return FALSE;
    }

    return TRUE;
}

static gboolean
show_access_cb(const gchar *option_name, const gchar *optarg, gpointer data,
               GError **error)
{
    if (pcmk__str_eq(optarg, "auto", pcmk__str_null_matches)) {
        options.acl_render_mode = pcmk__acl_render_default;

    } else if (g_strcmp0(optarg, "namespace") == 0) {
        options.acl_render_mode = pcmk__acl_render_namespace;

    } else if (g_strcmp0(optarg, "text") == 0) {
        options.acl_render_mode = pcmk__acl_render_text;

    } else if (g_strcmp0(optarg, "color") == 0) {
        options.acl_render_mode = pcmk__acl_render_color;

    } else {
        g_set_error(error, PCMK__EXITC_ERROR, CRM_EX_USAGE,
                    "Invalid value '%s' for option '%s'",
                    optarg, option_name);
        return FALSE;
    }
    return TRUE;
}

static gboolean
section_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    if (pcmk__str_any_of(option_name, "-o", "--scope", NULL)) {
        options.section_type = cibadmin_section_scope;

    } else if (pcmk__str_any_of(option_name, "-A", "--xpath", NULL)) {
        options.section_type = cibadmin_section_xpath;

    } else {
        // Should be impossible
        return FALSE;
    }

    pcmk__str_update(&options.cib_section, optarg);
    return TRUE;
}

static GOptionEntry command_entries[] = {
    { "upgrade", 'u', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Upgrade the configuration to the latest syntax", NULL },

    { "query", 'Q', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Query the contents of the CIB", NULL },

    { "erase", 'E', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Erase the contents of the whole CIB", NULL },

    { "bump", 'B', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Increase the CIB's epoch value by 1", NULL },

    { "create", 'C', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Create an object in the CIB (will fail if object already exists)",
      NULL },

    { "modify", 'M', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Find object somewhere in CIB's XML tree and update it (fails if object "
      "does not exist unless -c is also specified)",
      NULL },

    { "patch", 'P', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Supply an update in the form of an XML diff (see crm_diff(8))", NULL },

    { "replace", 'R', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Recursively replace an object in the CIB", NULL },

    { "delete", 'D', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Delete first object matching supplied criteria (for example, "
      "<" PCMK_XE_OP " " PCMK_XA_ID "=\"rsc1_op1\" "
          PCMK_XA_NAME "=\"monitor\"/>).\n"
      INDENT "The XML element name and all attributes must match in order for "
      "the element to be deleted.",
      NULL },

    { "delete-all", 'd', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      command_cb,
      "When used with --xpath, remove all matching objects in the "
      "configuration instead of just the first one",
      NULL },

    { "empty", 'a', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
      command_cb,
      "Output an empty CIB. Accepts an optional schema name argument to use as "
      "the " PCMK_XA_VALIDATE_WITH " value.\n"
      INDENT "If no schema is given, the latest will be used.",
      "[schema]" },

    { "md5-sum", '5', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Calculate the on-disk CIB digest", NULL },

    { "md5-sum-versioned", '6', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      command_cb, "Calculate an on-the-wire versioned CIB digest", NULL },

    { NULL }
};

static GOptionEntry data_entries[] = {
    /* @COMPAT: These arguments should be last-wins. We can have an enum option
     * that stores the input type, along with a single string option that stores
     * the XML string for --xml-text, filename for --xml-file, or NULL for
     * --xml-pipe.
     */
    { "xml-text", 'X', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING,
      &options.input_xml, "Retrieve XML from the supplied string", "value" },

    { "xml-file", 'x', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME,
      &options.input_file, "Retrieve XML from the named file", "value" },

    { "xml-pipe", 'p', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.input_stdin, "Retrieve XML from stdin", NULL },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "force", 'f', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.force,
      "Force the action to be performed", NULL },

    { "timeout", 't', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT,
      &options.message_timeout_sec,
      "Time (in seconds) to wait before declaring the operation failed",
      "value" },

    { "user", 'U', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.cib_user,
      "Run the command with permissions of the named user (valid only for the "
      "root and " CRM_DAEMON_USER " accounts)", "value" },

    { "scope", 'o', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, section_cb,
      "Limit scope of operation to specific section of CIB\n"
      INDENT "Valid values: " PCMK_XE_CONFIGURATION ", " PCMK_XE_NODES
      ", " PCMK_XE_RESOURCES ", " PCMK_XE_CONSTRAINTS
      ", " PCMK_XE_CRM_CONFIG ", " PCMK_XE_RSC_DEFAULTS ",\n"
      INDENT "              " PCMK_XE_OP_DEFAULTS ", " PCMK_XE_ACLS
      ", " PCMK_XE_FENCING_TOPOLOGY ", " PCMK_XE_TAGS ", " PCMK_XE_ALERTS
      ", " PCMK_XE_STATUS "\n"
      INDENT "If both --scope/-o and --xpath/-a are specified, the last one to "
      "appear takes effect",
      "value" },

    { "xpath", 'A', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, section_cb,
      "A valid XPath to use instead of --scope/-o\n"
      INDENT "If both --scope/-o and --xpath/-a are specified, the last one to "
      "appear takes effect",
      "value" },

    { "node-path", 'e', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.get_node_path,
      "When performing XPath queries, return paths of any matches found\n"
      INDENT "(for example, "
      "\"/" PCMK_XE_CIB "/" PCMK_XE_CONFIGURATION
      "/" PCMK_XE_RESOURCES "/" PCMK_XE_CLONE
      "[@" PCMK_XA_ID "='dummy-clone']"
      "/" PCMK_XE_PRIMITIVE "[@" PCMK_XA_ID "='dummy']\")",
      NULL },

    { "show-access", 'S', G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK,
      show_access_cb,
      "Whether to use syntax highlighting for ACLs (with -Q/--query and "
      "-U/--user)\n"
      INDENT "Allowed values: 'color' (default for terminal), 'text' (plain text, "
      "default for non-terminal),\n"
      INDENT "                'namespace', or 'auto' (use default value)\n"
      INDENT "Default value: 'auto'",
      "[value]" },

    { "score", 0, G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.score_update,
      "Treat new attribute values as atomic score updates where possible "
      "(with --modify/-M).\n"

      INDENT "This currently happens by default and cannot be disabled, but\n"
      INDENT "this default behavior is deprecated and will be removed in a\n"
      INDENT "future release. Set this flag if this behavior is desired.\n"

      INDENT "This option takes effect when updating XML attributes. For an\n"
      INDENT "attribute named \"name\", if the new value is \"name++\" or\n"
      INDENT "\"name+=X\" for some score X, the new value is set as follows:\n"
      INDENT "If attribute \"name\" is not already set to some value in\n"
      INDENT "the element being updated, the new value is set as a literal\n"
      INDENT "string.\n"
      INDENT "If the new value is \"name++\", then the attribute is set to \n"
      INDENT "its existing value (parsed as a score) plus 1.\n"
      INDENT "If the new value is \"name+=X\" for some score X, then the\n"
      INDENT "attribute is set to its existing value plus X, where the\n"
      INDENT "existing value and X are parsed and added as scores.\n"

      INDENT "Scores are integer values capped at INFINITY and -INFINITY.\n"
      INDENT "Refer to Pacemaker Explained for more details on scores,\n"
      INDENT "including how they are parsed and added.",
      NULL },

    { "allow-create", 'c', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.allow_create,
      "(Advanced) Allow target of --modify/-M to be created if it does not "
      "exist",
      NULL },

    { "no-children", 'n', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.no_children,
      "(Advanced) When querying an object, do not include its children in the "
      "result",
      NULL },

    { "node", 'N', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.dest_node,
      "(Advanced) Send command to the specified host", "value" },

    // @COMPAT Deprecated since 3.0.0
    { "local", 'l', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.local,
      "(deprecated)", NULL },

    // @COMPAT Deprecated since 3.0.1
    { "sync-call", 's', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE,
      &options.sync_call, "(deprecated)", NULL },

    { NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args)
{
    const char *desc = NULL;
    GOptionContext *context = NULL;

    GOptionEntry extra_prog_entries[] = {
        // @COMPAT: Deprecated
        { "extended-version", '!', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE,
          &options.extended_version, "deprecated", NULL },

        { NULL }
    };

    desc = "Examples:\n\n"
           "Query the configuration:\n\n"
           "\t# cibadmin --query\n\n"
           "Query just the cluster options configuration:\n\n"
           "\t# cibadmin --query --scope " PCMK_XE_CRM_CONFIG "\n\n"
           "Query all '" PCMK_META_TARGET_ROLE "' settings:\n\n"
           "\t# cibadmin --query --xpath "
               "\"//" PCMK_XE_NVPAIR
               "[@" PCMK_XA_NAME "='" PCMK_META_TARGET_ROLE"']\"\n\n"
           "Remove all '" PCMK_META_IS_MANAGED "' settings:\n\n"
           "\t# cibadmin --delete-all --xpath "
               "\"//" PCMK_XE_NVPAIR
               "[@" PCMK_XA_NAME "='" PCMK_META_IS_MANAGED "']\"\n\n"
           "Remove the resource named 'old':\n\n"
           "\t# cibadmin --delete --xml-text "
               "'<" PCMK_XE_PRIMITIVE " " PCMK_XA_ID "=\"old\"/>'\n\n"
           "Remove all resources from the configuration:\n\n"
           "\t# cibadmin --replace --scope " PCMK_XE_RESOURCES
               " --xml-text '<" PCMK_XE_RESOURCES "/>'\n\n"
           "Replace complete configuration with contents of "
               "$HOME/pacemaker.xml:\n\n"
           "\t# cibadmin --replace --xml-file $HOME/pacemaker.xml\n\n"
           "Replace " PCMK_XE_CONSTRAINTS " section of configuration with "
               "contents of $HOME/constraints.xml:\n\n"
           "\t# cibadmin --replace --scope " PCMK_XE_CONSTRAINTS
               " --xml-file $HOME/constraints.xml\n\n"
           "Increase configuration version to prevent old configurations from "
               "being loaded accidentally:\n\n"
           "\t# cibadmin --modify --score --xml-text "
               "'<" PCMK_XE_CIB " " PCMK_XA_ADMIN_EPOCH
                   "=\"" PCMK_XA_ADMIN_EPOCH "++\"/>'\n\n"
           "Edit the configuration with your favorite $EDITOR:\n\n"
           "\t# cibadmin --query > $HOME/local.xml\n\n"
           "\t# $EDITOR $HOME/local.xml\n\n"
           "\t# cibadmin --replace --xml-file $HOME/local.xml\n\n"
           "Assuming terminal, render configuration in color (green for "
               "writable, blue for readable, red for\n"
               "denied) to visualize permissions for user tony:\n\n"
           "\t# cibadmin --show-access=color --query --user tony | less -r\n\n"
           "SEE ALSO:\n"
           " crm(8), pcs(8), crm_shadow(8), crm_diff(8)\n";

    context = pcmk__build_arg_context(args, NULL, NULL, "<command>");
    g_option_context_set_description(context, desc);

    pcmk__add_main_args(context, extra_prog_entries);

    pcmk__add_arg_group(context, "commands", "Commands:", "Show command help",
                        command_entries);
    pcmk__add_arg_group(context, "data", "Data:", "Show data help",
                        data_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    const char *source = NULL;
    xmlNode *output = NULL;
    xmlNode *input = NULL;
    gchar *acl_cred = NULL;

    GError *error = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "ANSUXhotx");
    GOptionContext *context = build_arg_context(args);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (g_strv_length(processed_args) > 1) {
        gchar *help = g_option_context_get_help(context, TRUE, NULL);
        GString *extra = g_string_sized_new(128);

        for (int lpc = 1; processed_args[lpc] != NULL; lpc++) {
            if (extra->len > 0) {
                g_string_append_c(extra, ' ');
            }
            g_string_append(extra, processed_args[lpc]);
        }

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "non-option ARGV-elements: %s\n\n%s", extra->str, help);
        g_free(help);
        g_string_free(extra, TRUE);
        goto done;
    }

    if (args->version || options.extended_version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);

        /* FIXME: When cibadmin is converted to use formatted output, this can
         * be replaced by out->version with the appropriate boolean flag.
         *
         * options.extended_version is deprecated and will be removed in a
         * future release.
         */
        pcmk__cli_help(options.extended_version? '!' : 'v');
    }

    /* At LOG_ERR, stderr for CIB calls is rather verbose. Several lines like
     *
     * (func@file:line)      error: CIB <op> failures   <XML>
     *
     * In cibadmin we explicitly output the XML portion without the prefixes. So
     * we default to LOG_CRIT.
     */
    pcmk__cli_init_logging("cibadmin", 0);
    set_crm_log_level(LOG_CRIT);

    if (args->verbosity > 0) {
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_verbose);

        for (int i = 0; i < args->verbosity; i++) {
            crm_bump_log_level(argc, argv);
        }
    }

    if (options.cib_action == NULL) {
        // @COMPAT: Create a default command if other tools have one
        gchar *help = g_option_context_get_help(context, TRUE, NULL);

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Must specify a command option\n\n%s", help);
        g_free(help);
        goto done;
    }

    if (strcmp(options.cib_action, "empty") == 0) {
        // Output an empty CIB
        GString *buf = g_string_sized_new(1024);

        output = createEmptyCib(1);
        pcmk__xe_set(output, PCMK_XA_VALIDATE_WITH, options.validate_with);

        pcmk__xml_string(output, pcmk__xml_fmt_pretty, buf, 0);
        fprintf(stdout, "%s", buf->str);
        g_string_free(buf, TRUE);
        goto done;
    }

    if (cib_action_is_dangerous() && !options.force) {
        exit_code = CRM_EX_UNSAFE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "The supplied command is considered dangerous. To prevent "
                    "accidental destruction of the cluster, the --force flag "
                    "is required in order to proceed.");
        goto done;
    }

    if (options.message_timeout_sec < 1) {
        // Set default timeout
        options.message_timeout_sec = 30;
    }

    if (options.section_type == cibadmin_section_xpath) {
        // Enable getting section by XPath
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_xpath);

    } else if (options.section_type == cibadmin_section_scope) {
        if (!scope_is_valid(options.cib_section)) {
            // @COMPAT: Consider requiring --force to proceed
            fprintf(stderr,
                    "Invalid value '%s' for '--scope'. Operation will apply "
                    "to the entire CIB.\n", options.cib_section);
        }
    }

    if (options.allow_create) {
        // Allow target of --modify/-M to be created if it does not exist
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_can_create);
    }

    if (options.delete_all) {
        // With cibadmin_section_xpath, remove all matching objects
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_multiple);
    }

    if (options.get_node_path) {
        /* Enable getting node path of XPath query matches.
         * Meaningful only if options.section_type == cibadmin_section_xpath.
         */
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_xpath_address);
    }

    if (options.no_children) {
        // When querying an object, don't include its children in the result
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_no_children);
    }

    if (options.input_file != NULL) {
        input = pcmk__xml_read(options.input_file);
        source = options.input_file;

    } else if (options.input_xml != NULL) {
        input = pcmk__xml_parse(options.input_xml);
        source = "input string";

    } else if (options.input_stdin) {
        input = pcmk__xml_read(NULL);
        source = "STDIN";

    } else if (options.acl_render_mode != pcmk__acl_render_none) {
        char *username = pcmk__uid2username(geteuid());
        bool required = pcmk_acl_required(username);

        free(username);

        if (required) {
            if (options.force) {
                fprintf(stderr, "The supplied command can provide skewed"
                                 " result since it is run under user that also"
                                 " gets guarded per ACLs on their own right."
                                 " Continuing since --force flag was"
                                 " provided.\n");

            } else {
                exit_code = CRM_EX_UNSAFE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "The supplied command can provide skewed result "
                            "since it is run under user that also gets guarded "
                            "per ACLs in their own right. To accept the risk "
                            "of such a possible distortion (without even "
                            "knowing it at this time), use the --force flag.");
                goto done;
            }
        }

        if (options.cib_user == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "The supplied command requires -U user specified.");
            goto done;
        }

        /* We already stopped/warned ACL-controlled users about consequences.
         *
         * Note: acl_cred takes ownership of options.cib_user here.
         * options.cib_user is set to NULL so that the CIB is obtained as the
         * user running the cibadmin command. The CIB must be obtained as a user
         * with full permissions in order to show the CIB correctly annotated
         * for the options.cib_user's permissions.
         */
        acl_cred = options.cib_user;
        options.cib_user = NULL;
    }

    if (input != NULL) {
        crm_log_xml_debug(input, "[admin input]");

    } else if (source != NULL) {
        exit_code = CRM_EX_CONFIG;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Couldn't parse input from %s.", source);
        goto done;
    }

    if (pcmk__str_eq(options.cib_action, "md5-sum", pcmk__str_casei)) {
        char *digest = NULL;

        if (input == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Please supply XML to process with -X, -x, or -p");
            goto done;
        }

        digest = pcmk__digest_on_disk_cib(input);
        fprintf(stderr, "Digest: ");
        fprintf(stdout, "%s\n", pcmk__s(digest, "<null>"));
        free(digest);
        goto done;

    } else if (strcmp(options.cib_action, "md5-sum-versioned") == 0) {
        char *digest = NULL;

        if (input == NULL) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Please supply XML to process with -X, -x, or -p");
            goto done;
        }

        digest = pcmk__digest_xml(input, true);
        fprintf(stdout, "%s\n", pcmk__s(digest, "<null>"));
        free(digest);
        goto done;

    } else if (pcmk__str_eq(options.cib_action, PCMK__CIB_REQUEST_MODIFY,
                            pcmk__str_none)) {
        /* @COMPAT When we drop default support for expansion in cibadmin, guard
         * with `if (options.score_update)`
         */
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_score_update);
    }

    rc = do_init();
    if (rc != pcmk_ok) {
        rc = pcmk_legacy2rc(rc);
        exit_code = pcmk_rc2exitc(rc);

        crm_err("Init failed, could not perform requested operations: %s",
                pcmk_rc_str(rc));
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Init failed, could not perform requested operations: %s",
                    pcmk_rc_str(rc));
        goto done;
    }

    rc = do_work(input, &output);
    rc = pcmk_legacy2rc(rc);

    if ((rc == pcmk_rc_schema_unchanged)
        && (strcmp(options.cib_action, PCMK__CIB_REQUEST_UPGRADE) == 0)) {

        report_schema_unchanged();

    } else if (rc != pcmk_rc_ok) {
        crm_err("Call failed: %s", pcmk_rc_str(rc));
        fprintf(stderr, "Call failed: %s\n", pcmk_rc_str(rc));
        exit_code = pcmk_rc2exitc(rc);

        if (rc == pcmk_rc_schema_validation) {
            if (strcmp(options.cib_action, PCMK__CIB_REQUEST_UPGRADE) == 0) {
                xmlNode *obj = NULL;

                if (the_cib->cmds->query(the_cib, NULL, &obj,
                                         options.cmd_options) == pcmk_ok) {
                    pcmk__update_schema(&obj, NULL, true, false);
                }
                pcmk__xml_free(obj);

            } else if (output != NULL) {
                // Show validation errors to stderr
                pcmk__validate_xml(output, NULL, NULL, NULL);
            }
        }
    }

    if ((output != NULL)
        && (options.acl_render_mode != pcmk__acl_render_none)) {

        xmlDoc *acl_evaled_doc;
        rc = pcmk__acl_annotate_permissions(acl_cred, output->doc, &acl_evaled_doc);
        if (rc == pcmk_rc_ok) {
            xmlChar *rendered = NULL;

            rc = pcmk__acl_evaled_render(acl_evaled_doc,
                                         options.acl_render_mode, &rendered);
            if (rc != pcmk_rc_ok) {
                exit_code = CRM_EX_CONFIG;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Could not render evaluated access: %s",
                            pcmk_rc_str(rc));
                goto done;
            }
            printf("%s\n", (char *) rendered);
            free(rendered);

        } else {
            exit_code = CRM_EX_CONFIG;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not evaluate access per request (%s, error: %s)",
                        acl_cred, pcmk_rc_str(rc));
            goto done;
        }

    } else if (output != NULL) {
        print_xml_output(output);
    }

    crm_trace("%s exiting normally", crm_system_name);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_free(options.cib_user);
    g_free(options.dest_node);
    g_free(options.input_file);
    g_free(options.input_xml);
    free(options.cib_section);
    free(options.validate_with);

    g_free(acl_cred);
    pcmk__xml_free(input);
    pcmk__xml_free(output);

    rc = cib__clean_up_connection(&the_cib);
    if (exit_code == CRM_EX_OK) {
        exit_code = pcmk_rc2exitc(rc);
    }

    pcmk__output_and_clear_error(&error, NULL);
    crm_exit(exit_code);
}

static int
do_work(xmlNode *input, xmlNode **output)
{
    /* construct the request */
    the_cib->call_timeout = options.message_timeout_sec;
    if ((strcmp(options.cib_action, PCMK__CIB_REQUEST_REPLACE) == 0)
        && pcmk__xe_is(input, PCMK_XE_CIB)) {
        xmlNode *status = pcmk_find_cib_element(input, PCMK_XE_STATUS);

        if (status == NULL) {
            pcmk__xe_create(input, PCMK_XE_STATUS);
        }
    }

    crm_trace("Passing \"%s\" to variant_op...", options.cib_action);
    return cib_internal_op(the_cib, options.cib_action, options.dest_node,
                           options.cib_section, input, output,
                           options.cmd_options, options.cib_user);
}

int
do_init(void)
{
    int rc = pcmk_ok;

    the_cib = cib_new();
    rc = cib__signon_attempts(the_cib, cib_command, 5);
    if (rc != pcmk_ok) {
        crm_err("Could not connect to the CIB: %s", pcmk_strerror(rc));
        fprintf(stderr, "Could not connect to the CIB: %s\n",
                pcmk_strerror(rc));
    }

    return rc;
}

/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdint.h>                         // uint32_t, etc.
#include <stdio.h>                          // NULL, printf(), etc.

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>
#include <crm/cib/internal.h>

#include <pacemaker-internal.h>

#define SUMMARY "query and edit the Pacemaker configuration"

#define DEFAULT_TIMEOUT 30
#define INDENT "                                "

/*!
 * \internal
 * \brief How to interpret \c options.cib_section
 */
enum cibadmin_section_type {
    //! No section specified: the command applies to the entire CIB
    cibadmin_section_all = 0,

    //! Section is the name of the CIB element to which the command applies
    cibadmin_section_scope,

    //! Section is an XPath expression, and the command applies to matches
    cibadmin_section_xpath,
};

/*!
 * \internal
 * \brief Commands for \c cibadmin
 */
enum cibadmin_cmd {
    cibadmin_cmd_bump,
    cibadmin_cmd_create,
    cibadmin_cmd_delete,
    cibadmin_cmd_delete_all,
    cibadmin_cmd_empty,
    cibadmin_cmd_erase,
    cibadmin_cmd_md5_sum,
    cibadmin_cmd_md5_sum_versioned,
    cibadmin_cmd_modify,
    cibadmin_cmd_patch,
    cibadmin_cmd_query,
    cibadmin_cmd_replace,
    cibadmin_cmd_upgrade,

    // Update this when adding new commands
    cibadmin_cmd_max = cibadmin_cmd_upgrade,
};

/*!
 * \internal
 * \brief Flags to define attributes of a given \c cibadmin command
 */
enum cibadmin_command_flags {
    //! This flag has no effect
    cibadmin_cf_none           = UINT32_C(0),

    /*!
     * \brief Command requires input
     *
     * There is no optional input. Either a command requires input, or it
     * ignores any input that was provided.
     */
    cibadmin_cf_requires_input = (UINT32_C(1) << 0),

    /*!
     * \brief Command is especially unsafe
     *
     * Any command that modifies the CIB is unsafe. This flag is for commands
     * that are likely to be destructive to larger portions of the CIB and to be
     * used by mistake.
     */
    cibadmin_cf_unsafe         = (UINT32_C(1) << 1),

    /*!
     * \brief Command can use an XPath expression instead of input XML
     *
     * If \c options.section_type is \c cibadmin_section_xpath, then the command
     * uses \c options.cib_section rather than reading input XML.
     */
    cibadmin_cf_xpath_input    = (UINT32_C(1) << 2),
};

/*!
 * \internal
 * \brief Information about a \c cibadmin command type
 */
typedef struct {
    const char *cib_request; //!< Name of request to send to the CIB API
    uint32_t flags;          //!< Group of <tt>enum cibadmin_command_flags</tt>
} cibadmin_cmd_info_t;

static struct {
    enum cibadmin_cmd cmd;
    enum cibadmin_section_type section_type;
    char *cib_section;
    char *validate_with;
    gint timeout_sec;
    enum pcmk__acl_render_how acl_render_mode;
    gchar *cib_user;
    gchar *input_file;
    gchar *input_string;
    gboolean input_stdin;
    gboolean allow_create;
    gboolean force;
    gboolean get_node_path;
    gboolean no_children;
    gboolean score_update;

    // @COMPAT Deprecated since 3.0.2
    gchar *dest_node;

    // @COMPAT Deprecated since 3.0.0
    gboolean local;

    // @COMPAT Deprecated since 3.0.1
    gboolean sync_call;
} options = {
    .cmd = cibadmin_cmd_query,
    .timeout_sec = DEFAULT_TIMEOUT,
};

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

static int
print_xml_id(xmlNode *xml, void *user_data)
{
    const char *id = pcmk__xe_id(xml);

    if (id != NULL) {
        printf("%s\n", id);
    }
    return pcmk_rc_ok;
}

static crm_exit_t
cibadmin_pre_default(int *call_options, xmlNode *input, GError **error)
{
    if (options.cmd == cibadmin_cmd_empty) {
        /* Output an empty CIB.
         * Handles entirety of empty command; there is no CIB request.
         */
        GString *buf = g_string_sized_new(1024);
        xmlNode *output = createEmptyCib(1);

        crm_xml_add(output, PCMK_XA_VALIDATE_WITH, options.validate_with);

        pcmk__xml_string(output, pcmk__xml_fmt_pretty, buf, 0);
        fprintf(stdout, "%s", buf->str);

        g_string_free(buf, TRUE);
        pcmk__xml_free(output);
        return CRM_EX_OK;
    }
    if (options.cmd == cibadmin_cmd_md5_sum) {
        // Handles entirety of md5_sum command; there is no CIB request
        char *digest = pcmk__digest_on_disk_cib(input);

        printf("%s\n", pcmk__s(digest, "<null>"));
        free(digest);
        return CRM_EX_OK;
    }
    if (options.cmd == cibadmin_cmd_md5_sum_versioned) {
        /* Handles entirety of md5_sum_versioned command; there is no CIB
         * request
         */
        char *digest = pcmk__digest_xml(input, true);

        printf("%s\n", pcmk__s(digest, "<null>"));
        free(digest);
        return CRM_EX_OK;
    }

    if (options.cmd == cibadmin_cmd_delete_all) {
        // With cibadmin_section_xpath, remove all matching objects
        cib__set_call_options(*call_options, crm_system_name, cib_multiple);
    }

    if (options.cmd == cibadmin_cmd_modify) {
        /* @COMPAT When we drop default support for expansion in cibadmin, guard
         * with `if (options.score_update)`
         */
        cib__set_call_options(*call_options, crm_system_name, cib_score_update);

        if (options.allow_create) {
            // Allow target to be created if it does not exist
            cib__set_call_options(*call_options, crm_system_name,
                                  cib_can_create);
        }
    }

    if (options.cmd == cibadmin_cmd_query) {
        if (options.get_node_path) {
            /* Enable getting node path of XPath query matches. Meaningful only
             * if options.section_type == cibadmin_section_xpath.
             */
            cib__set_call_options(*call_options, crm_system_name,
                                  cib_xpath_address);
        }

        if (options.no_children) {
            // When querying an object, don't include its children in the result
            cib__set_call_options(*call_options, crm_system_name,
                                  cib_no_children);
        }
    }

    if ((options.cmd == cibadmin_cmd_replace)
        && pcmk__xe_is(input, PCMK_XE_CIB)) {

        xmlNode *status = pcmk_find_cib_element(input, PCMK_XE_STATUS);

        if (status == NULL) {
            pcmk__xe_create(input, PCMK_XE_STATUS);
        }
    }

    return CRM_EX_OK;
}

static crm_exit_t
cibadmin_handle_command(const cibadmin_cmd_info_t *cmd_info, int call_options,
                        const gchar *acl_user, xmlNode *input, GError **error)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    cib_t *cib_conn = NULL;
    xmlNode *output = NULL;

    exit_code = cibadmin_pre_default(&call_options, input, error);
    if ((exit_code != CRM_EX_OK) || (cmd_info->cib_request == NULL)) {
        goto done;
    }

    if (options.section_type == cibadmin_section_xpath) {
        // Enable getting section by XPath
        cib__set_call_options(call_options, crm_system_name, cib_xpath);

    } else if ((options.section_type == cibadmin_section_scope)
               && !scope_is_valid(options.cib_section)) {
        // @COMPAT: Consider requiring --force to proceed
        fprintf(stderr,
                "Invalid value '%s' for '--scope'. Operation will apply to the "
                "entire CIB.\n", options.cib_section);
    }

    rc = cib__create_signon(&cib_conn);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to the CIB API: %s", pcmk_rc_str(rc));
        goto done;
    }

    cib_conn->call_timeout = options.timeout_sec;
    if (cib_conn->call_timeout < 1) {
        fprintf(stderr, "Timeout must be positive, defaulting to %d\n",
                DEFAULT_TIMEOUT);
        cib_conn->call_timeout = DEFAULT_TIMEOUT;
    }

    rc = cib_internal_op(cib_conn, cmd_info->cib_request, options.dest_node,
                         options.cib_section, input, &output, call_options,
                         options.cib_user);
    rc = pcmk_legacy2rc(rc);

    // Handle return code depending on command
    if (options.cmd == cibadmin_cmd_upgrade) {
        if (rc == pcmk_rc_schema_unchanged) {
            printf("Upgrade unnecessary: %s\n", pcmk_rc_str(rc));
            exit_code = CRM_EX_OK;

        } else if (rc != pcmk_rc_ok) {
            fprintf(stderr, "Call failed: %s\n", pcmk_rc_str(rc));
            exit_code = pcmk_rc2exitc(rc);

            if (rc == pcmk_rc_schema_validation) {
                xmlNode *obj = NULL;

                if (cib_conn->cmds->query(cib_conn, NULL, &obj,
                                          call_options) == pcmk_ok) {
                    pcmk__update_schema(&obj, NULL, true, false);
                }
                pcmk__xml_free(obj);
            }
        }

    } else if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Call failed: %s\n", pcmk_rc_str(rc));
        exit_code = pcmk_rc2exitc(rc);

        if ((rc == pcmk_rc_schema_validation) && (output != NULL)) {
            // Show validation errors to stderr
            pcmk__validate_xml(output, NULL, NULL, NULL);
        }
    }

    if (output == NULL) {
        goto done;
    }

    // output is non-NULL, so this is a query or create command
    if (options.acl_render_mode != pcmk__acl_render_none) {
        xmlDoc *acl_evaled_doc = NULL;
        xmlChar *rendered = NULL;

        rc = pcmk__acl_annotate_permissions(acl_user, output->doc,
                                            &acl_evaled_doc);
        if (rc != pcmk_rc_ok) {
            exit_code = CRM_EX_CONFIG;
            g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                        "Could not evaluate access per request (%s, error: %s)",
                        acl_user, pcmk_rc_str(rc));
            goto done;
        }

        rc = pcmk__acl_evaled_render(acl_evaled_doc, options.acl_render_mode,
                                     &rendered);
        if (rc != pcmk_rc_ok) {
            exit_code = CRM_EX_CONFIG;
            g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                        "Could not render evaluated access: %s",
                        pcmk_rc_str(rc));
            goto done;
        }

        printf("%s\n", (char *) rendered);
        xmlFree(rendered);

    } else if (pcmk_is_set(call_options, cib_xpath_address)
               && pcmk__xe_is(output, PCMK__XE_XPATH_QUERY)) {

        pcmk__xe_foreach_child(output, PCMK__XE_XPATH_QUERY_PATH, print_xml_id,
                               NULL);

    } else {
        GString *buf = g_string_sized_new(1024);

        pcmk__xml_string(output, pcmk__xml_fmt_pretty, buf, 0);

        printf("%s", buf->str);
        g_string_free(buf, TRUE);
    }

done:
    pcmk__xml_free(output);

    rc = cib__clean_up_connection(&cib_conn);
    if (exit_code == CRM_EX_OK) {
        exit_code = pcmk_rc2exitc(rc);
    }

    return exit_code;
}

static const cibadmin_cmd_info_t cibadmin_command_info[] = {
    [cibadmin_cmd_bump] = {
        PCMK__CIB_REQUEST_BUMP, cibadmin_cf_none,
    },
    [cibadmin_cmd_create] = {
        PCMK__CIB_REQUEST_CREATE, cibadmin_cf_requires_input,
    },
    [cibadmin_cmd_delete] = {
        PCMK__CIB_REQUEST_DELETE,
        cibadmin_cf_requires_input|cibadmin_cf_xpath_input,
    },
    [cibadmin_cmd_delete_all] = {
        PCMK__CIB_REQUEST_DELETE,
        cibadmin_cf_requires_input|cibadmin_cf_unsafe|cibadmin_cf_xpath_input,
    },
    [cibadmin_cmd_empty] = {
        NULL, cibadmin_cf_none,
    },
    [cibadmin_cmd_erase] = {
        PCMK__CIB_REQUEST_ERASE, cibadmin_cf_unsafe,
    },
    [cibadmin_cmd_md5_sum] = {
        NULL, cibadmin_cf_requires_input,
    },
    [cibadmin_cmd_md5_sum_versioned] = {
        NULL, cibadmin_cf_requires_input,
    },
    [cibadmin_cmd_modify] = {
        PCMK__CIB_REQUEST_MODIFY, cibadmin_cf_requires_input,
    },
    [cibadmin_cmd_patch] = {
        PCMK__CIB_REQUEST_APPLY_PATCH, cibadmin_cf_requires_input,
    },
    [cibadmin_cmd_query] = {
        PCMK__CIB_REQUEST_QUERY, cibadmin_cf_none,
    },
    [cibadmin_cmd_replace] = {
        PCMK__CIB_REQUEST_REPLACE, cibadmin_cf_requires_input,
    },

    /* @TODO Ideally, --upgrade wouldn't be considered unsafe if the CIB already
     * uses the latest schema.
     */
    [cibadmin_cmd_upgrade] = {
        PCMK__CIB_REQUEST_UPGRADE, cibadmin_cf_unsafe,
    },
};

static gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    if (pcmk__str_any_of(option_name, "-u", "--upgrade", NULL)) {
        options.cmd = cibadmin_cmd_upgrade;

    } else if (pcmk__str_any_of(option_name, "-Q", "--query", NULL)) {
        options.cmd = cibadmin_cmd_query;

    } else if (pcmk__str_any_of(option_name, "-E", "--erase", NULL)) {
        options.cmd = cibadmin_cmd_erase;

    } else if (pcmk__str_any_of(option_name, "-B", "--bump", NULL)) {
        options.cmd = cibadmin_cmd_bump;

    } else if (pcmk__str_any_of(option_name, "-C", "--create", NULL)) {
        options.cmd = cibadmin_cmd_create;

    } else if (pcmk__str_any_of(option_name, "-M", "--modify", NULL)) {
        options.cmd = cibadmin_cmd_modify;

    } else if (pcmk__str_any_of(option_name, "-P", "--patch", NULL)) {
        options.cmd = cibadmin_cmd_patch;

    } else if (pcmk__str_any_of(option_name, "-R", "--replace", NULL)) {
        options.cmd = cibadmin_cmd_replace;

    } else if (pcmk__str_any_of(option_name, "-D", "--delete", NULL)) {
        options.cmd = cibadmin_cmd_delete;

    } else if (pcmk__str_any_of(option_name, "-d", "--delete-all", NULL)) {
        options.cmd = cibadmin_cmd_delete_all;

    } else if (pcmk__str_any_of(option_name, "-a", "--empty", NULL)) {
        options.cmd = cibadmin_cmd_empty;
        pcmk__str_update(&options.validate_with, optarg);

    } else if (pcmk__str_any_of(option_name, "-5", "--md5-sum", NULL)) {
        options.cmd = cibadmin_cmd_md5_sum;

    } else if (pcmk__str_any_of(option_name, "-6", "--md5-sum-versioned",
                                NULL)) {
        options.cmd = cibadmin_cmd_md5_sum_versioned;

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
    // @COMPAT These arguments should be last-one-wins
    { "xml-file", 'x', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME,
      &options.input_file,
      "Retrieve XML from the named file. Currently this takes precedence\n"
      INDENT "over --xml-text and --xml-pipe. In a future release, the last\n"
      INDENT "one specified will be used.",
      "FILE" },

    { "xml-text", 'X', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING,
      &options.input_string,
      "Retrieve XML from the supplied string. Currently this takes precedence\n"
      INDENT "over --xml-pipe, but --xml-file overrides this. In a future\n"
      INDENT "release, the last one specified will be used.",
      "STRING" },

    { "xml-pipe", 'p', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
      &options.input_stdin,
      "Retrieve XML from stdin. Currently --xml-file and --xml-text override\n"
      INDENT "this. In a future release, the last one specified will be used.",
      NULL },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "force", 'f', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.force,
      "Force the action to be performed", NULL },

    { "timeout", 't', G_OPTION_FLAG_NONE, G_OPTION_ARG_INT,
      &options.timeout_sec,
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

    // @COMPAT Deprecated since 3.0.0
    { "local", 'l', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_NONE, &options.local,
      "(deprecated)", NULL },

    // @COMPAT Deprecated since 3.0.2
    { "node", 'N', G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING,
      &options.dest_node, "(deprecated)", "value" },

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

    desc = "Examples:\n\n"
           "Query the configuration:\n\n"
           "\t# cibadmin --query\n\n"
           "or just:\n\n"
           "\t# cibadmin\n\n"
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

    context = pcmk__build_arg_context(args, NULL, NULL, "[<command>]");
    g_option_context_set_description(context, desc);

    pcmk__add_arg_group(context, "commands", "Commands:", "Show command help",
                        command_entries);
    pcmk__add_arg_group(context, "data", "Data:", "Show data help",
                        data_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

/*!
 * \internal
 * \brief Read input XML as specified on the command line
 *
 * Precedence is as follows:
 * 1. Input file
 * 2. Input string
 * 3. stdin
 *
 * If multiple input sources are given, only the last occurrence of the one with
 * the highest precedence is tried.
 *
 * If no input source is specified, this function does nothing.
 *
 * \param[out] input   Where to store parsed input
 * \param[out] source  Where to store string describing input source
 *
 * \return Standard Pacemaker return code
 */
static int
read_input(xmlNode **input, const char **source)
{
    if (options.input_file != NULL) {
        *source = options.input_file;
        *input = pcmk__xml_read(options.input_file);

    } else if (options.input_string != NULL) {
        *source = "input string";
        *input = pcmk__xml_parse(options.input_string);

    } else if (options.input_stdin) {
        *source = "stdin";
        *input = pcmk__xml_read(NULL);

    } else {
        *source = NULL;
        *input = NULL;
        return EINVAL;
    }

    if (*input == NULL) {
        return pcmk_rc_bad_input;
    }
    return pcmk_rc_ok;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    const cibadmin_cmd_info_t *cmd_info = NULL;
    int call_options = cib_sync_call;
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
        gchar *extra = g_strjoinv(" ", processed_args + 1);
        gchar *help = g_option_context_get_help(context, TRUE, NULL);

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "non-option ARGV-elements: %s\n\n%s", extra, help);
        g_free(extra);
        g_free(help);
        goto done;
    }

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);

        /* FIXME: When cibadmin is converted to use formatted output, this can
         * be replaced by out->version.
         */
        pcmk__cli_help();
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
        cib__set_call_options(call_options, crm_system_name, cib_verbose);

        for (int i = 0; i < args->verbosity; i++) {
            crm_bump_log_level(argc, argv);
        }
    }

    // Ensure command is in valid range
    if ((options.cmd >= 0) && (options.cmd <= cibadmin_cmd_max)) {
        cmd_info = &cibadmin_command_info[options.cmd];
    }
    if (cmd_info == NULL) {
        exit_code = CRM_EX_SOFTWARE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Bug: Unimplemented command: %d", (int) options.cmd);
        goto done;
    }

    if (pcmk_is_set(cmd_info->flags, cibadmin_cf_unsafe) && !options.force) {
        exit_code = CRM_EX_UNSAFE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "The supplied command is considered dangerous. To prevent "
                    "accidental destruction of the cluster, the --force flag "
                    "is required in order to proceed.");
        goto done;
    }

    /* Query is the only command that produces output suitable for ACL
     * rendering. Ignore --show-access for other commands.
     */
    if (options.acl_render_mode != pcmk__acl_render_none) {
        if (options.cmd == cibadmin_cmd_query) {
            char *username = NULL;

            if (options.cib_user == NULL) {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "The supplied command requires -U user specified.");
                goto done;
            }

            // @COMPAT Fail if pcmk_acl_required(username)
            username = pcmk__uid2username(geteuid());
            if (pcmk_acl_required(username)) {
                fprintf(stderr,
                        "Warning: cibadmin is being run as user %s, which is "
                        "subject to ACLs. As a result, ACLs for user %s may be "
                        "incorrect or incomplete in the output. In a future "
                        "release, running as a privileged user (root or "
                        CRM_DAEMON_USER ") will be required for "
                        "-S/--show-access.\n",
                        username, options.cib_user);
            }

            free(username);

            /* Note: acl_cred takes ownership of options.cib_user here.
             * options.cib_user is set to NULL so that the CIB is obtained as
             * the user running the cibadmin command. The CIB must be obtained
             * as a user with full permissions in order to show the CIB
             * correctly annotated for the options.cib_user's permissions.
             */
            acl_cred = options.cib_user;
            options.cib_user = NULL;

        } else {
            options.acl_render_mode = pcmk__acl_render_none;
        }
    }

    if (pcmk_is_set(cmd_info->flags, cibadmin_cf_requires_input)) {
        bool accepts_xpath = pcmk_is_set(cmd_info->flags,
                                         cibadmin_cf_xpath_input);

        /* If true, use options.cib_section (an XPath expression) instead of
         * input XML
         */
        bool as_xpath = accepts_xpath
                        && (options.section_type == cibadmin_section_xpath);

        if (!as_xpath) {
            const char *source = NULL;

            rc = read_input(&input, &source);
            if (rc == EINVAL) {
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "The supplied command requires %sinput via "
                            "--xml-file, --xml-text, or --xml-pipe",
                            (accepts_xpath? "either --xpath or " : ""));
                goto done;
            }
            if (rc != pcmk_rc_ok) {
                exit_code = pcmk_rc2exitc(rc);
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "Couldn't parse input from %s",
                            pcmk__s(source, "(BUG: null source)"));
                goto done;
            }
        }
    }

    exit_code = cibadmin_handle_command(cmd_info, call_options, acl_cred, input,
                                        &error);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_free(options.cib_user);
    g_free(options.dest_node);
    g_free(options.input_file);
    g_free(options.input_string);
    free(options.cib_section);
    free(options.validate_with);

    g_free(acl_cred);
    pcmk__xml_free(input);

    pcmk__output_and_clear_error(&error, NULL);
    crm_exit(exit_code);
}

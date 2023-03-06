/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <unistd.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <crm/msg_xml.h>

#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/xml.h>

#include <crm/cib.h>
#include <crm/cib/internal.h>

#define SUMMARY "perform Pacemaker configuration changes in a sandbox\n\n"  \
                "This command sets up an environment in which "             \
                "configuration tools (cibadmin,\n"                          \
                "crm_resource, etc.) work offline instead of against a "    \
                "live cluster, allowing\n"                                  \
                "changes to be previewed and tested for side effects."

#define INDENT "                              "

enum shadow_command {
    shadow_cmd_none = 0,
    shadow_cmd_which,
    shadow_cmd_display,
    shadow_cmd_diff,
    shadow_cmd_file,
    shadow_cmd_create,
    shadow_cmd_create_empty,
    shadow_cmd_commit,
    shadow_cmd_delete,
    shadow_cmd_edit,
    shadow_cmd_reset,
    shadow_cmd_switch,
};

static crm_exit_t exit_code = CRM_EX_OK;

static struct {
    enum shadow_command cmd;
    int cmd_options;
    char *instance;
    gboolean force;
    gboolean batch;
    gboolean full_upload;
    gchar *validate_with;
} options = {
    .cmd_options = cib_sync_call,
};

static char *
get_shadow_prompt(const char *name)
{
    return crm_strdup_printf("shadow[%.40s] # ", name);
}

/*!
 * \internal
 * \brief Get the active shadow instance from the environment
 *
 * This sets \p options.instance to the value of the \p CIB_shadow env variable.
 *
 * \param[out] error  Where to store error
 */
static int
get_instance_from_env(GError **error)
{
    int rc = pcmk_rc_ok;

    pcmk__str_update(&options.instance, getenv("CIB_shadow"));
    if (options.instance == NULL) {
        rc = ENXIO;
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "No active shadow configuration defined");
    }
    return rc;
}

/*!
 * \internal
 * \brief Validate that the shadow file does or does not exist, as appropriate
 *
 * \param[in]  filename      Absolute path of shadow file
 * \param[in]  should_exist  Whether the shadow file is expected to exist
 * \param[out] error         Where to store error
 *
 * \return Standard Pacemaker return code
 */
static int
check_file_exists(const char *filename, bool should_exist, GError **error)
{
    struct stat buf;

    if (!should_exist && (stat(filename, &buf) == 0)) {
        exit_code = CRM_EX_CANTCREAT;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "A shadow instance '%s' already exists.\n"
                    "To prevent accidental destruction of the shadow file, "
                    "the --force flag is required in order to proceed.",
                    options.instance);
        return EEXIST;
    }

    if (should_exist && (stat(filename, &buf) < 0)) {
        // @COMPAT: Use pcmk_rc2exitc(errno)?
        exit_code = CRM_EX_NOSUCH;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not access shadow instance '%s': %s",
                    options.instance, strerror(errno));
        return errno;
    }

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Connect to the "real" (non-shadow) CIB
 *
 * \param[out] real_cib  Where to store CIB connection
 * \param[out] error     Where to store error
 *
 * \return Standard Pacemaker return code
 */
static int
connect_real_cib(cib_t **real_cib, GError **error)
{
    int rc = pcmk_rc_ok;

    *real_cib = cib_new_no_shadow();
    if (*real_cib == NULL) {
        rc = ENOMEM;
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not create a CIB connection object");
        return rc;
    }

    rc = (*real_cib)->cmds->signon(*real_cib, crm_system_name, cib_command);
    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not connect to CIB: %s", pcmk_rc_str(rc));
    }
    return rc;
}

/*!
 * \internal
 * \brief Query the "real" (non-shadow) CIB and store the result
 *
 * \param[out]    output    Where to store query output
 * \param[out]    error     Where to store error
 *
 * \return Standard Pacemaker return code
 */
static int
query_real_cib(xmlNode **output, GError **error)
{
    cib_t *real_cib = NULL;
    int rc = connect_real_cib(&real_cib, error);

    if (rc != pcmk_rc_ok) {
        goto done;
    }

    rc = real_cib->cmds->query(real_cib, NULL, output, options.cmd_options);
    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not query the non-shadow CIB: %s", pcmk_rc_str(rc));
    }

done:
    cib_delete(real_cib);
    return rc;
}

static void
shadow_setup(char *name, gboolean do_switch)
{
    const char *prompt = getenv("PS1");
    const char *shell = getenv("SHELL");
    char *new_prompt = get_shadow_prompt(name);

    printf("Setting up shadow instance\n");

    if (pcmk__str_eq(new_prompt, prompt, pcmk__str_casei)) {
        /* nothing to do */
        goto done;

    } else if (!options.batch && (shell != NULL)) {
        setenv("PS1", new_prompt, 1);
        setenv("CIB_shadow", name, 1);
        printf("Type Ctrl-D to exit the crm_shadow shell\n");

        if (strstr(shell, "bash")) {
            execl(shell, shell, "--norc", "--noprofile", NULL);
        } else {
            execl(shell, shell, NULL);
        }

    } else if (do_switch) {
        printf("To switch to the named shadow instance, paste the following into your shell:\n");

    } else {
        printf
            ("A new shadow instance was created.  To begin using it paste the following into your shell:\n");
    }
    printf("  CIB_shadow=%s ; export CIB_shadow\n", name);

  done:
    free(new_prompt);
}

static void
shadow_teardown(char *name)
{
    const char *prompt = getenv("PS1");
    char *our_prompt = get_shadow_prompt(name);

    if (prompt != NULL && strstr(prompt, our_prompt)) {
        printf("Now type Ctrl-D to exit the crm_shadow shell\n");

    } else {
        printf
            ("Please remember to unset the CIB_shadow variable by pasting the following into your shell:\n");
        printf("  unset CIB_shadow\n");
    }
    free(our_prompt);
}

/*!
 * \internal
 * \brief Open the shadow file in a text editor
 *
 * \param[out] error  Where to store error
 *
 * \note The \p EDITOR environment variable must be set.
 */
static void
edit_shadow_file(GError **error)
{
    char *filename = NULL;
    const char *editor = NULL;

    if (get_instance_from_env(error) != pcmk_rc_ok) {
        return;
    }

    filename = get_shadow_file(options.instance);
    if (check_file_exists(filename, true, error) != pcmk_rc_ok) {
        goto done;
    }

    editor = getenv("EDITOR");
    if (editor == NULL) {
        exit_code = CRM_EX_NOT_CONFIGURED;
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "No value for EDITOR defined");
        goto done;
    }

    execlp(editor, "--", filename, NULL);
    exit_code = CRM_EX_OSFILE;
    g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                "Could not invoke EDITOR (%s %s): %s",
                editor, filename, strerror(errno));

done:
    free(filename);
}

/*!
 * \internal
 * \brief Show the contents of the active shadow instance
 *
 * \param[out] error  Where to store error
 */
static void
show_shadow_contents(GError **error)
{
    char *filename = NULL;

    if (get_instance_from_env(error) != pcmk_rc_ok) {
        return;
    }

    filename = get_shadow_file(options.instance);

    if (check_file_exists(filename, true, error) == pcmk_rc_ok) {
        char *output_s = NULL;
        xmlNode *output = filename2xml(filename);

        output_s = dump_xml_formatted(output);
        printf("%s", output_s);

        free(output_s);
        free_xml(output);
    }
    free(filename);
}

/*!
 * \internal
 * \brief Show the changes in the active shadow instance
 *
 * \param[out] error  Where to store error
 */
static void
show_shadow_diff(GError **error)
{
    char *filename = NULL;
    xmlNodePtr old_config = NULL;
    xmlNodePtr new_config = NULL;
    xmlNodePtr diff = NULL;
    pcmk__output_t *logger_out = NULL;
    int rc = pcmk_rc_ok;

    if (get_instance_from_env(error) != pcmk_rc_ok) {
        return;
    }

    filename = get_shadow_file(options.instance);
    if (check_file_exists(filename, true, error) != pcmk_rc_ok) {
        goto done;
    }

    if (query_real_cib(&old_config, error) != pcmk_rc_ok) {
        goto done;
    }

    new_config = filename2xml(filename);
    xml_track_changes(new_config, NULL, new_config, false);
    xml_calculate_changes(old_config, new_config);
    diff = xml_create_patchset(0, old_config, new_config, NULL, false);

    rc = pcmk__log_output_new(&logger_out);
    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not create logger object: %s", pcmk_rc_str(rc));
        goto done;
    }
    pcmk__output_set_log_level(logger_out, LOG_INFO);
    rc = pcmk__xml_show_changes(logger_out, new_config);
    logger_out->finish(logger_out, pcmk_rc2exitc(rc), true, NULL);
    pcmk__output_free(logger_out);

    xml_accept_changes(new_config);

    if (diff != NULL) {
        pcmk__output_t *out = NULL;

        rc = pcmk__text_output_new(&out, NULL);
        if (rc != pcmk_rc_ok) {
            exit_code = pcmk_rc2exitc(rc);
            g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                        "Could not create output object: %s", pcmk_rc_str(rc));
            goto done;
        }
        rc = out->message(out, "xml-patchset", diff);
        out->finish(out, pcmk_rc2exitc(rc), true, NULL);
        pcmk__output_free(out);

        /* @COMPAT: Exit with CRM_EX_DIGEST? This is not really an error; we
         * just want to indicate that there are differences (as the diff command
         * does).
         */
        exit_code = CRM_EX_ERROR;
    }

done:
    free(filename);
    free_xml(old_config);
    free_xml(new_config);
    free_xml(diff);
}

/*!
 * \internal
 * \brief Show the absolute path of the active shadow instance
 *
 * \param[out] error  Where to store error
 */
static void
show_shadow_filename(GError **error)
{
    if (get_instance_from_env(error) == pcmk_rc_ok) {
        char *filename = get_shadow_file(options.instance);

        printf("%s\n", filename);
        free(filename);
    }
}

/*!
 * \internal
 * \brief Show the active shadow instance
 *
 * \param[out] error  Where to store error
 */
static void
show_shadow_instance(GError **error)
{
    if (get_instance_from_env(error) == pcmk_rc_ok) {
        printf("%s\n", options.instance);
    }
}

/*!
 * \internal
 * \brief Switch to the given shadow instance
 *
 * \param[out] error  Where to store error
 */
static void
switch_shadow_instance(GError **error)
{
    char *filename = NULL;

    filename = get_shadow_file(options.instance);
    if (check_file_exists(filename, true, error) == pcmk_rc_ok) {
        shadow_setup(options.instance, TRUE);
    }
    free(filename);
}

static gboolean
command_cb(const gchar *option_name, const gchar *optarg, gpointer data,
           GError **error)
{
    if (pcmk__str_any_of(option_name, "-w", "--which", NULL)) {
        options.cmd = shadow_cmd_which;

    } else if (pcmk__str_any_of(option_name, "-p", "--display", NULL)) {
        options.cmd = shadow_cmd_display;

    } else if (pcmk__str_any_of(option_name, "-d", "--diff", NULL)) {
        options.cmd = shadow_cmd_diff;

    } else if (pcmk__str_any_of(option_name, "-F", "--file", NULL)) {
        options.cmd = shadow_cmd_file;

    } else if (pcmk__str_any_of(option_name, "-c", "--create", NULL)) {
        options.cmd = shadow_cmd_create;

    } else if (pcmk__str_any_of(option_name, "-e", "--create-empty", NULL)) {
        options.cmd = shadow_cmd_create_empty;

    } else if (pcmk__str_any_of(option_name, "-C", "--commit", NULL)) {
        options.cmd = shadow_cmd_commit;

    } else if (pcmk__str_any_of(option_name, "-D", "--delete", NULL)) {
        options.cmd = shadow_cmd_delete;

    } else if (pcmk__str_any_of(option_name, "-E", "--edit", NULL)) {
        options.cmd = shadow_cmd_edit;

    } else if (pcmk__str_any_of(option_name, "-r", "--reset", NULL)) {
        options.cmd = shadow_cmd_reset;

    } else if (pcmk__str_any_of(option_name, "-s", "--switch", NULL)) {
        options.cmd = shadow_cmd_switch;

    } else {
        // Should be impossible
        return FALSE;
    }

    // optarg may be NULL and that's okay
    pcmk__str_update(&options.instance, optarg);
    return TRUE;
}

static GOptionEntry query_entries[] = {
    { "which", 'w', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Indicate the active shadow copy", NULL },

    { "display", 'p', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the contents of the active shadow copy", NULL },

    { "diff", 'd', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the changes in the active shadow copy", NULL },

    { "file", 'F', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Display the location of the active shadow copy file", NULL },

    { NULL }
};

static GOptionEntry command_entries[] = {
    { "create", 'c', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "Create the named shadow copy of the active cluster configuration",
      "name" },

    { "create-empty", 'e', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
      command_cb,
      "Create the named shadow copy with an empty cluster configuration.\n"
      INDENT "Optional: --validate-with", "name" },

    { "commit", 'C', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "Upload the contents of the named shadow copy to the cluster", "name" },

    { "delete", 'D', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "Delete the contents of the named shadow copy", "name" },

    { "edit", 'E', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, command_cb,
      "Edit the contents of the active shadow copy with your favorite $EDITOR",
      NULL },

    { "reset", 'r', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "Recreate named shadow copy from the active cluster configuration",
      "name" },

    { "switch", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, command_cb,
      "(Advanced) Switch to the named shadow copy", "name" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "force", 'f', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.force,
      "(Advanced) Force the action to be performed", NULL },

    { "batch", 'b', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.batch,
      "(Advanced) Don't spawn a new shell", NULL },

    { "all", 'a', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.full_upload,
      "(Advanced) Upload entire CIB, including status, with --commit", NULL },

    { "validate-with", 'v', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING,
      &options.validate_with,
      "(Advanced) Create an older configuration version", NULL },

    { NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args)
{
    const char *desc = NULL;
    GOptionContext *context = NULL;

    desc = "Examples:\n\n"
           "Create a blank shadow configuration:\n\n"
           "\t# crm_shadow --create-empty myShadow\n\n"
           "Create a shadow configuration from the running cluster\n\n"
           "\t# crm_shadow --create myShadow\n\n"
           "Display the current shadow configuration:\n\n"
           "\t# crm_shadow --display\n\n"
           "Discard the current shadow configuration (named myShadow):\n\n"
           "\t# crm_shadow --delete myShadow --force\n\n"
           "Upload current shadow configuration (named myShadow) to running "
           "cluster:\n\n"
           "\t# crm_shadow --commit myShadow\n\n";

    context = pcmk__build_arg_context(args, NULL, NULL, "<query>|<command>");
    g_option_context_set_description(context, desc);

    pcmk__add_arg_group(context, "queries", "Queries:",
                        "Show query help", query_entries);
    pcmk__add_arg_group(context, "commands", "Commands:",
                        "Show command help", command_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_ok;
    char *shadow_file = NULL;
    bool needs_teardown = false;

    cib_t *real_cib = NULL;

    GError *error = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "ceCDrsv");
    GOptionContext *context = build_arg_context(args);

    crm_log_preinit(NULL, argc, argv);

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

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);

        /* FIXME: When crm_shadow is converted to use formatted output,
         * this can go.
         */
        pcmk__cli_help('v');
    }

    if (options.cmd == shadow_cmd_none) {
        // @COMPAT: Create a default command if other tools have one
        gchar *help = g_option_context_get_help(context, TRUE, NULL);

        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Must specify a query or command option\n\n%s", help);
        g_free(help);
        goto done;
    }

    pcmk__cli_init_logging("crm_shadow", args->verbosity);

    if (args->verbosity > 0) {
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_verbose);
    }

    if (options.force) {
        cib__set_call_options(options.cmd_options, crm_system_name,
                              cib_quorum_override);
    }

    /* Run the command
     * @TODO: Finish adding all commands here
     */
    switch (options.cmd) {
        case shadow_cmd_diff:
            show_shadow_diff(&error);
            goto done;
        case shadow_cmd_display:
            show_shadow_contents(&error);
            goto done;
        case shadow_cmd_edit:
            edit_shadow_file(&error);
            goto done;
        case shadow_cmd_file:
            show_shadow_filename(&error);
            goto done;
        case shadow_cmd_switch:
            switch_shadow_instance(&error);
            goto done;
        case shadow_cmd_which:
            show_shadow_instance(&error);
            goto done;
        default:
            break;
    }

    // Check for shadow instance mismatch
    if (options.cmd != shadow_cmd_create) {
        const char *local = getenv("CIB_shadow");

        if (!options.force
            && !pcmk__str_eq(local, options.instance, pcmk__str_null_matches)) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "The supplied shadow instance (%s) is not the same as "
                        "the active one (%s).\n"
                        "To prevent accidental destruction of the cluster, the "
                        "--force flag is required in order to proceed.",
                        options.instance, local);
            goto done;
        }
    }

    // Check for dangerous commands
    if (!options.force) {
        switch (options.cmd) {
            case shadow_cmd_commit:
            case shadow_cmd_delete:
                exit_code = CRM_EX_USAGE;
                g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                            "The supplied command is considered dangerous.\n"
                            "To prevent accidental destruction of the cluster, "
                            "the --force flag is required in order to "
                            "proceed.");
                goto done;
            default:
                break;
        }
    }

    shadow_file = get_shadow_file(options.instance);

    if (options.cmd == shadow_cmd_delete) {
        // Delete the shadow file
        if ((unlink(shadow_file) < 0) && (errno != ENOENT)) {
            exit_code = pcmk_rc2exitc(errno);
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "Could not remove shadow instance '%s': %s",
                        options.instance, strerror(errno));
        }
        needs_teardown = true;
        goto done;
    }

    // Check existence of the shadow file
    switch (options.cmd) {
        case shadow_cmd_create:
        case shadow_cmd_create_empty:
            if (!options.force
                && (check_file_exists(shadow_file, false,
                                      &error) != pcmk_rc_ok)) {
                goto done;
            }
            break;
        default:
            if (check_file_exists(shadow_file, true, &error) != pcmk_rc_ok) {
                goto done;
            }
            break;
    }

    // Run the command if we haven't already
    switch (options.cmd) {
        case shadow_cmd_create:
        case shadow_cmd_create_empty:
        case shadow_cmd_reset:
            // Create or reset the shadow file
            {
                xmlNode *output = NULL;

                if (options.cmd == shadow_cmd_create_empty) {
                    output = createEmptyCib(0);
                    crm_xml_add(output, XML_ATTR_VALIDATION,
                                options.validate_with);
                    printf("Created new %s configuration\n",
                           crm_element_value(output, XML_ATTR_VALIDATION));

                } else {
                    // Create a shadow instance based on the current CIB
                    if (query_real_cib(&output, &error) != pcmk_rc_ok) {
                        goto done;
                    }
                }

                rc = write_xml_file(output, shadow_file, FALSE);
                free_xml(output);

                if (rc < 0) {
                    const char *action = "create";
                    rc = pcmk_legacy2rc(rc);
                    exit_code = pcmk_rc2exitc(rc);

                    if (options.cmd == shadow_cmd_reset) {
                        action = "reset";
                    }

                    g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                                "Could not %s the shadow instance '%s': %s",
                                action, options.instance, pcmk_rc_str(rc));
                    goto done;
                }
                shadow_setup(options.instance, FALSE);
            }
            break;

        case shadow_cmd_commit:
            // Commit the shadow file to the cluster
            {
                xmlNode *input = filename2xml(shadow_file);
                xmlNode *section_xml = input;
                const char *section = NULL;

                if (connect_real_cib(&real_cib, &error) != pcmk_rc_ok) {
                    goto done;
                }

                if (!options.full_upload) {
                    section = XML_CIB_TAG_CONFIGURATION;
                    section_xml = first_named_child(input, section);
                }

                rc = real_cib->cmds->replace(real_cib, section, section_xml,
                                             options.cmd_options);
                if (rc != pcmk_ok) {
                    rc = pcmk_legacy2rc(rc);
                    exit_code = pcmk_rc2exitc(rc);
                    g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                                "Could not commit shadow instance '%s' to the "
                                "CIB: %s",
                                options.instance, pcmk_rc_str(rc));
                    goto done;
                }
                needs_teardown = true;
                free_xml(input);
            }
            break;

        default:
            // Should never reach this point
            break;
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, NULL);

    if (needs_teardown) {
        // Teardown message should be the last thing we output
        shadow_teardown(options.instance);
    }

    free(shadow_file);
    cib_delete(real_cib);

    free(options.instance);
    g_free(options.validate_with);
    crm_exit(exit_code);
}

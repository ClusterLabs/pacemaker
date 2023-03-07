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

static bool needs_teardown = false;
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

/*!
 * \internal
 * \brief Set the error when \p --force is not passed with a dangerous command
 *
 * \param[in]  reason         Why command is dangerous
 * \param[in]  for_shadow     If true, command is dangerous to the shadow file.
 *                            Otherwise, command is dangerous to the active
 *                            cluster.
 * \param[in]  show_mismatch  If true and the supplied shadow instance is not
 *                            the same as the active shadow instance, report
 *                            this
 * \param[out] error          Where to store error
 */
static inline void
set_danger_error(const char *reason, bool for_shadow, bool show_mismatch,
                 GError **error)
{
    const char *active = getenv("CIB_shadow");
    char *full = NULL;

    if (show_mismatch
        && !pcmk__str_eq(active, options.instance, pcmk__str_null_matches)) {

        full = crm_strdup_printf("%s.\nAdditionally, the supplied shadow "
                                 "instance (%s) is not the same as the active "
                                 "one (%s)",
                                reason, options.instance, active);
        reason = full;
    }

    g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                "%s%sTo prevent accidental destruction of the %s, the --force "
                "flag is required in order to proceed.",
                pcmk__s(reason, ""), ((reason != NULL)? ".\n" : ""),
                (for_shadow? "shadow file" : "cluster"));
    free(full);
}

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
        char *reason = crm_strdup_printf("A shadow instance '%s' already "
                                         "exists", options.instance);

        exit_code = CRM_EX_CANTCREAT;
        set_danger_error(reason, true, false, error);
        free(reason);
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

/*!
 * \internal
 * \brief Read XML from the given file
 *
 * \param[in]  filename  Path of input file
 * \param[out] output    Where to store XML read from \p filename
 * \param[out] error     Where to store error
 *
 * \return Standard Pacemaker return code
 */
static int
read_xml(const char *filename, xmlNode **output, GError **error)
{
    int rc = pcmk_rc_ok;

    *output = filename2xml(filename);
    if (*output == NULL) {
        rc = pcmk_rc_no_input;
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not parse XML from input file '%s'", filename);
    }
    return rc;
}

/*!
 * \internal
 * \brief Write the shadow XML to a file
 *
 * \param[in,out] xml       Shadow XML
 * \param[in]     filename  Name of destination file
 * \param[in]     reset     Whether the write is a reset (for logging only)
 * \param[out]    error     Where to store error
 */
static int
write_shadow_file(xmlNode *xml, const char *filename, bool reset,
                  GError **error)
{
    int rc = write_xml_file(xml, filename, FALSE);

    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not %s the shadow instance '%s': %s",
                    reset? "reset" : "create", options.instance,
                    pcmk_rc_str(rc));
        return rc;
    }
    return pcmk_rc_ok;
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
 * \brief Commit the shadow file contents to the active cluster
 *
 * \param[out] error  Where to store error
 */
static void
commit_shadow_file(GError **error)
{
    char *filename = NULL;
    cib_t *real_cib = NULL;

    xmlNodePtr input = NULL;
    xmlNodePtr section_xml = NULL;
    const char *section = NULL;

    int rc = pcmk_rc_ok;

    if (!options.force) {
        const char *reason = "The commit command overwrites the active cluster "
                             "configuration";

        exit_code = CRM_EX_USAGE;
        set_danger_error(reason, false, true, error);
        return;
    }

    filename = get_shadow_file(options.instance);
    if (check_file_exists(filename, true, error) != pcmk_rc_ok) {
        goto done;
    }

    if (connect_real_cib(&real_cib, error) != pcmk_rc_ok) {
        goto done;
    }

    if (read_xml(filename, &input, error) != pcmk_rc_ok) {
        goto done;
    }

    section_xml = input;

    if (!options.full_upload) {
        section = XML_CIB_TAG_CONFIGURATION;
        section_xml = first_named_child(input, section);
    }

    rc = real_cib->cmds->replace(real_cib, section, section_xml,
                                 options.cmd_options);
    rc = pcmk_legacy2rc(rc);

    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not commit shadow instance '%s' to the CIB: %s",
                    options.instance, pcmk_rc_str(rc));
    }
    needs_teardown = true;

done:
    free(filename);
    cib_delete(real_cib);
    free_xml(input);
}

/*!
 * \internal
 * \brief Create a new empty shadow instance
 *
 * \param[out] error  Where to store error
 *
 * \note If \p --force is given, we try to write the file regardless of whether
 *       it already exists.
 */
static void
create_shadow_empty(GError **error)
{
    char *filename = get_shadow_file(options.instance);
    xmlNode *output = NULL;

    if (!options.force
        && (check_file_exists(filename, false, error) != pcmk_rc_ok)) {
        goto done;
    }

    output = createEmptyCib(0);
    crm_xml_add(output, XML_ATTR_VALIDATION, options.validate_with);
    printf("Created new %s configuration\n",
           crm_element_value(output, XML_ATTR_VALIDATION));

    if (write_shadow_file(output, filename, false, error) != pcmk_rc_ok) {
        goto done;
    }
    shadow_setup(options.instance, FALSE);

done:
    free(filename);
    free_xml(output);
}

/*!
 * \internal
 * \brief Create a shadow instance based on the active CIB
 *
 * \param[in]  reset  If true, overwrite the given existing shadow instance.
 *                    Otherwise, create a new shadow instance with the given
 *                    name.
 * \param[out] error  Where to store error
 *
 * \note If \p --force is given, we try to write the file regardless of whether
 *       it already exists.
 */
static void
create_shadow_from_cib(bool reset, GError **error)
{
    char *filename = get_shadow_file(options.instance);
    xmlNode *output = NULL;

    if (!options.force) {
        if (reset) {
            /* @COMPAT: Reset is dangerous to the shadow file, but to preserve
             * compatibility we can't require --force unless there's a mismatch.
             * At a compatibility break, call set_danger_error() with for_shadow
             * and show_mismatch set to true.
             */
            const char *local = getenv("CIB_shadow");

            if (!pcmk__str_eq(local, options.instance, pcmk__str_null_matches)) {
                exit_code = CRM_EX_USAGE;
                g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                            "The supplied shadow instance (%s) is not the same "
                            "as the active one (%s).\n"
                            "To prevent accidental destruction of the shadow "
                            "file, the --force flag is required in order to "
                            "proceed.",
                            options.instance, local);
                goto done;
            }
        }

        if (check_file_exists(filename, reset, error) != pcmk_rc_ok) {
            goto done;
        }
    }

    if (query_real_cib(&output, error) != pcmk_rc_ok) {
        goto done;
    }

    if (write_shadow_file(output, filename, reset, error) != pcmk_rc_ok) {
        goto done;
    }
    shadow_setup(options.instance, FALSE);

done:
    free(filename);
    free_xml(output);
}

/*!
 * \internal
 * \brief Delete the shadow file
 *
 * \param[out] error  Where to store error
 */
static void
delete_shadow_file(GError **error)
{
    char *filename = NULL;

    if (!options.force) {
        const char *reason = "The delete command removes the specified shadow "
                             "file";

        exit_code = CRM_EX_USAGE;
        set_danger_error(reason, true, true, error);
        return;
    }

    filename = get_shadow_file(options.instance);

    if ((unlink(filename) < 0) && (errno != ENOENT)) {
        exit_code = pcmk_rc2exitc(errno);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not remove shadow instance '%s': %s",
                    options.instance, strerror(errno));
    }
    needs_teardown = true;
    free(filename);
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
        xmlNode *output = NULL;

        if (read_xml(filename, &output, error) != pcmk_rc_ok) {
            goto done;
        }

        output_s = dump_xml_formatted(output);
        printf("%s", output_s);

        free(output_s);
        free_xml(output);
    }

done:
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

    if (read_xml(filename, &new_config, error) != pcmk_rc_ok) {
        goto done;
    }
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

    // Run the command
    switch (options.cmd) {
        case shadow_cmd_commit:
            commit_shadow_file(&error);
            break;
        case shadow_cmd_create:
            create_shadow_from_cib(false, &error);
            break;
        case shadow_cmd_create_empty:
            create_shadow_empty(&error);
            break;
        case shadow_cmd_reset:
            create_shadow_from_cib(true, &error);
            break;
        case shadow_cmd_delete:
            delete_shadow_file(&error);
            break;
        case shadow_cmd_diff:
            show_shadow_diff(&error);
            break;
        case shadow_cmd_display:
            show_shadow_contents(&error);
            break;
        case shadow_cmd_edit:
            edit_shadow_file(&error);
            break;
        case shadow_cmd_file:
            show_shadow_filename(&error);
            break;
        case shadow_cmd_switch:
            switch_shadow_instance(&error);
            break;
        case shadow_cmd_which:
            show_shadow_instance(&error);
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
    free(options.instance);
    g_free(options.validate_with);
    crm_exit(exit_code);
}

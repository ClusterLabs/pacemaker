/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdint.h>                 // UINT32_C
#include <stdio.h>
#include <unistd.h>

#include <sys/param.h>
#include <crm/crm.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <glib.h>                           // GOption, etc.

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

/*!
 * \internal
 * \brief Bit flags to control which fields of shadow CIB info are displayed
 *
 * \note Ignored for XML output.
 */
enum shadow_disp_flags {
    shadow_disp_instance = (UINT32_C(1) << 0),
    shadow_disp_file     = (UINT32_C(1) << 1),
    shadow_disp_content  = (UINT32_C(1) << 2),
    shadow_disp_diff     = (UINT32_C(1) << 3),
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

/*!
 * \internal
 * \brief Display an instruction to the user
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Instructional message
 */
PCMK__OUTPUT_ARGS("instruction", "const char *")
static int
instruction_default(pcmk__output_t *out, va_list args)
{
    const char *msg = va_arg(args, const char *);

    if (msg == NULL) {
        return pcmk_rc_no_output;
    }
    return out->info(out, "%s", msg);
}

/*!
 * \internal
 * \brief Display an instruction to the user
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Instructional message
 */
PCMK__OUTPUT_ARGS("instruction", "const char *")
static int
instruction_xml(pcmk__output_t *out, va_list args)
{
    const char *msg = va_arg(args, const char *);

    if (msg == NULL) {
        return pcmk_rc_no_output;
    }
    pcmk__output_create_xml_text_node(out, "instruction", msg);
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Display information about a shadow CIB instance
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Instance name (can be \p NULL)
 *       -# Shadow file name (can be \p NULL)
 *       -# Shadow file content (can be \p NULL)
 *       -# Patchset containing the changes in the shadow CIB (can be \p NULL)
 *       -# Group of \p shadow_disp_flags indicating which fields to display
 */
PCMK__OUTPUT_ARGS("shadow", "const char *", "const char *", "const xmlNode *",
                  "const xmlNode *", "enum shadow_disp_flags")
static int
shadow_default(pcmk__output_t *out, va_list args)
{
    const char *instance = va_arg(args, const char *);
    const char *filename = va_arg(args, const char *);
    const xmlNode *content = va_arg(args, const xmlNode *);
    const xmlNode *diff = va_arg(args, const xmlNode *);
    enum shadow_disp_flags flags = (enum shadow_disp_flags) va_arg(args, int);

    int rc = pcmk_rc_no_output;

    if (pcmk__is_set(flags, shadow_disp_instance)) {
        rc = out->info(out, "Instance: %s", pcmk__s(instance, "<unknown>"));
    }
    if (pcmk__is_set(flags, shadow_disp_file)) {
        rc = out->info(out, "File name: %s", pcmk__s(filename, "<unknown>"));
    }
    if (pcmk__is_set(flags, shadow_disp_content)) {
        rc = out->info(out, "Content:");

        if (content != NULL) {
            GString *buf = g_string_sized_new(1024);
            gchar *str = NULL;

            pcmk__xml_string(content, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text,
                             buf, 0);

            str = g_string_free(buf, FALSE);
            str = g_strchomp(str);
            if (!pcmk__str_empty(str)) {
                out->info(out, "%s", str);
            }
            g_free(str);

        } else {
            out->info(out, "<unknown>");
        }
    }
    if (pcmk__is_set(flags, shadow_disp_diff)) {
        rc = out->info(out, "Diff:");

        if (diff != NULL) {
            out->message(out, "xml-patchset", diff);
        } else {
            out->info(out, "<empty>");
        }
    }

    return rc;
}

/*!
 * \internal
 * \brief Display information about a shadow CIB instance
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Instance name (can be \p NULL)
 *       -# Shadow file name (can be \p NULL)
 *       -# Shadow file content (can be \p NULL)
 *       -# Patchset containing the changes in the shadow CIB (can be \p NULL)
 *       -# Group of \p shadow_disp_flags indicating which fields to display
 */
PCMK__OUTPUT_ARGS("shadow", "const char *", "const char *", "const xmlNode *",
                  "const xmlNode *", "enum shadow_disp_flags")
static int
shadow_text(pcmk__output_t *out, va_list args)
{
    if (!out->is_quiet(out)) {
        return shadow_default(out, args);

    } else {
        const char *instance = va_arg(args, const char *);
        const char *filename = va_arg(args, const char *);
        const xmlNode *content = va_arg(args, const xmlNode *);
        const xmlNode *diff = va_arg(args, const xmlNode *);
        enum shadow_disp_flags flags = (enum shadow_disp_flags) va_arg(args, int);

        int rc = pcmk_rc_no_output;
        bool quiet_orig = out->quiet;

        /* We have to disable quiet mode for the "xml-patchset" message if we
         * call it, so we might as well do so for this whole section.
         */
        out->quiet = false;

        if (pcmk__is_set(flags, shadow_disp_instance) && (instance != NULL)) {
            rc = out->info(out, "%s", instance);
        }
        if (pcmk__is_set(flags, shadow_disp_file) && (filename != NULL)) {
            rc = out->info(out, "%s", filename);
        }
        if (pcmk__is_set(flags, shadow_disp_content) && (content != NULL)) {
            GString *buf = g_string_sized_new(1024);
            gchar *str = NULL;

            pcmk__xml_string(content, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text,
                             buf, 0);

            str = g_string_free(buf, FALSE);
            str = g_strchomp(str);
            rc = out->info(out, "%s", str);
            g_free(str);
        }
        if (pcmk__is_set(flags, shadow_disp_diff) && (diff != NULL)) {
            rc = out->message(out, "xml-patchset", diff);
        }

        out->quiet = quiet_orig;
        return rc;
    }
}

/*!
 * \internal
 * \brief Display information about a shadow CIB instance
 *
 * \param[in,out] out   Output object
 * \param[in]     args  Message-specific arguments
 *
 * \return Standard Pacemaker return code
 *
 * \note \p args should contain the following:
 *       -# Instance name (can be \p NULL)
 *       -# Shadow file name (can be \p NULL)
 *       -# Shadow file content (can be \p NULL)
 *       -# Patchset containing the changes in the shadow CIB (can be \p NULL)
 *       -# Group of \p shadow_disp_flags indicating which fields to display
 *          (ignored)
 */
PCMK__OUTPUT_ARGS("shadow", "const char *", "const char *", "const xmlNode *",
                  "const xmlNode *", "enum shadow_disp_flags")
static int
shadow_xml(pcmk__output_t *out, va_list args)
{
    const char *instance = va_arg(args, const char *);
    const char *filename = va_arg(args, const char *);
    const xmlNode *content = va_arg(args, const xmlNode *);
    const xmlNode *diff = va_arg(args, const xmlNode *);
    enum shadow_disp_flags flags G_GNUC_UNUSED =
        (enum shadow_disp_flags) va_arg(args, int);

    pcmk__output_xml_create_parent(out, PCMK_XE_SHADOW,
                                   PCMK_XA_INSTANCE, instance,
                                   PCMK_XA_FILE, filename,
                                   NULL);

    if (content != NULL) {
        GString *buf = g_string_sized_new(1024);

        pcmk__xml_string(content, pcmk__xml_fmt_pretty|pcmk__xml_fmt_text, buf,
                         0);

        out->output_xml(out, PCMK_XE_CONTENT, buf->str);
        g_string_free(buf, TRUE);
    }

    if (diff != NULL) {
        out->message(out, "xml-patchset", diff);
    }

    pcmk__output_xml_pop_parent(out);
    return pcmk_rc_ok;
}

static const pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static const pcmk__message_entry_t fmt_functions[] = {
    { "instruction", "default", instruction_default },
    { "instruction", "xml", instruction_xml },
    { "shadow", "default", shadow_default },
    { "shadow", "text", shadow_text },
    { "shadow", "xml", shadow_xml },

    { NULL, NULL, NULL }
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
static void
set_danger_error(const char *reason, bool for_shadow, bool show_mismatch,
                 GError **error)
{
    const char *active = getenv("CIB_shadow");
    char *full = NULL;

    if (show_mismatch
        && !pcmk__str_eq(active, options.instance, pcmk__str_null_matches)) {

        full = pcmk__assert_asprintf("%s.\nAdditionally, the supplied shadow "
                                     "instance (%s) is not the same as the "
                                     "active one (%s)",
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
        char *reason = pcmk__assert_asprintf("A shadow instance '%s' already "
                                             "exists",
                                             options.instance);

        exit_code = CRM_EX_CANTCREAT;
        set_danger_error(reason, true, false, error);
        free(reason);
        return EEXIST;
    }

    if (should_exist && (stat(filename, &buf) < 0)) {
        int rc = errno;

        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not access shadow instance '%s': %s",
                    options.instance, strerror(rc));
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
    const char *active = getenv("CIB_shadow");
    int rc = pcmk_rc_ok;

    // Create a non-shadowed CIB connection object and then restore CIB_shadow
    unsetenv("CIB_shadow");
    rc = cib__create_signon(real_cib);
    if (active != NULL) {
        setenv("CIB_shadow", active, 1);
    }

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

    *output = pcmk__xml_read(filename);
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
 * \param[in]  xml       Shadow XML
 * \param[in]  filename  Name of destination file
 * \param[in]  reset     Whether the write is a reset (for logging only)
 * \param[out] error     Where to store error
 */
static int
write_shadow_file(const xmlNode *xml, const char *filename, bool reset,
                  GError **error)
{
    int rc = pcmk__xml_write_file(xml, filename, false);

    if (rc != pcmk_rc_ok) {
        exit_code = pcmk_rc2exitc(rc);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Could not %s the shadow instance '%s': %s",
                    reset? "reset" : "create", options.instance,
                    pcmk_rc_str(rc));
    }
    return rc;
}

/*!
 * \internal
 * \brief Create a shell prompt based on the given shadow instance name
 *
 * \return Newly created prompt
 *
 * \note The caller is responsible for freeing the return value using \p free().
 */
static inline char *
get_shadow_prompt(void)
{
    return pcmk__assert_asprintf("shadow[%.40s] # ", options.instance);
}

/*!
 * \internal
 * \brief Set up environment variables for a shadow instance
 *
 * \param[in,out] out      Output object
 * \param[in]     do_switch  If true, switch to an existing instance (logging
 *                           only)
 * \param[out]    error      Where to store error
 */
static void
shadow_setup(pcmk__output_t *out, bool do_switch, GError **error)
{
    const char *active = getenv("CIB_shadow");
    const char *prompt = getenv("PS1");
    const char *shell = getenv("SHELL");
    char *new_prompt = get_shadow_prompt();

    if (pcmk__str_eq(active, options.instance, pcmk__str_none)
        && pcmk__str_eq(new_prompt, prompt, pcmk__str_none)) {
        // CIB_shadow and prompt environment variables are already set up
        goto done;
    }

    if (!options.batch && (shell != NULL)) {
        out->info(out, "Setting up shadow instance");
        setenv("PS1", new_prompt, 1);
        setenv("CIB_shadow", options.instance, 1);

        out->message(out, PCMK_XE_INSTRUCTION,
                     "Press Ctrl+D to exit the crm_shadow shell");

        if (pcmk__str_eq(shell, "(^|/)bash$", pcmk__str_regex)) {
            execl(shell, shell, "--norc", "--noprofile", NULL);
        } else {
            execl(shell, shell, NULL);
        }

        exit_code = pcmk_rc2exitc(errno);
        g_set_error(error, PCMK__EXITC_ERROR, exit_code,
                    "Failed to launch shell '%s': %s",
                    shell, pcmk_rc_str(errno));

    } else {
        char *msg = NULL;
        const char *prefix = "A new shadow instance was created. To begin "
                             "using it";

        if (do_switch) {
            prefix = "To switch to the named shadow instance";
        }

        msg = pcmk__assert_asprintf("%s, enter the following into your shell:\n"
                                    "\texport CIB_shadow=%s",
                                    prefix, options.instance);
        out->message(out, "instruction", msg);
        free(msg);
    }

done:
    free(new_prompt);
}

/*!
 * \internal
 * \brief Remind the user to clean up the shadow environment
 *
 * \param[in,out] out  Output object
 */
static void
shadow_teardown(pcmk__output_t *out)
{
    const char *active = getenv("CIB_shadow");
    const char *prompt = getenv("PS1");

    if (pcmk__str_eq(active, options.instance, pcmk__str_none)) {
        char *our_prompt = get_shadow_prompt();

        if (pcmk__str_eq(prompt, our_prompt, pcmk__str_none)) {
            out->message(out, "instruction",
                         "Press Ctrl+D to exit the crm_shadow shell");

        } else {
            out->message(out, "instruction",
                         "Remember to unset the CIB_shadow variable by "
                         "entering the following into your shell:\n"
                         "\tunset CIB_shadow");
        }
        free(our_prompt);
    }
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
        section = PCMK_XE_CONFIGURATION;
        section_xml = pcmk__xe_first_child(input, section, NULL, NULL);
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

done:
    free(filename);
    cib_delete(real_cib);
    pcmk__xml_free(input);
}

/*!
 * \internal
 * \brief Create a new empty shadow instance
 *
 * \param[in,out] out    Output object
 * \param[out]    error  Where to store error
 *
 * \note If \p --force is given, we try to write the file regardless of whether
 *       it already exists.
 */
static void
create_shadow_empty(pcmk__output_t *out, GError **error)
{
    char *filename = get_shadow_file(options.instance);
    xmlNode *output = NULL;

    if (!options.force
        && (check_file_exists(filename, false, error) != pcmk_rc_ok)) {
        goto done;
    }

    output = createEmptyCib(0);
    pcmk__xe_set(output, PCMK_XA_VALIDATE_WITH, options.validate_with);
    out->info(out, "Created new %s configuration",
              pcmk__xe_get(output, PCMK_XA_VALIDATE_WITH));

    if (write_shadow_file(output, filename, false, error) != pcmk_rc_ok) {
        goto done;
    }
    shadow_setup(out, false, error);

done:
    free(filename);
    pcmk__xml_free(output);
}

/*!
 * \internal
 * \brief Create a shadow instance based on the active CIB
 *
 * \param[in,out] out    Output object
 * \param[in]     reset  If true, overwrite the given existing shadow instance.
 *                       Otherwise, create a new shadow instance with the given
 *                       name.
 * \param[out]    error  Where to store error
 *
 * \note If \p --force is given, we try to write the file regardless of whether
 *       it already exists.
 */
static void
create_shadow_from_cib(pcmk__output_t *out, bool reset, GError **error)
{
    char *filename = get_shadow_file(options.instance);
    xmlNode *output = NULL;

    if (!options.force) {
        if (reset) {
            const char *reason = "The reset command overwrites the active "
                                 "shadow configuration";

            exit_code = CRM_EX_USAGE;
            set_danger_error(reason, true, true, error);
            goto done;
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
    shadow_setup(out, false, error);

done:
    free(filename);
    pcmk__xml_free(output);
}

/*!
 * \internal
 * \brief Delete the shadow file
 *
 * \param[in,out] out  Output object
 * \param[out]    error  Where to store error
 */
static void
delete_shadow_file(pcmk__output_t *out, GError **error)
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
    } else {
        shadow_teardown(out);
    }
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
 * \param[in,out] out    Output object
 * \param[out]    error  Where to store error
 */
static void
show_shadow_contents(pcmk__output_t *out, GError **error)
{
    char *filename = NULL;

    if (get_instance_from_env(error) != pcmk_rc_ok) {
        return;
    }

    filename = get_shadow_file(options.instance);

    if (check_file_exists(filename, true, error) == pcmk_rc_ok) {
        xmlNode *output = NULL;
        bool quiet_orig = out->quiet;

        if (read_xml(filename, &output, error) != pcmk_rc_ok) {
            goto done;
        }

        out->quiet = true;
        out->message(out, "shadow",
                     options.instance, NULL, output, NULL, shadow_disp_content);
        out->quiet = quiet_orig;

        pcmk__xml_free(output);
    }

done:
    free(filename);
}

/*!
 * \internal
 * \brief Show the changes in the active shadow instance
 *
 * \param[in,out] out    Output object
 * \param[out]    error  Where to store error
 */
static void
show_shadow_diff(pcmk__output_t *out, GError **error)
{
    char *filename = NULL;
    xmlNodePtr old_config = NULL;
    xmlNodePtr new_config = NULL;
    xmlNodePtr diff = NULL;
    bool quiet_orig = out->quiet;

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
    pcmk__xml_mark_changes(old_config, new_config);
    diff = xml_create_patchset(0, old_config, new_config, NULL, false);

    pcmk__log_xml_changes(LOG_INFO, new_config);
    pcmk__xml_commit_changes(new_config->doc);

    out->quiet = true;
    out->message(out, "shadow",
                 options.instance, NULL, NULL, diff, shadow_disp_diff);
    out->quiet = quiet_orig;

    if (diff != NULL) {
        /* @COMPAT: Exit with CRM_EX_DIGEST? This is not really an error; we
         * just want to indicate that there are differences (as the diff command
         * does).
         */
        exit_code = CRM_EX_ERROR;
    }

done:
    free(filename);
    pcmk__xml_free(old_config);
    pcmk__xml_free(new_config);
    pcmk__xml_free(diff);
}

/*!
 * \internal
 * \brief Show the absolute path of the active shadow instance
 *
 * \param[in,out] out    Output object
 * \param[out]    error  Where to store error
 */
static void
show_shadow_filename(pcmk__output_t *out, GError **error)
{
    if (get_instance_from_env(error) == pcmk_rc_ok) {
        char *filename = get_shadow_file(options.instance);
        bool quiet_orig = out->quiet;

        out->quiet = true;
        out->message(out, "shadow",
                     options.instance, filename, NULL, NULL, shadow_disp_file);
        out->quiet = quiet_orig;

        free(filename);
    }
}

/*!
 * \internal
 * \brief Show the active shadow instance
 *
 * \param[in,out] out    Output object
 * \param[out]    error  Where to store error
 */
static void
show_shadow_instance(pcmk__output_t *out, GError **error)
{
    if (get_instance_from_env(error) == pcmk_rc_ok) {
        bool quiet_orig = out->quiet;

        out->quiet = true;
        out->message(out, "shadow",
                     options.instance, NULL, NULL, NULL, shadow_disp_instance);
        out->quiet = quiet_orig;
    }
}

/*!
 * \internal
 * \brief Switch to the given shadow instance
 *
 * \param[in,out] out    Output object
 * \param[out]    error  Where to store error
 */
static void
switch_shadow_instance(pcmk__output_t *out, GError **error)
{
    char *filename = NULL;

    filename = get_shadow_file(options.instance);
    if (check_file_exists(filename, true, error) == pcmk_rc_ok) {
        shadow_setup(out, true, error);
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
      "name. Required: --force." },

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
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
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

    context = pcmk__build_arg_context(args, "text (default), xml", group,
                                      "<query>|<command>");
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
    int rc = pcmk_rc_ok;
    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "CDcersv");
    GOptionContext *context = build_arg_context(args, &output_group);

    crm_log_preinit(NULL, argc, argv);

    pcmk__register_formats(output_group, formats);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
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
        out->version(out);
        goto done;
    }

    pcmk__register_messages(out, fmt_functions);

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

    // Run the command
    switch (options.cmd) {
        case shadow_cmd_commit:
            commit_shadow_file(&error);
            break;
        case shadow_cmd_create:
            create_shadow_from_cib(out, false, &error);
            break;
        case shadow_cmd_create_empty:
            create_shadow_empty(out, &error);
            break;
        case shadow_cmd_reset:
            create_shadow_from_cib(out, true, &error);
            break;
        case shadow_cmd_delete:
            delete_shadow_file(out, &error);
            break;
        case shadow_cmd_diff:
            show_shadow_diff(out, &error);
            break;
        case shadow_cmd_display:
            show_shadow_contents(out, &error);
            break;
        case shadow_cmd_edit:
            edit_shadow_file(&error);
            break;
        case shadow_cmd_file:
            show_shadow_filename(out, &error);
            break;
        case shadow_cmd_switch:
            switch_shadow_instance(out, &error);
            break;
        case shadow_cmd_which:
            show_shadow_instance(out, &error);
            break;
        default:
            // Should never reach this point
            break;
    }

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    pcmk__output_and_clear_error(&error, out);

    free(options.instance);
    g_free(options.validate_with);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

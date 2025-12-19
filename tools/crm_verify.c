/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>

#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <glib.h>

#include <crm/common/xml.h>
#include <crm/common/util.h>
#include <crm/cib.h>
#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

const char *SUMMARY = "Check a Pacemaker configuration for errors\n\n"
                      "Check the well-formedness of a complete Pacemaker XML configuration,\n"
                      "its conformance to the configured schema, and the presence of common\n"
                      "misconfigurations. Problems reported as errors must be fixed before the\n"
                      "cluster will work properly. It is left to the administrator to decide\n"
                      "whether to fix problems reported as warnings.";

struct {
    char *cib_save;
    gboolean use_live_cib;
    char *xml_file;
    gboolean xml_stdin;
    char *xml_string;
    unsigned int verbosity;
} options;

static GOptionEntry data_entries[] = {
    { "live-check", 'L', 0, G_OPTION_ARG_NONE,
      &options.use_live_cib, "Check the configuration used by the running cluster",
      NULL },
    { "xml-file", 'x', 0, G_OPTION_ARG_FILENAME,
      &options.xml_file, "Check the configuration in the named file",
      "FILE" },
    { "xml-pipe", 'p', 0, G_OPTION_ARG_NONE,
      &options.xml_stdin, "Check the configuration piped in via stdin",
      NULL },
    { "xml-text", 'X', 0, G_OPTION_ARG_STRING,
      &options.xml_string, "Check the configuration in the supplied string",
      "XML" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "save-xml", 'S', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME,
      &options.cib_save, "Save verified XML to named file (most useful with -L)",
      "FILE" },

    { NULL }
};

static pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group) {
    GOptionContext *context = NULL;

    const char *description = "Examples:\n\n"
                              "Check the consistency of the configuration in the running cluster:\n\n"
                              "\tcrm_verify --live-check\n\n"
                              "Check the consistency of the configuration in a given file and "
                              "produce quiet output:\n\n"
                              "\tcrm_verify --xml-file file.xml --quiet\n\n"
                              "Check the consistency of the configuration in a given file and "
                              "produce verbose output:\n\n"
                              "\tcrm_verify --xml-file file.xml --verbose\n\n";

    GOptionEntry extra_prog_entries[] = {
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(args->quiet),
          "Don't print verify information",
          NULL },
        { NULL }
    };

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);

    pcmk__add_main_args(context, extra_prog_entries);

    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "data", "Data sources:",
                        "Show data options", data_entries);
    pcmk__add_arg_group(context, "additional", "Additional options:",
                        "Show additional options", addl_entries);

    return context;
}

/*!
 * \internal
 * \brief Output a configuration error
 *
 * \param[in] ctx  Output object
 * \param[in] msg  printf(3)-style format string
 * \param[in] ...  Format string arguments
 */
G_GNUC_PRINTF(2, 3)
static void
output_config_error(void *ctx, const char *msg, ...)
{
    va_list ap;
    char *buf = NULL;
    pcmk__output_t *out = ctx;

    va_start(ap, msg);
    pcmk__assert(vasprintf(&buf, msg, ap) > 0);
    if (options.verbosity > 0) {
        out->err(out, "error: %s", buf);
    }
    va_end(ap);
}

/*!
 * \internal
 * \brief Output a configuration warning
 *
 * \param[in] ctx  Output object
 * \param[in] msg  printf(3)-style format string
 * \param[in] ...  Format string arguments
 */
G_GNUC_PRINTF(2, 3)
static void
output_config_warning(void *ctx, const char *msg, ...)
{
    va_list ap;
    char *buf = NULL;
    pcmk__output_t *out = ctx;

    va_start(ap, msg);
    pcmk__assert(vasprintf(&buf, msg, ap) > 0);
    if (options.verbosity > 0) {
        out->err(out, "warning: %s", buf);
    }
    va_end(ap);
}

int
main(int argc, char **argv)
{

    pcmk_scheduler_t *scheduler = NULL;

    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    GError *error = NULL;

    pcmk__output_t *out = NULL;

    const char *cib_source = NULL;
    xmlNode *cib_object = NULL;

    GOptionGroup *output_group = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "xSX");
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (args->verbosity > 0) {
        args->verbosity -= args->quiet;
    }

    pcmk__cli_init_logging("crm_verify", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest,
                          (const char *const *) argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out);
        goto done;
    }

    pcmk__register_lib_messages(out);

    pcmk__set_config_error_handler(output_config_error, out);
    pcmk__set_config_warning_handler(output_config_warning, out);

    if (pcmk__str_eq(args->output_ty, "xml", pcmk__str_none)) {
        args->verbosity = 1;
    }
    options.verbosity = args->verbosity;

    if (options.xml_file != NULL) {
        cib_source = options.xml_file;
    } else if (options.xml_string != NULL) {
        cib_source = options.xml_string;
    } else if (options.xml_stdin) {
        cib_source = "-";
    } else if (options.use_live_cib) {
        cib_source = NULL;
    } else {
        rc = ENODATA;
        g_set_error(&error, PCMK__RC_ERROR, rc, "No input specified");
        goto done;
    }

    rc = pcmk__parse_cib(out, cib_source, &cib_object);
    if (rc != pcmk_rc_ok) {
        g_set_error(&error, PCMK__RC_ERROR, rc, "Verification failed: %s",
                    pcmk_rc_str(rc));
        goto done;
    }

    if (options.cib_save != NULL) {
        pcmk__xml_write_file(cib_object, options.cib_save, false);
    }

    scheduler = pcmk_new_scheduler();
    if (scheduler == NULL) {
        rc = errno;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "Could not allocate scheduler data: %s", pcmk_rc_str(rc));
        goto done;
    }

    scheduler->priv->out = out;

    rc = pcmk__verify(scheduler, out, &cib_object);

    if ((rc == pcmk_rc_schema_validation) && !args->quiet) {
        const char *failure_type = "";
        const char *verbose_hint = "";

        if (pcmk__config_has_error) {
            failure_type = "invalid";
        } else if (pcmk__config_has_warning) {
            failure_type = "may need attention";
        }
        if (options.verbosity == 0) {
            verbose_hint = " (-V may provide more detail)";
        }
        out->err(out, "Configuration %s%s", failure_type, verbose_hint);
    }

    pcmk_free_scheduler(scheduler);

  done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    free(options.cib_save);
    free(options.xml_file);
    free(options.xml_string);

    if (cib_object != NULL) {
        pcmk__xml_free(cib_object);
    }

    if (exit_code == CRM_EX_OK) {
        exit_code = pcmk_rc2exitc(rc);
    }

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

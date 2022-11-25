/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>

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
#include <crm/msg_xml.h>
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
                              "produce verbose output:\n\n"
                              "\tcrm_verify --xml-file file.xml --verbose\n\n";

    context = pcmk__build_arg_context(args, "text (default), xml", group, NULL);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "data", "Data sources:",
                        "Show data options", data_entries);
    pcmk__add_arg_group(context, "additional", "Additional options:",
                        "Show additional options", addl_entries);

    return context;
}

int
main(int argc, char **argv)
{
    xmlNode *cib_object = NULL;
    xmlNode *status = NULL;

    pe_working_set_t *data_set = NULL;
    const char *xml_tag = NULL;

    int rc = pcmk_rc_ok;
    crm_exit_t exit_code = CRM_EX_OK;

    GError *error = NULL;

    pcmk__output_t *out = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "xSX");
    GOptionContext *context = build_arg_context(args, &output_group);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_verify", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code, "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    pcmk__register_lib_messages(out);

    crm_info("=#=#=#=#= Getting XML =#=#=#=#=");

    if (options.use_live_cib) {
        crm_info("Reading XML from: live cluster");
        rc = cib__signon_query(out, NULL, &cib_object);

        if (rc != pcmk_rc_ok) {
            // cib__signon_query() outputs any relevant error
            goto done;
        }

    } else if (options.xml_file != NULL) {
        cib_object = filename2xml(options.xml_file);
        if (cib_object == NULL) {
            rc = ENODATA;
            g_set_error(&error, PCMK__RC_ERROR, rc, "Couldn't parse input file: %s", options.xml_file);
            goto done;
        }

    } else if (options.xml_string != NULL) {
        cib_object = string2xml(options.xml_string);
        if (cib_object == NULL) {
            rc = ENODATA;
            g_set_error(&error, PCMK__RC_ERROR, rc, "Couldn't parse input string: %s", options.xml_string);
            goto done;
        }
    } else if (options.xml_stdin) {
        cib_object = stdin2xml();
        if (cib_object == NULL) {
            rc = ENODATA;
            g_set_error(&error, PCMK__RC_ERROR, rc, "Couldn't parse input from STDIN.");
            goto done;
        }

    } else {
        rc = ENODATA;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "No configuration source specified.  Use --help for usage information.");
        goto done;
    }

    xml_tag = crm_element_name(cib_object);
    if (!pcmk__str_eq(xml_tag, XML_TAG_CIB, pcmk__str_casei)) {
        rc = EBADMSG;
        g_set_error(&error, PCMK__RC_ERROR, rc,
                    "This tool can only check complete configurations (i.e. those starting with <cib>).");
        goto done;
    }

    if (options.cib_save != NULL) {
        write_xml_file(cib_object, options.cib_save, FALSE);
    }

    status = pcmk_find_cib_element(cib_object, XML_CIB_TAG_STATUS);
    if (status == NULL) {
        create_xml_node(cib_object, XML_CIB_TAG_STATUS);
    }

    if (validate_xml(cib_object, NULL, FALSE) == FALSE) {
        pcmk__config_err("CIB did not pass schema validation");
        free_xml(cib_object);
        cib_object = NULL;

    } else if (cli_config_update(&cib_object, NULL, FALSE) == FALSE) {
        crm_config_error = TRUE;
        free_xml(cib_object);
        cib_object = NULL;
        out->err(out, "The cluster will NOT be able to use this configuration.\n"
                 "Please manually update the configuration to conform to the %s syntax.",
                 xml_latest_schema());
    }

    data_set = pe_new_working_set();
    if (data_set == NULL) {
        rc = errno;
        crm_perror(LOG_CRIT, "Unable to allocate working set");
        goto done;
    }
    data_set->priv = out;

    /* Process the configuration to set crm_config_error/crm_config_warning.
     *
     * @TODO Some parts of the configuration are unpacked only when needed (for
     * example, action configuration), so we aren't necessarily checking those.
     */
    if (cib_object != NULL) {
        unsigned long long flags = pe_flag_no_counts|pe_flag_no_compat;

        if ((status == NULL) && !options.use_live_cib) {
            // No status available, so do minimal checks
            flags |= pe_flag_check_config;
        }
        pcmk__schedule_actions(cib_object, flags, data_set);
    }
    pe_free_working_set(data_set);

    if (crm_config_error) {
        rc = pcmk_rc_schema_validation;

        if (args->verbosity > 0) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Errors found during check: config not valid");
        } else {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Errors found during check: config not valid\n-V may provide more details");
        }

    } else if (crm_config_warning) {
        rc = pcmk_rc_schema_validation;

        if (args->verbosity > 0) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Warnings found during check: config may not be valid");
        } else {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Warnings found during check: config may not be valid\n-V may provide more details");
        }
    }

  done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    free(options.cib_save);
    free(options.xml_file);
    free(options.xml_string);

    if (exit_code == CRM_EX_OK) {
        exit_code = pcmk_rc2exitc(rc);
    }

    pcmk__output_and_clear_error(error, NULL);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

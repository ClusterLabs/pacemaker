/*
 * Copyright 2005-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>        // bool
#include <stdio.h>          // NULL, printf(), etc.
#include <stdlib.h>         // free()

#include <glib.h>           // GOption, etc.
#include <libxml/tree.h>    // xmlNode

#include <crm/common/xml.h> // xml_{create,apply}_patchset()

#define SUMMARY "Compare two Pacemaker configurations (in XML format) to "    \
                "produce a custom diff-like output, or apply such an output " \
                "as a patch"
#define INDENT "                                   "

struct {
    gchar *source_file;
    gchar *target_file;
    gchar *source_string;
    gchar *target_string;
    bool patch;
    gboolean as_cib;
    gboolean no_version;
    gboolean use_stdin;
} options;

static gboolean
patch_cb(const gchar *option_name, const gchar *optarg, gpointer data,
         GError **error)
{
    options.patch = true;
    g_free(options.target_file);
    options.target_file = g_strdup(optarg);
    return TRUE;
}

// @COMPAT Use last-one-wins for original/new/patch input sources
static GOptionEntry original_xml_entries[] = {
    { "original", 'o', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING,
          &options.source_file,
      "XML is contained in the named file. Currently --original-string and\n"
      INDENT "--stdin both override this. In a future release, the last one\n"
      INDENT "specified will be used.",
      "FILE" },
    { "original-string", 'O', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          &options.source_string,
      "XML is contained in the supplied string. Currently this takes\n"
      INDENT "precedence over both --stdin and --original. In a future\n"
      INDENT "release, the last one specified will be used.",
      "STRING" },

    { NULL }
};

static GOptionEntry operation_entries[] = {
    { "new", 'n', G_OPTION_FLAG_NONE, G_OPTION_ARG_STRING, &options.target_file,
      "Compare the original XML to the contents of the named file. Currently\n"
      INDENT "--new-string and --stdin both override this. In a future\n"
      INDENT "release, the last one specified will be used.",
      "FILE" },
    { "new-string", 'N', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK,
          &options.target_string,
      "Compare the original XML with the contents of the supplied string.\n"
      INDENT "Currently this takes precedence over --stdin, --patch, and\n"
      INDENT "--new. In a future release, the last one specified will be used.",
      "STRING" },
    { "patch", 'p', G_OPTION_FLAG_NONE, G_OPTION_ARG_CALLBACK, patch_cb,
      "Patch the original XML with the contents of the named file. Currently\n"
      INDENT "--new-string, --stdin, and (if specified later) --new override\n"
      INDENT "the input source specified here. In a future release, the last\n"
      INDENT "one specified will be used. Note: even if this input source is\n"
      INDENT "overridden, the input source will be applied as a patch to the\n"
      INDENT "original XML.",
      "FILE" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "cib", 'c', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.as_cib,
      "Compare/patch the inputs as a CIB (includes version details)",
      NULL },
    { "stdin", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &options.use_stdin,
      "Get the original XML and new (or patch) XML from stdin. Currently\n"
      INDENT "--original-string and --new-string override this for original\n"
      INDENT "and new/patch XML, respectively. In a future release, the last\n"
      INDENT "one specified will be used.",
      NULL },
    { "no-version", 'u', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE,
          &options.no_version,
      "Generate the difference without version details",
      NULL },

    { NULL }
};

/*!
 * \internal
 * \brief Print an XML tree serialized to text
 *
 * \param[in] xml  XML tree to print
 *
 * \todo Use pcmk__output_t with message functions and drop this.
 *
 * \note This is basically a simplified version of \c pcmk__xml_write_fd(), but
 *       that function closes the stream before returning. We could modify it in
 *       the future. But we don't want to close stdout.
 */
static void
print_xml(const xmlNode *xml)
{
    GString *buffer = g_string_sized_new(1024);

    pcmk__xml_string(xml, pcmk__xml_fmt_pretty, buffer, 0);

    printf("%s", buffer->str);
    g_string_free(buffer, TRUE);
    fflush(stdout);
}

/*!
 * \internal
 * \brief Create an XML patchset from the given source and target XML trees
 *
 * \param[in,out] source      Source XML
 * \param[in,out] target      Target XML
 * \param[in]     as_cib      If \c true, treat the XML trees as CIBs. In
 *                            particular, ignore attribute position changes,
 *                            include the target digest in the patchset, and log
 *                            the source and target CIB versions.
 * \param[in]     no_version  If \c true, ignore changes to the CIB version
 *                            (must be \c false if \p as_cib is \c true)
 *
 * \return Standard Pacemaker return code
 */
static int
generate_patch(xmlNode *source, xmlNode *target, bool as_cib, bool no_version)
{
    static const char *const vfields[] = {
        PCMK_XA_ADMIN_EPOCH,
        PCMK_XA_EPOCH,
        PCMK_XA_NUM_UPDATES,
    };

    xmlNode *patchset = NULL;

    // Currently impossibly; just a reminder for when we move to libpacemaker
    pcmk__assert(!as_cib || !no_version);

    /* If we're ignoring the version, make the version information identical, so
     * it isn't detected as a change.
     */
    if (no_version) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            crm_xml_add(target, vfields[i],
                        crm_element_value(source, vfields[i]));
        }
    }

    if (as_cib) {
        pcmk__xml_doc_set_flags(target->doc, pcmk__xf_ignore_attr_pos);
    }
    pcmk__xml_mark_changes(source, target);
    crm_log_xml_debug(target, "target");

    patchset = xml_create_patchset(0, source, target, NULL, false);

    pcmk__log_xml_changes(LOG_INFO, target);
    pcmk__xml_commit_changes(target->doc);

    if (patchset == NULL) {
        return pcmk_rc_ok;  // No changes
    }

    if (as_cib) {
        pcmk__xml_patchset_add_digest(patchset, target);

    } else if (no_version) {
        pcmk__xml_free(pcmk__xe_first_child(patchset, PCMK_XE_VERSION, NULL,
                                            NULL));
    }

    pcmk__log_xml_patchset(LOG_NOTICE, patchset);
    print_xml(patchset);
    pcmk__xml_free(patchset);

    /* pcmk_rc_error means there's a non-empty diff.
     * @COMPAT Choose a more descriptive return code, like one that maps to
     * CRM_EX_DIGEST?
     */
    return pcmk_rc_error;
}

static const pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,

    { NULL, NULL, NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args) {
    GOptionContext *context = NULL;

    const char *description = "Examples:\n\n"
                              "Obtain the two different configuration files by running cibadmin on the two cluster setups to compare:\n\n"
                              "\t# cibadmin --query > cib-old.xml\n\n"
                              "\t# cibadmin --query > cib-new.xml\n\n"
                              "Calculate and save the difference between the two files:\n\n"
                              "\t# crm_diff --original cib-old.xml --new cib-new.xml > patch.xml\n\n"
                              "Apply the patch to the original file:\n\n"
                              "\t# crm_diff --original cib-old.xml --patch patch.xml > updated.xml\n\n"
                              "Apply the patch to the running cluster:\n\n"
                              "\t# cibadmin --patch -x patch.xml\n";

    context = pcmk__build_arg_context(args, NULL, NULL, NULL);
    g_option_context_set_description(context, description);

    pcmk__add_arg_group(context, "xml", "Original XML:",
                        "Show original XML options", original_xml_entries);
    pcmk__add_arg_group(context, "operation", "Operation:",
                        "Show operation options", operation_entries);
    pcmk__add_arg_group(context, "additional", "Additional Options:",
                        "Show additional options", addl_entries);
    return context;
}

int
main(int argc, char **argv)
{
    crm_exit_t exit_code = CRM_EX_OK;
    int rc = pcmk_rc_ok;

    xmlNode *source = NULL;
    xmlNode *target = NULL;

    pcmk__output_t *out = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "nopNO");
    GOptionContext *context = build_arg_context(args);

    pcmk__register_formats(output_group, formats);

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_diff", args->verbosity);

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s", args->output_ty,
                    pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if (options.no_version) {
        if (options.as_cib) {
            exit_code = CRM_EX_USAGE;
            g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                        "-u/--no-version incompatible with -c/--cib");
            goto done;
        }
        if (options.patch) {
            out->err(out, "Warning: -u/--no-version ignored with -p/--patch");
        }
    }

    if (options.source_string != NULL) {
        source = pcmk__xml_parse(options.source_string);

    } else if (options.use_stdin) {
        source = pcmk__xml_read(NULL);

    } else if (options.source_file != NULL) {
        source = pcmk__xml_read(options.source_file);

    } else {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Either --original, --original-string, or --stdin must be "
                    "specified");
        goto done;
    }

    if (options.target_string != NULL) {
        target = pcmk__xml_parse(options.target_string);

    } else if (options.use_stdin) {
        target = pcmk__xml_read(NULL);

    } else if (options.target_file != NULL) {
        target = pcmk__xml_read(options.target_file);

    } else {
        exit_code = CRM_EX_USAGE;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Either --new, --new-string, --patch, or --stdin must be "
                    "specified");
        goto done;
    }

    if (source == NULL) {
        exit_code = CRM_EX_DATAERR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Failed to parse original XML");
        goto done;
    }
    if (target == NULL) {
        exit_code = CRM_EX_DATAERR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Failed to parse %s XML", (options.patch? "patch" : "new"));
        goto done;
    }

    if (options.patch) {
        rc = xml_apply_patchset(source, target, options.as_cib);
        rc = pcmk_legacy2rc(rc);
        if (rc != pcmk_rc_ok) {
            g_set_error(&error, PCMK__RC_ERROR, rc,
                        "Could not apply patch: %s", pcmk_rc_str(rc));
        } else {
            print_xml(source);
        }

    } else {
        rc = generate_patch(source, target, options.as_cib, options.no_version);
    }
    exit_code = pcmk_rc2exitc(rc);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_free(options.source_file);
    g_free(options.target_file);
    g_free(options.source_string);
    g_free(options.target_string);
    pcmk__xml_free(source);
    pcmk__xml_free(target);

    pcmk__output_and_clear_error(&error, out);

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }
    crm_exit(exit_code);
}

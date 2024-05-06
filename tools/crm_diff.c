/*
 * Copyright 2005-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/types.h>

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/output_internal.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/cib.h>

#define SUMMARY "Compare two Pacemaker configurations (in XML format) to "    \
                "produce a custom diff-like output, or apply such an output " \
                "as a patch"
#define INDENT "                                   "

static const char *const vfields[] = {
    PCMK_XA_ADMIN_EPOCH,
    PCMK_XA_EPOCH,
    PCMK_XA_NUM_UPDATES,
};

static struct {
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

static void
print_patch(xmlNode *patch)
{
    GString *buffer = g_string_sized_new(1024);

    pcmk__xml_string(patch, pcmk__xml_fmt_pretty, buffer, 0);

    printf("%s", buffer->str);
    g_string_free(buffer, TRUE);
    fflush(stdout);
}

// \return Standard Pacemaker return code
static int
apply_patch(xmlNode *input, xmlNode *patch, gboolean as_cib)
{
    xmlNode *output = pcmk__xml_copy(NULL, input);
    int rc = xml_apply_patchset(output, patch, as_cib);

    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Could not apply patch: %s\n", pcmk_rc_str(rc));
        pcmk__xml_free(output);
        return rc;
    }

    if (output != NULL) {
        const char *version;
        char *buffer;

        print_patch(output);

        version = crm_element_value(output, PCMK_XA_CRM_FEATURE_SET);
        buffer = pcmk__digest_xml(output, true, version);
        crm_trace("Digest: %s", pcmk__s(buffer, "<null>\n"));
        free(buffer);
        pcmk__xml_free(output);
    }
    return pcmk_rc_ok;
}

static void
log_patch_cib_versions(xmlNode *patch)
{
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };

    const char *fmt = NULL;
    const char *digest = NULL;

    pcmk__xml_patchset_versions(patch, del, add);
    fmt = crm_element_value(patch, PCMK_XA_FORMAT);
    digest = crm_element_value(patch, PCMK__XA_DIGEST);

    if (add[2] != del[2] || add[1] != del[1] || add[0] != del[0]) {
        crm_info("Patch: --- %d.%d.%d %s", del[0], del[1], del[2], fmt);
        crm_info("Patch: +++ %d.%d.%d %s", add[0], add[1], add[2], digest);
    }
}

/*!
 * \internal
 * \brief Remove CIB version details from an XML patchset
 *
 * \param[in,out] patchset  XML patchset
 */
static void
strip_patchset_cib_versions(xmlNode *patchset)
{
    int format = 1;

    crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);
    if (format == 2) {
        pcmk__xml_free(pcmk__xe_first_child(patchset, PCMK_XE_VERSION, NULL,
                                            NULL));

    } else {
        static const char *const tags[] = {
            PCMK__XE_DIFF_REMOVED,
            PCMK__XE_DIFF_ADDED,
        };

        for (int i = 0; i < PCMK__NELEM(tags); i++) {
            xmlNode *tmp = pcmk__xe_first_child(patchset, tags[i], NULL, NULL);

            if (tmp == NULL) {
                continue;
            }
            for (int j = 0; j < PCMK__NELEM(vfields); j++) {
                pcmk__xe_remove_attr(tmp, vfields[j]);
            }

            tmp = pcmk__xe_first_child(tmp, PCMK_XE_CIB, NULL, NULL);
            if (tmp == NULL) {
                continue;
            }
            for (int j = 0; j < PCMK__NELEM(vfields); j++) {
                pcmk__xe_remove_attr(tmp, vfields[j]);
            }
        }
    }
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
 *
 * \return Standard Pacemaker return code
 */
static int
generate_patchset(xmlNode *source, xmlNode *target, bool as_cib,
                  bool no_version)
{
    int format = 1;
    xmlNode *patchset = NULL;

    /* If we're ignoring the version, make the version information identical,
     * so it isn't detected as a change
     */
    if (no_version) {
        for (int i = 0; i < PCMK__NELEM(vfields); i++) {
            crm_xml_add(target, vfields[i],
                        crm_element_value(source, vfields[i]));
        }
    }

    pcmk__xml_mark_changes(source, target, as_cib);
    crm_log_xml_debug(target, "target");

    patchset = xml_create_patchset(0, source, target, NULL, false);

    pcmk__log_xml_changes(LOG_INFO, target);
    pcmk__xml_accept_changes(target->doc);

    if (patchset == NULL) {
        return pcmk_rc_ok;  // No changes
    }

    crm_element_value_int(patchset, PCMK_XA_FORMAT, &format);
    if (as_cib || (format == 1)) {
        pcmk__xml_patchset_add_digest(patchset, source, target);
    }

    if (as_cib) {
        /* @TODO Will incorrectly be logged as the same in source and target
         * if no_version is true. Probably not ideal. Ignoring version isn't the
         * same as reporting an incorrect target version.
         */
        log_patch_cib_versions(patchset);

    } else if (no_version) {
        strip_patchset_cib_versions(patchset);
    }

    pcmk__log_xml_patchset(LOG_NOTICE, patchset);
    print_patch(patchset);
    pcmk__xml_free(patchset);

    /* pcmk_rc_error means there's a non-empty diff.
     * @COMPAT Choose a more descriptive return code, like one that maps to
     * CRM_EX_DIGEST?
     */
    return pcmk_rc_error;
}

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
    xmlNode *source = NULL;
    xmlNode *target = NULL;

    crm_exit_t exit_code = CRM_EX_OK;
    GError *error = NULL;

    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "nopNO");
    GOptionContext *context = build_arg_context(args);

    int rc = pcmk_rc_ok;

    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    pcmk__cli_init_logging("crm_diff", args->verbosity);

    if (args->version) {
        g_strfreev(processed_args);
        pcmk__free_arg_context(context);
        /* FIXME:  When crm_diff is converted to use formatted output, this can go. */
        pcmk__cli_help('v');
    }

    if (options.patch && options.no_version) {
        fprintf(stderr, "warning: -u/--no-version ignored with -p/--patch\n");
    } else if (options.as_cib && options.no_version) {
        fprintf(stderr, "error: -u/--no-version incompatible with -c/--cib\n");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.source_string != NULL) {
        source = pcmk__xml_parse(options.source_string);

    } else if (options.use_stdin) {
        fprintf(stderr, "Input first XML fragment:");
        source = pcmk__xml_read(NULL);

    } else if (options.source_file != NULL) {
        source = pcmk__xml_read(options.source_file);
    }

    if (options.target_string) {
        target = pcmk__xml_parse(options.target_string);

    } else if (options.use_stdin) {
        fprintf(stderr, "Input second XML fragment:");
        target = pcmk__xml_read(NULL);

    } else if (options.target_file != NULL) {
        target = pcmk__xml_read(options.target_file);
    }

    if (source == NULL) {
        fprintf(stderr, "Could not parse the first XML fragment\n");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }
    if (target == NULL) {
        fprintf(stderr, "Could not parse the second XML fragment\n");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    if (options.patch) {
        rc = apply_patch(source, target, options.as_cib);
    } else {
        rc = generate_patchset(source, target, options.as_cib,
                               options.no_version);
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

    pcmk__output_and_clear_error(&error, NULL);
    crm_exit(exit_code);
}

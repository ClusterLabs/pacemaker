/*
 * Copyright 2005-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

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

#define SUMMARY "Compare two Pacemaker configurations (in XML format) to produce a custom diff-like output, " \
                "or apply such an output as a patch"

struct {
    gboolean apply;
    gboolean as_cib;
    gboolean no_version;
    gboolean raw_original;
    gboolean raw_new;
    gboolean use_stdin;
    char *xml_file_original;
    char *xml_file_new;
} options;

gboolean new_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean original_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean patch_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry original_xml_entries[] = {
    { "original", 'o', 0, G_OPTION_ARG_STRING, &options.xml_file_original,
      "XML is contained in the named file",
      "FILE" },
    { "original-string", 'O', 0, G_OPTION_ARG_CALLBACK, original_string_cb,
      "XML is contained in the supplied string",
      "STRING" },

    { NULL }
};

static GOptionEntry operation_entries[] = {
    { "new", 'n', 0, G_OPTION_ARG_STRING, &options.xml_file_new,
      "Compare the original XML to the contents of the named file",
      "FILE" },
    { "new-string", 'N', 0, G_OPTION_ARG_CALLBACK, new_string_cb,
      "Compare the original XML with the contents of the supplied string",
      "STRING" },
    { "patch", 'p', 0, G_OPTION_ARG_CALLBACK, patch_cb,
      "Patch the original XML with the contents of the named file",
      "FILE" },

    { NULL }
};

static GOptionEntry addl_entries[] = {
    { "cib", 'c', 0, G_OPTION_ARG_NONE, &options.as_cib,
      "Compare/patch the inputs as a CIB (includes versions details)",
      NULL },
    { "stdin", 's', 0, G_OPTION_ARG_NONE, &options.use_stdin,
      "",
      NULL },
    { "no-version", 'u', 0, G_OPTION_ARG_NONE, &options.no_version,
      "Generate the difference without versions details",
      NULL },

    { NULL }
};

gboolean
new_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.raw_new = TRUE;
    pcmk__str_update(&options.xml_file_new, optarg);
    return TRUE;
}

gboolean
original_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.raw_original = TRUE;
    pcmk__str_update(&options.xml_file_original, optarg);
    return TRUE;
}

gboolean
patch_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.apply = TRUE;
    pcmk__str_update(&options.xml_file_new, optarg);
    return TRUE;
}

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
        char *buffer;

        print_patch(output);

        buffer = pcmk__digest_xml(output, true);
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

// \return Standard Pacemaker return code
static int
generate_patch(xmlNode *object_original, xmlNode *object_new, const char *xml_file_new,
               gboolean as_cib, gboolean no_version)
{
    const char *vfields[] = {
        PCMK_XA_ADMIN_EPOCH,
        PCMK_XA_EPOCH,
        PCMK_XA_NUM_UPDATES,
    };

    xmlNode *output = NULL;

    /* If we're ignoring the version, make the version information
     * identical, so it isn't detected as a change. */
    if (no_version) {
        int lpc;

        for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
            crm_copy_xml_element(object_original, object_new, vfields[lpc]);
        }
    }

    if (as_cib) {
        pcmk__xml_doc_set_flags(object_new->doc, pcmk__xf_ignore_attr_pos);
    }
    pcmk__xml_mark_changes(object_original, object_new);
    crm_log_xml_debug(object_new, (xml_file_new? xml_file_new: "target"));

    output = xml_create_patchset(0, object_original, object_new, NULL, FALSE);

    pcmk__log_xml_changes(LOG_INFO, object_new);
    pcmk__xml_commit_changes(object_new->doc);

    if (output == NULL) {
        return pcmk_rc_ok;  // No changes
    }

    patchset_process_digest(output, object_original, object_new, as_cib);

    if (as_cib) {
        log_patch_cib_versions(output);

    } else if (no_version) {
        pcmk__xml_free(pcmk__xe_first_child(output, PCMK_XE_VERSION, NULL,
                                            NULL));
    }

    pcmk__log_xml_patchset(LOG_NOTICE, output);
    print_patch(output);
    pcmk__xml_free(output);

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
    xmlNode *object_original = NULL;
    xmlNode *object_new = NULL;

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

    if (options.apply && options.no_version) {
        fprintf(stderr, "warning: -u/--no-version ignored with -p/--patch\n");
    } else if (options.as_cib && options.no_version) {
        fprintf(stderr, "error: -u/--no-version incompatible with -c/--cib\n");
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    if (options.raw_original) {
        object_original = pcmk__xml_parse(options.xml_file_original);

    } else if (options.use_stdin) {
        fprintf(stderr, "Input first XML fragment:");
        object_original = pcmk__xml_read(NULL);

    } else if (options.xml_file_original != NULL) {
        object_original = pcmk__xml_read(options.xml_file_original);
    }

    if (options.raw_new) {
        object_new = pcmk__xml_parse(options.xml_file_new);

    } else if (options.use_stdin) {
        fprintf(stderr, "Input second XML fragment:");
        object_new = pcmk__xml_read(NULL);

    } else if (options.xml_file_new != NULL) {
        object_new = pcmk__xml_read(options.xml_file_new);
    }

    if (object_original == NULL) {
        fprintf(stderr, "Could not parse the first XML fragment\n");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }
    if (object_new == NULL) {
        fprintf(stderr, "Could not parse the second XML fragment\n");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    if (options.apply) {
        rc = apply_patch(object_original, object_new, options.as_cib);
    } else {
        rc = generate_patch(object_original, object_new, options.xml_file_new, options.as_cib, options.no_version);
    }
    exit_code = pcmk_rc2exitc(rc);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    free(options.xml_file_original);
    free(options.xml_file_new);
    pcmk__xml_free(object_original);
    pcmk__xml_free(object_new);

    pcmk__output_and_clear_error(&error, NULL);
    crm_exit(exit_code);
}

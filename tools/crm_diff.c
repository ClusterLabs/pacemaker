/*
 * Copyright 2005-2022 the Pacemaker project contributors
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
#include <crm/msg_xml.h>
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
    gboolean raw_1;
    gboolean raw_2;
    gboolean use_stdin;
    char *xml_file_1;
    char *xml_file_2;
} options;

gboolean new_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean original_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);
gboolean patch_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error);

static GOptionEntry original_xml_entries[] = {
    { "original", 'o', 0, G_OPTION_ARG_STRING, &options.xml_file_1,
      "XML is contained in the named file",
      "FILE" },
    { "original-string", 'O', 0, G_OPTION_ARG_CALLBACK, original_string_cb,
      "XML is contained in the supplied string",
      "STRING" },

    { NULL }
};

static GOptionEntry operation_entries[] = {
    { "new", 'n', 0, G_OPTION_ARG_STRING, &options.xml_file_2,
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
    options.raw_2 = TRUE;
    pcmk__str_update(&options.xml_file_2, optarg);
    return TRUE;
}

gboolean
original_string_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.raw_1 = TRUE;
    pcmk__str_update(&options.xml_file_1, optarg);
    return TRUE;
}

gboolean
patch_cb(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    options.apply = TRUE;
    pcmk__str_update(&options.xml_file_2, optarg);
    return TRUE;
}

static void
print_patch(xmlNode *patch)
{
    char *buffer = dump_xml_formatted(patch);

    printf("%s", pcmk__s(buffer, "<null>\n"));
    free(buffer);
    fflush(stdout);
}

// \return Standard Pacemaker return code
static int
apply_patch(xmlNode *input, xmlNode *patch, gboolean as_cib)
{
    xmlNode *output = copy_xml(input);
    int rc = xml_apply_patchset(output, patch, as_cib);

    rc = pcmk_legacy2rc(rc);
    if (rc != pcmk_rc_ok) {
        fprintf(stderr, "Could not apply patch: %s\n", pcmk_rc_str(rc));
        free_xml(output);
        return rc;
    }

    if (output != NULL) {
        const char *version;
        char *buffer;

        print_patch(output);

        version = crm_element_value(output, XML_ATTR_CRM_VERSION);
        buffer = calculate_xml_versioned_digest(output, FALSE, TRUE, version);
        crm_trace("Digest: %s", pcmk__s(buffer, "<null>\n"));
        free(buffer);
        free_xml(output);
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

    xml_patch_versions(patch, add, del);
    fmt = crm_element_value(patch, "format");
    digest = crm_element_value(patch, XML_ATTR_DIGEST);

    if (add[2] != del[2] || add[1] != del[1] || add[0] != del[0]) {
        crm_info("Patch: --- %d.%d.%d %s", del[0], del[1], del[2], fmt);
        crm_info("Patch: +++ %d.%d.%d %s", add[0], add[1], add[2], digest);
    }
}

static void
strip_patch_cib_version(xmlNode *patch, const char **vfields, size_t nvfields)
{
    int format = 1;

    crm_element_value_int(patch, "format", &format);
    if (format == 2) {
        xmlNode *version_xml = find_xml_node(patch, "version", FALSE);

        if (version_xml) {
            free_xml(version_xml);
        }

    } else {
        int i = 0;

        const char *tags[] = {
            XML_TAG_DIFF_REMOVED,
            XML_TAG_DIFF_ADDED,
        };

        for (i = 0; i < PCMK__NELEM(tags); i++) {
            xmlNode *tmp = NULL;
            int lpc;

            tmp = find_xml_node(patch, tags[i], FALSE);
            if (tmp) {
                for (lpc = 0; lpc < nvfields; lpc++) {
                    xml_remove_prop(tmp, vfields[lpc]);
                }

                tmp = find_xml_node(tmp, XML_TAG_CIB, FALSE);
                if (tmp) {
                    for (lpc = 0; lpc < nvfields; lpc++) {
                        xml_remove_prop(tmp, vfields[lpc]);
                    }
                }
            }
        }
    }
}

// \return Standard Pacemaker return code
static int
generate_patch(xmlNode *object_1, xmlNode *object_2, const char *xml_file_2,
               gboolean as_cib, gboolean no_version)
{
    xmlNode *output = NULL;

    const char *vfields[] = {
        XML_ATTR_GENERATION_ADMIN,
        XML_ATTR_GENERATION,
        XML_ATTR_NUMUPDATES,
    };

    /* If we're ignoring the version, make the version information
     * identical, so it isn't detected as a change. */
    if (no_version) {
        int lpc;

        for (lpc = 0; lpc < PCMK__NELEM(vfields); lpc++) {
            crm_copy_xml_element(object_1, object_2, vfields[lpc]);
        }
    }

    xml_track_changes(object_2, NULL, object_2, FALSE);
    if(as_cib) {
        xml_calculate_significant_changes(object_1, object_2);
    } else {
        xml_calculate_changes(object_1, object_2);
    }
    crm_log_xml_debug(object_2, (xml_file_2? xml_file_2: "target"));

    output = xml_create_patchset(0, object_1, object_2, NULL, FALSE);

    xml_log_changes(LOG_INFO, __func__, object_2);
    xml_accept_changes(object_2);

    if (output == NULL) {
        return pcmk_rc_ok;
    }

    patchset_process_digest(output, object_1, object_2, as_cib);

    if (as_cib) {
        log_patch_cib_versions(output);

    } else if (no_version) {
        strip_patch_cib_version(output, vfields, PCMK__NELEM(vfields));
    }

    xml_log_patchset(LOG_NOTICE, __func__, output);
    print_patch(output);
    free_xml(output);
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
    xmlNode *object_1 = NULL;
    xmlNode *object_2 = NULL;

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

    if (options.raw_1) {
        object_1 = string2xml(options.xml_file_1);

    } else if (options.use_stdin) {
        fprintf(stderr, "Input first XML fragment:");
        object_1 = stdin2xml();

    } else if (options.xml_file_1 != NULL) {
        object_1 = filename2xml(options.xml_file_1);
    }

    if (options.raw_2) {
        object_2 = string2xml(options.xml_file_2);

    } else if (options.use_stdin) {
        fprintf(stderr, "Input second XML fragment:");
        object_2 = stdin2xml();

    } else if (options.xml_file_2 != NULL) {
        object_2 = filename2xml(options.xml_file_2);
    }

    if (object_1 == NULL) {
        fprintf(stderr, "Could not parse the first XML fragment\n");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }
    if (object_2 == NULL) {
        fprintf(stderr, "Could not parse the second XML fragment\n");
        exit_code = CRM_EX_DATAERR;
        goto done;
    }

    if (options.apply) {
        rc = apply_patch(object_1, object_2, options.as_cib);
    } else {
        rc = generate_patch(object_1, object_2, options.xml_file_2, options.as_cib, options.no_version);
    }
    exit_code = pcmk_rc2exitc(rc);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);
    free(options.xml_file_1);
    free(options.xml_file_2);
    free_xml(object_1);
    free_xml(object_2);

    pcmk__output_and_clear_error(error, NULL);
    crm_exit(exit_code);
}

/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <config.h>
#include <glib.h>

#include <crm/crm.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/util.h>

static gboolean
bump_verbosity(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    pcmk__common_args_t *common_args = (pcmk__common_args_t *) data;
    common_args->verbosity++;
    return TRUE;
}

pcmk__common_args_t *
pcmk__new_common_args(const char *summary)
{
    pcmk__common_args_t *args = NULL;

    args = calloc(1, sizeof(pcmk__common_args_t));
    if (args == NULL) {
        crm_exit(crm_errno2exit(-ENOMEM));
    }

    args->summary = strdup(summary);
    if (args->summary == NULL) {
        crm_exit(crm_errno2exit(-ENOMEM));
    }

    return args;
}

static void
free_common_args(gpointer data) {
    pcmk__common_args_t *common_args = (pcmk__common_args_t *) data;

    free(common_args->summary);
    free(common_args->output_ty);
    free(common_args->output_dest);

    if (common_args->output_as_descr != NULL) {
        free(common_args->output_as_descr);
    }

    free(common_args);
}

GOptionContext *
pcmk__build_arg_context(pcmk__common_args_t *common_args, const char *fmts,
                        GOptionGroup **output_group) {
    char *desc = crm_strdup_printf("Report bugs to %s\n", PACKAGE_BUGREPORT);
    GOptionContext *context;
    GOptionGroup *main_group;

    GOptionEntry main_entries[3] = {
        { "version", '$', 0, G_OPTION_ARG_NONE, &(common_args->version),
          "Display software version and exit",
          NULL },
        { "verbose", 'V', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, bump_verbosity,
          "Increase debug output (may be specified multiple times)",
          NULL },

        { NULL }
    };

    main_group = g_option_group_new(NULL, "Application Options:", NULL, common_args, free_common_args);
    g_option_group_add_entries(main_group, main_entries);

    context = g_option_context_new(NULL);
    g_option_context_set_summary(context, common_args->summary);
    g_option_context_set_description(context, desc);
    g_option_context_set_main_group(context, main_group);

    if (fmts != NULL) {
        GOptionEntry output_entries[3] = {
            { "output-as", 0, 0, G_OPTION_ARG_STRING, &(common_args->output_ty),
              NULL,
              "FORMAT" },
            { "output-to", 0, 0, G_OPTION_ARG_STRING, &(common_args->output_dest),
              "Specify file name for output (or \"-\" for stdout)", "DEST" },

            { NULL }
        };

        if (*output_group == NULL) {
            *output_group = g_option_group_new("output", "Output Options:", "Show output help", NULL, NULL);
        }

        common_args->output_as_descr = crm_strdup_printf("Specify output format as one of: %s", fmts);
        output_entries[0].description = common_args->output_as_descr;
        g_option_group_add_entries(*output_group, output_entries);
        g_option_context_add_group(context, *output_group);
    }

    free(desc);

    // main_group is now owned by context, we don't free it here
    // cppcheck-suppress memleak
    return context;
}

void
pcmk__free_arg_context(GOptionContext *context) {
    if (context == NULL) {
        return;
    }

    g_option_context_free(context);
}

void
pcmk__add_main_args(GOptionContext *context, GOptionEntry entries[])
{
    GOptionGroup *main_group = g_option_context_get_main_group(context);

    g_option_group_add_entries(main_group, entries);
}

void
pcmk__add_arg_group(GOptionContext *context, const char *name,
                    const char *header, const char *desc,
                    GOptionEntry entries[])
{
    GOptionGroup *group = NULL;

    group = g_option_group_new(name, header, desc, NULL, NULL);
    g_option_group_add_entries(group, entries);
    g_option_context_add_group(context, group);
    // group is now owned by context, we don't free it here
    // cppcheck-suppress memleak
}

gchar **
pcmk__cmdline_preproc(char **argv, const char *special) {
    gchar **retval = NULL;
    GPtrArray *arr = NULL;
    bool saw_dash_dash = false;

    if (argv == NULL) {
        return retval;
    }

    arr = g_ptr_array_new();

    for (int i = 0; argv[i] != NULL; i++) {
        /* If this is the first time we saw "--" in the command line, set
         * a flag so we know to just copy everything after it over.  We also
         * want to copy the "--" over so whatever actually parses the command
         * line when we're done knows where arguments end.
         */
        if (saw_dash_dash == false && strcmp(argv[i], "--") == 0) {
            saw_dash_dash = true;
        }

        if (saw_dash_dash == true) {
            g_ptr_array_add(arr, strdup(argv[i]));
            continue;
        }

        /* This is just a dash by itself.  That could indicate stdin/stdout, or
         * it could be user error.  Copy it over and let glib figure it out.
         */
        if (safe_str_eq(argv[i], "-")) {
            g_ptr_array_add(arr, strdup(argv[i]));
            continue;
        }

        /* This is a short argument, or perhaps several.  Iterate over it
         * and explode them out into individual arguments.
         */
        if (g_str_has_prefix(argv[i], "-") && !g_str_has_prefix(argv[i], "--")) {
            /* Skip over leading dash */
            char *ch = argv[i]+1;

            while (*ch != '\0') {
                /* This is a special short argument that takes an option.  getopt
                 * allows values to be interspersed with a list of arguments, but
                 * glib does not.  Grab both the argument and its value and
                 * separate them into a new argument.
                 */
                if (strchr(special, *ch) != NULL) {
                    /* The argument does not occur at the end of this string of
                     * arguments.  Take everything through the end as its value.
                     */
                    if (*(ch+1) != '\0') {
                        g_ptr_array_add(arr, (gpointer) crm_strdup_printf("-%c", *ch));
                        g_ptr_array_add(arr, strdup(ch+1));
                        break;

                    /* The argument occurs at the end of this string.  Hopefully
                     * whatever comes next in argv is its value.  It may not be,
                     * but that is not for us to decide.
                     */
                    } else {
                        g_ptr_array_add(arr, (gpointer) crm_strdup_printf("-%c", *ch));
                        ch++;
                    }

                /* This is a regular short argument.  Just copy it over. */
                } else {
                    g_ptr_array_add(arr, (gpointer) crm_strdup_printf("-%c", *ch));
                    ch++;
                }
            }

        /* This is a long argument, or an option, or something else.
         * Copy it over - everything else is copied, so this keeps it easy for
         * the caller to know what to do with the memory when it's done.
         */
        } else {
            g_ptr_array_add(arr, strdup(argv[i]));
        }
    }

    /* Convert the GPtrArray into a gchar **, which the command line parsing
     * code knows how to deal with.  Then we can free the array (but not its
     * contents).
     */
    retval = calloc(arr->len+1, sizeof(char *));
    for (int i = 0; i < arr->len; i++) {
        retval[i] = (gchar *) g_ptr_array_index(arr, i);
    }

    g_ptr_array_free(arr, FALSE);

    return retval;
}

G_GNUC_PRINTF(3, 4)
gboolean
pcmk__force_args(GOptionContext *context, GError **error, const char *format, ...) {
    int len = 0;
    char *buf = NULL;
    gchar **extra_args = NULL;
    va_list ap;
    gboolean retval = TRUE;

    va_start(ap, format);
    len = vasprintf(&buf, format, ap);
    CRM_ASSERT(len > 0);
    va_end(ap);

    if (!g_shell_parse_argv(buf, NULL, &extra_args, error)) {
        g_strfreev(extra_args);
        free(buf);
        return FALSE;
    }

    retval = g_option_context_parse_strv(context, &extra_args, error);

    g_strfreev(extra_args);
    free(buf);
    return retval;
}

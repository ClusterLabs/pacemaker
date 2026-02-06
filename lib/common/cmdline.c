/*
 * Copyright 2019-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <ctype.h>
#include <stdbool.h>

#include <glib.h>

#include <crm/crm.h>
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
        crm_exit(CRM_EX_OSERR);
    }

    // cppcheck-suppress nullPointerOutOfMemory
    args->summary = strdup(summary);
    // cppcheck-suppress nullPointerOutOfMemory
    if (args->summary == NULL) {
        free(args);
        args = NULL;
        crm_exit(CRM_EX_OSERR);
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
                        GOptionGroup **output_group, const char *param_string) {
    GOptionContext *context;
    GOptionGroup *main_group;

    GOptionEntry main_entries[3] = {
        { "version", '$', 0, G_OPTION_ARG_NONE, &(common_args->version),
          N_("Display software version and exit"),
          NULL },
        { "verbose", 'V', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, bump_verbosity,
          N_("Increase debug output (may be specified multiple times)"),
          NULL },

        { NULL }
    };

    main_group = g_option_group_new(NULL, "Application Options:", NULL, common_args, free_common_args);
    g_option_group_add_entries(main_group, main_entries);

    context = g_option_context_new(param_string);
    g_option_context_set_summary(context, common_args->summary);
    g_option_context_set_description(context,
                                     "Report bugs to " PCMK__BUG_URL "\n");
    g_option_context_set_main_group(context, main_group);

    if (fmts != NULL) {
        GOptionEntry output_entries[3] = {
            { "output-as", 0, 0, G_OPTION_ARG_STRING, &(common_args->output_ty),
              NULL,
              N_("FORMAT") },
            { "output-to", 0, 0, G_OPTION_ARG_STRING, &(common_args->output_dest),
              N_( "Specify file name for output (or \"-\" for stdout)"), N_("DEST") },

            { NULL }
        };

        if (*output_group == NULL) {
            *output_group = g_option_group_new("output", N_("Output Options:"), N_("Show output help"), NULL, NULL);
        }

        common_args->output_as_descr =
            pcmk__assert_asprintf("Specify output format as one of: %s", fmts);
        output_entries[0].description = common_args->output_as_descr;
        g_option_group_add_entries(*output_group, output_entries);
        g_option_context_add_group(context, *output_group);
    }

    // main_group is now owned by context, we don't free it here
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
pcmk__add_main_args(GOptionContext *context, const GOptionEntry entries[])
{
    GOptionGroup *main_group = g_option_context_get_main_group(context);

    g_option_group_add_entries(main_group, entries);
}

void
pcmk__add_arg_group(GOptionContext *context, const char *name,
                    const char *header, const char *desc,
                    const GOptionEntry entries[])
{
    GOptionGroup *group = NULL;

    group = g_option_group_new(name, header, desc, NULL, NULL);
    g_option_group_add_entries(group, entries);
    g_option_context_add_group(context, group);
    // group is now owned by context, we don't free it here
}

/*!
 * \internal
 * \brief Prepare a command line to add to a \c pcmk__output_t as the request
 *
 * This performs various transformations on the command line arguments, such
 * as surrounding arguments containing spaces with quotes and escaping any
 * single quotes in the string.
 *
 * \param[in] argv  Command line (typically from \c pcmk__cmdline_preproc())
 *
 * \return Newly allocated command line suitable for use as the
 *         \c PCMK_XA_REQUEST attribute value in XML output
 *
 * \note The caller is responsible for freeing the return value using
 *       \c g_free().
 */
gchar *
pcmk__quote_cmdline(const char *const *argv)
{
    GString *cmdline = NULL;

    if (argv == NULL) {
        return NULL;
    }

    for (int i = 0; argv[i] != NULL; i++) {
        gint argc = 0;

        /* Quote the argument if it's unparsable as-is (empty, all whitespace,
         * or having mismatched quotes), or if it contains more than one token
         */
        if (!g_shell_parse_argv(argv[i], &argc, NULL, NULL) || (argc > 1)) {
            gchar *quoted = g_shell_quote(argv[i]);

            pcmk__add_word(&cmdline, 128, quoted);
            g_free(quoted);

        } else {
            pcmk__add_word(&cmdline, 128, argv[i]);
        }
    }

    if (cmdline == NULL) {
        return NULL;
    }
    return g_string_free(cmdline, FALSE);
}

gchar **
pcmk__cmdline_preproc(char *const *argv, const char *special) {
    GPtrArray *arr = NULL;
    bool saw_dash_dash = false;
    bool copy_option = false;

    if (argv == NULL) {
        return NULL;
    }

    if (g_get_prgname() == NULL && argv && *argv) {
        gchar *basename = g_path_get_basename(*argv);

        g_set_prgname(basename);
        g_free(basename);
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
            g_ptr_array_add(arr, g_strdup(argv[i]));
            continue;
        }

        if (copy_option == true) {
            g_ptr_array_add(arr, g_strdup(argv[i]));
            copy_option = false;
            continue;
        }

        /* This is just a dash by itself.  That could indicate stdin/stdout, or
         * it could be user error.  Copy it over and let glib figure it out.
         */
        if (pcmk__str_eq(argv[i], "-", pcmk__str_casei)) {
            g_ptr_array_add(arr, g_strdup(argv[i]));
            continue;
        }

        /* "-INFINITY" is almost certainly meant as a string, not as an option
         * list
         */
        if (strcmp(argv[i], "-INFINITY") == 0) {
            g_ptr_array_add(arr, g_strdup(argv[i]));
            continue;
        }

        /* This is a short argument, or perhaps several.  Iterate over it
         * and explode them out into individual arguments.
         */
        if (g_str_has_prefix(argv[i], "-") && !g_str_has_prefix(argv[i], "--")) {
            /* Skip over leading dash */
            const char *ch = argv[i]+1;

            /* This looks like the start of a number, which means it is a negative
             * number.  It's probably the argument to the preceeding option, but
             * we can't know that here.  Copy it over and let whatever handles
             * arguments next figure it out.
             */
            if (*ch != '\0' && *ch >= '1' && *ch <= '9') {
                bool is_numeric = true;

                while (*ch != '\0') {
                    if (!isdigit(*ch)) {
                        is_numeric = false;
                        break;
                    }

                    ch++;
                }

                if (is_numeric) {
                    g_ptr_array_add(arr, g_strdup_printf("%s", argv[i]));
                    continue;
                } else {
                    /* This argument wasn't entirely numeric.  Reset ch to the
                     * beginning so we can process it one character at a time.
                     */
                    ch = argv[i]+1;
                }
            }

            while (*ch != '\0') {
                /* This is a special short argument that takes an option.  getopt
                 * allows values to be interspersed with a list of arguments, but
                 * glib does not.  Grab both the argument and its value and
                 * separate them into a new argument.
                 */
                if (special != NULL && strchr(special, *ch) != NULL) {
                    /* The argument does not occur at the end of this string of
                     * arguments.  Take everything through the end as its value.
                     */
                    if (*(ch+1) != '\0') {
                        fprintf(stderr, "Deprecated argument format '-%c%s' used.\n", *ch, ch+1);
                        fprintf(stderr, "Please use '-%c %s' instead.  "
                                        "Support will be removed in a future release.\n",
                                *ch, ch+1);

                        g_ptr_array_add(arr, g_strdup_printf("-%c", *ch));
                        g_ptr_array_add(arr, g_strdup(ch+1));
                        break;

                    /* The argument occurs at the end of this string.  Hopefully
                     * whatever comes next in argv is its value.  It may not be,
                     * but that is not for us to decide.
                     */
                    } else {
                        g_ptr_array_add(arr, g_strdup_printf("-%c", *ch));
                        copy_option = true;
                        ch++;
                    }

                /* This is a regular short argument.  Just copy it over. */
                } else {
                    g_ptr_array_add(arr, g_strdup_printf("-%c", *ch));
                    ch++;
                }
            }

        /* This is a long argument, or an option, or something else.
         * Copy it over - everything else is copied, so this keeps it easy for
         * the caller to know what to do with the memory when it's done.
         */
        } else {
            g_ptr_array_add(arr, g_strdup(argv[i]));
        }
    }

    g_ptr_array_add(arr, NULL);

    return (char **) g_ptr_array_free(arr, FALSE);
}

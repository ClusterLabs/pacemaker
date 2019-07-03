/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <config.h>
#include <glib.h>

#include <crm/common/cmdline_internal.h>
#include <crm/common/util.h>

static gboolean
bump_verbosity(const gchar *option_name, const gchar *optarg, gpointer data, GError **error) {
    pcmk__common_args_t *common_args = (pcmk__common_args_t *) data;
    common_args->verbosity++;
    return TRUE;
}

static void
free_common_args(gpointer data) {
    pcmk__common_args_t *common_args = (pcmk__common_args_t *) data;

    free(common_args->summary);
    free(common_args->output_ty);
    free(common_args->output_ty_desc);
    free(common_args->output_dest);
}

GOptionContext *
pcmk__build_arg_context(pcmk__common_args_t *common_args, const char *fmts) {
    char *desc = crm_strdup_printf("Report bugs to %s\n", PACKAGE_BUGREPORT);
    GOptionContext *context;
    GOptionGroup *main_group;

    GOptionEntry main_entries[6] = {
        { "version", '$', 0, G_OPTION_ARG_NONE, &(common_args->version),
          "Display version information and exit.",
          NULL },
        { "verbose", 'V', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK, bump_verbosity,
          "Increase debug output (may be specified multiple times).",
          NULL },
        { "quiet", 'q', 0, G_OPTION_ARG_NONE, &(common_args->quiet),
          "Be less descriptive in output.",
          NULL },
        { "output-as", 0, 0, G_OPTION_ARG_STRING, &(common_args->output_ty),
          NULL,
          "FORMAT" },
        { "output-to", 0, 0, G_OPTION_ARG_STRING, &(common_args->output_dest),
          "Specify the destination for output, \"-\" for stdout or a filename", "DEST" },

        { NULL }
    };

    common_args->output_ty_desc = crm_strdup_printf("Specify the format for output, one of: %s", fmts);
    main_entries[3].description = common_args->output_ty_desc;

    main_group = g_option_group_new(NULL, "Application Options:", NULL, common_args, free_common_args);
    g_option_group_add_entries(main_group, main_entries);

    context = g_option_context_new(NULL);
    g_option_context_set_summary(context, common_args->summary);
    g_option_context_set_description(context, desc);
    g_option_context_set_main_group(context, main_group);

    free(desc);

    return context;
}

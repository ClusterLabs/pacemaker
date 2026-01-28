/*
 * Copyright 2019-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <cmdline_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_CMDLINE_INTERNAL__H
#define PCMK__CRM_COMMON_CMDLINE_INTERNAL__H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *summary;
    char *output_as_descr;

    gboolean version;
    gboolean quiet;
    unsigned int verbosity;

    char *output_ty;
    char *output_dest;
} pcmk__common_args_t;

/*!
 * \internal
 * \brief Allocate a new common args object
 *
 * \param[in] summary  Summary description of tool for man page
 *
 * \return Newly allocated common args object
 * \note This function will immediately exit the program if memory allocation
 *       fails, since the intent is to call it at the very beginning of a
 *       program, before logging has been set up.
 */
pcmk__common_args_t *
pcmk__new_common_args(const char *summary);

/*!
 * \internal
 * \brief Create and return a GOptionContext containing the command line options
 *        supported by all tools.
 *
 * \note Formatted output options will be added unless fmts is NULL.  This allows
 *       for using this function in tools that have not yet been converted to
 *       formatted output.  It should not be NULL in any tool that calls
 *       pcmk__register_formats() as that function adds its own command line
 *       options.
 *
 * \param[in,out] common_args  A ::pcmk__common_args_t structure where the
 *                             results of handling command options will be written.
 * \param[in]     fmts         The help string for which formats are supported.
 * \param[in,out] output_group A ::GOptionGroup that formatted output related
 *                             command line arguments should be added to.
 * \param[in]     param_string A string describing any remaining command line
 *                             arguments.
 */
GOptionContext *
pcmk__build_arg_context(pcmk__common_args_t *common_args, const char *fmts,
                        GOptionGroup **output_group, const char *param_string);

/*!
 * \internal
 * \brief Clean up after pcmk__build_arg_context().  This should be called
 *        instead of ::g_option_context_free at program termination.
 *
 * \param[in,out] context Argument context to free
 */
void
pcmk__free_arg_context(GOptionContext *context);

/*!
 * \internal
 * \brief Add options to the main application options
 *
 * \param[in,out] context  Argument context to add options to
 * \param[in]     entries  Option entries to add
 *
 * \note This is simply a convenience wrapper to reduce duplication
 */
void pcmk__add_main_args(GOptionContext *context, const GOptionEntry entries[]);

/*!
 * \internal
 * \brief Add an option group to an argument context
 *
 * \param[in,out] context  Argument context to add group to
 * \param[in]     name     Option group name (to be used in --help-NAME)
 * \param[in]     header   Header for --help-NAME output
 * \param[in]     desc     Short description for --help-NAME option
 * \param[in]     entries  Array of options in group
 *
 * \note This is simply a convenience wrapper to reduce duplication
 */
void pcmk__add_arg_group(GOptionContext *context, const char *name,
                         const char *header, const char *desc,
                         const GOptionEntry entries[]);

gchar *pcmk__quote_cmdline(const char *const *argv);

/*!
 * \internal
 * \brief Pre-process command line arguments to preserve compatibility with
 *        getopt behavior.
 *
 * getopt and glib have slightly different behavior when it comes to processing
 * single command line arguments.  getopt allows this:  -x<val>, while glib will
 * try to handle <val> like it is additional single letter arguments.  glib
 * prefers -x <val> instead.
 *
 * This function scans argv, looking for any single letter command line options
 * (indicated by the 'special' parameter).  When one is found, everything after
 * that argument to the next whitespace is converted into its own value.  Single
 * letter command line options can come in a group after a single dash, but
 * this function will expand each group into many arguments.
 *
 * Long options and anything after "--" is preserved.  The result of this function
 * can then be passed to ::g_option_context_parse_strv for actual processing.
 *
 * In pseudocode, this:
 *
 * pcmk__cmdline_preproc(4, ["-XbA", "--blah=foo", "-aF", "-Fval", "--", "--extra", "-args"], "aF")
 *
 * Would be turned into this:
 *
 * ["-X", "-b", "-A", "--blah=foo", "-a", "F", "-F", "val", "--", "--extra", "-args"]
 *
 * This function does not modify argv, and the return value is built of copies
 * of all the command line arguments.  It is up to the caller to free this memory
 * after use.
 *
 * \note This function calls g_set_prgname assuming it wasn't previously set and
 *       assuming argv is not NULL.  It is not safe to call g_set_prgname more
 *       than once so clients should not do so after calling this function.
 *
 * \param[in] argv    The command line arguments.
 * \param[in] special Single-letter command line arguments that take a value.
 *                    These letters will all have pre-processing applied.
 *
 * \note @COMPAT We should drop this at a new major or minor release series
 *       after we no longer support building with Booth <1.2, which invokes
 *       Pacemaker CLI tools using the getopt syntax.
 */
gchar **
pcmk__cmdline_preproc(char *const *argv, const char *special);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_CMDLINE_INTERNAL__H

/*
 * Copyright 2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef CMDLINE_INTERNAL__H
#define CMDLINE_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

typedef struct {
    char *summary;

    gboolean version;
    gboolean quiet;
    unsigned int verbosity;

    char *output_ty;
    char *output_ty_desc;
    char *output_dest;
} pcmk__common_args_t;

GOptionContext *
pcmk__build_arg_context(pcmk__common_args_t *common_args, const char *fmts);

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
 * \param[in] argc    The length of argv.
 * \param[in] argv    The command line arguments.
 * \param[in] special Single-letter command line arguments that take a value.
 *                    These letters will all have pre-processing applied.
 */
char **
pcmk__cmdline_preproc(int argc, char **argv, const char *special);

#ifdef __cplusplus
}
#endif

#endif

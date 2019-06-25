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

#ifdef __cplusplus
}
#endif

#endif

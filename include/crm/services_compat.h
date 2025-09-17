/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_SERVICES_COMPAT__H
#define PCMK__CRM_SERVICES_COMPAT__H

#include <glib.h>               // GList, gboolean

#include <crm/common/results.h> // enum ocf_exitcode, PCMK_OCF_OK, etc.

#ifdef __cplusplus
extern "C" {
#endif

//! \deprecated Use crm_exit_str() instead
static inline const char *
services_ocf_exitcode_str(enum ocf_exitcode code)
{
    switch (code) {
        case PCMK_OCF_OK:
            return "ok";
        case PCMK_OCF_UNKNOWN_ERROR:
            return "error";
        case PCMK_OCF_INVALID_PARAM:
            return "invalid parameter";
        case PCMK_OCF_UNIMPLEMENT_FEATURE:
            return "unimplemented feature";
        case PCMK_OCF_INSUFFICIENT_PRIV:
            return "insufficient privileges";
        case PCMK_OCF_NOT_INSTALLED:
            return "not installed";
        case PCMK_OCF_NOT_CONFIGURED:
            return "not configured";
        case PCMK_OCF_NOT_RUNNING:
            return "not running";
        case PCMK_OCF_RUNNING_PROMOTED:
            return "promoted";
        case PCMK_OCF_FAILED_PROMOTED:
            return "promoted (failed)";
        case PCMK_OCF_DEGRADED:
            return "OCF_DEGRADED";
        case PCMK_OCF_DEGRADED_PROMOTED:
            return "promoted (degraded)";
        default:
            return "unknown";
    }
}

//! \deprecated Do not use
GList *get_directory_list(const char *root, gboolean files,
                          gboolean executable);

#  ifdef __cplusplus
}
#  endif

#endif // PCMK__CRM_SERVICES_COMPAT__H

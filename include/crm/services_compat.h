/*
 * Copyright 2010-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__SERVICES_COMPAT__H
#  define PCMK__SERVICES_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated services API
 * \ingroup core
 * \deprecated Do not include this header directly. The service APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

#include <crm/common/results.h>

//! \deprecated Use enum pcmk_exec_status instead
enum op_status {
    PCMK_LRM_OP_UNKNOWN = PCMK_EXEC_UNKNOWN,
    PCMK_LRM_OP_PENDING = PCMK_EXEC_PENDING,
    PCMK_LRM_OP_DONE = PCMK_EXEC_DONE,
    PCMK_LRM_OP_CANCELLED = PCMK_EXEC_CANCELLED,
    PCMK_LRM_OP_TIMEOUT = PCMK_EXEC_TIMEOUT,
    PCMK_LRM_OP_NOTSUPPORTED = PCMK_EXEC_NOT_SUPPORTED,
    PCMK_LRM_OP_ERROR = PCMK_EXEC_ERROR,
    PCMK_LRM_OP_ERROR_HARD = PCMK_EXEC_ERROR_HARD,
    PCMK_LRM_OP_ERROR_FATAL = PCMK_EXEC_ERROR_FATAL,
    PCMK_LRM_OP_NOT_INSTALLED = PCMK_EXEC_NOT_INSTALLED,
    PCMK_LRM_OP_NOT_CONNECTED = PCMK_EXEC_NOT_CONNECTED,
    PCMK_LRM_OP_INVALID = PCMK_EXEC_INVALID,
};

//! \deprecated Use pcmk_exec_status_str() instead
static inline const char *
services_lrm_status_str(enum op_status status)
{
    return pcmk_exec_status_str(status);
}

#ifdef __cplusplus
}
#endif

#endif

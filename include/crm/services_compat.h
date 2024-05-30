/*
 * Copyright 2010-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_SERVICES_COMPAT__H
#  define PCMK__CRM_SERVICES_COMPAT__H

#include <crm/common/actions.h>
#include <crm/common/results.h>
#include <crm/services.h>
#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Deprecated services API
 * \ingroup core
 * \deprecated Do not include this header directly. The service APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

#  ifndef LSB_ROOT_DIR
     //! \deprecated Do not use
#    define LSB_ROOT_DIR "/etc/init.d"
#  endif

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

//! \deprecated Use resources_action_create() instead
svc_action_t *services_action_create(const char *name, const char *action,
                                     guint interval_ms, int timeout);

#ifdef __cplusplus
}
#endif

#endif

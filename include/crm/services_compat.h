/*
 * Copyright 2010-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_SERVICES_COMPAT__H
#  define PCMK__CRM_SERVICES_COMPAT__H


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

//! \deprecated Use resources_list_agents() instead
GList *services_list(void);

//! \deprecated Use pcmk_exec_status_str() instead
static inline const char *
services_lrm_status_str(enum op_status status)
{
    return pcmk_exec_status_str((enum pcmk_exec_status) status);
}

//! \deprecated Use services_result2ocf() instead
static inline enum ocf_exitcode
services_get_ocf_exitcode(const char *action, int lsb_exitcode)
{
    /* For non-status actions, LSB and OCF share error code meaning <= 7 */
    if (action && strcmp(action, "status") && strcmp(action, "monitor")) {
        if ((lsb_exitcode < 0) || (lsb_exitcode > PCMK_LSB_NOT_RUNNING)) {
            return PCMK_OCF_UNKNOWN_ERROR;
        }
        return (enum ocf_exitcode)lsb_exitcode;
    }

    /* status has different return codes */
    switch (lsb_exitcode) {
        case PCMK_LSB_STATUS_OK:
            return PCMK_OCF_OK;
        case PCMK_LSB_STATUS_NOT_INSTALLED:
            return PCMK_OCF_NOT_INSTALLED;
        case PCMK_LSB_STATUS_INSUFFICIENT_PRIV:
            return PCMK_OCF_INSUFFICIENT_PRIV;
        case PCMK_LSB_STATUS_VAR_PID:
        case PCMK_LSB_STATUS_VAR_LOCK:
        case PCMK_LSB_STATUS_NOT_RUNNING:
            return PCMK_OCF_NOT_RUNNING;
    }
    return PCMK_OCF_UNKNOWN_ERROR;
}

#ifdef __cplusplus
}
#endif

#endif

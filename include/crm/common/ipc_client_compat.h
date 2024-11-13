/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_IPC_CLIENT_COMPAT__H
#define PCMK__CRM_COMMON_IPC_CLIENT_COMPAT__H

#include <stdbool.h>            // bool
#include <crm/common/ipc.h>     // crm_ipc_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker IPC APIs
 * \ingroup core
 * \deprecated Do not include this header directly. The IPC APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
bool crm_ipc_connect(crm_ipc_t *client);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_IPC_CLIENT_COMPAT__H

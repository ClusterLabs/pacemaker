/*
 * Copyright 2012-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_LRMD_COMPAT__H
#  define PCMK__CRM_LRMD_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated executor utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
#define F_LRMD_OPERATION "lrmd_op"

//! \deprecated Do not use
#define F_LRMD_CLIENTNAME "lrmd_clientname"

//! \deprecated Do not use
#define F_LRMD_CALLBACK_TOKEN "lrmd_async_id"

//! \deprecated Do not use
#define F_LRMD_IS_IPC_PROVIDER "lrmd_is_ipc_provider"

//! \deprecated Do not use
#define F_LRMD_CLIENTID "lrmd_clientid"

//! \deprecated Do not use
#define F_LRMD_PROTOCOL_VERSION "lrmd_protocol_version"

//! \deprecated Do not use
#define F_LRMD_REMOTE_MSG_TYPE "lrmd_remote_msg_type"

//! \deprecated Do not use
#define F_LRMD_REMOTE_MSG_ID "lrmd_remote_msg_id"

//! \deprecated Do not use
#define F_LRMD_CALLID "lrmd_callid"

//! \deprecated Do not use
#define F_LRMD_CALLOPTS "lrmd_callopt"

//! \deprecated Do not use
#define F_LRMD_CALLDATA "lrmd_calldata"

//! \deprecated Do not use
#define F_LRMD_RC "lrmd_rc"

//! \deprecated Do not use
#define F_LRMD_EXEC_RC "lrmd_exec_rc"

//! \deprecated Do not use
#define F_LRMD_OP_STATUS "lrmd_exec_op_status"

//! \deprecated Do not use
#define F_LRMD_TIMEOUT "lrmd_timeout"

//! \deprecated Do not use
#define F_LRMD_WATCHDOG "lrmd_watchdog"

//! \deprecated Do not use
#define F_LRMD_CLASS "lrmd_class"

//! \deprecated Do not use
#define F_LRMD_PROVIDER "lrmd_provider"

//! \deprecated Do not use
#define F_LRMD_TYPE "lrmd_type"

//! \deprecated Do not use
#define F_LRMD_ORIGIN "lrmd_origin"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_LRMD_COMPAT__H

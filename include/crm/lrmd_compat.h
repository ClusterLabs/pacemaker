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

//! \deprecated Do not use
#define F_LRMD_RSC_RUN_TIME "lrmd_run_time"

//! \deprecated Do not use
#define F_LRMD_RSC_RCCHANGE_TIME "lrmd_rcchange_time"

//! \deprecated Do not use
#define F_LRMD_RSC_EXEC_TIME "lrmd_exec_time"

//! \deprecated Do not use
#define F_LRMD_RSC_QUEUE_TIME "lrmd_queue_time"

//! \deprecated Do not use
#define F_LRMD_RSC_ID "lrmd_rsc_id"

//! \deprecated Do not use
#define F_LRMD_RSC_ACTION "lrmd_rsc_action"

//! \deprecated Do not use
#define F_LRMD_RSC_USERDATA_STR "lrmd_rsc_userdata_str"

//! \deprecated Do not use
#define F_LRMD_RSC_OUTPUT "lrmd_rsc_output"

//! \deprecated Do not use
#define F_LRMD_RSC_EXIT_REASON "lrmd_rsc_exit_reason"

//! \deprecated Do not use
#define F_LRMD_RSC_START_DELAY "lrmd_rsc_start_delay"

//! \deprecated Do not use
#define F_LRMD_RSC_INTERVAL "lrmd_rsc_interval"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_LRMD_COMPAT__H

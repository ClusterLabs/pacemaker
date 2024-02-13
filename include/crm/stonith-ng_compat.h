/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_STONITH_NG_COMPAT__H
#  define PCMK__CRM_STONITH_NG_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated fencer utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
#define T_STONITH_NOTIFY_DISCONNECT "st_notify_disconnect"

//! \deprecated Do not use
#define T_STONITH_NOTIFY_FENCE "st_notify_fence"

//! \deprecated Do not use
#define T_STONITH_NOTIFY_HISTORY "st_notify_history"

//! \deprecated Do not use
#define T_STONITH_NOTIFY_HISTORY_SYNCED "st_notify_history_synced"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_STONITH_NG_COMPAT__H

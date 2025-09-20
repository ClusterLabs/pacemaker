/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_OPTIONS_COMPAT__H
#define PCMK__CRM_COMMON_OPTIONS_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker options API
 * \ingroup core
 * \deprecated Do not include this header directly. The nvpair APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Do not use
#define PCMK_OPT_CLUSTER_IPC_LIMIT "cluster-ipc-limit"

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_OPTIONS_COMPAT__H

/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_AGENTS_COMPAT__H
#define PCMK__CRM_COMMON_AGENTS_COMPAT__H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker resource agents API
 * \ingroup core
 * \deprecated Do not include this header directly. The nvpair APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use \c PCMK_FENCING_ACTION_LIMIT instead
#define PCMK_STONITH_ACTION_LIMIT PCMK_FENCING_ACTION_LIMIT

//! \deprecated Use \c PCMK_FENCING_DELAY_BASE instead
#define PCMK_STONITH_DELAY_BASE PCMK_FENCING_DELAY_BASE

//! \deprecated Use \c PCMK_FENCING_DELAY_MAX instead
#define PCMK_STONITH_DELAY_MAX PCMK_FENCING_DELAY_MAX

//! \deprecated Use \c PCMK_FENCING_HOST_ARGUMENT instead
#define PCMK_STONITH_HOST_ARGUMENT PCMK_FENCING_HOST_ARGUMENT

//! \deprecated Use \c PCMK_FENCING_HOST_CHECK instead
#define PCMK_STONITH_HOST_CHECK PCMK_FENCING_HOST_CHECK

//! \deprecated Use \c PCMK_FENCING_HOST_LIST instead
#define PCMK_STONITH_HOST_LIST PCMK_FENCING_HOST_LIST

//! \deprecated Use \c PCMK_FENCING_HOST_MAP instead
#define PCMK_STONITH_HOST_MAP PCMK_FENCING_HOST_MAP

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_AGENTS_COMPAT__H

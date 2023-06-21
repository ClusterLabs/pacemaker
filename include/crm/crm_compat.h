/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CRM_COMPAT__H
#  define PCMK__CRM_CRM_COMPAT__H

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker utilities
 * \ingroup core
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

//! \deprecated Use '\0' instead
#define EOS '\0'

//! \deprecated This defined constant will be removed in a future release
#define MAX_IPC_DELAY 120

//! \deprecated This defined constant will be removed in a future release
#define CRM_OP_LRM_QUERY "lrm_query"

//! \deprecated This defined constant will be removed in a future release
#define CRM_ATTR_RA_VERSION "#ra-version"

//! \deprecated Use PCMK_ACTION_START instead
#define CRMD_ACTION_START PCMK_ACTION_START

//! \deprecated Use PCMK_ACTION_STOP instead
#define CRMD_ACTION_STOP PCMK_ACTION_STOP

//! \deprecated Use PCMK_ACTION_START instead
#define RSC_START PCMK_ACTION_START

//!@{
//! \deprecated This macro will be removed in a future release

#  ifndef __GNUC__
#    define __builtin_expect(expr, result) (expr)
#  endif

#define __likely(expr) __builtin_expect(expr, 1)

#define __unlikely(expr) __builtin_expect(expr, 0)

// This ends the doxygen deprecation comment
//!@}

//! \deprecated Use GList * instead
typedef GList *GListPtr;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CRM_COMPAT__H

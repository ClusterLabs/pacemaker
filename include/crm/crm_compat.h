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

//! \deprecated Use PCMK_ACTION_CANCEL instead
#define CRMD_ACTION_CANCEL PCMK_ACTION_CANCEL

//! \deprecated Use PCMK_ACTION_DELETE instead
#define CRMD_ACTION_DELETE PCMK_ACTION_DELETE

//! \deprecated Use PCMK_ACTION_DEMOTE instead
#define CRMD_ACTION_DEMOTE PCMK_ACTION_DEMOTE

//! \deprecated Use PCMK_ACTION_META_DATA instead
#define CRMD_ACTION_METADATA PCMK_ACTION_META_DATA

//! \deprecated Use PCMK_ACTION_MIGRATE_TO instead
#define CRMD_ACTION_MIGRATE PCMK_ACTION_MIGRATE_TO

//! \deprecated Use PCMK_ACTION_NOTIFY instead
#define CRMD_ACTION_NOTIFY PCMK_ACTION_NOTIFY

//! \deprecated Use PCMK_ACTION_PROMOTE instead
#define CRMD_ACTION_PROMOTE PCMK_ACTION_PROMOTE

//! \deprecated Use PCMK_ACTION_RELOAD instead
#define CRMD_ACTION_RELOAD PCMK_ACTION_RELOAD

//! \deprecated Use PCMK_ACTION_RELOAD_AGENT instead
#define CRMD_ACTION_RELOAD_AGENT PCMK_ACTION_RELOAD_AGENT

//! \deprecated Use PCMK_ACTION_START instead
#define CRMD_ACTION_START PCMK_ACTION_START

//! \deprecated Use PCMK_ACTION_MONITOR instead
#define CRMD_ACTION_STATUS PCMK_ACTION_MONITOR

//! \deprecated Use PCMK_ACTION_STOP instead
#define CRMD_ACTION_STOP PCMK_ACTION_STOP

//! \deprecated Use PCMK_ACTION_CANCEL instead
#define RSC_CANCEL PCMK_ACTION_CANCEL

//! \deprecated Use PCMK_ACTION_DELETE instead
#define RSC_DELETE PCMK_ACTION_DELETE

//! \deprecated Use PCMK_ACTION_DEMOTE instead
#define RSC_DEMOTE PCMK_ACTION_DEMOTE

//! \deprecated Use PCMK_ACTION_META_DATA instead
#define RSC_METADATA PCMK_ACTION_META_DATA

//! \deprecated Use PCMK_ACTION_MIGRATE_TO instead
#define RSC_MIGRATE PCMK_ACTION_MIGRATE_TO

//! \deprecated Use PCMK_ACTION_NOTIFY instead
#define RSC_NOTIFY PCMK_ACTION_NOTIFY

//! \deprecated Use PCMK_ACTION_PROMOTE instead
#define RSC_PROMOTE PCMK_ACTION_PROMOTE

//! \deprecated Use PCMK_ACTION_START instead
#define RSC_START PCMK_ACTION_START

//! \deprecated Use PCMK_ACTION_MONITOR instead
#define RSC_STATUS PCMK_ACTION_MONITOR

//! \deprecated Use PCMK_ACTION_STOP instead
#define RSC_STOP PCMK_ACTION_STOP

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

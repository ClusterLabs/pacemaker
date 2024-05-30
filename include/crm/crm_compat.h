/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CRM_COMPAT__H
#  define PCMK__CRM_CRM_COMPAT__H

#include <strings.h>
#include <glib.h>

#include <crm/common/actions.h>
#include <crm/common/scores.h>

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

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use PCMK_SCORE_INFINITY instead
#define CRM_SCORE_INFINITY PCMK_SCORE_INFINITY

/* INFINITY might be defined elsewhere (such as math.h), so undefine it first.
 * This, of course, complicates any attempt to use the other definition in any
 * code that includes this header.
 */
//! \deprecated Use PCMK_SCORE_INFINITY instead
#undef INFINITY
#define INFINITY PCMK_SCORE_INFINITY

//! \deprecated Use PCMK_VALUE_INFINITY instead
#define CRM_INFINITY_S PCMK_VALUE_INFINITY

//! \deprecated Use PCMK_VALUE_MINUS_INFINITY instead
#define CRM_MINUS_INFINITY_S PCMK_VALUE_MINUS_INFINITY

//! \deprecated Use PCMK_VALUE_PLUS_INFINITY instead
#define CRM_PLUS_INFINITY_S PCMK_VALUE_PLUS_INFINITY

//! \deprecated Use PCMK_VALUE_INFINITY instead
#define INFINITY_S "INFINITY"

//! \deprecated Use PCMK_VALUE_MINUS_INFINITY instead
#define MINUS_INFINITY_S "-INFINITY"

//! \deprecated Use PCMK_ACTION_STONITH instead
#define CRM_OP_FENCE PCMK_ACTION_STONITH

//! \deprecated This defined constant will be removed in a future release
#define CRM_OP_LRM_QUERY "lrm_query"

//! \deprecated Use PCMK_ACTION_CLONE_ONE_OR_MORE instead
#define CRM_OP_RELAXED_CLONE PCMK_ACTION_CLONE_ONE_OR_MORE

//! \deprecated Use PCMK_ACTION_ONE_OR_MORE instead
#define CRM_OP_RELAXED_SET PCMK_ACTION_ONE_OR_MORE

//! \deprecated This defined constant will be removed in a future release
#define CRM_ATTR_RA_VERSION "#ra-version"

//! \deprecated Use PCMK_ACTION_CANCEL instead
#define CRMD_ACTION_CANCEL PCMK_ACTION_CANCEL

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use GList * instead
typedef GList *GListPtr;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CRM_COMPAT__H

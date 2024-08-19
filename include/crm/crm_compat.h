/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_CRM_COMPAT__H
#define PCMK__CRM_CRM_COMPAT__H

#include <glib.h>               // GList

#include <crm_config.h>         // PCMK_SCHEDULER_INPUT_DIR, PCMK_SCHEMA_DIR
#include <crm/common/scores.h>  // PCMK_SCORE_INFINITY

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

//! \deprecated Do not use (will be removed in a future release)
#define CRM_SYSTEM_STONITHD "stonithd"

//! \deprecated Use PCMK_SCHEMA_DIR instead
#define CRM_SCHEMA_DIRECTORY PCMK_SCHEMA_DIR

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use PCMK_SCORE_INFINITY instead
#define CRM_SCORE_INFINITY PCMK_SCORE_INFINITY

//! \deprecated Use PCMK_SCHEDULER_INPUT_DIR instead
#define PE_STATE_DIR PCMK_SCHEDULER_INPUT_DIR

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use GList * instead
typedef GList *GListPtr;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_CRM_COMPAT__H

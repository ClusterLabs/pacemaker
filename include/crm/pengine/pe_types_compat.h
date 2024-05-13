/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H
#  define PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

#include <crm/common/scheduler.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker scheduler API
 * \ingroup pengine
 * \deprecated Do not include this header directly. The scheduler APIs in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_rsc_managed                  (1ULL << 1)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_flag_have_quorum             pcmk_sched_quorate

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_flag_have_stonith_resource   pcmk_sched_have_fencing

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_node_t instead
typedef struct pe_node_s node_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated use pcmk_resource_t instead
typedef struct pe_resource_s resource_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_scheduler_t instead
typedef struct pe_working_set_s pe_working_set_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

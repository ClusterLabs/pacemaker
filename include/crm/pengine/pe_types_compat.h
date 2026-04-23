/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H
#  define PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

#include <stdint.h>                // UINT64_C
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
#define pe_rsc_managed                  (UINT64_C(1) << 1)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_flag_have_quorum             (UINT64_C(1) << 0)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Do not use
#define pe_flag_have_stonith_resource   (UINT64_C(1) << 5)

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_node_t instead
typedef struct pcmk__scored_node node_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated use pcmk_resource_t instead
typedef struct pcmk__resource resource_t;

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_scheduler_t instead
typedef struct pcmk__scheduler pe_working_set_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

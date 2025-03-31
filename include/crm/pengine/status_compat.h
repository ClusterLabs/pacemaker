/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_STATUS_COMPAT__H
#define PCMK__CRM_PENGINE_STATUS_COMPAT__H

#include <stdbool.h>                // bool
#include <crm/common/scheduler.h>   // pcmk_resource_t, pcmk__rsc_unique, etc.

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \file
 * \brief Deprecated Pacemaker scheduler utilities
 * \ingroup pengine
 * \deprecated Do not include this header directly. The utilities in this
 *             header, and the header itself, will be removed in a future
 *             release.
 */

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_new_scheduler() instead
pcmk_scheduler_t *pe_new_working_set(void);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_reset_scheduler() instead
void pe_reset_working_set(pcmk_scheduler_t *scheduler);

//! \deprecated Use pcmk_reset_scheduler() instead
void cleanup_calculations(pcmk_scheduler_t *scheduler);

//! \deprecated Use pcmk_reset_scheduler() instead
void set_working_set_defaults(pcmk_scheduler_t *scheduler);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_free_scheduler() instead
void pe_free_working_set(pcmk_scheduler_t *scheduler);

// NOTE: sbd (as of at least 1.5.2) uses this
//! \deprecated Use pcmk_find_node() with scheduler object instead
pcmk_node_t *pe_find_node(const GList *node_list, const char *node_name);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_STATUS_COMPAT__H

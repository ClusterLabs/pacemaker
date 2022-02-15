/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H
#  define PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

#include <crm/pengine/pe_types.h>

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

//!< \deprecated Use pe_action_t instead
typedef struct pe_action_s action_t;

//!< \deprecated Use pe_action_wrapper_t instead
typedef struct pe_action_wrapper_s action_wrapper_t;

//!< \deprecated Use pe_node_t instead
typedef struct pe_node_s node_t;

//!< \deprecated Use enum pe_quorum_policy instead
typedef enum pe_quorum_policy no_quorum_policy_t;

//!< \deprecated use pe_resource_t instead
typedef struct pe_resource_s resource_t;

//!< \deprecated Use pe_tag_t instead
typedef struct pe_tag_s tag_t;

//!< \deprecated Use pe_ticket_t instead
typedef struct pe_ticket_s ticket_t;

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_PENGINE_PE_TYPES_COMPAT__H

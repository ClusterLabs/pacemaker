/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_RESOURCES__H
#define PCMK__CRM_COMMON_RESOURCES__H

#include <stdbool.h>                    // bool
#include <sys/types.h>                  // time_t
#include <libxml/tree.h>                // xmlNode
#include <glib.h>                       // gboolean, guint, GList, GHashTable

#include <crm/common/roles.h>           // enum rsc_role_e
#include <crm/common/scheduler_types.h> // pcmk_resource_t, etc.

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \file
 * \brief Scheduler API for resources
 * \ingroup core
 */

//! Search options for resources (exact resource ID always matches)
enum pe_find {
    //! Also match clone instance ID from resource history
    pcmk_rsc_match_history          = (1 << 0),

    //! Also match anonymous clone instances by base name
    pcmk_rsc_match_anon_basename    = (1 << 1),

    //! Match only clones and their instances, by either clone or instance ID
    pcmk_rsc_match_clone_only       = (1 << 2),

    //! If matching by node, compare current node instead of assigned node
    pcmk_rsc_match_current_node     = (1 << 3),

    //! \deprecated Do not use
    pe_find_inactive                = (1 << 4),

    //! Match clone instances (even unique) by base name as well as exact ID
    pcmk_rsc_match_basename         = (1 << 5),

#if !defined(PCMK_ALLOW_DEPRECATED) || (PCMK_ALLOW_DEPRECATED == 1)
    //! \deprecated Use pcmk_rsc_match_current_node instead
    pe_find_current     = pcmk_rsc_match_current_node,

    //! \deprecated Use pcmk_rsc_match_basename instead
    pe_find_any         = pcmk_rsc_match_basename,
#endif
};

//! \internal Do not use
typedef struct pcmk__resource_private pcmk__resource_private_t;

// Implementation of pcmk_resource_t
// @COMPAT Make this internal when we can break API backward compatibility
//!@{
//! \deprecated Do not use (public access will be removed in a future release)
struct pcmk__resource {
    /* @COMPAT Once all members are moved to pcmk__resource_private_t,
     * We can make that the pcmk_resource_t implementation and drop this
     * struct altogether, leaving pcmk_resource_t as an opaque public type.
     */
    pcmk__resource_private_t *private;

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_resource_id() instead
    char *id;                           // Resource ID in configuration

    // NOTE: sbd (as of at least 1.5.2) uses this
    //! \deprecated Call pcmk_resource_is_managed() instead
    unsigned long long flags;       // Group of enum pcmk__rsc_flags
};
//!@}

const char *pcmk_resource_id(const pcmk_resource_t *rsc);
bool pcmk_resource_is_managed(const pcmk_resource_t *rsc);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_RESOURCES__H

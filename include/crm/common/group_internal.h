/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_GROUP_INTERNAL__H
#define PCMK__CRM_COMMON_GROUP_INTERNAL__H

#include <stdbool.h>                    // bool
#include <crm/common/scheduler_types.h> // pcmk_resource_t
#include <crm/common/resources.h>       // pcmk_rsc_variant_group

#ifdef __cplusplus
extern "C" {
#endif

// Group resource flags (used in variant data)
enum pcmk__group_flags {
    pcmk__group_ordered     = (1 << 0), // Members start sequentially
    pcmk__group_colocated   = (1 << 1), // Members must be on same node
};

/*!
 * \internal
 * \brief Check whether a resource is a group resource
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is a group, otherwise false
 *
 * \note This does not return true if \p rsc is a clone of a group.
 */
static inline bool
pcmk__is_group(const pcmk_resource_t *rsc)
{
    return (rsc != NULL) && (rsc->variant == pcmk_rsc_variant_group);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_GROUP_INTERNAL__H

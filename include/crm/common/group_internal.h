/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__INCLUDED_CRM_COMMON_INTERNAL_H
#error "Include <crm/common/internal.h> instead of <group_internal.h> directly"
#endif

#ifndef PCMK__CRM_COMMON_GROUP_INTERNAL__H
#define PCMK__CRM_COMMON_GROUP_INTERNAL__H

#include <stdio.h>                          // NULL
#include <stdbool.h>                        // bool
#include <stdint.h>                         // UINT32_C
#include <crm/common/scheduler_types.h>     // pcmk_resource_t
#include <crm/common/resources_internal.h>  // pcmk__rsc_variant_group etc.

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Group resource flags (used in variant data)
 */
enum pcmk__group_flags {
    //! Members start sequentially
    pcmk__group_ordered     = (UINT32_C(1) << 0),

    //! Members must be on same node
    pcmk__group_colocated   = (UINT32_C(1) << 1),
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
    return (rsc != NULL) && (rsc->priv->variant == pcmk__rsc_variant_group);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_GROUP_INTERNAL__H

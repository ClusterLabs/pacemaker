/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_CLONE_INTERNAL__H
#define PCMK__CRM_COMMON_CLONE_INTERNAL__H

#include <stdio.h>                          // NULL
#include <stdbool.h>                        // bool
#include <crm/common/scheduler_types.h>     // pcmk_resource_t
#include <crm/common/resources.h>           // pcmk_rsc_unique,
#include <crm/common/resources_internal.h>  // pcmk__rsc_variant_clone etc.
#include <crm/common/util.h>                // pcmk_is_set

#ifdef __cplusplus
extern "C" {
#endif

// Clone resource flags (used in variant data)
enum pcmk__clone_flags {
    // Whether instances should be started sequentially
    pcmk__clone_ordered                 = (1 << 0),

    // Whether promotion scores have been added
    pcmk__clone_promotion_added         = (1 << 1),

    // Whether promotion constraints have been added
    pcmk__clone_promotion_constrained   = (1 << 2),
};

/*!
 * \internal
 * \brief Check whether a resource is a clone resource
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is a clone, otherwise false
 *
 * \note This does not return true if \p rsc has a clone ancestor.
 */
static inline bool
pcmk__is_clone(const pcmk_resource_t *rsc)
{
    return (rsc != NULL) && (rsc->private->variant == pcmk__rsc_variant_clone);
}

/*!
 * \internal
 * \brief Check whether a resource is a globally unique clone
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is a unique clone, otherwise false
 */
static inline bool
pcmk__is_unique_clone(const pcmk_resource_t *rsc)
{
    return pcmk__is_clone(rsc) && pcmk_is_set(rsc->flags, pcmk__rsc_unique);
}

/*!
 * \internal
 * \brief Check whether a resource is an anonymous clone
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is an anonymous clone, otherwise false
 */
static inline bool
pcmk__is_anonymous_clone(const pcmk_resource_t *rsc)
{
    return pcmk__is_clone(rsc) && !pcmk_is_set(rsc->flags, pcmk__rsc_unique);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_CLONE_INTERNAL__H

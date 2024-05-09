/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_PRIMITIVE_INTERNAL__H
#define PCMK__CRM_COMMON_PRIMITIVE_INTERNAL__H

#include <stdbool.h>                    // bool
#include <crm/common/scheduler_types.h> // pcmk_resource_t
#include <crm/common/resources.h>       // pcmk_rsc_variant_primitive

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Check whether a resource is a primitive resource
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is a primitive, otherwise false
 */
static inline bool
pcmk__is_primitive(const pcmk_resource_t *rsc)
{
    return (rsc != NULL) && (rsc->variant == pcmk_rsc_variant_primitive);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_PRIMITIVE_INTERNAL__H

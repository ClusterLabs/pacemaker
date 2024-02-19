/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_NVPAIR_INTERNAL__H
#define PCMK__CRM_COMMON_NVPAIR_INTERNAL__H

#include <crm/common/strings_internal.h>    // pcmk__str_eq(), etc.

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * \internal
 * \brief Insert a meta-attribute into a hash table
 *
 * \param[in] obj    Resource (pe_resource_t) or action (pe_action_t) to add to
 * \param[in] name   Meta-attribute name
 * \param[in] value  Value to add
 */
#define pcmk__insert_meta(obj, name, value) do {                        \
        if (!pcmk__str_eq((value), "#default",                          \
                          pcmk__str_casei|pcmk__str_null_matches)) {    \
            pcmk__insert_dup((obj)->meta, (name), (value));             \
        }                                                               \
    } while (0)

int pcmk__xe_get_datetime(const xmlNode *xml, const char *attr, crm_time_t **t);

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_NVPAIR_INTERNAL__H

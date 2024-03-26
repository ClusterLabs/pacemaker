/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_ROLES_INTERNAL__H
#  define PCMK__CRM_COMMON_ROLES_INTERNAL__H

#ifdef __cplusplus
extern "C" {
#endif

// String equivalents of enum rsc_role_e
#define PCMK__ROLE_UNKNOWN      "Unknown"
#define PCMK__ROLE_PROMOTED     "Promoted"
#define PCMK__ROLE_UNPROMOTED_LEGACY    "Slave"
#define PCMK__ROLE_PROMOTED_LEGACY      "Master"

/*!
 * \internal
 * \brief Set resource flags
 *
 * \param[in,out] resource      Resource to set flags for
 * \param[in]     flags_to_set  Group of enum pcmk_rsc_flags to set
 */
#define pcmk__set_rsc_flags(resource, flags_to_set) do {                    \
        (resource)->flags = pcmk__set_flags_as(__func__, __LINE__,          \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_set), #flags_to_set);                                 \
    } while (0)

/*!
 * \internal
 * \brief Clear resource flags
 *
 * \param[in,out] resource        Resource to clear flags for
 * \param[in]     flags_to_clear  Group of enum pcmk_rsc_flags to clear
 */
#define pcmk__clear_rsc_flags(resource, flags_to_clear) do {                \
        (resource)->flags = pcmk__clear_flags_as(__func__, __LINE__,        \
            LOG_TRACE, "Resource", (resource)->id, (resource)->flags,       \
            (flags_to_clear), #flags_to_clear);                             \
    } while (0)

/*!
 * \internal
 * \brief Get node where resource is currently active (if any)
 *
 * \param[in] rsc  Resource to check
 *
 * \return Node that \p rsc is active on, if any, otherwise NULL
 */
static inline pcmk_node_t *
pcmk__current_node(const pcmk_resource_t *rsc)
{
    return (rsc == NULL)? NULL : rsc->fns->active_node(rsc, NULL, NULL);
}

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_ROLES_INTERNAL__H

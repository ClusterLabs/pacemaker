/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>

/*!
 * \brief Get readable description of a resource role
 *
 * \param[in] role  Resource role
 *
 * \return Static string describing \p role, suitable for logging or display
 */
const char *
pcmk_role_text(enum rsc_role_e role)
{
    switch (role) {
        case pcmk_role_stopped:
            return PCMK_ROLE_STOPPED;

        case pcmk_role_started:
            return PCMK_ROLE_STARTED;

        case pcmk_role_unpromoted:
#ifdef PCMK__COMPAT_2_0
            return PCMK__ROLE_UNPROMOTED_LEGACY;
#else
            return PCMK_ROLE_UNPROMOTED;
#endif

        case pcmk_role_promoted:
#ifdef PCMK__COMPAT_2_0
            return PCMK__ROLE_PROMOTED_LEGACY;
#else
            return PCMK__ROLE_PROMOTED;
#endif

        default: // pcmk_role_unknown
            return PCMK__ROLE_UNKNOWN;
    }
}

/*!
 * \brief Parse a resource role from a string role specification
 *
 * \param[in] role  Role specification
 *
 * \return Resource role corresponding to \p role
 */
enum rsc_role_e
pcmk_parse_role(const char *role)
{
    if (pcmk__str_eq(role, PCMK__ROLE_UNKNOWN,
                     pcmk__str_casei|pcmk__str_null_matches)) {
        return pcmk_role_unknown;
    } else if (pcmk__str_eq(role, PCMK_ROLE_STOPPED, pcmk__str_casei)) {
        return pcmk_role_stopped;
    } else if (pcmk__str_eq(role, PCMK_ROLE_STARTED, pcmk__str_casei)) {
        return pcmk_role_started;
    } else if (pcmk__strcase_any_of(role, PCMK_ROLE_UNPROMOTED,
                                    PCMK__ROLE_UNPROMOTED_LEGACY, NULL)) {
        return pcmk_role_unpromoted;
    } else if (pcmk__strcase_any_of(role, PCMK__ROLE_PROMOTED,
                                    PCMK__ROLE_PROMOTED_LEGACY, NULL)) {
        return pcmk_role_promoted;
    }
    return pcmk_role_unknown; // Invalid role given
}

/*
 * Copyright 2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>      // NULL
#include <stdbool.h>    // bool, false

#include <crm/common/scheduler.h>
#include <crm/common/scheduler_internal.h>

/*!
 * \internal
 * \brief Get a resource's ID
 *
 * \param[in] rsc  Resource to check
 *
 * \return ID of \p rsc (or NULL if \p rsc is NULL)
 */
const char *
pcmk_resource_id(const pcmk_resource_t *rsc)
{
    return (rsc == NULL)? NULL : rsc->id;
}

/*!
 * \internal
 * \brief Check whether a resource is managed by the cluster
 *
 * \param[in] rsc  Resource to check
 *
 * \return true if \p rsc is managed, otherwise false
 */
bool
pcmk_resource_is_managed(const pcmk_resource_t *rsc)
{
    return (rsc == NULL)? false : pcmk_is_set(rsc->flags, pcmk_rsc_managed);
}

/*!
 * \brief Get readable description of a multiply-active recovery type
 *
 * \param[in] rsc  Resource with recovery type to check
 *
 * \return Static string describing recovery type of \p rsc
 */
const char *
pcmk__multiply_active_text(const pcmk_resource_t *rsc)
{
    switch (rsc->recovery_type) {
        case pcmk_multiply_active_stop:
            return "shutting it down";
        case pcmk_multiply_active_restart:
            return "attempting recovery";
        case pcmk_multiply_active_block:
            return "waiting for an administrator";
        case pcmk_multiply_active_unexpected:
            return "stopping unexpected instances";
    }
    return "Unknown";
}

/*
 * Copyright 2024-2025 the Pacemaker project contributors
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
 * \brief Free a resource object
 *
 * \param[in,out] user_data  Resource object to free
 */
void
pcmk__free_resource(gpointer user_data)
{
    pcmk_resource_t *rsc = user_data;

    if (rsc != NULL) {
        rsc->priv->fns->free(rsc);
    }
}

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
    return (rsc == NULL)? false : pcmk__is_set(rsc->flags, pcmk__rsc_managed);
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
    switch (rsc->priv->multiply_active_policy) {
        case pcmk__multiply_active_stop:
            return "shutting it down";
        case pcmk__multiply_active_restart:
            return "attempting recovery";
        case pcmk__multiply_active_block:
            return "waiting for an administrator";
        case pcmk__multiply_active_unexpected:
            return "stopping unexpected instances";
    }
    return "Unknown";
}

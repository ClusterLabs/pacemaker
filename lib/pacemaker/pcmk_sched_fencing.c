/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Order all actions appropriately relative to a fencing operation
 *
 * Ensure start operations of affected resources are ordered after fencing,
 * imply stop and demote operations of affected resources by marking them as
 * pseudo-actions, etc.
 *
 * \param[in]     stonith_op  Fencing operation
 * \param[in,out] data_set    Working set of cluster
 */
void
pcmk__order_vs_fence(pe_action_t *stonith_op, pe_working_set_t *data_set)
{
    CRM_CHECK(stonith_op && data_set, return);
    for (GList *r = data_set->resources; r != NULL; r = r->next) {
        rsc_stonith_ordering((pe_resource_t *) r->data, stonith_op, data_set);
    }
}


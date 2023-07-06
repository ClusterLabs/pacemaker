/*
 * Copyright 2008-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <glib.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <pacemaker-based.h>

static const cib__op_fn_t cib_op_functions[] = {
    [cib__op_abs_delete]  = cib_process_delete_absolute,
    [cib__op_apply_patch] = cib_server_process_diff,
    [cib__op_bump]        = cib_process_bump,
    [cib__op_create]      = cib_process_create,
    [cib__op_delete]      = cib_process_delete,
    [cib__op_erase]       = cib_process_erase,
    [cib__op_is_primary]  = cib_process_readwrite,
    [cib__op_modify]      = cib_process_modify,
    [cib__op_noop]        = cib_process_noop,
    [cib__op_ping]        = cib_process_ping,
    [cib__op_primary]     = cib_process_readwrite,
    [cib__op_query]       = cib_process_query,
    [cib__op_replace]     = cib_process_replace_svr,
    [cib__op_secondary]   = cib_process_readwrite,
    [cib__op_shutdown]    = cib_process_shutdown_req,
    [cib__op_sync_all]    = cib_process_sync,
    [cib__op_sync_one]    = cib_process_sync_one,
    [cib__op_upgrade]     = cib_process_upgrade_server,

    /* PCMK__CIB_REQUEST_*_TRANSACT requests must be processed locally because
     * they depend on the client table. Requests that manage transactions on
     * other nodes would likely be problematic in many other ways as well.
     */
    [cib__op_init_transact]    = cib_process_init_transaction,
    [cib__op_commit_transact]  = cib_process_commit_transaction,
    [cib__op_discard_transact] = cib_process_discard_transaction,
};

/*!
 * \internal
 * \brief Get the function that performs a given server-side CIB operation
 *
 * \param[in] operation  Operation whose function to look up
 *
 * \return Function that performs \p operation within \c pacemaker-based
 */
cib__op_fn_t
based_get_op_function(const cib__operation_t *operation)
{
    enum cib__op_type type = operation->type;

    CRM_ASSERT(type >= 0);

    if (type >= PCMK__NELEM(cib_op_functions)) {
        return NULL;
    }
    return cib_op_functions[type];
}

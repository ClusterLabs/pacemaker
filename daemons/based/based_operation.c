/*
 * Copyright 2008-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stddef.h>                 // NULL

#include <crm/cib/internal.h>       // cib__*
#include <crm/common/internal.h>    // pcmk__assert, PCMK__NELEM

#include "pacemaker-based.h"

static const cib__op_fn_t op_functions[] = {
    [cib__op_abs_delete]       = based_process_abs_delete,
    [cib__op_apply_patch]      = based_process_apply_patch,
    [cib__op_bump]             = cib__process_bump,
    [cib__op_commit_transact]  = based_process_commit_transact,
    [cib__op_create]           = cib__process_create,
    [cib__op_delete]           = cib__process_delete,
    [cib__op_erase]            = cib__process_erase,
    [cib__op_is_primary]       = based_process_is_primary,
    [cib__op_modify]           = cib__process_modify,
    [cib__op_noop]             = based_process_noop,
    [cib__op_ping]             = based_process_ping,
    [cib__op_primary]          = cib_process_readwrite,
    [cib__op_query]            = cib_process_query,
    [cib__op_replace]          = cib_process_replace_svr,
    [cib__op_secondary]        = cib_process_readwrite,
    [cib__op_shutdown]         = cib_process_shutdown_req,
    [cib__op_sync_all]         = cib_process_sync,
    [cib__op_sync_one]         = cib_process_sync_one,
    [cib__op_upgrade]          = cib_process_upgrade_server,
    [cib__op_schemas]          = cib_process_schemas,
};

/*!
 * \internal
 * \brief Get the function that performs a given server-side CIB operation
 *
 * \param[in] operation  Operation whose function to look up
 *
 * \return Function that performs \p operation within the CIB manager
 */
cib__op_fn_t
based_get_op_function(const cib__operation_t *operation)
{
    enum cib__op_type type = operation->type;

    pcmk__assert(type >= 0);

    if (type >= PCMK__NELEM(op_functions)) {
        return NULL;
    }
    return op_functions[type];
}

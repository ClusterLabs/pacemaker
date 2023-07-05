/*
 * Copyright 2008-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/cluster.h>

#include <crm/common/xml.h>

#include <pacemaker-based.h>

static const cib_operation_t cib_server_ops[] = {
    {
        PCMK__CIB_REQUEST_QUERY, cib__op_query,
        cib_op_attr_none,
        cib_process_query
    },
    {
        PCMK__CIB_REQUEST_MODIFY, cib__op_modify,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_process_modify
    },
    {
        PCMK__CIB_REQUEST_APPLY_PATCH, cib__op_apply_patch,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_server_process_diff
    },
    {
        PCMK__CIB_REQUEST_REPLACE, cib__op_replace,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_replaces
        |cib_op_attr_writes_through
        |cib_op_attr_transaction,
        cib_process_replace_svr
    },
    {
        PCMK__CIB_REQUEST_CREATE, cib__op_create,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_process_create
    },
    {
        PCMK__CIB_REQUEST_DELETE, cib__op_delete,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_process_delete
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ALL, cib__op_sync_all,
        cib_op_attr_privileged,
        cib_process_sync
    },
    {
        PCMK__CIB_REQUEST_BUMP, cib__op_bump,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_process_bump
    },
    {
        PCMK__CIB_REQUEST_ERASE, cib__op_erase,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_replaces
        |cib_op_attr_transaction,
        cib_process_erase
    },
    {
        PCMK__CIB_REQUEST_NOOP, cib__op_noop,
        cib_op_attr_none,
        cib_process_noop
    },
    {
        PCMK__CIB_REQUEST_ABS_DELETE, cib__op_abs_delete,
        cib_op_attr_modifies|cib_op_attr_privileged,
        cib_process_delete_absolute
    },
    {
        PCMK__CIB_REQUEST_UPGRADE, cib__op_upgrade,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_writes_through
        |cib_op_attr_transaction,
        cib_process_upgrade_server
    },
    {
        PCMK__CIB_REQUEST_SECONDARY, cib__op_secondary,
        cib_op_attr_privileged|cib_op_attr_local,
        cib_process_readwrite
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ONE, cib__op_sync_one,
        cib_op_attr_privileged,
        cib_process_sync_one
    },
    {
        // @COMPAT: Drop cib_op_attr_modifies when we drop legacy mode support
        PCMK__CIB_REQUEST_PRIMARY, cib__op_primary,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_local,
        cib_process_readwrite
    },
    {
        PCMK__CIB_REQUEST_IS_PRIMARY, cib__op_is_primary,
        cib_op_attr_privileged,
        cib_process_readwrite
    },
    {
        PCMK__CIB_REQUEST_SHUTDOWN, cib__op_shutdown,
        cib_op_attr_privileged,
        cib_process_shutdown_req
    },
    {
        CRM_OP_PING, cib__op_ping,
        cib_op_attr_none,
        cib_process_ping
    },

    /* PCMK__CIB_REQUEST_*_TRANSACT requests must be processed locally because
     * they depend on the client table. Requests that manage transactions on
     * other nodes would likely be problematic in many other ways as well.
     */
    {
        PCMK__CIB_REQUEST_INIT_TRANSACT, cib__op_init_transact,
        cib_op_attr_privileged|cib_op_attr_local,
        cib_process_init_transaction,
    },
    {
        PCMK__CIB_REQUEST_COMMIT_TRANSACT, cib__op_commit_transact,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_local
        |cib_op_attr_replaces
        |cib_op_attr_writes_through,
        cib_process_commit_transaction,
    },
    {
        PCMK__CIB_REQUEST_DISCARD_TRANSACT, cib__op_discard_transact,
        cib_op_attr_privileged|cib_op_attr_local,
        cib_process_discard_transaction,
    },
};

int
cib_get_operation(const char *op, const cib_operation_t **operation)
{
    static GHashTable *operation_hash = NULL;

    CRM_ASSERT((op != NULL) && (operation != NULL));

    if (operation_hash == NULL) {
        operation_hash = pcmk__strkey_table(NULL, NULL);

        for (int lpc = 0; lpc < PCMK__NELEM(cib_server_ops); lpc++) {
            const cib_operation_t *oper = &(cib_server_ops[lpc]);

            g_hash_table_insert(operation_hash, (gpointer) oper->name,
                                (gpointer) oper);
        }
    }

    *operation = g_hash_table_lookup(operation_hash, op);

    if (*operation == NULL) {
        crm_err("Operation %s is not valid", op);
        return -EINVAL;
    }
    return pcmk_ok;
}

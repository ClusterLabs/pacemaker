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

gboolean stand_alone = FALSE;

extern int cib_perform_command(xmlNode * request, xmlNode ** reply, xmlNode ** cib_diff,
                               gboolean privileged);

static xmlNode *
cib_prepare_common(xmlNode * root, const char *section)
{
    xmlNode *data = NULL;

    /* extract the CIB from the fragment */
    if (root == NULL) {
        return NULL;
    }

    if (pcmk__str_any_of(crm_element_name(root), F_CRM_DATA, F_CIB_CALLDATA,
                         NULL)) {
        data = first_named_child(root, XML_TAG_CIB);

    } else {
        data = root;
    }

    /* grab the section specified for the command */
    if (section != NULL && data != NULL && pcmk__str_eq(crm_element_name(data), XML_TAG_CIB, pcmk__str_none)) {
        data = pcmk_find_cib_element(data, section);
    }

    /* crm_log_xml_trace(root, "cib:input"); */
    return data;
}

static int
cib_prepare_none(xmlNode * request, xmlNode ** data, const char **section)
{
    *data = NULL;
    *section = crm_element_value(request, F_CIB_SECTION);
    return pcmk_ok;
}

static int
cib_prepare_data(xmlNode * request, xmlNode ** data, const char **section)
{
    xmlNode *input_fragment = get_message_xml(request, F_CIB_CALLDATA);

    *section = crm_element_value(request, F_CIB_SECTION);
    *data = cib_prepare_common(input_fragment, *section);
    /* crm_log_xml_debug(*data, "data"); */
    return pcmk_ok;
}

static int
cib_prepare_sync(xmlNode * request, xmlNode ** data, const char **section)
{
    *data = NULL;
    *section = crm_element_value(request, F_CIB_SECTION);
    return pcmk_ok;
}

static int
cib_prepare_diff(xmlNode * request, xmlNode ** data, const char **section)
{
    xmlNode *input_fragment = NULL;

    *data = NULL;
    *section = NULL;

    if (pcmk__xe_attr_is_true(request, F_CIB_GLOBAL_UPDATE)) {
        input_fragment = get_message_xml(request, F_CIB_UPDATE_DIFF);
    } else {
        input_fragment = get_message_xml(request, F_CIB_CALLDATA);
    }

    CRM_CHECK(input_fragment != NULL, crm_log_xml_warn(request, "no input"));
    *data = cib_prepare_common(input_fragment, NULL);
    return pcmk_ok;
}

static int
cib_cleanup_query(int options, xmlNode ** data, xmlNode ** output)
{
    CRM_LOG_ASSERT(*data == NULL);
    if (*output != the_cib) {
        free_xml(*output);
    }
    return pcmk_ok;
}

static int
cib_cleanup_data(int options, xmlNode ** data, xmlNode ** output)
{
    free_xml(*output);
    *data = NULL;
    return pcmk_ok;
}

static int
cib_cleanup_output(int options, xmlNode ** data, xmlNode ** output)
{
    free_xml(*output);
    return pcmk_ok;
}

static int
cib_cleanup_none(int options, xmlNode ** data, xmlNode ** output)
{
    CRM_LOG_ASSERT(*data == NULL);
    CRM_LOG_ASSERT(*output == NULL);
    return pcmk_ok;
}

static const cib_operation_t cib_server_ops[] = {
    {
        PCMK__CIB_REQUEST_QUERY,
        cib_op_attr_none,
        cib_prepare_none, cib_cleanup_query, cib_process_query
    },
    {
        PCMK__CIB_REQUEST_MODIFY,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_prepare_data, cib_cleanup_data, cib_process_modify
    },
    {
        PCMK__CIB_REQUEST_APPLY_PATCH,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_prepare_diff, cib_cleanup_data, cib_server_process_diff
    },
    {
        PCMK__CIB_REQUEST_REPLACE,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_replaces
        |cib_op_attr_writes_through
        |cib_op_attr_transaction,
        cib_prepare_data, cib_cleanup_data, cib_process_replace_svr
    },
    {
        PCMK__CIB_REQUEST_CREATE,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_prepare_data, cib_cleanup_data, cib_process_create
    },
    {
        PCMK__CIB_REQUEST_DELETE,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_prepare_data, cib_cleanup_data, cib_process_delete
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ALL,
        cib_op_attr_privileged,
        cib_prepare_sync, cib_cleanup_none, cib_process_sync
    },
    {
        PCMK__CIB_REQUEST_BUMP,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_transaction,
        cib_prepare_none, cib_cleanup_output, cib_process_bump
    },
    {
        PCMK__CIB_REQUEST_ERASE,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_replaces
        |cib_op_attr_transaction,
        cib_prepare_none, cib_cleanup_output, cib_process_erase
    },
    {
        PCMK__CIB_REQUEST_NOOP,
        cib_op_attr_none,
        cib_prepare_none, cib_cleanup_none, cib_process_noop
    },
    {
        PCMK__CIB_REQUEST_ABS_DELETE,
        cib_op_attr_modifies|cib_op_attr_privileged,
        cib_prepare_data, cib_cleanup_data, cib_process_delete_absolute
    },
    {
        PCMK__CIB_REQUEST_UPGRADE,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_writes_through
        |cib_op_attr_transaction,
        cib_prepare_none, cib_cleanup_output, cib_process_upgrade_server
    },
    {
        PCMK__CIB_REQUEST_SECONDARY,
        cib_op_attr_privileged|cib_op_attr_local,
        cib_prepare_none, cib_cleanup_none, cib_process_readwrite
    },
    {
        PCMK__CIB_REQUEST_SYNC_TO_ONE,
        cib_op_attr_privileged,
        cib_prepare_sync, cib_cleanup_none, cib_process_sync_one
    },
    {
        // @COMPAT: Drop cib_op_attr_modifies when we drop legacy mode support
        PCMK__CIB_REQUEST_PRIMARY,
        cib_op_attr_modifies|cib_op_attr_privileged|cib_op_attr_local,
        cib_prepare_data, cib_cleanup_data, cib_process_readwrite
    },
    {
        PCMK__CIB_REQUEST_IS_PRIMARY,
        cib_op_attr_privileged,
        cib_prepare_none, cib_cleanup_none, cib_process_readwrite
    },
    {
        PCMK__CIB_REQUEST_SHUTDOWN,
        cib_op_attr_privileged,
        cib_prepare_sync, cib_cleanup_none, cib_process_shutdown_req
    },
    {
        CRM_OP_PING,
        cib_op_attr_none,
        cib_prepare_none, cib_cleanup_output, cib_process_ping
    },

    /* PCMK__CIB_REQUEST_*_TRANSACT requests must be processed locally because
     * they depend on the client table. Requests that manage transactions on
     * other nodes would likely be problematic in many other ways as well.
     */
    {
        PCMK__CIB_REQUEST_INIT_TRANSACT,
        cib_op_attr_privileged|cib_op_attr_local,
        cib_prepare_none, cib_cleanup_none, cib_process_init_transaction,
    },
    {
        PCMK__CIB_REQUEST_COMMIT_TRANSACT,
        cib_op_attr_modifies
        |cib_op_attr_privileged
        |cib_op_attr_local
        |cib_op_attr_replaces
        |cib_op_attr_writes_through,
        cib_prepare_none, cib_cleanup_none, cib_process_commit_transaction,
    },
    {
        PCMK__CIB_REQUEST_DISCARD_TRANSACT,
        cib_op_attr_privileged|cib_op_attr_local,
        cib_prepare_none, cib_cleanup_none, cib_process_discard_transaction,
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

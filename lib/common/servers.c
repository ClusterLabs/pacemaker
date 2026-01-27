/*
 * Copyright 2024-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>      // NULL

#include <crm/crm.h>

/* Each Pacemaker subdaemon offers an IPC interface, and most exchange cluster
 * messages as well. Particular names need to be used for logging, connecting
 * IPC, and IPC/cluster message types.
 *
 * This array is indexed by enum pcmk_ipc_server and gathers all those names for
 * easier mapping. Most members are lists with the first value listed being the
 * "main" one returned if another value is mapped to it.
 *
 * @COMPAT Ideally, we'd use a single string (such as the server's
 * crm_system_name) as the sole IPC name and sole message type for each server,
 * making most of this unnecessary. However, backward compatiblity with older
 * nodes involved in a rolling upgrade or Pacemaker Remote connection would
 * be a nightmare: we'd have to add duplicate message attributes, struct
 * members, and libqb IPC server endpoints for both the old and new names, and
 * could drop the old names only after we no longer supported connections with
 * older nodes.
 *
 * @TODO It would be easy to use system_names[0] as a server's IPC name.
 * Everything would automatically use the new names except for proxied
 * connections from *older* Pacemaker Remote nodes. We would just have to map
 * the old names to the new names in remote_proxy_new(), the same as we're
 * currently mapping PCMK__SERVER_BASED_RO to PCMK__SERVER_BASED_RW there.
 */
static struct {
    const char *log_name;         // Readable server name for use in logs
    const char *system_names[2];  // crm_system_name values (subdaemon names)
    const char *ipc_name;         // libqb IPC name used to contact server
    const char *message_types[3]; // IPC/cluster message types sent to server
} server_info[] = {
    [pcmk_ipc_unknown] = {
        NULL,
        { NULL, NULL, },
        NULL,
        { NULL, NULL, NULL, },
    },

    [pcmk_ipc_attrd] = {
        "attribute manager",
        { PCMK__SERVER_ATTRD, NULL, },
        PCMK__VALUE_ATTRD,
        { PCMK__VALUE_ATTRD, NULL, NULL, },
    },

    [pcmk_ipc_based] = {
        "CIB manager",
        { PCMK__SERVER_BASED, NULL, },
        PCMK__SERVER_BASED_RW,
        { CRM_SYSTEM_CIB, NULL, NULL, },
    },

    [pcmk_ipc_controld] = {
        "controller",
        { PCMK__SERVER_CONTROLD, NULL, },
        PCMK__VALUE_CRMD,
        { PCMK__VALUE_CRMD, CRM_SYSTEM_DC, CRM_SYSTEM_TENGINE, },
    },

    [pcmk_ipc_execd] = {
        "executor",
        { PCMK__SERVER_EXECD, PCMK__SERVER_REMOTED, },
        PCMK__VALUE_LRMD,
        { PCMK__VALUE_LRMD, NULL, NULL, },
    },

    [pcmk_ipc_fenced] = {
        "fencer",
        { PCMK__SERVER_FENCED, NULL, },
        PCMK__VALUE_STONITH_NG,
        { PCMK__VALUE_STONITH_NG, NULL, NULL, },
    },

    [pcmk_ipc_pacemakerd] = {
        "launcher",
        { PCMK__SERVER_PACEMAKERD, NULL, },
        CRM_SYSTEM_MCP,
        { CRM_SYSTEM_MCP, NULL, NULL, },
    },

    [pcmk_ipc_schedulerd] = {
        "scheduler",
        { PCMK__SERVER_SCHEDULERD, NULL, },
        CRM_SYSTEM_PENGINE,
        { CRM_SYSTEM_PENGINE, NULL, NULL, },
    },
};

/*!
 * \internal
 * \brief Return server's (primary) system name
 *
 * \param[in] server  Server to get system name for
 *
 * \return System name for server (or NULL if invalid)
 * \note If \p server is an \c enum pcmk_ipc_server value other than
 *       \c pcmk_ipc_unknown, the return value is guaranteed to be non-NULL.
 */
const char *
pcmk__server_name(enum pcmk_ipc_server server)
{
    CRM_CHECK((server > 0) && (server < PCMK__NELEM(server_info)),
              return NULL);
    return server_info[server].system_names[0];
}

/*!
 * \internal
 * \brief Return a readable description of server for logging
 *
 * \param[in] server  Server to get log name for
 *
 * \return Log name for server (or NULL if invalid)
 * \note If \p server is an \c enum pcmk_ipc_server value other than
 *       \c pcmk_ipc_unknown, the return value is guaranteed to be non-NULL.
 */
const char *
pcmk__server_log_name(enum pcmk_ipc_server server)
{
    CRM_CHECK((server > 0) && (server < PCMK__NELEM(server_info)),
              return NULL);
    return server_info[server].log_name;
}

/*!
 * \internal
 * \brief Return the IPC endpoint name for a server
 *
 * \param[in] server  Server to get IPC endpoint for
 *
 * \return IPC endpoint for server (or NULL if invalid)
 * \note If \p server is an \c enum pcmk_ipc_server value other than
 *       \c pcmk_ipc_unknown, the return value is guaranteed to be non-NULL.
 */
const char *
pcmk__server_ipc_name(enum pcmk_ipc_server server)
{
    CRM_CHECK((server > 0) && (server < PCMK__NELEM(server_info)),
              return NULL);
    return server_info[server].ipc_name;
}

/*!
 * \internal
 * \brief Return the (primary) message type for a server
 *
 * \param[in] server  Server to get message type for
 *
 * \return Message type for server (or NULL if invalid)
 * \note If \p server is an \c enum pcmk_ipc_server value other than
 *       \c pcmk_ipc_unknown, the return value is guaranteed to be non-NULL.
 */
const char *
pcmk__server_message_type(enum pcmk_ipc_server server)
{
    CRM_CHECK((server > 0) && (server < PCMK__NELEM(server_info)),
              return NULL);
    return server_info[server].message_types[0];
}

/*!
 * \internal
 * \brief Get the server corresponding to a name
 *
 * \param[in] text  A system name, IPC endpoint name, or message type
 *
 * \return Server corresponding to \p text
 */
enum pcmk_ipc_server
pcmk__parse_server(const char *text)
{
    if (text == NULL) {
        return pcmk_ipc_unknown;
    }
    for (enum pcmk_ipc_server server = pcmk_ipc_attrd;
         server <= pcmk_ipc_schedulerd; ++server) {

        int name;

        for (name = 0;
             (name < 2) && (server_info[server].system_names[name] != NULL);
             ++name) {
            if (strcmp(text, server_info[server].system_names[name]) == 0) {
                return server;
            }
        }

        if (pcmk__str_eq(text, server_info[server].ipc_name, pcmk__str_none)) {
            return server;
        }

        for (name = 0;
             (name < 3) && (server_info[server].message_types[name] != NULL);
             ++name) {
            if (strcmp(text, server_info[server].message_types[name]) == 0) {
                return server;
            }
        }
    }
    return pcmk_ipc_unknown;
}

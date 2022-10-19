/*
 * Copyright 2018-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef PCMK__CRM_COMMON_MESSAGES_INTERNAL__H
#define PCMK__CRM_COMMON_MESSAGES_INTERNAL__H

#include <stdint.h>                         // uint32_t
#include <libxml/tree.h>                    // xmlNode
#include <crm/common/ipc_internal.h>        // pcmk__client_t
#include <crm/common/results_internal.h>    // pcmk__action_result_t

enum pcmk__request_flags {
    pcmk__request_none          = UINT32_C(0),

    /* It would be nice if we could check for synchronous requests generically,
     * but each daemon uses its own call options, so the daemons are responsible
     * for setting this flag when appropriate.
     */
    pcmk__request_sync          = (UINT32_C(1) << 0),

    /* Whether reply must use original call options (the library code does not
     * use this, so it is for internal daemon use)
     */
    pcmk__request_reuse_options = (UINT32_C(1) << 1),
};

// Server request (whether from an IPC client or cluster peer)
typedef struct {
    // If request is from an IPC client
    pcmk__client_t *ipc_client;     // IPC client (NULL if not via IPC)
    uint32_t ipc_id;                // IPC message ID
    uint32_t ipc_flags;             // IPC message flags

    // If message is from a cluster peer
    const char *peer;       // Peer name (NULL if not via cluster)

    // Common information regardless of origin
    xmlNode *xml;                   // Request XML
    int call_options;               // Call options set on request
    uint32_t flags;                 // Flag group of pcmk__request_flags
    pcmk__action_result_t result;   // Where to store operation result

    /* It would be nice if we could pull the IPC command from the XML
     * generically, but each daemon uses a different XML attribute for it,
     * so the daemon is responsible for populating this field.
     *
     * This must be a copy of the XML field, and not just a pointer into xml,
     * because handlers might modify the original XML.
     *
     * @TODO Create a per-daemon struct with IPC handlers, IPC endpoints, etc.,
     * and the name of the XML attribute for IPC commands, then replace this
     * with a convenience function to copy the command.
     */
    char *op;                       // IPC command name
} pcmk__request_t;

#define pcmk__set_request_flags(request, flags_to_set) do {         \
        (request)->flags = pcmk__set_flags_as(__func__, __LINE__,   \
        LOG_TRACE, "Request", "message", (request)->flags,          \
        (flags_to_set), #flags_to_set);                             \
    } while (0)

// Type for mapping a server command to a handler
typedef struct {
    const char *command;
    xmlNode *(*handler)(pcmk__request_t *request);
} pcmk__server_command_t;

const char *pcmk__message_name(const char *name);
GHashTable *pcmk__register_handlers(const pcmk__server_command_t handlers[]);
xmlNode *pcmk__process_request(pcmk__request_t *request, GHashTable *handlers);
void pcmk__reset_request(pcmk__request_t *request);

/*!
 * \internal
 * \brief Get a loggable description of a request's origin
 *
 * \param[in] request
 *
 * \return "peer" if request was via CPG, "client" if via IPC, or "originator"
 *         if unknown
 */
static inline const char *
pcmk__request_origin_type(const pcmk__request_t *request)
{
    if ((request != NULL) && (request->ipc_client != NULL)) {
        return "client";
    } else if ((request != NULL) && (request->peer != NULL)) {
        return "peer";
    } else {
        return "originator";
    }
}

/*!
 * \internal
 * \brief Get a loggable name for a request's origin
 *
 * \param[in] request
 *
 * \return Peer name if request was via CPG, client name if via IPC, or
 *         "(unspecified)" if unknown
 */
static inline const char *
pcmk__request_origin(const pcmk__request_t *request)
{
    if ((request != NULL) && (request->ipc_client != NULL)) {
        return pcmk__client_name(request->ipc_client);
    } else if ((request != NULL) && (request->peer != NULL)) {
        return request->peer;
    } else {
        return "(unspecified)";
    }
}

#endif // PCMK__CRM_COMMON_MESSAGES_INTERNAL__H

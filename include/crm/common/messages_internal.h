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

// Server request (whether from an IPC client or cluster peer)
typedef struct {
    // If request is from an IPC client
    pcmk__client_t *client;  // IPC client (NULL if not via IPC)
    uint32_t id;             // IPC message ID
    uint32_t flags;          // IPC message flags

    // If message is from a cluster peer
    const char *peer;       // Peer name (NULL if not via cluster)

    // Common information regardless of origin
    xmlNode *xml;                   // Request XML
    int call_options;               // Call options set on request
    pcmk__action_result_t result;   // Where to store operation result
} pcmk__request_t;

const char *pcmk__message_name(const char *name);

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
pcmk__request_origin_type(pcmk__request_t *request)
{
    if ((request != NULL) && (request->client != NULL)) {
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
pcmk__request_origin(pcmk__request_t *request)
{
    if ((request != NULL) && (request->client != NULL)) {
        return pcmk__client_name(request->client);
    } else if ((request != NULL) && (request->peer != NULL)) {
        return request->peer;
    } else {
        return "(unspecified)";
    }
}

#endif // PCMK__CRM_COMMON_MESSAGES_INTERNAL__H

/*
 * Copyright 2018-2024 the Pacemaker project contributors
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
#include <crm/common/xml_internal.h>        // pcmk__xml_copy()

#ifdef __cplusplus
extern "C" {
#endif

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

/*!
 * \internal
 * \brief Create message XML (for IPC or the cluster layer)
 *
 * Create standard, generic XML that can be used as a message sent via IPC or
 * the cluster layer. Currently, not all IPC and cluster layer messaging uses
 * this, but it should (eventually, keeping backward compatibility in mind).
 *
 * \param[in] server            Server whose protocol defines message semantics
 * \param[in] reply_to          If NULL, create message as a request with a
 *                              generated message ID, otherwise create message
 *                              as a reply to this message ID
 * \param[in] sender_system     Sender's subsystem (required; this is an
 *                              arbitrary string that may have meaning between
 *                              the sender and recipient)
 * \param[in] recipient_node    If not NULL, add as message's recipient node
 *                              (NULL typically indicates a broadcast message)
 * \param[in] recipient_system  If not NULL, add as message's recipient
 *                              subsystem (this is an arbitrary string that may
 *                              have meaning between the sender and recipient)
 * \param[in] task              Add as message's task (required)
 * \param[in] data              If not NULL, copy as message's data (callers
 *                              should not add attributes to the returned
 *                              message element, but instead pass any desired
 *                              information here, though this is not always
 *                              honored currently)
 *
 * \return Newly created message XML
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
#define pcmk__new_message(server, reply_to, sender_system,                  \
                          recipient_node, recipient_system, task, data)     \
    pcmk__new_message_as(__func__, (server), (reply_to),                    \
                         (sender_system), (recipient_node),                 \
                         (recipient_system), (task), (data))

/*!
 * \internal
 * \brief Create a Pacemaker reply (for IPC or cluster layer)
 *
 * \param[in] original_request  XML of request being replied to
 * \param[in] data              If not NULL, copy as reply's data (callers
 *                              should not add attributes to the returned
 *                              message element, but instead pass any desired
 *                              information here, though this is not always
 *                              honored currently)
 *
 * \return Newly created reply XML
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
#define pcmk__new_reply(original_request, data) \
    pcmk__new_reply_as(__func__, (original_request), (data))

xmlNode *pcmk__new_message_as(const char *origin, enum pcmk_ipc_server server,
                              const char *reply_to, const char *sender_system,
                              const char *recipient_node,
                              const char *recipient_system, const char *task,
                              xmlNode *data);

xmlNode *pcmk__new_reply_as(const char *origin, const xmlNode *original_request,
                            xmlNode *data);

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

#ifdef __cplusplus
}
#endif

#endif // PCMK__CRM_COMMON_MESSAGES_INTERNAL__H

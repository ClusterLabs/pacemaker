/*
 * Copyright 2004-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <time.h>                       // time()
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/common/xml.h>

/*!
 * \internal
 * \brief Create message XML (for IPC or the cluster layer)
 *
 * Create standard, generic XML that can be used as a message sent via IPC or
 * the cluster layer. Currently, not all IPC and cluster layer messaging uses
 * this, but it should (eventually, keeping backward compatibility in mind).
 *
 * \param[in] origin            Name of function that called this one (required)
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
 *
 * \note This function should usually not be called directly, but via the
 *       pcmk__new_message() wrapper.
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
xmlNode *
pcmk__new_message_as(const char *origin, enum pcmk_ipc_server server,
                     const char *reply_to, const char *sender_system,
                     const char *recipient_node, const char *recipient_system,
                     const char *task, xmlNode *data)
{
    static unsigned int message_counter = 0U;

    xmlNode *message = NULL;
    char *message_id = NULL;
    const char *subtype = PCMK__VALUE_RESPONSE;

    CRM_CHECK(!pcmk__str_empty(origin)
              && !pcmk__str_empty(sender_system)
              && !pcmk__str_empty(task),
              return NULL);

    if (reply_to == NULL) {
        subtype = PCMK__VALUE_REQUEST;
        message_id = pcmk__assert_asprintf("%s-%s-%llu-%u", task, sender_system,
                                           (unsigned long long) time(NULL),
                                           message_counter++);
        reply_to = message_id;
    }

    message = pcmk__xe_create(NULL, PCMK__XE_MESSAGE);
    pcmk__xe_set_props(message,
                       PCMK_XA_ORIGIN, origin,
                       PCMK__XA_T, pcmk__server_message_type(server),
                       PCMK__XA_SUBT, subtype,
                       PCMK_XA_VERSION, CRM_FEATURE_SET,
                       PCMK_XA_REFERENCE, reply_to,
                       PCMK__XA_CRM_SYS_FROM, sender_system,
                       PCMK__XA_CRM_HOST_TO, recipient_node,
                       PCMK__XA_CRM_SYS_TO, recipient_system,
                       PCMK__XA_CRM_TASK, task,
                       NULL);
    if (data != NULL) {
        xmlNode *wrapper = pcmk__xe_create(message, PCMK__XE_CRM_XML);

        pcmk__xml_copy(wrapper, data);
    }
    free(message_id);
    return message;
}

/*!
 * \internal
 * \brief Create a Pacemaker reply (for IPC or cluster layer)
 *
 * \param[in] origin            Name of function that called this one
 * \param[in] original_request  XML of request being replied to
 * \param[in] data              If not NULL, copy as reply's data (callers
 *                              should not add attributes to the returned
 *                              message element, but instead pass any desired
 *                              information here, though this is not always
 *                              honored currently)
 *
 * \return Newly created reply XML
 *
 * \note This function should not be called directly, but via the
 *       pcmk__new_reply() wrapper.
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
xmlNode *
pcmk__new_reply_as(const char *origin, const xmlNode *original_request,
                   xmlNode *data)
{
    const char *message_type = pcmk__xe_get(original_request, PCMK__XA_T);
    const char *host_from = pcmk__xe_get(original_request, PCMK__XA_SRC);
    const char *sys_from = pcmk__xe_get(original_request,
                                        PCMK__XA_CRM_SYS_FROM);
    const char *sys_to = pcmk__xe_get(original_request, PCMK__XA_CRM_SYS_TO);
    const char *type = pcmk__xe_get(original_request, PCMK__XA_SUBT);
    const char *operation = pcmk__xe_get(original_request, PCMK__XA_CRM_TASK);
    const char *crm_msg_reference = pcmk__xe_get(original_request,
                                                 PCMK_XA_REFERENCE);
    enum pcmk_ipc_server server = pcmk__parse_server(message_type);

    if (server == pcmk_ipc_unknown) {
        /* @COMPAT Not all requests currently specify a message type, so use a
         * default that preserves past behavior.
         *
         * @TODO Ensure all requests specify a message type, drop this check
         * after we no longer support rolling upgrades or Pacemaker Remote
         * connections involving versions before that.
         */
        server = pcmk_ipc_controld;
    }

    if (type == NULL) {
        pcmk__warn("Cannot reply to invalid message: No message type "
                   "specified");
        return NULL;
    }

    if (strcmp(type, PCMK__VALUE_REQUEST) != 0) {
        /* Replies should only be generated for request messages, but it's possible
         * we expect replies to other messages right now so this can't be enforced.
         */
        pcmk__trace("Creating a reply for a non-request original message");
    }

    // Since this is a reply, we reverse the sender and recipient info
    return pcmk__new_message_as(origin, server, crm_msg_reference, sys_to,
                                host_from, sys_from, operation, data);
}

/*!
 * \internal
 * \brief Register handlers for server commands
 *
 * \param[in] handlers  Array of handler functions for supported server commands
 *                      (the final entry must have a NULL command name, and if
 *                      it has a handler it will be used as the default handler
 *                      for unrecognized commands)
 *
 * \return Newly created hash table with commands and handlers
 * \note The caller is responsible for freeing the return value with
 *       g_hash_table_destroy().
 */
GHashTable *
pcmk__register_handlers(const pcmk__server_command_t handlers[])
{
    GHashTable *commands = g_hash_table_new(g_str_hash, g_str_equal);

    if (handlers != NULL) {
        int i;

        for (i = 0; handlers[i].command != NULL; ++i) {
            g_hash_table_insert(commands, (gpointer) handlers[i].command,
                                handlers[i].handler);
        }
        if (handlers[i].handler != NULL) {
            // g_str_hash() can't handle NULL, so use empty string for default
            g_hash_table_insert(commands, (gpointer) "", handlers[i].handler);
        }
    }
    return commands;
}

/*!
 * \internal
 * \brief Process an incoming request
 *
 * \param[in,out] request   Request to process
 * \param[in]     handlers  Command table created by pcmk__register_handlers()
 *
 * \return XML to send as reply (or NULL if no reply is needed)
 */
xmlNode *
pcmk__process_request(pcmk__request_t *request, GHashTable *handlers)
{
    xmlNode *(*handler)(pcmk__request_t *request) = NULL;

    CRM_CHECK((request != NULL) && (request->op != NULL) && (handlers != NULL),
              return NULL);

    if (pcmk__is_set(request->flags, pcmk__request_sync)
        && (request->ipc_client != NULL)) {
        CRM_CHECK(request->ipc_client->request_id == request->ipc_id,
                  return NULL);
    }

    handler = g_hash_table_lookup(handlers, request->op);
    if (handler == NULL) {
        handler = g_hash_table_lookup(handlers, ""); // Default handler
        if (handler == NULL) {
            pcmk__info("Ignoring %s request from %s %s with no handler",
                       request->op, pcmk__request_origin_type(request),
                       pcmk__request_origin(request));
            return NULL;
        }
    }

    return handler(request);
}

/*!
 * \internal
 * \brief Free memory used within a request (but not the request itself)
 *
 * \param[in,out] request  Request to reset
 */
void
pcmk__reset_request(pcmk__request_t *request)
{
    free(request->op);
    request->op = NULL;

    pcmk__reset_result(&(request->result));
}

/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
#include <crm/common/xml_internal.h>

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
        message_id = crm_strdup_printf("%s-%s-%llu-%u", task, sender_system,
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
 * \brief Create a Pacemaker request (for IPC or cluster layer)
 *
 * \param[in] task          What to set as the request's task
 * \param[in] msg_data      What to add as the request's data contents
 * \param[in] host_to       What to set as the request's destination host
 * \param[in] sys_to        What to set as the request's destination system
 * \param[in] sys_from      If not NULL, set as request's origin system
 * \param[in] uuid_from     If not NULL, use in request's origin system
 * \param[in] origin        Name of function that called this one
 *
 * \return XML of new request
 *
 * \note One of sys_from or uuid_from must be non-NULL
 * \note This function should not be called directly, but via the
 *       create_request() wrapper.
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
xmlNode *
create_request_adv(const char *task, xmlNode *msg_data,
                   const char *host_to, const char *sys_to,
                   const char *sys_from, const char *uuid_from,
                   const char *origin)
{
    char *true_from = NULL;
    xmlNode *request = NULL;

    if (uuid_from != NULL) {
        true_from = crm_strdup_printf("%s_%s", uuid_from,
                                      (sys_from? sys_from : "none"));
    } else if (sys_from != NULL) {
        true_from = strdup(sys_from);
    } else {
        crm_err("Cannot create IPC request: No originating system specified");
    }
    request = pcmk__new_message_as(origin, pcmk_ipc_controld, NULL, true_from,
                                   host_to, sys_to, task, msg_data);
    free(true_from);
    return request;
}

/*!
 * \brief Create a Pacemaker reply (for IPC or cluster layer)
 *
 * \param[in] original_request   XML of request this is a reply to
 * \param[in] xml_response_data  XML to copy as data section of reply
 * \param[in] origin             Name of function that called this one
 *
 * \return XML of new reply
 *
 * \note This function should not be called directly, but via the
 *       pcmk__new_reply() wrapper.
 * \note The caller is responsible for freeing the return value using
 *       \c pcmk__xml_free().
 */
xmlNode *
create_reply_adv(const xmlNode *original_request, xmlNode *xml_response_data,
                 const char *origin)
{
    const char *host_from = crm_element_value(original_request, PCMK__XA_SRC);
    const char *sys_from = crm_element_value(original_request,
                                             PCMK__XA_CRM_SYS_FROM);
    const char *sys_to = crm_element_value(original_request,
                                           PCMK__XA_CRM_SYS_TO);
    const char *type = crm_element_value(original_request, PCMK__XA_SUBT);
    const char *operation = crm_element_value(original_request,
                                              PCMK__XA_CRM_TASK);
    const char *crm_msg_reference = crm_element_value(original_request,
                                                      PCMK_XA_REFERENCE);

    if (type == NULL) {
        crm_err("Cannot create new_message, no message type in original message");
        CRM_ASSERT(type != NULL);
        return NULL;
    }

    if (strcmp(type, PCMK__VALUE_REQUEST) != 0) {
        /* Replies should only be generated for request messages, but it's possible
         * we expect replies to other messages right now so this can't be enforced.
         */
        crm_trace("Creating a reply for a non-request original message");
    }

    // Since this is a reply, we reverse the sender and recipient info
    return pcmk__new_message_as(origin, pcmk_ipc_controld, crm_msg_reference,
                                sys_to, host_from, sys_from, operation,
                                xml_response_data);
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

    if (pcmk_is_set(request->flags, pcmk__request_sync)
        && (request->ipc_client != NULL)) {
        CRM_CHECK(request->ipc_client->request_id == request->ipc_id,
                  return NULL);
    }

    handler = g_hash_table_lookup(handlers, request->op);
    if (handler == NULL) {
        handler = g_hash_table_lookup(handlers, ""); // Default handler
        if (handler == NULL) {
            crm_info("Ignoring %s request from %s %s with no handler",
                     request->op, pcmk__request_origin_type(request),
                     pcmk__request_origin(request));
            return NULL;
        }
    }

    return (*handler)(request);
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

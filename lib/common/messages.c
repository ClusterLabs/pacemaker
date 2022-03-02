/*
 * Copyright 2004-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>

#include <glib.h>
#include <libxml/tree.h>

#include <crm/msg_xml.h>
#include <crm/common/xml_internal.h>

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
 * \note The caller is responsible for freeing the result using free_xml().
 */
xmlNode *
create_request_adv(const char *task, xmlNode * msg_data,
                   const char *host_to, const char *sys_to,
                   const char *sys_from, const char *uuid_from,
                   const char *origin)
{
    static uint ref_counter = 0;

    char *true_from = NULL;
    xmlNode *request = NULL;
    char *reference = crm_strdup_printf("%s-%s-%lld-%u",
                                        (task? task : "_empty_"),
                                        (sys_from? sys_from : "_empty_"),
                                        (long long) time(NULL), ref_counter++);

    if (uuid_from != NULL) {
        true_from = crm_strdup_printf("%s_%s", uuid_from,
                                      (sys_from? sys_from : "none"));
    } else if (sys_from != NULL) {
        true_from = strdup(sys_from);
    } else {
        crm_err("Cannot create IPC request: No originating system specified");
    }

    // host_from will get set for us if necessary by the controller when routed
    request = create_xml_node(NULL, __func__);
    crm_xml_add(request, F_CRM_ORIGIN, origin);
    crm_xml_add(request, F_TYPE, T_CRM);
    crm_xml_add(request, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(request, F_CRM_MSG_TYPE, XML_ATTR_REQUEST);
    crm_xml_add(request, F_CRM_REFERENCE, reference);
    crm_xml_add(request, F_CRM_TASK, task);
    crm_xml_add(request, F_CRM_SYS_TO, sys_to);
    crm_xml_add(request, F_CRM_SYS_FROM, true_from);

    /* HOSTTO will be ignored if it is to the DC anyway. */
    if (host_to != NULL && strlen(host_to) > 0) {
        crm_xml_add(request, F_CRM_HOST_TO, host_to);
    }

    if (msg_data != NULL) {
        add_message_xml(request, F_CRM_DATA, msg_data);
    }
    free(reference);
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
 *       create_reply() wrapper.
 * \note The caller is responsible for freeing the result using free_xml().
 */
xmlNode *
create_reply_adv(xmlNode *original_request, xmlNode *xml_response_data,
                 const char *origin)
{
    xmlNode *reply = NULL;

    const char *host_from = crm_element_value(original_request, F_CRM_HOST_FROM);
    const char *sys_from = crm_element_value(original_request, F_CRM_SYS_FROM);
    const char *sys_to = crm_element_value(original_request, F_CRM_SYS_TO);
    const char *type = crm_element_value(original_request, F_CRM_MSG_TYPE);
    const char *operation = crm_element_value(original_request, F_CRM_TASK);
    const char *crm_msg_reference = crm_element_value(original_request, F_CRM_REFERENCE);

    if (type == NULL) {
        crm_err("Cannot create new_message, no message type in original message");
        CRM_ASSERT(type != NULL);
        return NULL;
#if 0
    } else if (strcasecmp(XML_ATTR_REQUEST, type) != 0) {
        crm_err("Cannot create new_message, original message was not a request");
        return NULL;
#endif
    }
    reply = create_xml_node(NULL, __func__);
    if (reply == NULL) {
        crm_err("Cannot create new_message, malloc failed");
        return NULL;
    }

    crm_xml_add(reply, F_CRM_ORIGIN, origin);
    crm_xml_add(reply, F_TYPE, T_CRM);
    crm_xml_add(reply, F_CRM_VERSION, CRM_FEATURE_SET);
    crm_xml_add(reply, F_CRM_MSG_TYPE, XML_ATTR_RESPONSE);
    crm_xml_add(reply, F_CRM_REFERENCE, crm_msg_reference);
    crm_xml_add(reply, F_CRM_TASK, operation);

    /* since this is a reply, we reverse the from and to */
    crm_xml_add(reply, F_CRM_SYS_TO, sys_from);
    crm_xml_add(reply, F_CRM_SYS_FROM, sys_to);

    /* HOSTTO will be ignored if it is to the DC anyway. */
    if (host_from != NULL && strlen(host_from) > 0) {
        crm_xml_add(reply, F_CRM_HOST_TO, host_from);
    }

    if (xml_response_data != NULL) {
        add_message_xml(reply, F_CRM_DATA, xml_response_data);
    }

    return reply;
}

xmlNode *
get_message_xml(xmlNode *msg, const char *field)
{
    xmlNode *tmp = first_named_child(msg, field);

    return pcmk__xml_first_child(tmp);
}

gboolean
add_message_xml(xmlNode *msg, const char *field, xmlNode *xml)
{
    xmlNode *holder = create_xml_node(msg, field);

    add_node_copy(holder, xml);
    return TRUE;
}

/*!
 * \brief Get name to be used as identifier for cluster messages
 *
 * \param[in] name  Actual system name to check
 *
 * \return Non-NULL cluster message identifier corresponding to name
 *
 * \note The Pacemaker daemons were renamed in version 2.0.0, but the old names
 *       must continue to be used as the identifier for cluster messages, so
 *       that mixed-version clusters are possible during a rolling upgrade.
 */
const char *
pcmk__message_name(const char *name)
{
    if (name == NULL) {
        return "unknown";

    } else if (!strcmp(name, "pacemaker-attrd")) {
        return "attrd";

    } else if (!strcmp(name, "pacemaker-based")) {
        return CRM_SYSTEM_CIB;

    } else if (!strcmp(name, "pacemaker-controld")) {
        return CRM_SYSTEM_CRMD;

    } else if (!strcmp(name, "pacemaker-execd")) {
        return CRM_SYSTEM_LRMD;

    } else if (!strcmp(name, "pacemaker-fenced")) {
        return "stonith-ng";

    } else if (!strcmp(name, "pacemaker-schedulerd")) {
        return CRM_SYSTEM_PENGINE;

    } else {
        return name;
    }
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
pcmk__register_handlers(pcmk__server_command_t *handlers)
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
 * \param[in] request   Request to process
 * \param[in] op        Operation type of request
 * \param[in] sync      Whether request is synchronous
 * \param[in] handlers  Command table created by pcmk__register_handlers()
 *
 * \return XML to send as reply (or NULL if no reply is needed)
 * \todo It would be nice if we could pull \p op from \p request->xml and
 *       \p sync from \p request->call_options, but the relevant identifiers are
 *       not currently standardized across daemons.
 */
xmlNode *
pcmk__process_request(pcmk__request_t *request, const char *op,
                      bool sync, GHashTable *handlers)
{
    xmlNode *(*handler)(pcmk__request_t *request) = NULL;

    CRM_CHECK((request != NULL) && (op != NULL) && (handlers != NULL),
              return NULL);

    if (sync && (request->ipc_client != NULL)) {
        CRM_CHECK(request->ipc_client->request_id == request->ipc_id,
                  return NULL);
    }

    handler = g_hash_table_lookup(handlers, op);
    if (handler == NULL) {
        handler = g_hash_table_lookup(handlers, ""); // Default handler
        if (handler == NULL) {
            crm_info("Ignoring %s request from %s %s with no handler",
                     op, pcmk__request_origin_type(request),
                     pcmk__request_origin(request));
            return NULL;
        }
    }

    return (*handler)(request);
}

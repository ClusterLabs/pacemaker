/*
 * Copyright 2004-2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <sys/types.h>

#include <crm/msg_xml.h>

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
        true_from = generate_hash_key(sys_from, uuid_from);
    } else if (sys_from != NULL) {
        true_from = strdup(sys_from);
    } else {
        crm_err("No sys from specified");
    }

    // host_from will get set for us if necessary by the controller when routed
    request = create_xml_node(NULL, __FUNCTION__);
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
    reply = create_xml_node(NULL, __FUNCTION__);
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

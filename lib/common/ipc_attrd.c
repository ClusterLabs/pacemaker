/*
 * Copyright 2011-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <crm_internal.h>

#include <stdio.h>

#include <crm/crm.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_attrd_internal.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/attrd_internal.h>
#include <crm/msg_xml.h>
#include "crmcommon_private.h"

static void
set_pairs_data(pcmk__attrd_api_reply_t *data, xmlNode *msg_data)
{
    const char *name = NULL;
    pcmk__attrd_query_pair_t *pair;

    name = crm_element_value(msg_data, PCMK__XA_ATTR_NAME);

    for (xmlNode *node = first_named_child(msg_data, XML_CIB_TAG_NODE);
         node != NULL; node = crm_next_same_xml(node)) {
        pair = calloc(1, sizeof(pcmk__attrd_query_pair_t));

        CRM_ASSERT(pair != NULL);

        pair->node = crm_element_value(node, PCMK__XA_ATTR_NODE_NAME);
        pair->name = name;
        pair->value = crm_element_value(node, PCMK__XA_ATTR_VALUE);
        data->data.pairs = g_list_prepend(data->data.pairs, pair);
    }
}

static bool
reply_expected(pcmk_ipc_api_t *api, xmlNode *request)
{
    const char *command = crm_element_value(request, PCMK__XA_TASK);

    /* Only the query command gets a reply. */
    return pcmk__str_any_of(command, PCMK__ATTRD_CMD_QUERY, NULL);
}

static bool
dispatch(pcmk_ipc_api_t *api, xmlNode *reply)
{
    const char *value = NULL;
    crm_exit_t status = CRM_EX_OK;

    pcmk__attrd_api_reply_t reply_data = {
        pcmk__attrd_reply_unknown
    };

    if (pcmk__str_eq((const char *) reply->name, "ack", pcmk__str_none)) {
        return false;
    }

    /* Do some basic validation of the reply */
    value = crm_element_value(reply, F_TYPE);
    if (value == NULL || !pcmk__str_eq(value, T_ATTRD, pcmk__str_none)) {
        crm_debug("Unrecognizable attrd message: invalid message type '%s'",
                  crm_str(value));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    /* Only the query command gets a reply for now. */
    value = crm_element_value(reply, F_SUBTYPE);
    if (pcmk__str_eq(value, PCMK__ATTRD_CMD_QUERY, pcmk__str_null_matches)) {
        /* This likely means the client gave us an attribute name that doesn't
         * exist.
         */
        if (!xmlHasProp(reply, (pcmkXmlStr) PCMK__XA_ATTR_NAME)) {
            crm_debug("Empty attrd message: no attribute name");
            status = ENXIO;
            goto done;
        }

        reply_data.reply_type = pcmk__attrd_reply_query;

        set_pairs_data(&reply_data, reply);
    } else {
        crm_debug("Cannot handle a reply from message type '%s'",
                  crm_str(value));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

done:
    pcmk__call_ipc_callback(api, pcmk_ipc_event_reply, status, &reply_data);

    /* Free any reply data that was allocated */
    if (reply_data.data.pairs) {
        g_list_free_full(reply_data.data.pairs, free);
    }

    return false;
}

pcmk__ipc_methods_t *
pcmk__attrd_api_methods()
{
    pcmk__ipc_methods_t *cmds = calloc(1, sizeof(pcmk__ipc_methods_t));

    if (cmds != NULL) {
        cmds->new_data = NULL;
        cmds->free_data = NULL;
        cmds->post_connect = NULL;
        cmds->reply_expected = reply_expected;
        cmds->dispatch = dispatch;
    }
    return cmds;
}

/*!
 * \internal
 * \brief Create a generic pacemaker-attrd operation
 *
 * \param[in] user_name  If not NULL, ACL user to set for operation
 *
 * \return XML of pacemaker-attrd operation
 */
static xmlNode *
create_attrd_op(const char *user_name)
{
    xmlNode *attrd_op = create_xml_node(NULL, __func__);

    crm_xml_add(attrd_op, F_TYPE, T_ATTRD);
    crm_xml_add(attrd_op, F_ORIG, (crm_system_name? crm_system_name: "unknown"));
    crm_xml_add(attrd_op, PCMK__XA_ATTR_USER, user_name);

    return attrd_op;
}

static int
send_attrd_request(pcmk_ipc_api_t *api, xmlNode *request)
{
    return pcmk__send_ipc_request(api, request);
}

int
pcmk__attrd_api_delete(pcmk_ipc_api_t *api, const char *node, const char *name,
                       uint32_t options)
{
    if (name == NULL) {
        return EINVAL;
    }

    /* Make sure the right update option is set. */
    options &= ~pcmk__node_attr_delay;
    options |= pcmk__node_attr_value;

    return pcmk__attrd_api_update(api, node, name, NULL, NULL, NULL, NULL, options);
}

int
pcmk__attrd_api_query(pcmk_ipc_api_t *api, const char *node, const char *name,
                      uint32_t options)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;

    if (name == NULL) {
        return EINVAL;
    }

    request = create_attrd_op(NULL);

    crm_xml_add(request, PCMK__XA_ATTR_NAME, name);
    crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_QUERY);
    crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node);

    rc = send_attrd_request(api, request);
    free_xml(request);

    if (node) {
        crm_debug("Queried pacemaker-attrd for %s on %s: %s (%d)",
                  name, node, pcmk_rc_str(rc), rc);
    } else {
        crm_debug("Queried pacemaker-attrd for %s: %s (%d)",
                  name, pcmk_rc_str(rc), rc);
    }

    return rc;
}

int
pcmk__attrd_api_refresh(pcmk_ipc_api_t *api, const char *node)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;
    const char *display_host = (node ? node : "localhost");

    request = create_attrd_op(NULL);

    crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_REFRESH);
    crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node);

    rc = send_attrd_request(api, request);
    free_xml(request);

    crm_debug("Asked pacemaker-attrd to refresh %s: %s (%d)",
              display_host, pcmk_rc_str(rc), rc);

    return rc;
}

int
pcmk__attrd_api_update(pcmk_ipc_api_t *api, const char *node, const char *name,
                       const char *value, const char *dampen, const char *set,
                       const char *user_name, uint32_t options)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;
    const char *display_host = (node ? node : "localhost");

    if (name == NULL) {
        return EINVAL;
    }

    request = create_attrd_op(user_name);

    if (pcmk_is_set(options, pcmk__node_attr_pattern)) {
        crm_xml_add(request, PCMK__XA_ATTR_PATTERN, name);
    } else {
        crm_xml_add(request, PCMK__XA_ATTR_NAME, name);
    }

    if (pcmk_all_flags_set(options, pcmk__node_attr_value | pcmk__node_attr_delay)) {
        crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE_BOTH);
    } else if (pcmk_is_set(options, pcmk__node_attr_value)) {
        crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    } else if (pcmk_is_set(options, pcmk__node_attr_delay)) {
        crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE_DELAY);
    }

    crm_xml_add(request, PCMK__XA_ATTR_VALUE, value);
    crm_xml_add(request, PCMK__XA_ATTR_DAMPENING, dampen);
    crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node);
    crm_xml_add(request, PCMK__XA_ATTR_SET, set);
    crm_xml_add_int(request, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));
    crm_xml_add_int(request, PCMK__XA_ATTR_IS_PRIVATE,
                    pcmk_is_set(options, pcmk__node_attr_private));

    rc = send_attrd_request(api, request);
    free_xml(request);

    crm_debug("Asked pacemaker-attrd to update %s on %s: %s (%d)",
              name, display_host, pcmk_rc_str(rc), rc);

    return rc;
}

/*!
 * \internal
 * \brief Send an operation to pacemaker-attrd via IPC
 *
 * \param[in] ipc       Connection to pacemaker-attrd (or create one if NULL)
 * \param[in] attrd_op  XML of pacemaker-attrd operation to send
 *
 * \return Standard Pacemaker return code
 */
static int
send_attrd_op(crm_ipc_t *ipc, xmlNode *attrd_op)
{
    int rc = -ENOTCONN; // initially handled as legacy return code
    int max = 5;

    static gboolean connected = TRUE;
    static crm_ipc_t *local_ipc = NULL;
    static enum crm_ipc_flags flags = crm_ipc_flags_none;

    if (ipc == NULL && local_ipc == NULL) {
        local_ipc = crm_ipc_new(T_ATTRD, 0);
        pcmk__set_ipc_flags(flags, "client", crm_ipc_client_response);
        connected = FALSE;
    }

    if (ipc == NULL) {
        ipc = local_ipc;
    }

    while (max > 0) {
        if (connected == FALSE) {
            crm_info("Connecting to cluster... %d retries remaining", max);
            connected = crm_ipc_connect(ipc);
        }

        if (connected) {
            rc = crm_ipc_send(ipc, attrd_op, flags, 0, NULL);
        } else {
            crm_perror(LOG_INFO, "Connection to cluster attribute manager failed");
        }

        if (ipc != local_ipc) {
            break;

        } else if (rc > 0) {
            break;

        } else if (rc == -EAGAIN || rc == -EALREADY) {
            sleep(5 - max);
            max--;

        } else {
            crm_ipc_close(ipc);
            connected = FALSE;
            sleep(5 - max);
            max--;
        }
    }

    if (rc > 0) {
        rc = pcmk_ok;
    }
    return pcmk_legacy2rc(rc);
}

/*!
 * \internal
 * \brief Send a request to pacemaker-attrd
 *
 * \param[in] ipc      Connection to pacemaker-attrd (or NULL to use a local connection)
 * \param[in] command  A character indicating the type of pacemaker-attrd request:
 *                     U or v: update attribute (or refresh if name is NULL)
 *                     u: update attributes matching regular expression in name
 *                     D: delete attribute (value must be NULL)
 *                     R: refresh
 *                     B: update both attribute and its dampening
 *                     Y: update attribute dampening only
 *                     Q: query attribute
 *                     C: remove peer specified by host
 * \param[in] host     Affect only this host (or NULL for all hosts)
 * \param[in] name     Name of attribute to affect
 * \param[in] value    Attribute value to set
 * \param[in] section  Status or nodes
 * \param[in] set      ID of attribute set to use (or NULL to choose first)
 * \param[in] dampen   Attribute dampening to use with B/Y, and U/v if creating
 * \param[in] user_name ACL user to pass to pacemaker-attrd
 * \param[in] options  Bitmask of pcmk__node_attr_opts
 *
 * \return Standard Pacemaker return code
 */
int
pcmk__node_attr_request(crm_ipc_t *ipc, char command, const char *host,
                        const char *name, const char *value,
                        const char *section, const char *set,
                        const char *dampen, const char *user_name, int options)
{
    int rc = pcmk_rc_ok;
    const char *task = NULL;
    const char *name_as = NULL;
    const char *display_host = (host ? host : "localhost");
    const char *display_command = NULL; /* for commands without name/value */
    xmlNode *update = create_attrd_op(user_name);

    /* remap common aliases */
    if (pcmk__str_eq(section, "reboot", pcmk__str_casei)) {
        section = XML_CIB_TAG_STATUS;

    } else if (pcmk__str_eq(section, "forever", pcmk__str_casei)) {
        section = XML_CIB_TAG_NODES;
    }

    if (name == NULL && command == 'U') {
        command = 'R';
    }

    switch (command) {
        case 'u':
            task = PCMK__ATTRD_CMD_UPDATE;
            name_as = PCMK__XA_ATTR_PATTERN;
            break;
        case 'D':
        case 'U':
        case 'v':
            task = PCMK__ATTRD_CMD_UPDATE;
            name_as = PCMK__XA_ATTR_NAME;
            break;
        case 'R':
            task = PCMK__ATTRD_CMD_REFRESH;
            display_command = "refresh";
            break;
        case 'B':
            task = PCMK__ATTRD_CMD_UPDATE_BOTH;
            name_as = PCMK__XA_ATTR_NAME;
            break;
        case 'Y':
            task = PCMK__ATTRD_CMD_UPDATE_DELAY;
            name_as = PCMK__XA_ATTR_NAME;
            break;
        case 'Q':
            task = PCMK__ATTRD_CMD_QUERY;
            name_as = PCMK__XA_ATTR_NAME;
            break;
        case 'C':
            task = PCMK__ATTRD_CMD_PEER_REMOVE;
            display_command = "purge";
            break;
    }

    if (name_as != NULL) {
        if (name == NULL) {
            rc = EINVAL;
            goto done;
        }
        crm_xml_add(update, name_as, name);
    }

    crm_xml_add(update, PCMK__XA_TASK, task);
    crm_xml_add(update, PCMK__XA_ATTR_VALUE, value);
    crm_xml_add(update, PCMK__XA_ATTR_DAMPENING, dampen);
    crm_xml_add(update, PCMK__XA_ATTR_SECTION, section);
    crm_xml_add(update, PCMK__XA_ATTR_NODE_NAME, host);
    crm_xml_add(update, PCMK__XA_ATTR_SET, set);
    crm_xml_add_int(update, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));
    crm_xml_add_int(update, PCMK__XA_ATTR_IS_PRIVATE,
                    pcmk_is_set(options, pcmk__node_attr_private));

    rc = send_attrd_op(ipc, update);

done:
    free_xml(update);

    if (display_command) {
        crm_debug("Asked pacemaker-attrd to %s %s: %s (%d)",
                  display_command, display_host, pcmk_rc_str(rc), rc);
    } else {
        crm_debug("Asked pacemaker-attrd to update %s=%s for %s: %s (%d)",
                  name, value, display_host, pcmk_rc_str(rc), rc);
    }
    return rc;
}

/*!
 * \internal
 * \brief Send a request to pacemaker-attrd to clear resource failure
 *
 * \param[in] ipc           Connection to pacemaker-attrd (NULL to use local connection)
 * \param[in] host          Affect only this host (or NULL for all hosts)
 * \param[in] resource      Name of resource to clear (or NULL for all)
 * \param[in] operation     Name of operation to clear (or NULL for all)
 * \param[in] interval_spec If operation is not NULL, its interval
 * \param[in] user_name     ACL user to pass to pacemaker-attrd
 * \param[in] options       Bitmask of pcmk__node_attr_opts
 *
 * \return pcmk_ok if request was successfully submitted to pacemaker-attrd, else -errno
 */
int
pcmk__node_attr_request_clear(crm_ipc_t *ipc, const char *host,
                              const char *resource, const char *operation,
                              const char *interval_spec, const char *user_name,
                              int options)
{
    int rc = pcmk_rc_ok;
    xmlNode *clear_op = create_attrd_op(user_name);
    const char *interval_desc = NULL;
    const char *op_desc = NULL;

    crm_xml_add(clear_op, PCMK__XA_TASK, PCMK__ATTRD_CMD_CLEAR_FAILURE);
    crm_xml_add(clear_op, PCMK__XA_ATTR_NODE_NAME, host);
    crm_xml_add(clear_op, PCMK__XA_ATTR_RESOURCE, resource);
    crm_xml_add(clear_op, PCMK__XA_ATTR_OPERATION, operation);
    crm_xml_add(clear_op, PCMK__XA_ATTR_INTERVAL, interval_spec);
    crm_xml_add_int(clear_op, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));

    rc = send_attrd_op(ipc, clear_op);
    free_xml(clear_op);

    if (operation) {
        interval_desc = interval_spec? interval_spec : "nonrecurring";
        op_desc = operation;
    } else {
        interval_desc = "all";
        op_desc = "operations";
    }
    crm_debug("Asked pacemaker-attrd to clear failure of %s %s for %s on %s: %s (%d)",
              interval_desc, op_desc, (resource? resource : "all resources"),
              (host? host : "all nodes"), pcmk_rc_str(rc), rc);
    return rc;
}

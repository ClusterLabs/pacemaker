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

    return pcmk__str_any_of(command, PCMK__ATTRD_CMD_UPDATE,
                            PCMK__ATTRD_CMD_UPDATE_BOTH, PCMK__ATTRD_CMD_UPDATE_DELAY,
                            PCMK__ATTRD_CMD_QUERY, NULL);
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
    if (value == NULL) {
        crm_debug("Unrecognizable attrd message: no message type specified");
        status = CRM_EX_PROTOCOL;
        goto done;
    }
    if (!pcmk__str_eq(value, T_ATTRD, pcmk__str_none)) {
        crm_debug("Unrecognizable attrd message: invalid message type '%s'",
                  value);
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
                  pcmk__s(value, "(unspecified)"));
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
connect_and_send_attrd_request(xmlNode *request)
{
    pcmk_ipc_api_t *api = NULL;
    int rc = pcmk_rc_ok;
    int max = 5;

    rc = pcmk_new_ipc_api(&api, pcmk_ipc_attrd);
    if (rc != pcmk_rc_ok) {
        crm_err("error: Could not connect to attrd: %s", pcmk_rc_str(rc));
        return ENOTCONN;
    }

    while (max > 0) {
        crm_info("Connecting to cluster... %d retries remaining", max);
        rc = pcmk_connect_ipc(api, pcmk_ipc_dispatch_sync);

        if (rc == pcmk_rc_ok) {
            rc = pcmk__send_ipc_request(api, request);
            pcmk_disconnect_ipc(api);
            pcmk_free_ipc_api(api);
            api = NULL;
            break;
        } else if (rc == EAGAIN || rc == EALREADY) {
            sleep(5 - max);
            max--;
        } else {
            crm_err("error: Could not connect to attrd: %s", pcmk_rc_str(rc));
            break;
        }
    }

    return rc;
}

static int
send_attrd_request(pcmk_ipc_api_t *api, xmlNode *request)
{
    return pcmk__send_ipc_request(api, request);
}

int
pcmk__attrd_api_clear_failures(pcmk_ipc_api_t *api, const char *node,
                               const char *resource, const char *operation,
                               const char *interval_spec, const char *user_name,
                               uint32_t options)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = create_attrd_op(user_name);
    const char *interval_desc = NULL;
    const char *op_desc = NULL;
    const char *target = pcmk__node_attr_target(node);

    if (target != NULL) {
        node = target;
    }

    crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_CLEAR_FAILURE);
    crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node);
    crm_xml_add(request, PCMK__XA_ATTR_RESOURCE, resource);
    crm_xml_add(request, PCMK__XA_ATTR_OPERATION, operation);
    crm_xml_add(request, PCMK__XA_ATTR_INTERVAL, interval_spec);
    crm_xml_add_int(request, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));

    if (api == NULL) {
        rc = connect_and_send_attrd_request(request);
    } else {
        rc = send_attrd_request(api, request);
    }

    free_xml(request);

    if (operation) {
        interval_desc = interval_spec? interval_spec : "nonrecurring";
        op_desc = operation;
    } else {
        interval_desc = "all";
        op_desc = "operations";
    }

    crm_debug("Asked pacemaker-attrd to clear failure of %s %s for %s on %s: %s (%d)",
              interval_desc, op_desc, (resource? resource : "all resources"),
              (node? node : "all nodes"), pcmk_rc_str(rc), rc);

    return rc;
}

int
pcmk__attrd_api_delete(pcmk_ipc_api_t *api, const char *node, const char *name,
                       uint32_t options)
{
    const char *target = NULL;

    if (name == NULL) {
        return EINVAL;
    }

    target = pcmk__node_attr_target(node);

    if (target != NULL) {
        node = target;
    }

    /* Make sure the right update option is set. */
    options &= ~pcmk__node_attr_delay;
    options |= pcmk__node_attr_value;

    return pcmk__attrd_api_update(api, node, name, NULL, NULL, NULL, NULL, options);
}

int
pcmk__attrd_api_purge(pcmk_ipc_api_t *api, const char *node)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;
    const char *display_host = (node ? node : "localhost");
    const char *target = pcmk__node_attr_target(node);

    if (target != NULL) {
        node = target;
    }

    request = create_attrd_op(NULL);

    crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_PEER_REMOVE);
    crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node);

    if (api == NULL) {
        rc = connect_and_send_attrd_request(request);
    } else {
        rc = send_attrd_request(api, request);
    }

    free_xml(request);

    crm_debug("Asked pacemaker-attrd to purge %s: %s (%d)",
              display_host, pcmk_rc_str(rc), rc);

    return rc;
}

int
pcmk__attrd_api_query(pcmk_ipc_api_t *api, const char *node, const char *name,
                      uint32_t options)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;
    const char *target = NULL;

    if (name == NULL) {
        return EINVAL;
    }

    target = pcmk__node_attr_target(node);

    if (target != NULL) {
        node = target;
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
    const char *target = pcmk__node_attr_target(node);

    if (target != NULL) {
        node = target;
    }

    request = create_attrd_op(NULL);

    crm_xml_add(request, PCMK__XA_TASK, PCMK__ATTRD_CMD_REFRESH);
    crm_xml_add(request, PCMK__XA_ATTR_NODE_NAME, node);

    if (api == NULL) {
        rc = connect_and_send_attrd_request(request);
    } else {
        rc = send_attrd_request(api, request);
    }

    free_xml(request);

    crm_debug("Asked pacemaker-attrd to refresh %s: %s (%d)",
              display_host, pcmk_rc_str(rc), rc);

    return rc;
}

static void
add_op_attr(xmlNode *op, uint32_t options)
{
    if (pcmk_all_flags_set(options, pcmk__node_attr_value | pcmk__node_attr_delay)) {
        crm_xml_add(op, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE_BOTH);
    } else if (pcmk_is_set(options, pcmk__node_attr_value)) {
        crm_xml_add(op, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE);
    } else if (pcmk_is_set(options, pcmk__node_attr_delay)) {
        crm_xml_add(op, PCMK__XA_TASK, PCMK__ATTRD_CMD_UPDATE_DELAY);
    }
}

static void
populate_update_op(xmlNode *op, const char *node, const char *name, const char *value,
                   const char *dampen, const char *set, uint32_t options)
{
    if (pcmk_is_set(options, pcmk__node_attr_pattern)) {
        crm_xml_add(op, PCMK__XA_ATTR_PATTERN, name);
    } else {
        crm_xml_add(op, PCMK__XA_ATTR_NAME, name);
    }

    add_op_attr(op, options);

    crm_xml_add(op, PCMK__XA_ATTR_VALUE, value);
    crm_xml_add(op, PCMK__XA_ATTR_DAMPENING, dampen);
    crm_xml_add(op, PCMK__XA_ATTR_NODE_NAME, node);
    crm_xml_add(op, PCMK__XA_ATTR_SET, set);
    crm_xml_add_int(op, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));
    crm_xml_add_int(op, PCMK__XA_ATTR_IS_PRIVATE,
                    pcmk_is_set(options, pcmk__node_attr_private));
}

int
pcmk__attrd_api_update(pcmk_ipc_api_t *api, const char *node, const char *name,
                       const char *value, const char *dampen, const char *set,
                       const char *user_name, uint32_t options)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;
    const char *display_host = (node ? node : "localhost");
    const char *target = NULL;

    if (name == NULL) {
        return EINVAL;
    }

    target = pcmk__node_attr_target(node);

    if (target != NULL) {
        node = target;
    }

    request = create_attrd_op(user_name);
    populate_update_op(request, node, name, value, dampen, set, options);

    if (api == NULL) {
        rc = connect_and_send_attrd_request(request);
    } else {
        rc = send_attrd_request(api, request);
    }

    free_xml(request);

    crm_debug("Asked pacemaker-attrd to update %s on %s: %s (%d)",
              name, display_host, pcmk_rc_str(rc), rc);

    return rc;
}

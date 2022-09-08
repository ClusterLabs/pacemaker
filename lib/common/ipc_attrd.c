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

    return pcmk__str_any_of(command,
                            PCMK__ATTRD_CMD_QUERY,
                            PCMK__ATTRD_CMD_REFRESH,
                            PCMK__ATTRD_CMD_UPDATE,
                            PCMK__ATTRD_CMD_UPDATE_BOTH,
                            PCMK__ATTRD_CMD_UPDATE_DELAY,
                            NULL);
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
    if (pcmk__str_empty(value)
        || !pcmk__str_eq(value, T_ATTRD, pcmk__str_none)) {
        crm_info("Unrecognizable message from attribute manager: "
                 "message type '%s' not '" T_ATTRD "'", pcmk__s(value, ""));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    value = crm_element_value(reply, F_SUBTYPE);

    /* Only the query command gets a reply for now. NULL counts as query for
     * backward compatibility with attribute managers <2.1.3 that didn't set it.
     */
    if (pcmk__str_eq(value, PCMK__ATTRD_CMD_QUERY, pcmk__str_null_matches)) {
        if (!xmlHasProp(reply, (pcmkXmlStr) PCMK__XA_ATTR_NAME)) {
            status = ENXIO; // Most likely, the attribute doesn't exist
            goto done;
        }
        reply_data.reply_type = pcmk__attrd_reply_query;
        set_pairs_data(&reply_data, reply);

    } else {
        crm_info("Unrecognizable message from attribute manager: "
                 "message subtype '%s' unknown", pcmk__s(value, ""));
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
pcmk__attrd_api_methods(void)
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
create_api(pcmk_ipc_api_t **api)
{
    int rc = pcmk_new_ipc_api(api, pcmk_ipc_attrd);

    if (rc != pcmk_rc_ok) {
        crm_err("Could not connect to attrd: %s", pcmk_rc_str(rc));
    }

    return rc;
}

static void
destroy_api(pcmk_ipc_api_t *api)
{
    pcmk_disconnect_ipc(api);
    pcmk_free_ipc_api(api);
    api = NULL;
}

static int
connect_and_send_attrd_request(pcmk_ipc_api_t *api, xmlNode *request)
{
    int rc = pcmk_rc_ok;
    int max = 5;

    while (max > 0) {
        crm_info("Connecting to cluster... %d retries remaining", max);
        rc = pcmk_connect_ipc(api, pcmk_ipc_dispatch_sync);

        if (rc == pcmk_rc_ok) {
            rc = pcmk__send_ipc_request(api, request);
            break;
        } else if (rc == EAGAIN || rc == EALREADY) {
            sleep(5 - max);
            max--;
        } else {
            crm_err("Could not connect to attrd: %s", pcmk_rc_str(rc));
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
    pcmk__xe_add_node(request, node, 0);
    crm_xml_add(request, PCMK__XA_ATTR_RESOURCE, resource);
    crm_xml_add(request, PCMK__XA_ATTR_OPERATION, operation);
    crm_xml_add(request, PCMK__XA_ATTR_INTERVAL, interval_spec);
    crm_xml_add_int(request, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));

    if (api == NULL) {
        rc = create_api(&api);
        if (rc != pcmk_rc_ok) {
            return rc;
        }

        rc = connect_and_send_attrd_request(api, request);
        destroy_api(api);

    } else if (!pcmk_ipc_is_connected(api)) {
        rc = connect_and_send_attrd_request(api, request);

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
    pcmk__xe_add_node(request, node, 0);

    if (api == NULL) {
        rc = create_api(&api);
        if (rc != pcmk_rc_ok) {
            return rc;
        }

        rc = connect_and_send_attrd_request(api, request);
        destroy_api(api);

    } else if (!pcmk_ipc_is_connected(api)) {
        rc = connect_and_send_attrd_request(api, request);

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
    pcmk__xe_add_node(request, node, 0);

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
    pcmk__xe_add_node(request, node, 0);

    if (api == NULL) {
        rc = create_api(&api);
        if (rc != pcmk_rc_ok) {
            return rc;
        }

        rc = connect_and_send_attrd_request(api, request);
        destroy_api(api);

    } else if (!pcmk_ipc_is_connected(api)) {
        rc = connect_and_send_attrd_request(api, request);

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
    pcmk__xe_add_node(op, node, 0);
    crm_xml_add(op, PCMK__XA_ATTR_SET, set);
    crm_xml_add_int(op, PCMK__XA_ATTR_IS_REMOTE,
                    pcmk_is_set(options, pcmk__node_attr_remote));
    crm_xml_add_int(op, PCMK__XA_ATTR_IS_PRIVATE,
                    pcmk_is_set(options, pcmk__node_attr_private));

    if (pcmk_is_set(options, pcmk__node_attr_sync_local)) {
        crm_xml_add(op, PCMK__XA_ATTR_SYNC_POINT, PCMK__ATTRD_SYNC_POINT_LOCAL);
    } else if (pcmk_is_set(options, pcmk__node_attr_sync_all)) {
        crm_xml_add(op, PCMK__XA_ATTR_SYNC_POINT, PCMK__ATTRD_SYNC_POINT_ALL);
    }
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
        rc = create_api(&api);
        if (rc != pcmk_rc_ok) {
            return rc;
        }

        rc = connect_and_send_attrd_request(api, request);
        destroy_api(api);

    } else if (!pcmk_ipc_is_connected(api)) {
        rc = connect_and_send_attrd_request(api, request);

    } else {
        rc = send_attrd_request(api, request);
    }

    free_xml(request);

    crm_debug("Asked pacemaker-attrd to update %s on %s: %s (%d)",
              name, display_host, pcmk_rc_str(rc), rc);

    return rc;
}

int
pcmk__attrd_api_update_list(pcmk_ipc_api_t *api, GList *attrs, const char *dampen,
                            const char *set, const char *user_name,
                            uint32_t options)
{
    int rc = pcmk_rc_ok;
    xmlNode *request = NULL;

    if (attrs == NULL) {
        return EINVAL;
    }

    /* There are two different ways of handling a list of attributes:
     *
     * (1) For messages originating from some command line tool, we have to send
     *     them one at a time.  In this loop, we just call pcmk__attrd_api_update
     *     for each, letting it deal with creating the API object if it doesn't
     *     already exist.
     *
     *     The reason we can't use a single message in this case is that we can't
     *     trust that the server supports it.  Remote nodes could be involved
     *     here, and there's no guarantee that a newer client running on a remote
     *     node is talking to (or proxied through) a cluster node with a newer
     *     attrd.  We also can't just try sending a single message and then falling
     *     back on multiple.  There's no handshake with the attrd server to
     *     determine its version.  And then we would need to do that fallback in the
     *     dispatch function for this to work for all connection types (mainloop in
     *     particular), and at that point we won't know what the original message
     *     was in order to break it apart and resend as individual messages.
     *
     * (2) For messages between daemons, we can be assured that the local attrd
     *     will support the new message and that it can send to the other attrds
     *     as one request or split up according to the minimum supported version.
     */
    for (GList *iter = attrs; iter != NULL; iter = iter->next) {
        pcmk__attrd_query_pair_t *pair = (pcmk__attrd_query_pair_t *) iter->data;

        if (pcmk__is_daemon) {
            const char *target = NULL;
            xmlNode *child = NULL;

            /* First time through this loop - create the basic request. */
            if (request == NULL) {
                request = create_attrd_op(user_name);
                add_op_attr(request, options);
            }

            /* Add a child node for this operation.  We add the task to the top
             * level XML node so attrd_ipc_dispatch doesn't need changes.  And
             * then we also add the task to each child node in populate_update_op
             * so attrd_client_update knows what form of update is taking place.
             */
            child = create_xml_node(request, XML_ATTR_OP);
            target = pcmk__node_attr_target(pair->node);

            if (target != NULL) {
                pair->node = target;
            }

            populate_update_op(child, pair->node, pair->name, pair->value, dampen,
                               set, options);
        } else {
            rc = pcmk__attrd_api_update(api, pair->node, pair->name, pair->value,
                                        dampen, set, user_name, options);
        }
    }

    /* If we were doing multiple attributes at once, we still need to send the
     * request.  Do that now, creating and destroying the API object if needed.
     */
    if (pcmk__is_daemon) {
        bool created_api = false;

        if (api == NULL) {
            rc = create_api(&api);
            if (rc != pcmk_rc_ok) {
                return rc;
            }

            created_api = true;
        }

        rc = connect_and_send_attrd_request(api, request);
        free_xml(request);

        if (created_api) {
            destroy_api(api);
        }
    }

    return rc;
}

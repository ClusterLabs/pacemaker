/*
 * Copyright 2020-2022 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <libxml/tree.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/ipc_controld.h>
#include "crmcommon_private.h"

struct controld_api_private_s {
    char *client_uuid;
    unsigned int replies_expected;
};

/*!
 * \internal
 * \brief Get a string representation of a controller API reply type
 *
 * \param[in] reply  Controller API reply type
 *
 * \return String representation of a controller API reply type
 */
const char *
pcmk__controld_api_reply2str(enum pcmk_controld_api_reply reply)
{
    switch (reply) {
        case pcmk_controld_reply_reprobe:
            return "reprobe";
        case pcmk_controld_reply_info:
            return "info";
        case pcmk_controld_reply_resource:
            return "resource";
        case pcmk_controld_reply_ping:
            return "ping";
        case pcmk_controld_reply_nodes:
            return "nodes";
        default:
            return "unknown";
    }
}

// \return Standard Pacemaker return code
static int
new_data(pcmk_ipc_api_t *api)
{
    struct controld_api_private_s *private = NULL;

    api->api_data = calloc(1, sizeof(struct controld_api_private_s));

    if (api->api_data == NULL) {
        return errno;
    }

    private = api->api_data;

    /* This is set to the PID because that's how it was always done, but PIDs
     * are not unique because clients can be remote. The value appears to be
     * unused other than as part of F_CRM_SYS_FROM in IPC requests, which is
     * only compared against the internal system names (CRM_SYSTEM_TENGINE,
     * etc.), so it shouldn't be a problem.
     */
    private->client_uuid = pcmk__getpid_s();

    /* @TODO Implement a call ID model similar to the CIB, executor, and fencer
     *       IPC APIs, so that requests and replies can be matched, and
     *       duplicate replies can be discarded.
     */
    return pcmk_rc_ok;
}

static void
free_data(void *data)
{
    free(((struct controld_api_private_s *) data)->client_uuid);
    free(data);
}

// \return Standard Pacemaker return code
static int
post_connect(pcmk_ipc_api_t *api)
{
    /* The controller currently requires clients to register via a hello
     * request, but does not reply back.
     */
    struct controld_api_private_s *private = api->api_data;
    const char *client_name = crm_system_name? crm_system_name : "client";
    xmlNode *hello;
    int rc;

    hello = create_hello_message(private->client_uuid, client_name,
                                 PCMK__CONTROLD_API_MAJOR,
                                 PCMK__CONTROLD_API_MINOR);
    rc = pcmk__send_ipc_request(api, hello);
    free_xml(hello);
    if (rc != pcmk_rc_ok) {
        crm_info("Could not send IPC hello to %s: %s " CRM_XS " rc=%s",
                 pcmk_ipc_name(api, true), pcmk_rc_str(rc), rc);
    } else {
        crm_debug("Sent IPC hello to %s", pcmk_ipc_name(api, true));
    }
    return rc;
}

static void
set_node_info_data(pcmk_controld_api_reply_t *data, xmlNode *msg_data)
{
    data->reply_type = pcmk_controld_reply_info;
    if (msg_data == NULL) {
        return;
    }
    data->data.node_info.have_quorum = pcmk__xe_attr_is_true(msg_data, XML_ATTR_HAVE_QUORUM);
    data->data.node_info.is_remote = pcmk__xe_attr_is_true(msg_data, XML_NODE_IS_REMOTE);
    crm_element_value_int(msg_data, XML_ATTR_ID, &(data->data.node_info.id));
    data->data.node_info.uuid = crm_element_value(msg_data, XML_ATTR_UUID);
    data->data.node_info.uname = crm_element_value(msg_data, XML_ATTR_UNAME);
    data->data.node_info.state = crm_element_value(msg_data, XML_NODE_IS_PEER);
}

static void
set_ping_data(pcmk_controld_api_reply_t *data, xmlNode *msg_data)
{
    data->reply_type = pcmk_controld_reply_ping;
    if (msg_data == NULL) {
        return;
    }
    data->data.ping.sys_from = crm_element_value(msg_data,
                                                 XML_PING_ATTR_SYSFROM);
    data->data.ping.fsa_state = crm_element_value(msg_data,
                                                  XML_PING_ATTR_CRMDSTATE);
    data->data.ping.result = crm_element_value(msg_data, XML_PING_ATTR_STATUS);
}

static void
set_nodes_data(pcmk_controld_api_reply_t *data, xmlNode *msg_data)
{
    pcmk_controld_api_node_t *node_info;

    data->reply_type = pcmk_controld_reply_nodes;
    for (xmlNode *node = first_named_child(msg_data, XML_CIB_TAG_NODE);
         node != NULL; node = crm_next_same_xml(node)) {

        long long id_ll = 0;

        node_info = calloc(1, sizeof(pcmk_controld_api_node_t));
        crm_element_value_ll(node, XML_ATTR_ID, &id_ll);
        if (id_ll > 0) {
            node_info->id = id_ll;
        }
        node_info->uname = crm_element_value(node, XML_ATTR_UNAME);
        node_info->state = crm_element_value(node, XML_NODE_IN_CLUSTER);
        data->data.nodes = g_list_prepend(data->data.nodes, node_info);
    }
}

static bool
reply_expected(pcmk_ipc_api_t *api, xmlNode *request)
{
    const char *command = crm_element_value(request, F_CRM_TASK);

    if (command == NULL) {
        return false;
    }

    // We only need to handle commands that functions in this file can send
    return !strcmp(command, CRM_OP_REPROBE)
           || !strcmp(command, CRM_OP_NODE_INFO)
           || !strcmp(command, CRM_OP_PING)
           || !strcmp(command, CRM_OP_LRM_FAIL)
           || !strcmp(command, CRM_OP_LRM_DELETE);
}

static bool
dispatch(pcmk_ipc_api_t *api, xmlNode *reply)
{
    struct controld_api_private_s *private = api->api_data;
    crm_exit_t status = CRM_EX_OK;
    xmlNode *msg_data = NULL;
    const char *value = NULL;
    pcmk_controld_api_reply_t reply_data = {
        pcmk_controld_reply_unknown, NULL, NULL,
    };

    /* If we got an ACK, return true so the caller knows to expect more responses
     * from the IPC server.  We do this before decrementing replies_expected because
     * ACKs are not going to be included in that value.
     *
     * Note that we cannot do the same kind of status checking here that we do in
     * ipc_pacemakerd.c.  The ACK message we receive does not necessarily contain
     * a status attribute.  That is, we may receive this:
     *
     * <ack function="crmd_remote_proxy_cb" line="556"/>
     *
     * Instead of this:
     *
     * <ack function="dispatch_controller_ipc" line="391" status="112"/>
     */
    if (pcmk__str_eq(crm_element_name(reply), "ack", pcmk__str_none)) {
        return true; // More replies needed
    }

    if (private->replies_expected > 0) {
        private->replies_expected--;
    }

    // Do some basic validation of the reply

    /* @TODO We should be able to verify that value is always a response, but
     *       currently the controller doesn't always properly set the type. Even
     *       if we fix the controller, we'll still need to handle replies from
     *       old versions (feature set could be used to differentiate).
     */
    value = crm_element_value(reply, F_CRM_MSG_TYPE);
    if (pcmk__str_empty(value)
        || !pcmk__str_any_of(value, XML_ATTR_REQUEST, XML_ATTR_RESPONSE, NULL)) {
        crm_info("Unrecognizable message from controller: "
                 "invalid message type '%s'", pcmk__s(value, ""));
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    if (pcmk__str_empty(crm_element_value(reply, XML_ATTR_REFERENCE))) {
        crm_info("Unrecognizable message from controller: no reference");
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    value = crm_element_value(reply, F_CRM_TASK);
    if (pcmk__str_empty(value)) {
        crm_info("Unrecognizable message from controller: no command name");
        status = CRM_EX_PROTOCOL;
        goto done;
    }

    // Parse useful info from reply

    reply_data.feature_set = crm_element_value(reply, XML_ATTR_VERSION);
    reply_data.host_from = crm_element_value(reply, F_CRM_HOST_FROM);
    msg_data = get_message_xml(reply, F_CRM_DATA);

    if (!strcmp(value, CRM_OP_REPROBE)) {
        reply_data.reply_type = pcmk_controld_reply_reprobe;

    } else if (!strcmp(value, CRM_OP_NODE_INFO)) {
        set_node_info_data(&reply_data, msg_data);

    } else if (!strcmp(value, CRM_OP_INVOKE_LRM)) {
        reply_data.reply_type = pcmk_controld_reply_resource;
        reply_data.data.resource.node_state = msg_data;

    } else if (!strcmp(value, CRM_OP_PING)) {
        set_ping_data(&reply_data, msg_data);

    } else if (!strcmp(value, PCMK__CONTROLD_CMD_NODES)) {
        set_nodes_data(&reply_data, msg_data);

    } else {
        crm_info("Unrecognizable message from controller: unknown command '%s'",
                 value);
        status = CRM_EX_PROTOCOL;
    }

done:
    pcmk__call_ipc_callback(api, pcmk_ipc_event_reply, status, &reply_data);

    // Free any reply data that was allocated
    if (pcmk__str_eq(value, PCMK__CONTROLD_CMD_NODES, pcmk__str_casei)) {
        g_list_free_full(reply_data.data.nodes, free);
    }

    return false; // No further replies needed
}

pcmk__ipc_methods_t *
pcmk__controld_api_methods(void)
{
    pcmk__ipc_methods_t *cmds = calloc(1, sizeof(pcmk__ipc_methods_t));

    if (cmds != NULL) {
        cmds->new_data = new_data;
        cmds->free_data = free_data;
        cmds->post_connect = post_connect;
        cmds->reply_expected = reply_expected;
        cmds->dispatch = dispatch;
    }
    return cmds;
}

/*!
 * \internal
 * \brief Create XML for a controller IPC request
 *
 * \param[in] api       Controller connection
 * \param[in] op        Controller IPC command name
 * \param[in] node      Node name to set as destination host
 * \param[in] msg_data  XML to attach to request as message data
 *
 * \return Newly allocated XML for request
 */
static xmlNode *
create_controller_request(const pcmk_ipc_api_t *api, const char *op,
                          const char *node, xmlNode *msg_data)
{
    struct controld_api_private_s *private = NULL;
    const char *sys_to = NULL;

    if (api == NULL) {
        return NULL;
    }
    private = api->api_data;
    if ((node == NULL) && !strcmp(op, CRM_OP_PING)) {
        sys_to = CRM_SYSTEM_DC;
    } else {
        sys_to = CRM_SYSTEM_CRMD;
    }
    return create_request(op, msg_data, node, sys_to,
                          (crm_system_name? crm_system_name : "client"),
                          private->client_uuid);
}

// \return Standard Pacemaker return code
static int
send_controller_request(pcmk_ipc_api_t *api, xmlNode *request,
                        bool reply_is_expected)
{
    int rc;

    if (crm_element_value(request, XML_ATTR_REFERENCE) == NULL) {
        return EINVAL;
    }
    rc = pcmk__send_ipc_request(api, request);
    if ((rc == pcmk_rc_ok) && reply_is_expected) {
        struct controld_api_private_s *private = api->api_data;

        private->replies_expected++;
    }
    return rc;
}

static xmlNode *
create_reprobe_message_data(const char *target_node, const char *router_node)
{
    xmlNode *msg_data;

    msg_data = create_xml_node(NULL, "data_for_" CRM_OP_REPROBE);
    crm_xml_add(msg_data, XML_LRM_ATTR_TARGET, target_node);
    if ((router_node != NULL) && !pcmk__str_eq(router_node, target_node, pcmk__str_casei)) {
        crm_xml_add(msg_data, XML_LRM_ATTR_ROUTER_NODE, router_node);
    }
    return msg_data;
}

/*!
 * \brief Send a reprobe controller operation
 *
 * \param[in,out] api          Controller connection
 * \param[in]     target_node  Name of node to reprobe
 * \param[in]     router_node  Router node for host
 *
 * \return Standard Pacemaker return code
 * \note Event callback will get a reply of type pcmk_controld_reply_reprobe.
 */
int
pcmk_controld_api_reprobe(pcmk_ipc_api_t *api, const char *target_node,
                          const char *router_node)
{
    xmlNode *request;
    xmlNode *msg_data;
    int rc = pcmk_rc_ok;

    if (api == NULL) {
        return EINVAL;
    }
    if (router_node == NULL) {
        router_node = target_node;
    }
    crm_debug("Sending %s IPC request to reprobe %s via %s",
              pcmk_ipc_name(api, true), pcmk__s(target_node, "local node"),
              pcmk__s(router_node, "local node"));
    msg_data = create_reprobe_message_data(target_node, router_node);
    request = create_controller_request(api, CRM_OP_REPROBE, router_node,
                                        msg_data);
    rc = send_controller_request(api, request, true);
    free_xml(msg_data);
    free_xml(request);
    return rc;
}

/*!
 * \brief Send a "node info" controller operation
 *
 * \param[in,out] api     Controller connection
 * \param[in]     nodeid  ID of node to get info for (or 0 for local node)
 *
 * \return Standard Pacemaker return code
 * \note Event callback will get a reply of type pcmk_controld_reply_info.
 */
int
pcmk_controld_api_node_info(pcmk_ipc_api_t *api, uint32_t nodeid)
{
    xmlNode *request;
    int rc = pcmk_rc_ok;

    request = create_controller_request(api, CRM_OP_NODE_INFO, NULL, NULL);
    if (request == NULL) {
        return EINVAL;
    }
    if (nodeid > 0) {
        crm_xml_set_id(request, "%lu", (unsigned long) nodeid);
    }

    rc = send_controller_request(api, request, true);
    free_xml(request);
    return rc;
}

/*!
 * \brief Ask the controller for status
 *
 * \param[in,out] api        Controller connection
 * \param[in]     node_name  Name of node whose status is desired (NULL for DC)
 *
 * \return Standard Pacemaker return code
 * \note Event callback will get a reply of type pcmk_controld_reply_ping.
 */
int
pcmk_controld_api_ping(pcmk_ipc_api_t *api, const char *node_name)
{
    xmlNode *request;
    int rc = pcmk_rc_ok;

    request = create_controller_request(api, CRM_OP_PING, node_name, NULL);
    if (request == NULL) {
        return EINVAL;
    }
    rc = send_controller_request(api, request, true);
    free_xml(request);
    return rc;
}

/*!
 * \brief Ask the controller for cluster information
 *
 * \param[in,out] api  Controller connection
 *
 * \return Standard Pacemaker return code
 * \note Event callback will get a reply of type pcmk_controld_reply_nodes.
 */
int
pcmk_controld_api_list_nodes(pcmk_ipc_api_t *api)
{
    xmlNode *request;
    int rc = EINVAL;

    request = create_controller_request(api, PCMK__CONTROLD_CMD_NODES, NULL,
                                        NULL);
    if (request != NULL) {
        rc = send_controller_request(api, request, true);
        free_xml(request);
    }
    return rc;
}

// \return Standard Pacemaker return code
static int
controller_resource_op(pcmk_ipc_api_t *api, const char *op,
                       const char *target_node, const char *router_node,
                       bool cib_only, const char *rsc_id,
                       const char *rsc_long_id, const char *standard,
                       const char *provider, const char *type)
{
    int rc = pcmk_rc_ok;
    char *key;
    xmlNode *request, *msg_data, *xml_rsc, *params;

    if (api == NULL) {
        return EINVAL;
    }
    if (router_node == NULL) {
        router_node = target_node;
    }

    msg_data = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);

    /* The controller logs the transition key from resource op requests, so we
     * need to have *something* for it.
     * @TODO don't use "crm-resource"
     */
    key = pcmk__transition_key(0, getpid(), 0,
                               "xxxxxxxx-xrsc-opxx-xcrm-resourcexxxx");
    crm_xml_add(msg_data, XML_ATTR_TRANSITION_KEY, key);
    free(key);

    crm_xml_add(msg_data, XML_LRM_ATTR_TARGET, target_node);
    if (!pcmk__str_eq(router_node, target_node, pcmk__str_casei)) {
        crm_xml_add(msg_data, XML_LRM_ATTR_ROUTER_NODE, router_node);
    }

    if (cib_only) {
        // Indicate that only the CIB needs to be cleaned
        crm_xml_add(msg_data, PCMK__XA_MODE, XML_TAG_CIB);
    }

    xml_rsc = create_xml_node(msg_data, XML_CIB_TAG_RESOURCE);
    crm_xml_add(xml_rsc, XML_ATTR_ID, rsc_id);
    crm_xml_add(xml_rsc, XML_ATTR_ID_LONG, rsc_long_id);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_CLASS, standard);
    crm_xml_add(xml_rsc, XML_AGENT_ATTR_PROVIDER, provider);
    crm_xml_add(xml_rsc, XML_ATTR_TYPE, type);

    params = create_xml_node(msg_data, XML_TAG_ATTRS);
    crm_xml_add(params, XML_ATTR_CRM_VERSION, CRM_FEATURE_SET);

    // The controller parses the timeout from the request
    key = crm_meta_name(XML_ATTR_TIMEOUT);
    crm_xml_add(params, key, "60000");  /* 1 minute */ //@TODO pass as arg
    free(key);

    request = create_controller_request(api, op, router_node, msg_data);
    rc = send_controller_request(api, request, true);
    free_xml(msg_data);
    free_xml(request);
    return rc;
}

/*!
 * \brief Ask the controller to fail a resource
 *
 * \param[in,out] api          Controller connection
 * \param[in]     target_node  Name of node resource is on
 * \param[in]     router_node  Router node for target
 * \param[in]     rsc_id       ID of resource to fail
 * \param[in]     rsc_long_id  Long ID of resource (if any)
 * \param[in]     standard     Standard of resource
 * \param[in]     provider     Provider of resource (if any)
 * \param[in]     type         Type of resource to fail
 *
 * \return Standard Pacemaker return code
 * \note Event callback will get a reply of type pcmk_controld_reply_resource.
 */
int
pcmk_controld_api_fail(pcmk_ipc_api_t *api,
                       const char *target_node, const char *router_node,
                       const char *rsc_id, const char *rsc_long_id,
                       const char *standard, const char *provider,
                       const char *type)
{
    crm_debug("Sending %s IPC request to fail %s (a.k.a. %s) on %s via %s",
              pcmk_ipc_name(api, true), pcmk__s(rsc_id, "unknown resource"),
              pcmk__s(rsc_long_id, "no other names"),
              pcmk__s(target_node, "unspecified node"),
              pcmk__s(router_node, "unspecified node"));
    return controller_resource_op(api, CRM_OP_LRM_FAIL, target_node,
                                  router_node, false, rsc_id, rsc_long_id,
                                  standard, provider, type);
}

/*!
 * \brief Ask the controller to refresh a resource
 *
 * \param[in,out] api          Controller connection
 * \param[in]     target_node  Name of node resource is on
 * \param[in]     router_node  Router node for target
 * \param[in]     rsc_id       ID of resource to refresh
 * \param[in]     rsc_long_id  Long ID of resource (if any)
 * \param[in]     standard     Standard of resource
 * \param[in]     provider     Provider of resource (if any)
 * \param[in]     type         Type of resource
 * \param[in]     cib_only     If true, clean resource from CIB only
 *
 * \return Standard Pacemaker return code
 * \note Event callback will get a reply of type pcmk_controld_reply_resource.
 */
int
pcmk_controld_api_refresh(pcmk_ipc_api_t *api, const char *target_node,
                          const char *router_node,
                          const char *rsc_id, const char *rsc_long_id,
                          const char *standard, const char *provider,
                          const char *type, bool cib_only)
{
    crm_debug("Sending %s IPC request to refresh %s (a.k.a. %s) on %s via %s",
              pcmk_ipc_name(api, true), pcmk__s(rsc_id, "unknown resource"),
              pcmk__s(rsc_long_id, "no other names"),
              pcmk__s(target_node, "unspecified node"),
              pcmk__s(router_node, "unspecified node"));
    return controller_resource_op(api, CRM_OP_LRM_DELETE, target_node,
                                  router_node, cib_only, rsc_id, rsc_long_id,
                                  standard, provider, type);
}

/*!
 * \brief Get the number of IPC replies currently expected from the controller
 *
 * \param[in] api  Controller IPC API connection
 *
 * \return Number of replies expected
 */
unsigned int
pcmk_controld_api_replies_expected(const pcmk_ipc_api_t *api)
{
    struct controld_api_private_s *private = api->api_data;

    return private->replies_expected;
}

/*!
 * \brief Create XML for a controller IPC "hello" message
 *
 * \deprecated This function is deprecated as part of the public C API.
 */
// \todo make this static to this file when breaking API backward compatibility
xmlNode *
create_hello_message(const char *uuid, const char *client_name,
                     const char *major_version, const char *minor_version)
{
    xmlNode *hello_node = NULL;
    xmlNode *hello = NULL;

    if (pcmk__str_empty(uuid) || pcmk__str_empty(client_name)
        || pcmk__str_empty(major_version) || pcmk__str_empty(minor_version)) {
        crm_err("Could not create IPC hello message from %s (UUID %s): "
                "missing information",
                client_name? client_name : "unknown client",
                uuid? uuid : "unknown");
        return NULL;
    }

    hello_node = create_xml_node(NULL, XML_TAG_OPTIONS);
    if (hello_node == NULL) {
        crm_err("Could not create IPC hello message from %s (UUID %s): "
                "Message data creation failed", client_name, uuid);
        return NULL;
    }

    crm_xml_add(hello_node, "major_version", major_version);
    crm_xml_add(hello_node, "minor_version", minor_version);
    crm_xml_add(hello_node, "client_name", client_name);
    crm_xml_add(hello_node, "client_uuid", uuid);

    hello = create_request(CRM_OP_HELLO, hello_node, NULL, NULL, client_name, uuid);
    if (hello == NULL) {
        crm_err("Could not create IPC hello message from %s (UUID %s): "
                "Request creation failed", client_name, uuid);
        return NULL;
    }
    free_xml(hello_node);

    crm_trace("Created hello message from %s (UUID %s)", client_name, uuid);
    return hello;
}

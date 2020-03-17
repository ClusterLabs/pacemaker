/*
 * Copyright 2020 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdio.h>
#include <errno.h>
#include "crm_resource.h"

// API object's private members
struct controller_private {
    char *client_name;              // Client name to use with IPC
    char *client_uuid;              // Client UUID to use with IPC
    mainloop_io_t *source;          // If main loop used, I/O source for IPC
    crm_ipc_t *ipc;                 // IPC connection to controller
    int replies_expected;           // How many controller replies are expected
    pcmk_controld_api_cb_t dispatch_cb; // Caller's registered dispatch callback
    pcmk_controld_api_cb_t destroy_cb;  // Caller's registered destroy callback
};

static void
call_client_callback(pcmk_controld_api_t *api, pcmk_controld_api_cb_t *cb,
                     void *api_data)
{
    if ((cb != NULL) && (cb->callback != NULL)) {
        cb->callback(api, api_data, cb->user_data);
    }
}

/*
 * IPC callbacks when used with main loop
 */

static void
controller_ipc_destroy(gpointer user_data)
{
    pcmk_controld_api_t *api = user_data;
    struct controller_private *private = api->private;

    private->ipc = NULL;
    private->source = NULL;
    call_client_callback(api, &(private->destroy_cb), NULL);
}

// \return < 0 if connection is no longer required, >= 0 if it is
static int
controller_ipc_dispatch(const char *buffer, ssize_t length, gpointer user_data)
{
    xmlNode *msg = NULL;
    pcmk_controld_api_t *api = user_data;

    CRM_CHECK(buffer && api && api->private, return 0);

    msg = string2xml(buffer);
    if (msg == NULL) {
        crm_warn("Received malformed controller IPC message");
    } else {
        struct controller_private *private = api->private;

        crm_log_xml_trace(msg, "controller-reply");
        private->replies_expected--;
        call_client_callback(api, &(private->dispatch_cb),
                             get_message_xml(msg, F_CRM_DATA));
        free_xml(msg);
    }
    return 0;
}

/*
 * IPC utilities
 */

// \return Standard Pacemaker return code
static int
send_hello(crm_ipc_t *ipc, const char *client_name, const char *client_uuid)
{
    xmlNode *hello = create_hello_message(client_uuid, client_name, "0", "1");
    int rc = crm_ipc_send(ipc, hello, 0, 0, NULL);

    free_xml(hello);
    if (rc < 0) {
        rc = pcmk_legacy2rc(rc);
        crm_info("Could not send IPC hello to %s: %s " CRM_XS " rc=%s",
                 CRM_SYSTEM_CRMD /* ipc->name */,
                 pcmk_rc_str(rc), rc);
        return rc;
    }
    crm_debug("Sent IPC hello to %s", CRM_SYSTEM_CRMD /* ipc->name */);
    return pcmk_rc_ok;
}

// \return Standard Pacemaker return code
static int
send_controller_request(pcmk_controld_api_t *api, const char *op,
                        xmlNode *msg_data, const char *node)
{
    int rc;
    struct controller_private *private = api->private;
    xmlNode *cmd = create_request(op, msg_data, node, CRM_SYSTEM_CRMD,
                                  private->client_name, private->client_uuid);
    const char *reference = crm_element_value(cmd, XML_ATTR_REFERENCE);

    if ((cmd == NULL) || (reference == NULL)) {
        return EINVAL;
    }

    //@TODO pass as args? 0=crm_ipc_flags, 0=timeout_ms (default 5s), NULL=reply
    crm_log_xml_trace(cmd, "controller-request");
    rc = crm_ipc_send(private->ipc, cmd, 0, 0, NULL);
    free_xml(cmd);
    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    }
    private->replies_expected++;
    return pcmk_rc_ok;
}

/*
 * pcmk_controld_api_t methods
 */

static int
controller_connect_mainloop(pcmk_controld_api_t *api)
{
    struct controller_private *private = api->private;
    struct ipc_client_callbacks callbacks = {
        .dispatch = controller_ipc_dispatch,
        .destroy = controller_ipc_destroy,
    };

    private->source = mainloop_add_ipc_client(CRM_SYSTEM_CRMD,
                                              G_PRIORITY_DEFAULT, 0, api,
                                              &callbacks);
    if (private->source == NULL) {
        return ENOTCONN;
    }

    private->ipc = mainloop_get_ipc_client(private->source);
    if (private->ipc == NULL) {
        (void) api->disconnect(api);
        return ENOTCONN;
    }

    crm_debug("Connected to %s IPC (attaching to main loop)", CRM_SYSTEM_CRMD);
    return pcmk_rc_ok;
}

static int
controller_connect_no_mainloop(pcmk_controld_api_t *api)
{
    struct controller_private *private = api->private;

    private->ipc = crm_ipc_new(CRM_SYSTEM_CRMD, 0);
    if (private->ipc == NULL) {
        return ENOTCONN;
    }
    if (!crm_ipc_connect(private->ipc)) {
        crm_ipc_close(private->ipc);
        crm_ipc_destroy(private->ipc);
        private->ipc = NULL;
        return errno;
    }
    /* @TODO caller needs crm_ipc_get_fd(private->ipc); either add method for
     * that, or replace use_mainloop with int *fd
     */
    crm_debug("Connected to %s IPC", CRM_SYSTEM_CRMD);
    return pcmk_rc_ok;
}

static void
set_callback(pcmk_controld_api_cb_t *dest, pcmk_controld_api_cb_t *source)
{
    if (source) {
        dest->callback  = source->callback;
        dest->user_data = source->user_data;
    }
}

static int
controller_api_connect(pcmk_controld_api_t *api, bool use_mainloop,
                       pcmk_controld_api_cb_t *dispatch_cb,
                       pcmk_controld_api_cb_t *destroy_cb)
{
    int rc = pcmk_rc_ok;
    struct controller_private *private;

    if (api == NULL) {
        return EINVAL;
    }
    private = api->private;

    set_callback(&(private->dispatch_cb), dispatch_cb);
    set_callback(&(private->destroy_cb), destroy_cb);

    if (private->ipc != NULL) {
        return pcmk_rc_ok; // already connected
    }

    if (use_mainloop) {
        rc = controller_connect_mainloop(api);
    } else {
        rc = controller_connect_no_mainloop(api);
    }
    if (rc != pcmk_rc_ok) {
        return rc;
    }

    rc = send_hello(private->ipc, private->client_name, private->client_uuid);
    if (rc != pcmk_rc_ok) {
        (void) api->disconnect(api);
    }
    return rc;
}

static int
controller_api_disconnect(pcmk_controld_api_t *api)
{
    struct controller_private *private = api->private;

    if (private->source != NULL) {
        // Attached to main loop
        mainloop_del_ipc_client(private->source);
        private->source = NULL;
        private->ipc = NULL;

    } else if (private->ipc != NULL) {
        // Not attached to main loop
        crm_ipc_t *ipc = private->ipc;

        private->ipc = NULL;
        crm_ipc_close(ipc);
        crm_ipc_destroy(ipc);
    }
    crm_debug("Disconnected from %s IPC", CRM_SYSTEM_CRMD /* ipc->name */);
    return pcmk_rc_ok;
}

//@TODO dispatch function for non-mainloop a la stonith_dispatch()
//@TODO convenience retry-connect function a la stonith_api_connect_retry()

static unsigned int
controller_api_replies_expected(pcmk_controld_api_t *api)
{
    if (api != NULL) {
        struct controller_private *private = api->private;

        return private->replies_expected;
    }
    return 0;
}

static xmlNode *
create_reprobe_message_data(const char *target_node, const char *router_node)
{
    xmlNode *msg_data;

    msg_data = create_xml_node(NULL, "data_for_" CRM_OP_REPROBE);
    crm_xml_add(msg_data, XML_LRM_ATTR_TARGET, target_node);
    if ((router_node != NULL) && safe_str_neq(router_node, target_node)) {
        crm_xml_add(msg_data, XML_LRM_ATTR_ROUTER_NODE, router_node);
    }
    return msg_data;
}

static int
controller_api_reprobe(pcmk_controld_api_t *api, const char *target_node,
                       const char *router_node)
{
    int rc = EINVAL;

    if (api != NULL) {
        xmlNode *msg_data;

        crm_debug("Sending %s IPC request to reprobe %s via %s",
                  CRM_SYSTEM_CRMD, crm_str(target_node), crm_str(router_node));
        msg_data = create_reprobe_message_data(target_node, router_node);
        rc = send_controller_request(api, CRM_OP_REPROBE, msg_data,
                                     (router_node? router_node : target_node));
        free_xml(msg_data);
    }
    return rc;
}

// \return Standard Pacemaker return code
static int
controller_resource_op(pcmk_controld_api_t *api, const char *op,
                       const char *target_node, const char *router_node,
                       bool cib_only, const char *rsc_id,
                       const char *rsc_long_id, const char *standard,
                       const char *provider, const char *type)
{
    int rc;
    char *key;
    xmlNode *msg_data, *xml_rsc, *params;

    if (api == NULL) {
        return EINVAL;
    }
    if (router_node == NULL) {
        router_node = target_node;
    }

    msg_data = create_xml_node(NULL, XML_GRAPH_TAG_RSC_OP);

    /* The controller logs the transition key from resource op requests, so we
     * need to have *something* for it.
     */
    key = pcmk__transition_key(0, getpid(), 0,
                               "xxxxxxxx-xrsc-opxx-xcrm-resourcexxxx");
    crm_xml_add(msg_data, XML_ATTR_TRANSITION_KEY, key);
    free(key);

    crm_xml_add(msg_data, XML_LRM_ATTR_TARGET, target_node);
    if (safe_str_neq(router_node, target_node)) {
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

    rc = send_controller_request(api, op, msg_data, router_node);
    free_xml(msg_data);
    return rc;
}

static int
controller_api_fail_resource(pcmk_controld_api_t *api,
                             const char *target_node, const char *router_node,
                             const char *rsc_id, const char *rsc_long_id,
                             const char *standard, const char *provider,
                             const char *type)
{
    crm_debug("Sending %s IPC request to fail %s (a.k.a. %s) on %s via %s",
              CRM_SYSTEM_CRMD, crm_str(rsc_id), crm_str(rsc_long_id),
              crm_str(target_node), crm_str(router_node));
    return controller_resource_op(api, CRM_OP_LRM_FAIL, target_node,
                                  router_node, false, rsc_id, rsc_long_id,
                                  standard, provider, type);
}

static int
controller_api_refresh_resource(pcmk_controld_api_t *api,
                                const char *target_node,
                                const char *router_node,
                                const char *rsc_id, const char *rsc_long_id,
                                const char *standard, const char *provider,
                                const char *type, bool cib_only)
{
    crm_debug("Sending %s IPC request to refresh %s (a.k.a. %s) on %s via %s",
              CRM_SYSTEM_CRMD, crm_str(rsc_id), crm_str(rsc_long_id),
              crm_str(target_node), crm_str(router_node));
    return controller_resource_op(api, CRM_OP_LRM_DELETE, target_node,
                                  router_node, cib_only, rsc_id, rsc_long_id,
                                  standard, provider, type);
}

pcmk_controld_api_t *
pcmk_new_controld_api(const char *client_name, const char *client_uuid)
{
    struct controller_private *private;
    pcmk_controld_api_t *api = calloc(1, sizeof(pcmk_controld_api_t));

    CRM_ASSERT(api != NULL);

    api->private = calloc(1, sizeof(struct controller_private));
    CRM_ASSERT(api->private != NULL);
    private = api->private;

    if (client_name == NULL) {
        client_name = crm_system_name? crm_system_name : "client";
    }
    private->client_name = strdup(client_name);
    CRM_ASSERT(private->client_name != NULL);

    if (client_uuid == NULL) {
        private->client_uuid = crm_generate_uuid();
    } else {
        private->client_uuid = strdup(client_uuid);
    }
    CRM_ASSERT(private->client_uuid != NULL);

    api->connect = controller_api_connect;
    api->disconnect = controller_api_disconnect;
    api->replies_expected = controller_api_replies_expected;
    api->reprobe = controller_api_reprobe;
    api->fail_resource = controller_api_fail_resource;
    api->refresh_resource = controller_api_refresh_resource;
    return api;
}

void
pcmk_free_controld_api(pcmk_controld_api_t *api)
{
    if (api != NULL) {
        struct controller_private *private = api->private;

        api->disconnect(api);
        free(private->client_name);
        free(private->client_uuid);
        free(api->private);
        free(api);
    }
}

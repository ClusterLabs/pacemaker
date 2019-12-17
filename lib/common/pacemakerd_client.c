/*
 * Copyright 2004-2019 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <stdlib.h>
#include <time.h>

#include <crm/msg_xml.h>
#include <crm/common/mainloop.h>
#include <crm/common/pacemakerd_types.h>

CRM_TRACE_INIT_DATA(pacemakerd);

typedef struct pacemakerd_api_private_s {
    mainloop_io_t *source;
    void (*ping_callback) (pacemakerd_t *pacemakerd, time_t last_good,
                           enum pacemakerd_state state, int rc,
                           gpointer userdata);
    gpointer ping_userdata;
    void (*disconnect_callback) (gpointer userdata);
    gpointer disconnect_userdata;
} pacemakerd_api_private_t;

const char *pacemakerd_state_str[] = {
    XML_PING_ATTR_PACEMAKERDSTATE_INIT,
    XML_PING_ATTR_PACEMAKERDSTATE_STARTINGDAEMONS,
    XML_PING_ATTR_PACEMAKERDSTATE_WAITPING,
    XML_PING_ATTR_PACEMAKERDSTATE_RUNNING,
    XML_PING_ATTR_PACEMAKERDSTATE_SHUTTINGDOWN,
    XML_PING_ATTR_PACEMAKERDSTATE_SHUTDOWNCOMPLETE
};

enum pacemakerd_state pacemakerd_state_text2enum(const char *state)
{
    int i;

    if (state == NULL) {
        return pacemakerd_state_invalid;
    }
    for (i=pacemakerd_state_init; i <= pacemakerd_state_max;
         i++) {
        if (crm_str_eq(state, pacemakerd_state_str[i], TRUE)) {
            return i;
        }
    }
    return pacemakerd_state_invalid;
}

const char *pacemakerd_state_enum2text(enum pacemakerd_state state)
{
    if ((state >= pacemakerd_state_init) &&
        (state <= pacemakerd_state_max)) {
        return pacemakerd_state_str[state];
    }
    return NULL;
}

static int
pacemakerd_dispatch_internal(const char *buffer, ssize_t length, gpointer userdata)
{
    pacemakerd_t *pacemakerd = userdata;
    pacemakerd_api_private_t *native;
    const char *type = NULL;
    const char *crm_msg_reference = NULL;
    xmlNode *xml;
    int rc = 0;

    CRM_CHECK(pacemakerd != NULL, return rc);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);
    CRM_ASSERT(native->ping_callback != NULL);

    xml = string2xml(buffer);
    if (xml == NULL) {
        return rc;
    }

    type = crm_element_value(xml, F_CRM_MSG_TYPE);
    crm_msg_reference = crm_element_value(xml, XML_ATTR_REFERENCE);

    if (type == NULL) {
        crm_info("No message type defined.");
    } else if (strcasecmp(XML_ATTR_RESPONSE, type) != 0) {
        crm_info("Expecting a (%s) message but received a (%s).",
                 XML_ATTR_RESPONSE, type);
    } else if (crm_msg_reference == NULL) {
        crm_info("No message crm_msg_reference defined.");
    } else {
        xmlNode *data = get_message_xml(xml, F_CRM_DATA);
        const char *state =
            crm_element_value(data, XML_PING_ATTR_PACEMAKERDSTATE);
        const char *status =
            crm_element_value(data, XML_PING_ATTR_STATUS);
        time_t pinged = (time_t) 0;
        long long value_ll = 0;

        crm_element_value_ll(data, XML_ATTR_TSTAMP, &value_ll);
        pinged = (time_t) value_ll;
        native->ping_callback(pacemakerd, pinged,
            pacemakerd_state_text2enum(state),
            crm_str_eq(status, "ok", FALSE)?pcmk_ok:pcmk_err_generic,
            userdata);
        rc = 1;
    }

    free_xml(xml);
    return rc;
}

static void
pacemakerd_connection_destroy(gpointer userdata)
{
    pacemakerd_t *pacemakerd = userdata;
    pacemakerd_api_private_t *native;

    CRM_CHECK(pacemakerd != NULL, return);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);
    CRM_ASSERT(native->disconnect_callback != NULL);

    crm_trace("Sending destroyed notification");
    native->source = NULL;
    pacemakerd->conn_state = pacemakerd_conn_disconnected;
    native->disconnect_callback(native->disconnect_userdata);
}

static int
pacemakerd_api_connect(pacemakerd_t *pacemakerd, const char *name)
{
    pacemakerd_api_private_t *native;
    const char *display_name = name? name : "client";
    static struct ipc_client_callbacks pacemakerd_callbacks = {
        .dispatch = pacemakerd_dispatch_internal,
        .destroy = pacemakerd_connection_destroy
    };

    CRM_CHECK(pacemakerd != NULL, return -EINVAL);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);

    crm_debug("Attempting pacemakerd connection by %s", display_name);
    if (pacemakerd->conn_state != pacemakerd_conn_connected) {
        native->source =
            mainloop_add_ipc_client(CRM_SYSTEM_MCP, G_PRIORITY_DEFAULT, 0,
                                    (gpointer) pacemakerd,
                                    &pacemakerd_callbacks);
        if (native->source) {
            pacemakerd->conn_state = pacemakerd_conn_connected;
        }
    }

    return (pacemakerd->conn_state == pacemakerd_conn_connected)?
                pcmk_ok:-ENOTCONN;
}

static int
pacemakerd_api_disconnect(pacemakerd_t *pacemakerd)
{
    pacemakerd_api_private_t *native;

    CRM_CHECK(pacemakerd != NULL, return -EINVAL);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);

    crm_debug("Disconnecting from pacemakerd");

    if (native->source) {
        mainloop_del_ipc_client(native->source);
        native->source = NULL;
    }

    pacemakerd->conn_state = pacemakerd_conn_disconnected;
    return pcmk_ok;
}

static void
pacemakerd_api_free(pacemakerd_t *pacemakerd)
{
    if (pacemakerd) {
        if (pacemakerd->conn_state == pacemakerd_conn_connected) {
            pacemakerd_api_disconnect(pacemakerd);
        }
        free(pacemakerd->pacemakerd_private);
        free(pacemakerd->cmds);
        free(pacemakerd);
    }
}

static int
pacemakerd_api_set_ping_callback(pacemakerd_t *pacemakerd,
    void (*callback) (pacemakerd_t *pacemakerd,
                      time_t last_good,
                      enum pacemakerd_state state,
                      int rc, gpointer userdata),
    gpointer userdata)
{
    pacemakerd_api_private_t *native;

    CRM_CHECK(pacemakerd != NULL, return -EINVAL);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);
    native->ping_callback = callback;
    native->ping_userdata = userdata;

    return pcmk_ok;
}

static int
pacemakerd_api_set_disconnect_callback(pacemakerd_t *pacemakerd,
    void (*callback) (gpointer userdata),
    gpointer userdata)
{
    pacemakerd_api_private_t *native;

    CRM_CHECK(pacemakerd != NULL, return -EINVAL);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);
    native->disconnect_callback = callback;
    native->disconnect_userdata = userdata;

    return pcmk_ok;
}

static int
pacemakerd_api_ping(pacemakerd_t *pacemakerd, const char *name,
                     const char *admin_uuid, int call_options)
{
    pacemakerd_api_private_t *native;
    xmlNode *cmd;
    int rc;

    CRM_CHECK(pacemakerd != NULL, return -EINVAL);
    native = pacemakerd->pacemakerd_private;
    CRM_ASSERT(native != NULL);

    cmd = create_request(CRM_OP_PING, NULL, NULL,
                         CRM_SYSTEM_MCP, name, admin_uuid);

    if (cmd) {
        rc = crm_ipc_send(mainloop_get_ipc_client(native->source),
                          cmd, 0, 0, NULL);
        if (rc < 0) {
            crm_debug("Couldn't register with the pacemakerd: %s "
                      CRM_XS " rc=%d", pcmk_strerror(rc), rc);
            rc = -ECOMM;
        }
        free_xml(cmd);
    } else {
        rc = -ENOMSG;
    }

    return rc;
}

pacemakerd_t *
pacemakerd_api_new(void)
{
    pacemakerd_t *api = calloc(1, sizeof(pacemakerd_t));
    pacemakerd_api_operations_t *cmds =
        calloc(1, sizeof(pacemakerd_api_operations_t));
    pacemakerd_api_private_t *private =
        calloc(1, sizeof(pacemakerd_api_private_t));

    if (api && cmds && private) {
        api->pacemakerd_private = private;
        api->cmds =               cmds;
        api->conn_state =         pacemakerd_conn_disconnected;

        cmds->connect =           pacemakerd_api_connect;
        cmds->disconnect =        pacemakerd_api_disconnect;
        cmds->free =              pacemakerd_api_free;
        cmds->set_ping_callback = pacemakerd_api_set_ping_callback;
        cmds->set_disconnect_callback =
                                  pacemakerd_api_set_disconnect_callback;
        cmds->ping =              pacemakerd_api_ping;

    } else {
        free(cmds);
        free(api);
        free(private);
        api = NULL;
    }
    return api;
}

void
pacemakerd_api_delete(pacemakerd_t * pacemakerd)
{
    if ((pacemakerd) && (pacemakerd->cmds) &&
        (pacemakerd->cmds->free)) {
        pacemakerd->cmds->free(pacemakerd);
    }
}
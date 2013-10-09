/*
 * Copyright (C) 2009 Andrew Beekhof <andrew@beekhof.net>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/ipc.h>
#include <crm/common/ipcs.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>

#include <crm/common/mainloop.h>

#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <allocate.h>

#include <internal.h>

#include <standalone_config.h>

char *stonith_our_uname = NULL;
char *stonith_our_uuid = NULL;

GMainLoop *mainloop = NULL;

gboolean stand_alone = FALSE;
gboolean no_cib_connect = FALSE;
gboolean stonith_shutdown_flag = FALSE;

qb_ipcs_service_t *ipcs = NULL;
xmlNode *local_cib = NULL;

static cib_t *cib_api = NULL;
static void *cib_library = NULL;

static void stonith_shutdown(int nsig);
static void stonith_cleanup(void);

static int32_t
st_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    if (stonith_shutdown_flag) {
        crm_info("Ignoring new client [%d] during shutdown", crm_ipcs_client_pid(c));
        return -EPERM;
    }

    if (crm_client_new(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

static void
st_ipc_created(qb_ipcs_connection_t * c)
{
    crm_trace("Connection created for %p", c);
}

/* Exit code means? */
static int32_t
st_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    xmlNode *request = NULL;
    crm_client_t *c = crm_client_get(qbc);

    if (c == NULL) {
        crm_info("Invalid client: %p", qbc);
        return 0;
    }

    request = crm_ipcs_recv(c, data, size, &id, &flags);
    if (request == NULL) {
        crm_ipcs_send_ack(c, id, flags, "nack", __FUNCTION__, __LINE__);
        return 0;
    }

    if (c->name == NULL) {
        const char *value = crm_element_value(request, F_STONITH_CLIENTNAME);

        if (value == NULL) {
            value = "unknown";
        }
        c->name = g_strdup_printf("%s.%u", value, c->pid);
    }

    crm_trace("Flags %u for command %u from %s", flags, id, crm_client_name(c));
    if (flags & crm_ipc_client_response) {
        crm_trace("Need response");
        CRM_LOG_ASSERT(c->request_id == 0);     /* This means the client has two synchronous events in-flight */
        c->request_id = id;     /* Reply only to the last one */
    }

    crm_xml_add(request, F_STONITH_CLIENTID, c->id);
    crm_xml_add(request, F_STONITH_CLIENTNAME, crm_client_name(c));
    crm_xml_add(request, F_STONITH_CLIENTNODE, stonith_our_uname);

    crm_log_xml_trace(request, "Client[inbound]");
    stonith_command(c, id, flags, request, NULL);

    free_xml(request);
    return 0;
}

/* Error code means? */
static int32_t
st_ipc_closed(qb_ipcs_connection_t * c)
{
    crm_client_t *client = crm_client_get(c);

    crm_trace("Connection %p closed", c);
    crm_client_destroy(client);

    /* 0 means: yes, go ahead and destroy the connection */
    return 0;
}

static void
st_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p destroyed", c);
}

static void
stonith_peer_callback(xmlNode * msg, void *private_data)
{
    const char *remote_peer = crm_element_value(msg, F_ORIG);
    const char *op = crm_element_value(msg, F_STONITH_OPERATION);

    if (crm_str_eq(op, "poke", TRUE)) {
        return;
    }

    crm_log_xml_trace(msg, "Peer[inbound]");
    stonith_command(NULL, 0, 0, msg, remote_peer);
}

#if SUPPORT_HEARTBEAT
static void
stonith_peer_hb_callback(HA_Message * msg, void *private_data)
{
    xmlNode *xml = convert_ha_message(NULL, msg, __FUNCTION__);

    stonith_peer_callback(xml, private_data);
    free_xml(xml);
}

static void
stonith_peer_hb_destroy(gpointer user_data)
{
    if (stonith_shutdown_flag) {
        crm_info("Heartbeat disconnection complete... exiting");
    } else {
        crm_err("Heartbeat connection lost!  Exiting.");
    }
    stonith_shutdown(0);
}
#endif

#if SUPPORT_COROSYNC
static void
stonith_peer_ais_callback(cpg_handle_t handle,
                          const struct cpg_name *groupName,
                          uint32_t nodeid, uint32_t pid, void *msg, size_t msg_len)
{
    uint32_t kind = 0;
    xmlNode *xml = NULL;
    const char *from = NULL;
    char *data = pcmk_message_common_cs(handle, nodeid, pid, msg, &kind, &from);

    if(data == NULL) {
        return;
    }
    if (kind == crm_class_cluster) {
        xml = string2xml(data);
        if (xml == NULL) {
            crm_err("Invalid XML: '%.120s'", data);
            free(data);
            return;
        }
        crm_xml_add(xml, F_ORIG, from);
        /* crm_xml_add_int(xml, F_SEQ, wrapper->id); */
        stonith_peer_callback(xml, NULL);
    }

    free_xml(xml);
    free(data);
    return;
}

static void
stonith_peer_cs_destroy(gpointer user_data)
{
    crm_err("Corosync connection terminated");
    stonith_shutdown(0);
}
#endif

void
do_local_reply(xmlNode * notify_src, const char *client_id, gboolean sync_reply, gboolean from_peer)
{
    /* send callback to originating child */
    crm_client_t *client_obj = NULL;
    int local_rc = pcmk_ok;

    crm_trace("Sending response");
    client_obj = crm_client_get_by_id(client_id);

    crm_trace("Sending callback to request originator");
    if (client_obj == NULL) {
        local_rc = -1;
        crm_trace("No client to sent the response to.  F_STONITH_CLIENTID not set.");

    } else {
        int rid = 0;

        if (sync_reply) {
            CRM_LOG_ASSERT(client_obj->request_id);

            rid = client_obj->request_id;
            client_obj->request_id = 0;

            crm_trace("Sending response %d to %s %s",
                      rid, client_obj->name, from_peer ? "(originator of delegated request)" : "");

        } else {
            crm_trace("Sending an event to %s %s",
                      client_obj->name, from_peer ? "(originator of delegated request)" : "");
        }

        local_rc = crm_ipcs_send(client_obj, rid, notify_src, !sync_reply);
    }

    if (local_rc < pcmk_ok && client_obj != NULL) {
        crm_warn("%sSync reply to %s failed: %s",
                 sync_reply ? "" : "A-",
                 client_obj ? client_obj->name : "<unknown>", pcmk_strerror(local_rc));
    }
}

long long
get_stonith_flag(const char *name)
{
    if (safe_str_eq(name, T_STONITH_NOTIFY_FENCE)) {
        return 0x01;

    } else if (safe_str_eq(name, STONITH_OP_DEVICE_ADD)) {
        return 0x04;

    } else if (safe_str_eq(name, STONITH_OP_DEVICE_DEL)) {
        return 0x10;
    }
    return 0;
}

static void
stonith_notify_client(gpointer key, gpointer value, gpointer user_data)
{

    xmlNode *update_msg = user_data;
    crm_client_t *client = value;
    const char *type = NULL;

    CRM_CHECK(client != NULL, return);
    CRM_CHECK(update_msg != NULL, return);

    type = crm_element_value(update_msg, F_SUBTYPE);
    CRM_CHECK(type != NULL, crm_log_xml_err(update_msg, "notify"); return);

    if (client->ipcs == NULL) {
        crm_trace("Skipping client with NULL channel");
        return;
    }

    if (client->options & get_stonith_flag(type)) {
        int rc = crm_ipcs_send(client, 0, update_msg, crm_ipc_server_event | crm_ipc_server_error);

        if (rc <= 0) {
            crm_warn("%s notification of client %s.%.6s failed: %s (%d)",
                     type, crm_client_name(client), client->id, pcmk_strerror(rc), rc);
        } else {
            crm_trace("Sent %s notification to client %s.%.6s", type, crm_client_name(client),
                      client->id);
        }
    }
}

void
do_stonith_async_timeout_update(const char *client_id, const char *call_id, int timeout)
{
    crm_client_t *client = NULL;
    xmlNode *notify_data = NULL;

    if (!timeout || !call_id || !client_id) {
        return;
    }

    client = crm_client_get_by_id(client_id);
    if (!client) {
        return;
    }

    notify_data = create_xml_node(NULL, T_STONITH_TIMEOUT_VALUE);
    crm_xml_add(notify_data, F_TYPE, T_STONITH_TIMEOUT_VALUE);
    crm_xml_add(notify_data, F_STONITH_CALLID, call_id);
    crm_xml_add_int(notify_data, F_STONITH_TIMEOUT, timeout);

    crm_trace("timeout update is %d for client %s and call id %s", timeout, client_id, call_id);

    if (client) {
        crm_ipcs_send(client, 0, notify_data, crm_ipc_server_event);
    }

    free_xml(notify_data);
}

void
do_stonith_notify(int options, const char *type, int result, xmlNode * data)
{
    /* TODO: Standardize the contents of data */
    xmlNode *update_msg = create_xml_node(NULL, "notify");

    CRM_CHECK(type != NULL,;);

    crm_xml_add(update_msg, F_TYPE, T_STONITH_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, type);
    crm_xml_add(update_msg, F_STONITH_OPERATION, type);
    crm_xml_add_int(update_msg, F_STONITH_RC, result);

    if (data != NULL) {
        add_message_xml(update_msg, F_STONITH_CALLDATA, data);
    }

    crm_trace("Notifying clients");
    g_hash_table_foreach(client_connections, stonith_notify_client, update_msg);
    free_xml(update_msg);
    crm_trace("Notify complete");
}

static stonith_key_value_t *
parse_device_list(const char *devices)
{
    int lpc = 0;
    int max = 0;
    int last = 0;
    stonith_key_value_t *output = NULL;

    if (devices == NULL) {
        return output;
    }

    max = strlen(devices);
    for (lpc = 0; lpc <= max; lpc++) {
        if (devices[lpc] == ',' || devices[lpc] == 0) {
            char *line = NULL;

            line = calloc(1, 2 + lpc - last);
            snprintf(line, 1 + lpc - last, "%s", devices + last);
            output = stonith_key_value_add(output, NULL, line);
            free(line);

            last = lpc + 1;
        }
    }

    return output;
}

static void
topology_remove_helper(const char *node, int level)
{
    int rc;
    char *desc = NULL;
    xmlNode *data = create_xml_node(NULL, F_STONITH_LEVEL);
    xmlNode *notify_data = create_xml_node(NULL, STONITH_OP_LEVEL_DEL);

    crm_xml_add(data, "origin", __FUNCTION__);
    crm_xml_add_int(data, XML_ATTR_ID, level);
    crm_xml_add(data, F_STONITH_TARGET, node);

    rc = stonith_level_remove(data, &desc);

    crm_xml_add(notify_data, F_STONITH_DEVICE, desc);
    crm_xml_add_int(notify_data, F_STONITH_ACTIVE, g_hash_table_size(topology));

    do_stonith_notify(0, STONITH_OP_LEVEL_DEL, rc, notify_data);

    free_xml(notify_data);
    free_xml(data);
    free(desc);
}

static void
topology_register_helper(const char *node, int level, stonith_key_value_t * device_list)
{
    int rc;
    char *desc = NULL;
    xmlNode *notify_data = create_xml_node(NULL, STONITH_OP_LEVEL_ADD);
    xmlNode *data = create_level_registration_xml(node, level, device_list);

    rc = stonith_level_register(data, &desc);

    crm_xml_add(notify_data, F_STONITH_DEVICE, desc);
    crm_xml_add_int(notify_data, F_STONITH_ACTIVE, g_hash_table_size(topology));

    do_stonith_notify(0, STONITH_OP_LEVEL_ADD, rc, notify_data);

    free_xml(notify_data);
    free_xml(data);
    free(desc);
}

static void
remove_cib_device(xmlXPathObjectPtr xpathObj)
{
    int max = numXpathResults(xpathObj), lpc = 0;

    for (lpc = 0; lpc < max; lpc++) {
        const char *rsc_id = NULL;
        const char *standard = NULL;
        xmlNode *match = getXpathResult(xpathObj, lpc);

        CRM_CHECK(match != NULL, continue);

        standard = crm_element_value(match, XML_AGENT_ATTR_CLASS);

        if (safe_str_neq(standard, "stonith")) {
            continue;
        }

        rsc_id = crm_element_value(match, XML_ATTR_ID);

        stonith_device_remove(rsc_id, TRUE);
    }
}

static void
remove_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = numXpathResults(xpathObj), lpc = 0;

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *match = getXpathResult(xpathObj, lpc);

        CRM_CHECK(match != NULL, continue);

        if (crm_element_value(match, XML_DIFF_MARKER)) {
            /* Deletion */
            int index = 0;
            const char *target = crm_element_value(match, XML_ATTR_STONITH_TARGET);

            crm_element_value_int(match, XML_ATTR_STONITH_INDEX, &index);
            if (target == NULL) {
                crm_err("Invalid fencing target in element %s", ID(match));

            } else if (index <= 0) {
                crm_err("Invalid level for %s in element %s", target, ID(match));

            } else {
                topology_remove_helper(target, index);
            }
            /* } else { Deal with modifications during the 'addition' stage */
        }
    }
}

static void
register_fencing_topology(xmlXPathObjectPtr xpathObj, gboolean force)
{
    int max = numXpathResults(xpathObj), lpc = 0;

    for (lpc = 0; lpc < max; lpc++) {
        int index = 0;
        const char *target;
        const char *dev_list;
        stonith_key_value_t *devices = NULL;
        xmlNode *match = getXpathResult(xpathObj, lpc);

        CRM_CHECK(match != NULL, continue);

        crm_element_value_int(match, XML_ATTR_STONITH_INDEX, &index);
        target = crm_element_value(match, XML_ATTR_STONITH_TARGET);
        dev_list = crm_element_value(match, XML_ATTR_STONITH_DEVICES);
        devices = parse_device_list(dev_list);

        crm_trace("Updating %s[%d] (%s) to %s", target, index, ID(match), dev_list);

        if (target == NULL) {
            crm_err("Invalid fencing target in element %s", ID(match));

        } else if (index <= 0) {
            crm_err("Invalid level for %s in element %s", target, ID(match));

        } else if (force == FALSE && crm_element_value(match, XML_DIFF_MARKER)) {
            /* Addition */
            topology_register_helper(target, index, devices);

        } else {                /* Modification */
            /* Remove then re-add */
            topology_remove_helper(target, index);
            topology_register_helper(target, index, devices);
        }

        stonith_key_value_freeall(devices, 1, 1);
    }
}

/* Fencing
<diff crm_feature_set="3.0.6">
  <diff-removed>
    <fencing-topology>
      <fencing-level id="f-p1.1" target="pcmk-1" index="1" devices="poison-pill" __crm_diff_marker__="removed:top"/>
      <fencing-level id="f-p1.2" target="pcmk-1" index="2" devices="power" __crm_diff_marker__="removed:top"/>
      <fencing-level devices="disk,network" id="f-p2.1"/>
    </fencing-topology>
  </diff-removed>
  <diff-added>
    <fencing-topology>
      <fencing-level id="f-p.1" target="pcmk-1" index="1" devices="poison-pill" __crm_diff_marker__="added:top"/>
      <fencing-level id="f-p2.1" target="pcmk-2" index="1" devices="disk,something"/>
      <fencing-level id="f-p3.1" target="pcmk-2" index="2" devices="power" __crm_diff_marker__="added:top"/>
    </fencing-topology>
  </diff-added>
</diff>
*/

static void
fencing_topology_init(xmlNode * msg)
{
    xmlXPathObjectPtr xpathObj = NULL;
    const char *xpath = "//" XML_TAG_FENCING_LEVEL;

    crm_trace("Pushing in stonith topology");

    /* Grab everything */
    xpathObj = xpath_search(msg, xpath);

    register_fencing_topology(xpathObj, TRUE);

    freeXpathObject(xpathObj);
}

#define rsc_name(x) x->clone_name?x->clone_name:x->id
static bool have_fence_scsi = FALSE;

static void cib_device_update(resource_t *rsc, pe_working_set_t *data_set)
{
    node_t *node = NULL;
    const char *value = NULL;
    const char *rclass = NULL;

    if(rsc->children) {
        GListPtr gIter = NULL;
        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            cib_device_update(gIter->data, data_set);
            if(rsc->variant == pe_clone || rsc->variant == pe_master) {
                crm_trace("Only processing one copy of the clone %s", rsc->id);
                break;
            }
        }
        return;
    }

    if(g_hash_table_lookup(device_list, rsc_name(rsc))) {
        stonith_device_remove(rsc_name(rsc), TRUE);
    }

    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    if(safe_str_neq(rclass, "stonith")) {
        return;
    }

    value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    if(value && strcmp(RSC_STOPPED, value) == 0) {
        crm_info("Device %s has been disabled", rsc->id);
        return;

    } else if(stonith_our_uname) {
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if(node && strcmp(node->details->uname, stonith_our_uname) == 0) {
                break;
            }
            node = NULL;
        }
    }

    if(node == NULL) {
        GHashTableIter iter;

        crm_info("Device %s has been disabled on %s: unknown", rsc->id, stonith_our_uname);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            crm_trace("Available: %s = %d", node->details->uname, node->weight);
        }

        return;

    } else if(node->weight < 0) {
        char *score = score2char(node->weight);

        crm_info("Device %s has been disabled on %s: score=%s", rsc->id, stonith_our_uname, score);
        free(score);

        return;

    } else {
        xmlNode *data;
        GHashTableIter gIter;
        stonith_key_value_t *params = NULL;

        const char *name = NULL;
        const char *agent = crm_element_value(rsc->xml, XML_EXPR_ATTR_TYPE);
        const char *provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);

        crm_info("Device %s is allowed on %s: score=%d", rsc->id, stonith_our_uname, node->weight);
        get_rsc_attributes(rsc->parameters, rsc, node, data_set);

        g_hash_table_iter_init(&gIter, rsc->parameters);
        while (g_hash_table_iter_next(&gIter, (gpointer *) & name, (gpointer *) & value)) {
            if (!name || !value) {
                continue;
            }
            params = stonith_key_value_add(params, name, value);
            crm_trace(" %s=%s", name, value);
        }

        data = create_device_registration_xml(rsc_name(rsc), provider, agent, params);
        stonith_device_register(data, NULL, TRUE);

        /* If required, unfence ourselves on cluster startup
         *
         * Make this generic/smarter if/when more than a single agent needs this
         */
        if(have_fence_scsi == FALSE && safe_str_eq(agent, "fence_scsi")) {
            stonith_device_t *device = g_hash_table_lookup(device_list, rsc->id);

            if(stonith_our_uname == NULL) {
                crm_trace("Cannot unfence ourselves: no local host name");

            } else if(device == NULL) {
                crm_err("Cannot unfence ourselves: no such device '%s'", rsc->id);

            } else {
                const char *alias = g_hash_table_lookup(device->aliases, stonith_our_uname);

                if (!alias) {
                    alias = stonith_our_uname;
                }

                if (device->targets && string_in_list(device->targets, alias)) {
                    have_fence_scsi = TRUE;
                    crm_notice("Unfencing ourselves with %s (%s)", agent, device->id);
                    schedule_internal_command(__FUNCTION__, device, "on", stonith_our_uname, 0, NULL, unfence_cb);
                }
            }
        }

        stonith_key_value_freeall(params, 1, 1);
        free_xml(data);
    }
}

extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now);
extern node_t *create_node(const char *id, const char *uname, const char *type, const char *score, pe_working_set_t * data_set);

static void
cib_devices_update(void)
{
    GListPtr gIter = NULL;
    pe_working_set_t data_set;

    set_working_set_defaults(&data_set);
    data_set.input = local_cib;
    data_set.now = crm_time_new(NULL);
    data_set.flags |= pe_flag_quick_location;
    data_set.localhost = stonith_our_uname;

    cluster_status(&data_set);
    do_calculations(&data_set, NULL, NULL);

    for (gIter = data_set.resources; gIter != NULL; gIter = gIter->next) {
        cib_device_update(gIter->data, &data_set);
    }
    data_set.input = NULL; /* Wasn't a copy */
    cleanup_alloc_calculations(&data_set);
}

static void
update_cib_stonith_devices(const char *event, xmlNode * msg)
{
    const char *reason = "none";
    gboolean needs_update = FALSE;
    xmlXPathObjectPtr xpath_obj = NULL;

    /* process new constraints */
    xpath_obj = xpath_search(msg, "//" F_CIB_UPDATE_RESULT "//" XML_CONS_TAG_RSC_LOCATION);
    if (numXpathResults(xpath_obj) > 0) {
        int max = numXpathResults(xpath_obj), lpc = 0;

        /* Safest and simplest to always recompute */
        needs_update = TRUE;
        reason = "new location constraint";

        for (lpc = 0; lpc < max; lpc++) {
            xmlNode *match = getXpathResult(xpath_obj, lpc);

            crm_log_xml_trace(match, "new constraint");
        }
    }
    freeXpathObject(xpath_obj);

    /* process deletions */
    xpath_obj = xpath_search(msg, "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//" XML_CIB_TAG_RESOURCE);
    if (numXpathResults(xpath_obj) > 0) {
        remove_cib_device(xpath_obj);
    }
    freeXpathObject(xpath_obj);

    /* process additions */
    xpath_obj = xpath_search(msg, "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_CIB_TAG_RESOURCE);
    if (numXpathResults(xpath_obj) > 0) {
        int max = numXpathResults(xpath_obj), lpc = 0;

        for (lpc = 0; lpc < max; lpc++) {
            const char *rsc_id = NULL;
            const char *standard = NULL;
            xmlNode *match = getXpathResult(xpath_obj, lpc);

            rsc_id = crm_element_value(match, XML_ATTR_ID);
            standard = crm_element_value(match, XML_AGENT_ATTR_CLASS);

            if (safe_str_neq(standard, "stonith")) {
                continue;
            }

            crm_trace("Fencing resource %s was added or modified", rsc_id);
            reason = "new resource";
            needs_update = TRUE;
        }
    }
    freeXpathObject(xpath_obj);

    if(needs_update) {
        crm_info("Updating device list from the cib: %s", reason);
        cib_devices_update();
    }
}

static void
update_fencing_topology(const char *event, xmlNode * msg)
{
    const char *xpath;
    xmlXPathObjectPtr xpathObj = NULL;

    /* Process deletions (only) */
    xpath = "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//" XML_TAG_FENCING_LEVEL;
    xpathObj = xpath_search(msg, xpath);

    remove_fencing_topology(xpathObj);
    freeXpathObject(xpathObj);

    /* Process additions and changes */
    xpath = "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_TAG_FENCING_LEVEL;
    xpathObj = xpath_search(msg, xpath);

    register_fencing_topology(xpathObj, FALSE);
    freeXpathObject(xpathObj);
}
static bool have_cib_devices = FALSE;

static void
update_cib_cache_cb(const char *event, xmlNode * msg)
{
    int rc = pcmk_ok;
    static int (*cib_apply_patch_event)(xmlNode *, xmlNode *, xmlNode **, int) = NULL;

    if(!have_cib_devices) {
        crm_trace("Skipping updates until we get a full dump");
        return;

    } else if(msg == NULL) {
        crm_trace("Missing %s update", event);
        return;
    }

    if (cib_apply_patch_event == NULL) {
        cib_apply_patch_event = find_library_function(&cib_library, CIB_LIBRARY, "cib_apply_patch_event", TRUE);
    }

    CRM_ASSERT(cib_apply_patch_event);

    /* Maintain a local copy of the CIB so that we have full access to the device definitions and location constraints */
    if (local_cib != NULL) {
        xmlNode *cib_last = local_cib;

        local_cib = NULL;
        rc = (*cib_apply_patch_event)(msg, cib_last, &local_cib, LOG_DEBUG);
        free_xml(cib_last);

        switch (rc) {
            case -pcmk_err_diff_resync:
            case -pcmk_err_diff_failed:
                crm_notice("[%s] Patch aborted: %s (%d)", event, pcmk_strerror(rc), rc);
            case pcmk_ok:
                break;
            default:
                crm_warn("[%s] ABORTED: %s (%d)", event, pcmk_strerror(rc), rc);
        }
    }

    if (local_cib == NULL) {
        crm_trace("Re-requesting the full cib after diff failure");
        rc = cib_api->cmds->query(cib_api, NULL, &local_cib, cib_scope_local | cib_sync_call);
        if(rc != pcmk_ok) {
            crm_err("Couldnt retrieve the CIB: %s (%d)", pcmk_strerror(rc), rc);
        }
        CRM_ASSERT(local_cib != NULL);
    }

    update_fencing_topology(event, msg);
    update_cib_stonith_devices(event, msg);
}

static void
init_cib_cache_cb(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    crm_info("Updating device list from the cib: init");
    have_cib_devices = TRUE;
    local_cib = copy_xml(output);

    fencing_topology_init(msg);
    cib_devices_update();
}

static void
stonith_shutdown(int nsig)
{
    stonith_shutdown_flag = TRUE;
    crm_info("Terminating with  %d clients", crm_hash_table_size(client_connections));
    if (mainloop != NULL && g_main_is_running(mainloop)) {
        g_main_quit(mainloop);
    } else {
        stonith_cleanup();
        crm_exit(pcmk_ok);
    }
}

static void
cib_connection_destroy(gpointer user_data)
{
    if (stonith_shutdown_flag) {
        crm_info("Connection to the CIB closed.");
        return;
    } else {
        crm_notice("Connection to the CIB terminated. Shutting down.");
    }
    if (cib_api) {
        cib_api->cmds->signoff(cib_api);
    }
    stonith_shutdown(0);
}

static void
stonith_cleanup(void)
{
    if (cib_api) {
        cib_api->cmds->signoff(cib_api);
    }

    if (ipcs) {
        qb_ipcs_destroy(ipcs);
    }
    crm_peer_destroy();
    crm_client_cleanup();
    free(stonith_our_uname);
    free_xml(local_cib);
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"stand-alone",         0, 0, 's'},
    {"stand-alone-w-cpg",   0, 0, 'c'},
    {"verbose",     0, 0, 'V'},
    {"version",     0, 0, '$'},
    {"help",        0, 0, '?'},

    {0, 0, 0, 0}
};
/* *INDENT-ON* */

static void
setup_cib(void)
{
    int rc, retries = 0;
    static cib_t *(*cib_new_fn) (void) = NULL;

    if (cib_new_fn == NULL) {
        cib_new_fn = find_library_function(&cib_library, CIB_LIBRARY, "cib_new", TRUE);
    }

    if (cib_new_fn != NULL) {
        cib_api = (*cib_new_fn) ();
    }

    if (cib_api == NULL) {
        crm_err("No connection to the CIB");
        return;
    }

    do {
        sleep(retries);
        rc = cib_api->cmds->signon(cib_api, CRM_SYSTEM_CRMD, cib_command);
    } while (rc == -ENOTCONN && ++retries < 5);

    if (rc != pcmk_ok) {
        crm_err("Could not connect to the CIB service: %s (%d)", pcmk_strerror(rc), rc);

    } else if (pcmk_ok !=
               cib_api->cmds->add_notify_callback(cib_api, T_CIB_DIFF_NOTIFY, update_cib_cache_cb)) {
        crm_err("Could not set CIB notification callback");

    } else {
        rc = cib_api->cmds->query(cib_api, NULL, NULL, cib_scope_local);
        cib_api->cmds->register_callback(cib_api, rc, 120, FALSE, NULL, "init_cib_cache_cb",
                                         init_cib_cache_cb);
        cib_api->cmds->set_connection_dnotify(cib_api, cib_connection_destroy);
        crm_notice("Watching for stonith topology changes");
    }
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = st_ipc_accept,
    .connection_created = st_ipc_created,
    .msg_process = st_ipc_dispatch,
    .connection_closed = st_ipc_closed,
    .connection_destroyed = st_ipc_destroy
};

static void
st_peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    /*
     * This is a hack until we can send to a nodeid and/or we fix node name lookups
     * These messages are ignored in stonith_peer_callback()
     */
    xmlNode *query = create_xml_node(NULL, "stonith_command");

    crm_xml_add(query, F_XML_TAGNAME, "stonith_command");
    crm_xml_add(query, F_TYPE, T_STONITH_NG);
    crm_xml_add(query, F_STONITH_OPERATION, "poke");

    crm_debug("Broadcasting our uname because of node %u", node->id);
    send_cluster_message(NULL, crm_msg_stonith_ng, query, FALSE);

    free_xml(query);
}

int
main(int argc, char **argv)
{
    int flag;
    int rc = 0;
    int lpc = 0;
    int argerr = 0;
    int option_index = 0;
    crm_cluster_t cluster;
    const char *actions[] = { "reboot", "off", "list", "monitor", "status" };

    crm_log_init("stonith-ng", LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    crm_set_options(NULL, "mode [options]", long_options,
                    "Provides a summary of cluster's current state."
                    "\n\nOutputs varying levels of detail in a number of different formats.\n");

    while (1) {
        flag = crm_get_option(argc, argv, &option_index);
        if (flag == -1) {
            break;
        }

        switch (flag) {
            case 'V':
                crm_bump_log_level(argc, argv);
                break;
            case 's':
                stand_alone = TRUE;
                break;
            case 'c':
                stand_alone = FALSE;
                no_cib_connect = TRUE;
                break;
            case '$':
            case '?':
                crm_help(flag, EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        printf("<?xml version=\"1.0\"?><!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n");
        printf("<resource-agent name=\"stonithd\">\n");
        printf(" <version>1.0</version>\n");
        printf
            (" <longdesc lang=\"en\">This is a fake resource that details the instance attributes handled by stonithd.</longdesc>\n");
        printf(" <shortdesc lang=\"en\">Options available for all stonith resources</shortdesc>\n");
        printf(" <parameters>\n");

        printf("  <parameter name=\"stonith-timeout\" unique=\"0\">\n");
        printf
            ("    <shortdesc lang=\"en\">How long to wait for the STONITH action to complete per a stonith device.</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">Overrides the stonith-timeout cluster property</longdesc>\n");
        printf("    <content type=\"time\" default=\"60s\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"priority\" unique=\"0\">\n");
        printf
            ("    <shortdesc lang=\"en\">The priority of the stonith resource. Devices are tried in order of highest priority to lowest.</shortdesc>\n");
        printf("    <content type=\"integer\" default=\"0\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTARG);
        printf
            ("    <shortdesc lang=\"en\">Advanced use only: An alternate parameter to supply instead of 'port'</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">Some devices do not support the standard 'port' parameter or may provide additional ones.\n"
             "Use this to specify an alternate, device-specific, parameter that should indicate the machine to be fenced.\n"
             "A value of 'none' can be used to tell the cluster not to supply any additional parameters.\n"
             "     </longdesc>\n");
        printf("    <content type=\"string\" default=\"port\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTMAP);
        printf
            ("    <shortdesc lang=\"en\">A mapping of host names to ports numbers for devices that do not support host names.</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">Eg. node1:1;node2:2,3 would tell the cluster to use port 1 for node1 and ports 2 and 3 for node2</longdesc>\n");
        printf("    <content type=\"string\" default=\"\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTLIST);
        printf
            ("    <shortdesc lang=\"en\">A list of machines controlled by this device (Optional unless %s=static-list).</shortdesc>\n",
             STONITH_ATTR_HOSTCHECK);
        printf("    <content type=\"string\" default=\"\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_HOSTCHECK);
        printf
            ("    <shortdesc lang=\"en\">How to determin which machines are controlled by the device.</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">Allowed values: dynamic-list (query the device), static-list (check the %s attribute), none (assume every device can fence every machine)</longdesc>\n",
             STONITH_ATTR_HOSTLIST);
        printf("    <content type=\"string\" default=\"dynamic-list\"/>\n");
        printf("  </parameter>\n");

        for (lpc = 0; lpc < DIMOF(actions); lpc++) {
            printf("  <parameter name=\"pcmk_%s_action\" unique=\"0\">\n", actions[lpc]);
            printf
                ("    <shortdesc lang=\"en\">Advanced use only: An alternate command to run instead of '%s'</shortdesc>\n",
                 actions[lpc]);
            printf
                ("    <longdesc lang=\"en\">Some devices do not support the standard commands or may provide additional ones.\n"
                 "Use this to specify an alternate, device-specific, command that implements the '%s' action.</longdesc>\n",
                 actions[lpc]);
            printf("    <content type=\"string\" default=\"%s\"/>\n", actions[lpc]);
            printf("  </parameter>\n");

            printf("  <parameter name=\"pcmk_%s_timeout\" unique=\"0\">\n", actions[lpc]);
            printf
                ("    <shortdesc lang=\"en\">Advanced use only: Specify an alternate timeout to use for %s actions instead of stonith-timeout</shortdesc>\n",
                 actions[lpc]);
            printf
                ("    <longdesc lang=\"en\">Some devices need much more/less time to complete than normal.\n"
                 "Use this to specify an alternate, device-specific, timeout for '%s' actions.</longdesc>\n",
                 actions[lpc]);
            printf("    <content type=\"time\" default=\"60s\"/>\n");
            printf("  </parameter>\n");

            printf("  <parameter name=\"pcmk_%s_retries\" unique=\"0\">\n", actions[lpc]);
            printf
                ("    <shortdesc lang=\"en\">Advanced use only: The maximum number of times to retry the '%s' command within the timeout period</shortdesc>\n",
                 actions[lpc]);
            printf("    <longdesc lang=\"en\">Some devices do not support multiple connections."
                   " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation, if there is time remaining."
                   " Use this option to alter the number of times Pacemaker retries '%s' actions before giving up."
                   "</longdesc>\n", actions[lpc]);
            printf("    <content type=\"integer\" default=\"2\"/>\n");
            printf("  </parameter>\n");
        }

        printf(" </parameters>\n");
        printf("</resource-agent>\n");
        return 0;
    }

    if (optind != argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', EX_USAGE);
    }

    mainloop_add_signal(SIGTERM, stonith_shutdown);

    crm_peer_init();

    if (stand_alone == FALSE) {
#if SUPPORT_HEARTBEAT
        cluster.hb_conn = NULL;
        cluster.hb_dispatch = stonith_peer_hb_callback;
        cluster.destroy = stonith_peer_hb_destroy;
#endif

        if (is_openais_cluster()) {
#if SUPPORT_COROSYNC
            cluster.destroy = stonith_peer_cs_destroy;
            cluster.cpg.cpg_deliver_fn = stonith_peer_ais_callback;
            cluster.cpg.cpg_confchg_fn = pcmk_cpg_membership;
#endif
        }

        if (crm_cluster_connect(&cluster) == FALSE) {
            crm_crit("Cannot sign in to the cluster... terminating");
            crm_exit(DAEMON_RESPAWN_STOP);
        }
        stonith_our_uname = cluster.uname;
        stonith_our_uuid = cluster.uuid;

        if (no_cib_connect == FALSE) {
            setup_cib();
        }

    } else {
        stonith_our_uname = strdup("localhost");
    }

    crm_set_status_callback(&st_peer_update_callback);

    device_list = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, free_device);

    topology = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, free_topology_entry);

    stonith_ipc_server_init(&ipcs, &ipc_callbacks);

#if SUPPORT_STONITH_CONFIG
    if (((stand_alone == TRUE)) && !(standalone_cfg_read_file(STONITH_NG_CONF_FILE))) {
        standalone_cfg_commit();
    }
#endif

    /* Create the mainloop and run it... */
    mainloop = g_main_new(FALSE);
    crm_info("Starting %s mainloop", crm_system_name);

    g_main_run(mainloop);
    stonith_cleanup();

#if SUPPORT_HEARTBEAT
    if (cluster.hb_conn) {
        cluster.hb_conn->llc_ops->delete(cluster.hb_conn);
    }
#endif

    crm_info("Done");

    return crm_exit(rc);
}

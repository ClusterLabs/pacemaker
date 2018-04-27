/*
 * Copyright 2009-2018 Andrew Beekhof <andrew@beekhof.net>
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
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
#include <sched_allocate.h>

#include <pacemaker-fenced.h>

char *stonith_our_uname = NULL;
char *stonith_our_uuid = NULL;
long stonith_watchdog_timeout_ms = 0;

GMainLoop *mainloop = NULL;

gboolean stand_alone = FALSE;
gboolean no_cib_connect = FALSE;
gboolean stonith_shutdown_flag = FALSE;

qb_ipcs_service_t *ipcs = NULL;
xmlNode *local_cib = NULL;

GHashTable *known_peer_names = NULL;

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
    int call_options = 0;
    xmlNode *request = NULL;
    crm_client_t *c = crm_client_get(qbc);
    const char *op = NULL;

    if (c == NULL) {
        crm_info("Invalid client: %p", qbc);
        return 0;
    }

    request = crm_ipcs_recv(c, data, size, &id, &flags);
    if (request == NULL) {
        crm_ipcs_send_ack(c, id, flags, "nack", __FUNCTION__, __LINE__);
        return 0;
    }


    op = crm_element_value(request, F_CRM_TASK);
    if(safe_str_eq(op, CRM_OP_RM_NODE_CACHE)) {
        crm_xml_add(request, F_TYPE, T_STONITH_NG);
        crm_xml_add(request, F_STONITH_OPERATION, op);
        crm_xml_add(request, F_STONITH_CLIENTID, c->id);
        crm_xml_add(request, F_STONITH_CLIENTNAME, crm_client_name(c));
        crm_xml_add(request, F_STONITH_CLIENTNODE, stonith_our_uname);

        send_cluster_message(NULL, crm_msg_stonith_ng, request, FALSE);
        free_xml(request);
        return 0;
    }

    if (c->name == NULL) {
        const char *value = crm_element_value(request, F_STONITH_CLIENTNAME);

        if (value == NULL) {
            value = "unknown";
        }
        c->name = crm_strdup_printf("%s.%u", value, c->pid);
    }

    crm_element_value_int(request, F_STONITH_CALLOPTS, &call_options);
    crm_trace("Flags %u/%u for command %u from %s", flags, call_options, id, crm_client_name(c));

    if (is_set(call_options, st_opt_sync_call)) {
        CRM_ASSERT(flags & crm_ipc_client_response);
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

    if (client == NULL) {
        return 0;
    }

    crm_trace("Connection %p closed", c);
    crm_client_destroy(client);

    /* 0 means: yes, go ahead and destroy the connection */
    return 0;
}

static void
st_ipc_destroy(qb_ipcs_connection_t * c)
{
    crm_trace("Connection %p destroyed", c);
    st_ipc_closed(c);
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

        local_rc = crm_ipcs_send(client_obj, rid, notify_src, sync_reply?crm_ipc_flags_none:crm_ipc_server_event);
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

static void
do_stonith_notify_config(int options, const char *op, int rc,
                         const char *desc, int active)
{
    xmlNode *notify_data = create_xml_node(NULL, op);

    CRM_CHECK(notify_data != NULL, return);

    crm_xml_add(notify_data, F_STONITH_DEVICE, desc);
    crm_xml_add_int(notify_data, F_STONITH_ACTIVE, active);

    do_stonith_notify(options, op, rc, notify_data);
    free_xml(notify_data);
}

void
do_stonith_notify_device(int options, const char *op, int rc, const char *desc)
{
    do_stonith_notify_config(options, op, rc, desc, g_hash_table_size(device_list));
}

void
do_stonith_notify_level(int options, const char *op, int rc, const char *desc)
{
    do_stonith_notify_config(options, op, rc, desc, g_hash_table_size(topology));
}

static void
topology_remove_helper(const char *node, int level)
{
    int rc;
    char *desc = NULL;
    xmlNode *data = create_xml_node(NULL, XML_TAG_FENCING_LEVEL);

    crm_xml_add(data, F_STONITH_ORIGIN, __FUNCTION__);
    crm_xml_add_int(data, XML_ATTR_STONITH_INDEX, level);
    crm_xml_add(data, XML_ATTR_STONITH_TARGET, node);

    rc = stonith_level_remove(data, &desc);
    do_stonith_notify_level(0, STONITH_OP_LEVEL_DEL, rc, desc);

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

        CRM_LOG_ASSERT(match != NULL);
        if(match != NULL) {
            standard = crm_element_value(match, XML_AGENT_ATTR_CLASS);
        }

        if (safe_str_neq(standard, PCMK_RESOURCE_CLASS_STONITH)) {
            continue;
        }

        rsc_id = crm_element_value(match, XML_ATTR_ID);

        stonith_device_remove(rsc_id, TRUE);
    }
}

static void
handle_topology_change(xmlNode *match, bool remove) 
{
    int rc;
    char *desc = NULL;

    CRM_CHECK(match != NULL, return);
    crm_trace("Updating %s", ID(match));

    if(remove) {
        int index = 0;
        char *key = stonith_level_key(match, -1);

        crm_element_value_int(match, XML_ATTR_STONITH_INDEX, &index);
        topology_remove_helper(key, index);
        free(key);
    }

    rc = stonith_level_register(match, &desc);
    do_stonith_notify_level(0, STONITH_OP_LEVEL_ADD, rc, desc);

    free(desc);
}

static void
remove_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = numXpathResults(xpathObj), lpc = 0;

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *match = getXpathResult(xpathObj, lpc);

        CRM_LOG_ASSERT(match != NULL);
        if (match && crm_element_value(match, XML_DIFF_MARKER)) {
            /* Deletion */
            int index = 0;
            char *target = stonith_level_key(match, -1);

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
register_fencing_topology(xmlXPathObjectPtr xpathObj)
{
    int max = numXpathResults(xpathObj), lpc = 0;

    for (lpc = 0; lpc < max; lpc++) {
        xmlNode *match = getXpathResult(xpathObj, lpc);

        handle_topology_change(match, TRUE);
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
fencing_topology_init()
{
    xmlXPathObjectPtr xpathObj = NULL;
    const char *xpath = "//" XML_TAG_FENCING_LEVEL;

    crm_trace("Full topology refresh");
    free_topology_list();
    init_topology_list();

    /* Grab everything */
    xpathObj = xpath_search(local_cib, xpath);
    register_fencing_topology(xpathObj);

    freeXpathObject(xpathObj);
}

#define rsc_name(x) x->clone_name?x->clone_name:x->id

/*!
 * \internal
 * \brief Check whether our uname is in a resource's allowed node list
 *
 * \param[in] rsc  Resource to check
 *
 * \return Pointer to node object if found, NULL otherwise
 */
static node_t *
our_node_allowed_for(resource_t *rsc)
{
    GHashTableIter iter;
    node_t *node = NULL;

    if (rsc && stonith_our_uname) {
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if (node && strcmp(node->details->uname, stonith_our_uname) == 0) {
                break;
            }
            node = NULL;
        }
    }
    return node;
}

/*!
 * \internal
 * \brief If a resource or any of its children are STONITH devices, update their
 *        definitions given a cluster working set.
 *
 * \param[in] rsc       Resource to check
 * \param[in] data_set  Cluster working set with device information
 */
static void cib_device_update(resource_t *rsc, pe_working_set_t *data_set)
{
    node_t *node = NULL;
    const char *value = NULL;
    const char *rclass = NULL;
    node_t *parent = NULL;
    gboolean remove = TRUE;

    /* If this is a complex resource, check children rather than this resource itself.
     * TODO: Mark each installed device and remove if untouched when this process finishes.
     */
    if(rsc->children) {
        GListPtr gIter = NULL;
        for (gIter = rsc->children; gIter != NULL; gIter = gIter->next) {
            cib_device_update(gIter->data, data_set);
            if(pe_rsc_is_clone(rsc)) {
                crm_trace("Only processing one copy of the clone %s", rsc->id);
                break;
            }
        }
        return;
    }

    /* We only care about STONITH resources. */
    rclass = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    if (safe_str_neq(rclass, PCMK_RESOURCE_CLASS_STONITH)) {
        return;
    }

    /* If this STONITH resource is disabled, just remove it. */
    value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);
    if (safe_str_eq(value, RSC_STOPPED)) {
        crm_info("Device %s has been disabled", rsc->id);
        goto update_done;
    }

    /* Check whether our node is allowed for this resource (and its parent if in a group) */
    node = our_node_allowed_for(rsc);
    if (rsc->parent && (rsc->parent->variant == pe_group)) {
        parent = our_node_allowed_for(rsc->parent);
    }

    if(node == NULL) {
        /* Our node is disallowed, so remove the device */
        GHashTableIter iter;

        crm_info("Device %s has been disabled on %s: unknown", rsc->id, stonith_our_uname);
        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            crm_trace("Available: %s = %d", node->details->uname, node->weight);
        }

        goto update_done;

    } else if(node->weight < 0 || (parent && parent->weight < 0)) {
        /* Our node (or its group) is disallowed by score, so remove the device */
        char *score = score2char((node->weight < 0) ? node->weight : parent->weight);

        crm_info("Device %s has been disabled on %s: score=%s", rsc->id, stonith_our_uname, score);
        free(score);

        goto update_done;

    } else {
        /* Our node is allowed, so update the device information */
        xmlNode *data;
        GHashTableIter gIter;
        stonith_key_value_t *params = NULL;

        const char *name = NULL;
        const char *agent = crm_element_value(rsc->xml, XML_EXPR_ATTR_TYPE);
        const char *provider = crm_element_value(rsc->xml, XML_AGENT_ATTR_PROVIDER);
        const char *rsc_provides = NULL;

        crm_debug("Device %s is allowed on %s: score=%d", rsc->id, stonith_our_uname, node->weight);
        get_rsc_attributes(rsc->parameters, rsc, node, data_set);
        get_meta_attributes(rsc->meta, rsc, node, data_set);

        rsc_provides = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_PROVIDES);

        g_hash_table_iter_init(&gIter, rsc->parameters);
        while (g_hash_table_iter_next(&gIter, (gpointer *) & name, (gpointer *) & value)) {
            if (!name || !value) {
                continue;
            }
            params = stonith_key_value_add(params, name, value);
            crm_trace(" %s=%s", name, value);
        }

        remove = FALSE;
        data = create_device_registration_xml(rsc_name(rsc), provider, agent, params, rsc_provides);
        stonith_device_register(data, NULL, TRUE);

        stonith_key_value_freeall(params, 1, 1);
        free_xml(data);
    }

update_done:

    if(remove && g_hash_table_lookup(device_list, rsc_name(rsc))) {
        stonith_device_remove(rsc_name(rsc), TRUE);
    }
}

extern xmlNode *do_calculations(pe_working_set_t * data_set, xmlNode * xml_input, crm_time_t * now);

/*!
 * \internal
 * \brief Update all STONITH device definitions based on current CIB
 */
static void
cib_devices_update(void)
{
    GListPtr gIter = NULL;
    pe_working_set_t data_set;

    crm_info("Updating devices to version %s.%s.%s",
             crm_element_value(local_cib, XML_ATTR_GENERATION_ADMIN),
             crm_element_value(local_cib, XML_ATTR_GENERATION),
             crm_element_value(local_cib, XML_ATTR_NUMUPDATES));

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
update_cib_stonith_devices_v2(const char *event, xmlNode * msg)
{
    xmlNode *change = NULL;
    char *reason = NULL;
    bool needs_update = FALSE;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    for (change = __xml_first_child(patchset); change != NULL; change = __xml_next(change)) {
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);
        const char *shortpath = NULL;

        if(op == NULL || strcmp(op, "move") == 0) {
            continue;

        } else if(safe_str_eq(op, "delete") && strstr(xpath, XML_CIB_TAG_RESOURCE)) {
            const char *rsc_id = NULL;
            char *search = NULL;
            char *mutable = NULL;

            if (strstr(xpath, XML_TAG_ATTR_SETS)) {
                needs_update = TRUE;
                break;
            } 
            mutable = strdup(xpath);
            rsc_id = strstr(mutable, "primitive[@id=\'");
            if (rsc_id != NULL) {
                rsc_id += strlen("primitive[@id=\'");
                search = strchr(rsc_id, '\'');
            }
            if (search != NULL) {
                *search = 0;
                stonith_device_remove(rsc_id, TRUE);
            } else {
                crm_warn("Ignoring malformed CIB update (resource deletion)");
            }
            free(mutable);

        } else if(strstr(xpath, XML_CIB_TAG_RESOURCES)) {
            shortpath = strrchr(xpath, '/'); CRM_ASSERT(shortpath);
            reason = crm_strdup_printf("%s %s", op, shortpath+1);
            needs_update = TRUE;
            break;

        } else if(strstr(xpath, XML_CIB_TAG_CONSTRAINTS)) {
            shortpath = strrchr(xpath, '/'); CRM_ASSERT(shortpath);
            reason = crm_strdup_printf("%s %s", op, shortpath+1);
            needs_update = TRUE;
            break;
        }
    }

    if(needs_update) {
        crm_info("Updating device list from the cib: %s", reason);
        cib_devices_update();
    } else {
        crm_trace("No updates for device list found in cib");
    }
    free(reason);
}


static void
update_cib_stonith_devices_v1(const char *event, xmlNode * msg)
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

            if (safe_str_neq(standard, PCMK_RESOURCE_CLASS_STONITH)) {
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
update_cib_stonith_devices(const char *event, xmlNode * msg)
{
    int format = 1;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    CRM_ASSERT(patchset);
    crm_element_value_int(patchset, "format", &format);
    switch(format) {
        case 1:
            update_cib_stonith_devices_v1(event, msg);
            break;
        case 2:
            update_cib_stonith_devices_v2(event, msg);
            break;
        default:
            crm_warn("Unknown patch format: %d", format);
    }
}

/* Needs to hold node name + attribute name + attribute value + 75 */
#define XPATH_MAX 512

/*!
 * \internal
 * \brief Check whether a node has a specific attribute name/value
 *
 * \param[in] node    Name of node to check
 * \param[in] name    Name of an attribute to look for
 * \param[in] value   The value the named attribute needs to be set to in order to be considered a match
 *
 * \return TRUE if the locally cached CIB has the specified node attribute
 */
gboolean
node_has_attr(const char *node, const char *name, const char *value)
{
    char xpath[XPATH_MAX];
    xmlNode *match;
    int n;

    CRM_CHECK(local_cib != NULL, return FALSE);

    /* Search for the node's attributes in the CIB. While the schema allows
     * multiple sets of instance attributes, and allows instance attributes to
     * use id-ref to reference values elsewhere, that is intended for resources,
     * so we ignore that here.
     */
    n = snprintf(xpath, XPATH_MAX, "//" XML_CIB_TAG_NODES
                 "/" XML_CIB_TAG_NODE "[@uname='%s']/" XML_TAG_ATTR_SETS
                 "/" XML_CIB_TAG_NVPAIR "[@name='%s' and @value='%s']",
                 node, name, value);
    match = get_xpath_object(xpath, local_cib, LOG_TRACE);

    CRM_CHECK(n < XPATH_MAX, return FALSE);
    return (match != NULL);
}

static void
update_fencing_topology(const char *event, xmlNode * msg)
{
    int format = 1;
    const char *xpath;
    xmlXPathObjectPtr xpathObj = NULL;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    CRM_ASSERT(patchset);
    crm_element_value_int(patchset, "format", &format);

    if(format == 1) {
        /* Process deletions (only) */
        xpath = "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_REMOVED "//" XML_TAG_FENCING_LEVEL;
        xpathObj = xpath_search(msg, xpath);

        remove_fencing_topology(xpathObj);
        freeXpathObject(xpathObj);

        /* Process additions and changes */
        xpath = "//" F_CIB_UPDATE_RESULT "//" XML_TAG_DIFF_ADDED "//" XML_TAG_FENCING_LEVEL;
        xpathObj = xpath_search(msg, xpath);

        register_fencing_topology(xpathObj);
        freeXpathObject(xpathObj);

    } else if(format == 2) {
        xmlNode *change = NULL;
        int add[] = { 0, 0, 0 };
        int del[] = { 0, 0, 0 };

        xml_patch_versions(patchset, add, del);

        for (change = __xml_first_child(patchset); change != NULL; change = __xml_next(change)) {
            const char *op = crm_element_value(change, XML_DIFF_OP);
            const char *xpath = crm_element_value(change, XML_DIFF_PATH);

            if(op == NULL) {
                continue;

            } else if(strstr(xpath, "/" XML_TAG_FENCING_LEVEL) != NULL) {
                /* Change to a specific entry */

                crm_trace("Handling %s operation %d.%d.%d for %s", op, add[0], add[1], add[2], xpath);
                if(strcmp(op, "move") == 0) {
                    continue;

                } else if(strcmp(op, "create") == 0) {
                    handle_topology_change(change->children, FALSE);

                } else if(strcmp(op, "modify") == 0) {
                    xmlNode *match = first_named_child(change, XML_DIFF_RESULT);

                    if(match) {
                        handle_topology_change(match->children, TRUE);
                    }

                } else if(strcmp(op, "delete") == 0) {
                    /* Nuclear option, all we have is the path and an id... not enough to remove a specific entry */
                    crm_info("Re-initializing fencing topology after %s operation %d.%d.%d for %s",
                             op, add[0], add[1], add[2], xpath);
                    fencing_topology_init();
                    return;
                }

            } else if (strstr(xpath, "/" XML_TAG_FENCING_TOPOLOGY) != NULL) {
                /* Change to the topology in general */
                crm_info("Re-initializing fencing topology after top-level %s operation  %d.%d.%d for %s",
                         op, add[0], add[1], add[2], xpath);
                fencing_topology_init();
                return;

            } else if (strstr(xpath, "/" XML_CIB_TAG_CONFIGURATION)) {
                /* Changes to the whole config section, possibly including the topology as a whild */
                if(first_named_child(change, XML_TAG_FENCING_TOPOLOGY) == NULL) {
                    crm_trace("Nothing for us in %s operation %d.%d.%d for %s.",
                              op, add[0], add[1], add[2], xpath);

                } else if(strcmp(op, "delete") == 0 || strcmp(op, "create") == 0) {
                    crm_info("Re-initializing fencing topology after top-level %s operation %d.%d.%d for %s.",
                             op, add[0], add[1], add[2], xpath);
                    fencing_topology_init();
                    return;
                }

            } else {
                crm_trace("Nothing for us in %s operation %d.%d.%d for %s",
                          op, add[0], add[1], add[2], xpath);
            }
        }

    } else {
        crm_warn("Unknown patch format: %d", format);
    }
}
static bool have_cib_devices = FALSE;

static void
update_cib_cache_cb(const char *event, xmlNode * msg)
{
    int rc = pcmk_ok;
    xmlNode *stonith_enabled_xml = NULL;
    xmlNode *stonith_watchdog_xml = NULL;
    const char *stonith_enabled_s = NULL;
    static gboolean stonith_enabled_saved = TRUE;

    if(!have_cib_devices) {
        crm_trace("Skipping updates until we get a full dump");
        return;

    } else if(msg == NULL) {
        crm_trace("Missing %s update", event);
        return;
    }

    /* Maintain a local copy of the CIB so that we have full access
     * to device definitions, location constraints, and node attributes
     */
    if (local_cib != NULL) {
        int rc = pcmk_ok;
        xmlNode *patchset = NULL;

        crm_element_value_int(msg, F_CIB_RC, &rc);
        if (rc != pcmk_ok) {
            return;
        }

        patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);
        xml_log_patchset(LOG_TRACE, "Config update", patchset);
        rc = xml_apply_patchset(local_cib, patchset, TRUE);
        switch (rc) {
            case pcmk_ok:
            case -pcmk_err_old_data:
                break;
            case -pcmk_err_diff_resync:
            case -pcmk_err_diff_failed:
                crm_notice("[%s] Patch aborted: %s (%d)", event, pcmk_strerror(rc), rc);
                free_xml(local_cib);
                local_cib = NULL;
                break;
            default:
                crm_warn("[%s] ABORTED: %s (%d)", event, pcmk_strerror(rc), rc);
                free_xml(local_cib);
                local_cib = NULL;
        }
    }

    if (local_cib == NULL) {
        crm_trace("Re-requesting the full cib");
        rc = cib_api->cmds->query(cib_api, NULL, &local_cib, cib_scope_local | cib_sync_call);
        if(rc != pcmk_ok) {
            crm_err("Couldn't retrieve the CIB: %s (%d)", pcmk_strerror(rc), rc);
            return;
        }
        CRM_ASSERT(local_cib != NULL);
        stonith_enabled_saved = FALSE; /* Trigger a full refresh below */
    }

    stonith_enabled_xml = get_xpath_object("//nvpair[@name='stonith-enabled']", local_cib, LOG_TRACE);
    if (stonith_enabled_xml) {
        stonith_enabled_s = crm_element_value(stonith_enabled_xml, XML_NVPAIR_ATTR_VALUE);
    }

    if (stonith_enabled_s == NULL || crm_is_true(stonith_enabled_s)) {
        long timeout_ms = 0;
        const char *value = NULL;

        stonith_watchdog_xml = get_xpath_object("//nvpair[@name='stonith-watchdog-timeout']", local_cib, LOG_TRACE);
        if (stonith_watchdog_xml) {
            value = crm_element_value(stonith_watchdog_xml, XML_NVPAIR_ATTR_VALUE);
        }

        if(value) {
            timeout_ms = crm_get_msec(value);
        }
        if (timeout_ms < 0) {
            timeout_ms = crm_auto_watchdog_timeout();
        }

        if(timeout_ms != stonith_watchdog_timeout_ms) {
            crm_notice("New watchdog timeout %lds (was %lds)", timeout_ms/1000, stonith_watchdog_timeout_ms/1000);
            stonith_watchdog_timeout_ms = timeout_ms;
        }

    } else {
        stonith_watchdog_timeout_ms = 0;
    }

    if (stonith_enabled_s && crm_is_true(stonith_enabled_s) == FALSE) {
        crm_trace("Ignoring cib updates while stonith is disabled");
        stonith_enabled_saved = FALSE;
        return;

    } else if (stonith_enabled_saved == FALSE) {
        crm_info("Updating stonith device and topology lists now that stonith is enabled");
        stonith_enabled_saved = TRUE;
        fencing_topology_init();
        cib_devices_update();

    } else {
        update_fencing_topology(event, msg);
        update_cib_stonith_devices(event, msg);
    }
}

static void
init_cib_cache_cb(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    crm_info("Updating device list from the cib: init");
    have_cib_devices = TRUE;
    local_cib = copy_xml(output);

    fencing_topology_init();
    cib_devices_update();
}

static void
stonith_shutdown(int nsig)
{
    stonith_shutdown_flag = TRUE;
    crm_info("Terminating with %d clients",
             crm_hash_table_size(client_connections));
    if (mainloop != NULL && g_main_is_running(mainloop)) {
        g_main_loop_quit(mainloop);
    } else {
        stonith_cleanup();
        crm_exit(CRM_EX_OK);
    }
}

static void
cib_connection_destroy(gpointer user_data)
{
    if (stonith_shutdown_flag) {
        crm_info("Connection to the CIB manager closed");
        return;
    } else {
        crm_notice("Connection to the CIB manager terminated, shutting down");
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

    g_hash_table_destroy(known_peer_names);
    known_peer_names = NULL;

    crm_peer_destroy();
    crm_client_cleanup();
    free_remote_op_list();
    free_topology_list();
    free_device_list();
    free_metadata_cache();
    free(stonith_our_uname);
    free_xml(local_cib);
}

/* *INDENT-OFF* */
static struct crm_option long_options[] = {
    {"stand-alone",         0, 0, 's'},
    {"stand-alone-w-cpg",   0, 0, 'c'},
    {"logfile",             1, 0, 'l'},
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
        crm_err("No connection to the CIB manager");
        return;
    }

    do {
        sleep(retries);
        rc = cib_api->cmds->signon(cib_api, CRM_SYSTEM_STONITHD, cib_command);
    } while (rc == -ENOTCONN && ++retries < 5);

    if (rc != pcmk_ok) {
        crm_err("Could not connect to the CIB manager: %s (%d)", pcmk_strerror(rc), rc);

    } else if (pcmk_ok !=
               cib_api->cmds->add_notify_callback(cib_api, T_CIB_DIFF_NOTIFY, update_cib_cache_cb)) {
        crm_err("Could not set CIB notification callback");

    } else {
        rc = cib_api->cmds->query(cib_api, NULL, NULL, cib_scope_local);
        cib_api->cmds->register_callback(cib_api, rc, 120, FALSE, NULL, "init_cib_cache_cb",
                                         init_cib_cache_cb);
        cib_api->cmds->set_connection_dnotify(cib_api, cib_connection_destroy);
        crm_info("Watching for stonith topology changes");
    }
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = st_ipc_accept,
    .connection_created = st_ipc_created,
    .msg_process = st_ipc_dispatch,
    .connection_closed = st_ipc_closed,
    .connection_destroyed = st_ipc_destroy
};

/*!
 * \internal
 * \brief Callback for peer status changes
 *
 * \param[in] type  What changed
 * \param[in] node  What peer had the change
 * \param[in] data  Previous value of what changed
 */
static void
st_peer_update_callback(enum crm_status_type type, crm_node_t * node, const void *data)
{
    if ((type != crm_status_processes) && !is_set(node->flags, crm_remote_node)) {
        xmlNode *query = NULL;

        if (node->id && node->uname) {
            g_hash_table_insert(known_peer_names, GUINT_TO_POINTER(node->id), strdup(node->uname));
        }

        /*
         * This is a hack until we can send to a nodeid and/or we fix node name lookups
         * These messages are ignored in stonith_peer_callback()
         */
        query = create_xml_node(NULL, "stonith_command");

        crm_xml_add(query, F_XML_TAGNAME, "stonith_command");
        crm_xml_add(query, F_TYPE, T_STONITH_NG);
        crm_xml_add(query, F_STONITH_OPERATION, "poke");

        crm_debug("Broadcasting our uname because of node %u", node->id);
        send_cluster_message(NULL, crm_msg_stonith_ng, query, FALSE);

        free_xml(query);
    }
}

int
main(int argc, char **argv)
{
    int flag;
    int lpc = 0;
    int argerr = 0;
    int option_index = 0;
    crm_cluster_t cluster;
    const char *actions[] = { "reboot", "off", "on", "list", "monitor", "status" };

    crm_log_preinit(NULL, argc, argv);
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
            case 'l':
                crm_add_logfile(optarg);
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
                crm_help(flag, CRM_EX_OK);
                break;
            default:
                ++argerr;
                break;
        }
    }

    if (argc - optind == 1 && safe_str_eq("metadata", argv[optind])) {
        printf("<?xml version=\"1.0\"?><!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n");
        printf("<resource-agent name=\"pacemaker-fenced\">\n");
        printf(" <version>1.0</version>\n");
        printf(" <longdesc lang=\"en\">Instance attributes available for all \"stonith\"-class resources</longdesc>\n");
        printf(" <shortdesc lang=\"en\">Instance attributes available for all \"stonith\"-class resources</shortdesc>\n");
        printf(" <parameters>\n");

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
            ("    <shortdesc lang=\"en\">How to determine which machines are controlled by the device.</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">Allowed values: dynamic-list (query the device), static-list (check the %s attribute), none (assume every device can fence every machine)</longdesc>\n",
             STONITH_ATTR_HOSTLIST);
        printf("    <content type=\"string\" default=\"dynamic-list\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_DELAY_MAX);
        printf
            ("    <shortdesc lang=\"en\">Enable a random delay for stonith actions and specify the maximum of random delay.</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">This prevents double fencing when using slow devices such as sbd.\n"
             "Use this to enable a random delay for stonith actions.\n"
             "The overall delay is derived from this random delay value adding a static delay so that the sum is kept below the maximum delay.</longdesc>\n");
        printf("    <content type=\"time\" default=\"0s\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_DELAY_BASE);
        printf
            ("    <shortdesc lang=\"en\">Enable a base delay for stonith actions and specify base delay value.</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">This prevents double fencing when different delays are configured on the nodes.\n"
             "Use this to enable a static delay for stonith actions.\n"
             "The overall delay is derived from a random delay value adding this static delay so that the sum is kept below the maximum delay.</longdesc>\n");
        printf("    <content type=\"time\" default=\"0s\"/>\n");
        printf("  </parameter>\n");

        printf("  <parameter name=\"%s\" unique=\"0\">\n", STONITH_ATTR_ACTION_LIMIT);
        printf
            ("    <shortdesc lang=\"en\">The maximum number of actions can be performed in parallel on this device</shortdesc>\n");
        printf
            ("    <longdesc lang=\"en\">Cluster property concurrent-fencing=true needs to be configured first.\n"
             "Then use this to specify the maximum number of actions can be performed in parallel on this device. -1 is unlimited.</longdesc>\n");
        printf("    <content type=\"integer\" default=\"1\"/>\n");
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
        return CRM_EX_OK;
    }

    if (optind != argc) {
        ++argerr;
    }

    if (argerr) {
        crm_help('?', CRM_EX_USAGE);
    }

    crm_log_init(NULL, LOG_INFO, TRUE, FALSE, argc, argv, FALSE);
    mainloop_add_signal(SIGTERM, stonith_shutdown);

    crm_peer_init();
    known_peer_names = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, free);

    if (stand_alone == FALSE) {

        if (is_corosync_cluster()) {
#if SUPPORT_COROSYNC
            cluster.destroy = stonith_peer_cs_destroy;
            cluster.cpg.cpg_deliver_fn = stonith_peer_ais_callback;
            cluster.cpg.cpg_confchg_fn = pcmk_cpg_membership;
#endif
        }

        crm_set_status_callback(&st_peer_update_callback);

        if (crm_cluster_connect(&cluster) == FALSE) {
            crm_crit("Cannot sign in to the cluster... terminating");
            crm_exit(CRM_EX_FATAL);
        }
        stonith_our_uname = cluster.uname;
        stonith_our_uuid = cluster.uuid;

        if (no_cib_connect == FALSE) {
            setup_cib();
        }

    } else {
        stonith_our_uname = strdup("localhost");
    }

    init_device_list();
    init_topology_list();

    if(stonith_watchdog_timeout_ms > 0) {
        xmlNode *xml;
        stonith_key_value_t *params = NULL;

        params = stonith_key_value_add(params, STONITH_ATTR_HOSTLIST, stonith_our_uname);

        xml = create_device_registration_xml("watchdog", "internal", STONITH_WATCHDOG_AGENT, params, NULL);
        stonith_device_register(xml, NULL, FALSE);

        stonith_key_value_freeall(params, 1, 1);
        free_xml(xml);
    }

    stonith_ipc_server_init(&ipcs, &ipc_callbacks);

    /* Create the mainloop and run it... */
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_info("Starting %s mainloop", crm_system_name);
    g_main_loop_run(mainloop);

    stonith_cleanup();
    crm_info("Done");
    return crm_exit(CRM_EX_OK);
}

/*
 * Copyright 2009-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
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
#include <inttypes.h>  // PRIu32, PRIx32

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/cmdline_internal.h>
#include <crm/common/ipc.h>
#include <crm/common/ipc_internal.h>
#include <crm/common/output_internal.h>
#include <crm/cluster/internal.h>

#include <crm/stonith-ng.h>
#include <crm/fencing/internal.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <crm/common/mainloop.h>

#include <crm/cib/internal.h>
#include <crm/pengine/status.h>
#include <pacemaker-internal.h>

#include <pacemaker-fenced.h>

#define SUMMARY "daemon for executing fencing devices in a Pacemaker cluster"

char *stonith_our_uname = NULL;
long stonith_watchdog_timeout_ms = 0;
GList *stonith_watchdog_targets = NULL;

static GMainLoop *mainloop = NULL;

gboolean stand_alone = FALSE;
static gboolean stonith_shutdown_flag = FALSE;

static qb_ipcs_service_t *ipcs = NULL;
static xmlNode *local_cib = NULL;
static pe_working_set_t *fenced_data_set = NULL;
static const unsigned long long data_set_flags = pe_flag_quick_location
                                                 | pe_flag_no_compat
                                                 | pe_flag_no_counts;

static cib_t *cib_api = NULL;

static pcmk__output_t *logger_out = NULL;
static pcmk__output_t *out = NULL;

pcmk__supported_format_t formats[] = {
    PCMK__SUPPORTED_FORMAT_NONE,
    PCMK__SUPPORTED_FORMAT_TEXT,
    PCMK__SUPPORTED_FORMAT_XML,
    { NULL, NULL, NULL }
};

static struct {
    bool no_cib_connect;
    gchar **log_files;
} options;

static crm_exit_t exit_code = CRM_EX_OK;

static void stonith_shutdown(int nsig);
static void stonith_cleanup(void);

static int32_t
st_ipc_accept(qb_ipcs_connection_t * c, uid_t uid, gid_t gid)
{
    if (stonith_shutdown_flag) {
        crm_info("Ignoring new client [%d] during shutdown",
                 pcmk__client_pid(c));
        return -EPERM;
    }

    if (pcmk__new_client(c, uid, gid) == NULL) {
        return -EIO;
    }
    return 0;
}

/* Exit code means? */
static int32_t
st_ipc_dispatch(qb_ipcs_connection_t * qbc, void *data, size_t size)
{
    uint32_t id = 0;
    uint32_t flags = 0;
    int call_options = 0;
    xmlNode *request = NULL;
    pcmk__client_t *c = pcmk__find_client(qbc);
    const char *op = NULL;

    if (c == NULL) {
        crm_info("Invalid client: %p", qbc);
        return 0;
    }

    request = pcmk__client_data2xml(c, data, &id, &flags);
    if (request == NULL) {
        pcmk__ipc_send_ack(c, id, flags, "nack", NULL, CRM_EX_PROTOCOL);
        return 0;
    }


    op = crm_element_value(request, F_CRM_TASK);
    if(pcmk__str_eq(op, CRM_OP_RM_NODE_CACHE, pcmk__str_casei)) {
        crm_xml_add(request, F_TYPE, T_STONITH_NG);
        crm_xml_add(request, F_STONITH_OPERATION, op);
        crm_xml_add(request, F_STONITH_CLIENTID, c->id);
        crm_xml_add(request, F_STONITH_CLIENTNAME, pcmk__client_name(c));
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
    crm_trace("Flags %#08" PRIx32 "/%#08x for command %" PRIu32
              " from client %s", flags, call_options, id, pcmk__client_name(c));

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_ASSERT(flags & crm_ipc_client_response);
        CRM_LOG_ASSERT(c->request_id == 0);     /* This means the client has two synchronous events in-flight */
        c->request_id = id;     /* Reply only to the last one */
    }

    crm_xml_add(request, F_STONITH_CLIENTID, c->id);
    crm_xml_add(request, F_STONITH_CLIENTNAME, pcmk__client_name(c));
    crm_xml_add(request, F_STONITH_CLIENTNODE, stonith_our_uname);

    crm_log_xml_trace(request, "ipc-received");
    stonith_command(c, id, flags, request, NULL);

    free_xml(request);
    return 0;
}

/* Error code means? */
static int32_t
st_ipc_closed(qb_ipcs_connection_t * c)
{
    pcmk__client_t *client = pcmk__find_client(c);

    if (client == NULL) {
        return 0;
    }

    crm_trace("Connection %p closed", c);
    pcmk__free_client(client);

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

    if (pcmk__str_eq(op, "poke", pcmk__str_none)) {
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
    crm_crit("Lost connection to cluster layer, shutting down");
    stonith_shutdown(0);
}
#endif

void
do_local_reply(xmlNode *notify_src, pcmk__client_t *client, int call_options)
{
    /* send callback to originating child */
    int local_rc = pcmk_rc_ok;
    int rid = 0;
    uint32_t ipc_flags = crm_ipc_server_event;

    if (pcmk_is_set(call_options, st_opt_sync_call)) {
        CRM_LOG_ASSERT(client->request_id);
        rid = client->request_id;
        client->request_id = 0;
        ipc_flags = crm_ipc_flags_none;
    }

    local_rc = pcmk__ipc_send_xml(client, rid, notify_src, ipc_flags);
    if (local_rc == pcmk_rc_ok) {
        crm_trace("Sent response %d to client %s",
                  rid, pcmk__client_name(client));
    } else {
        crm_warn("%synchronous reply to client %s failed: %s",
                 (pcmk_is_set(call_options, st_opt_sync_call)? "S" : "As"),
                 pcmk__client_name(client), pcmk_rc_str(local_rc));
    }
}

uint64_t
get_stonith_flag(const char *name)
{
    if (pcmk__str_eq(name, T_STONITH_NOTIFY_FENCE, pcmk__str_casei)) {
        return st_callback_notify_fence;

    } else if (pcmk__str_eq(name, STONITH_OP_DEVICE_ADD, pcmk__str_casei)) {
        return st_callback_device_add;

    } else if (pcmk__str_eq(name, STONITH_OP_DEVICE_DEL, pcmk__str_casei)) {
        return st_callback_device_del;

    } else if (pcmk__str_eq(name, T_STONITH_NOTIFY_HISTORY, pcmk__str_casei)) {
        return st_callback_notify_history;

    } else if (pcmk__str_eq(name, T_STONITH_NOTIFY_HISTORY_SYNCED, pcmk__str_casei)) {
        return st_callback_notify_history_synced;

    }
    return st_callback_unknown;
}

static void
stonith_notify_client(gpointer key, gpointer value, gpointer user_data)
{

    xmlNode *update_msg = user_data;
    pcmk__client_t *client = value;
    const char *type = NULL;

    CRM_CHECK(client != NULL, return);
    CRM_CHECK(update_msg != NULL, return);

    type = crm_element_value(update_msg, F_SUBTYPE);
    CRM_CHECK(type != NULL, crm_log_xml_err(update_msg, "notify"); return);

    if (client->ipcs == NULL) {
        crm_trace("Skipping client with NULL channel");
        return;
    }

    if (pcmk_is_set(client->flags, get_stonith_flag(type))) {
        int rc = pcmk__ipc_send_xml(client, 0, update_msg,
                                    crm_ipc_server_event);

        if (rc != pcmk_rc_ok) {
            crm_warn("%s notification of client %s failed: %s "
                     CRM_XS " id=%.8s rc=%d", type, pcmk__client_name(client),
                     pcmk_rc_str(rc), client->id, rc);
        } else {
            crm_trace("Sent %s notification to client %s",
                      type, pcmk__client_name(client));
        }
    }
}

void
do_stonith_async_timeout_update(const char *client_id, const char *call_id, int timeout)
{
    pcmk__client_t *client = NULL;
    xmlNode *notify_data = NULL;

    if (!timeout || !call_id || !client_id) {
        return;
    }

    client = pcmk__find_client_by_id(client_id);
    if (!client) {
        return;
    }

    notify_data = create_xml_node(NULL, T_STONITH_TIMEOUT_VALUE);
    crm_xml_add(notify_data, F_TYPE, T_STONITH_TIMEOUT_VALUE);
    crm_xml_add(notify_data, F_STONITH_CALLID, call_id);
    crm_xml_add_int(notify_data, F_STONITH_TIMEOUT, timeout);

    crm_trace("timeout update is %d for client %s and call id %s", timeout, client_id, call_id);

    if (client) {
        pcmk__ipc_send_xml(client, 0, notify_data, crm_ipc_server_event);
    }

    free_xml(notify_data);
}

/*!
 * \internal
 * \brief Notify relevant IPC clients of a fencing operation result
 *
 * \param[in] type     Notification type
 * \param[in] result   Result of fencing operation (assume success if NULL)
 * \param[in] data     If not NULL, add to notification as call data
 */
void
fenced_send_notification(const char *type, const pcmk__action_result_t *result,
                         xmlNode *data)
{
    /* TODO: Standardize the contents of data */
    xmlNode *update_msg = create_xml_node(NULL, "notify");

    CRM_LOG_ASSERT(type != NULL);

    crm_xml_add(update_msg, F_TYPE, T_STONITH_NOTIFY);
    crm_xml_add(update_msg, F_SUBTYPE, type);
    crm_xml_add(update_msg, F_STONITH_OPERATION, type);
    stonith__xe_set_result(update_msg, result);

    if (data != NULL) {
        add_message_xml(update_msg, F_STONITH_CALLDATA, data);
    }

    crm_trace("Notifying clients");
    pcmk__foreach_ipc_client(stonith_notify_client, update_msg);
    free_xml(update_msg);
    crm_trace("Notify complete");
}

/*!
 * \internal
 * \brief Send notifications for a configuration change to subscribed clients
 *
 * \param[in] op      Notification type (STONITH_OP_DEVICE_ADD,
 *                    STONITH_OP_DEVICE_DEL, STONITH_OP_LEVEL_ADD, or
 *                    STONITH_OP_LEVEL_DEL)
 * \param[in] result  Operation result
 * \param[in] desc    Description of what changed
 * \param[in] active  Current number of devices or topologies in use
 */
static void
send_config_notification(const char *op, const pcmk__action_result_t *result,
                         const char *desc, int active)
{
    xmlNode *notify_data = create_xml_node(NULL, op);

    CRM_CHECK(notify_data != NULL, return);

    crm_xml_add(notify_data, F_STONITH_DEVICE, desc);
    crm_xml_add_int(notify_data, F_STONITH_ACTIVE, active);

    fenced_send_notification(op, result, notify_data);
    free_xml(notify_data);
}

/*!
 * \internal
 * \brief Send notifications for a device change to subscribed clients
 *
 * \param[in] op      Notification type (STONITH_OP_DEVICE_ADD or
 *                    STONITH_OP_DEVICE_DEL)
 * \param[in] result  Operation result
 * \param[in] desc    ID of device that changed
 */
void
fenced_send_device_notification(const char *op,
                                const pcmk__action_result_t *result,
                                const char *desc)
{
    send_config_notification(op, result, desc, g_hash_table_size(device_list));
}

/*!
 * \internal
 * \brief Send notifications for a topology level change to subscribed clients
 *
 * \param[in] op      Notification type (STONITH_OP_LEVEL_ADD or
 *                    STONITH_OP_LEVEL_DEL)
 * \param[in] result  Operation result
 * \param[in] desc    String representation of level (<target>[<level_index>])
 */
void
fenced_send_level_notification(const char *op,
                               const pcmk__action_result_t *result,
                               const char *desc)
{
    send_config_notification(op, result, desc, g_hash_table_size(topology));
}

static void
topology_remove_helper(const char *node, int level)
{
    char *desc = NULL;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;
    xmlNode *data = create_xml_node(NULL, XML_TAG_FENCING_LEVEL);

    crm_xml_add(data, F_STONITH_ORIGIN, __func__);
    crm_xml_add_int(data, XML_ATTR_STONITH_INDEX, level);
    crm_xml_add(data, XML_ATTR_STONITH_TARGET, node);

    fenced_unregister_level(data, &desc, &result);
    fenced_send_level_notification(STONITH_OP_LEVEL_DEL, &result, desc);
    pcmk__reset_result(&result);
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

        if (!pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
            continue;
        }

        rsc_id = crm_element_value(match, XML_ATTR_ID);

        stonith_device_remove(rsc_id, true);
    }
}

static void
remove_topology_level(xmlNode *match)
{
    int index = 0;
    char *key = NULL;

    CRM_CHECK(match != NULL, return);

    key = stonith_level_key(match, fenced_target_by_unknown);
    crm_element_value_int(match, XML_ATTR_STONITH_INDEX, &index);
    topology_remove_helper(key, index);
    free(key);
}

static void
add_topology_level(xmlNode *match)
{
    char *desc = NULL;
    pcmk__action_result_t result = PCMK__UNKNOWN_RESULT;

    CRM_CHECK(match != NULL, return);

    fenced_register_level(match, &desc, &result);
    fenced_send_level_notification(STONITH_OP_LEVEL_ADD, &result, desc);
    pcmk__reset_result(&result);
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
            char *target = stonith_level_key(match, fenced_target_by_unknown);

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

        remove_topology_level(match);
        add_topology_level(match);
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
fencing_topology_init(void)
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
static pe_node_t *
our_node_allowed_for(const pe_resource_t *rsc)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;

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

static void
watchdog_device_update(void)
{
    if (stonith_watchdog_timeout_ms > 0) {
        if (!g_hash_table_lookup(device_list, STONITH_WATCHDOG_ID) &&
            !stonith_watchdog_targets) {
            /* getting here watchdog-fencing enabled, no device there yet
               and reason isn't stonith_watchdog_targets preventing that
             */
            int rc;
            xmlNode *xml;

            xml = create_device_registration_xml(
                    STONITH_WATCHDOG_ID,
                    st_namespace_internal,
                    STONITH_WATCHDOG_AGENT,
                    NULL, /* stonith_device_register will add our
                             own name as PCMK_STONITH_HOST_LIST param
                             so we can skip that here
                           */
                    NULL);
            rc = stonith_device_register(xml, TRUE);
            free_xml(xml);
            if (rc != pcmk_ok) {
                rc = pcmk_legacy2rc(rc);
                exit_code = CRM_EX_FATAL;
                crm_crit("Cannot register watchdog pseudo fence agent: %s",
                         pcmk_rc_str(rc));
                stonith_shutdown(0);
            }
        }

    } else if (g_hash_table_lookup(device_list, STONITH_WATCHDOG_ID) != NULL) {
        /* be silent if no device - todo parameter to stonith_device_remove */
        stonith_device_remove(STONITH_WATCHDOG_ID, true);
    }
}

static void
update_stonith_watchdog_timeout_ms(xmlNode *cib)
{
    long timeout_ms = 0;
    xmlNode *stonith_watchdog_xml = NULL;
    const char *value = NULL;

    stonith_watchdog_xml = get_xpath_object("//nvpair[@name='stonith-watchdog-timeout']",
					    cib, LOG_NEVER);
    if (stonith_watchdog_xml) {
        value = crm_element_value(stonith_watchdog_xml, XML_NVPAIR_ATTR_VALUE);
    }
    if (value) {
        timeout_ms = crm_get_msec(value);
    }

    if (timeout_ms < 0) {
        timeout_ms = pcmk__auto_watchdog_timeout();
    }

    stonith_watchdog_timeout_ms = timeout_ms;
}

/*!
 * \internal
 * \brief If a resource or any of its children are STONITH devices, update their
 *        definitions given a cluster working set.
 *
 * \param[in,out] rsc       Resource to check
 * \param[in,out] data_set  Cluster working set with device information
 */
static void
cib_device_update(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    pe_node_t *node = NULL;
    const char *value = NULL;
    const char *rclass = NULL;
    pe_node_t *parent = NULL;

    /* If this is a complex resource, check children rather than this resource itself. */
    if(rsc->children) {
        GList *gIter = NULL;
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
    if (!pcmk__str_eq(rclass, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
        return;
    }

    /* If this STONITH resource is disabled, remove it. */
    if (pe__resource_is_disabled(rsc)) {
        crm_info("Device %s has been disabled", rsc->id);
        return;
    }

    /* if watchdog-fencing is disabled handle any watchdog-fence
       resource as if it was disabled
     */
    if ((stonith_watchdog_timeout_ms <= 0) &&
        pcmk__str_eq(rsc->id, STONITH_WATCHDOG_ID, pcmk__str_none)) {
        crm_info("Watchdog-fencing disabled thus handling "
                 "device %s as disabled", rsc->id);
        return;
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
            crm_trace("Available: %s = %d", pe__node_name(node), node->weight);
        }

        return;

    } else if(node->weight < 0 || (parent && parent->weight < 0)) {
        /* Our node (or its group) is disallowed by score, so remove the device */
        int score = (node->weight < 0)? node->weight : parent->weight;

        crm_info("Device %s has been disabled on %s: score=%s",
                 rsc->id, stonith_our_uname, pcmk_readable_score(score));
        return;

    } else {
        /* Our node is allowed, so update the device information */
        int rc;
        xmlNode *data;
        GHashTable *rsc_params = NULL;
        GHashTableIter gIter;
        stonith_key_value_t *params = NULL;

        const char *name = NULL;
        const char *agent = crm_element_value(rsc->xml, XML_EXPR_ATTR_TYPE);
        const char *rsc_provides = NULL;

        crm_debug("Device %s is allowed on %s: score=%d", rsc->id, stonith_our_uname, node->weight);
        rsc_params = pe_rsc_params(rsc, node, data_set);
        get_meta_attributes(rsc->meta, rsc, node, data_set);

        rsc_provides = g_hash_table_lookup(rsc->meta, PCMK_STONITH_PROVIDES);

        g_hash_table_iter_init(&gIter, rsc_params);
        while (g_hash_table_iter_next(&gIter, (gpointer *) & name, (gpointer *) & value)) {
            if (!name || !value) {
                continue;
            }
            params = stonith_key_value_add(params, name, value);
            crm_trace(" %s=%s", name, value);
        }

        data = create_device_registration_xml(rsc_name(rsc), st_namespace_any,
                                              agent, params, rsc_provides);
        stonith_key_value_freeall(params, 1, 1);
        rc = stonith_device_register(data, TRUE);
        CRM_ASSERT(rc == pcmk_ok);
        free_xml(data);
    }
}

/*!
 * \internal
 * \brief Update all STONITH device definitions based on current CIB
 */
static void
cib_devices_update(void)
{
    GHashTableIter iter;
    stonith_device_t *device = NULL;

    crm_info("Updating devices to version %s.%s.%s",
             crm_element_value(local_cib, XML_ATTR_GENERATION_ADMIN),
             crm_element_value(local_cib, XML_ATTR_GENERATION),
             crm_element_value(local_cib, XML_ATTR_NUMUPDATES));

    if (fenced_data_set->now != NULL) {
        crm_time_free(fenced_data_set->now);
        fenced_data_set->now = NULL;
    }
    fenced_data_set->localhost = stonith_our_uname;
    pcmk__schedule_actions(local_cib, data_set_flags, fenced_data_set);

    g_hash_table_iter_init(&iter, device_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&device)) {
        if (device->cib_registered) {
            device->dirty = TRUE;
        }
    }

    /* have list repopulated if cib has a watchdog-fencing-resource
       TODO: keep a cached list for queries happening while we are refreshing
     */
    g_list_free_full(stonith_watchdog_targets, free);
    stonith_watchdog_targets = NULL;
    g_list_foreach(fenced_data_set->resources, (GFunc) cib_device_update, fenced_data_set);

    g_hash_table_iter_init(&iter, device_list);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&device)) {
        if (device->dirty) {
            g_hash_table_iter_remove(&iter);
        }
    }

    fenced_data_set->input = NULL; // Wasn't a copy, so don't let API free it
    pe_reset_working_set(fenced_data_set);
}

static void
update_cib_stonith_devices_v2(const char *event, xmlNode * msg)
{
    xmlNode *change = NULL;
    char *reason = NULL;
    bool needs_update = FALSE;
    xmlNode *patchset = get_message_xml(msg, F_CIB_UPDATE_RESULT);

    for (change = pcmk__xml_first_child(patchset); change != NULL;
         change = pcmk__xml_next(change)) {
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *xpath = crm_element_value(change, XML_DIFF_PATH);
        const char *shortpath = NULL;

        if ((op == NULL) ||
            (strcmp(op, "move") == 0) ||
            strstr(xpath, "/"XML_CIB_TAG_STATUS)) {
            continue;
        } else if (pcmk__str_eq(op, "delete", pcmk__str_casei) && strstr(xpath, "/"XML_CIB_TAG_RESOURCE)) {
            const char *rsc_id = NULL;
            char *search = NULL;
            char *mutable = NULL;

            if (strstr(xpath, XML_TAG_ATTR_SETS) ||
                strstr(xpath, XML_TAG_META_SETS)) {
                needs_update = TRUE;
                pcmk__str_update(&reason,
                                 "(meta) attribute deleted from resource");
                break;
            }
            pcmk__str_update(&mutable, xpath);
            rsc_id = strstr(mutable, "primitive[@" XML_ATTR_ID "=\'");
            if (rsc_id != NULL) {
                rsc_id += strlen("primitive[@" XML_ATTR_ID "=\'");
                search = strchr(rsc_id, '\'');
            }
            if (search != NULL) {
                *search = 0;
                stonith_device_remove(rsc_id, true);
                /* watchdog_device_update called afterwards
                   to fall back to implicit definition if needed */
            } else {
                crm_warn("Ignoring malformed CIB update (resource deletion)");
            }
            free(mutable);

        } else if (strstr(xpath, "/"XML_CIB_TAG_RESOURCES) ||
                   strstr(xpath, "/"XML_CIB_TAG_CONSTRAINTS) ||
                   strstr(xpath, "/"XML_CIB_TAG_RSCCONFIG)) {
            shortpath = strrchr(xpath, '/'); CRM_ASSERT(shortpath);
            reason = crm_strdup_printf("%s %s", op, shortpath+1);
            needs_update = TRUE;
            break;
        }
    }

    if(needs_update) {
        crm_info("Updating device list from CIB: %s", reason);
        cib_devices_update();
    } else {
        crm_trace("No updates for device list found in CIB");
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

            if (!pcmk__str_eq(standard, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_casei)) {
                continue;
            }

            crm_trace("Fencing resource %s was added or modified", rsc_id);
            reason = "new resource";
            needs_update = TRUE;
        }
    }
    freeXpathObject(xpath_obj);

    if(needs_update) {
        crm_info("Updating device list from CIB: %s", reason);
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
    GString *xpath = NULL;
    xmlNode *match;

    CRM_CHECK((local_cib != NULL) && (node != NULL) && (name != NULL)
              && (value != NULL), return FALSE);

    /* Search for the node's attributes in the CIB. While the schema allows
     * multiple sets of instance attributes, and allows instance attributes to
     * use id-ref to reference values elsewhere, that is intended for resources,
     * so we ignore that here.
     */
    xpath = g_string_sized_new(256);
    pcmk__g_strcat(xpath,
                   "//" XML_CIB_TAG_NODES "/" XML_CIB_TAG_NODE
                   "[@" XML_ATTR_UNAME "='", node, "']/" XML_TAG_ATTR_SETS
                   "/" XML_CIB_TAG_NVPAIR
                   "[@" XML_NVPAIR_ATTR_NAME "='", name, "' "
                   "and @" XML_NVPAIR_ATTR_VALUE "='", value, "']", NULL);

    match = get_xpath_object((const char *) xpath->str, local_cib, LOG_NEVER);

    g_string_free(xpath, TRUE);
    return (match != NULL);
}

/*!
 * \internal
 * \brief Check whether a node does watchdog-fencing
 *
 * \param[in] node    Name of node to check
 *
 * \return TRUE if node found in stonith_watchdog_targets
 *         or stonith_watchdog_targets is empty indicating
 *         all nodes are doing watchdog-fencing
 */
gboolean
node_does_watchdog_fencing(const char *node)
{
    return ((stonith_watchdog_targets == NULL) ||
            pcmk__str_in_list(node, stonith_watchdog_targets, pcmk__str_casei));
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

        for (change = pcmk__xml_first_child(patchset); change != NULL;
             change = pcmk__xml_next(change)) {
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
                    add_topology_level(change->children);

                } else if(strcmp(op, "modify") == 0) {
                    xmlNode *match = first_named_child(change, XML_DIFF_RESULT);

                    if(match) {
                        remove_topology_level(match->children);
                        add_topology_level(match->children);
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
    long timeout_ms_saved = stonith_watchdog_timeout_ms;
    bool need_full_refresh = false;

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
        pcmk__output_set_log_level(logger_out, LOG_TRACE);
        out->message(out, "xml-patchset", patchset);
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
        crm_trace("Re-requesting full CIB");
        rc = cib_api->cmds->query(cib_api, NULL, &local_cib, cib_scope_local | cib_sync_call);
        if(rc != pcmk_ok) {
            crm_err("Couldn't retrieve the CIB: %s (%d)", pcmk_strerror(rc), rc);
            return;
        }
        CRM_ASSERT(local_cib != NULL);
        need_full_refresh = true;
    }

    pcmk__refresh_node_caches_from_cib(local_cib);
    update_stonith_watchdog_timeout_ms(local_cib);

    if (timeout_ms_saved != stonith_watchdog_timeout_ms) {
        need_full_refresh = true;
    }

    if (need_full_refresh) {
        fencing_topology_init();
        cib_devices_update();
    } else {
        // Partial refresh
        update_fencing_topology(event, msg);
        update_cib_stonith_devices(event, msg);
    }

    watchdog_device_update();
}

static void
init_cib_cache_cb(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    crm_info("Updating device list from CIB");
    have_cib_devices = TRUE;
    local_cib = copy_xml(output);

    pcmk__refresh_node_caches_from_cib(local_cib);
    update_stonith_watchdog_timeout_ms(local_cib);

    fencing_topology_init();
    cib_devices_update();
    watchdog_device_update();
}

static void
stonith_shutdown(int nsig)
{
    crm_info("Terminating with %d clients", pcmk__ipc_client_count());
    stonith_shutdown_flag = TRUE;
    if (mainloop != NULL && g_main_loop_is_running(mainloop)) {
        g_main_loop_quit(mainloop);
    }
}

static void
cib_connection_destroy(gpointer user_data)
{
    if (stonith_shutdown_flag) {
        crm_info("Connection to the CIB manager closed");
        return;
    } else {
        crm_crit("Lost connection to the CIB manager, shutting down");
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
        cib_api->cmds->del_notify_callback(cib_api, T_CIB_DIFF_NOTIFY, update_cib_cache_cb);
        cib_api->cmds->signoff(cib_api);
    }

    if (ipcs) {
        qb_ipcs_destroy(ipcs);
    }

    crm_peer_destroy();
    pcmk__client_cleanup();
    free_stonith_remote_op_list();
    free_topology_list();
    free_device_list();
    free_metadata_cache();
    fenced_unregister_handlers();

    free(stonith_our_uname);
    stonith_our_uname = NULL;

    free_xml(local_cib);
    local_cib = NULL;
}

static gboolean
stand_alone_cpg_cb(const gchar *option_name, const gchar *optarg, gpointer data,
                   GError **error)
{
    stand_alone = FALSE;
    options.no_cib_connect = true;
    return TRUE;
}

static void
setup_cib(void)
{
    int rc, retries = 0;

    cib_api = cib_new();
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
        crm_info("Watching for fencing topology changes");
    }
}

struct qb_ipcs_service_handlers ipc_callbacks = {
    .connection_accept = st_ipc_accept,
    .connection_created = NULL,
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
    if ((type != crm_status_processes)
        && !pcmk_is_set(node->flags, crm_remote_node)) {
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
}

static pcmk__cluster_option_t fencer_options[] = {
    /* name, old name, type, allowed values,
     * default value, validator,
     * short description,
     * long description
     */
    {
        PCMK_STONITH_HOST_ARGUMENT, NULL, "string", NULL, "port", NULL,
        N_("Advanced use only: An alternate parameter to supply instead of 'port'"),
        N_("some devices do not support the "
           "standard 'port' parameter or may provide additional ones. Use "
           "this to specify an alternate, device-specific, parameter "
           "that should indicate the machine to be fenced. A value of "
           "none can be used to tell the cluster not to supply any "
           "additional parameters.")
    },
    {
        PCMK_STONITH_HOST_MAP,NULL, "string", NULL, "", NULL,
        N_("A mapping of host names to ports numbers for devices that do not support host names."),
        N_("Eg. node1:1;node2:2,3 would tell the cluster to use port 1 for node1 and ports 2 and 3 for node2")
    },
    {
        PCMK_STONITH_HOST_LIST,NULL, "string", NULL, "", NULL,
        N_("Eg. node1,node2,node3"),
        N_("A list of machines controlled by "
               "this device (Optional unless pcmk_host_list=static-list)")
    },
    {
        PCMK_STONITH_HOST_CHECK,NULL, "string", NULL, "dynamic-list", NULL,
        N_("How to determine which machines are controlled by the device."),
        N_("Allowed values: dynamic-list "
               "(query the device via the 'list' command), static-list "
               "(check the pcmk_host_list attribute), status "
               "(query the device via the 'status' command), "
               "none (assume every device can fence every "
               "machine)")
    },
    {
        PCMK_STONITH_DELAY_MAX,NULL, "time", NULL, "0s", NULL,
        N_("Enable a base delay for fencing actions and specify base delay value."),
        N_("Enable a delay of no more than the "
               "time specified before executing fencing actions. Pacemaker "
               "derives the overall delay by taking the value of "
               "pcmk_delay_base and adding a random delay value such "
               "that the sum is kept below this maximum.")
    },
    {
        PCMK_STONITH_DELAY_BASE,NULL, "string", NULL, "0s", NULL,
        N_("Enable a base delay for "
               "fencing actions and specify base delay value."),
        N_("This enables a static delay for "
               "fencing actions, which can help avoid \"death matches\" where "
               "two nodes try to fence each other at the same time. If "
               "pcmk_delay_max  is also used, a random delay will be "
               "added such that the total delay is kept below that value."
               "This can be set to a single time value to apply to any node "
               "targeted by this device (useful if a separate device is "
               "configured for each target), or to a node map (for example, "
               "\"node1:1s;node2:5\") to set a different value per target.")
    },
    {
        PCMK_STONITH_ACTION_LIMIT,NULL, "integer", NULL, "1", NULL,
        N_("The maximum number of actions can be performed in parallel on this device"),
        N_("Cluster property concurrent-fencing=true needs to be configured first."
             "Then use this to specify the maximum number of actions can be performed in parallel on this device. -1 is unlimited.")
    },
    {
	"pcmk_reboot_action",NULL, "string", NULL, "reboot", NULL,
	N_("Advanced use only: An alternate command to run instead of 'reboot'"),
        N_("Some devices do not support the standard commands or may provide additional ones.\n"
                 "Use this to specify an alternate, device-specific, command that implements the \'reboot\' action.")
    },
    {
	"pcmk_reboot_timeout",NULL, "time", NULL, "60s", NULL,
	N_("Advanced use only: Specify an alternate timeout to use for reboot actions instead of stonith-timeout"),
        N_("Some devices need much more/less time to complete than normal."
	   "Use this to specify an alternate, device-specific, timeout for \'reboot\' actions.")
    },
    {
	"pcmk_reboot_retries",NULL, "integer", NULL, "2", NULL,
	N_("Advanced use only: The maximum number of times to retry the 'reboot' command within the timeout period"),
        N_("Some devices do not support multiple connections."
           " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation,      if there is time remaining."
           " Use this option to alter the number of times Pacemaker retries \'reboot\' actions before giving up.")
    },
    {
	"pcmk_off_action",NULL, "string", NULL, "off", NULL,
	N_("Advanced use only: An alternate command to run instead of \'off\'"),
        N_("Some devices do not support the standard commands or may provide additional ones."
                 "Use this to specify an alternate, device-specific, command that implements the \'off\' action.")
    },
    {
	"pcmk_off_timeout",NULL, "time", NULL, "60s", NULL,
	N_("Advanced use only: Specify an alternate timeout to use for off actions instead of stonith-timeout"),
        N_("Some devices need much more/less time to complete than normal."
	   "Use this to specify an alternate, device-specific, timeout for \'off\' actions.")
    },
    {
	"pcmk_off_retries",NULL, "integer", NULL, "2", NULL,
	N_("Advanced use only: The maximum number of times to retry the 'off' command within the timeout period"),
        N_("Some devices do not support multiple connections."
           " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation,      if there is time remaining."
           " Use this option to alter the number of times Pacemaker retries \'off\' actions before giving up.")
    },
    {
	"pcmk_on_action",NULL, "string", NULL, "on", NULL,
	N_("Advanced use only: An alternate command to run instead of 'on'"),
        N_("Some devices do not support the standard commands or may provide additional ones."
                 "Use this to specify an alternate, device-specific, command that implements the \'on\' action.")
    },
    {
	"pcmk_on_timeout",NULL, "time", NULL, "60s", NULL,
	N_("Advanced use only: Specify an alternate timeout to use for on actions instead of stonith-timeout"),
        N_("Some devices need much more/less time to complete than normal."
	   "Use this to specify an alternate, device-specific, timeout for \'on\' actions.")
    },
    {
	"pcmk_on_retries",NULL, "integer", NULL, "2", NULL,
	N_("Advanced use only: The maximum number of times to retry the 'on' command within the timeout period"),
        N_("Some devices do not support multiple connections."
           " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation,      if there is time remaining."
           " Use this option to alter the number of times Pacemaker retries \'on\' actions before giving up.")
    },
    {
	"pcmk_list_action",NULL, "string", NULL, "list", NULL,
	N_("Advanced use only: An alternate command to run instead of \'list\'"),
        N_("Some devices do not support the standard commands or may provide additional ones."
                 "Use this to specify an alternate, device-specific, command that implements the \'list\' action.")
    },
    {
	"pcmk_list_timeout",NULL, "time", NULL, "60s", NULL,
	N_("Advanced use only: Specify an alternate timeout to use for list actions instead of stonith-timeout"),
        N_("Some devices need much more/less time to complete than normal."
	   "Use this to specify an alternate, device-specific, timeout for \'list\' actions.")
    },
    {
	"pcmk_list_retries",NULL, "integer", NULL, "2", NULL,
	N_("Advanced use only: The maximum number of times to retry the \'list\' command within the timeout period"),
        N_("Some devices do not support multiple connections."
           " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation,      if there is time remaining."
           " Use this option to alter the number of times Pacemaker retries \'list\' actions before giving up.")
    },
    {
	"pcmk_monitor_action",NULL, "string", NULL, "monitor", NULL,
	N_("Advanced use only: An alternate command to run instead of \'monitor\'"),
        N_("Some devices do not support the standard commands or may provide additional ones."
                 "Use this to specify an alternate, device-specific, command that implements the \'monitor\' action.")
    },
    {
	"pcmk_monitor_timeout",NULL, "time", NULL, "60s", NULL,
	N_("Advanced use only: Specify an alternate timeout to use for monitor actions instead of stonith-timeout"),
        N_("Some devices need much more/less time to complete than normal.\n"
	   "Use this to specify an alternate, device-specific, timeout for \'monitor\' actions.")
    },
    {
	"pcmk_monitor_retries",NULL, "integer", NULL, "2", NULL,
	N_("Advanced use only: The maximum number of times to retry the \'monitor\' command within the timeout period"),
        N_("Some devices do not support multiple connections."
           " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation,      if there is time remaining."
           " Use this option to alter the number of times Pacemaker retries \'monitor\' actions before giving up.")
    },
    {
	"pcmk_status_action",NULL, "string", NULL, "status", NULL,
	N_("Advanced use only: An alternate command to run instead of \'status\'"),
        N_("Some devices do not support the standard commands or may provide additional ones."
                 "Use this to specify an alternate, device-specific, command that implements the \'status\' action.")
    },
    {
	"pcmk_status_timeout",NULL, "time", NULL, "60s", NULL,
	N_("Advanced use only: Specify an alternate timeout to use for status actions instead of stonith-timeout"),
        N_("Some devices need much more/less time to complete than normal."
	   "Use this to specify an alternate, device-specific, timeout for \'status\' actions.")
    },
    {
	"pcmk_status_retries",NULL, "integer", NULL, "2", NULL,
	N_("Advanced use only: The maximum number of times to retry the \'status\' command within the timeout period"),
        N_("Some devices do not support multiple connections."
           " Operations may 'fail' if the device is busy with another task so Pacemaker will automatically retry the operation,      if there is time remaining."
           " Use this option to alter the number of times Pacemaker retries \'status\' actions before giving up.")
    },
};

void
fencer_metadata(void)
{
    const char *desc_short = N_("Instance attributes available for all "
                             "\"stonith\"-class resources");
    const char *desc_long = N_("Instance attributes available for all \"stonith\"-"
                            "class resources and used by Pacemaker's fence "
                            "daemon, formerly known as stonithd");

    gchar *s = pcmk__format_option_metadata("pacemaker-fenced", desc_short,
                                            desc_long, fencer_options,
                                            PCMK__NELEM(fencer_options));
    printf("%s", s);
    g_free(s);
}

static GOptionEntry entries[] = {
    { "stand-alone", 's', G_OPTION_FLAG_NONE, G_OPTION_ARG_NONE, &stand_alone,
      "Deprecated (will be removed in a future release)", NULL },

    { "stand-alone-w-cpg", 'c', G_OPTION_FLAG_NO_ARG, G_OPTION_ARG_CALLBACK,
      stand_alone_cpg_cb, "Intended for use in regression testing only", NULL },

    { "logfile", 'l', G_OPTION_FLAG_NONE, G_OPTION_ARG_FILENAME_ARRAY,
      &options.log_files, "Send logs to the additional named logfile", NULL },

    { NULL }
};

static GOptionContext *
build_arg_context(pcmk__common_args_t *args, GOptionGroup **group)
{
    GOptionContext *context = NULL;

    context = pcmk__build_arg_context(args, "text (default), xml", group,
                                      "[metadata]");
    pcmk__add_main_args(context, entries);
    return context;
}

int
main(int argc, char **argv)
{
    int rc = pcmk_rc_ok;
    crm_cluster_t *cluster = NULL;
    crm_ipc_t *old_instance = NULL;

    GError *error = NULL;

    GOptionGroup *output_group = NULL;
    pcmk__common_args_t *args = pcmk__new_common_args(SUMMARY);
    gchar **processed_args = pcmk__cmdline_preproc(argv, "l");
    GOptionContext *context = build_arg_context(args, &output_group);

    crm_log_preinit(NULL, argc, argv);

    pcmk__register_formats(output_group, formats);
    if (!g_option_context_parse_strv(context, &processed_args, &error)) {
        exit_code = CRM_EX_USAGE;
        goto done;
    }

    rc = pcmk__output_new(&out, args->output_ty, args->output_dest, argv);
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_ERROR;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format %s: %s",
                    args->output_ty, pcmk_rc_str(rc));
        goto done;
    }

    if (args->version) {
        out->version(out, false);
        goto done;
    }

    if ((g_strv_length(processed_args) >= 2)
        && pcmk__str_eq(processed_args[1], "metadata", pcmk__str_none)) {
        fencer_metadata();
        goto done;
    }

    // Open additional log files
    pcmk__add_logfiles(options.log_files, out);

    crm_log_init(NULL, LOG_INFO + args->verbosity, TRUE,
                 (args->verbosity > 0), argc, argv, FALSE);

    crm_notice("Starting Pacemaker fencer");

    old_instance = crm_ipc_new("stonith-ng", 0);
    if (old_instance == NULL) {
        /* crm_ipc_new() will have already logged an error message with
         * crm_err()
         */
        exit_code = CRM_EX_FATAL;
        goto done;
    }

    if (crm_ipc_connect(old_instance)) {
        // IPC endpoint already up
        crm_ipc_close(old_instance);
        crm_ipc_destroy(old_instance);
        crm_err("pacemaker-fenced is already active, aborting startup");
        goto done;
    } else {
        // Not up or not authentic, we'll proceed either way
        crm_ipc_destroy(old_instance);
        old_instance = NULL;
    }

    mainloop_add_signal(SIGTERM, stonith_shutdown);

    crm_peer_init();

    fenced_data_set = pe_new_working_set();
    CRM_ASSERT(fenced_data_set != NULL);

    cluster = pcmk_cluster_new();

    /* Initialize the logger prior to setup_cib(). update_cib_cache_cb() may
     * call the "xml-patchset" message function, which needs the logger, after
     * setup_cib() has run.
     */
    rc = pcmk__log_output_new(&logger_out) != pcmk_rc_ok;
    if (rc != pcmk_rc_ok) {
        exit_code = CRM_EX_FATAL;
        g_set_error(&error, PCMK__EXITC_ERROR, exit_code,
                    "Error creating output format log: %s", pcmk_rc_str(rc));
        goto done;
    }
    pe__register_messages(logger_out);
    pcmk__register_lib_messages(logger_out);
    pcmk__output_set_log_level(logger_out, LOG_TRACE);
    fenced_data_set->priv = logger_out;

    if (!stand_alone) {
#if SUPPORT_COROSYNC
        if (is_corosync_cluster()) {
            cluster->destroy = stonith_peer_cs_destroy;
            cluster->cpg.cpg_deliver_fn = stonith_peer_ais_callback;
            cluster->cpg.cpg_confchg_fn = pcmk_cpg_membership;
        }
#endif // SUPPORT_COROSYNC

        crm_set_status_callback(&st_peer_update_callback);

        if (crm_cluster_connect(cluster) == FALSE) {
            exit_code = CRM_EX_FATAL;
            crm_crit("Cannot sign in to the cluster... terminating");
            goto done;
        }
        pcmk__str_update(&stonith_our_uname, cluster->uname);

        if (!options.no_cib_connect) {
            setup_cib();
        }

    } else {
        pcmk__str_update(&stonith_our_uname, "localhost");
        crm_warn("Stand-alone mode is deprecated and will be removed "
                 "in a future release");
    }

    init_device_list();
    init_topology_list();

    pcmk__serve_fenced_ipc(&ipcs, &ipc_callbacks);

    // Create the mainloop and run it...
    mainloop = g_main_loop_new(NULL, FALSE);
    crm_notice("Pacemaker fencer successfully started and accepting connections");
    g_main_loop_run(mainloop);

done:
    g_strfreev(processed_args);
    pcmk__free_arg_context(context);

    g_strfreev(options.log_files);

    stonith_cleanup();
    pcmk_cluster_free(cluster);
    pe_free_working_set(fenced_data_set);

    pcmk__output_and_clear_error(&error, out);

    if (logger_out != NULL) {
        logger_out->finish(logger_out, exit_code, true, NULL);
        pcmk__output_free(logger_out);
    }

    if (out != NULL) {
        out->finish(out, exit_code, true, NULL);
        pcmk__output_free(out);
    }

    pcmk__unregister_formats();
    crm_exit(exit_code);
}

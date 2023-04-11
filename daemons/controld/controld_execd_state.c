/*
 * Copyright 2012-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/rules_internal.h>
#include <crm/lrmd_internal.h>

#include <pacemaker-internal.h>
#include <pacemaker-controld.h>

static GHashTable *lrm_state_table = NULL;
extern GHashTable *proxy_table;
int lrmd_internal_proxy_send(lrmd_t * lrmd, xmlNode *msg);
void lrmd_internal_set_proxy_callback(lrmd_t * lrmd, void *userdata, void (*callback)(lrmd_t *lrmd, void *userdata, xmlNode *msg));

static void
free_rsc_info(gpointer value)
{
    lrmd_rsc_info_t *rsc_info = value;

    lrmd_free_rsc_info(rsc_info);
}

static void
free_deletion_op(gpointer value)
{
    struct pending_deletion_op_s *op = value;

    free(op->rsc);
    delete_ha_msg_input(op->input);
    free(op);
}

static void
free_recurring_op(gpointer value)
{
    active_op_t *op = value;

    free(op->user_data);
    free(op->rsc_id);
    free(op->op_type);
    free(op->op_key);
    if (op->params) {
        g_hash_table_destroy(op->params);
    }
    free(op);
}

static gboolean
fail_pending_op(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_event_data_t event = { 0, };
    lrm_state_t *lrm_state = user_data;
    active_op_t *op = value;

    crm_trace("Pre-emptively failing " PCMK__OP_FMT " on %s (call=%s, %s)",
              op->rsc_id, op->op_type, op->interval_ms,
              lrm_state->node_name, (char*)key, op->user_data);

    event.type = lrmd_event_exec_complete;
    event.rsc_id = op->rsc_id;
    event.op_type = op->op_type;
    event.user_data = op->user_data;
    event.timeout = 0;
    event.interval_ms = op->interval_ms;
    lrmd__set_result(&event, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_NOT_CONNECTED,
                     "Action was pending when executor connection was dropped");
    event.t_run = (unsigned int) op->start_time;
    event.t_rcchange = (unsigned int) op->start_time;

    event.call_id = op->call_id;
    event.remote_nodename = lrm_state->node_name;
    event.params = op->params;

    process_lrm_event(lrm_state, &event, op, NULL);
    lrmd__reset_result(&event);
    return TRUE;
}

gboolean
lrm_state_is_local(lrm_state_t *lrm_state)
{
    return (lrm_state != NULL)
           && pcmk__str_eq(lrm_state->node_name, controld_globals.our_nodename,
                           pcmk__str_casei);
}

/*!
 * \internal
 * \brief Create executor state entry for a node and add it to the state table
 *
 * \param[in]  node_name  Node to create entry for
 *
 * \return Newly allocated executor state object initialized for \p node_name
 */
static lrm_state_t *
lrm_state_create(const char *node_name)
{
    lrm_state_t *state = NULL;

    if (!node_name) {
        crm_err("No node name given for lrm state object");
        return NULL;
    }

    state = calloc(1, sizeof(lrm_state_t));
    if (!state) {
        return NULL;
    }

    state->node_name = strdup(node_name);
    state->rsc_info_cache = pcmk__strkey_table(NULL, free_rsc_info);
    state->deletion_ops = pcmk__strkey_table(free, free_deletion_op);
    state->active_ops = pcmk__strkey_table(free, free_recurring_op);
    state->resource_history = pcmk__strkey_table(NULL, history_free);
    state->metadata_cache = metadata_cache_new();

    g_hash_table_insert(lrm_state_table, (char *)state->node_name, state);
    return state;
}

void
lrm_state_destroy(const char *node_name)
{
    g_hash_table_remove(lrm_state_table, node_name);
}

static gboolean
remote_proxy_remove_by_node(gpointer key, gpointer value, gpointer user_data)
{
    remote_proxy_t *proxy = value;
    const char *node_name = user_data;

    if (pcmk__str_eq(node_name, proxy->node_name, pcmk__str_casei)) {
        return TRUE;
    }

    return FALSE;
}

static remote_proxy_t *
find_connected_proxy_by_node(const char * node_name)
{
    GHashTableIter gIter;
    remote_proxy_t *proxy = NULL;

    CRM_CHECK(proxy_table != NULL, return NULL);

    g_hash_table_iter_init(&gIter, proxy_table);

    while (g_hash_table_iter_next(&gIter, NULL, (gpointer *) &proxy)) {
        if (proxy->source
            && pcmk__str_eq(node_name, proxy->node_name, pcmk__str_casei)) {
            return proxy;
        }
    }

    return NULL;
}

static void
remote_proxy_disconnect_by_node(const char * node_name)
{
    remote_proxy_t *proxy = NULL;

    CRM_CHECK(proxy_table != NULL, return);

    while ((proxy = find_connected_proxy_by_node(node_name)) != NULL) {
        /* mainloop_del_ipc_client() eventually calls remote_proxy_disconnected()
         * , which removes the entry from proxy_table.
         * Do not do this in a g_hash_table_iter_next() loop. */
        if (proxy->source) {
            mainloop_del_ipc_client(proxy->source);
        }
    }

    return;
}

static void
internal_lrm_state_destroy(gpointer data)
{
    lrm_state_t *lrm_state = data;

    if (!lrm_state) {
        return;
    }

    /* Rather than directly remove the recorded proxy entries from proxy_table,
     * make sure any connected proxies get disconnected. So that
     * remote_proxy_disconnected() will be called and as well remove the
     * entries from proxy_table.
     */
    remote_proxy_disconnect_by_node(lrm_state->node_name);

    crm_trace("Destroying proxy table %s with %u members",
              lrm_state->node_name, g_hash_table_size(proxy_table));
    // Just in case there's still any leftovers in proxy_table
    g_hash_table_foreach_remove(proxy_table, remote_proxy_remove_by_node, (char *) lrm_state->node_name);
    remote_ra_cleanup(lrm_state);
    lrmd_api_delete(lrm_state->conn);

    if (lrm_state->rsc_info_cache) {
        crm_trace("Destroying rsc info cache with %u members",
                  g_hash_table_size(lrm_state->rsc_info_cache));
        g_hash_table_destroy(lrm_state->rsc_info_cache);
    }
    if (lrm_state->resource_history) {
        crm_trace("Destroying history op cache with %u members",
                  g_hash_table_size(lrm_state->resource_history));
        g_hash_table_destroy(lrm_state->resource_history);
    }
    if (lrm_state->deletion_ops) {
        crm_trace("Destroying deletion op cache with %u members",
                  g_hash_table_size(lrm_state->deletion_ops));
        g_hash_table_destroy(lrm_state->deletion_ops);
    }
    if (lrm_state->active_ops != NULL) {
        crm_trace("Destroying pending op cache with %u members",
                  g_hash_table_size(lrm_state->active_ops));
        g_hash_table_destroy(lrm_state->active_ops);
    }
    metadata_cache_free(lrm_state->metadata_cache);

    free((char *)lrm_state->node_name);
    free(lrm_state);
}

void
lrm_state_reset_tables(lrm_state_t * lrm_state, gboolean reset_metadata)
{
    if (lrm_state->resource_history) {
        crm_trace("Resetting resource history cache with %u members",
                  g_hash_table_size(lrm_state->resource_history));
        g_hash_table_remove_all(lrm_state->resource_history);
    }
    if (lrm_state->deletion_ops) {
        crm_trace("Resetting deletion operations cache with %u members",
                  g_hash_table_size(lrm_state->deletion_ops));
        g_hash_table_remove_all(lrm_state->deletion_ops);
    }
    if (lrm_state->active_ops != NULL) {
        crm_trace("Resetting active operations cache with %u members",
                  g_hash_table_size(lrm_state->active_ops));
        g_hash_table_remove_all(lrm_state->active_ops);
    }
    if (lrm_state->rsc_info_cache) {
        crm_trace("Resetting resource information cache with %u members",
                  g_hash_table_size(lrm_state->rsc_info_cache));
        g_hash_table_remove_all(lrm_state->rsc_info_cache);
    }
    if (reset_metadata) {
        metadata_cache_reset(lrm_state->metadata_cache);
    }
}

gboolean
lrm_state_init_local(void)
{
    if (lrm_state_table) {
        return TRUE;
    }

    lrm_state_table = pcmk__strikey_table(NULL, internal_lrm_state_destroy);
    if (!lrm_state_table) {
        return FALSE;
    }

    proxy_table = pcmk__strikey_table(NULL, remote_proxy_free);
    if (!proxy_table) {
        g_hash_table_destroy(lrm_state_table);
        lrm_state_table = NULL;
        return FALSE;
    }

    return TRUE;
}

void
lrm_state_destroy_all(void)
{
    if (lrm_state_table) {
        crm_trace("Destroying state table with %u members",
                  g_hash_table_size(lrm_state_table));
        g_hash_table_destroy(lrm_state_table); lrm_state_table = NULL;
    }
    if(proxy_table) {
        crm_trace("Destroying proxy table with %u members",
                  g_hash_table_size(proxy_table));
        g_hash_table_destroy(proxy_table); proxy_table = NULL;
    }
}

lrm_state_t *
lrm_state_find(const char *node_name)
{
    if (!node_name) {
        return NULL;
    }
    return g_hash_table_lookup(lrm_state_table, node_name);
}

lrm_state_t *
lrm_state_find_or_create(const char *node_name)
{
    lrm_state_t *lrm_state;

    lrm_state = g_hash_table_lookup(lrm_state_table, node_name);
    if (!lrm_state) {
        lrm_state = lrm_state_create(node_name);
    }

    return lrm_state;
}

GList *
lrm_state_get_list(void)
{
    return g_hash_table_get_values(lrm_state_table);
}

void
lrm_state_disconnect_only(lrm_state_t * lrm_state)
{
    int removed = 0;

    if (!lrm_state->conn) {
        return;
    }
    crm_trace("Disconnecting %s", lrm_state->node_name);

    remote_proxy_disconnect_by_node(lrm_state->node_name);

    ((lrmd_t *) lrm_state->conn)->cmds->disconnect(lrm_state->conn);

    if (!pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                              fail_pending_op, lrm_state);
        crm_trace("Synthesized %d operation failures for %s", removed, lrm_state->node_name);
    }
}

void
lrm_state_disconnect(lrm_state_t * lrm_state)
{
    if (!lrm_state->conn) {
        return;
    }

    lrm_state_disconnect_only(lrm_state);

    lrmd_api_delete(lrm_state->conn);
    lrm_state->conn = NULL;
}

int
lrm_state_is_connected(lrm_state_t * lrm_state)
{
    if (!lrm_state->conn) {
        return FALSE;
    }
    return ((lrmd_t *) lrm_state->conn)->cmds->is_connected(lrm_state->conn);
}

int
lrm_state_poke_connection(lrm_state_t * lrm_state)
{

    if (!lrm_state->conn) {
        return -ENOTCONN;
    }
    return ((lrmd_t *) lrm_state->conn)->cmds->poke_connection(lrm_state->conn);
}

// \return Standard Pacemaker return code
int
controld_connect_local_executor(lrm_state_t *lrm_state)
{
    int rc = pcmk_rc_ok;

    if (lrm_state->conn == NULL) {
        lrmd_t *api = NULL;

        rc = lrmd__new(&api, NULL, NULL, 0);
        if (rc != pcmk_rc_ok) {
            return rc;
        }
        api->cmds->set_callback(api, lrm_op_callback);
        lrm_state->conn = api;
    }

    rc = ((lrmd_t *) lrm_state->conn)->cmds->connect(lrm_state->conn,
                                                     CRM_SYSTEM_CRMD, NULL);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        lrm_state->num_lrm_register_fails = 0;
    } else {
        lrm_state->num_lrm_register_fails++;
    }
    return rc;
}

static remote_proxy_t *
crmd_remote_proxy_new(lrmd_t *lrmd, const char *node_name, const char *session_id, const char *channel)
{
    struct ipc_client_callbacks proxy_callbacks = {
        .dispatch = remote_proxy_dispatch,
        .destroy = remote_proxy_disconnected
    };
    remote_proxy_t *proxy = remote_proxy_new(lrmd, &proxy_callbacks, node_name,
                                             session_id, channel);
    return proxy;
}

gboolean
crmd_is_proxy_session(const char *session)
{
    return g_hash_table_lookup(proxy_table, session) ? TRUE : FALSE;
}

void
crmd_proxy_send(const char *session, xmlNode *msg)
{
    remote_proxy_t *proxy = g_hash_table_lookup(proxy_table, session);
    lrm_state_t *lrm_state = NULL;

    if (!proxy) {
        return;
    }
    crm_log_xml_trace(msg, "to-proxy");
    lrm_state = lrm_state_find(proxy->node_name);
    if (lrm_state) {
        crm_trace("Sending event to %.8s on %s", proxy->session_id, proxy->node_name);
        remote_proxy_relay_event(proxy, msg);
    }
}

static void
crmd_proxy_dispatch(const char *session, xmlNode *msg)
{
    crm_trace("Processing proxied IPC message from session %s", session);
    crm_log_xml_trace(msg, "controller[inbound]");
    crm_xml_add(msg, F_CRM_SYS_FROM, session);
    if (controld_authorize_ipc_message(msg, NULL, session)) {
        route_message(C_IPC_MESSAGE, msg);
    }
    controld_trigger_fsa();
}

static void
remote_config_check(xmlNode * msg, int call_id, int rc, xmlNode * output, void *user_data)
{
    if (rc != pcmk_ok) {
        crm_err("Query resulted in an error: %s", pcmk_strerror(rc));

        if (rc == -EACCES || rc == -pcmk_err_schema_validation) {
            crm_err("The cluster is mis-configured - shutting down and staying down");
        }

    } else {
        lrmd_t * lrmd = (lrmd_t *)user_data;
        crm_time_t *now = crm_time_new(NULL);
        GHashTable *config_hash = pcmk__strkey_table(free, free);

        crm_debug("Call %d : Parsing CIB options", call_id);

        pe_unpack_nvpairs(output, output, XML_CIB_TAG_PROPSET, NULL,
                          config_hash, CIB_OPTIONS_FIRST, FALSE, now, NULL);

        /* Now send it to the remote peer */
        lrmd__validate_remote_settings(lrmd, config_hash);

        g_hash_table_destroy(config_hash);
        crm_time_free(now);
    }
}

static void
crmd_remote_proxy_cb(lrmd_t *lrmd, void *userdata, xmlNode *msg)
{
    lrm_state_t *lrm_state = userdata;
    const char *session = crm_element_value(msg, F_LRMD_IPC_SESSION);
    remote_proxy_t *proxy = g_hash_table_lookup(proxy_table, session);

    const char *op = crm_element_value(msg, F_LRMD_IPC_OP);
    if (pcmk__str_eq(op, LRMD_IPC_OP_NEW, pcmk__str_casei)) {
        const char *channel = crm_element_value(msg, F_LRMD_IPC_IPC_SERVER);

        proxy = crmd_remote_proxy_new(lrmd, lrm_state->node_name, session, channel);
        if (!remote_ra_controlling_guest(lrm_state)) {
            if (proxy != NULL) {
                cib_t *cib_conn = controld_globals.cib_conn;

                /* Look up stonith-watchdog-timeout and send to the remote peer for validation */
                int rc = cib_conn->cmds->query(cib_conn, XML_CIB_TAG_CRMCONFIG,
                                               NULL, cib_scope_local);
                cib_conn->cmds->register_callback_full(cib_conn, rc, 10, FALSE,
                                                       lrmd,
                                                       "remote_config_check",
                                                       remote_config_check,
                                                       NULL);
            }
        } else {
            crm_debug("Skipping remote_config_check for guest-nodes");
        }

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_SHUTDOWN_REQ, pcmk__str_casei)) {
        char *now_s = NULL;

        crm_notice("%s requested shutdown of its remote connection",
                   lrm_state->node_name);

        if (!remote_ra_is_in_maintenance(lrm_state)) {
            now_s = pcmk__ttoa(time(NULL));
            update_attrd(lrm_state->node_name, XML_CIB_ATTR_SHUTDOWN, now_s, NULL, TRUE);
            free(now_s);

            remote_proxy_ack_shutdown(lrmd);

            crm_warn("Reconnection attempts to %s may result in failures that must be cleared",
                    lrm_state->node_name);
        } else {
            remote_proxy_nack_shutdown(lrmd);

            crm_notice("Remote resource for %s is not managed so no ordered shutdown happening",
                    lrm_state->node_name);
        }
        return;

    } else if (pcmk__str_eq(op, LRMD_IPC_OP_REQUEST, pcmk__str_casei) && proxy && proxy->is_local) {
        /* This is for the controller, which we are, so don't try
         * to send to ourselves over IPC -- do it directly.
         */
        int flags = 0;
        xmlNode *request = get_message_xml(msg, F_LRMD_IPC_MSG);

        CRM_CHECK(request != NULL, return);
        CRM_CHECK(lrm_state->node_name, return);
        crm_xml_add(request, XML_ACL_TAG_ROLE, "pacemaker-remote");
        pcmk__update_acl_user(request, F_LRMD_IPC_USER, lrm_state->node_name);

        /* Pacemaker Remote nodes don't know their own names (as known to the
         * cluster). When getting a node info request with no name or ID, add
         * the name, so we don't return info for ourselves instead of the
         * Pacemaker Remote node.
         */
        if (pcmk__str_eq(crm_element_value(request, F_CRM_TASK), CRM_OP_NODE_INFO, pcmk__str_casei)) {
            int node_id = 0;

            crm_element_value_int(request, XML_ATTR_ID, &node_id);
            if ((node_id <= 0)
                && (crm_element_value(request, XML_ATTR_UNAME) == NULL)) {
                crm_xml_add(request, XML_ATTR_UNAME, lrm_state->node_name);
            }
        }

        crmd_proxy_dispatch(session, request);

        crm_element_value_int(msg, F_LRMD_IPC_MSG_FLAGS, &flags);
        if (flags & crm_ipc_client_response) {
            int msg_id = 0;
            xmlNode *op_reply = create_xml_node(NULL, "ack");

            crm_xml_add(op_reply, "function", __func__);
            crm_xml_add_int(op_reply, "line", __LINE__);

            crm_element_value_int(msg, F_LRMD_IPC_MSG_ID, &msg_id);
            remote_proxy_relay_response(proxy, op_reply, msg_id);

            free_xml(op_reply);
        }

    } else {
        remote_proxy_cb(lrmd, lrm_state->node_name, msg);
    }
}


// \return Standard Pacemaker return code
int
controld_connect_remote_executor(lrm_state_t *lrm_state, const char *server,
                                 int port, int timeout_ms)
{
    int rc = pcmk_rc_ok;

    if (lrm_state->conn == NULL) {
        lrmd_t *api = NULL;

        rc = lrmd__new(&api, lrm_state->node_name, server, port);
        if (rc != pcmk_rc_ok) {
            crm_warn("Pacemaker Remote connection to %s:%s failed: %s "
                     CRM_XS " rc=%d", server, port, pcmk_rc_str(rc), rc);

            return rc;
        }
        lrm_state->conn = api;
        api->cmds->set_callback(api, remote_lrm_op_callback);
        lrmd_internal_set_proxy_callback(api, lrm_state, crmd_remote_proxy_cb);
    }

    crm_trace("Initiating remote connection to %s:%d with timeout %dms",
              server, port, timeout_ms);
    rc = ((lrmd_t *) lrm_state->conn)->cmds->connect_async(lrm_state->conn,
                                                           lrm_state->node_name,
                                                           timeout_ms);
    if (rc == pcmk_ok) {
        lrm_state->num_lrm_register_fails = 0;
    } else {
        lrm_state->num_lrm_register_fails++; // Ignored for remote connections
    }
    return pcmk_legacy2rc(rc);
}

int
lrm_state_get_metadata(lrm_state_t * lrm_state,
                       const char *class,
                       const char *provider,
                       const char *agent, char **output, enum lrmd_call_options options)
{
    lrmd_key_value_t *params = NULL;

    if (!lrm_state->conn) {
        return -ENOTCONN;
    }

    /* Add the node name to the environment, as is done with normal resource
     * action calls. Meta-data calls shouldn't need it, but some agents are
     * written with an ocf_local_nodename call at the beginning regardless of
     * action. Without the environment variable, the agent would try to contact
     * the controller to get the node name -- but the controller would be
     * blocking on the synchronous meta-data call.
     *
     * At this point, we have to assume that agents are unlikely to make other
     * calls that require the controller, such as crm_node --quorum or
     * --cluster-id.
     *
     * @TODO Make meta-data calls asynchronous. (This will be part of a larger
     * project to make meta-data calls via the executor rather than directly.)
     */
    params = lrmd_key_value_add(params, CRM_META "_" XML_LRM_ATTR_TARGET,
                                lrm_state->node_name);

    return ((lrmd_t *) lrm_state->conn)->cmds->get_metadata_params(lrm_state->conn,
            class, provider, agent, output, options, params);
}

int
lrm_state_cancel(lrm_state_t *lrm_state, const char *rsc_id, const char *action,
                 guint interval_ms)
{
    if (!lrm_state->conn) {
        return -ENOTCONN;
    }

    /* Figure out a way to make this async?
     * NOTICE: Currently it's synced and directly acknowledged in do_lrm_invoke(). */
    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        return remote_ra_cancel(lrm_state, rsc_id, action, interval_ms);
    }
    return ((lrmd_t *) lrm_state->conn)->cmds->cancel(lrm_state->conn, rsc_id,
                                                      action, interval_ms);
}

lrmd_rsc_info_t *
lrm_state_get_rsc_info(lrm_state_t * lrm_state, const char *rsc_id, enum lrmd_call_options options)
{
    lrmd_rsc_info_t *rsc = NULL;

    if (!lrm_state->conn) {
        return NULL;
    }
    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        return remote_ra_get_rsc_info(lrm_state, rsc_id);
    }

    rsc = g_hash_table_lookup(lrm_state->rsc_info_cache, rsc_id);
    if (rsc == NULL) {
        /* only contact the lrmd if we don't already have a cached rsc info */
        rsc = ((lrmd_t *) lrm_state->conn)->cmds->get_rsc_info(lrm_state->conn, rsc_id, options);
        if (rsc == NULL) {
		    return NULL;
        }
        /* cache the result */
        g_hash_table_insert(lrm_state->rsc_info_cache, rsc->id, rsc);
    }

    return lrmd_copy_rsc_info(rsc);

}

/*!
 * \internal
 * \brief Initiate a resource agent action
 *
 * \param[in,out] lrm_state       Executor state object
 * \param[in]     rsc_id          ID of resource for action
 * \param[in]     action          Action to execute
 * \param[in]     userdata        String to copy and pass to execution callback
 * \param[in]     interval_ms     Action interval (in milliseconds)
 * \param[in]     timeout_ms      Action timeout (in milliseconds)
 * \param[in]     start_delay_ms  Delay (in ms) before initiating action
 * \param[in]     parameters      Hash table of resource parameters
 * \param[out]    call_id         Where to store call ID on success
 *
 * \return Standard Pacemaker return code
 */
int
controld_execute_resource_agent(lrm_state_t *lrm_state, const char *rsc_id,
                                const char *action, const char *userdata,
                                guint interval_ms, int timeout_ms,
                                int start_delay_ms, GHashTable *parameters,
                                int *call_id)
{
    int rc = pcmk_rc_ok;
    lrmd_key_value_t *params = NULL;

    if (lrm_state->conn == NULL) {
        return ENOTCONN;
    }

    // Convert parameters from hash table to list
    if (parameters != NULL) {
        const char *key = NULL;
        const char *value = NULL;
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, parameters);
        while (g_hash_table_iter_next(&iter, (gpointer *) &key,
                                      (gpointer *) &value)) {
            params = lrmd_key_value_add(params, key, value);
        }
    }

    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        rc = controld_execute_remote_agent(lrm_state, rsc_id, action,
                                           userdata, interval_ms, timeout_ms,
                                           start_delay_ms, params, call_id);

    } else {
        rc = ((lrmd_t *) lrm_state->conn)->cmds->exec(lrm_state->conn, rsc_id,
                                                      action, userdata,
                                                      interval_ms, timeout_ms,
                                                      start_delay_ms,
                                                      lrmd_opt_notify_changes_only,
                                                      params);
        if (rc < 0) {
            rc = pcmk_legacy2rc(rc);
        } else {
            *call_id = rc;
            rc = pcmk_rc_ok;
        }
    }
    return rc;
}

int
lrm_state_register_rsc(lrm_state_t * lrm_state,
                       const char *rsc_id,
                       const char *class,
                       const char *provider, const char *agent, enum lrmd_call_options options)
{
    lrmd_t *conn = (lrmd_t *) lrm_state->conn;

    if (conn == NULL) {
        return -ENOTCONN;
    }

    if (is_remote_lrmd_ra(agent, provider, NULL)) {
        return lrm_state_find_or_create(rsc_id)? pcmk_ok : -EINVAL;
    }

    /* @TODO Implement an asynchronous version of this (currently a blocking
     * call to the lrmd).
     */
    return conn->cmds->register_rsc(lrm_state->conn, rsc_id, class, provider,
                                    agent, options);
}

int
lrm_state_unregister_rsc(lrm_state_t * lrm_state,
                         const char *rsc_id, enum lrmd_call_options options)
{
    if (!lrm_state->conn) {
        return -ENOTCONN;
    }

    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        lrm_state_destroy(rsc_id);
        return pcmk_ok;
    }

    g_hash_table_remove(lrm_state->rsc_info_cache, rsc_id);

    /* @TODO Optimize this ... this function is a blocking round trip from
     * client to daemon. The controld_execd_state.c code path that uses this
     * function should always treat it as an async operation. The executor API
     * should make an async version available.
     */
    return ((lrmd_t *) lrm_state->conn)->cmds->unregister_rsc(lrm_state->conn, rsc_id, options);
}

/*
 * Copyright 2012-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <errno.h>
#include <stdbool.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
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
    g_clear_pointer(&op->params, g_hash_table_destroy);
    free(op);
}

static gboolean
fail_pending_op(gpointer key, gpointer value, gpointer user_data)
{
    lrmd_event_data_t event = { 0, };
    lrm_state_t *lrm_state = user_data;
    active_op_t *op = value;

    pcmk__trace("Pre-emptively failing " PCMK__OP_FMT " on %s (call=%s, %s)",
                op->rsc_id, op->op_type, op->interval_ms,
                lrm_state->node_name, (const char *) key, op->user_data);

    event.type = lrmd_event_exec_complete;
    event.rsc_id = op->rsc_id;
    event.op_type = op->op_type;
    event.user_data = op->user_data;
    event.timeout = 0;
    event.interval_ms = op->interval_ms;
    lrmd__set_result(&event, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_NOT_CONNECTED,
                     "Action was pending when executor connection was dropped");
    event.t_run = op->start_time;
    event.t_rcchange = op->start_time;

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
    return (lrm_state != NULL) && controld_is_local_node(lrm_state->node_name);
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
        pcmk__err("No node name given for lrm state object");
        return NULL;
    }

    state = pcmk__assert_alloc(1, sizeof(lrm_state_t));

    state->node_name = pcmk__str_copy(node_name);
    state->rsc_info_cache = pcmk__strkey_table(NULL, free_rsc_info);
    state->deletion_ops = pcmk__strkey_table(free, free_deletion_op);
    state->active_ops = pcmk__strkey_table(free, free_recurring_op);
    state->resource_history = pcmk__strkey_table(NULL, history_free);
    state->metadata_cache = metadata_cache_new();

    g_hash_table_insert(lrm_state_table, (char *)state->node_name, state);
    return state;
}

static gboolean
remote_proxy_remove_by_node(gpointer key, gpointer value, gpointer user_data)
{
    controld_remote_proxy_t *proxy = value;
    const char *node_name = user_data;

    if (pcmk__str_eq(node_name, proxy->node_name, pcmk__str_casei)) {
        return TRUE;
    }

    return FALSE;
}

static controld_remote_proxy_t *
find_connected_proxy_by_node(const char * node_name)
{
    GHashTableIter gIter;
    controld_remote_proxy_t *proxy = NULL;

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
    controld_remote_proxy_t *proxy = NULL;

    CRM_CHECK(proxy_table != NULL, return);

    while ((proxy = find_connected_proxy_by_node(node_name)) != NULL) {
        /* mainloop_del_ipc_client() eventually calls remote_proxy_disconnected()
         * , which removes the entry from proxy_table.
         * Do not do this in a g_hash_table_iter_next() loop. */
        if (proxy->source) {
            mainloop_del_ipc_client(proxy->source);
        }
    }
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

    pcmk__trace("Destroying proxy table %s with %u members",
                lrm_state->node_name, g_hash_table_size(proxy_table));
    // Just in case there's still any leftovers in proxy_table
    g_hash_table_foreach_remove(proxy_table, remote_proxy_remove_by_node, (char *) lrm_state->node_name);
    remote_ra_cleanup(lrm_state);
    lrmd_api_delete(lrm_state->conn);

    g_clear_pointer(&lrm_state->rsc_info_cache, g_hash_table_destroy);
    g_clear_pointer(&lrm_state->resource_history, g_hash_table_destroy);
    g_clear_pointer(&lrm_state->deletion_ops, g_hash_table_destroy);
    g_clear_pointer(&lrm_state->active_ops, g_hash_table_destroy);

    metadata_cache_free(lrm_state->metadata_cache);

    free((char *)lrm_state->node_name);
    free(lrm_state);
}

void
lrm_state_reset_tables(lrm_state_t * lrm_state, gboolean reset_metadata)
{
    if (lrm_state->resource_history) {
        pcmk__trace("Resetting resource history cache with %u members",
                    g_hash_table_size(lrm_state->resource_history));
        g_hash_table_remove_all(lrm_state->resource_history);
    }
    if (lrm_state->deletion_ops) {
        pcmk__trace("Resetting deletion operations cache with %u members",
                    g_hash_table_size(lrm_state->deletion_ops));
        g_hash_table_remove_all(lrm_state->deletion_ops);
    }
    if (lrm_state->active_ops != NULL) {
        pcmk__trace("Resetting active operations cache with %u members",
                    g_hash_table_size(lrm_state->active_ops));
        g_hash_table_remove_all(lrm_state->active_ops);
    }
    if (lrm_state->rsc_info_cache) {
        pcmk__trace("Resetting resource information cache with %u members",
                    g_hash_table_size(lrm_state->rsc_info_cache));
        g_hash_table_remove_all(lrm_state->rsc_info_cache);
    }
    if (reset_metadata) {
        metadata_cache_reset(lrm_state->metadata_cache);
    }
}

void
controld_execd_state_table_init(void)
{
    if (lrm_state_table != NULL) {
        return;
    }

    lrm_state_table = pcmk__strikey_table(NULL, internal_lrm_state_destroy);
    proxy_table = pcmk__strikey_table(NULL, remote_proxy_free);
}

void
lrm_state_destroy_all(void)
{
    g_clear_pointer(&lrm_state_table, g_hash_table_destroy);
    g_clear_pointer(&proxy_table, g_hash_table_destroy);
}

/*!
 * \internal
 * \brief Get executor state object
 *
 * \param[in] node_name  Get executor state for this node (local node if NULL)
 * \param[in] create     If true, create executor state if it doesn't exist
 *
 * \return Executor state object for \p node_name
 */
lrm_state_t *
controld_get_executor_state(const char *node_name, bool create)
{
    lrm_state_t *state = NULL;

    if ((node_name == NULL) && (controld_globals.cluster != NULL)) {
        node_name = controld_globals.cluster->priv->node_name;
    }
    if ((node_name == NULL) || (lrm_state_table == NULL)) {
        return NULL;
    }

    state = g_hash_table_lookup(lrm_state_table, node_name);
    if ((state == NULL) && create) {
        state = lrm_state_create(node_name);
    }
    return state;
}

/* @TODO the lone caller just needs to iterate over the values, so replace this
 * with a g_hash_table_foreach() wrapper instead
 */
GList *
lrm_state_get_list(void)
{
    if (lrm_state_table == NULL) {
        return NULL;
    }
    return g_hash_table_get_values(lrm_state_table);
}

void
lrm_state_disconnect_only(lrm_state_t * lrm_state)
{
    guint removed = 0;

    if (!lrm_state->conn) {
        return;
    }
    pcmk__trace("Disconnecting %s", lrm_state->node_name);

    remote_proxy_disconnect_by_node(lrm_state->node_name);

    ((lrmd_t *) lrm_state->conn)->cmds->disconnect(lrm_state->conn);

    if (!pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                              fail_pending_op, lrm_state);
        pcmk__trace("Synthesized %u operation failures for %s", removed,
                    lrm_state->node_name);
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
            pcmk__warn("Pacemaker Remote connection to %s:%s failed: %s "
                       QB_XS " rc=%d",
                       server, port, pcmk_rc_str(rc), rc);

            return rc;
        }
        lrm_state->conn = api;
        api->cmds->set_callback(api, remote_lrm_op_callback);
        lrmd_internal_set_proxy_callback(api, lrm_state,
                                         controld_remote_proxy_cb);
    }

    pcmk__trace("Initiating remote connection to %s:%d with timeout %dms",
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
    params = lrmd_key_value_add(params, CRM_META "_" PCMK__META_ON_NODE,
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
     * NOTICE: Currently it's synced and directly acknowledged in
     * controld_invoke_execd().
     */
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
        return controld_get_executor_state(rsc_id, true)? pcmk_ok : -EINVAL;
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
        g_hash_table_remove(lrm_state_table, rsc_id);
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

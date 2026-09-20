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
#include <crm/lrmd_internal.h>          // lrmd__*

#include <pacemaker-internal.h>
#include <pacemaker-controld.h>

static GHashTable *lrm_state_table = NULL;

/*!
 * \internal
 * \brief Free a recurring operation
 *
 * \param[in,out] data  Operation to free (<tt>active_op_t *</tt>)
 *
 * \note This is a \c GDestroyNotify.
 */
static void
free_recurring_op(void *data)
{
    active_op_t *op = data;

    if (op == NULL) {
        return;
    }

    free(op->rsc_id);
    free(op->op_type);
    free(op->op_key);
    free(op->transition_key);
    g_clear_pointer(&op->params, g_hash_table_destroy);
    free(op);
}

/*!
 * \internal
 * \brief Free a pending deletion operation
 *
 * \param[in,out] data  Operation to free
 *                      (<tt>struct pending_deletion_op_s *</tt>)
 *
 * \note This is a \c GDestroyNotify.
 */
static void
free_pending_deletion_op(void *data)
{
    struct pending_deletion_op_s *op = data;

    if (op == NULL) {
        return;
    }

    free(op->rsc);
    delete_ha_msg_input(op->input);
    free(op);
}

/*!
 * \internal
 * \brief Create an executor state object for a node
 *
 * \param[in] node_name  Node name
 *
 * \return Newly allocated executor state object for node \p node_name
 *         (guaranteed not to be \c NULL)
 *
 * \note The caller is responsible for freeing the return value using
 *       \c free_lrm_state().
 */
static lrm_state_t *
new_lrm_state(const char *node_name)
{
    lrm_state_t *state = pcmk__assert_alloc(1, sizeof(lrm_state_t));

    state->node_name = pcmk__str_copy(node_name);
    state->resource_history = pcmk__strkey_table(NULL, history_free);
    state->active_ops = pcmk__strkey_table(free, free_recurring_op);
    state->deletion_ops = pcmk__strkey_table(free, free_pending_deletion_op);
    state->rsc_info_cache =
        pcmk__strkey_table(NULL, (GDestroyNotify) lrmd_free_rsc_info);
    state->metadata_cache = metadata_cache_new();

    return state;
}

/*!
 * \internal
 * \brief Free an executor state object
 *
 * Disconnect proxies for the associated node, disconnect the executor IPC
 * connection, and free all dynamically allocated memory for the object.
 *
 * The destroy callback will remove the proxies from the proxy table -- see
 * \c controld_remote_proxy_disconnect_node().
 *
 * \param[in,out] data  Executor state (<tt>lrm_state_t *</tt>)
 *
 * \note This is a \c GDestroyNotify.
 */
static void
free_lrm_state(void *data)
{
    lrm_state_t *lrm_state = data;

    if (lrm_state == NULL) {
        return;
    }

    controld_remote_proxy_disconnect_node(lrm_state->node_name);
    remote_ra_cleanup(lrm_state);
    lrmd_api_delete(lrm_state->conn);

    g_clear_pointer(&lrm_state->resource_history, g_hash_table_destroy);
    g_clear_pointer(&lrm_state->active_ops, g_hash_table_destroy);
    g_clear_pointer(&lrm_state->deletion_ops, g_hash_table_destroy);
    g_clear_pointer(&lrm_state->rsc_info_cache, g_hash_table_destroy);

    metadata_cache_free(lrm_state->metadata_cache);

    free(lrm_state->node_name);
    free(lrm_state);
}

/*!
 * \internal
 * \brief Remove all entries from an executor state object's non-metadata tables
 *
 * This removes all entries from the object's \c resource_history,
 * \c active_ops, \c deletion_ops, and \c rsc_info_cache hash tables.
 *
 * \param[in,out] lrm_state  Executor state
 */
void
controld_execd_state_reset_tables(lrm_state_t *lrm_state)
{
    pcmk__assert(lrm_state != NULL);

    pcmk__trace("Resetting resource history cache with %u members",
                g_hash_table_size(lrm_state->resource_history));
    g_hash_table_remove_all(lrm_state->resource_history);

    pcmk__trace("Resetting active operations cache with %u members",
                g_hash_table_size(lrm_state->active_ops));
    g_hash_table_remove_all(lrm_state->active_ops);

    pcmk__trace("Resetting deletion operations cache with %u members",
                g_hash_table_size(lrm_state->deletion_ops));
    g_hash_table_remove_all(lrm_state->deletion_ops);

    pcmk__trace("Resetting resource information cache with %u members",
                g_hash_table_size(lrm_state->rsc_info_cache));
    g_hash_table_remove_all(lrm_state->rsc_info_cache);
}

/*!
 * \internal
 * \brief Initialize the executor state table
 */
void
controld_execd_state_table_init(void)
{
    if (lrm_state_table != NULL) {
        return;
    }

    lrm_state_table = pcmk__strikey_table(NULL, free_lrm_state);
}

/*!
 * \internal
 * \brief Free the executor state table and its entries
 */
void
controld_execd_state_table_free(void)
{
    g_clear_pointer(&lrm_state_table, g_hash_table_destroy);
}

/*!
 * \internal
 * \brief Get executor state object for a given node
 *
 * \param[in] node_name  Node name (\c NULL for local node name)
 * \param[in] create     If \c true, create executor state if it doesn't exist
 *
 * \return Executor state object for \p node_name, or \c NULL if the object
 *         doesn't exist and \p create is \c false
 */
lrm_state_t *
controld_execd_state_get(const char *node_name, bool create)
{
    lrm_state_t *state = NULL;

    if ((node_name == NULL) && (controld_globals.cluster != NULL)) {
        node_name = controld_globals.cluster->priv->node_name;
    }

    if ((node_name == NULL) || (lrm_state_table == NULL)) {
        return NULL;
    }

    state = g_hash_table_lookup(lrm_state_table, node_name);
    if ((state != NULL) || !create) {
        return state;
    }

    state = new_lrm_state(node_name);
    g_hash_table_insert(lrm_state_table, state->node_name, state);
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

/*!
 * \internal
 * \brief Cancel a given operation if it's recurring
 *
 * \param[in]     key        Executor call key (<tt>const char *</tt>)
 * \param[in]     value      Operation (<tt>const active_op_t *</tt>)
 * \param[in,out] user_data  Executor state (<tt>lrm_state_t *</tt>)
 *
 * \return \c true if a cancellation request was sent to the executor
 *         successfully, or \c false otherwise (including if the operation was
 *         not found or was already canceled)
 *
 * \note This is a \c GHRFunc.
 */
static gboolean
cancel_recurring_op(void *key, void *value, void *user_data)
{
    const char *call_key = key;
    const active_op_t *op = value;
    lrm_state_t *lrm_state = user_data;

    pcmk__assert((call_key != NULL) && (op != NULL) && (lrm_state != NULL));

    if (op->interval_ms == 0) {
        return false;
    }

    pcmk__info("Cancelling op %d for %s (%s)", op->call_id, op->rsc_id,
               call_key);

    return !controld_execd_cancel_op(lrm_state, op->rsc_id, call_key,
                                     op->call_id, false);
}

/*!
 * \internal
 * \brief Check whether a resource should be logged as active on a given node
 *
 * This function is for logging purposes only. It's called when the controller
 * is exiting or disconnecting from the executor, to determine whether to log a
 * message noting that the resource is active.
 *
 * We check the resource history of the node to which \p lrm_state belongs.
 *
 * A resource is considered inactive on the node if its last recorded operation
 * there:
 * * returned \c PCMK_OCF_NOT_RUNNING
 * * returned \c PCMK_OCF_NOT_CONFIGURED and was not a recurring operation
 * * returned \c PCMK_OCF_OK and was a \c PCMK_ACTION_STOP or
 *   \c PCMK_ACTION_MIGRATE_TO operation
 *
 * Otherwise, the resource is considered active.
 *
 * \param[in] lrm_state  Executor state
 * \param[in] rsc_id     Resource ID
 *
 * \return \c true if the resource should be logged as active, or \c false
 *         otherwise
 */
static bool
is_rsc_active(const lrm_state_t *lrm_state, const char *rsc_id)
{
    const rsc_history_t *entry = NULL;
    const lrmd_event_data_t *last = NULL;

    entry = g_hash_table_lookup(lrm_state->resource_history, rsc_id);
    if ((entry == NULL) || (entry->last == NULL)) {
        return false;
    }

    last = entry->last;

    pcmk__trace("Processing %s: %s.%d=%d", rsc_id, last->op_type,
                last->interval_ms, last->rc);

    if (last->rc == PCMK_OCF_NOT_RUNNING) {
        return false;
    }

    if ((last->interval_ms == 0) && (last->rc == PCMK_OCF_NOT_CONFIGURED)) {
        /* The resource probably never started due to misconfiguration. Don't
         * let the caller log the resource as active.
         */
        return false;
    }

    if (last->rc != PCMK_OCF_OK) {
        // Resource may be active, so let the caller log it as active
        return true;
    }

    if (pcmk__str_eq(last->op_type, PCMK_ACTION_STOP, pcmk__str_none)) {
        // Resource has cleanly stopped
        return false;
    }

    if (pcmk__str_eq(last->op_type, PCMK_ACTION_MIGRATE_TO, pcmk__str_none)) {
        // Resource has successfully migrated to another node
        return false;
    }

    // Last operation was successful and left the resource active
    return true;
}

/*!
 * \internal
 * \brief Increment a counter if a given operation is non-recurring
 *
 * \param[in]     key        Ignored
 * \param[in]     value      Operation (<tt>const active_op_t *</tt>)
 * \param[in,out] user_data  Counter (<tt>unsigned int *</tt>)
 *
 * \note This is a \c GHFunc.
 */
static void
count_non_recurring_op(void *key, void *value, void *user_data)
{
    const active_op_t *op = value;
    unsigned int *count = user_data;

    pcmk__assert((op != NULL) && (count != NULL));

    if (op->interval_ms == 0) {
        (*count)++;
    }
}

/*!
 * \internal
 * \brief Log a given pending operation at a given level
 *
 * \param[in] key        Executor call key (<tt>const char *</tt>)
 * \param[in] value      Operation (<tt>const active_op_t *</tt>)
 * \param[in] user_data  Log level (<tt>GINT_TO_POINTER(<int>)</tt>)
 *
 * \note This is a \c GHFunc.
 */
static void
log_pending_op(void *key, void *value, void *user_data)
{
    const char *call_key = key;
    const active_op_t *op = value;
    int log_level = GPOINTER_TO_INT(user_data);

    pcmk__assert((call_key != NULL) && (op != NULL));

    do_crm_log(log_level, "Pending operation: %s (%s)", call_key, op->op_key);
}

/*!
 * \internal
 * \brief User data for \c log_incomplete_op()
 */
struct log_incomplete_op_data {
    //! Resource ID to match
    const char *id;

    //! Event that triggered the function call (for logging only)
    const char *when;
};

/*!
 * \internal
 * \brief Log a given incomplete operation if it matches a given resource ID
 *
 * The operation is logged only if its \c rsc_id field matches \p user_data->id.
 *
 * \param[in] key        Executor call key (<tt>const char *</tt>)
 * \param[in] value      Operation (<tt>const active_op_t *</tt>)
 * \param[in] user_data  User data
 *                       (<tt>const struct log_incomplete_op_data *</tt>)
 *
 * \note This is a \c GHFunc.
 */
static void
log_incomplete_op(void *key, void *value, void *user_data)
{
    const char *call_key = key;
    const active_op_t *op = value;
    const struct log_incomplete_op_data *data = user_data;

    pcmk__assert((call_key != NULL) && (op != NULL) && (data != NULL));

    if (!pcmk__str_eq(data->id, op->rsc_id, pcmk__str_none)) {
        return;
    }

    pcmk__notice("Recurring action %s (%s) incomplete at %s", call_key,
                 op->op_key, data->when);
}

/*!
 * \internal
 * \brief User data for \c count_active_resource_data()
 */
struct count_active_resource_data {
    //! Executor state
    const lrm_state_t *lrm_state;

    //! Log level
    int log_level;

    //! Event that triggered the function call (for logging only)
    const char *when;

    //! Counter
    unsigned int count;
};

/*!
 * \internal
 * \brief Increment a counter if a given resource is active
 *
 * Also log the resource's incomplete operations.
 *
 * \param[in]     key        Ignored
 * \param[in]     value      Resource history entry
 *                           (<tt>const rsc_history_entry_t *</tt>)
 * \param[in,out] user_data  User data
 *                           (<tt>struct count_active_resource_data *</tt>)
 *
 * \note This is a \c GHFunc.
 */
static void
count_active_resource(void *key, void *value, void *user_data)
{
    const rsc_history_t *entry = value;
    struct count_active_resource_data *data = user_data;

    const struct log_incomplete_op_data lio_data = {
        .id = entry->id,
        .when = data->when,
    };

    pcmk__assert((entry != NULL) && (data != NULL));

    if (!is_rsc_active(data->lrm_state, entry->id)) {
        return;
    }

    data->count++;

    if (data->log_level == LOG_ERR) {
        pcmk__info("Found %s active at %s", entry->id, data->when);

    } else {
        pcmk__trace("Found %s active at %s", entry->id, data->when);
    }

    g_hash_table_foreach(data->lrm_state->active_ops, log_incomplete_op,
                         (void *) &lio_data);
}

// @TODO Understand this function better and then add Doxygen
bool
lrm_state_verify_stopped(lrm_state_t *lrm_state, enum crmd_fsa_state cur_state,
                         int log_level)
{
    unsigned int count = 0;
    const char *when = "lrm disconnect";
    struct count_active_resource_data data = {
        .lrm_state = lrm_state,
        .log_level = log_level,
    };

    pcmk__assert(lrm_state != NULL);

    pcmk__debug("Checking for active resources before exit");

    if (cur_state == S_TERMINATE) {
        log_level = LOG_ERR;
        when = "shutdown";

    } else if (pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        when = "shutdown... waiting";
    }

    if (g_hash_table_size(lrm_state->active_ops) > 0) {
        unsigned int size = g_hash_table_size(lrm_state->active_ops);
        unsigned int removed = 0;

        if (lrm_state->conn->cmds->is_connected(lrm_state->conn)) {
            removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                                  cancel_recurring_op,
                                                  lrm_state);
            size -= removed;
        }

        pcmk__notice("Canceled %u recurring operation%s at %s (%u operations "
                     "remaining)", removed, pcmk__plural_s(removed), when,
                     size);

        /* Ignore recurring operations. Don't just subtract removed from the
         * original size, because lrm_state->conn may not be connected, or
         * cancel_recurring_op() may return false for a recurring operation.
         */
        g_hash_table_foreach(lrm_state->active_ops, count_non_recurring_op,
                             &count);
    }

    if (count > 0) {
        do_crm_log(log_level, "%u pending executor operation%s at %s", count,
                   pcmk__plural_s(count), when);

        if ((cur_state != S_TERMINATE)
            && pcmk__is_set(controld_globals.fsa_input_register,
                            R_SENT_RSC_STOP)) {

            return false;
        }

        g_hash_table_foreach(lrm_state->active_ops, log_pending_op,
                             GINT_TO_POINTER(log_level));
        return true;
    }

    // There are no non-recurring actions in lrm_state->active_ops

    if (pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        /* At this point we're not waiting, we're just shutting down */
        when = "shutdown";
    }

    data.when = when;
    g_hash_table_foreach(lrm_state->resource_history, count_active_resource,
                         &data);

    if (data.count > 0) {
        pcmk__err("%u resource%s active at %s", data.count,
                  pcmk__plural_alt(data.count, " was", "s were"), when);
    }

    return true;
}

/*!
 * \internal
 * \brief Fail a pending operation in response to executor disconnection
 *
 * \param[in]     key        Executor call key (<tt>const char *</tt>)
 * \param[in,out] value      Operation (<tt>active_op_t *</tt>)
 * \param[in,out] user_data  Executor state (<tt>lrm_state_t *</tt>)
 *
 * \return \c true (to remove \p key and \p value from the hash table)
 *
 * \note This is a \c GHRFunc.
 */
static gboolean
fail_pending_op(void *key, void *value, void *user_data)
{
    const char *call_key = key;
    active_op_t *op = value;
    lrm_state_t *lrm_state = user_data;

    lrmd_event_data_t *event = NULL;

    pcmk__assert((call_key != NULL) && (op != NULL) && (lrm_state != NULL));

    pcmk__trace("Preemptively failing " PCMK__OP_FMT " on %s (call=%s, %s)",
                op->rsc_id, op->op_type, op->interval_ms,
                lrm_state->node_name, call_key, op->transition_key);

    event = lrmd_new_event(op->rsc_id, op->op_type, op->interval_ms);
    event->type = lrmd_event_exec_complete;
    event->user_data = pcmk__str_copy(op->transition_key);
    event->call_id = op->call_id;
    event->t_run = op->start_time;
    event->t_rcchange = op->start_time;
    event->params = pcmk__str_table_dup(op->params);
    event->remote_nodename = pcmk__str_copy(lrm_state->node_name);

    lrmd__set_result(event, PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_NOT_CONNECTED,
                     "Action was pending when executor connection was dropped");

    process_lrm_event(lrm_state, event, op, NULL);
    lrmd_free_event(event);
    return true;
}

/*!
 * \internal
 * \brief Disconnect an executor state object
 *
 * Disconnect the remote proxies for the object's node and disconnect its
 * executor IPC connection. If the controller isn't shutting down, synthesize
 * failures for operations that are still pending and remove them from the
 * object's \c active_ops table.
 *
 * \param[in,out] lrm_state  Executor state
 */
void
controld_execd_state_disconnect(lrm_state_t *lrm_state)
{
    unsigned int removed = 0;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        return;
    }

    pcmk__trace("Disconnecting %s", lrm_state->node_name);
    controld_remote_proxy_disconnect_node(lrm_state->node_name);
    lrm_state->conn->cmds->disconnect(lrm_state->conn);

    if (pcmk__is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
        return;
    }

    removed = g_hash_table_foreach_remove(lrm_state->active_ops,
                                          fail_pending_op, lrm_state);
    pcmk__trace("Synthesized %u operation failures for %s", removed,
                lrm_state->node_name);
}

/*!
 * \internal
 * \brief Connect an executor state object to the local executor
 *
 * This initializes the object's \c conn field if it's \c NULL. It increments
 * the \c num_lrm_register_fails counter on failure or sets it to 0 on success.
 *
 * \param[in,out] lrm_state  Executor state
 *
 * \return Standard Pacemaker return code
 */
int
controld_execd_state_connect_local(lrm_state_t *lrm_state)
{
    int rc = pcmk_rc_ok;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        lrm_state->conn = lrmd_api_new();
        lrm_state->conn->cmds->set_callback(lrm_state->conn, lrm_op_callback);
    }

    rc = lrm_state->conn->cmds->connect(lrm_state->conn, CRM_SYSTEM_CRMD, NULL);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        lrm_state->num_lrm_register_fails = 0;

    } else {
        lrm_state->num_lrm_register_fails++;
    }

    return rc;
}

/*!
 * \internal
 * \brief Connect an executor state object to a Pacemaker Remote node
 *
 * This initializes the object's \c conn field if it's \c NULL. It increments
 * the \c num_lrm_register_fails counter on failure or sets it to 0 on success.
 *
 * \param[in,out] lrm_state   Executor state
 * \param[in]     server      Resolvable host name or IP address
 * \param[in]     port        Port number on \p server
 * \param[in]     timeout_ms  Asynchronous connection timeout in milliseconds
 *
 * \return Standard Pacemaker return code
 */
int
controld_execd_state_connect_remote(lrm_state_t *lrm_state, const char *server,
                                    int port, int timeout_ms)
{
    int rc = pcmk_rc_ok;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        lrm_state->conn = lrmd_remote_api_new(lrm_state->node_name, server,
                                              port);
        lrm_state->conn->cmds->set_callback(lrm_state->conn,
                                            remote_lrm_op_callback);
        lrmd__proxy_set_callback(lrm_state->conn, lrm_state,
                                 controld_remote_proxy_cb);
    }

    pcmk__trace("Initiating remote connection to %s:%d with timeout %dms",
                server, port, timeout_ms);

    rc = lrm_state->conn->cmds->connect_async(lrm_state->conn,
                                              lrm_state->node_name, timeout_ms);
    rc = pcmk_legacy2rc(rc);

    if (rc == pcmk_rc_ok) {
        lrm_state->num_lrm_register_fails = 0;

    } else {
        /* Ignored for remote connections.
         *
         * @TODO Do we even need to set this in this function?
         */
        lrm_state->num_lrm_register_fails++;
    }

    return rc;
}

/*!
 * \internal
 * \brief Get resource agent metadata via an executor state object
 *
 * This function does not communicate with the executor. \p lrm_state->conn is
 * used only as a means of accessing the executor API. The
 * \c get_metadata_params() method doesn't use the IPC connection.
 *
 * \param[in]  lrm_state   Executor state
 * \param[in]  class       Resource agent standard
 * \param[in]  provider    Resource agent provider (can be \c NULL)
 * \param[in]  agent       Resource agent name
 * \param[out] output      Where to store the output of the metadata request
 *
 * \return Standard Pacemaker return code
 */
int
controld_execd_state_get_metadata(const lrm_state_t *lrm_state,
                                  const char *class, const char *provider,
                                  const char *agent, char **output)
{
    int rc = pcmk_rc_ok;
    lrmd_key_value_t *params = NULL;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        return ENOTCONN;
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

    rc = lrm_state->conn->cmds->get_metadata_params(lrm_state->conn, class,
                                                    provider, agent, output,
                                                    lrmd_opt_none, params);
    return pcmk_legacy2rc(rc);
}

/*!
 * \internal
 * \brief Cancel a resource operation via a given executor state object
 *
 * If \p rsc_id is the name of a remote connection resource, use the executor
 * state object belonging to node \p rsc_id. Otherwise, use \p lrm_state.
 *
 * Send a cancellation request containing \p rsc_id, \p action, and
 * \p interval_ms, via the selected executor state object's connection.
 *
 * \param[in,out] lrm_state    Executor state
 * \param[in]     rsc_id       Operation resource ID
 * \param[in]     action       Operation action name
 * \param[in]     interval_ms  Operation interval in milliseconds
 *
 * \return Standard Pacemaker return code
 */
int
controld_execd_state_cancel(lrm_state_t *lrm_state, const char *rsc_id,
                            const char *action, unsigned int interval_ms)
{
    int rc = pcmk_rc_ok;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        return ENOTCONN;
    }

    /* Figure out a way to make this async?
     * NOTICE: Currently it's synced and directly acknowledged in
     * controld_invoke_execd().
     */
    if (is_remote_lrmd_ra(rsc_id)) {
        rc = remote_ra_cancel(rsc_id, action, interval_ms);

    } else {
        rc = lrm_state->conn->cmds->cancel(lrm_state->conn, rsc_id, action,
                                           interval_ms);
    }

    return pcmk_legacy2rc(rc);
}

/*!
 * \internal
 * \brief Get info for a given resource via a given executor state object
 *
 * If \p rsc_id is the name of a remote connection resource, use the executor
 * state object belonging to node \p rsc_id. Otherwise, use \p lrm_state.
 *
 * Look up the resource in the resource info cache first. If not found, request
 * it from the executor, and add it to the cache on success.
 *
 * \param[in,out] lrm_state    Executor state
 * \param[in]     rsc_id       Resource ID
 *
 * \return Newly allocated copy of resource info for \p rsc_id, or \c NULL on
 *         failure to get the resource info
 *
 * \note The caller is responsible for freeing the return value using
 *       \c lrmd_free_rsc_info().
 */
lrmd_rsc_info_t *
controld_execd_state_get_rsc_info(lrm_state_t *lrm_state, const char *rsc_id)
{
    lrmd_rsc_info_t *rsc = NULL;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        return NULL;
    }

    if (is_remote_lrmd_ra(rsc_id)) {
        return remote_ra_get_rsc_info(rsc_id);
    }

    rsc = g_hash_table_lookup(lrm_state->rsc_info_cache, rsc_id);
    if (rsc != NULL) {
        return lrmd_copy_rsc_info(rsc);
    }

    rsc = lrm_state->conn->cmds->get_rsc_info(lrm_state->conn, rsc_id,
                                              lrmd_opt_none);
    if (rsc == NULL) {
        return NULL;
    }

    g_hash_table_insert(lrm_state->rsc_info_cache, rsc->id, rsc);
    return lrmd_copy_rsc_info(rsc);
}

/*!
 * \internal
 * \brief Initiate a resource operation via a given executor state object
 *
 * \param[in,out] lrm_state       Executor state
 * \param[in]     rsc_id          Operation resource ID
 * \param[in]     action          Operation action name
 * \param[in]     user_data       User data for executor event callback
 * \param[in]     interval_ms     Operation interval in milliseconds
 * \param[in]     timeout_ms      Operation timeout in milliseconds
 * \param[in]     start_delay_ms  Delay in milliseconds before initiating
 *                                operation
 * \param[in]     parameters      Resource parameters (can be \c NULL)
 * \param[out]    call_id         Where to store call ID on success
 *
 * \return Standard Pacemaker return code
 */
int
controld_execd_state_exec(lrm_state_t *lrm_state, const char *rsc_id,
                          const char *action, const char *user_data,
                          unsigned int interval_ms, int timeout_ms,
                          int start_delay_ms, GHashTable *parameters,
                          int *call_id)
{
    int rc = pcmk_rc_ok;
    lrmd_key_value_t *params = NULL;

    pcmk__assert((lrm_state != NULL) && (call_id != NULL));

    if (lrm_state->conn == NULL) {
        return ENOTCONN;
    }

    // Convert parameters from hash table to list
    if (parameters != NULL) {
        g_hash_table_foreach(parameters, lrmd__key_value_add_from_hash,
                             &params);
    }

    if (is_remote_lrmd_ra(rsc_id)) {
        return controld_execute_remote_agent(lrm_state, rsc_id, action,
                                             user_data, interval_ms, timeout_ms,
                                             start_delay_ms, params, call_id);
    }

    rc = lrm_state->conn->cmds->exec(lrm_state->conn, rsc_id, action, user_data,
                                     interval_ms, timeout_ms, start_delay_ms,
                                     lrmd_opt_notify_changes_only, params);
    if (rc < 0) {
        return pcmk_legacy2rc(rc);
    }

    *call_id = rc;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Register a resource with the executor via a given state object
 *
 * If \p provider is \c "pacemaker" and \p agent is \c "remote" -- that is, if
 * the registration is for a remote connection resource -- create an executor
 * state object for node \p rsc_id and return.
 *
 * When \p lrm_state disconnects, the executor will cancel all of the resource's
 * recurring operations that were initiated via \p lrm_state.
 *
 * \param[in,out] lrm_state    Executor state
 * \param[in]     rsc_id       Resource ID
 * \param[in]     class        Resource agent standard
 * \param[in]     provider     Resource agent provider (can be \c NULL)
 * \param[in]     agent        Resource agent name
 *
 * \return Standard Pacemaker return code
 *
 * \todo This function probably shouldn't handle remote connection resources,
 *       since it doesn't register a resource in that case.
 */
int
controld_execd_state_register_rsc(lrm_state_t *lrm_state, const char *rsc_id,
                                  const char *class, const char *provider,
                                  const char *agent)
{
    int rc = pcmk_rc_ok;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        return ENOTCONN;
    }

    if (pcmk__str_eq(provider, "pacemaker", pcmk__str_none)
        && pcmk__str_eq(agent, "remote", pcmk__str_none)) {

        return controld_execd_state_get(rsc_id, true)? pcmk_rc_ok : EINVAL;
    }

    // @TODO Implement an asynchronous version of this
    rc = lrm_state->conn->cmds->register_rsc(lrm_state->conn, rsc_id, class,
                                             provider, agent,
                                             lrmd_opt_drop_recurring);
    return pcmk_legacy2rc(rc);
}

/*!
 * \internal
 * \brief Unegister a resource with the executor via a given state object
 *
 * If \p rsc_id is the name of a remote connection resource, remove the executor
 * state object for node \p rsc_id from the state table.
 *
 * Otherwise, remove the \p lrm_state resource info cache entry for \p rsc_id,
 * and send an unregister request to the executor for \p rsc_id.
 *
 * \param[in,out] lrm_state    Executor state
 * \param[in]     rsc_id       Resource ID
 *
 * \return Standard Pacemaker return code
 *
 * \todo This function probably shouldn't handle remote connection resources,
 *       since it doesn't unregister a resource in that case.
 */
int
controld_execd_state_unregister_rsc(lrm_state_t *lrm_state, const char *rsc_id)
{
    int rc = pcmk_rc_ok;

    pcmk__assert(lrm_state != NULL);

    if (lrm_state->conn == NULL) {
        return ENOTCONN;
    }

    if (is_remote_lrmd_ra(rsc_id)) {
        g_hash_table_remove(lrm_state_table, rsc_id);
        return pcmk_rc_ok;
    }

    g_hash_table_remove(lrm_state->rsc_info_cache, rsc_id);

    // @TODO Implement an asynchronous version of this
    rc = lrm_state->conn->cmds->unregister_rsc(lrm_state->conn, rsc_id,
                                               lrmd_opt_none);
    return pcmk_legacy2rc(rc);
}

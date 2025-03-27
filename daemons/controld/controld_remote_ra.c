/*
 * Copyright 2013-2025 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/lrmd.h>
#include <crm/lrmd_internal.h>
#include <crm/services.h>

#include <libxml/xpath.h>               // xmlXPathObject, etc.

#include <pacemaker-controld.h>

#define REMOTE_LRMD_RA "remote"

/* The max start timeout before cmd retry */
#define MAX_START_TIMEOUT_MS 10000

#define cmd_set_flags(cmd, flags_to_set) do { \
    (cmd)->status = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE, \
                                       "Remote command", (cmd)->rsc_id, (cmd)->status, \
                                       (flags_to_set), #flags_to_set); \
        } while (0)

#define cmd_clear_flags(cmd, flags_to_clear) do { \
    (cmd)->status = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, \
                                         "Remote command", (cmd)->rsc_id, (cmd)->status, \
                                         (flags_to_clear), #flags_to_clear); \
        } while (0)

enum remote_cmd_status {
    cmd_reported_success    = (1 << 0),
    cmd_cancel              = (1 << 1),
};

typedef struct remote_ra_cmd_s {
    /*! the local node the cmd is issued from */
    char *owner;
    /*! the remote node the cmd is executed on */
    char *rsc_id;
    /*! the action to execute */
    char *action;
    /*! some string the client wants us to give it back */
    char *userdata;
    /*! start delay in ms */
    int start_delay;
    /*! timer id used for start delay. */
    int delay_id;
    /*! timeout in ms for cmd */
    int timeout;
    /*! recurring interval in ms */
    guint interval_ms;
    /*! interval timer id */
    int interval_id;
    int monitor_timeout_id;
    int takeover_timeout_id;
    /*! action parameters */
    lrmd_key_value_t *params;
    pcmk__action_result_t result;
    int call_id;
    time_t start_time;
    uint32_t status;
} remote_ra_cmd_t;

#define lrm_remote_set_flags(lrm_state, flags_to_set) do { \
    lrm_state_t *lrm = (lrm_state); \
    remote_ra_data_t *ra = lrm->remote_ra_data; \
    ra->status = pcmk__set_flags_as(__func__, __LINE__, LOG_TRACE, "Remote", \
                                    lrm->node_name, ra->status, \
                                    (flags_to_set), #flags_to_set); \
        } while (0)

#define lrm_remote_clear_flags(lrm_state, flags_to_clear) do { \
    lrm_state_t *lrm = (lrm_state); \
    remote_ra_data_t *ra = lrm->remote_ra_data; \
    ra->status = pcmk__clear_flags_as(__func__, __LINE__, LOG_TRACE, "Remote", \
                                      lrm->node_name, ra->status, \
                                      (flags_to_clear), #flags_to_clear); \
        } while (0)

enum remote_status {
    expect_takeover     = (1 << 0),
    takeover_complete   = (1 << 1),
    remote_active       = (1 << 2),
    /* Maintenance mode is difficult to determine from the controller's context,
     * so we have it signalled back with the transition from the scheduler.
     */
    remote_in_maint     = (1 << 3),
    /* Similar for whether we are controlling a guest node or remote node.
     * Fortunately there is a meta-attribute in the transition already and
     * as the situation doesn't change over time we can use the
     * resource start for noting down the information for later use when
     * the attributes aren't at hand.
     */
    controlling_guest   = (1 << 4),
};

typedef struct remote_ra_data_s {
    crm_trigger_t *work;
    remote_ra_cmd_t *cur_cmd;
    GList *cmds;
    GList *recurring_cmds;
    uint32_t status;
} remote_ra_data_t;

static int handle_remote_ra_start(lrm_state_t * lrm_state, remote_ra_cmd_t * cmd, int timeout_ms);
static void handle_remote_ra_stop(lrm_state_t * lrm_state, remote_ra_cmd_t * cmd);
static GList *fail_all_monitor_cmds(GList * list);

static void
free_cmd(gpointer user_data)
{
    remote_ra_cmd_t *cmd = user_data;

    if (!cmd) {
        return;
    }
    if (cmd->delay_id) {
        g_source_remove(cmd->delay_id);
    }
    if (cmd->interval_id) {
        g_source_remove(cmd->interval_id);
    }
    if (cmd->monitor_timeout_id) {
        g_source_remove(cmd->monitor_timeout_id);
    }
    if (cmd->takeover_timeout_id) {
        g_source_remove(cmd->takeover_timeout_id);
    }
    free(cmd->owner);
    free(cmd->rsc_id);
    free(cmd->action);
    free(cmd->userdata);
    pcmk__reset_result(&(cmd->result));
    lrmd_key_value_freeall(cmd->params);
    free(cmd);
}

static int
generate_callid(void)
{
    static int remote_ra_callid = 0;

    remote_ra_callid++;
    if (remote_ra_callid <= 0) {
        remote_ra_callid = 1;
    }

    return remote_ra_callid;
}

static gboolean
recurring_helper(gpointer data)
{
    remote_ra_cmd_t *cmd = data;
    lrm_state_t *connection_rsc = NULL;

    cmd->interval_id = 0;
    connection_rsc = controld_get_executor_state(cmd->rsc_id, false);
    if (connection_rsc && connection_rsc->remote_ra_data) {
        remote_ra_data_t *ra_data = connection_rsc->remote_ra_data;

        ra_data->recurring_cmds = g_list_remove(ra_data->recurring_cmds, cmd);

        ra_data->cmds = g_list_append(ra_data->cmds, cmd);
        mainloop_set_trigger(ra_data->work);
    }
    return FALSE;
}

static gboolean
start_delay_helper(gpointer data)
{
    remote_ra_cmd_t *cmd = data;
    lrm_state_t *connection_rsc = NULL;

    cmd->delay_id = 0;
    connection_rsc = controld_get_executor_state(cmd->rsc_id, false);
    if (connection_rsc && connection_rsc->remote_ra_data) {
        remote_ra_data_t *ra_data = connection_rsc->remote_ra_data;

        mainloop_set_trigger(ra_data->work);
    }
    return FALSE;
}

static bool
should_purge_attributes(pcmk__node_status_t *node)
{
    pcmk__node_status_t *conn_node = NULL;
    lrm_state_t *connection_rsc = NULL;

    if ((node->conn_host == NULL) || (node->name == NULL)) {
        return true;
    }

    /* Get the node that was hosting the remote connection resource from the
     * peer cache.  That's the one we really care about here.
     */
    conn_node = pcmk__get_node(0, node->conn_host, NULL,
                               pcmk__node_search_cluster_member);
    if (conn_node == NULL) {
        return true;
    }

    /* Check the uptime of connection_rsc.  If it hasn't been running long
     * enough, set purge=true.  "Long enough" means it started running earlier
     * than the timestamp when we noticed it went away in the first place.
     */
    connection_rsc = controld_get_executor_state(node->name, false);

    if (connection_rsc != NULL) {
        lrmd_t *lrm = connection_rsc->conn;
        time_t uptime = lrmd__uptime(lrm);
        time_t now = time(NULL);

        /* Add 20s of fuzziness to give corosync a while to notice the remote
         * host is gone.  On various error conditions (failure to get uptime,
         * peer_lost isn't set) we default to purging.
         */
        if (uptime > 0 &&
            conn_node->peer_lost > 0 &&
            uptime + 20 >= now - conn_node->peer_lost) {
            return false;
        }
    }

    return true;
}

static enum controld_section_e
section_to_delete(bool purge)
{
    if (pcmk_is_set(controld_globals.flags, controld_shutdown_lock_enabled)) {
        if (purge) {
            return controld_section_all_unlocked;
        } else {
            return controld_section_lrm_unlocked;
        }
    } else {
        if (purge) {
            return controld_section_all;
        } else {
            return controld_section_lrm;
        }
    }
}

static void
purge_remote_node_attrs(int call_opt, pcmk__node_status_t *node)
{
    bool purge = should_purge_attributes(node);
    enum controld_section_e section = section_to_delete(purge);

    /* Purge node from attrd's memory */
    if (purge) {
        update_attrd_remote_node_removed(node->name, NULL);
    }

    controld_delete_node_state(node->name, section, call_opt);
}

/*!
 * \internal
 * \brief Handle cluster communication related to pacemaker_remote node joining
 *
 * \param[in] node_name  Name of newly integrated pacemaker_remote node
 */
static void
remote_node_up(const char *node_name)
{
    int call_opt;
    xmlNode *update, *state;
    pcmk__node_status_t *node = NULL;
    lrm_state_t *connection_rsc = NULL;

    CRM_CHECK(node_name != NULL, return);
    crm_info("Announcing Pacemaker Remote node %s", node_name);

    call_opt = crmd_cib_smart_opt();

    /* Delete node's CRM_OP_PROBED attribute. Deleting any attribute ensures
     * that the attribute manager learns the node is remote. Deletion of this
     * specfic attribute is a holdover from when it had special meaning.
     *
     * @COMPAT Find another way to tell attrd that the node is remote, without
     * risking deletion or overwrite of an arbitrary attribute. Then work on
     * deprecating CRM_OP_PROBED.
     */
    update_attrd(node_name, CRM_OP_PROBED, NULL, NULL, TRUE);

    /* Ensure node is in the remote peer cache with member status */
    node = pcmk__cluster_lookup_remote_node(node_name);
    CRM_CHECK((node != NULL) && (node->name != NULL), return);

    purge_remote_node_attrs(call_opt, node);
    pcmk__update_peer_state(__func__, node, PCMK_VALUE_MEMBER, 0);

    /* Apply any start state that we were given from the environment on the
     * remote node.
     */
    connection_rsc = controld_get_executor_state(node->name, false);

    if (connection_rsc != NULL) {
        lrmd_t *lrm = connection_rsc->conn;
        const char *start_state = lrmd__node_start_state(lrm);

        if (start_state) {
            set_join_state(start_state, node->name, node->xml_id, true);
        }
    }

    /* pacemaker_remote nodes don't participate in the membership layer,
     * so cluster nodes don't automatically get notified when they come and go.
     * We send a cluster message to the DC, and update the CIB node state entry,
     * so the DC will get it sooner (via message) or later (via CIB refresh),
     * and any other interested parties can query the CIB.
     */
    broadcast_remote_state_message(node_name, true);

    update = pcmk__xe_create(NULL, PCMK_XE_STATUS);
    state = create_node_state_update(node, node_update_cluster, update,
                                     __func__);

    /* Clear the PCMK__XA_NODE_FENCED flag in the node state. If the node ever
     * needs to be fenced, this flag will allow various actions to determine
     * whether the fencing has happened yet.
     */
    pcmk__xe_set(state, PCMK__XA_NODE_FENCED, "0");

    /* TODO: If the remote connection drops, and this (async) CIB update either
     * failed or has not yet completed, later actions could mistakenly think the
     * node has already been fenced (if the PCMK__XA_NODE_FENCED attribute was
     * previously set, because it won't have been cleared). This could prevent
     * actual fencing or allow recurring monitor failures to be cleared too
     * soon. Ideally, we wouldn't rely on the CIB for the fenced status.
     */
    controld_update_cib(PCMK_XE_STATUS, update, call_opt, NULL);
    pcmk__xml_free(update);
}

enum down_opts {
    DOWN_KEEP_LRM,
    DOWN_ERASE_LRM
};

/*!
 * \internal
 * \brief Handle cluster communication related to pacemaker_remote node leaving
 *
 * \param[in] node_name  Name of lost node
 * \param[in] opts       Whether to keep or erase LRM history
 */
static void
remote_node_down(const char *node_name, const enum down_opts opts)
{
    xmlNode *update;
    int call_opt = crmd_cib_smart_opt();
    pcmk__node_status_t *node = NULL;

    /* Purge node from attrd's memory */
    update_attrd_remote_node_removed(node_name, NULL);

    /* Normally, only node attributes should be erased, and the resource history
     * should be kept until the node comes back up. However, after a successful
     * fence, we want to clear the history as well, so we don't think resources
     * are still running on the node.
     */
    if (opts == DOWN_ERASE_LRM) {
        controld_delete_node_state(node_name, controld_section_all, call_opt);
    } else {
        controld_delete_node_state(node_name, controld_section_attrs, call_opt);
    }

    /* Ensure node is in the remote peer cache with lost state */
    node = pcmk__cluster_lookup_remote_node(node_name);
    CRM_CHECK(node != NULL, return);
    pcmk__update_peer_state(__func__, node, PCMK__VALUE_LOST, 0);

    /* Notify DC */
    broadcast_remote_state_message(node_name, false);

    /* Update CIB node state */
    update = pcmk__xe_create(NULL, PCMK_XE_STATUS);
    create_node_state_update(node, node_update_cluster, update, __func__);
    controld_update_cib(PCMK_XE_STATUS, update, call_opt, NULL);
    pcmk__xml_free(update);
}

/*!
 * \internal
 * \brief Handle effects of a remote RA command on node state
 *
 * \param[in] cmd  Completed remote RA command
 */
static void
check_remote_node_state(const remote_ra_cmd_t *cmd)
{
    /* Only successful actions can change node state */
    if (!pcmk__result_ok(&(cmd->result))) {
        return;
    }

    if (pcmk__str_eq(cmd->action, PCMK_ACTION_START, pcmk__str_casei)) {
        remote_node_up(cmd->rsc_id);

    } else if (pcmk__str_eq(cmd->action, PCMK_ACTION_MIGRATE_FROM,
                            pcmk__str_casei)) {
        /* After a successful migration, we don't need to do remote_node_up()
         * because the DC already knows the node is up, and we don't want to
         * clear LRM history etc. We do need to add the remote node to this
         * host's remote peer cache, because (unless it happens to be DC)
         * it hasn't been tracking the remote node, and other code relies on
         * the cache to distinguish remote nodes from unseen cluster nodes.
         */
        pcmk__node_status_t *node =
            pcmk__cluster_lookup_remote_node(cmd->rsc_id);

        CRM_CHECK(node != NULL, return);
        pcmk__update_peer_state(__func__, node, PCMK_VALUE_MEMBER, 0);

    } else if (pcmk__str_eq(cmd->action, PCMK_ACTION_STOP, pcmk__str_casei)) {
        lrm_state_t *lrm_state = controld_get_executor_state(cmd->rsc_id,
                                                             false);
        remote_ra_data_t *ra_data = lrm_state? lrm_state->remote_ra_data : NULL;

        if (ra_data) {
            if (!pcmk_is_set(ra_data->status, takeover_complete)) {
                /* Stop means down if we didn't successfully migrate elsewhere */
                remote_node_down(cmd->rsc_id, DOWN_KEEP_LRM);
            } else if (AM_I_DC == FALSE) {
                /* Only the connection host and DC track node state,
                 * so if the connection migrated elsewhere and we aren't DC,
                 * un-cache the node, so we don't have stale info
                 */
                pcmk__cluster_forget_remote_node(cmd->rsc_id);
            }
        }
    }

    /* We don't do anything for successful monitors, which is correct for
     * routine recurring monitors, and for monitors on nodes where the
     * connection isn't supposed to be (the cluster will stop the connection in
     * that case). However, if the initial probe finds the connection already
     * active on the node where we want it, we probably should do
     * remote_node_up(). Unfortunately, we can't distinguish that case here.
     * Given that connections have to be initiated by the cluster, the chance of
     * that should be close to zero.
     */
}

static void
report_remote_ra_result(remote_ra_cmd_t * cmd)
{
    lrmd_event_data_t op = { 0, };

    check_remote_node_state(cmd);

    op.type = lrmd_event_exec_complete;
    op.rsc_id = cmd->rsc_id;
    op.op_type = cmd->action;
    op.user_data = cmd->userdata;
    op.timeout = cmd->timeout;
    op.interval_ms = cmd->interval_ms;
    op.t_run = cmd->start_time;
    op.t_rcchange = cmd->start_time;

    lrmd__set_result(&op, cmd->result.exit_status, cmd->result.execution_status,
                     cmd->result.exit_reason);

    if (pcmk_is_set(cmd->status, cmd_reported_success) && !pcmk__result_ok(&(cmd->result))) {
        op.t_rcchange = time(NULL);
        /* This edge case will likely never ever occur, but if it does the
         * result is that a failure will not be processed correctly. This is only
         * remotely possible because we are able to detect a connection resource's tcp
         * connection has failed at any moment after start has completed. The actual
         * recurring operation is just a connectivity ping.
         *
         * basically, we are not guaranteed that the first successful monitor op and
         * a subsequent failed monitor op will not occur in the same timestamp. We have to
         * make it look like the operations occurred at separate times though. */
        if (op.t_rcchange == op.t_run) {
            op.t_rcchange++;
        }
    }

    if (cmd->params) {
        lrmd_key_value_t *tmp;

        op.params = pcmk__strkey_table(free, free);
        for (tmp = cmd->params; tmp; tmp = tmp->next) {
            pcmk__insert_dup(op.params, tmp->key, tmp->value);
        }

    }
    op.call_id = cmd->call_id;
    op.remote_nodename = cmd->owner;

    lrm_op_callback(&op);

    if (op.params) {
        g_hash_table_destroy(op.params);
    }
    lrmd__reset_result(&op);
}

/*!
 * \internal
 * \brief Return a remote command's remaining timeout in seconds
 *
 * \param[in] cmd  Remote command to check
 *
 * \return Command's remaining timeout in seconds
 */
static int
remaining_timeout_sec(const remote_ra_cmd_t *cmd)
{
    return pcmk__timeout_ms2s(cmd->timeout) - (time(NULL) - cmd->start_time);
}

static gboolean
retry_start_cmd_cb(gpointer data)
{
    lrm_state_t *lrm_state = data;
    remote_ra_data_t *ra_data = lrm_state->remote_ra_data;
    remote_ra_cmd_t *cmd = NULL;
    int rc = ETIME;
    int remaining = 0;

    if (!ra_data || !ra_data->cur_cmd) {
        return FALSE;
    }
    cmd = ra_data->cur_cmd;
    if (!pcmk__is_up_action(cmd->action)) {
        return FALSE;
    }

    remaining = remaining_timeout_sec(cmd);
    if (remaining > 0) {
        rc = handle_remote_ra_start(lrm_state, cmd, remaining * 1000);
    } else {
        pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                         PCMK_EXEC_TIMEOUT,
                         "Not enough time remains to retry remote connection");
    }

    if (rc != pcmk_rc_ok) {
        report_remote_ra_result(cmd);

        if (ra_data->cmds) {
            mainloop_set_trigger(ra_data->work);
        }
        ra_data->cur_cmd = NULL;
        free_cmd(cmd);
    } else {
        /* wait for connection event */
    }

    return FALSE;
}


static gboolean
connection_takeover_timeout_cb(gpointer data)
{
    lrm_state_t *lrm_state = NULL;
    remote_ra_cmd_t *cmd = data;

    crm_info("takeover event timed out for node %s", cmd->rsc_id);
    cmd->takeover_timeout_id = 0;

    lrm_state = controld_get_executor_state(cmd->rsc_id, false);

    handle_remote_ra_stop(lrm_state, cmd);
    free_cmd(cmd);

    return FALSE;
}

static gboolean
monitor_timeout_cb(gpointer data)
{
    lrm_state_t *lrm_state = NULL;
    remote_ra_cmd_t *cmd = data;

    lrm_state = controld_get_executor_state(cmd->rsc_id, false);

    crm_info("Timed out waiting for remote poke response from %s%s",
             cmd->rsc_id, (lrm_state? "" : " (no LRM state)"));
    cmd->monitor_timeout_id = 0;
    pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR, PCMK_EXEC_TIMEOUT,
                     "Remote executor did not respond");

    if (lrm_state && lrm_state->remote_ra_data) {
        remote_ra_data_t *ra_data = lrm_state->remote_ra_data;

        if (ra_data->cur_cmd == cmd) {
            ra_data->cur_cmd = NULL;
        }
        if (ra_data->cmds) {
            mainloop_set_trigger(ra_data->work);
        }
    }

    report_remote_ra_result(cmd);
    free_cmd(cmd);

    if(lrm_state) {
        // @TODO Should we move this before reporting the result above?
        lrm_state_disconnect(lrm_state);
    }
    return FALSE;
}

static void
synthesize_lrmd_success(lrm_state_t *lrm_state, const char *rsc_id, const char *op_type)
{
    lrmd_event_data_t op = { 0, };

    if (lrm_state == NULL) {
        /* if lrm_state not given assume local */
        lrm_state = controld_get_executor_state(NULL, false);
    }
    pcmk__assert(lrm_state != NULL);

    op.type = lrmd_event_exec_complete;
    op.rsc_id = rsc_id;
    op.op_type = op_type;
    op.t_run = time(NULL);
    op.t_rcchange = op.t_run;
    op.call_id = generate_callid();
    lrmd__set_result(&op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
    process_lrm_event(lrm_state, &op, NULL, NULL);
}

void
remote_lrm_op_callback(lrmd_event_data_t * op)
{
    gboolean cmd_handled = FALSE;
    lrm_state_t *lrm_state = NULL;
    remote_ra_data_t *ra_data = NULL;
    remote_ra_cmd_t *cmd = NULL;

    CRM_CHECK((op != NULL) && (op->remote_nodename != NULL), return);

    crm_debug("Processing '%s%s%s' event on remote connection to %s: %s "
              "(%d) status=%s (%d)",
              (op->op_type? op->op_type : ""), (op->op_type? " " : ""),
              lrmd_event_type2str(op->type), op->remote_nodename,
              crm_exit_str((crm_exit_t) op->rc), op->rc,
              pcmk_exec_status_str(op->op_status), op->op_status);

    lrm_state = controld_get_executor_state(op->remote_nodename, false);
    if (!lrm_state || !lrm_state->remote_ra_data) {
        crm_debug("No state information found for remote connection event");
        return;
    }
    ra_data = lrm_state->remote_ra_data;

    if (op->type == lrmd_event_new_client) {
        // Another client has connected to the remote daemon

        if (pcmk_is_set(ra_data->status, expect_takeover)) {
            // Great, we knew this was coming
            lrm_remote_clear_flags(lrm_state, expect_takeover);
            lrm_remote_set_flags(lrm_state, takeover_complete);

        } else {
            crm_err("Disconnecting from Pacemaker Remote node %s due to "
                    "unexpected client takeover", op->remote_nodename);
            /* In this case, lrmd_tls_connection_destroy() will be called under the control of mainloop. */
            /* Do not free lrm_state->conn yet. */
            /* It'll be freed in the following stop action. */
            lrm_state_disconnect_only(lrm_state);
        }
        return;
    }

    /* filter all EXEC events up */
    if (op->type == lrmd_event_exec_complete) {
        if (pcmk_is_set(ra_data->status, takeover_complete)) {
            crm_debug("ignoring event, this connection is taken over by another node");
        } else {
            lrm_op_callback(op);
        }
        return;
    }

    if ((op->type == lrmd_event_disconnect) && (ra_data->cur_cmd == NULL)) {

        if (!pcmk_is_set(ra_data->status, remote_active)) {
            crm_debug("Disconnection from Pacemaker Remote node %s complete",
                      lrm_state->node_name);

        } else if (!remote_ra_is_in_maintenance(lrm_state)) {
            crm_err("Lost connection to Pacemaker Remote node %s",
                    lrm_state->node_name);
            ra_data->recurring_cmds = fail_all_monitor_cmds(ra_data->recurring_cmds);
            ra_data->cmds = fail_all_monitor_cmds(ra_data->cmds);

        } else {
            crm_notice("Unmanaged Pacemaker Remote node %s disconnected",
                       lrm_state->node_name);
            /* Do roughly what a 'stop' on the remote-resource would do */
            handle_remote_ra_stop(lrm_state, NULL);
            remote_node_down(lrm_state->node_name, DOWN_KEEP_LRM);
            /* now fake the reply of a successful 'stop' */
            synthesize_lrmd_success(NULL, lrm_state->node_name,
                                    PCMK_ACTION_STOP);
        }
        return;
    }

    if (!ra_data->cur_cmd) {
        crm_debug("no event to match");
        return;
    }

    cmd = ra_data->cur_cmd;

    /* Start actions and migrate from actions complete after connection
     * comes back to us. */
    if ((op->type == lrmd_event_connect) && pcmk__is_up_action(cmd->action)) {
        if (op->connection_rc < 0) {
            int remaining = remaining_timeout_sec(cmd);

            if ((op->connection_rc == -ENOKEY)
                || (op->connection_rc == -EKEYREJECTED)) {
                // Hard error, don't retry
                pcmk__set_result(&(cmd->result), PCMK_OCF_INVALID_PARAM,
                                 PCMK_EXEC_ERROR,
                                 pcmk_strerror(op->connection_rc));

            } else if (remaining > 3) {
                crm_trace("Rescheduling start (%ds remains before timeout)",
                          remaining);
                pcmk__create_timer(1000, retry_start_cmd_cb, lrm_state);
                return;

            } else {
                crm_trace("Not enough time before timeout (%ds) "
                          "to reschedule start", remaining);
                pcmk__format_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                                    PCMK_EXEC_TIMEOUT,
                                    "%s without enough time to retry",
                                    pcmk_strerror(op->connection_rc));
            }

        } else {
            lrm_state_reset_tables(lrm_state, TRUE);
            pcmk__set_result(&(cmd->result), PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            lrm_remote_set_flags(lrm_state, remote_active);
        }

        crm_debug("Remote connection event matched %s action", cmd->action);
        report_remote_ra_result(cmd);
        cmd_handled = TRUE;

    } else if ((op->type == lrmd_event_poke)
               && pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                               pcmk__str_casei)) {

        if (cmd->monitor_timeout_id) {
            g_source_remove(cmd->monitor_timeout_id);
            cmd->monitor_timeout_id = 0;
        }

        /* Only report success the first time, after that only worry about failures.
         * For this function, if we get the poke pack, it is always a success. Pokes
         * only fail if the send fails, or the response times out. */
        if (!pcmk_is_set(cmd->status, cmd_reported_success)) {
            pcmk__set_result(&(cmd->result), PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            report_remote_ra_result(cmd);
            cmd_set_flags(cmd, cmd_reported_success);
        }

        crm_debug("Remote poke event matched %s action", cmd->action);

        /* success, keep rescheduling if interval is present. */
        if (cmd->interval_ms && !pcmk_is_set(cmd->status, cmd_cancel)) {
            ra_data->recurring_cmds = g_list_append(ra_data->recurring_cmds, cmd);
            cmd->interval_id = pcmk__create_timer(cmd->interval_ms,
                                                  recurring_helper, cmd);
            cmd = NULL;         /* prevent free */
        }
        cmd_handled = TRUE;

    } else if ((op->type == lrmd_event_disconnect)
               && pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                               pcmk__str_casei)) {
        if (pcmk_is_set(ra_data->status, remote_active) &&
            !pcmk_is_set(cmd->status, cmd_cancel)) {
            pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                             PCMK_EXEC_ERROR,
                             "Remote connection unexpectedly dropped "
                             "during monitor");
            report_remote_ra_result(cmd);
            crm_err("Remote connection to %s unexpectedly dropped during monitor",
                    lrm_state->node_name);
        }
        cmd_handled = TRUE;

    } else {
        crm_debug("Event did not match %s action", ra_data->cur_cmd->action);
    }

    if (cmd_handled) {
        ra_data->cur_cmd = NULL;
        if (ra_data->cmds) {
            mainloop_set_trigger(ra_data->work);
        }
        free_cmd(cmd);
    }
}

static void
handle_remote_ra_stop(lrm_state_t * lrm_state, remote_ra_cmd_t * cmd)
{
    remote_ra_data_t *ra_data = NULL;

    pcmk__assert(lrm_state != NULL);
    ra_data = lrm_state->remote_ra_data;

    if (!pcmk_is_set(ra_data->status, takeover_complete)) {
        /* delete pending ops when ever the remote connection is intentionally stopped */
        g_hash_table_remove_all(lrm_state->active_ops);
    } else {
        /* we no longer hold the history if this connection has been migrated,
         * however, we keep metadata cache for future use */
        lrm_state_reset_tables(lrm_state, FALSE);
    }

    lrm_remote_clear_flags(lrm_state, remote_active);
    lrm_state_disconnect(lrm_state);

    if (ra_data->cmds) {
        g_list_free_full(ra_data->cmds, free_cmd);
    }
    if (ra_data->recurring_cmds) {
        g_list_free_full(ra_data->recurring_cmds, free_cmd);
    }
    ra_data->cmds = NULL;
    ra_data->recurring_cmds = NULL;
    ra_data->cur_cmd = NULL;

    if (cmd) {
        pcmk__set_result(&(cmd->result), PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        report_remote_ra_result(cmd);
    }
}

// \return Standard Pacemaker return code
static int
handle_remote_ra_start(lrm_state_t * lrm_state, remote_ra_cmd_t * cmd, int timeout_ms)
{
    const char *server = NULL;
    lrmd_key_value_t *tmp = NULL;
    int port = 0;
    int timeout_used = timeout_ms > MAX_START_TIMEOUT_MS ? MAX_START_TIMEOUT_MS : timeout_ms;
    int rc = pcmk_rc_ok;

    for (tmp = cmd->params; tmp; tmp = tmp->next) {
        if (pcmk__strcase_any_of(tmp->key,
                                 PCMK_REMOTE_RA_ADDR, PCMK_REMOTE_RA_SERVER,
                                 NULL)) {
            server = tmp->value;

        } else if (pcmk__str_eq(tmp->key, PCMK_REMOTE_RA_PORT,
                                pcmk__str_none)) {
            port = atoi(tmp->value);

        } else if (pcmk__str_eq(tmp->key, CRM_META "_" PCMK__META_CONTAINER,
                                pcmk__str_none)) {
            lrm_remote_set_flags(lrm_state, controlling_guest);
        }
    }

    rc = controld_connect_remote_executor(lrm_state, server, port,
                                          timeout_used);
    if (rc != pcmk_rc_ok) {
        pcmk__format_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                            PCMK_EXEC_ERROR,
                            "Could not connect to Pacemaker Remote node %s: %s",
                            lrm_state->node_name, pcmk_rc_str(rc));
    }
    return rc;
}

static gboolean
handle_remote_ra_exec(gpointer user_data)
{
    int rc = 0;
    lrm_state_t *lrm_state = user_data;
    remote_ra_data_t *ra_data = lrm_state->remote_ra_data;
    remote_ra_cmd_t *cmd;
    GList *first = NULL;

    if (ra_data->cur_cmd) {
        /* still waiting on previous cmd */
        return TRUE;
    }

    while (ra_data->cmds) {
        first = ra_data->cmds;
        cmd = first->data;
        if (cmd->delay_id) {
            /* still waiting for start delay timer to trip */
            return TRUE;
        }

        ra_data->cmds = g_list_remove_link(ra_data->cmds, first);
        g_list_free_1(first);

        if (pcmk__str_any_of(cmd->action, PCMK_ACTION_START,
                             PCMK_ACTION_MIGRATE_FROM, NULL)) {
            lrm_remote_clear_flags(lrm_state, expect_takeover | takeover_complete);
            if (handle_remote_ra_start(lrm_state, cmd,
                                       cmd->timeout) == pcmk_rc_ok) {
                /* take care of this later when we get async connection result */
                crm_debug("Initiated async remote connection, %s action will complete after connect event",
                          cmd->action);
                ra_data->cur_cmd = cmd;
                return TRUE;
            }
            report_remote_ra_result(cmd);

        } else if (!strcmp(cmd->action, PCMK_ACTION_MONITOR)) {

            if (lrm_state_is_connected(lrm_state) == TRUE) {
                rc = lrm_state_poke_connection(lrm_state);
                if (rc < 0) {
                    pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                                     PCMK_EXEC_ERROR, pcmk_strerror(rc));
                }
            } else {
                rc = -1;
                pcmk__set_result(&(cmd->result), PCMK_OCF_NOT_RUNNING,
                                 PCMK_EXEC_DONE, "Remote connection inactive");
            }

            if (rc == 0) {
                crm_debug("Poked Pacemaker Remote at node %s, waiting for async response",
                          cmd->rsc_id);
                ra_data->cur_cmd = cmd;
                cmd->monitor_timeout_id = pcmk__create_timer(cmd->timeout, monitor_timeout_cb, cmd);
                return TRUE;
            }
            report_remote_ra_result(cmd);

        } else if (!strcmp(cmd->action, PCMK_ACTION_STOP)) {

            if (pcmk_is_set(ra_data->status, expect_takeover)) {
                /* Briefly wait on stop for an expected takeover to occur. If
                 * the takeover does not occur during the wait, that's fine; it
                 * just means that the remote node's resource history will be
                 * cleared, which will require probing all resources on the
                 * remote node. If the takeover does occur successfully, then we
                 * can leave the status section intact.
                 */
                cmd->takeover_timeout_id = pcmk__create_timer((cmd->timeout/2),
                                                              connection_takeover_timeout_cb,
                                                              cmd);
                ra_data->cur_cmd = cmd;
                return TRUE;
            }

            handle_remote_ra_stop(lrm_state, cmd);

        } else if (strcmp(cmd->action, PCMK_ACTION_MIGRATE_TO) == 0) {
            lrm_remote_clear_flags(lrm_state, takeover_complete);
            lrm_remote_set_flags(lrm_state, expect_takeover);
            pcmk__set_result(&(cmd->result), PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            report_remote_ra_result(cmd);

        } else if (pcmk__str_any_of(cmd->action, PCMK_ACTION_RELOAD,
                                    PCMK_ACTION_RELOAD_AGENT, NULL))  {
            /* Currently the only reloadable parameter is
             * PCMK_REMOTE_RA_RECONNECT_INTERVAL, which is only used by the
             * scheduler via the CIB, so reloads are a no-op.
             *
             * @COMPAT DC <2.1.0: We only need to check for "reload" in case
             * we're in a rolling upgrade with a DC scheduling "reload" instead
             * of "reload-agent". An OCF 1.1 "reload" would be a no-op anyway,
             * so this would work for that purpose as well.
             */
            pcmk__set_result(&(cmd->result), PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
            report_remote_ra_result(cmd);
        }

        free_cmd(cmd);
    }

    return TRUE;
}

static void
remote_ra_data_init(lrm_state_t * lrm_state)
{
    remote_ra_data_t *ra_data = NULL;

    if (lrm_state->remote_ra_data) {
        return;
    }

    ra_data = pcmk__assert_alloc(1, sizeof(remote_ra_data_t));
    ra_data->work = mainloop_add_trigger(G_PRIORITY_HIGH, handle_remote_ra_exec, lrm_state);
    lrm_state->remote_ra_data = ra_data;
}

void
remote_ra_cleanup(lrm_state_t * lrm_state)
{
    remote_ra_data_t *ra_data = lrm_state->remote_ra_data;

    if (!ra_data) {
        return;
    }

    if (ra_data->cmds) {
        g_list_free_full(ra_data->cmds, free_cmd);
    }

    if (ra_data->recurring_cmds) {
        g_list_free_full(ra_data->recurring_cmds, free_cmd);
    }
    mainloop_destroy_trigger(ra_data->work);
    free(ra_data);
    lrm_state->remote_ra_data = NULL;
}

gboolean
is_remote_lrmd_ra(const char *agent, const char *provider, const char *id)
{
    if (agent && provider && !strcmp(agent, REMOTE_LRMD_RA) && !strcmp(provider, "pacemaker")) {
        return TRUE;
    }
    return (id != NULL) && (controld_get_executor_state(id, false) != NULL)
           && !controld_is_local_node(id);
}

lrmd_rsc_info_t *
remote_ra_get_rsc_info(lrm_state_t * lrm_state, const char *rsc_id)
{
    lrmd_rsc_info_t *info = NULL;

    CRM_CHECK(rsc_id != NULL, return NULL);

    if (controld_get_executor_state(rsc_id, false) != NULL) {
        info = pcmk__assert_alloc(1, sizeof(lrmd_rsc_info_t));

        info->id = pcmk__str_copy(rsc_id);
        info->type = pcmk__str_copy(REMOTE_LRMD_RA);
        info->standard = pcmk__str_copy(PCMK_RESOURCE_CLASS_OCF);
        info->provider = pcmk__str_copy("pacemaker");
    }

    return info;
}

static gboolean
is_remote_ra_supported_action(const char *action)
{
    return pcmk__str_any_of(action,
                            PCMK_ACTION_START,
                            PCMK_ACTION_STOP,
                            PCMK_ACTION_MONITOR,
                            PCMK_ACTION_MIGRATE_TO,
                            PCMK_ACTION_MIGRATE_FROM,
                            PCMK_ACTION_RELOAD_AGENT,
                            PCMK_ACTION_RELOAD,
                            NULL);
}

static GList *
fail_all_monitor_cmds(GList * list)
{
    GList *rm_list = NULL;
    remote_ra_cmd_t *cmd = NULL;
    GList *gIter = NULL;

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        cmd = gIter->data;
        if ((cmd->interval_ms > 0)
            && pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                            pcmk__str_casei)) {
            rm_list = g_list_append(rm_list, cmd);
        }
    }

    for (gIter = rm_list; gIter != NULL; gIter = gIter->next) {
        cmd = gIter->data;

        pcmk__set_result(&(cmd->result), PCMK_OCF_UNKNOWN_ERROR,
                         PCMK_EXEC_ERROR, "Lost connection to remote executor");
        crm_trace("Pre-emptively failing %s %s (interval=%u, %s)",
                  cmd->action, cmd->rsc_id, cmd->interval_ms, cmd->userdata);
        report_remote_ra_result(cmd);

        list = g_list_remove(list, cmd);
        free_cmd(cmd);
    }

    /* frees only the list data, not the cmds */
    g_list_free(rm_list);
    return list;
}

static GList *
remove_cmd(GList * list, const char *action, guint interval_ms)
{
    remote_ra_cmd_t *cmd = NULL;
    GList *gIter = NULL;

    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        cmd = gIter->data;
        if ((cmd->interval_ms == interval_ms)
            && pcmk__str_eq(cmd->action, action, pcmk__str_casei)) {
            break;
        }
        cmd = NULL;
    }
    if (cmd) {
        list = g_list_remove(list, cmd);
        free_cmd(cmd);
    }
    return list;
}

int
remote_ra_cancel(lrm_state_t *lrm_state, const char *rsc_id,
                 const char *action, guint interval_ms)
{
    lrm_state_t *connection_rsc = NULL;
    remote_ra_data_t *ra_data = NULL;

    CRM_CHECK(rsc_id != NULL, return -EINVAL);

    connection_rsc = controld_get_executor_state(rsc_id, false);
    if (!connection_rsc || !connection_rsc->remote_ra_data) {
        return -EINVAL;
    }

    ra_data = connection_rsc->remote_ra_data;
    ra_data->cmds = remove_cmd(ra_data->cmds, action, interval_ms);
    ra_data->recurring_cmds = remove_cmd(ra_data->recurring_cmds, action,
                                         interval_ms);
    if (ra_data->cur_cmd &&
        (ra_data->cur_cmd->interval_ms == interval_ms) &&
        (pcmk__str_eq(ra_data->cur_cmd->action, action, pcmk__str_casei))) {

        cmd_set_flags(ra_data->cur_cmd, cmd_cancel);
    }

    return 0;
}

static remote_ra_cmd_t *
handle_dup_monitor(remote_ra_data_t *ra_data, guint interval_ms,
                   const char *userdata)
{
    GList *gIter = NULL;
    remote_ra_cmd_t *cmd = NULL;

    /* there are 3 places a potential duplicate monitor operation
     * could exist.
     * 1. recurring_cmds list. where the op is waiting for its next interval
     * 2. cmds list, where the op is queued to get executed immediately
     * 3. cur_cmd, which means the monitor op is in flight right now.
     */
    if (interval_ms == 0) {
        return NULL;
    }

    if (ra_data->cur_cmd &&
        !pcmk_is_set(ra_data->cur_cmd->status, cmd_cancel) &&
        (ra_data->cur_cmd->interval_ms == interval_ms)
        && pcmk__str_eq(ra_data->cur_cmd->action, PCMK_ACTION_MONITOR,
                        pcmk__str_casei)) {

        cmd = ra_data->cur_cmd;
        goto handle_dup;
    }

    for (gIter = ra_data->recurring_cmds; gIter != NULL; gIter = gIter->next) {
        cmd = gIter->data;
        if ((cmd->interval_ms == interval_ms)
            && pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                            pcmk__str_casei)) {
            goto handle_dup;
        }
    }

    for (gIter = ra_data->cmds; gIter != NULL; gIter = gIter->next) {
        cmd = gIter->data;
        if ((cmd->interval_ms == interval_ms)
            && pcmk__str_eq(cmd->action, PCMK_ACTION_MONITOR,
                            pcmk__str_casei)) {
            goto handle_dup;
        }
    }

    return NULL;

handle_dup:

    crm_trace("merging duplicate monitor cmd " PCMK__OP_FMT,
              cmd->rsc_id, PCMK_ACTION_MONITOR, interval_ms);

    /* update the userdata */
    if (userdata) {
       free(cmd->userdata);
       cmd->userdata = pcmk__str_copy(userdata);
    }

    /* if we've already reported success, generate a new call id */
    if (pcmk_is_set(cmd->status, cmd_reported_success)) {
        cmd->start_time = time(NULL);
        cmd->call_id = generate_callid();
        cmd_clear_flags(cmd, cmd_reported_success);
    }

    /* if we have an interval_id set, that means we are in the process of
     * waiting for this cmd's next interval. instead of waiting, cancel
     * the timer and execute the action immediately */
    if (cmd->interval_id) {
        g_source_remove(cmd->interval_id);
        cmd->interval_id = 0;
        recurring_helper(cmd);
    }

    return cmd;
}

/*!
 * \internal
 * \brief Execute an action using the (internal) ocf:pacemaker:remote agent
 *
 * \param[in]     lrm_state      Executor state object for remote connection
 * \param[in]     rsc_id         Connection resource ID
 * \param[in]     action         Action to execute
 * \param[in]     userdata       String to copy and pass to execution callback
 * \param[in]     interval_ms    Action interval (in milliseconds)
 * \param[in]     timeout_ms     Action timeout (in milliseconds)
 * \param[in]     start_delay_ms Delay (in milliseconds) before executing action
 * \param[in,out] params         Connection resource parameters
 * \param[out]    call_id        Where to store call ID on success
 *
 * \return Standard Pacemaker return code
 * \note This takes ownership of \p params, which should not be used or freed
 *       after calling this function.
 */
int
controld_execute_remote_agent(const lrm_state_t *lrm_state, const char *rsc_id,
                              const char *action, const char *userdata,
                              guint interval_ms, int timeout_ms,
                              int start_delay_ms, lrmd_key_value_t *params,
                              int *call_id)
{
    lrm_state_t *connection_rsc = NULL;
    remote_ra_cmd_t *cmd = NULL;
    remote_ra_data_t *ra_data = NULL;

    *call_id = 0;

    CRM_CHECK((lrm_state != NULL) && (rsc_id != NULL) && (action != NULL)
              && (userdata != NULL) && (call_id != NULL),
              lrmd_key_value_freeall(params); return EINVAL);

    if (!is_remote_ra_supported_action(action)) {
        lrmd_key_value_freeall(params);
        return EOPNOTSUPP;
    }

    connection_rsc = controld_get_executor_state(rsc_id, false);
    if (connection_rsc == NULL) {
        lrmd_key_value_freeall(params);
        return ENOTCONN;
    }

    remote_ra_data_init(connection_rsc);
    ra_data = connection_rsc->remote_ra_data;

    cmd = handle_dup_monitor(ra_data, interval_ms, userdata);
    if (cmd) {
        *call_id = cmd->call_id;
        lrmd_key_value_freeall(params);
        return pcmk_rc_ok;
    }

    cmd = pcmk__assert_alloc(1, sizeof(remote_ra_cmd_t));

    cmd->owner = pcmk__str_copy(lrm_state->node_name);
    cmd->rsc_id = pcmk__str_copy(rsc_id);
    cmd->action = pcmk__str_copy(action);
    cmd->userdata = pcmk__str_copy(userdata);
    cmd->interval_ms = interval_ms;
    cmd->timeout = timeout_ms;
    cmd->start_delay = start_delay_ms;
    cmd->params = params;
    cmd->start_time = time(NULL);

    cmd->call_id = generate_callid();

    if (cmd->start_delay) {
        cmd->delay_id = pcmk__create_timer(cmd->start_delay, start_delay_helper, cmd);
    }

    ra_data->cmds = g_list_append(ra_data->cmds, cmd);
    mainloop_set_trigger(ra_data->work);

    *call_id = cmd->call_id;
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Immediately fail all monitors of a remote node, if proxied here
 *
 * \param[in] node_name  Name of pacemaker_remote node
 */
void
remote_ra_fail(const char *node_name)
{
    lrm_state_t *lrm_state = NULL;

    CRM_CHECK(node_name != NULL, return);

    lrm_state = controld_get_executor_state(node_name, false);
    if (lrm_state && lrm_state_is_connected(lrm_state)) {
        remote_ra_data_t *ra_data = lrm_state->remote_ra_data;

        crm_info("Failing monitors on Pacemaker Remote node %s", node_name);
        ra_data->recurring_cmds = fail_all_monitor_cmds(ra_data->recurring_cmds);
        ra_data->cmds = fail_all_monitor_cmds(ra_data->cmds);
    }
}

/* A guest node fencing implied by host fencing looks like:
 *
 *  <pseudo_event id="103" operation="stonith" operation_key="stonith-lxc1-off"
 *                on_node="lxc1" on_node_uuid="lxc1">
 *     <attributes CRM_meta_on_node="lxc1" CRM_meta_on_node_uuid="lxc1"
 *                 CRM_meta_stonith_action="off" crm_feature_set="3.0.12"/>
 *     <downed>
 *       <node id="lxc1"/>
 *     </downed>
 *  </pseudo_event>
 */
#define XPATH_PSEUDO_FENCE "/" PCMK__XE_PSEUDO_EVENT \
    "[@" PCMK_XA_OPERATION "='stonith']/" PCMK__XE_DOWNED "/" PCMK_XE_NODE

/*!
 * \internal
 * \brief Check a pseudo-action for Pacemaker Remote node side effects
 *
 * \param[in,out] xml  XML of pseudo-action to check
 */
void
remote_ra_process_pseudo(xmlNode *xml)
{
    xmlXPathObject *search = pcmk__xpath_search(xml->doc, XPATH_PSEUDO_FENCE);

    if (pcmk__xpath_num_results(search) == 1) {
        xmlNode *result = pcmk__xpath_result(search, 0);

        /* Normally, we handle the necessary side effects of a guest node stop
         * action when reporting the remote agent's result. However, if the stop
         * is implied due to fencing, it will be a fencing pseudo-event, and
         * there won't be a result to report. Handle that case here.
         *
         * This will result in a duplicate call to remote_node_down() if the
         * guest stop was real instead of implied, but that shouldn't hurt.
         *
         * There is still one corner case that isn't handled: if a guest node
         * isn't running any resources when its host is fenced, it will appear
         * to be cleanly stopped, so there will be no pseudo-fence, and our
         * peer cache state will be incorrect unless and until the guest is
         * recovered.
         */
        if (result) {
            const char *remote = pcmk__xe_id(result);

            if (remote) {
                remote_node_down(remote, DOWN_ERASE_LRM);
            }
        }
    }
    xmlXPathFreeObject(search);
}

static void
remote_ra_maintenance(lrm_state_t * lrm_state, gboolean maintenance)
{
    xmlNode *update, *state;
    int call_opt;
    pcmk__node_status_t *node = NULL;

    call_opt = crmd_cib_smart_opt();
    node = pcmk__cluster_lookup_remote_node(lrm_state->node_name);
    CRM_CHECK(node != NULL, return);
    update = pcmk__xe_create(NULL, PCMK_XE_STATUS);
    state = create_node_state_update(node, node_update_none, update,
                                     __func__);
    pcmk__xe_set(state, PCMK__XA_NODE_IN_MAINTENANCE, (maintenance? "1" : "0"));
    if (controld_update_cib(PCMK_XE_STATUS, update, call_opt,
                            NULL) == pcmk_rc_ok) {
        /* TODO: still not 100% sure that async update will succeed ... */
        if (maintenance) {
            lrm_remote_set_flags(lrm_state, remote_in_maint);
        } else {
            lrm_remote_clear_flags(lrm_state, remote_in_maint);
        }
    }
    pcmk__xml_free(update);
}

#define XPATH_PSEUDO_MAINTENANCE "//" PCMK__XE_PSEUDO_EVENT         \
    "[@" PCMK_XA_OPERATION "='" PCMK_ACTION_MAINTENANCE_NODES "']/" \
    PCMK__XE_MAINTENANCE

/*!
 * \internal
 * \brief Check a pseudo-action holding updates for maintenance state
 *
 * \param[in,out] xml  XML of pseudo-action to check
 */
void
remote_ra_process_maintenance_nodes(xmlNode *xml)
{
    xmlXPathObject *search = pcmk__xpath_search(xml->doc,
                                                XPATH_PSEUDO_MAINTENANCE);

    if (pcmk__xpath_num_results(search) == 1) {
        xmlNode *node;
        int cnt = 0, cnt_remote = 0;

        for (node = pcmk__xe_first_child(pcmk__xpath_result(search, 0),
                                         PCMK_XE_NODE, NULL, NULL);
             node != NULL; node = pcmk__xe_next(node, PCMK_XE_NODE)) {

            lrm_state_t *lrm_state = NULL;
            const char *id = pcmk__xe_id(node);

            cnt++;
            if (id == NULL) {
                continue; // Shouldn't be possible
            }

            lrm_state = controld_get_executor_state(id, false);

            if (lrm_state && lrm_state->remote_ra_data &&
                pcmk_is_set(((remote_ra_data_t *) lrm_state->remote_ra_data)->status, remote_active)) {

                const char *in_maint_s = NULL;
                int in_maint;

                cnt_remote++;
                in_maint_s = pcmk__xe_get(node, PCMK__XA_NODE_IN_MAINTENANCE);
                pcmk__scan_min_int(in_maint_s, &in_maint, 0);
                remote_ra_maintenance(lrm_state, in_maint);
            }
        }
        crm_trace("Action holds %d nodes (%d remotes found) adjusting "
                  PCMK_OPT_MAINTENANCE_MODE,
                  cnt, cnt_remote);
    }
    xmlXPathFreeObject(search);
}

gboolean
remote_ra_is_in_maintenance(lrm_state_t * lrm_state)
{
    remote_ra_data_t *ra_data = lrm_state->remote_ra_data;
    return pcmk_is_set(ra_data->status, remote_in_maint);
}

gboolean
remote_ra_controlling_guest(lrm_state_t * lrm_state)
{
    remote_ra_data_t *ra_data = lrm_state->remote_ra_data;
    return pcmk_is_set(ra_data->status, controlling_guest);
}

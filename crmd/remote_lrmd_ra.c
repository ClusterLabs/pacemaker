/* 
 * Copyright (C) 2013 David Vossel <dvossel@redhat.com>
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
#include <crm/crm.h>

#include <crmd.h>
#include <crmd_fsa.h>
#include <crmd_messages.h>
#include <crmd_callbacks.h>
#include <crmd_lrm.h>
#include <crm/lrmd.h>
#include <crm/services.h>

#define REMOTE_LRMD_RA "remote"

int remote_ra_callid = 0;

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
    int interval;
    /*! interval timer id */
    int interval_id;
    int reported_success;
    int monitor_timeout_id;
    /*! action parameters */
    lrmd_key_value_t *params;
    /*! executed rc */
    int rc;
    int op_status;
    int call_id;
    gboolean cancel;
} remote_ra_cmd_t;

typedef struct remote_ra_data_s {
    crm_trigger_t *work;
    remote_ra_cmd_t *cur_cmd;
    GList *cmds;
    GList *recurring_cmds;

} remote_ra_data_t;

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
    free(cmd->owner);
    free(cmd->rsc_id);
    free(cmd->action);
    free(cmd->userdata);
    lrmd_key_value_freeall(cmd->params);
    free(cmd);
}

static gboolean
recurring_helper(gpointer data)
{
    remote_ra_cmd_t *cmd = data;
    lrm_state_t *connection_rsc = NULL;

    cmd->interval_id = 0;
    connection_rsc = lrm_state_find(cmd->rsc_id);
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
    connection_rsc = lrm_state_find(cmd->rsc_id);
    if (connection_rsc && connection_rsc->remote_ra_data) {
        remote_ra_data_t *ra_data = connection_rsc->remote_ra_data;
        mainloop_set_trigger(ra_data->work);
    }
    return FALSE;
}

static void
report_remote_ra_result(remote_ra_cmd_t *cmd)
{
    lrmd_event_data_t op = { 0, };

    op.type = lrmd_event_exec_complete;
    op.rsc_id = cmd->rsc_id;
    op.op_type = cmd->action;
    op.user_data = cmd->userdata;
    op.timeout = cmd->timeout;
    op.interval = cmd->interval;
    op.rc = cmd->rc;
    op.op_status = cmd->op_status;
    if (cmd->params) {
        lrmd_key_value_t *tmp;

        op.params = g_hash_table_new_full(crm_str_hash,
                        g_str_equal, g_hash_destroy_str, g_hash_destroy_str);
        for (tmp = cmd->params; tmp; tmp = tmp->next) {
            g_hash_table_insert(op.params, strdup(tmp->key), strdup(tmp->value));
        }

    }
    op.call_id = cmd->call_id;
    op.remote_nodename = cmd->owner;

    lrm_op_callback(&op);

    if (op.params) {
        g_hash_table_destroy(op.params);
    }
}

static gboolean
monitor_timeout_cb(gpointer data)
{
    lrm_state_t *lrm_state = NULL;
    remote_ra_cmd_t *cmd = data;

    crm_debug("Poke async response timed out for node %s", cmd->rsc_id);
    cmd->monitor_timeout_id = 0;
    cmd->op_status = PCMK_LRM_OP_TIMEOUT;
    cmd->rc = PCMK_EXECRA_UNKNOWN_ERROR;

    lrm_state = lrm_state_find(cmd->rsc_id);
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
    return FALSE;
}

void
remote_lrm_op_callback(lrmd_event_data_t * op)
{
    lrm_state_t *lrm_state = NULL;
    remote_ra_data_t *ra_data = NULL;
    remote_ra_cmd_t *cmd = NULL;

    crm_debug("remote connection event - event_type:%s node:%s action:%s rc:%s op_status:%s",
             lrmd_event_type2str(op->type),
             op->remote_nodename,
             op->op_type ? op->op_type : "none",
             lrmd_event_rc2str(op->rc),
             services_lrm_status_str(op->op_status));

    /* we filter connection events and map them to start events for the remote agent */
    if ((op->type != lrmd_event_connect) && (op->type != lrmd_event_poke)) {
        crm_debug("not a connection or poke event, pass it up to crmd lrm callback");
        lrm_op_callback(op);
        return;
    } else if (!op->remote_nodename) {
        crm_debug("no node name, dropping event.");
        return;
    }

    lrm_state = lrm_state_find(op->remote_nodename);
    if (!lrm_state || !lrm_state->remote_ra_data) {
        crm_debug("lrm_state info not found for remote lrmd connection event");
        lrm_op_callback(op);
        return;
    }

    ra_data = lrm_state->remote_ra_data;

    if (!ra_data->cur_cmd) {
        crm_debug("no event to match");
        lrm_op_callback(op);
        return;
    }

    cmd = ra_data->cur_cmd;

    /* Start actions and migrate from actions complete after connection
     * comes back to us. */
    if (op->type == lrmd_event_connect && (
            safe_str_eq(cmd->action, "start") ||
            safe_str_eq(cmd->action, "migrate_from"))) {

        if (op->connection_rc == -ETIMEDOUT) {
            cmd->op_status = PCMK_LRM_OP_TIMEOUT;
            cmd->rc = PCMK_EXECRA_UNKNOWN_ERROR;
        } else if (op->connection_rc < 0) {
            cmd->rc = PCMK_EXECRA_UNKNOWN_ERROR;
            cmd->op_status = PCMK_LRM_OP_ERROR;
        } else {
            cmd->rc = PCMK_EXECRA_OK;
            cmd->op_status = PCMK_LRM_OP_DONE;
        }

        crm_debug("remote lrmd connect event matched %s action. ", cmd->action);
        report_remote_ra_result(cmd);
        if (ra_data->cmds) {
            mainloop_set_trigger(ra_data->work);
        }
        ra_data->cur_cmd = NULL;
        free_cmd(cmd);
        return;
    } else if (op->type == lrmd_event_poke && safe_str_eq(cmd->action, "monitor")) {

        if (cmd->monitor_timeout_id) {
            g_source_remove(cmd->monitor_timeout_id);
            cmd->monitor_timeout_id = 0;
        }

        /* Only report success the first time, after that only worry about failures.
         * For this function, if we get the poke pack, it is always a success. Pokes
         * only fail if the send fails, or the response times out. */
        if (!cmd->reported_success) {
            cmd->rc = PCMK_EXECRA_OK;
            cmd->op_status = PCMK_LRM_OP_DONE;
            report_remote_ra_result(cmd);
            cmd->reported_success = 1;
        }

        crm_debug("remote lrmd poke event matched %s action. ", cmd->action);

        /* success, keep rescheduling if interval is present. */
        if (cmd->interval && (cmd->cancel == FALSE)) {
            ra_data->recurring_cmds = g_list_append(ra_data->recurring_cmds, cmd);
            cmd->interval_id = g_timeout_add(cmd->interval, recurring_helper, cmd);
            cmd = NULL; /* prevent free */
        }

        if (ra_data->cmds) {
            mainloop_set_trigger(ra_data->work);
        }
        ra_data->cur_cmd = NULL;
        free_cmd(cmd);
        return;
    }

    crm_debug("Event did not match %s action", ra_data->cur_cmd->action);
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
        /* still waiting on previous cmd*/
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

        if (!strcmp(cmd->action, "start") || !strcmp(cmd->action, "migrate_from")) {
            const char *server = NULL;
            lrmd_key_value_t *tmp = NULL;
            int port = 0;

            for (tmp = cmd->params; tmp; tmp = tmp->next) {
                if (safe_str_eq(tmp->key, "server")) {
                    server = tmp->value;
                }
                if (safe_str_eq(tmp->key, "port")) {
                    port = atoi(tmp->value);
                }
            }

            rc = lrm_state_remote_connect_async(lrm_state, server, port, cmd->timeout);

            if (rc == 0) {
               /* take care of this later when we get async connection result */
                crm_debug("began remote lrmd connect, waiting for connect event.");
                ra_data->cur_cmd = cmd;
                return TRUE;
            } else {
                crm_debug("connect failed, not expecting to match any connection event later");
                cmd->rc = PCMK_EXECRA_UNKNOWN_ERROR;
                cmd->op_status = PCMK_LRM_OP_ERROR;
            }
            report_remote_ra_result(cmd);

        } else if (!strcmp(cmd->action, "monitor")) {

            if (lrm_state_is_connected(lrm_state) == TRUE) {
                rc = lrm_state_poke_connection(lrm_state);
                if (rc < 0) {
                    cmd->rc = PCMK_EXECRA_UNKNOWN_ERROR;
                    cmd->op_status = PCMK_LRM_OP_ERROR;
                }
            } else {
                rc = -1;
                cmd->op_status = PCMK_LRM_OP_DONE;
                cmd->rc = PCMK_EXECRA_NOT_RUNNING;
            }

            if (rc == 0) {
                crm_debug("poked remote lrmd at node %s, waiting for async response.", cmd->rsc_id);
                ra_data->cur_cmd = cmd;
                cmd->monitor_timeout_id = g_timeout_add(cmd->timeout, monitor_timeout_cb, cmd);
                return TRUE;
            }
            report_remote_ra_result(cmd);

        } else if (!strcmp(cmd->action, "stop")) {
            lrm_state_disconnect(lrm_state);
            cmd->rc = PCMK_EXECRA_OK;
            cmd->op_status = PCMK_LRM_OP_DONE;
            report_remote_ra_result(cmd);

        } else if (!strcmp(cmd->action, "migrate_to")) {
            /* no-op. */
            cmd->rc = PCMK_EXECRA_OK;
            cmd->op_status = PCMK_LRM_OP_DONE;
            report_remote_ra_result(cmd);
        }

        free_cmd(cmd);
    }

    return TRUE;
}

static void
remote_ra_data_init(lrm_state_t *lrm_state)
{
    remote_ra_data_t *ra_data = NULL;

    if (lrm_state->remote_ra_data) {
        return;
    }

    ra_data = calloc(1, sizeof(remote_ra_data_t));
    ra_data->work = mainloop_add_trigger(G_PRIORITY_HIGH, handle_remote_ra_exec, lrm_state);
    lrm_state->remote_ra_data = ra_data;
}

void
remote_ra_cleanup(lrm_state_t *lrm_state)
{
    remote_ra_data_t *ra_data = lrm_state->remote_ra_data;

    if (!ra_data) {
        return;
    }

    if (ra_data->cmds) {
        g_list_free_full(ra_data->cmds, free_cmd);
    }

    if (ra_data->cmds) {
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
    if (id && lrm_state_find(id)) {
        return TRUE;
    }

    return FALSE;
}

lrmd_rsc_info_t *
remote_ra_get_rsc_info(lrm_state_t *lrm_state, const char *rsc_id)
{
    lrmd_rsc_info_t *info = NULL;
    if ((lrm_state_find(rsc_id))) {
        info = calloc(1, sizeof(lrmd_rsc_info_t));

        info->id = strdup(rsc_id);
        info->type = strdup(REMOTE_LRMD_RA);
        info->class = strdup("ocf");
        info->provider = strdup("pacemaker");
    }

    return info;
}

static gboolean
is_remote_ra_supported_action(const char *action)
{
    if (!action) {
        return FALSE;
    } else if (strcmp(action,"start") &&
               strcmp(action,"stop") &&
               strcmp(action,"migrate_to") &&
               strcmp(action,"migrate_from") &&
               strcmp(action,"monitor")) {
        return FALSE;
    }

    return TRUE;
}

static GList *
remove_cmd(GList *list, const char *action, int interval)
{
    remote_ra_cmd_t *cmd = NULL;
    GListPtr gIter = NULL;
    for (gIter = list; gIter != NULL; gIter = gIter->next) {
        cmd = gIter->data;
        if (cmd->interval == interval && safe_str_eq(cmd->action, action)) {
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

int remote_ra_cancel(lrm_state_t *lrm_state, const char *rsc_id, const char *action, int interval)
{
    lrm_state_t *connection_rsc = NULL;
    remote_ra_data_t *ra_data = NULL;

    connection_rsc = lrm_state_find(rsc_id);
    if (!connection_rsc || !connection_rsc->remote_ra_data) {
        return -EINVAL;
    }

    ra_data = connection_rsc->remote_ra_data;
    ra_data->cmds = remove_cmd(ra_data->cmds, action, interval);
    ra_data->recurring_cmds = remove_cmd(ra_data->cmds, action, interval);
    if (ra_data->cur_cmd &&
        (ra_data->cur_cmd->interval == interval) &&
        (safe_str_eq(ra_data->cur_cmd->action, action))) {

        ra_data->cur_cmd->cancel = TRUE;
    }

    return 0;
}

int remote_ra_exec(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *action,
    const char *userdata,
    int interval, /* ms */
    int timeout, /* ms */
    int start_delay, /* ms */
    lrmd_key_value_t *params)
{
    int rc = 0;
    lrm_state_t *connection_rsc = NULL;
    remote_ra_cmd_t *cmd = NULL;
    remote_ra_data_t *ra_data = NULL;

    if (is_remote_ra_supported_action(action) == FALSE) {
        rc = -EINVAL;
        goto exec_done;
    }

    connection_rsc = lrm_state_find(rsc_id);
    if (!connection_rsc) {
        rc = -EINVAL;
        goto exec_done;
    }

    remote_ra_data_init(connection_rsc);

    cmd = calloc(1, sizeof(remote_ra_cmd_t));
    cmd->owner = strdup(lrm_state->node_name);
    cmd->rsc_id = strdup(rsc_id);
    cmd->action = strdup(action);
    cmd->userdata = strdup(userdata);
    cmd->interval = interval;
    cmd->timeout = timeout;
    cmd->start_delay = start_delay;
    cmd->params = params;

    remote_ra_callid++;
    if (remote_ra_callid <=0) {
        remote_ra_callid = 1;
    }
    cmd->call_id = remote_ra_callid;

    if (cmd->start_delay) {
        cmd->delay_id = g_timeout_add(cmd->start_delay, start_delay_helper, cmd);
    }
    ra_data = connection_rsc->remote_ra_data;

    ra_data->cmds = g_list_append(ra_data->cmds, cmd);
    mainloop_set_trigger(ra_data->work);

    return cmd->call_id;
exec_done:

    lrmd_key_value_freeall(params);
    return rc;
}

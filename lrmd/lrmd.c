/*
 * Copyright (c) 2012 David Vossel <dvossel@redhat.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <crm_internal.h>

#include <glib.h>
#include <unistd.h>

#include <crm/crm.h>
#include <crm/services.h>
#include <crm/common/mainloop.h>
#include <crm/common/ipc.h>
#include <crm/msg_xml.h>

#include <lrmd_private.h>

#ifdef HAVE_SYS_TIMEB_H
#  include <sys/timeb.h>
#endif

GHashTable *rsc_list = NULL;
GHashTable *client_list = NULL;

typedef struct lrmd_cmd_s {
    int timeout;
    int interval;
    int start_delay;

    int call_id;
    int exec_rc;
    int lrmd_op_status;

    /* Timer ids, must be removed on cmd destruction. */
    int delay_id;
    int stonith_recurring_id;

    int rsc_deleted;

    char *only_notify_client;
    char *origin;
    char *rsc_id;
    char *action;
    char *output;
    char *userdata_str;

#ifdef HAVE_SYS_TIMEB_H
    /* Timestamp of when op ran */
    struct timeb t_run;
    /* Timestamp of when op was queued */
    struct timeb t_queue;
    /* Timestamp of last rc change */
    struct timeb t_rcchange;
#endif

    GHashTable *params;
} lrmd_cmd_t;

static void cmd_finalize(lrmd_cmd_t * cmd, lrmd_rsc_t * rsc);
static gboolean lrmd_rsc_dispatch(gpointer user_data);

static lrmd_rsc_t *
build_rsc_from_xml(xmlNode * msg)
{
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, msg, LOG_ERR);
    lrmd_rsc_t *rsc = NULL;

    rsc = calloc(1, sizeof(lrmd_rsc_t));
    rsc->rsc_id = crm_element_value_copy(rsc_xml, F_LRMD_RSC_ID);
    rsc->class = crm_element_value_copy(rsc_xml, F_LRMD_CLASS);
    rsc->provider = crm_element_value_copy(rsc_xml, F_LRMD_PROVIDER);
    rsc->type = crm_element_value_copy(rsc_xml, F_LRMD_TYPE);
    rsc->work = mainloop_add_trigger(G_PRIORITY_HIGH, lrmd_rsc_dispatch, rsc);
    return rsc;
}

static lrmd_cmd_t *
create_lrmd_cmd(xmlNode * msg, lrmd_client_t * client)
{
    int call_options = 0;
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, msg, LOG_ERR);
    lrmd_cmd_t *cmd = NULL;

    cmd = calloc(1, sizeof(lrmd_cmd_t));

    crm_element_value_int(msg, F_LRMD_CALLOPTS, &call_options);

    if (call_options & lrmd_opt_notify_orig_only) {
        cmd->only_notify_client = strdup(client->id);
    }

    crm_element_value_int(msg, F_LRMD_CALLID, &cmd->call_id);
    crm_element_value_int(rsc_xml, F_LRMD_RSC_INTERVAL, &cmd->interval);
    crm_element_value_int(rsc_xml, F_LRMD_TIMEOUT, &cmd->timeout);
    crm_element_value_int(rsc_xml, F_LRMD_RSC_START_DELAY, &cmd->start_delay);

    cmd->origin = crm_element_value_copy(rsc_xml, F_LRMD_ORIGIN);
    cmd->action = crm_element_value_copy(rsc_xml, F_LRMD_RSC_ACTION);
    cmd->userdata_str = crm_element_value_copy(rsc_xml, F_LRMD_RSC_USERDATA_STR);
    cmd->rsc_id = crm_element_value_copy(rsc_xml, F_LRMD_RSC_ID);

    cmd->params = xml2list(rsc_xml);

    return cmd;
}

static void
free_lrmd_cmd(lrmd_cmd_t * cmd)
{
    if (cmd->stonith_recurring_id) {
        g_source_remove(cmd->stonith_recurring_id);
    }
    if (cmd->delay_id) {
        g_source_remove(cmd->delay_id);
    }
    if (cmd->params) {
        g_hash_table_destroy(cmd->params);
    }
    free(cmd->origin);
    free(cmd->action);
    free(cmd->userdata_str);
    free(cmd->rsc_id);
    free(cmd->output);
    free(cmd->only_notify_client);
    free(cmd);
}

static gboolean
stonith_recurring_op_helper(gpointer data)
{
    lrmd_cmd_t *cmd = data;
    lrmd_rsc_t *rsc;

    cmd->stonith_recurring_id = 0;

    if (!cmd->rsc_id) {
        return FALSE;
    }

    rsc = g_hash_table_lookup(rsc_list, cmd->rsc_id);

    CRM_ASSERT(rsc != NULL);
    /* take it out of recurring_ops list, and put it in the pending ops
     * to be executed */
    rsc->recurring_ops = g_list_remove(rsc->recurring_ops, cmd);
    rsc->pending_ops = g_list_append(rsc->pending_ops, cmd);
#ifdef HAVE_SYS_TIMEB_H
    ftime(&cmd->t_queue);
#endif
    mainloop_set_trigger(rsc->work);

    return FALSE;
}

static gboolean
start_delay_helper(gpointer data)
{
    lrmd_cmd_t *cmd = data;
    lrmd_rsc_t *rsc = NULL;

    cmd->delay_id = 0;
    rsc = cmd->rsc_id ? g_hash_table_lookup(rsc_list, cmd->rsc_id) : NULL;

    if (rsc) {
        mainloop_set_trigger(rsc->work);
    }

    return FALSE;
}

static void
schedule_lrmd_cmd(lrmd_rsc_t * rsc, lrmd_cmd_t * cmd)
{
    CRM_CHECK(cmd != NULL, return);
    CRM_CHECK(rsc != NULL, return);

    crm_trace("Scheduling %s on %s", cmd->action, rsc->rsc_id);
    rsc->pending_ops = g_list_append(rsc->pending_ops, cmd);
#ifdef HAVE_SYS_TIMEB_H
    ftime(&cmd->t_queue);
#endif
    mainloop_set_trigger(rsc->work);

    if (cmd->start_delay) {
        cmd->delay_id = g_timeout_add(cmd->start_delay, start_delay_helper, cmd);
    }

}

static void
send_reply(lrmd_client_t * client, int rc, uint32_t id, int call_id)
{
    int send_rc = 0;
    xmlNode *reply = NULL;

    reply = create_xml_node(NULL, T_LRMD_REPLY);
    crm_xml_add(reply, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add_int(reply, F_LRMD_RC, rc);
    crm_xml_add_int(reply, F_LRMD_CALLID, call_id);

    send_rc = crm_ipcs_send(client->channel, id, reply, FALSE);

    free_xml(reply);
    if (send_rc < 0) {
        crm_warn("LRMD reply to %s failed: %d", client->name, send_rc);
    }
}

static void
send_client_notify(gpointer key, gpointer value, gpointer user_data)
{
    xmlNode *update_msg = user_data;
    lrmd_client_t *client = value;

    if (client == NULL) {
        crm_err("Asked to send event to  NULL client");
        return;
    } else if (client->channel == NULL) {
        crm_trace("Asked to send event to disconnected client");
        return;
    } else if (client->name == NULL) {
        crm_trace("Asked to send event to client with no name");
        return;
    }

    if (crm_ipcs_send(client->channel, 0, update_msg, TRUE) <= 0) {
        crm_warn("Notification of client %s/%s failed", client->name, client->id);
    }
}

#ifdef HAVE_SYS_TIMEB_H
static int
time_diff_ms(struct timeb *now, struct timeb *old)
{
    int sec = difftime(now->time, old->time);
    int ms = now->millitm - old->millitm;

    if (old->time == 0) {
        return 0;
    }

    return (sec * 1000) + ms;
}
#endif

static void
send_cmd_complete_notify(lrmd_cmd_t * cmd)
{
#ifdef HAVE_SYS_TIMEB_H
    struct timeb now = { 0, };
#endif
    xmlNode *notify = NULL;

    notify = create_xml_node(NULL, T_LRMD_NOTIFY);

    crm_xml_add(notify, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add_int(notify, F_LRMD_TIMEOUT, cmd->timeout);
    crm_xml_add_int(notify, F_LRMD_RSC_INTERVAL, cmd->interval);
    crm_xml_add_int(notify, F_LRMD_RSC_START_DELAY, cmd->start_delay);
    crm_xml_add_int(notify, F_LRMD_EXEC_RC, cmd->exec_rc);
    crm_xml_add_int(notify, F_LRMD_OP_STATUS, cmd->lrmd_op_status);
    crm_xml_add_int(notify, F_LRMD_CALLID, cmd->call_id);
    crm_xml_add_int(notify, F_LRMD_RSC_DELETED, cmd->rsc_deleted);

#ifdef HAVE_SYS_TIMEB_H
    ftime(&now);
    crm_xml_add_int(notify, F_LRMD_RSC_RUN_TIME, cmd->t_run.time);
    crm_xml_add_int(notify, F_LRMD_RSC_RCCHANGE_TIME, cmd->t_rcchange.time);
    crm_xml_add_int(notify, F_LRMD_RSC_EXEC_TIME, time_diff_ms(&now, &cmd->t_run));
    crm_xml_add_int(notify, F_LRMD_RSC_QUEUE_TIME, time_diff_ms(&cmd->t_run, &cmd->t_queue));
#endif

    crm_xml_add(notify, F_LRMD_OPERATION, LRMD_OP_RSC_EXEC);
    crm_xml_add(notify, F_LRMD_RSC_ID, cmd->rsc_id);
    crm_xml_add(notify, F_LRMD_RSC_ACTION, cmd->action);
    crm_xml_add(notify, F_LRMD_RSC_USERDATA_STR, cmd->userdata_str);
    crm_xml_add(notify, F_LRMD_RSC_OUTPUT, cmd->output);

    if (cmd->params) {
        char *key = NULL;
        char *value = NULL;
        GHashTableIter iter;

        xmlNode *args = create_xml_node(notify, XML_TAG_ATTRS);

        g_hash_table_iter_init(&iter, cmd->params);
        while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
            hash2field((gpointer) key, (gpointer) value, args);
        }
    }

    if (cmd->only_notify_client) {
        lrmd_client_t *client = g_hash_table_lookup(client_list, cmd->only_notify_client);

        if (client) {
            send_client_notify(client->id, client, notify);
        }
    } else {
        g_hash_table_foreach(client_list, send_client_notify, notify);
    }

    free_xml(notify);
}

static void
send_generic_notify(int rc, xmlNode * request)
{
    int call_id = 0;
    xmlNode *notify = NULL;
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, request, LOG_ERR);
    const char *rsc_id = crm_element_value(rsc_xml, F_LRMD_RSC_ID);
    const char *op = crm_element_value(request, F_LRMD_OPERATION);

    crm_element_value_int(request, F_LRMD_CALLID, &call_id);

    notify = create_xml_node(NULL, T_LRMD_NOTIFY);
    crm_xml_add(notify, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add_int(notify, F_LRMD_RC, rc);
    crm_xml_add_int(notify, F_LRMD_CALLID, call_id);
    crm_xml_add(notify, F_LRMD_OPERATION, op);
    crm_xml_add(notify, F_LRMD_RSC_ID, rsc_id);

    g_hash_table_foreach(client_list, send_client_notify, notify);

    free_xml(notify);
}

static void
cmd_finalize(lrmd_cmd_t * cmd, lrmd_rsc_t * rsc)
{
    crm_trace("Resource operation rsc:%s action:%s completed (%p %p)", cmd->rsc_id, cmd->action, rsc?rsc->active:NULL, cmd);

    if (rsc && (rsc->active == cmd)) {
        rsc->active = NULL;
        mainloop_set_trigger(rsc->work);
    }

    if (!rsc) {
        cmd->rsc_deleted = 1;
    }

    send_cmd_complete_notify(cmd);

    if (cmd->interval && (cmd->lrmd_op_status == PCMK_LRM_OP_CANCELLED)) {
        if (rsc) {
            rsc->recurring_ops = g_list_remove(rsc->recurring_ops, cmd);
            rsc->pending_ops = g_list_remove(rsc->pending_ops, cmd);
        }
        free_lrmd_cmd(cmd);
    } else if (cmd->interval == 0) {
        if (rsc) {
            rsc->pending_ops = g_list_remove(rsc->pending_ops, cmd);
        }
        free_lrmd_cmd(cmd);
    } else {
        /* Clear all the values pertaining just to the last iteration of a recurring op. */
        cmd->lrmd_op_status = 0;
        memset(&cmd->t_run, 0, sizeof(cmd->t_run));
        memset(&cmd->t_queue, 0, sizeof(cmd->t_queue));
        free(cmd->output);
        cmd->output = NULL;
    }
}

static int
lsb2uniform_rc(const char *action, int rc)
{
    if (rc < 0) {
        return PCMK_EXECRA_UNKNOWN_ERROR;
    }

    /* status has different return codes that everything else. */
    if (!safe_str_eq(action, "status") && !safe_str_eq(action, "monitor")) {
        if (rc > PCMK_LSB_NOT_RUNNING) {
            return PCMK_EXECRA_UNKNOWN_ERROR;
        }
        return rc;
    }

    switch (rc) {
        case PCMK_LSB_STATUS_OK:
            return PCMK_EXECRA_OK;
        case PCMK_LSB_STATUS_NOT_INSTALLED:
            return PCMK_EXECRA_NOT_INSTALLED;
        case PCMK_LSB_STATUS_VAR_PID:
        case PCMK_LSB_STATUS_VAR_LOCK:
        case PCMK_LSB_STATUS_NOT_RUNNING:
            return PCMK_EXECRA_NOT_RUNNING;
        default:
            return PCMK_EXECRA_UNKNOWN_ERROR;
    }

    return PCMK_EXECRA_UNKNOWN_ERROR;
}

static int
ocf2uniform_rc(int rc)
{
    if (rc < 0 || rc > PCMK_OCF_FAILED_MASTER) {
        return PCMK_EXECRA_UNKNOWN_ERROR;
    }

    return rc;
}

static int
stonith2uniform_rc(const char *action, int rc)
{
    if (rc == -ENODEV) {
        if (safe_str_eq(action, "stop")) {
            rc = PCMK_EXECRA_OK;
        } else if (safe_str_eq(action, "start")) {
            rc = PCMK_EXECRA_NOT_INSTALLED;
        } else {
            rc = PCMK_EXECRA_NOT_RUNNING;
        }
    } else if (rc != 0) {
        rc = PCMK_EXECRA_UNKNOWN_ERROR;
    }
    return rc;
}

static int
get_uniform_rc(const char *standard, const char *action, int rc)
{
    if (safe_str_eq(standard, "ocf")) {
        return ocf2uniform_rc(rc);
    } else if (safe_str_eq(standard, "stonith")) {
        return stonith2uniform_rc(action, rc);
    } else if (safe_str_eq(standard, "systemd")) {
        return rc;
    } else if (safe_str_eq(standard, "upstart")) {
        return rc;
    } else {
        return lsb2uniform_rc(action, rc);
    }
}

static void
action_complete(svc_action_t * action)
{
    lrmd_rsc_t *rsc;
    lrmd_cmd_t *cmd = action->cb_data;

    if (!cmd) {
        crm_err("LRMD action (%s) completed does not match any known operations.", action->id);
        return;
    }
#ifdef HAVE_SYS_TIMEB_H
    if (cmd->exec_rc != action->rc) {
        ftime(&cmd->t_rcchange);
    }
#endif

    cmd->exec_rc = get_uniform_rc(action->standard, cmd->action, action->rc);
    cmd->lrmd_op_status = action->status;
    rsc = cmd->rsc_id ? g_hash_table_lookup(rsc_list, cmd->rsc_id) : NULL;

    if (action->stdout_data) {
        cmd->output = strdup(action->stdout_data);
    }

    cmd_finalize(cmd, rsc);
}


static void
stonith_action_complete(lrmd_cmd_t *cmd, int rc)
{
    lrmd_rsc_t *rsc = NULL;

    cmd->exec_rc = get_uniform_rc("stonith", cmd->action, rc);

    /* Attempt to map return codes to op status if possible */
    if (rc) {
        switch (rc) {
            case -EPROTONOSUPPORT:
                cmd->lrmd_op_status = PCMK_LRM_OP_NOTSUPPORTED;
                break;
            case -ETIME:
                cmd->lrmd_op_status = PCMK_LRM_OP_TIMEOUT;
                break;
            default:
                cmd->lrmd_op_status = PCMK_LRM_OP_ERROR;
        }
    } else {
        cmd->lrmd_op_status = PCMK_LRM_OP_DONE;
    }

    rsc = g_hash_table_lookup(rsc_list, cmd->rsc_id);
    if ((cmd->interval > 0) && rsc) {
        rsc->recurring_ops = g_list_append(rsc->recurring_ops, cmd);
        cmd->stonith_recurring_id = g_timeout_add(cmd->interval, stonith_recurring_op_helper, cmd);
    }

    cmd_finalize(cmd, rsc);
}

static void
lrmd_stonith_callback(stonith_t * stonith,
        const xmlNode * msg,
        int call_id,
        int rc,
        xmlNode * output,
        void *userdata)
{
    stonith_action_complete(userdata, rc);
}

static int
lrmd_rsc_execute_stonith(lrmd_rsc_t * rsc, lrmd_cmd_t * cmd)
{
    int rc = 0;
    int do_monitor = 0;

    stonith_t *stonith_api = get_stonith_connection();

    if (!stonith_api) {
        cmd->exec_rc = get_uniform_rc("stonith", cmd->action, -ENOTCONN);
        cmd->lrmd_op_status = PCMK_LRM_OP_ERROR;
        cmd_finalize(cmd, rsc);
        return -EUNATCH;
    }

    if (safe_str_eq(cmd->action, "start")) {
        char *key = NULL;
        char *value = NULL;
        stonith_key_value_t *device_params = NULL;

        if (cmd->params) {
            GHashTableIter iter;

            g_hash_table_iter_init(&iter, cmd->params);
            while (g_hash_table_iter_next(&iter, (gpointer *) & key, (gpointer *) & value)) {
                device_params = stonith_key_value_add(device_params, key, value);
            }
        }

        rc = stonith_api->cmds->register_device(stonith_api,
                                                st_opt_sync_call,
                                                cmd->rsc_id,
                                                rsc->provider, rsc->type, device_params);

        stonith_key_value_freeall(device_params, 1, 1);
        if (rc == 0) {
            do_monitor = 1;
        }
    } else if (safe_str_eq(cmd->action, "stop")) {
        rc = stonith_api->cmds->remove_device(stonith_api, st_opt_sync_call, cmd->rsc_id);
    } else if (safe_str_eq(cmd->action, "monitor")) {
        do_monitor = 1;
    }

    if (!do_monitor) {
        goto cleanup_stonith_exec;
    }

    rc = stonith_api->cmds->monitor(stonith_api,
               0, cmd->rsc_id, cmd->timeout);

    rc = stonith_api->cmds->register_callback(
                stonith_api,
                rc,
                cmd->timeout,
                FALSE,
                cmd,
                "lrmd_stonith_callback",
                lrmd_stonith_callback);

    /* don't cleanup yet, we will find out the result of the monitor later */
    if (rc > 0) {
        rsc->active = cmd;
        return rc;
    } else if (rc == 0) {
		rc = -1;
	}

cleanup_stonith_exec:
    stonith_action_complete(cmd, rc);
    return rc;
}

static const char *
normalize_action_name(lrmd_rsc_t * rsc, const char *action)
{
    if (safe_str_eq(action, "monitor") &&
        (safe_str_eq(rsc->class, "lsb") ||
         safe_str_eq(rsc->class, "service") || safe_str_eq(rsc->class, "systemd"))) {
        return "status";
    }
    return action;
}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    g_hash_table_replace(user_data, strdup(key), strdup(value));
}

static int
lrmd_rsc_execute_service_lib(lrmd_rsc_t * rsc, lrmd_cmd_t * cmd)
{
    svc_action_t *action = NULL;
    GHashTable *params_copy = NULL;

    crm_trace("Creating action, resource:%s action:%s class:%s provider:%s agent:%s",
              rsc->rsc_id, cmd->action, rsc->class, rsc->provider, rsc->type);

    if (cmd->params) {
        params_copy = g_hash_table_new_full(crm_str_hash,
                                            g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

        if (params_copy != NULL) {
            g_hash_table_foreach(cmd->params, dup_attr, params_copy);
        }
    }

    action = resources_action_create(rsc->rsc_id,
                                     rsc->class,
                                     rsc->provider,
                                     rsc->type,
                                     normalize_action_name(rsc, cmd->action),
                                     cmd->interval, cmd->timeout, params_copy);

    if (!action) {
        crm_err("Failed to create action, action:%s on resource %s", cmd->action, rsc->rsc_id);
        cmd->lrmd_op_status = PCMK_LRM_OP_ERROR;
        goto exec_done;
    }

    action->cb_data = cmd;
    /* The cmd will be finalized by the action_complete callback after
     * the service library is done with it */
    rsc->active = cmd;          /* only one op at a time for a rsc */
    if (cmd->interval) {
        rsc->recurring_ops = g_list_append(rsc->recurring_ops, cmd);
    }

    /* 'cmd' may not be valid after this point
     *
     * Upstart and systemd both synchronously determine monitor/status
     * results and call action_complete (which may free 'cmd') if necessary
     */
    if (services_action_async(action, action_complete)) {
        return TRUE;
    }

    cmd->exec_rc = action->rc;
    cmd->lrmd_op_status = PCMK_LRM_OP_ERROR;
    services_action_free(action);
    action = NULL;

  exec_done:
    if (cmd) {
        cmd_finalize(cmd, rsc);
    }
    return TRUE;
}

static gboolean
lrmd_rsc_execute(lrmd_rsc_t * rsc)
{
    lrmd_cmd_t *cmd = NULL;

    CRM_CHECK(rsc != NULL, return FALSE);

    if (rsc->active) {
        crm_trace("%s is still active", rsc->rsc_id);
        return TRUE;
    }

    if (rsc->pending_ops) {
        GList *first = rsc->pending_ops;

        cmd = first->data;
        if (cmd->delay_id) {
            crm_trace
                ("Command %s %s was asked to run too early, waiting for start_delay timeout of %dms",
                 cmd->rsc_id, cmd->action, cmd->start_delay);
            return TRUE;
        }
        rsc->pending_ops = g_list_remove_link(rsc->pending_ops, first);
        g_list_free_1(first);

#ifdef HAVE_SYS_TIMEB_H
        ftime(&cmd->t_run);
    }
#endif

    if (!cmd) {
        crm_trace("Nothing further to do for %s", rsc->rsc_id);
        return TRUE;
    }

    if (safe_str_eq(rsc->class, "stonith")) {
        lrmd_rsc_execute_stonith(rsc, cmd);
    } else {
        lrmd_rsc_execute_service_lib(rsc, cmd);
    }

    return TRUE;
}

static gboolean
lrmd_rsc_dispatch(gpointer user_data)
{
    return lrmd_rsc_execute(user_data);
}

void
free_rsc(gpointer data)
{
    GListPtr gIter = NULL;
    lrmd_rsc_t *rsc = data;
    int is_stonith = safe_str_eq(rsc->class, "stonith");

    for (gIter = rsc->pending_ops; gIter != NULL; gIter = gIter->next) {
        lrmd_cmd_t *cmd = gIter->data;

        /* command was never executed */
        cmd->lrmd_op_status = PCMK_LRM_OP_CANCELLED;
        cmd_finalize(cmd, NULL);
    }
    /* frees list, but not list elements. */
    g_list_free(rsc->pending_ops);

    for (gIter = rsc->recurring_ops; gIter != NULL; gIter = gIter->next) {
        lrmd_cmd_t *cmd = gIter->data;

        if (is_stonith) {
            cmd->lrmd_op_status = PCMK_LRM_OP_CANCELLED;
            cmd_finalize(cmd, NULL);
        } else {
            /* This command is already handed off to service library,
             * let service library cancel it and tell us via the callback
             * when it is cancelled. The rsc can be safely destroyed
             * even if we are waiting for the cancel result */
            services_action_cancel(rsc->rsc_id, cmd->action, cmd->interval);
        }
    }
    /* frees list, but not list elements. */
    g_list_free(rsc->recurring_ops);

    free(rsc->rsc_id);
    free(rsc->class);
    free(rsc->provider);
    free(rsc->type);
    mainloop_destroy_trigger(rsc->work);

    free(rsc);
}

static int
process_lrmd_signon(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    xmlNode *reply = create_xml_node(NULL, "reply");

    crm_xml_add(reply, F_LRMD_OPERATION, CRM_OP_REGISTER);
    crm_xml_add(reply, F_LRMD_CLIENTID, client->id);
    crm_ipcs_send(client->channel, id, reply, FALSE);

    free_xml(reply);
    return pcmk_ok;
}

static int
process_lrmd_rsc_register(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    int rc = pcmk_ok;
    lrmd_rsc_t *rsc = build_rsc_from_xml(request);
    lrmd_rsc_t *dup = g_hash_table_lookup(rsc_list, rsc->rsc_id);

    if (dup &&
        safe_str_eq(rsc->class, dup->class) &&
        safe_str_eq(rsc->provider, dup->provider) && safe_str_eq(rsc->type, dup->type)) {

        crm_warn("Can't add, RSC '%s' already present in the rsc list (%d active resources)",
                 rsc->rsc_id, g_hash_table_size(rsc_list));

        free_rsc(rsc);
        return rc;
    }

    g_hash_table_replace(rsc_list, rsc->rsc_id, rsc);
    crm_info("Added '%s' to the rsc list (%d active resources)",
             rsc->rsc_id, g_hash_table_size(rsc_list));

    return rc;
}

static void
process_lrmd_get_rsc_info(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    int rc = pcmk_ok;
    int send_rc = 0;
    int call_id = 0;
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, request, LOG_ERR);
    const char *rsc_id = crm_element_value(rsc_xml, F_LRMD_RSC_ID);
    xmlNode *reply = NULL;
    lrmd_rsc_t *rsc = NULL;

    crm_element_value_int(request, F_LRMD_CALLID, &call_id);

    if (!rsc_id) {
        rc = -ENODEV;
        goto get_rsc_done;
    }

    if (!(rsc = g_hash_table_lookup(rsc_list, rsc_id))) {
        crm_info("Resource '%s' not found (%d active resources)",
                 rsc_id, g_hash_table_size(rsc_list));
        rc = -ENODEV;
        goto get_rsc_done;
    }

  get_rsc_done:

    reply = create_xml_node(NULL, T_LRMD_REPLY);
    crm_xml_add(reply, F_LRMD_ORIGIN, __FUNCTION__);
    crm_xml_add_int(reply, F_LRMD_RC, rc);
    crm_xml_add_int(reply, F_LRMD_CALLID, call_id);

    if (rsc) {
        crm_xml_add(reply, F_LRMD_RSC_ID, rsc->rsc_id);
        crm_xml_add(reply, F_LRMD_CLASS, rsc->class);
        crm_xml_add(reply, F_LRMD_PROVIDER, rsc->provider);
        crm_xml_add(reply, F_LRMD_TYPE, rsc->type);
    }

    send_rc = crm_ipcs_send(client->channel, id, reply, FALSE);

    if (send_rc < 0) {
        crm_warn("LRMD reply to %s failed: %d", client->name, send_rc);
    }

    free_xml(reply);
}

static int
process_lrmd_rsc_unregister(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    int rc = pcmk_ok;
    lrmd_rsc_t *rsc = NULL;
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, request, LOG_ERR);
    const char *rsc_id = crm_element_value(rsc_xml, F_LRMD_RSC_ID);

    if (!rsc_id) {
        return -ENODEV;
    }

    if (!(rsc = g_hash_table_lookup(rsc_list, rsc_id))) {
        crm_info("Resource '%s' not found (%d active resources)",
                 rsc_id, g_hash_table_size(rsc_list));
        return pcmk_ok;
    }

    if (rsc->active) {
        /* let the caller know there are still active ops on this rsc to watch for */
        crm_trace("Operation still in progress: %p", rsc->active);
        rc = -EINPROGRESS;
    }

    g_hash_table_remove(rsc_list, rsc_id);

    return rc;
}

static int
process_lrmd_rsc_exec(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    lrmd_rsc_t *rsc = NULL;
    lrmd_cmd_t *cmd = NULL;
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, request, LOG_ERR);
    const char *rsc_id = crm_element_value(rsc_xml, F_LRMD_RSC_ID);

    if (!rsc_id) {
        return -EINVAL;
    }
    if (!(rsc = g_hash_table_lookup(rsc_list, rsc_id))) {
        crm_info("Resource '%s' not found (%d active resources)",
                 rsc_id, g_hash_table_size(rsc_list));
        return -ENODEV;
    }

    cmd = create_lrmd_cmd(request, client);
    schedule_lrmd_cmd(rsc, cmd);

    return cmd->call_id;
}

static int
cancel_op(const char *rsc_id, const char *action, int interval)
{
    GListPtr gIter = NULL;
    lrmd_rsc_t *rsc = g_hash_table_lookup(rsc_list, rsc_id);

    /* How to cancel an action.
     * 1. Check pending ops list, if it hasn't been handed off
     *    to the service library or stonith recurring list remove
     *    it there and that will stop it.
     * 2. If it isn't in the pending ops list, then its either a
     *    recurring op in the stonith recurring list, or the service
     *    library's recurring list.  Stop it there
     * 3. If not found in any lists, then this operation has either
     *    been executed already and is not a recurring operation, or
     *    never existed.
     */
    if (!rsc) {
        return -ENODEV;
    }

    for (gIter = rsc->pending_ops; gIter != NULL; gIter = gIter->next) {
        lrmd_cmd_t *cmd = gIter->data;

        if (safe_str_eq(cmd->action, action) && cmd->interval == interval) {
            cmd->lrmd_op_status = PCMK_LRM_OP_CANCELLED;
            cmd_finalize(cmd, rsc);
            return pcmk_ok;
        }
    }

    if (safe_str_eq(rsc->class, "stonith")) {
        /* The service library does not handle stonith operations.
         * We have to handle recurring stonith opereations ourselves. */
        for (gIter = rsc->recurring_ops; gIter != NULL; gIter = gIter->next) {
            lrmd_cmd_t *cmd = gIter->data;

            if (safe_str_eq(cmd->action, action) && cmd->interval == interval) {
                cmd->lrmd_op_status = PCMK_LRM_OP_CANCELLED;
                cmd_finalize(cmd, rsc);
                return pcmk_ok;
            }
        }
    } else if (services_action_cancel(rsc_id, normalize_action_name(rsc, action), interval) == TRUE) {
        /* The service library will tell the action_complete callback function
         * this action was cancelled, which will destroy the cmd and remove
         * it from the recurring_op list. Do not do that in this function
         * if the service library says it cancelled it. */
        return pcmk_ok;
    }

    return -EOPNOTSUPP;
}

static int
process_lrmd_rsc_cancel(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    xmlNode *rsc_xml = get_xpath_object("//" F_LRMD_RSC, request, LOG_ERR);
    const char *rsc_id = crm_element_value(rsc_xml, F_LRMD_RSC_ID);
    const char *action = crm_element_value(rsc_xml, F_LRMD_RSC_ACTION);
    int interval = 0;

    crm_element_value_int(rsc_xml, F_LRMD_RSC_INTERVAL, &interval);

    if (!rsc_id || !action) {
        return -EINVAL;
    }

    return cancel_op(rsc_id, action, interval);
}

void
process_lrmd_message(lrmd_client_t * client, uint32_t id, xmlNode * request)
{
    int rc = pcmk_ok;
    int call_id = 0;
    const char *op = crm_element_value(request, F_LRMD_OPERATION);
    int do_reply = 0;
    int do_notify = 0;
    int exit = 0;

    crm_trace("Processing %s operation from %s", op, client->id);
    crm_element_value_int(request, F_LRMD_CALLID, &call_id);

    if (crm_str_eq(op, CRM_OP_REGISTER, TRUE)) {
        rc = process_lrmd_signon(client, id, request);
    } else if (crm_str_eq(op, LRMD_OP_RSC_REG, TRUE)) {
        rc = process_lrmd_rsc_register(client, id, request);
        do_notify = 1;
        do_reply = 1;
    } else if (crm_str_eq(op, LRMD_OP_RSC_INFO, TRUE)) {
        process_lrmd_get_rsc_info(client, id, request);
    } else if (crm_str_eq(op, LRMD_OP_RSC_UNREG, TRUE)) {
        rc = process_lrmd_rsc_unregister(client, id, request);
        /* don't notify anyone about failed un-registers */
        if (rc == pcmk_ok || rc == -EINPROGRESS) {
            do_notify = 1;
        }
        do_reply = 1;
    } else if (crm_str_eq(op, LRMD_OP_RSC_EXEC, TRUE)) {
        rc = process_lrmd_rsc_exec(client, id, request);
        do_reply = 1;
    } else if (crm_str_eq(op, LRMD_OP_RSC_CANCEL, TRUE)) {
        rc = process_lrmd_rsc_cancel(client, id, request);
        do_reply = 1;
    } else if (crm_str_eq(op, CRM_OP_QUIT, TRUE)) {
        do_reply = 1;
        exit = 1;
    } else {
        rc = -EOPNOTSUPP;
        do_reply = 1;
        crm_err("Unknown %s from %s", op, client->name);
        crm_log_xml_warn(request, "UnknownOp");
    }

    crm_debug("Processed %s operation from %s: rc=%d, reply=%d, notify=%d, exit=%d",
              op, client->id, rc, do_reply, do_notify, exit);

    if (do_reply) {
        send_reply(client, rc, id, call_id);
    }

    if (do_notify) {
        send_generic_notify(rc, request);
    }

    if (exit) {
        lrmd_shutdown(0);
    }
}

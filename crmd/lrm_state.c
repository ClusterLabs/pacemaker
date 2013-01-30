/* 
 * Copyright (C) 2012 David Vossel <dvossel@redhat.com>
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

GHashTable *lrm_state_table = NULL;

static void
history_cache_destroy(gpointer data)
{
    rsc_history_t *entry = data;

    if (entry->stop_params) {
        g_hash_table_destroy(entry->stop_params);
    }

    free(entry->rsc.type);
    free(entry->rsc.class);
    free(entry->rsc.provider);

    lrmd_free_event(entry->failed);
    lrmd_free_event(entry->last);
    free(entry->id);
    free(entry);
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
    struct recurring_op_s *op = (struct recurring_op_s *)value;

    free(op->rsc_id);
    free(op->op_type);
    free(op->op_key);
    free(op);
}


lrm_state_t *
lrm_state_create(const char *node_name)
{

    lrm_state_t *state = calloc(1, sizeof(lrm_state_t));

    if (!state) {
        return NULL;
    } else if (!node_name) {
        crm_err("No node name given for lrm state object");
        return NULL;
    }

    state->node_name = strdup(node_name);

    state->deletion_ops = g_hash_table_new_full(crm_str_hash,
                                                g_str_equal,
                                                g_hash_destroy_str,
                                                free_deletion_op);

    state->pending_ops = g_hash_table_new_full(crm_str_hash,
                                               g_str_equal,
                                               g_hash_destroy_str,
                                               free_recurring_op);

    state->resource_history = g_hash_table_new_full(crm_str_hash,
                                                    g_str_equal,
                                                    NULL,
                                                    history_cache_destroy);

    g_hash_table_insert(lrm_state_table, (char *) state->node_name, state);
    return state;

}

void lrm_state_destroy(const char *node_name)
{
    g_hash_table_remove(lrm_state_table, node_name);
}

static void
internal_lrm_state_destroy(gpointer data)
{
    lrm_state_t *lrm_state = data;
    if (!lrm_state) {
        return;
    }

    remote_ra_cleanup(lrm_state);
    lrmd_api_delete(lrm_state->conn);

    if (lrm_state->resource_history) {
        g_hash_table_destroy(lrm_state->resource_history);
    }
    if (lrm_state->deletion_ops) {
        g_hash_table_destroy(lrm_state->deletion_ops);
    }
    if (lrm_state->pending_ops) {
        g_hash_table_destroy(lrm_state->pending_ops);
    }

    free((char *) lrm_state->node_name);
    free(lrm_state);
}

void lrm_state_reset_tables(lrm_state_t *lrm_state)
{

    if (lrm_state->resource_history) {
        g_hash_table_remove_all(lrm_state->resource_history);
    }
    if (lrm_state->deletion_ops) {
        g_hash_table_remove_all(lrm_state->deletion_ops);
    }
    if (lrm_state->pending_ops) {
        g_hash_table_remove_all(lrm_state->pending_ops);
    }
}

gboolean lrm_state_init_local(void)
{
    if (lrm_state_table) {
        return TRUE;
    }

    lrm_state_table = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, internal_lrm_state_destroy);
    if (!lrm_state_table) {
        return FALSE;
    }

    return TRUE;
}

void lrm_state_destroy_all(void)
{
    if (lrm_state_table) {
        g_hash_table_destroy(lrm_state_table);
    }
}

lrm_state_t *lrm_state_find(const char *node_name)
{
    return g_hash_table_lookup(lrm_state_table, node_name);
}

lrm_state_t *lrm_state_find_or_create(const char *node_name)
{
    lrm_state_t *lrm_state;

    lrm_state = g_hash_table_lookup(lrm_state_table, node_name);
    if (!lrm_state) {
        lrm_state = lrm_state_create(node_name);
    }

    return lrm_state;
}

GList *lrm_state_get_list(void)
{
    return g_hash_table_get_values(lrm_state_table);
}

void
lrm_state_disconnect(lrm_state_t *lrm_state)
{
    if (!lrm_state->conn) {
        return;
    }
    ((lrmd_t *) lrm_state->conn)->cmds->disconnect(lrm_state->conn);
    lrmd_api_delete(lrm_state->conn);
    lrm_state->conn = NULL;
}

int
lrm_state_is_connected(lrm_state_t *lrm_state)
{
    if (!lrm_state->conn) {
        return FALSE;
    }
    return ((lrmd_t *) lrm_state->conn)->cmds->is_connected(lrm_state->conn);
}

int lrm_state_poke_connection(lrm_state_t *lrm_state)
{

    if (!lrm_state->conn) {
        return -1;
    }
    return ((lrmd_t *) lrm_state->conn)->cmds->poke_connection(lrm_state->conn);
}

int
lrm_state_ipc_connect(lrm_state_t *lrm_state)
{
    int ret;

    if (!lrm_state->conn) {
        lrm_state->conn = lrmd_api_new();
        ((lrmd_t *)lrm_state->conn)->cmds->set_callback(lrm_state->conn, lrm_op_callback);
    }

    ret = ((lrmd_t *) lrm_state->conn)->cmds->connect(lrm_state->conn, CRM_SYSTEM_CRMD, NULL);

    if (ret != pcmk_ok) {
        lrm_state->num_lrm_register_fails++;
    } else {
        lrm_state->num_lrm_register_fails = 0;
    }

    return ret;
}

int
lrm_state_remote_connect_async(lrm_state_t *lrm_state, const char *server, int port, int timeout_ms)
{
    int ret;

    if (!lrm_state->conn) {
        lrm_state->conn = lrmd_remote_api_new(lrm_state->node_name, server, port);
        if (!lrm_state->conn) {
            return -1;
        }
        ((lrmd_t *) lrm_state->conn)->cmds->set_callback(lrm_state->conn, remote_lrm_op_callback);
    }

    crm_trace("initiating remote connection to %s at %d with timeout %d", server, port, timeout_ms);
    ret = ((lrmd_t *) lrm_state->conn)->cmds->connect_async(lrm_state->conn, lrm_state->node_name, timeout_ms);

    if (ret != pcmk_ok) {
        lrm_state->num_lrm_register_fails++;
    } else {
        lrm_state->num_lrm_register_fails = 0;
    }

    return ret;
}

int lrm_state_get_metadata (lrm_state_t *lrm_state,
        const char *class,
        const char *provider,
        const char *agent,
        char **output,
        enum lrmd_call_options options)
{
    if (!lrm_state->conn) {
        return -ENOTCONN;
    }
    if (is_remote_lrmd_ra(agent, provider, NULL)) {
        return remote_ra_get_metadata(output);
    }

    /* Optimize this... only retrieve metadata from local lrmd connection. Perhaps consider
     * caching result. */
    return ((lrmd_t *) lrm_state->conn)->cmds->get_metadata(lrm_state->conn, class, provider, agent, output, options);
}

int lrm_state_cancel(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *action,
    int interval)
{
    if (!lrm_state->conn) {
        return -ENOTCONN;
    }

    /* Optimize this, cancel requires a synced request/response to the server.
     * Figure out a way to make this async. */
    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        return remote_ra_cancel(lrm_state, rsc_id, action, interval);
    }
    return ((lrmd_t *) lrm_state->conn)->cmds->cancel(lrm_state->conn, rsc_id, action, interval);
}

lrmd_rsc_info_t *lrm_state_get_rsc_info(lrm_state_t *lrm_state,
    const char *rsc_id,
    enum lrmd_call_options options)
{
    if (!lrm_state->conn) {
        return NULL;
    }
    /* optimize this... this function is a synced round trip from client to daemon.
     * It should be possible to cache the resource info in the lrmd client to prevent this. */
    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        return remote_ra_get_rsc_info(lrm_state, rsc_id);
    }

    return ((lrmd_t *) lrm_state->conn)->cmds->get_rsc_info(lrm_state->conn, rsc_id, options);
}

int lrm_state_exec(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *action,
    const char *userdata,
    int interval, /* ms */
    int timeout, /* ms */
    int start_delay, /* ms */
    lrmd_key_value_t *params)
{

    if (!lrm_state->conn) {
        lrmd_key_value_freeall(params);
        return -ENOTCONN;
    }

    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        return remote_ra_exec(lrm_state,
            rsc_id,
            action,
            userdata,
            interval,
            timeout,
            start_delay,
            params);
    }

    return ((lrmd_t *) lrm_state->conn)->cmds->exec(lrm_state->conn,
        rsc_id,
        action,
        userdata,
        interval,
        timeout,
        start_delay,
        lrmd_opt_notify_changes_only,
        params);
}

int lrm_state_register_rsc(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *class,
    const char *provider,
    const char *agent,
    enum lrmd_call_options options)
{
    if (!lrm_state->conn) {
        return -ENOTCONN;
    }

    /* optimize this... this function is a synced round trip from client to daemon.
     * The crmd/lrm.c code path should be re-factored to allow the register of resources
     * to be performed async. The lrmd client api needs to make an async version
     * of register available. */
    if (is_remote_lrmd_ra(agent, provider, NULL)) {
        return lrm_state_find_or_create(rsc_id) ? pcmk_ok : -1;
    }

    return ((lrmd_t *) lrm_state->conn)->cmds->register_rsc(lrm_state->conn, rsc_id, class, provider, agent, options);
}

int lrm_state_unregister_rsc(lrm_state_t *lrm_state,
    const char *rsc_id,
    enum lrmd_call_options options)
{
    if (!lrm_state->conn) {
        return -ENOTCONN;
    }

    /* optimize this... this function is a synced round trip from client to daemon.
     * The crmd/lrm.c code path that uses this function should always treat it as an
     * async operation. The lrmd client api needs to make an async version unreg available. */
    if (is_remote_lrmd_ra(NULL, NULL, rsc_id)) {
        lrm_state_destroy(rsc_id);
        return pcmk_ok;
    }

    return ((lrmd_t *) lrm_state->conn)->cmds->unregister_rsc(lrm_state->conn, rsc_id, options);
}

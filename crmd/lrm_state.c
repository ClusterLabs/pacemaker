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


static lrm_state_t *
internal_state_create(const char *node_name)
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
static lrm_state_t *
lrm_state_create_local(const char *node_name)
{

    lrm_state_t *state = internal_state_create(node_name);

    if (state) {
        state->conn = lrmd_api_new();
        state->conn->cmds->set_callback(state->conn, lrm_op_callback);
	}
    return state;
}

lrm_state_t *
lrm_state_create_remote(const char *node_name, const char *server, int port)
{
    lrm_state_t *state;

    if (!server || !port) {
        return NULL;
    }

    state = internal_state_create(node_name);

    if (state) {
        state->conn = lrmd_remote_api_new(node_name, server, port);
        state->conn->cmds->set_callback(state->conn, lrm_op_callback);
    }
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

lrm_state_t *lrm_state_find_or_create_local(const char *node_name)
{
    lrm_state_t *lrm_state;

    lrm_state = g_hash_table_lookup(lrm_state_table, node_name);
    if (!lrm_state) {
        lrm_state = lrm_state_create_local(node_name);
    }

    return lrm_state;
}

GList *lrm_state_get_list(void)
{
    return g_hash_table_get_values(lrm_state_table);
}

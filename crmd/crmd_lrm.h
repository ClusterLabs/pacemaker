/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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

extern gboolean verify_stopped(enum crmd_fsa_state cur_state, int log_level);
extern void lrm_clear_last_failure(const char *rsc_id);
void lrm_op_callback(lrmd_event_data_t * op);

typedef struct resource_history_s {
    char *id;
    lrmd_rsc_info_t rsc;
    lrmd_event_data_t *last;
    lrmd_event_data_t *failed;
    GList *recurring_op_list;

    /* Resources must be stopped using the same
     * parameters they were started with.  This hashtable
     * holds the parameters that should be used for the next stop
     * cmd on this resource. */
    GHashTable *stop_params;
} rsc_history_t;

struct recurring_op_s {
    char *rsc_id;
    char *op_type;
    char *op_key;
    int call_id;
    int interval;
    gboolean remove;
    gboolean cancelled;
};

typedef struct lrm_state_s {
    const char *node_name;
    lrmd_t *conn;

    GHashTable *resource_history;
    GHashTable *pending_ops;
    GHashTable *deletion_ops;

    int num_lrm_register_fails;
} lrm_state_t;

struct pending_deletion_op_s {
    char *rsc;
    ha_msg_input_t *input;
};

/*!
 * \brief Clear all state information from a single state entry. 
 * \note This does not close the lrmd connection
 */
void lrm_state_reset_tables(lrm_state_t *lrm_state);
GList *lrm_state_get_list(void);

/*!
 * \brief Initiate internal state tables
 */
gboolean lrm_state_init_local(void);

/*!
 * \brief Destroy all state entries and internal state tables
 */
void lrm_state_destroy_all(void);

/*!
 * \brief Create remote lrmd connection entry.
 */
lrm_state_t *lrm_state_create_remote(const char *node_name, const char *server, int port);

/*!
 * \brief Destroy lrmd connection keyed of node name
 */
void lrm_state_destroy(const char *node_name);

/*!
 * \brief Find lrm_state data by node name
 */
lrm_state_t *lrm_state_find(const char *node_name);

/*!
 * \brief Either find or create a new entry for the local
 *        ipc lrmd connection.
 */
lrm_state_t *lrm_state_find_or_create_local(const char *node_name);


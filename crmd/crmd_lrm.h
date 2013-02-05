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
    void *conn;
    void *remote_ra_data;

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
 * \brief Create lrmd connection entry.
 */
lrm_state_t *lrm_state_create(const char *node_name);

/*!
 * \brief Destroy lrmd connection keyed of node name
 */
void lrm_state_destroy(const char *node_name);

/*!
 * \brief Find lrm_state data by node name
 */
lrm_state_t *lrm_state_find(const char *node_name);

/*!
 * \brief Either find or create a new entry
 */
lrm_state_t *lrm_state_find_or_create(const char *node_name);


/*!
 * The functions below are wrappers for the lrmd api calls the crmd
 * uses.  These wrapper functions allow us to treat the crmd's remote
 * lrmd connection resources the same as regular resources.  Internally
 * Regular resources go to the lrmd, and remote connection resources are
 * handled locally in the crmd.
 */
void lrm_state_disconnect(lrm_state_t *lrm_state);
int lrm_state_ipc_connect(lrm_state_t *lrm_state);
int lrm_state_remote_connect_async(lrm_state_t *lrm_state, const char *server, int port, int timeout);
int lrm_state_is_connected(lrm_state_t *lrm_state);
int lrm_state_poke_connection(lrm_state_t *lrm_state);

int lrm_state_get_metadata (lrm_state_t *lrm_state,
        const char *class,
        const char *provider,
        const char *agent,
        char **output,
        enum lrmd_call_options options);
int lrm_state_cancel(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *action,
    int interval);
int lrm_state_exec(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *action,
    const char *userdata,
    int interval, /* ms */
    int timeout, /* ms */
    int start_delay, /* ms */
    lrmd_key_value_t *params);
lrmd_rsc_info_t *lrm_state_get_rsc_info(lrm_state_t *lrm_state,
    const char *rsc_id,
    enum lrmd_call_options options);
int lrm_state_register_rsc(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *class,
    const char *provider,
    const char *agent,
    enum lrmd_call_options options);
int lrm_state_unregister_rsc(lrm_state_t *lrm_state,
    const char *rsc_id,
    enum lrmd_call_options options);

/*! These functions are used to manage the remote lrmd connection resources */
void remote_lrm_op_callback(lrmd_event_data_t * op);
gboolean is_remote_lrmd_ra(const char *agent, const char *provider, const char *id);
lrmd_rsc_info_t * remote_ra_get_rsc_info(lrm_state_t *lrm_state, const char *rsc_id);
int remote_ra_cancel(lrm_state_t *lrm_state, const char *rsc_id, const char *action, int interval);
int remote_ra_exec(lrm_state_t *lrm_state,
    const char *rsc_id,
    const char *action,
    const char *userdata,
    int interval, /* ms */
    int timeout, /* ms */
    int start_delay, /* ms */
    lrmd_key_value_t *params);
void remote_ra_cleanup(lrm_state_t *lrm_state);

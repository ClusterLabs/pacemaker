/*
 * Copyright 2004-2026 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */
#ifndef CONTROLD_LRM__H
#  define CONTROLD_LRM__H

#include <stdbool.h>
#include <stdint.h>                 // UINT32_C
#include <crm/lrmd.h>               // lrmd_t

#include <controld_fsa.h>           // fsa_data_t
#include <controld_messages.h>
#include <controld_remote_ra.h>     // remote_ra_data_t

extern gboolean verify_stopped(enum crmd_fsa_state cur_state, int log_level);
void lrm_clear_last_failure(const char *rsc_id, const char *node_name,
                            const char *operation, guint interval_ms);
void controld_invoke_execd(fsa_data_t *msg_data);

void lrm_op_callback(lrmd_event_data_t * op);
lrmd_t *crmd_local_lrmd_conn(void);

typedef struct {
    char *id;
    uint32_t last_callid;
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

void history_free(gpointer data);

enum active_op_e {
    active_op_remove    = (UINT32_C(1) << 0),
    active_op_cancelled = (UINT32_C(1) << 1),
};

// In-flight action (recurring or pending)
typedef struct {
    guint interval_ms;
    int call_id;
    uint32_t flags; // bitmask of active_op_e
    time_t start_time;
    time_t lock_time;
    char *rsc_id;
    char *op_type;
    char *op_key;
    char *user_data;
    GHashTable *params;
} active_op_t;

#define controld_set_active_op_flags(active_op, flags_to_set) do {          \
        (active_op)->flags = pcmk__set_flags_as(__func__, __LINE__,         \
            LOG_TRACE, "Active operation", (active_op)->op_key,             \
            (active_op)->flags, (flags_to_set), #flags_to_set);             \
    } while (0)

#define controld_clear_active_op_flags(active_op, flags_to_clear) do {      \
        (active_op)->flags = pcmk__clear_flags_as(__func__, __LINE__,       \
            LOG_TRACE, "Active operation", (active_op)->op_key,             \
            (active_op)->flags, (flags_to_clear), #flags_to_clear);         \
    } while (0)

typedef struct {
    const char *node_name;
    lrmd_t *conn;                       // Reserved for controld_execd_state.c
    remote_ra_data_t *remote_ra_data;   // Reserved for controld_remote_ra.c

    GHashTable *resource_history;
    GHashTable *active_ops;     // Pending and recurring actions
    GHashTable *deletion_ops;
    GHashTable *rsc_info_cache;
    GHashTable *metadata_cache; // key = class[:provider]:agent, value = ra_metadata_s

    int num_lrm_register_fails;
} lrm_state_t;

struct pending_deletion_op_s {
    char *rsc;
    ha_msg_input_t *input;
};

/*!
 * \brief Check whether this the local IPC connection to the executor
 */
gboolean
lrm_state_is_local(lrm_state_t *lrm_state);

/*!
 * \brief Clear all state information from a single state entry.
 * \note It sometimes useful to save metadata cache when it won't go stale.
 * \note This does not close the executor connection
 */
void lrm_state_reset_tables(lrm_state_t * lrm_state, gboolean reset_metadata);
GList *lrm_state_get_list(void);

/*!
 * \brief Initiate internal state tables
 */
gboolean lrm_state_init_local(void);

/*!
 * \brief Destroy all state entries and internal state tables
 */
void lrm_state_destroy_all(void);

lrm_state_t *controld_get_executor_state(const char *node_name, bool create);

/*!
 * The functions below are wrappers for the executor API the controller uses.
 * These wrapper functions allow us to treat the controller's remote executor
 * connection resources the same as regular resources. Internally, regular
 * resources go to the executor, and remote connection resources are handled
 * locally in the controller.
 */
void lrm_state_disconnect_only(lrm_state_t * lrm_state);
void lrm_state_disconnect(lrm_state_t * lrm_state);
int controld_connect_local_executor(lrm_state_t *lrm_state);
int controld_connect_remote_executor(lrm_state_t *lrm_state, const char *server,
                                     int port, int timeout);
int lrm_state_is_connected(lrm_state_t * lrm_state);
int lrm_state_poke_connection(lrm_state_t * lrm_state);

int lrm_state_get_metadata(lrm_state_t * lrm_state,
                           const char *class,
                           const char *provider,
                           const char *agent, char **output, enum lrmd_call_options options);
int lrm_state_cancel(lrm_state_t *lrm_state, const char *rsc_id,
                     const char *action, guint interval_ms);
int controld_execute_resource_agent(lrm_state_t *lrm_state, const char *rsc_id,
                                    const char *action, const char *userdata,
                                    guint interval_ms, int timeout_ms,
                                    int start_delay_ms,
                                    GHashTable *parameters, int *call_id);
lrmd_rsc_info_t *lrm_state_get_rsc_info(lrm_state_t * lrm_state,
                                        const char *rsc_id, enum lrmd_call_options options);
int lrm_state_register_rsc(lrm_state_t * lrm_state,
                           const char *rsc_id,
                           const char *class,
                           const char *provider, const char *agent, enum lrmd_call_options options);
int lrm_state_unregister_rsc(lrm_state_t * lrm_state,
                             const char *rsc_id, enum lrmd_call_options options);

// Functions used to manage remote executor connection resources
void remote_lrm_op_callback(lrmd_event_data_t * op);
gboolean is_remote_lrmd_ra(const char *agent, const char *provider, const char *id);
lrmd_rsc_info_t *remote_ra_get_rsc_info(lrm_state_t * lrm_state, const char *rsc_id);
int remote_ra_cancel(lrm_state_t *lrm_state, const char *rsc_id,
                     const char *action, guint interval_ms);
int controld_execute_remote_agent(const lrm_state_t *lrm_state,
                                  const char *rsc_id, const char *action,
                                  const char *userdata,
                                  guint interval_ms, int timeout_ms,
                                  int start_delay_ms, lrmd_key_value_t *params,
                                  int *call_id);
void remote_ra_cleanup(lrm_state_t * lrm_state);
void remote_ra_fail(const char *node_name);
void remote_ra_process_pseudo(xmlNode *xml);
gboolean remote_ra_is_in_maintenance(lrm_state_t * lrm_state);
void remote_ra_process_maintenance_nodes(xmlNode *xml);
gboolean remote_ra_controlling_guest(lrm_state_t * lrm_state);

void process_lrm_event(lrm_state_t *lrm_state, lrmd_event_data_t *op,
                       active_op_t *pending, const xmlNode *action_xml);
void controld_ack_event_directly(const char *to_host, const char *to_sys,
                                 const lrmd_rsc_info_t *rsc,
                                 lrmd_event_data_t *op, const char *rsc_id);
void controld_rc2event(lrmd_event_data_t *event, int rc);
void controld_trigger_delete_refresh(const char *from_sys, const char *rsc_id);

#endif

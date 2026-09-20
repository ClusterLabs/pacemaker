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

#include <glib.h>                   // gboolean, GHashTable, GList

#include <controld_fsa.h>           // fsa_data_t
#include <controld_messages.h>
#include <controld_remote_ra.h>     // remote_ra_data_t

void verify_stopped(enum crmd_fsa_state cur_state, int log_level);
void lrm_clear_last_failure(const char *rsc_id, const char *node_name,
                            const char *operation, unsigned int interval_ms);
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

void history_free(void *data);

enum active_op_e {
    active_op_remove    = (UINT32_C(1) << 0),
    active_op_cancelled = (UINT32_C(1) << 1),
};

// In-flight action (recurring or pending)
typedef struct {
    unsigned int interval_ms;
    int call_id;
    uint32_t flags; // bitmask of active_op_e
    time_t start_time;
    time_t lock_time;
    char *rsc_id;
    char *op_type;
    char *op_key;
    char *transition_key;
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
    char *node_name;
    lrmd_t *conn;                       // Reserved for controld_execd_state.c
    remote_ra_data_t *remote_ra_data;   // Reserved for controld_remote_ra.c

    /* All of these hash tables should be allocated when the lrm_state_t object
     * is allocated, and they should be freed only when the lrm_state_t object
     * is freed. Thus they should be non-NULL for the lifetime of the
     * lrm_state_t object.
     */

    GHashTable *resource_history;

    /*!
     * Pending and recurring actions.
     *
     * Key: Executor call key in <tt><resource_id>:<execd_call_id></tt> format
     *      (<tt>char *</tt>).
     * Value: Operation (<tt>active_op_t *</tt>).
     */
    GHashTable *active_ops;

    GHashTable *deletion_ops;
    GHashTable *rsc_info_cache;
    GHashTable *metadata_cache; // key = class[:provider]:agent, value = ra_metadata_s

    int num_lrm_register_fails;
} lrm_state_t;

struct pending_deletion_op_s {
    char *rsc;
    ha_msg_input_t *input;
};

void controld_execd_state_reset_tables(lrm_state_t *lrm_state);
GList *lrm_state_get_list(void);

void controld_execd_state_table_init(void);
void controld_execd_state_table_free(void);

lrm_state_t *controld_execd_state_get(const char *node_name, bool create);

bool lrm_state_verify_stopped(lrm_state_t *lrm_state,
                              enum crmd_fsa_state cur_state, int log_level);

/*!
 * The functions below are wrappers for the executor API the controller uses.
 * These wrapper functions allow us to treat the controller's remote executor
 * connection resources the same as regular resources. Internally, regular
 * resources go to the executor, and remote connection resources are handled
 * locally in the controller.
 */
void controld_execd_state_disconnect(lrm_state_t *lrm_state);
int controld_execd_state_connect_local(lrm_state_t *lrm_state);
int controld_execd_state_connect_remote(lrm_state_t *lrm_state,
                                        const char *server, int port,
                                        int timeout_ms);

bool controld_execd_cancel_op(lrm_state_t *lrm_state, const char *rsc_id,
                              const char *key, int op, bool remove);
int controld_execd_state_get_metadata(const lrm_state_t *lrm_state,
                                      const char *class, const char *provider,
                                      const char *agent, char **output);
int controld_execd_state_cancel(lrm_state_t *lrm_state, const char *rsc_id,
                                const char *action, unsigned int interval_ms);
int controld_execd_state_exec(lrm_state_t *lrm_state, const char *rsc_id,
                              const char *action, const char *user_data,
                              unsigned int interval_ms, int timeout_ms,
                              int start_delay_ms, GHashTable *parameters,
                              int *call_id);
lrmd_rsc_info_t *controld_execd_state_get_rsc_info(lrm_state_t *lrm_state,
                                                   const char *rsc_id);

int controld_execd_state_register_rsc(lrm_state_t *lrm_state,
                                      const char *rsc_id, const char *class,
                                      const char *provider, const char *agent);
int controld_execd_state_unregister_rsc(lrm_state_t *lrm_state,
                                        const char *rsc_id);

// Functions used to manage remote executor connection resources
void remote_lrm_op_callback(lrmd_event_data_t * op);
bool is_remote_lrmd_ra(const char *id);
lrmd_rsc_info_t *remote_ra_get_rsc_info(const char *rsc_id);
int remote_ra_cancel(const char *rsc_id, const char *action,
                     unsigned int interval_ms);
int controld_execute_remote_agent(const lrm_state_t *lrm_state,
                                  const char *rsc_id, const char *action,
                                  const char *userdata,
                                  unsigned int interval_ms, int timeout_ms,
                                  int start_delay_ms, lrmd_key_value_t *params,
                                  int *call_id);
void remote_ra_cleanup(lrm_state_t * lrm_state);
void remote_ra_fail(const char *node_name);
void remote_ra_process_pseudo(xmlNode *xml);
bool controld_remote_ra_in_maintenance(const lrm_state_t *lrm_state);
void remote_ra_process_maintenance_nodes(xmlNode *xml);
bool controld_remote_ra_controlling_guest(const lrm_state_t *lrm_state);

void process_lrm_event(lrm_state_t *lrm_state, lrmd_event_data_t *op,
                       active_op_t *pending, const xmlNode *action_xml);
void controld_ack_event_directly(const char *to_host, const char *to_sys,
                                 const lrmd_rsc_info_t *rsc,
                                 lrmd_event_data_t *op, const char *rsc_id);
void controld_rc2event(lrmd_event_data_t *event, int rc);
void controld_trigger_delete_refresh(const char *from_sys, const char *rsc_id);

#endif

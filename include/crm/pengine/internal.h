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
#ifndef PE_INTERNAL__H
#  define PE_INTERNAL__H
#  include <crm/pengine/status.h>

#  define pe_rsc_info(rsc, fmt, args...)  crm_log_tag(LOG_INFO,  rsc ? rsc->id : "<NULL>", fmt, ##args)
#  define pe_rsc_debug(rsc, fmt, args...) crm_log_tag(LOG_DEBUG, rsc ? rsc->id : "<NULL>", fmt, ##args)
#  define pe_rsc_trace(rsc, fmt, args...) crm_log_tag(LOG_TRACE, rsc ? rsc->id : "<NULL>", fmt, ##args)

#  define pe_err(fmt...) { was_processing_error = TRUE; crm_config_error = TRUE; crm_err(fmt); }
#  define pe_warn(fmt...) { was_processing_warning = TRUE; crm_config_warning = TRUE; crm_warn(fmt); }
#  define pe_proc_err(fmt...) { was_processing_error = TRUE; crm_err(fmt); }
#  define pe_proc_warn(fmt...) { was_processing_warning = TRUE; crm_warn(fmt); }
#  define pe_set_action_bit(action, bit) action->flags = crm_set_bit(__FUNCTION__, action->uuid, action->flags, bit)
#  define pe_clear_action_bit(action, bit) action->flags = crm_clear_bit(__FUNCTION__, action->uuid, action->flags, bit)

typedef struct notify_data_s {
    GHashTable *keys;

    const char *action;

    action_t *pre;
    action_t *post;
    action_t *pre_done;
    action_t *post_done;

    GListPtr active;            /* notify_entry_t*  */
    GListPtr inactive;          /* notify_entry_t*  */
    GListPtr start;             /* notify_entry_t*  */
    GListPtr stop;              /* notify_entry_t*  */
    GListPtr demote;            /* notify_entry_t*  */
    GListPtr promote;           /* notify_entry_t*  */
    GListPtr master;            /* notify_entry_t*  */
    GListPtr slave;             /* notify_entry_t*  */

} notify_data_t;

bool pe_can_fence(pe_working_set_t *data_set, node_t *node);

int merge_weights(int w1, int w2);
void add_hash_param(GHashTable * hash, const char *name, const char *value);
void append_hashtable(gpointer key, gpointer value, gpointer user_data);

char *native_parameter(resource_t * rsc, node_t * node, gboolean create, const char *name,
                       pe_working_set_t * data_set);
node_t *native_location(resource_t * rsc, GListPtr * list, gboolean current);

void pe_metadata(void);
void verify_pe_options(GHashTable * options);

void common_update_score(resource_t * rsc, const char *id, int score);
void native_add_running(resource_t * rsc, node_t * node, pe_working_set_t * data_set);
node_t *rsc_known_on(resource_t * rsc, GListPtr * list);

gboolean native_unpack(resource_t * rsc, pe_working_set_t * data_set);
gboolean group_unpack(resource_t * rsc, pe_working_set_t * data_set);
gboolean clone_unpack(resource_t * rsc, pe_working_set_t * data_set);
gboolean master_unpack(resource_t * rsc, pe_working_set_t * data_set);

resource_t *native_find_rsc(resource_t * rsc, const char *id, node_t * node, int flags);

gboolean native_active(resource_t * rsc, gboolean all);
gboolean group_active(resource_t * rsc, gboolean all);
gboolean clone_active(resource_t * rsc, gboolean all);
gboolean master_active(resource_t * rsc, gboolean all);

void native_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void group_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void clone_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void master_print(resource_t * rsc, const char *pre_text, long options, void *print_data);

void native_free(resource_t * rsc);
void group_free(resource_t * rsc);
void clone_free(resource_t * rsc);
void master_free(resource_t * rsc);

enum rsc_role_e native_resource_state(const resource_t * rsc, gboolean current);
enum rsc_role_e group_resource_state(const resource_t * rsc, gboolean current);
enum rsc_role_e clone_resource_state(const resource_t * rsc, gboolean current);
enum rsc_role_e master_resource_state(const resource_t * rsc, gboolean current);

gboolean common_unpack(xmlNode * xml_obj, resource_t ** rsc, resource_t * parent,
                       pe_working_set_t * data_set);
void common_print(resource_t * rsc, const char *pre_text, long options, void *print_data);
void common_free(resource_t * rsc);

extern pe_working_set_t *pe_dataset;

extern node_t *node_copy(node_t * this_node);
extern time_t get_effective_time(pe_working_set_t * data_set);
extern int get_failcount(node_t * node, resource_t * rsc, time_t *last_failure,
                         pe_working_set_t * data_set);
extern int get_failcount_full(node_t * node, resource_t * rsc, time_t *last_failure,
                              bool effective, pe_working_set_t * data_set);
extern int get_failcount_all(node_t * node, resource_t * rsc, time_t *last_failure,
                             pe_working_set_t * data_set);

/* Binary like operators for lists of nodes */
extern void node_list_exclude(GHashTable * list, GListPtr list2, gboolean merge_scores);
extern GListPtr node_list_dup(GListPtr list, gboolean reset, gboolean filter);
extern GListPtr node_list_from_hash(GHashTable * hash, gboolean reset, gboolean filter);

extern GHashTable *node_hash_from_list(GListPtr list);
static inline gpointer
pe_hash_table_lookup(GHashTable * hash, gconstpointer key)
{
    if (hash) {
        return g_hash_table_lookup(hash, key);
    }
    return NULL;
}

extern action_t *get_pseudo_op(const char *name, pe_working_set_t * data_set);
extern gboolean order_actions(action_t * lh_action, action_t * rh_action, enum pe_ordering order);

extern GListPtr node_list_and(GListPtr list1, GListPtr list2, gboolean filter);

extern GListPtr node_list_xor(GListPtr list1, GListPtr list2, gboolean filter);

extern GListPtr node_list_minus(GListPtr list1, GListPtr list2, gboolean filter);

extern void pe_free_shallow(GListPtr alist);
extern void pe_free_shallow_adv(GListPtr alist, gboolean with_data);

/* Printing functions for debug */
extern void print_node(const char *pre_text, node_t * node, gboolean details);

extern void print_resource(int log_level, const char *pre_text, resource_t * rsc, gboolean details);

extern void dump_node_scores_worker(int level, const char *file, const char *function, int line,
                                    resource_t * rsc, const char *comment, GHashTable * nodes);

extern void dump_node_capacity(int level, const char *comment, node_t * node);
extern void dump_rsc_utilization(int level, const char *comment, resource_t * rsc, node_t * node);

#  define dump_node_scores(level, rsc, text, nodes) do {		\
        dump_node_scores_worker(level, __FILE__, __FUNCTION__, __LINE__, rsc, text, nodes); \
    } while(0)

/* Sorting functions */
extern gint sort_rsc_priority(gconstpointer a, gconstpointer b);
extern gint sort_rsc_index(gconstpointer a, gconstpointer b);

extern xmlNode *find_rsc_op_entry(resource_t * rsc, const char *key);

extern action_t *custom_action(resource_t * rsc, char *key, const char *task, node_t * on_node,
                               gboolean optional, gboolean foo, pe_working_set_t * data_set);

#  define delete_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_DELETE, 0)
#  define delete_action(rsc, node, optional) custom_action(		\
		rsc, delete_key(rsc), CRMD_ACTION_DELETE, node,		\
		optional, TRUE, data_set);

#  define stopped_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_STOPPED, 0)
#  define stopped_action(rsc, node, optional) custom_action(		\
		rsc, stopped_key(rsc), CRMD_ACTION_STOPPED, node,	\
		optional, TRUE, data_set);

#  define stop_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_STOP, 0)
#  define stop_action(rsc, node, optional) custom_action(			\
		rsc, stop_key(rsc), CRMD_ACTION_STOP, node,		\
		optional, TRUE, data_set);

#  define start_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_START, 0)
#  define start_action(rsc, node, optional) custom_action(		\
		rsc, start_key(rsc), CRMD_ACTION_START, node,		\
		optional, TRUE, data_set)

#  define started_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_STARTED, 0)
#  define started_action(rsc, node, optional) custom_action(		\
		rsc, started_key(rsc), CRMD_ACTION_STARTED, node,	\
		optional, TRUE, data_set)

#  define promote_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_PROMOTE, 0)
#  define promote_action(rsc, node, optional) custom_action(		\
		rsc, promote_key(rsc), CRMD_ACTION_PROMOTE, node,	\
		optional, TRUE, data_set)

#  define promoted_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_PROMOTED, 0)
#  define promoted_action(rsc, node, optional) custom_action(		\
		rsc, promoted_key(rsc), CRMD_ACTION_PROMOTED, node,	\
		optional, TRUE, data_set)

#  define demote_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_DEMOTE, 0)
#  define demote_action(rsc, node, optional) custom_action(		\
		rsc, demote_key(rsc), CRMD_ACTION_DEMOTE, node,		\
		optional, TRUE, data_set)

#  define demoted_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_DEMOTED, 0)
#  define demoted_action(rsc, node, optional) custom_action(		\
		rsc, demoted_key(rsc), CRMD_ACTION_DEMOTED, node,	\
		optional, TRUE, data_set)

extern action_t *find_first_action(GListPtr input, const char *uuid, const char *task,
                                   node_t * on_node);
extern enum action_tasks get_complex_task(resource_t * rsc, const char *name,
                                          gboolean allow_non_atomic);

extern GListPtr find_actions(GListPtr input, const char *key, node_t * on_node);
extern GListPtr find_actions_exact(GListPtr input, const char *key, node_t * on_node);
extern GListPtr find_recurring_actions(GListPtr input, node_t * not_on_node);

extern void pe_free_action(action_t * action);

extern void resource_location(resource_t * rsc, node_t * node, int score, const char *tag,
                              pe_working_set_t * data_set);

extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);
extern gboolean get_target_role(resource_t * rsc, enum rsc_role_e *role);

extern resource_t *find_clone_instance(resource_t * rsc, const char *sub_id,
                                       pe_working_set_t * data_set);

extern void destroy_ticket(gpointer data);
extern ticket_t *ticket_new(const char *ticket_id, pe_working_set_t * data_set);

char *clone_strip(const char *last_rsc_id);
char *clone_zero(const char *last_rsc_id);

gint sort_node_uname(gconstpointer a, gconstpointer b);
bool is_set_recursive(resource_t * rsc, long long flag, bool any);

enum rsc_digest_cmp_val {
    /*! Digests are the same */
    RSC_DIGEST_MATCH = 0,
    /*! Params that require a restart changed */
    RSC_DIGEST_RESTART,
    /*! Some parameter changed.  */
    RSC_DIGEST_ALL,
    /*! rsc op didn't have a digest associated with it, so
     *  it is unknown if parameters changed or not. */
    RSC_DIGEST_UNKNOWN,
};

typedef struct op_digest_cache_s {
    enum rsc_digest_cmp_val rc;
    xmlNode *params_all;
    xmlNode *params_restart;
    char *digest_all_calc;
    char *digest_restart_calc;
} op_digest_cache_t;

op_digest_cache_t *rsc_action_digest_cmp(resource_t * rsc, xmlNode * xml_op, node_t * node,
                                         pe_working_set_t * data_set);

gboolean is_remote_node(xmlNode *xml);

#endif

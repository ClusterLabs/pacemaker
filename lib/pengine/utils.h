/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
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
 */
#ifndef PE_UTILS__H
#  define PE_UTILS__H
#  include <crm/pengine/common.h>
#  include <crm/pengine/status.h>

extern pe_working_set_t *pe_dataset;

extern node_t *node_copy(node_t * this_node);
extern time_t get_timet_now(pe_working_set_t * data_set);
extern int get_failcount(node_t * node, resource_t * rsc, int *last_failure,
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

/* For creating the transition graph */
extern xmlNode *action2xml(action_t * action, gboolean as_input);

/* Printing functions for debug */
extern void print_node(const char *pre_text, node_t * node, gboolean details);

extern void print_resource(int log_level, const char *pre_text, resource_t * rsc, gboolean details);

extern void dump_node_scores_worker(int level, const char *file, const char *function, int line,
                                    resource_t * rsc, const char *comment, GHashTable * nodes);

extern void dump_node_capacity(int level, const char *comment, node_t * node);
extern void dump_rsc_utilization(int level, const char *comment, resource_t * rsc, node_t * node);

#    define dump_node_scores(level, rsc, text, nodes) do {		\
	if((level) == 0 || __unlikely((level) < crm_log_level)) {	\
	    dump_node_scores_worker(level, __FILE__, NULL, 0, rsc, text, nodes); \
	}								\
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

extern void

resource_location(resource_t * rsc, node_t * node, int score, const char *tag,
                  pe_working_set_t * data_set);

extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);
extern gboolean get_target_role(resource_t * rsc, enum rsc_role_e *role);

extern resource_t *find_clone_instance(resource_t * rsc, const char *sub_id,
                                       pe_working_set_t * data_set);

#endif

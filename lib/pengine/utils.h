/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#ifndef PE_UTILS__H
#define PE_UTILS__H
#include <crm/pengine/common.h>
#include <crm/pengine/status.h>


extern node_t *node_copy(node_t *this_node) ;
extern time_t get_timet_now(pe_working_set_t *data_set);
extern int get_failcount(node_t *node, resource_t *rsc, int *last_failure, pe_working_set_t *data_set);

/* Binary like operators for lists of nodes */
extern GListPtr node_list_exclude(GListPtr list1, GListPtr list2, gboolean merge_scores);
extern GListPtr node_list_dup(GListPtr list1, gboolean reset, gboolean filter);

extern GListPtr node_list_and(GListPtr list1, GListPtr list2, gboolean filter);

extern GListPtr node_list_xor(GListPtr list1, GListPtr list2, gboolean filter);

extern GListPtr node_list_minus(GListPtr list1,GListPtr list2,gboolean filter);

extern gboolean node_list_eq(GListPtr list1, GListPtr list2, gboolean filter);

extern GListPtr node_list_or(GListPtr list1, GListPtr list2, gboolean filter);

extern void pe_free_shallow(GListPtr alist);
extern void pe_free_shallow_adv(GListPtr alist, gboolean with_data);

/* For creating the transition graph */
extern xmlNode *action2xml(action_t *action, gboolean as_input);

/* Printing functions for debug */
extern void print_node(
	const char *pre_text, node_t *node, gboolean details);

extern void print_resource(
	int log_level, const char *pre_text, resource_t *rsc, gboolean details);

extern void dump_node_scores(int level, resource_t *rsc, const char *comment, GListPtr nodes);

/* Sorting functions */
extern gint sort_rsc_priority(gconstpointer a, gconstpointer b);
extern gint sort_rsc_index(gconstpointer a, gconstpointer b);

extern xmlNode *find_rsc_op_entry(resource_t *rsc, const char *key);

extern action_t *custom_action(
	resource_t *rsc, char *key, const char *task, node_t *on_node,
	gboolean optional, gboolean foo, pe_working_set_t *data_set);

#define delete_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_DELETE, 0)
#define delete_action(rsc, node, optional) custom_action(		\
		rsc, delete_key(rsc), CRMD_ACTION_DELETE, node,		\
		optional, TRUE, data_set);

#define stopped_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_STOPPED, 0)
#define stopped_action(rsc, node, optional) custom_action(		\
		rsc, stopped_key(rsc), CRMD_ACTION_STOPPED, node,	\
		optional, TRUE, data_set);

#define stop_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_STOP, 0)
#define stop_action(rsc, node, optional) custom_action(			\
		rsc, stop_key(rsc), CRMD_ACTION_STOP, node,		\
		optional, TRUE, data_set);

#define start_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_START, 0)
#define start_action(rsc, node, optional) custom_action(		\
		rsc, start_key(rsc), CRMD_ACTION_START, node,		\
		optional, TRUE, data_set)

#define started_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_STARTED, 0)
#define started_action(rsc, node, optional) custom_action(		\
		rsc, started_key(rsc), CRMD_ACTION_STARTED, node,	\
		optional, TRUE, data_set)

#define promote_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_PROMOTE, 0)
#define promote_action(rsc, node, optional) custom_action(		\
		rsc, promote_key(rsc), CRMD_ACTION_PROMOTE, node,	\
		optional, TRUE, data_set)

#define promoted_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_PROMOTED, 0)
#define promoted_action(rsc, node, optional) custom_action(		\
		rsc, promoted_key(rsc), CRMD_ACTION_PROMOTED, node,	\
		optional, TRUE, data_set)

#define demote_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_DEMOTE, 0)
#define demote_action(rsc, node, optional) custom_action(		\
		rsc, demote_key(rsc), CRMD_ACTION_DEMOTE, node,		\
		optional, TRUE, data_set)

#define demoted_key(rsc) generate_op_key(rsc->id, CRMD_ACTION_DEMOTED, 0)
#define demoted_action(rsc, node, optional) custom_action(		\
		rsc, demoted_key(rsc), CRMD_ACTION_DEMOTED, node,	\
		optional, TRUE, data_set)

extern action_t *find_first_action(GListPtr input, const char *uuid, const char *task, node_t *on_node);

extern GListPtr find_actions(GListPtr input, const char *key, node_t *on_node);
extern GListPtr find_actions_exact(
	GListPtr input, const char *key, node_t *on_node);
extern GListPtr find_recurring_actions(GListPtr input, node_t *not_on_node);

extern void set_id(xmlNode *xml_obj, const char *prefix, int child);
extern void pe_free_action(action_t *action);

extern void
resource_location(resource_t *rsc, node_t *node, int score, const char *tag,
		  pe_working_set_t *data_set);

extern gint sort_op_by_callid(gconstpointer a, gconstpointer b);
extern gboolean get_target_role(resource_t *rsc, enum rsc_role_e *role);

#endif

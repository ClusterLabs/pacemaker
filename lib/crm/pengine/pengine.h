/* $Id: pengine.h,v 1.1 2006/06/07 12:46:56 andrew Exp $ */
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
#ifndef PENGINE__H
#define PENGINE__H

#include <clplumbing/ipc.h>

typedef struct rsc_to_node_s rsc_to_node_t;
typedef struct rsc_colocation_s rsc_colocation_t;
typedef struct lrm_agent_s lrm_agent_t;
typedef struct order_constraint_s order_constraint_t;
typedef struct action_s action_t;
typedef struct action_wrapper_s action_wrapper_t;

#include <glib.h>
#include <crm/crm.h>
#include <crm/common/msg.h>
#include <crm/common/iso8601.h>
#include <crm/pengine/rules.h>
#include <crm/pengine/common.h>
#include <crm/pengine/status.h>

#include <linux-ha/config.h>

#include <crm/pengine/complex.h>

enum con_strength {
	pecs_ignore,
	pecs_must,
	pecs_must_not,
	pecs_startstop
};


enum pe_stop_fail {
	pesf_block,
	pesf_stonith,
	pesf_ignore
};

enum pe_ordering {
	pe_ordering_manditory,
	pe_ordering_restart,
	pe_ordering_recover,
	pe_ordering_postnotify,
	pe_ordering_optional
};


struct color_shared_s {
		int      id;
		int    highest_priority;
		GListPtr candidate_nodes; /* node_t* */
		GListPtr allocated_resources; /* resources_t* */
		node_t  *chosen_node;
		gboolean pending;
		int	 num_resources;
};

struct color_s { 
		int id; 
		struct color_shared_s *details;
		int local_weight;
};

struct rsc_colocation_s { 
		const char	*id;
		resource_t	*rsc_lh;
		resource_t	*rsc_rh;

		const char *state_lh;
		const char *state_rh;
		
		enum con_strength strength;
};

struct rsc_to_node_s { 
		const char *id;
		resource_t *rsc_lh; 

		enum rsc_role_e role_filter;
		GListPtr    node_list_rh; /* node_t* */
};


struct action_wrapper_s 
{
		enum pe_ordering type;
		action_t *action;
};


struct action_s 
{
		int         id;
		int         priority;
		resource_t *rsc;
		void       *rsc_opaque;
		node_t     *node;
		const char *task;

		char *uuid;
		crm_data_t *op_entry;
		
		gboolean pseudo;
		gboolean runnable;
		gboolean optional;
		gboolean failure_is_fatal;

		enum rsc_start_requirement needs;
		enum action_fail_response  on_fail;
		enum rsc_role_e fail_role;
		
		gboolean dumped;
		gboolean processed;

		action_t *pre_notify;
		action_t *pre_notified;
		action_t *post_notify;
		action_t *post_notified;
		
		int seen_count;

		GHashTable *meta;
		GHashTable *extra;
		GHashTable *notify_keys;  /* do NOT free */
		
		GListPtr actions_before; /* action_warpper_t* */
		GListPtr actions_after;  /* action_warpper_t* */
};

struct order_constraint_s 
{
		int id;
		enum pe_ordering type;

		void *lh_opaque;
		resource_t *lh_rsc;
		action_t   *lh_action;
		char *lh_action_task;
		
		void *rh_opaque;
		resource_t *rh_rsc;
		action_t   *rh_action;
		char *rh_action_task;

		/* (soon to be) variant specific */
/* 		int   lh_rsc_incarnation; */
/* 		int   rh_rsc_incarnation; */
};

extern gboolean stage0(pe_working_set_t *data_set);
extern gboolean stage1(pe_working_set_t *data_set);
extern gboolean stage2(pe_working_set_t *data_set);
extern gboolean stage3(pe_working_set_t *data_set);
extern gboolean stage4(pe_working_set_t *data_set);
extern gboolean stage5(pe_working_set_t *data_set);
extern gboolean stage6(pe_working_set_t *data_set);
extern gboolean stage7(pe_working_set_t *data_set);
extern gboolean stage8(pe_working_set_t *data_set);

extern gboolean summary(GListPtr resources);

extern gboolean pe_msg_dispatch(IPC_Channel *sender, void *user_data);

extern gboolean process_pe_message(
	HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender);

extern gboolean unpack_constraints(
	crm_data_t *xml_constraints, pe_working_set_t *data_set);

extern gboolean unpack_resources(
	crm_data_t *xml_resources, pe_working_set_t *data_set);

extern gboolean unpack_config(crm_data_t *config, pe_working_set_t *data_set);

extern gboolean unpack_nodes(crm_data_t *xml_nodes, pe_working_set_t *data_set);

extern gboolean unpack_status(crm_data_t *status, pe_working_set_t *data_set);

extern gboolean apply_placement_constraints(pe_working_set_t *data_set);

extern gboolean choose_node_from_list(color_t *color);

extern gboolean update_action_states(GListPtr actions);

extern gboolean shutdown_constraints(
	node_t *node, action_t *shutdown_op, pe_working_set_t *data_set);

extern gboolean stonith_constraints(
	node_t *node, action_t *stonith_op, pe_working_set_t *data_set);

extern gboolean custom_action_order(
	resource_t *lh_rsc, char *lh_task, action_t *lh_action,
	resource_t *rh_rsc, char *rh_task, action_t *rh_action,
	enum pe_ordering type, pe_working_set_t *data_set);

#define order_start_start(rsc1,rsc2, type)				\
	custom_action_order(rsc1, start_key(rsc1), NULL,		\
			    rsc2, start_key(rsc2) ,NULL,		\
			    type, data_set)
#define order_stop_stop(rsc1, rsc2, type)				\
	custom_action_order(rsc1, stop_key(rsc1), NULL,		\
			    rsc2, stop_key(rsc2) ,NULL,		\
			    type, data_set)

#define order_restart(rsc1)						\
	custom_action_order(rsc1, stop_key(rsc1), NULL,		\
			    rsc1, start_key(rsc1), NULL,	\
			    pe_ordering_restart, data_set)

#define order_stop_start(rsc1, rsc2, type)				\
	custom_action_order(rsc1, stop_key(rsc1), NULL,		\
			    rsc2, start_key(rsc2) ,NULL,		\
			    type, data_set)

#define order_start_stop(rsc1, rsc2, type)				\
	custom_action_order(rsc1, start_key(rsc1), NULL,		\
			    rsc2, stop_key(rsc2) ,NULL,		\
			    type, data_set)

extern gboolean process_colored_constraints(resource_t *rsc);
extern void graph_element_from_action(
	action_t *action, pe_working_set_t *data_set);
extern void order_actions(action_t *lh_action, action_t *rh_action, enum pe_ordering order);

extern const char* transition_idle_timeout;

#endif


/* $Id: pengine.h,v 1.34 2004/08/30 03:17:39 msoffen Exp $ */
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

typedef struct node_s node_t;
typedef struct color_s color_t;
typedef struct rsc_to_node_s rsc_to_node_t;
typedef struct rsc_to_rsc_s rsc_to_rsc_t;
typedef struct resource_s resource_t;
typedef struct lrm_agent_s lrm_agent_t;
typedef struct order_constraint_s order_constraint_t;
typedef struct action_s action_t;
typedef struct action_wrapper_s action_wrapper_t;

enum con_type {
	type_none,
	rsc_to_rsc,
	rsc_to_node,
	rsc_to_attr,
	base_weight
};

enum node_type {
	node_ping,
	node_member
};

enum con_strength {
	pecs_ignore,
	pecs_must,
	pecs_should,
	pecs_should_not,
	pecs_must_not,
	pecs_startstop
};

enum action_tasks {
	no_action,
	stop_rsc,
	start_rsc,
	shutdown_crm,
	stonith_op
};

enum rsc_con_type {
	start_before,
	start_after,
	same_node
};

struct node_shared_s { 
		const char *id; 
		const char *uname; 
		gboolean online;
		gboolean unclean;
		gboolean shutdown;
		GListPtr running_rsc;	/* resource_t* */
		GListPtr agents;	/* lrm_agent_t* */
		
		GHashTable *attrs;	/* char* => char* */
		enum node_type type;
}; 

struct node_s { 
		float	weight; 
		gboolean fixed;
		struct node_shared_s *details;
};

struct color_shared_s {
		int      id;
		float    highest_priority;
		GListPtr candidate_nodes; /* node_t* */
		GListPtr allocated_resources; /* resources_t* */
		node_t  *chosen_node;
		gboolean pending;
};

struct color_s { 
		int id; 
		struct color_shared_s *details;
		float local_weight;
};

struct rsc_to_rsc_s { 
		const char	*id;
		resource_t	*rsc_lh; 

		enum rsc_con_type variant;
		resource_t	*rsc_rh; 
		enum con_strength strength;
};

struct rsc_to_node_s { 
		const char	*id;
		resource_t	*rsc_lh; 

		float		weight;
		GListPtr node_list_rh; /* node_t* */
/*		enum con_modifier modifier; */
		gboolean can;
};

struct lrm_agent_s { 
		const char *class;
		const char *type;
		const char *version;
};

enum pe_stop_fail {
	pesf_block,
	pesf_stonith,
	pesf_ignore
};


struct resource_s { 
		const char	*id; 
		xmlNodePtr	xml; 
		float		priority; 
		float		effective_priority; 
		node_t		*cur_node; 

		lrm_agent_t	*agent;
		
		gboolean	is_stonith;
		gboolean	runnable;
		gboolean	provisional;

		enum pe_stop_fail stopfail_type;

		action_t	*stop;
		action_t	*start;
		
		GListPtr	actions;	  /* action_t* */
		
		GListPtr	candidate_colors; /* color_t* */
		GListPtr	allowed_nodes;    /* node_t* */
		GListPtr	node_cons;        /* rsc_to_node_t*  */
		GListPtr	rsc_cons;         /* resource_t* */
		GListPtr	fencable_nodes;   /* node_t* */

		color_t		*color;
};

struct action_wrapper_s 
{
		enum con_strength strength;
		action_t *action;
};


struct action_s 
{
		int id;
		resource_t *rsc;
		node_t *node;
		enum action_tasks task;
		
		gboolean runnable;
		gboolean processed;
		gboolean optional;
		gboolean discard;
		gboolean failure_is_fatal;

		int seen_count;

		xmlNodePtr args;
		
		GListPtr actions_before; /* action_warpper_t* */
		GListPtr actions_after;  /* action_warpper_t* */
};

struct order_constraint_s 
{
		int id;
		action_t *lh_action;
		action_t *rh_action;
		enum con_strength strength;
/*		enum action_order order; */
};

extern gboolean stage0(xmlNodePtr cib,
		       GListPtr *nodes,
		       GListPtr *rscs,
		       GListPtr *cons,
		       GListPtr *actions, GListPtr *action_constraints,
		       GListPtr *stonith_list, GListPtr *shutdown_list);

extern gboolean stage1(GListPtr node_constraints,
		       GListPtr nodes,
		       GListPtr resources);

extern gboolean stage2(GListPtr sorted_rscs,
		       GListPtr sorted_nodes,
		       GListPtr *colors);

extern gboolean stage3(GListPtr colors);

extern gboolean stage4(GListPtr colors);

extern gboolean stage5(GListPtr resources);

extern gboolean stage6(
	GListPtr *actions, GListPtr *action_constraints,
	GListPtr nodes, GListPtr resources);

extern gboolean stage7(GListPtr resources,
		       GListPtr actions,
		       GListPtr action_constraints,
		       GListPtr *action_sets);

extern gboolean stage8(GListPtr action_sets, xmlNodePtr *graph);

extern gboolean summary(GListPtr resources);

extern gboolean pe_input_dispatch(IPC_Channel *sender, void *user_data);

extern gboolean process_pe_message(xmlNodePtr msg, IPC_Channel *sender);

extern gboolean unpack_constraints(xmlNodePtr xml_constraints,
				   GListPtr nodes, GListPtr resources,
				   GListPtr *node_constraints,
				   GListPtr *action_constraints);

extern gboolean unpack_resources(xmlNodePtr xml_resources,
				 GListPtr *resources,
				 GListPtr *actions,
				 GListPtr *action_cons,
				 GListPtr all_nodes);

extern gboolean unpack_config(xmlNodePtr config);

extern gboolean unpack_config(xmlNodePtr config);

extern gboolean unpack_global_defaults(xmlNodePtr defaults);

extern gboolean unpack_nodes(xmlNodePtr xml_nodes, GListPtr *nodes);

extern gboolean unpack_status(xmlNodePtr status,
			      GListPtr nodes,
			      GListPtr rsc_list,
			      GListPtr *actions,
			      GListPtr *node_constraints);


extern gboolean apply_node_constraints(GListPtr constraints, GListPtr nodes);

extern gboolean apply_agent_constraints(GListPtr resources);

extern void color_resource(resource_t *lh_resource,
			   GListPtr *colors,
			   GListPtr resources);

extern gboolean choose_node_from_list(color_t *color);

extern gboolean update_runnable(GListPtr actions);
extern GListPtr create_action_set(action_t *action);

extern gboolean shutdown_constraints(
	node_t *node, action_t *shutdown_op, GListPtr *action_constraints);

extern gboolean stonith_constraints(
	node_t *node, action_t *stonith_op, action_t *shutdown_op,
	GListPtr *action_constraints);

extern gboolean order_new(
	action_t *before, action_t *after, enum con_strength strength,
	GListPtr *action_constraints);


extern gboolean process_colored_constraints(resource_t *rsc);

extern color_t *no_color;
extern int      max_valid_nodes;
extern int      order_id;
extern int      action_id;
extern gboolean stonith_enabled;
extern GListPtr agent_defaults;

#endif


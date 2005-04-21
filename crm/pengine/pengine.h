/* $Id: pengine.h,v 1.60 2005/04/21 15:32:02 andrew Exp $ */
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
typedef struct rsc_colocation_s rsc_colocation_t;
typedef struct resource_s resource_t;
typedef struct lrm_agent_s lrm_agent_t;
typedef struct order_constraint_s order_constraint_t;
typedef struct action_s action_t;
typedef struct action_wrapper_s action_wrapper_t;

#include <glib.h>
#include <crm/crm.h>
#include <crm/common/msg.h>
#include <complex.h>

typedef enum no_quorum_policy_e {
	no_quorum_freeze,
	no_quorum_stop,
	no_quorum_ignore
} no_quorum_policy_t;

enum con_type {
	type_none,
	rsc_colocation,
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
	pecs_must_not,
	pecs_startstop
};

enum action_tasks {
	no_action,
	monitor_rsc,
	stop_rsc,
	stopped_rsc,
	start_rsc,
	started_rsc,
	shutdown_crm,
	stonith_node
};

enum rsc_recovery_type {
	recovery_stop_start,
	recovery_stop_only,
	recovery_block
};


enum pe_stop_fail {
	pesf_block,
	pesf_stonith,
	pesf_ignore
};

enum pe_restart {
	pe_restart_restart,
	pe_restart_ignore
};


struct node_shared_s { 
		const char *id; 
		const char *uname; 
		gboolean online;
		gboolean unclean;
		gboolean shutdown;
		gboolean expected_up;
		gboolean is_dc;
		int	 num_resources;
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
		int	 num_resources;
};

struct color_s { 
		int id; 
		struct color_shared_s *details;
		float local_weight;
};

struct rsc_colocation_s { 
		const char	*id;
		resource_t	*rsc_lh; 

		resource_t	*rsc_rh; 
		enum con_strength strength;
};

struct rsc_to_node_s { 
		const char	*id;
		resource_t	*rsc_lh; 

		float		weight;
		GListPtr node_list_rh; /* node_t* */
};

struct lrm_agent_s { 
		const char *class;
		const char *type;
		const char *version;
};

struct resource_s { 
		const char *id; 
		crm_data_t * xml; 
		crm_data_t * ops_xml; 

		void *variant_opaque;
		enum pe_obj_types variant;
		resource_object_functions_t *fns;

		enum rsc_recovery_type recovery_type;
		enum pe_stop_fail      stopfail_type;
		enum pe_restart        restart_type;

		float	 priority; 
		float	 effective_priority; 

		gboolean start_pending;
		gboolean schedule_recurring;
		gboolean recover;
		gboolean starting;
		gboolean stopping;
		gboolean is_stonith;
		gboolean runnable;
		gboolean provisional;
		gboolean unclean;

		GListPtr candidate_colors; /* color_t*          */
		GListPtr rsc_cons;         /* rsc_colocation_t* */
		GListPtr actions;	   /* action_t*         */

		GHashTable * parameters;
};

struct action_wrapper_s 
{
		enum con_strength strength;
		action_t *action;
};


struct action_s 
{
		int         id;
		resource_t *rsc;
		void       *rsc_opaque;
		node_t     *node;
		enum action_tasks task;
		
		gboolean pseudo;
		gboolean runnable;
		gboolean dumped;
		gboolean processed;
		gboolean optional;
		gboolean failure_is_fatal;

		int seen_count;
		const char *timeout;

/* 		crm_data_t *args; */
		GHashTable *extra;
		
		GListPtr actions_before; /* action_warpper_t* */
		GListPtr actions_after;  /* action_warpper_t* */
};

struct order_constraint_s 
{
		int id;
		enum con_strength strength;

		void *lh_opaque;
		resource_t *lh_rsc;
		action_t   *lh_action;
		enum action_tasks lh_action_task;
		
		void *rh_opaque;
		resource_t *rh_rsc;
		action_t   *rh_action;
		enum action_tasks rh_action_task;

		/* (soon to be) variant specific */
/* 		int   lh_rsc_incarnation; */
/* 		int   rh_rsc_incarnation; */
};


extern gboolean stage0(crm_data_t *cib,
		       GListPtr *nodes,
		       GListPtr *rscs,
		       GListPtr *cons,
		       GListPtr *actions, GListPtr *ordering_constraints,
		       GListPtr *stonith_list, GListPtr *shutdown_list);

extern gboolean stage1(GListPtr placement_constraints,
		       GListPtr nodes,
		       GListPtr resources);

extern gboolean stage2(GListPtr sorted_rscs,
		       GListPtr sorted_nodes,
		       GListPtr *colors);

extern gboolean stage3(GListPtr colors);

extern gboolean stage4(GListPtr colors);

extern gboolean stage5(GListPtr resources, GListPtr *ordering_constraints);

extern gboolean stage6(
	GListPtr *actions, GListPtr *ordering_constraints,
	GListPtr nodes, GListPtr resources);

extern gboolean stage7(
	GListPtr resources, GListPtr actions, GListPtr ordering_constraints);

extern gboolean stage8(
	GListPtr resources, GListPtr action_sets, crm_data_t **graph);

extern gboolean summary(GListPtr resources);

extern gboolean pe_msg_dispatch(IPC_Channel *sender, void *user_data);

extern gboolean process_pe_message(
	HA_Message *msg, crm_data_t *xml_data, IPC_Channel *sender);

extern gboolean unpack_constraints(crm_data_t *xml_constraints,
				   GListPtr nodes, GListPtr resources,
				   GListPtr *placement_constraints,
				   GListPtr *ordering_constraints);

extern gboolean unpack_resources(crm_data_t *xml_resources,
				 GListPtr *resources,
				 GListPtr *actions,
				 GListPtr *ordering_constraints,
				 GListPtr *placement_constraints,
				 GListPtr all_nodes);

extern gboolean unpack_config(crm_data_t *config);

extern gboolean unpack_config(crm_data_t *config);

extern gboolean unpack_global_defaults(crm_data_t *defaults);

extern gboolean unpack_nodes(crm_data_t *xml_nodes, GListPtr *nodes);

extern gboolean unpack_status(crm_data_t *status,
			      GListPtr nodes,
			      GListPtr rsc_list,
			      GListPtr *actions,
			      GListPtr *placement_constraints);


extern gboolean apply_placement_constraints(GListPtr constraints, GListPtr nodes);

extern gboolean apply_agent_constraints(GListPtr resources);

extern void color_resource(resource_t *lh_resource,
			   GListPtr *colors,
			   GListPtr resources);

extern gboolean choose_node_from_list(color_t *color);

extern gboolean update_action_states(GListPtr actions);

extern gboolean shutdown_constraints(
	node_t *node, action_t *shutdown_op, GListPtr *ordering_constraints);

extern gboolean stonith_constraints(
	node_t *node, action_t *stonith_op, action_t *shutdown_op,
	GListPtr *ordering_constraints);

extern gboolean order_new(
	resource_t *lh_rsc, enum action_tasks lh_task, action_t *lh_action,
	resource_t *rh_rsc, enum action_tasks rh_task, action_t *rh_action,
	enum con_strength strength, GListPtr *ordering_constraints);


extern gboolean process_colored_constraints(resource_t *rsc);
extern void graph_element_from_action(action_t *action, crm_data_t **graph);

extern color_t *no_color;
extern int      max_valid_nodes;
extern int      order_id;
extern int      action_id;
extern gboolean stonith_enabled;
extern gboolean have_quorum;
extern no_quorum_policy_t no_quorum_policy;
extern gboolean symmetric_cluster;
extern GListPtr agent_defaults;
extern const char* transition_timeout;
extern int num_synapse;
extern int color_id;
extern char *dc_uuid;

#endif


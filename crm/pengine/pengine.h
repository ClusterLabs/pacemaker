/* $Id: pengine.h,v 1.20 2004/06/02 18:41:40 andrew Exp $ */
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
	ignore,
	must,
	should,
	should_not,
	must_not,
	startstop
};

enum con_modifier {
	modifier_none,
	set,
	inc,
	dec
};

enum action_tasks {
	no_action,
	stop_rsc,
	start_rsc,
	shutdown_crm,
	stonith_op
};

enum action_order {
	dontcare,
	before,
	after
};

struct node_shared_s { 
		char	*id; 
		gboolean online;
		gboolean unclean;
		gboolean shutdown;
		GListPtr running_rsc; // resource_t*
		
		GHashTable *attrs;     // char* => char*
		enum node_type type;
}; 

struct node_s { 
		float	weight; 
		gboolean fixed;
		struct node_shared_s *details;
}; 
 
struct color_shared_s {
		int id; 
		GListPtr candidate_nodes; // node_t*
		node_t *chosen_node; 
};

struct color_s { 
		int id; 
		struct color_shared_s *details;
		float local_weight;
};

struct rsc_to_rsc_s { 
		char		*id;
		resource_t	*rsc_lh; 

//		gboolean	is_placement;
		resource_t	*rsc_rh; 
		enum con_strength strength;
};

struct rsc_to_node_s { 
		char		*id;
		resource_t	*rsc_lh; 

		float		weight;
		GListPtr node_list_rh; // node_t*
		enum con_modifier modifier;
};

struct resource_s { 
		char *id; 
		xmlNodePtr xml; 
		int priority; 
		node_t *cur_node; 

		gboolean runnable;
		gboolean provisional; 

		action_t *stop;
		action_t *start;
		
		GListPtr candidate_colors; // color_t*
		GListPtr allowed_nodes;    // node_t*
		GListPtr node_cons;        // rsc_to_node_t* 
		GListPtr rsc_cons;         // resource_t*

		color_t *color;
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
		
		GListPtr actions_before; // action_warpper_t*
		GListPtr actions_after;  // action_warpper_t*
};

struct order_constraint_s 
{
		int id;
		action_t *lh_action;
		action_t *rh_action;
		enum con_strength strength;
//		enum action_order order;
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

extern gboolean stage6(GListPtr *actions,
		       GListPtr *action_constraints,
		       GListPtr stonith,
		       GListPtr shutdown);

extern gboolean stage7(GListPtr resources,
		       GListPtr actions,
		       GListPtr action_constraints,
		       GListPtr *action_sets);

extern gboolean stage8(GListPtr action_sets, xmlNodePtr *graph);

extern gboolean summary(GListPtr resources);

extern gboolean pe_input_dispatch(IPC_Channel *sender, void *user_data);

extern void pe_free_nodes(GListPtr nodes);
extern void pe_free_colors(GListPtr colors);
extern void pe_free_rsc_to_rsc(rsc_to_rsc_t *cons);
extern void pe_free_rsc_to_node(rsc_to_node_t *cons);
extern void pe_free_shallow(GListPtr alist);
extern void pe_free_shallow_adv(GListPtr alist, gboolean with_data);
extern void pe_free_resources(GListPtr resources);
extern void pe_free_actions(GListPtr actions);

extern gboolean pe_debug;
extern gboolean pe_debug_saved;
extern color_t *no_color;

#define pdebug_action(x) if(pe_debug) {		\
		x;				\
	}

#define pdebug(x...) if(pe_debug) {		\
		cl_log(LOG_DEBUG, x);		\
	}

#define pe_debug_on()  pe_debug_saved = pe_debug; pe_debug = TRUE;
#define pe_debug_off() pe_debug_saved = pe_debug; pe_debug = FALSE;
#define pe_debug_restore() pe_debug = pe_debug_saved;

#define safe_val(def, x,y)          (x?x->y:def)
#define safe_val3(def, t,u,v)       (t?t->u?t->u->v:def:def)
#define safe_val4(def, t,u,v,w)     (t?t->u?t->u->v?t->u->v->w:def:def:def)
#define safe_val5(def, t,u,v,w,x)   (t?t->u?t->u->v?t->u->v->w?t->u->v->w->x:def:def:def:def)
#define safe_val6(def, t,u,v,w,x,y) (t?t->u?t->u->v?t->u->v->w?t->u->v->w->x?t->u->v->w->x->y:def:def:def:def:def)
#define safe_val7(def, t,u,v,w,x,y,z) (t?t->u?t->u->v?t->u->v->w?t->u->v->w->x?t->u->v->w->x->y?t->u->v->w->x->y->z:def:def:def:def:def:def)

#endif

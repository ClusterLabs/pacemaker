#ifndef PENGINE__H
#define PENGINE__H

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
		GSListPtr running_rsc; // resource_t*
		
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
		GSListPtr candidate_nodes; // node_t*
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
		GSListPtr node_list_rh; // node_t*
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
		
		GSListPtr candidate_colors; // color_t*
		GSListPtr allowed_nodes;    // node_t*
		GSListPtr node_cons;        // rsc_to_node_t* 
		GSListPtr rsc_cons;         // resource_t*

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
		
		GSListPtr actions_before; // action_warpper_t*
		GSListPtr actions_after;  // action_warpper_t*
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
		       GSListPtr *nodes,
		       GSListPtr *rscs,
		       GSListPtr *cons,
		       GSListPtr *actions, GSListPtr *action_constraints,
		       GSListPtr *stonith_list, GSListPtr *shutdown_list);

extern gboolean stage1(GSListPtr node_constraints,
		       GSListPtr nodes,
		       GSListPtr resources);

extern gboolean stage2(GSListPtr sorted_rscs,
		       GSListPtr sorted_nodes,
		       GSListPtr *colors);

extern gboolean stage3(GSListPtr colors);

extern gboolean stage4(GSListPtr colors);

extern gboolean stage5(GSListPtr resources);

extern gboolean stage6(GSListPtr *actions,
		       GSListPtr *action_constraints,
		       GSListPtr stonith,
		       GSListPtr shutdown);

extern gboolean stage7(GSListPtr resources,
		       GSListPtr actions,
		       GSListPtr action_constraints,
		       GSListPtr *action_sets);

extern gboolean stage8(GSListPtr action_sets, xmlNodePtr *graph);

extern gboolean summary(GSListPtr resources);

extern gboolean pe_input_dispatch(IPC_Channel *sender, void *user_data);

extern void pe_free_nodes(GSListPtr nodes);
extern void pe_free_colors(GSListPtr colors);
extern void pe_free_rsc_to_rsc(rsc_to_rsc_t *cons);
extern void pe_free_rsc_to_node(rsc_to_node_t *cons);
extern void pe_free_shallow(GSListPtr alist);
extern void pe_free_shallow_adv(GSListPtr alist, gboolean with_data);
extern void pe_free_resources(GSListPtr resources);
extern void pe_free_actions(GSListPtr actions);

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

typedef GSList* GSListPtr;


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
		gboolean failed;
		gboolean complete;

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

extern gboolean stage0(xmlNodePtr cib);
extern gboolean stage1(GSListPtr node_constraints,
		       GSListPtr nodes,
		       GSListPtr resources);
extern gboolean stage2(GSListPtr sorted_rsc, 
		       GSListPtr sorted_nodes,         
		       GSListPtr operations);
extern gboolean stage3(void);
extern gboolean stage4(GSListPtr colors);
extern gboolean stage5(GSListPtr resources);
extern gboolean stage6(GSListPtr resources,
		       GSListPtr actions,
		       GSListPtr action_constraints);
extern gboolean stage7(GSListPtr resources);
extern gboolean summary(GSListPtr resources);

extern GSListPtr rsc_list; 
extern GSListPtr node_list;
extern GSListPtr rsc_cons_list;
extern GSListPtr node_cons_list;
extern GSListPtr action_list;
extern GSListPtr action_cons_list;
extern GSListPtr colors;
extern GSListPtr stonith_list;
extern GSListPtr shutdown_list;
extern GSListPtr action_set_list;

extern void print_node(const char *pre_text,
		       node_t *node,
		       gboolean details);

extern void print_resource(const char *pre_text,
			   resource_t *rsc,
			   gboolean details);

extern void print_rsc_to_node(const char *pre_text,
			      rsc_to_node_t *cons,
			      gboolean details);

extern void print_rsc_to_rsc(const char *pre_text,
			     rsc_to_rsc_t *cons,
			     gboolean details);

extern void print_color(const char *pre_text,
			color_t *color,
			gboolean details);

extern void print_color_details(const char *pre_text,
				struct color_shared_s *color,
				gboolean details);

extern void print_action(const char *pre_text,
			 action_t *action,
			 gboolean details);

extern const char *contype2text(enum con_type type);
extern const char *strength2text(enum con_strength strength);
extern const char *modifier2text(enum con_modifier modifier);
extern const char *task2text(enum action_tasks task);

extern action_t *action_new(int id, resource_t *rsc, enum action_tasks task);

#define slist_iter(w, x, y, z, a) for(z = 0; z < g_slist_length(y);  z++) { \
				         x *w = (x*)g_slist_nth_data(y, z); \
					 a;				    \
				  }

extern gboolean pe_debug;
extern gboolean pe_debug_saved;
#define pdebug_action(x) if(pe_debug) {		\
		x;				\
	}

#define pdebug(x...) if(pe_debug) {		\
		cl_log(LOG_DEBUG, x);		\
	}

#define pe_debug_on()  pe_debug_saved = pe_debug; pe_debug = TRUE;
#define pe_debug_off() pe_debug_saved = pe_debug; pe_debug = FALSE;
#define pe_debug_restore() pe_debug = pe_debug_saved;

#define safe_val(def, x,y)          (x==NULL?def:x->y)
#define safe_val3(def, t,u,v)       safe_val(def, safe_val(NULL, t,u),v)
#define safe_val4(def, t,u,v,w)     safe_val(def, safe_val(NULL, safe_val(NULL, t,u),v),w)
#define safe_val5(def, t,u,v,w,x)   safe_val(def, safe_val(NULL, safe_val(NULL, safe_val(NULL, t,u),v),w),x)
#define safe_val6(def, t,u,v,w,x,y) safe_val(def, safe_val(NULL, safe_val(NULL, safe_val(NULL, safe_val(NULL, t,u),v),w),x),y)
#define safe_val7(def, t,u,v,w,x,y,z) safe_val(def, safe_val(NULL, safe_val(NULL, safe_val(NULL, safe_val(NULL, safe_val(NULL, t,u),v),w),x),y),z)

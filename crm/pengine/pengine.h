typedef GSList* GSListPtr;


typedef struct node_s node_t;
typedef struct color_s color_t;
typedef struct rsc_constraint_s rsc_constraint_t;
typedef struct resource_s resource_t;

enum con_type {
	none,
	rsc_to_rsc,
	rsc_to_node,
	base_weight
};

enum con_strength {
	must,
	should,
	should_not,
	must_not
};

enum con_modifier {
  modifier_none,
	set,
	inc,
	dec
};
  
struct node_s { 
		char	*id; 
		float	weight; 
		gboolean fixed; 
}; 
 
struct color_shared_s {
		int id; 
		GSListPtr candidate_nodes; 
		node_t *chosen_node; 
};


struct color_s { 
		int id; 
		struct color_shared_s *details;
		float local_weight;
}; 

 
struct rsc_constraint_s { 
		char		*id;
		resource_t	*rsc_lh; 
		enum con_type type;

		// rsc_to_rsc
		gboolean	is_placement;
		resource_t	*rsc_rh; 
		enum con_strength strength;

		// rsc_to_node
		float		weight;
		node_t	*node_rh; 
		enum con_modifier modifier;
}; 

struct resource_s { 
		char *id; 
		xmlNodePtr xml; 
		int priority; 
		GSListPtr candidate_colors; 
		color_t *color; 
		gboolean provisional; 
		GSListPtr allowed_nodes; 
		GSListPtr constraints; 
}; 

extern gboolean stage1(xmlNodePtr cib);
extern gboolean stage2(GSListPtr sorted_rsc, 
		 GSListPtr sorted_nodes,         
		 GSListPtr operations);
extern gboolean stage3(GSListPtr colors);

extern GSListPtr rsc_list; 
extern GSListPtr node_list;
extern GSListPtr cons_list;
extern GSListPtr colors;
extern GSListPtr stonith_list;
extern color_t *current_color;

#define slist_iter(w, x, y, z, a) for(z = 0; z < g_slist_length(y);  z++) { \
				         x *w = (x*)g_slist_nth_data(y, z); \
					 a;				    \
				  }
extern void print_node(node_t *node);
extern void print_resource(resource_t *rsc, gboolean details);
extern void print_cons(rsc_constraint_t *cons, gboolean details);
extern void print_color(color_t *color, gboolean details);
extern void print_color_details(struct color_shared_s *color, gboolean details);

extern const char *contype2text(enum con_type type);
extern const char *strength2text(enum con_strength strength);
extern const char *modifier2text(enum con_modifier modifier);

#ifndef PE_UTILS__H
#define PE_UTILS__H


// General utilities
extern resource_t *pe_find_resource(GSListPtr rsc_list, const char *id_rh);

extern action_t *action_new(int id, resource_t *rsc, enum action_tasks task);


// Constraint helper functions
extern rsc_to_rsc_t *invert_constraint(rsc_to_rsc_t *constraint);

extern rsc_to_node_t *copy_constraint(rsc_to_node_t *constraint);

// Color helper functions
extern void add_color_to_rsc(resource_t *rsc, color_t *color);

extern color_t *find_color(GSListPtr candidate_colors, color_t *other_color);

extern color_t *create_color(GSListPtr *colors,
			     GSListPtr nodes,
			     GSListPtr resources);

// Node helper functions
extern gboolean filter_nodes(resource_t *rsc);

extern node_t *pe_find_node(GSListPtr node_list, const char *id);

extern node_t *node_copy(node_t *this_node) ;

extern node_t *find_list_node(GSListPtr list, const char *id);


// Binary like operators for lists of nodes
extern GSListPtr node_list_dup(GSListPtr list1);

extern GSListPtr node_list_and(GSListPtr list1, GSListPtr list2);

extern GSListPtr node_list_xor(GSListPtr list1, GSListPtr list2);

extern GSListPtr node_list_minus(GSListPtr list1, GSListPtr list2);

extern gboolean node_list_eq(GSListPtr list1, GSListPtr list2);



// For creating the transition graph
extern xmlNodePtr action2xml(action_t *action);

// Printing functions for debug
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

// Sorting functions
extern gint sort_rsc_priority(gconstpointer a, gconstpointer b);
extern gint sort_cons_strength(gconstpointer a, gconstpointer b);
extern gint sort_color_weight(gconstpointer a, gconstpointer b);
extern gint sort_node_weight(gconstpointer a, gconstpointer b);

// enum 2 text functions (mostly used by print_*)
extern const char *contype2text(enum con_type type);
extern const char *strength2text(enum con_strength strength);
extern const char *modifier2text(enum con_modifier modifier);
extern const char *task2text(enum action_tasks task);

#endif


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
extern xmlNodePtr action2xml(action_t *action);

extern color_t *create_color(GSListPtr *colors,
			     GSListPtr nodes,
			     GSListPtr resources);

extern void add_color_to_rsc(resource_t *rsc, color_t *color);

gint sort_rsc_priority(gconstpointer a, gconstpointer b);
gint sort_cons_strength(gconstpointer a, gconstpointer b);
gint sort_color_weight(gconstpointer a, gconstpointer b);
gint sort_node_weight(gconstpointer a, gconstpointer b);

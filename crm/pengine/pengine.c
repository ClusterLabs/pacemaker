#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>
#include <crm/cib.h>
#include <glib.h>
#include <libxml/tree.h>

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


color_t *create_color(GSListPtr nodes, int new_id);
void add_color_to_rsc(resource_t *rsc, color_t *color);

gint sort_rsc_priority(gconstpointer a, gconstpointer b);
gint sort_cons_strength(gconstpointer a, gconstpointer b);
gint sort_color_weight(gconstpointer a, gconstpointer b);
gint sort_node_weight(gconstpointer a, gconstpointer b);

gboolean stage1(xmlNodePtr cib);
gboolean stage2(GSListPtr sorted_rsc, 
		 GSListPtr sorted_nodes,         
		 GSListPtr operations);
gboolean stage3(GSListPtr colors);

gboolean unpack_constraints(xmlNodePtr constraints);
gboolean unpack_resources(xmlNodePtr resources);
gboolean unpack_nodes(xmlNodePtr nodes);
gboolean unpack_status(xmlNodePtr status);

gboolean apply_node_constraints(GSListPtr constraints, 
				GSListPtr resources,
				GSListPtr nodes);
void color_resource(resource_t *lh_resource, 
		    GSListPtr sorted_rsc,
		    GSListPtr colors);

gboolean is_active(rsc_constraint_t *cons);
rsc_constraint_t *invert_constraint(rsc_constraint_t *constraint);
gboolean filter_nodes(GSListPtr rsc_list);
color_t *find_color(GSListPtr candidate_colors, color_t *other_color);
resource_t *pe_find_resource(GSListPtr rsc_list, const char *id_rh);
node_t *pe_find_node(GSListPtr node_list, resource_t *rsc, const char *id);
gboolean choose_node_from_list(GSListPtr colors,
			       color_t *color,
			       GSListPtr nodes);

GSListPtr node_list_dup(GSListPtr list1);
GSListPtr node_list_and(GSListPtr list1, GSListPtr list2);
GSListPtr node_list_xor(GSListPtr list1, GSListPtr list2);
GSListPtr node_list_minus(GSListPtr list1, GSListPtr list2);
gboolean node_list_eq(GSListPtr list1, GSListPtr list2);
node_t *node_copy(node_t *this_node) ;

GSListPtr rsc_list = NULL; 
GSListPtr node_list = NULL;
GSListPtr cons_list = NULL;
GSListPtr colors = NULL;
GSListPtr stonith_list = NULL;
color_t *current_color = NULL;

gboolean
stage1(xmlNodePtr cib)
{
	xmlNodePtr cib_nodes = get_object_root("nodes", cib);
	xmlNodePtr cib_resources = get_object_root("resources", cib);
	xmlNodePtr cib_constraints = get_object_root("constraints", cib);
	xmlNodePtr cib_status = get_object_root("status", cib);

	rsc_list = g_slist_alloc();
	node_list = g_slist_alloc();
	cons_list = g_slist_alloc();
	colors = g_slist_alloc();
	stonith_list = g_slist_alloc();

	unpack_nodes(cib_nodes);
	unpack_resources(cib_resources);
	unpack_status(cib_status);
	unpack_constraints(cib_constraints);
	apply_node_constraints(cons_list, node_list, rsc_list);
	filter_nodes(rsc_list);

	return TRUE;
} 

void
color_resource(resource_t *lh_resource, GSListPtr sorted_rsc, GSListPtr colors)
{
  int lpc = 0;
  
	g_slist_sort(lh_resource->constraints, sort_cons_strength);

	//------ Pre-processing
	for(; lpc < g_slist_length(lh_resource->constraints); lpc++) {
	  rsc_constraint_t *constraint = (rsc_constraint_t*)g_slist_nth_data(lh_resource->constraints, lpc);
		color_t *other_color = NULL;
		color_t *local_color = NULL;

		if(constraint->is_placement == FALSE) {
			continue;
		}

		other_color = constraint->rsc_rh->color;
		local_color = find_color(lh_resource->candidate_colors, other_color);
		switch(constraint->strength) {
			case must:
				/// not yet...
				break;

				// x * should * should_not = x
			case should:
				if(constraint->rsc_rh->provisional == FALSE) {
					local_color->local_weight = 
					  local_color->local_weight * 2.0;
				}
				break;
			case should_not:
				if(constraint->rsc_rh->provisional == FALSE) {
					local_color->local_weight = 
					  local_color->local_weight * 0.5;
				}
				break;
			case must_not:
				/* should be redundant
				   if(constraint->rsc_rh->provisional == FALSE) {
				   g_slist_remove(lh_resource->candidate_colors, local_color);
				   }
				*/
				break;
			default:
				// error
				break;
		}

	}

	// filter out nodes with a negative weight
	filter_nodes(lh_resource->allowed_nodes);
  
	/* Choose a color from the candidates or,
	 *  create a new one if no color is suitable 
	 * (this may need modification pending further napkin drawings)
	 */
	g_slist_sort(lh_resource->candidate_colors, sort_color_weight);
	for(lpc = 0; 
	    lpc < g_slist_length(lh_resource->candidate_colors)
		    && lh_resource->provisional;
	    lpc++) {
	  color_t *this_color = (color_t*)g_slist_nth_data(lh_resource->candidate_colors, lpc);
		GSListPtr intersection = node_list_and(this_color->details->candidate_nodes, 
						       lh_resource->allowed_nodes);
    
		if(g_slist_length(intersection) != 0) {
			// TODO: merge node weights
			g_slist_free(this_color->details->candidate_nodes);
			this_color->details->candidate_nodes = intersection;
			lh_resource->color = this_color;
			lh_resource->provisional = FALSE;
		}
	}
  
	if(lh_resource->provisional) {
		// Create new color
		current_color = create_color(lh_resource->allowed_nodes, 
					     current_color->id + 1);
	}

	//------ Post-processing
	for(lpc = 0; lpc < g_slist_length(lh_resource->constraints); lpc++) {
	  rsc_constraint_t *constraint = (rsc_constraint_t*)g_slist_nth_data(lh_resource->constraints, lpc);
		color_t *local_color = lh_resource->color;
		color_t *other_color = NULL;

		if(constraint->is_placement == FALSE) {
			continue;
		}
    
		other_color = find_color(constraint->rsc_rh->candidate_colors,
					 local_color);

		switch(constraint->strength) {
			case must:
				if(constraint->rsc_rh->provisional == TRUE) {
					constraint->rsc_rh->color = other_color;
					constraint->rsc_rh->provisional = FALSE;
					color_resource(constraint->rsc_rh, sorted_rsc, colors);
				}
				// else check for error
				break;

				// x * should * should_not = x
			case should:
				/* will be taken care of in the pre-processing stage of coloring rsc_rh
				   if(constraint->rsc_rh->provisional == TRUE) {
				   other_color->weight = other_color->weight * 2.0;
				   }
				*/
				break;
			case should_not:
				/* will be taken care of in the pre-processing stage of coloring rsc_rh
				   if(constraint->rsc_rh->provisional == TRUE) {
				   other_color->weight = other_color->weight * 0.5;
				   }
				*/
				break;
			case must_not:
				/* will be taken care of in the pre-processing stage of coloring rsc_rh 
				   if(constraint->rsc_rh->provisional == FALSE) {
				   g_slist_remove(constraint->rsc_rh->candidate_colors, other_color);
				   }
				*/
				if(constraint->rsc_rh->provisional == TRUE) {
					// check for error
				}
				break;
			default:
				// error
				break;
		}

	}

}


gboolean
stage2(GSListPtr sorted_rsc, 
       GSListPtr sorted_nodes, 
       GSListPtr operations)
{

  int lpc = 0; 
	// Set initial color
	// Set color.candidate_nodes = all active nodes
	current_color = cl_malloc(sizeof(color_t));

	current_color->id = 0;
	current_color->local_weight = 1.0;
	current_color->details->chosen_node = NULL; 
	current_color->details->candidate_nodes = node_list_dup(sorted_nodes);
	g_slist_append(colors, current_color);
  
	// Set resource.color = color (all resources)
	// Set resource.provisional = TRUE (all resources)
	for(lpc = 0; lpc < g_slist_length(sorted_rsc); lpc++) {
	  resource_t *this_resource = (resource_t*)g_slist_nth_data(sorted_rsc, lpc);
		this_resource->color = current_color;
		g_slist_append(this_resource->candidate_colors, current_color);
		this_resource->provisional = TRUE;
	}
  
	// Take (next) highest resource
	for(lpc = 0; lpc < g_slist_length(sorted_rsc); lpc++) {
	  resource_t *lh_resource = (resource_t*)g_slist_nth_data(sorted_rsc, lpc);

		// if resource.provisional == FALSE, repeat 
		if(lh_resource->provisional == FALSE) {
			// already processed this resource
			continue;
		}
    
		color_resource(lh_resource, sorted_rsc, colors);
		// next resource
	}
	return TRUE;
}

#define color_n_nodes color_n->details->candidate_nodes
#define color_n_plus_1_nodes color_n->details->candidate_nodes

gboolean
stage3(GSListPtr colors)
{

  int lpc = 0;
	color_t *color_n = NULL;
	color_t *color_n_plus_1 = NULL;
	for(lpc = 0; lpc < g_slist_length(colors); lpc++) {
		color_n = color_n_plus_1;
		color_n_plus_1 = (color_t*)g_slist_nth_data(colors, lpc);

		if(color_n == NULL) {
			continue;
		}

		GSListPtr xor = node_list_xor(color_n_nodes,
					      color_n_plus_1_nodes);

		if(g_slist_length(xor) == 0) {
			choose_node_from_list(colors, color_n, xor);

		} else {
			GSListPtr minus = node_list_minus(color_n_nodes,
							  color_n_plus_1_nodes);
			if(g_slist_length(minus) == 0) {
				choose_node_from_list(colors, color_n, minus);

			} else {
				minus = node_list_minus(color_n_plus_1_nodes,
							color_n_nodes);
				choose_node_from_list(colors, color_n, minus);
			}
      
		}

		// chose last color
		choose_node_from_list(colors, 
				      color_n_plus_1, 
				      color_n_plus_1_nodes);
	}
	return TRUE;
	
}

gboolean
choose_node_from_list(GSListPtr colors, color_t *color, GSListPtr nodes)
{
	/*
	  1. Sort by weight
	  2. color.chosen_node = highest wieghted node 
	  3. remove color.chosen_node from all other colors
	*/
  int lpc = 0;
  g_slist_sort(nodes, sort_node_weight);
	color->details->chosen_node = (node_t*)g_slist_nth_data(nodes, 0);

	for(lpc = 0; lpc < g_slist_length(colors); lpc++) {
	  color_t *color_n = (color_t*)g_slist_nth_data(colors, lpc);
		g_slist_remove(color_n->details->candidate_nodes,
			       color->details->chosen_node);
	}
	return TRUE;
}

/* only for rsc_to_rsc constraints */
rsc_constraint_t *
invert_constraint(rsc_constraint_t *constraint) 
{
	rsc_constraint_t *inverted_con =
		cl_malloc(sizeof(rsc_constraint_t));

	inverted_con->id = cl_strdup(constraint->id);
	inverted_con->type = constraint->type;
	inverted_con->strength = constraint->strength;
	inverted_con->is_placement = constraint->is_placement;

	// swap the direction
	inverted_con->rsc_lh = constraint->rsc_rh;
	inverted_con->rsc_rh = constraint->rsc_lh;

	inverted_con->node_rh = NULL;
	inverted_con->modifier = modifier_none;
	inverted_con->weight = 0.0;
  
	return inverted_con;
}


/* are the contents of list1 and list2 equal */
/* nodes with weight < 0 are ignored */
gboolean
node_list_eq(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = g_slist_alloc();
 
	if(g_slist_length(list1) != g_slist_length(list2)) {
		return FALSE;
	}
  
	// do stuff
 
	return g_slist_length(result) != 0;
}

/* the intersection of list1 and list2 */
/* nodes with weight < 0 are ignored */
GSListPtr
node_list_and(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = g_slist_alloc();
	int lpc = 0;
	// merge node weights
	for(lpc = 0; lpc < g_slist_length(list2); lpc++) {
		node_t *new_node = NULL;
		node_t *other_node = NULL;
		node_t *node = (node_t*)g_slist_nth_data(list2, lpc);
		int index = g_slist_index(result, node);
		if(index < 0) {
			continue;
		}
		new_node = node_copy(node);
		other_node = (node_t*)g_slist_nth_data(list2, index);
		if(node->weight < 0 || other_node->weight < 0) {
			new_node->weight = -1;
		} else {
			new_node->weight = 
			  (node->weight + other_node->weight) / 2.0;
		}
		g_slist_append(result, new_node);
    
	}
  
 
	return result;
}

/* list1 - list2 */
/* nodes with weight < 0 are ignored */
GSListPtr
node_list_minus(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = g_slist_alloc();
	int lpc = 0;

	g_slist_concat(result, list1);

	for(lpc = 0; lpc < g_slist_length(list2); lpc++) {
	  node_t *node = (node_t*)g_slist_nth_data(list2, lpc);
		g_slist_remove(result, node);
	}
  
	return result;
}

/* list1 + list2 - (intersection of list1 and list2) */
/* nodes with weight < 0 are ignored */
GSListPtr
node_list_xor(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = g_slist_alloc();
	GSListPtr and = node_list_and(list1, list2);
	int lpc = 0;

	// merge weights
	g_slist_concat(result, list1);
	g_slist_concat(result, list2);

	for(lpc = 0; lpc < g_slist_length(and); lpc++) {
	  node_t *node = (node_t*)g_slist_nth_data(and, lpc);
		// twice, it may have been in list1 and list2
		g_slist_remove(result, node);    
		g_slist_remove(result, node);
	}
  
	return result;
}

GSListPtr 
node_list_dup(GSListPtr list1)
{
	GSListPtr result = g_slist_alloc();
	int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(list1); lpc++) {
	  node_t *this_node = (node_t*)g_slist_nth_data(list1, lpc);
		node_t *new_node = node_copy(this_node);
		g_slist_append(result, new_node);
	}
  
	return result;
}

node_t *
node_copy(node_t *this_node) 
{
	node_t *new_node = cl_malloc(sizeof(node_t));
	new_node->id     = cl_strdup(this_node->id); 
	new_node->weight = this_node->weight; 
	new_node->fixed  = this_node->fixed; 
  
	return new_node;
}

color_t *
create_color(GSListPtr nodes, int new_id)
{
  int lpc = 0;
	color_t *new_color = cl_malloc(sizeof(color_t));
	new_color->id = new_id;
	new_color->local_weight = 0; // not used here
	new_color->details = cl_malloc(sizeof(struct color_shared_s));
	new_color->details->chosen_node = NULL; 
	new_color->details->candidate_nodes = node_list_dup(nodes);
    
	g_slist_append(colors, new_color);      

	/*  Add any new color to the list of candidate_colors for
	 * resources that havent been decided yet 
	 */
	for(lpc = 0; lpc < g_slist_length(rsc_list); lpc++) {
	  resource_t *rh_resource = 
	    (resource_t*)g_slist_nth_data(rsc_list, lpc);
	  add_color_to_rsc(rh_resource, new_color);
	}

	return new_color;
}


void
add_color_to_rsc(resource_t *rsc, color_t *color)
{
	if(rsc->provisional) {
		color_t *color_copy = cl_malloc(sizeof(color_t));
		color_copy->id = color->id;
		color_copy->local_weight = 1.0; 
		color_copy->details = color->details;
		g_slist_append(rsc->candidate_colors, color_copy);
	}
}


gboolean
unpack_nodes(xmlNodePtr nodes)
{
	while(nodes != NULL) {
		const char *id = xmlGetProp(nodes, "id");
		if(id == NULL) {
			// error
			continue;
		}
		node_t *new_node = cl_malloc(sizeof(node_t));
		new_node->weight = 1.0;
		new_node->id = cl_strdup(id);
    
		g_slist_append(node_list, new_node);
    
		nodes = nodes->next;
	}
	g_slist_sort(node_list, sort_node_weight);
  
	return TRUE;
}


gboolean 
unpack_resources(xmlNodePtr resources)
{
	while(resources != NULL) {
		const char *id = xmlGetProp(resources, "id");
		const char *priority = xmlGetProp(resources, "priority");
		float priority_f = atof(priority);
		
		if(id == NULL) {
			// error
			continue;
		}
		resource_t *new_rsc = cl_malloc(sizeof(resource_t));
		new_rsc->xml = resources; // copy first 
		new_rsc->priority = priority_f; 
		new_rsc->candidate_colors = g_slist_alloc();
		new_rsc->color = NULL; 
		new_rsc->provisional = TRUE; 
		new_rsc->allowed_nodes = g_slist_alloc();    
		new_rsc->constraints = g_slist_alloc(); 
		new_rsc->id = cl_strdup(id);

		g_slist_append(rsc_list, new_rsc);

		resources = resources->next;
	}
	g_slist_sort(rsc_list, sort_rsc_priority);

	return TRUE;
}



gboolean 
unpack_constraints(xmlNodePtr constraints) 
{
	while(constraints != NULL) {
		const char *id = xmlGetProp(constraints, "id");
		if(id == NULL) {
			// error
			continue;
		}

		rsc_constraint_t *new_con =cl_malloc(sizeof(rsc_constraint_t));
		rsc_constraint_t *inverted_con = NULL;
		resource_t *rsc_lh = 
		  pe_find_resource(rsc_list, 
				   xmlGetProp(constraints, "rsc_id_1"));
		new_con->id = cl_strdup(id);

		if(safe_str_eq("rsc_to_rsc", constraints->name)) {
			new_con->type = rsc_to_rsc;
			const char *strength = xmlGetProp(constraints, "strength");
			if(safe_str_eq(strength, "must")) {
				new_con->strength = must;

			} else if(safe_str_eq(strength, "should")) {
				new_con->strength = should;

			} else if(safe_str_eq(strength, "should_not")) {
				new_con->strength = should_not;

			} else if(safe_str_eq(strength, "must_not")) {
				new_con->strength = must_not;
			} else {
				// error
			}

			const char *type = xmlGetProp(constraints, "type");
			if(safe_str_eq(type, "ordering")) {
				new_con->is_placement = FALSE;

			} else if (safe_str_eq(type, "placement")) {
				new_con->is_placement = TRUE;

			} else {
				// error
			}
      
			new_con->node_rh = NULL;
			resource_t *rsc_rh = pe_find_resource(rsc_list, xmlGetProp(constraints, "rsc_id_2"));
			new_con->rsc_rh = rsc_rh;

			inverted_con = invert_constraint(new_con);
			g_slist_insert_sorted(cons_list, new_con, sort_cons_strength);

		} else if(safe_str_eq("rsc_to_node", constraints->name)) {
			new_con->type = rsc_to_node;
			new_con->rsc_rh = NULL;
			new_con->node_rh = pe_find_node(node_list, rsc_lh, 
							xmlGetProp(constraints, "node_id"));

			if(new_con->node_rh->fixed) {
				// warning
			} else {
				const char *mod = xmlGetProp(constraints, "modifier");
				const char *weight = xmlGetProp(constraints, "weight");
				float weight_f = atof(weight);
				new_con->weight = weight_f;
	
				if(safe_str_eq(mod, "set")){
					new_con->modifier = set;
				} else if(safe_str_eq(mod, "inc")){
					new_con->modifier = inc;
				} else if(safe_str_eq(mod, "dec")){
					new_con->modifier = dec;
				} else {
					// error
				}
	
			}

			/* dont add it to the resource,
			 *  the information is in the resouce's node list
			 */

		} else {
			// error
		}

		g_slist_insert_sorted(cons_list, new_con, sort_cons_strength);

		constraints = constraints->next;
	}

	return TRUE;
}


gboolean 
apply_node_constraints(GSListPtr constraints, 
		       GSListPtr resources,
		       GSListPtr nodes)
{
  int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(constraints); lpc++) {
	  rsc_constraint_t *cons = (rsc_constraint_t *)g_slist_nth_data(constraints, lpc);
    
		// take "lifetime" into account
		if(is_active(cons) == FALSE) {
			// warning
			continue;
		}
    
		resource_t *rsc_lh = cons->rsc_lh;
		g_slist_append(rsc_lh->constraints, cons);

		if(cons->type == rsc_to_rsc) {
			// nothing 

		} else if(cons->type == rsc_to_node) {
			if(cons->node_rh->fixed) {
				// warning
			} else {
				switch(cons->modifier) {
					case set:
						cons->node_rh->weight = cons->weight;
						cons->node_rh->fixed = TRUE;
						break;
					case inc:
						cons->node_rh->weight += cons->weight;
						break;
					case dec:
						cons->node_rh->weight -= cons->weight;
						break;
				case modifier_none:
				  // warning
				  break;
				  
				}
			}

			/* dont add it to the resource,
			 *  the information is in the resouce's node list
			 */

		} else {
			// error
		}
	}
	return TRUE;
	
}

gboolean
filter_nodes(GSListPtr rsc_list)
{
  int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(rsc_list); lpc++) {
		resource_t *rsc = g_slist_nth_data(rsc_list, lpc);
		int lpc2 = 0;
		
		for(lpc2 = 0; lpc2 < g_slist_length(rsc->allowed_nodes); lpc2++) {
			node_t *node = g_slist_nth_data(rsc->allowed_nodes, lpc2);
			if(node->weight < 0.0) {
				g_slist_remove(rsc->allowed_nodes,node);
			}
      
		}
	}

	return TRUE;
}

resource_t *
pe_find_resource(GSListPtr rsc_list, const char *id_rh)
{
  int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(rsc_list); lpc++) {
		resource_t *rsc = g_slist_nth_data(rsc_list, lpc);
		if(safe_str_eq(rsc->id, id_rh)){
			return rsc;
		}
	}
	// error
	return NULL;
}
node_t *
pe_find_node(GSListPtr node_list, resource_t *rsc, const char *id)
{
  int lpc = 0;
  
	for(lpc = 0; lpc < g_slist_length(rsc->allowed_nodes); lpc++) {
		node_t *node = g_slist_nth_data(rsc->allowed_nodes, lpc);
		if(safe_str_eq(node->id, id)) {
			return node;
		}
	}
  
	for(lpc = 0; lpc < g_slist_length(node_list); lpc++) {
		node_t *node = g_slist_nth_data(node_list, lpc);
		if(safe_str_eq(node->id, id)) {      
			return node_copy(node);
		}
	}
	// error
	return NULL;
}

// remove nodes that are down, stopping
// create +ve rsc_to_node constraints between resources and the nodes they are running on
// anything else?
gboolean
unpack_status(xmlNodePtr status)
{

	while(status != NULL) {
		const char *id = xmlGetProp(status, "id");
		const char *state = xmlGetProp(status, "state");
		const char *exp_state = xmlGetProp(status, "exp_state");
		xmlNodePtr lrm_state = find_xml_node(status, "lrm");
		lrm_state = find_xml_node(lrm_state, "lrm_resource");
		lrm_state = find_xml_node(lrm_state, "rsc_state");

		if(id == NULL) {
			// error
			continue;
		}

		if(safe_str_eq(exp_state, "active")
		   && safe_str_eq(state, "active")) {
			// process resource, make +ve preference

			while(lrm_state != NULL) {
				const char *rsc_id = xmlGetProp(lrm_state, "rsc_id");
				const char *node_id = xmlGetProp(lrm_state, "node_id");
				const char *rsc_state = xmlGetProp(lrm_state, "rsc_state");

				if((safe_str_eq(rsc_state, "starting"))
				   || (safe_str_eq(rsc_state, "started"))) {

					rsc_constraint_t *new_cons = cl_malloc(sizeof(rsc_constraint_t));
					new_cons->id = cl_strdup(""); // genereate one
					new_cons->rsc_lh = pe_find_resource(rsc_list, rsc_id);
					new_cons->type = rsc_to_node;
					new_cons->weight = 100.0;
					new_cons->node_rh = pe_find_node(node_list, new_cons->rsc_lh, node_id);
					new_cons->modifier = inc;
	 
					g_slist_append(cons_list, new_cons);

				} else if(safe_str_eq(rsc_state, "stop_fail")) {
					// do soemthing
				} // else no preference

				lrm_state = lrm_state->next;
			}
		} else {
			// remove node from contention
			node_t *node = NULL;
			int lpc = 0;
			for(; lpc < g_slist_length(node_list); lpc++) {
			  node_t *node = (node_t*)g_slist_nth_data(node_list, lpc);
				if(safe_str_eq(node->id, id)){
					node->weight = -1;
					node->fixed = TRUE;
				}
			}
      
			if(safe_str_eq(exp_state, "down") 
			   && safe_str_eq(state, "shutdown")) {
				// create shutdown req
			} else if(safe_str_eq(exp_state, "active")
				  && safe_str_neq(state, "active")) {
				// create stonith
				// mark unclean
				// remove any running resources from being allocated
			}
      
			if(safe_str_eq(state, "unclean")) {
				g_slist_append(stonith_list, node);
			}

		}

		status = status->next;
	}
	g_slist_sort(cons_list, sort_cons_strength);

	return TRUE;
	
}


color_t *
find_color(GSListPtr candidate_colors, color_t *other_color)
{
  // figure out what this does
  return NULL;
}

gboolean
is_active(rsc_constraint_t *cons)
{
  return TRUE;
}

gint sort_rsc_priority(gconstpointer a, gconstpointer b)
{
  resource_t *resource1 = (resource_t*)a;
  resource_t *resource2 = (resource_t*)b;
  
  if(resource1->priority > resource2->priority)
    return 1;

  if(resource1->priority < resource2->priority)
    return -1;

  return 0;
}

gint sort_cons_strength(gconstpointer a, gconstpointer b)
{
  rsc_constraint_t *rsc_constraint1 = (rsc_constraint_t*)a;
  rsc_constraint_t *rsc_constraint2 = (rsc_constraint_t*)b;
  
  if(rsc_constraint1->strength > rsc_constraint2->strength)
    return 1;

  if(rsc_constraint1->strength < rsc_constraint2->strength)
    return -1;
  return 0;
}

gint sort_color_weight(gconstpointer a, gconstpointer b)
{
  color_t *color1 = (color_t*)a;
  color_t *color2 = (color_t*)b;
  
  if(color1->weight > color2->weight)
    return 1;

  if(color1->weight < color2->weight)
    return -1;

  return 0;
}

gint sort_node_weight(gconstpointer a, gconstpointer b)
{
  node_t *node1 = (node_t*)a;
  node_t *node2 = (node_t*)b;
  
  if(node1->weight > node2->weight)
    return 1;

  if(node1->weight < node2->weight)
    return -1;
  

  return 0;
}


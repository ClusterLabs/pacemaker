#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>
#include <crm/cib.h>
#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>

color_t *create_color(GSListPtr nodes);
void add_color_to_rsc(resource_t *rsc, color_t *color);

gint sort_rsc_priority(gconstpointer a, gconstpointer b);
gint sort_cons_strength(gconstpointer a, gconstpointer b);
gint sort_color_weight(gconstpointer a, gconstpointer b);
gint sort_node_weight(gconstpointer a, gconstpointer b);


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
gboolean filter_nodes(resource_t *rsc);
color_t *find_color(GSListPtr candidate_colors, color_t *other_color);
resource_t *pe_find_resource(GSListPtr rsc_list, const char *id_rh);
node_t *pe_find_node(GSListPtr node_list, const char *id);
gboolean choose_node_from_list(GSListPtr colors,
			       color_t *color,
			       GSListPtr nodes);
rsc_constraint_t *copy_constraint(rsc_constraint_t *constraint);

GSListPtr node_list_dup(GSListPtr list1);
GSListPtr node_list_and(GSListPtr list1, GSListPtr list2);
GSListPtr node_list_xor(GSListPtr list1, GSListPtr list2);
GSListPtr node_list_minus(GSListPtr list1, GSListPtr list2);
gboolean node_list_eq(GSListPtr list1, GSListPtr list2);
node_t *node_copy(node_t *this_node) ;
node_t *find_list_node(GSListPtr list, const char *id);

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

/* 	rsc_list = g_slist_alloc(); */
/* 	node_list = create_slist(); */
/* 	cons_list = g_slist_alloc(); */
/* 	colors = g_slist_alloc(); */
/* 	stonith_list = g_slist_alloc(); */

	unpack_nodes(cib_nodes->children);
	unpack_resources(cib_resources->children);
	unpack_status(cib_status);
	unpack_constraints(cib_constraints->children);
	apply_node_constraints(cons_list, node_list, rsc_list);

	// filter_nodes(rsc_list);

	return TRUE;
} 

void
color_resource(resource_t *lh_resource, GSListPtr sorted_rsc, GSListPtr colors)
{
	int lpc = 0;

	cl_log(LOG_DEBUG, "Coloring resource");
	print_resource(lh_resource, FALSE);
	
	lh_resource->constraints = g_slist_sort(lh_resource->constraints, sort_cons_strength);

	cl_log(LOG_DEBUG, "Pre-processing");
	//------ Pre-processing
	for(; lpc < g_slist_length(lh_resource->constraints); lpc++) {
		rsc_constraint_t *constraint = (rsc_constraint_t*)g_slist_nth_data(lh_resource->constraints, lpc);
		color_t *other_color = NULL;
		color_t *local_color = NULL;
		cl_log(LOG_DEBUG, "Processing constraint %d", lpc);
		print_cons(constraint, FALSE);
		if(constraint->is_placement == FALSE) {
			continue;
		}

		if(constraint->type != rsc_to_rsc) {
			continue;
		}
		if(constraint->rsc_rh == NULL) {
			cl_log(LOG_ERR, "rsc_rh was NULL for %s", constraint->id);
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
				   if(constraint->rsc_rh->provisional == FALSE) {
					   lh_resource->candidate_colors = g_slist_remove(lh_resource->candidate_colors, local_color);
				   }
				break;
			default:
				// error
				break;
		}

	}

	// filter out nodes with a negative weight
	filter_nodes(lh_resource);
  
	/* Choose a color from the candidates or,
	 *  create a new one if no color is suitable 
	 * (this may need modification pending further napkin drawings)
	 */
	lh_resource->candidate_colors = g_slist_sort(lh_resource->candidate_colors, sort_color_weight);
	cl_log(LOG_DEBUG, "Choose a color from %d possibilities", g_slist_length(lh_resource->candidate_colors ));
	for(lpc = 0; 
	    lpc < g_slist_length(lh_resource->candidate_colors)
		    && lh_resource->provisional;
	    lpc++) {
		color_t *this_color = (color_t*)g_slist_nth_data(lh_resource->candidate_colors, lpc);
		print_color(this_color, FALSE);
		GSListPtr intersection = node_list_and(this_color->details->candidate_nodes, 
						       lh_resource->allowed_nodes);

		cl_log(LOG_DEBUG, "Checking the node intersection %d", g_slist_length(intersection));

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
		cl_log(LOG_DEBUG, "Create a new color");
		current_color = create_color(lh_resource->allowed_nodes);
		lh_resource->color = current_color;
		lh_resource->provisional = FALSE;
	}

	cl_log(LOG_DEBUG, "Post-processing");

	//------ Post-processing

	for(lpc = 0; lpc < g_slist_length(lh_resource->constraints); lpc++) {
		rsc_constraint_t *constraint = (rsc_constraint_t*)g_slist_nth_data(lh_resource->constraints, lpc);
		color_t *local_color = lh_resource->color;
		color_t *other_color = NULL;

		if(constraint->is_placement == FALSE) {
			continue;
		} else if(constraint->type != rsc_to_rsc) {
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

	cl_log(LOG_DEBUG, "setup");
	current_color = create_color(node_list);
  
	// Set resource.color = color (all resources)
	// Set resource.provisional = TRUE (all resources)
	for(lpc = 0; lpc < g_slist_length(sorted_rsc); lpc++) {
		resource_t *this_resource = (resource_t*)g_slist_nth_data(sorted_rsc, lpc);
		this_resource->color = current_color;
		this_resource->provisional = TRUE;
	}

	cl_log(LOG_DEBUG, "initialized resources to default color");
  
	// Take (next) highest resource
	for(lpc = 0; lpc < g_slist_length(sorted_rsc); lpc++) {
		cl_log(LOG_DEBUG, "Processing resource %d", lpc);
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
#define color_n_plus_1_nodes color_n_plus_1->details->candidate_nodes

gboolean
stage3(GSListPtr colors)
{

	int lpc = 0;
	color_t *color_n = NULL;
	color_t *color_n_plus_1 = NULL;
	for(lpc = 0; lpc < g_slist_length(colors); lpc++) {
		color_n = color_n_plus_1;
		color_n_plus_1 = (color_t*)g_slist_nth_data(colors, lpc);

		cl_log(LOG_DEBUG, "Choose node for...");
		print_color(color_n, FALSE);
		print_color(color_n_plus_1, FALSE);
		
		if(color_n == NULL) {
			continue;
		}


		GSListPtr xor = node_list_xor(color_n_nodes,
					      color_n_plus_1_nodes);
		GSListPtr minus = node_list_minus(color_n_nodes,
						  color_n_plus_1_nodes);

		if(g_slist_length(xor) == 0 || g_slist_length(minus) == 0) {
			cl_log(LOG_DEBUG, "Choose any node from our list");
			choose_node_from_list(colors, color_n, color_n_nodes);

		} else {
			cl_log(LOG_DEBUG, "Choose a node not in n+1");
			choose_node_from_list(colors, color_n, minus);      
		}

	}

	// chose last color
	if(color_n_plus_1 != NULL) {
		cl_log(LOG_DEBUG, "Choose node for last color...");
		print_color(color_n, FALSE);
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
	nodes = g_slist_sort(nodes, sort_node_weight);
	color->details->chosen_node = (node_t*)g_slist_nth_data(nodes, 0);

	if(color->details->chosen_node == NULL) {
		cl_log(LOG_ERR, "Could not allocate a node for color %d", color->id);
		return FALSE;
	}
	
	for(lpc = 0; lpc < g_slist_length(colors); lpc++) {
		color_t *color_n = (color_t*)g_slist_nth_data(colors, lpc);
		node_t *other_node = pe_find_node(color_n->details->candidate_nodes,
						    color->details->chosen_node->id);
		color_n->details->candidate_nodes =
			g_slist_remove(color_n->details->candidate_nodes,
				       other_node);
	}
	return TRUE;
}

/* only for rsc_to_rsc constraints */
rsc_constraint_t *
invert_constraint(rsc_constraint_t *constraint) 
{
	cl_log(LOG_DEBUG, "Inverting constraint");
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
  
	cl_log(LOG_DEBUG, "Inverted constraint");
	print_cons(inverted_con, FALSE);
	return inverted_con;
}

rsc_constraint_t *
copy_constraint(rsc_constraint_t *constraint) 
{
	rsc_constraint_t *copied_con =
		cl_malloc(sizeof(rsc_constraint_t));

	copied_con->id = cl_strdup(constraint->id);
	copied_con->type = constraint->type;
	copied_con->strength = constraint->strength;
	copied_con->is_placement = constraint->is_placement;

	// swap the direction
	copied_con->rsc_lh = constraint->rsc_lh;
	copied_con->rsc_rh = constraint->rsc_rh;

	copied_con->node_rh = constraint->node_rh;
	copied_con->modifier = constraint->modifier;
	copied_con->weight = constraint->weight;
  
	return copied_con;
}


/* are the contents of list1 and list2 equal */
/* nodes with weight < 0 are ignored */
gboolean
node_list_eq(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = NULL;
 
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
	GSListPtr result = NULL;
	int lpc = 0;

	cl_log(LOG_DEBUG, "Len 1: %d, len 2: %d", g_slist_length(list1), g_slist_length(list2));
	for(lpc = 0; lpc < g_slist_length(list1); lpc++) {
		node_t *node = (node_t*)g_slist_nth_data(list1, lpc);
		node_t *new_node = node_copy(node);
		node_t *other_node = (node_t*)find_list_node(list2, node->id);

		if(node == NULL || other_node == NULL) {
			continue;
			
			// merge node weights
		} else if(node->weight < 0 || other_node->weight < 0) {
			new_node->weight = -1;
		} else {
			new_node->weight = 
				node->weight + other_node->weight;
			if(new_node->weight != 0) {
				new_node->weight = new_node->weight /2.0;
			}
		}
		result = g_slist_append(result, new_node);
    
	}
  
 
	return result;
}

node_t *
find_list_node(GSListPtr list, const char *id)
{
	int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(list); lpc++) {
		node_t *thing = (node_t *)g_slist_nth_data(list, lpc);
		if(safe_str_eq(thing->id, id)) {
			return thing;
		}
	}
	return NULL;
}

/* list1 - list2 */
/* nodes with weight < 0 are ignored */
GSListPtr
node_list_minus(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = NULL;
	int lpc = 0;

	for(lpc = 0; lpc < g_slist_length(list1); lpc++) {
		node_t *node = (node_t*)g_slist_nth_data(list1, lpc);
		node_t *other_node = (node_t*)find_list_node(list2, node->id);
		
		if(node == NULL || other_node != NULL) {
			continue;
			
			// merge node weights
		}
		node_t *new_node = node_copy(node);
		result = g_slist_append(result, new_node);
    
	}
  
	cl_log(LOG_DEBUG, "Minus result len: %d", g_slist_length(result));
	return result;
}

/* list1 + list2 - (intersection of list1 and list2) */
/* nodes with weight < 0 are ignored */
GSListPtr
node_list_xor(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = NULL;
	int lpc = 0;

	for(lpc = 0; lpc < g_slist_length(list1); lpc++) {
		node_t *node = (node_t*)g_slist_nth_data(list1, lpc);
		node_t *other_node = (node_t*)find_list_node(list2, node->id);

		if(node == NULL || other_node != NULL) {
			continue;
			
			// merge node weights
		}
		node_t *new_node = node_copy(node);
		result = g_slist_append(result, new_node);
    
	}
 
	for(lpc = 0; lpc < g_slist_length(list2); lpc++) {
		node_t *node = (node_t*)g_slist_nth_data(list2, lpc);
		node_t *other_node = (node_t*)find_list_node(list1, node->id);

		if(node == NULL || other_node != NULL) {
			continue;
			
			// merge node weights
		}
		node_t *new_node = node_copy(node);
		result = g_slist_append(result, new_node);
	}
  
	cl_log(LOG_DEBUG, "Xor result len: %d", g_slist_length(result));
	return result;
}

GSListPtr 
node_list_dup(GSListPtr list1)
{
	GSListPtr result = NULL;
	int lpc = 0;
	if(list1 == NULL) {
		return NULL;
	}
	for(lpc = 0; lpc < g_slist_length(list1); lpc++) {
		node_t *this_node = (node_t*)g_slist_nth_data(list1, lpc);
		node_t *new_node = node_copy(this_node);
		if(new_node != NULL) {
			result = g_slist_append(result, new_node);
		}
	}
  
	return result;
}

node_t *
node_copy(node_t *this_node) 
{
	if(this_node == NULL) {
		print_node(this_node);
		return NULL;
	}
	node_t *new_node = cl_malloc(sizeof(node_t));
	new_node->id     = cl_strdup(this_node->id); 
	new_node->weight = this_node->weight; 
	new_node->fixed  = this_node->fixed; 

	return new_node;
}

static int color_id = 0;
color_t *
create_color(GSListPtr nodes)
{
	int lpc = 0;
	color_t *new_color = cl_malloc(sizeof(color_t));
	new_color->id = color_id++;
	new_color->local_weight = 0; // not used here
	new_color->details = cl_malloc(sizeof(struct color_shared_s));
	new_color->details->chosen_node = NULL; 
	new_color->details->candidate_nodes = node_list_dup(nodes);
    
	colors = g_slist_append(colors, new_color);      

	print_color(new_color, FALSE);
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
		rsc->candidate_colors = g_slist_append(rsc->candidate_colors, color_copy);
	}
}


gboolean
unpack_nodes(xmlNodePtr nodes)
{
	cl_log(LOG_DEBUG, "Begining unpack... %s", __FUNCTION__);
	cl_log(LOG_DEBUG, "Number of nodes... %d", g_slist_length(node_list));
	int lpc = 1;
	while(nodes != NULL) {
		cl_log(LOG_DEBUG, "Processing node...");
		xmlNodePtr xml_obj = nodes;
		const char *id = xmlGetProp(xml_obj, "id");
		nodes = nodes->next;
	
		if(id == NULL) {
			cl_log(LOG_ERR, "Must specify id tag in <node>");
			continue;
		}
		node_t *new_node = cl_malloc(sizeof(node_t));
		new_node->weight = 1.0 * lpc++;
		new_node->fixed = FALSE;
		new_node->id = cl_strdup(id);
		cl_log(LOG_DEBUG, "Adding node id... %s (%p)", id, new_node);

		node_list = g_slist_append(node_list, new_node);
		cl_log(LOG_DEBUG, "Number of nodes... %d", g_slist_length(node_list));
    
	}
  
	cl_log(LOG_DEBUG, "Sorting nodes... %s", __FUNCTION__);
	node_list = g_slist_sort(node_list, sort_node_weight);

	return TRUE;
}


gboolean 
unpack_resources(xmlNodePtr resources)
{
	cl_log(LOG_DEBUG, "Begining unpack... %s", __FUNCTION__);
	while(resources != NULL) {
		xmlNodePtr xml_obj = resources;
		const char *id = xmlGetProp(xml_obj, "id");
		const char *priority = xmlGetProp(xml_obj, "priority");
		float priority_f = atof(priority);
		resources = resources->next;

		cl_log(LOG_DEBUG, "Processing resource...");
		
		if(id == NULL) {
			cl_log(LOG_ERR, "Must specify id tag in <resource>");
			continue;
		}
		resource_t *new_rsc = cl_malloc(sizeof(resource_t));
		new_rsc->xml = xml_obj; // copy first 
		new_rsc->priority = priority_f; 
		new_rsc->candidate_colors = NULL;
		new_rsc->color = NULL; 
		new_rsc->provisional = TRUE; 
		new_rsc->allowed_nodes = node_list_dup(node_list);    
		new_rsc->constraints = NULL; 
		new_rsc->id = cl_strdup(id);

		cl_log(LOG_DEBUG, "Adding resource %s (%p)...", id, new_rsc);
		rsc_list = g_slist_append(rsc_list, new_rsc);

	}
	rsc_list = g_slist_sort(rsc_list, sort_rsc_priority);

	return TRUE;
}



gboolean 
unpack_constraints(xmlNodePtr constraints)
{
	cl_log(LOG_DEBUG, "Begining unpack... %s", __FUNCTION__);
	while(constraints != NULL) {
		const char *id = xmlGetProp(constraints, "id");
		xmlNodePtr xml_obj = constraints;
		constraints = constraints->next;
		if(id == NULL) {
			cl_log(LOG_ERR, "Constraint must have an id");
			continue;
		}

		cl_log(LOG_DEBUG, "Processing constraint %s", id);
		rsc_constraint_t *new_con = cl_malloc(sizeof(rsc_constraint_t));
		rsc_constraint_t *inverted_con = NULL;
		const char *id_lh =  xmlGetProp(xml_obj, "from");
		cl_log(LOG_DEBUG, "Looking up resource...");
		resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);
		if(rsc_lh == NULL) {
			cl_log(LOG_ERR, "No resource (con=%s, rsc=%s)",
			       id, id_lh);
			continue;
		}
		new_con->id = cl_strdup(id);
		new_con->rsc_lh = rsc_lh;
		if(safe_str_eq("rsc_to_rsc", xml_obj->name)) {
			new_con->type = rsc_to_rsc;
			const char *strength = xmlGetProp(xml_obj, "strength");
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

			const char *type = xmlGetProp(xml_obj, "type");
			if(safe_str_eq(type, "ordering")) {
				new_con->is_placement = FALSE;

			} else if (safe_str_eq(type, "placement")) {
				new_con->is_placement = TRUE;

			} else {
				// error
			}
      
			new_con->node_rh = NULL;
			const char *id_rh = xmlGetProp(xml_obj, "to");
			resource_t *rsc_rh = pe_find_resource(rsc_list, id_rh);
			if(rsc_rh == NULL) {
				cl_log(LOG_ERR, "No rh resource found with id %s", id_rh);
				continue;
			}
			new_con->rsc_rh = rsc_rh;

			inverted_con = invert_constraint(new_con);
			cons_list = g_slist_insert_sorted(cons_list, inverted_con, sort_cons_strength);
			cons_list = g_slist_insert_sorted(cons_list, new_con, sort_cons_strength);

		} else if(safe_str_eq("rsc_to_node", xml_obj->name)) {
			xmlNodePtr node_ref = xml_obj->children;
			new_con->type = rsc_to_node;
			new_con->rsc_rh = NULL;

			const char *mod = xmlGetProp(xml_obj, "modifier");
			const char *weight = xmlGetProp(xml_obj, "weight");
			float weight_f = atof(weight);
			new_con->weight = weight_f;

			cl_log(LOG_DEBUG, "Mod: %s", mod);
			
			if(safe_str_eq(mod, "set")){
				new_con->modifier = set;
			} else if(safe_str_eq(mod, "inc")){
				new_con->modifier = inc;
			} else if(safe_str_eq(mod, "dec")){
				new_con->modifier = dec;
			} else {
				// error
			}
/*
  <rsc_to_node>
     <node_ref id= type= name=/>
     <node_ref id= type= name=/>
     <node_ref id= type= name=/>
*/		
//			

			while(node_ref != NULL) {
				const char *id_rh = xmlGetProp(node_ref, "name");
				rsc_constraint_t *cons_copy = copy_constraint(new_con);
				cons_copy->node_rh = pe_find_node(rsc_lh->allowed_nodes, id_rh);
				
				if(cons_copy->node_rh == NULL) {
					// error
					cl_log(LOG_ERR,
					       "node %s (from %s) not found",
					       id_rh, node_ref->name);
				} else {
					cons_list = g_slist_insert_sorted(cons_list, cons_copy, sort_cons_strength);
				}					
				
				/* dont add it to the resource,
				 *  the information is in the resouce's node list
				 */
				node_ref = node_ref->next;
			}
			cl_free(new_con->id);
			cl_free(new_con);

		} else {
			// error
		}


	}

	int lpc = 0;
	cl_log(LOG_INFO, "========= Constraints =========");
	slist_iter(resource, rsc_constraint_t, cons_list, lpc,
		   print_cons(resource, FALSE));

	return TRUE;
}


gboolean 
apply_node_constraints(GSListPtr constraints, 
		       GSListPtr resources,
		       GSListPtr nodes)
{
	cl_log(LOG_DEBUG, "Applying constraints... %s", __FUNCTION__);
	int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(constraints); lpc++) {
		rsc_constraint_t *cons = (rsc_constraint_t *)
			g_slist_nth_data(constraints, lpc);
		
		cl_log(LOG_DEBUG, "Processing constraint %d", lpc);
		// take "lifetime" into account
		if(cons == NULL) {
			cl_log(LOG_ERR, "Constraint (%d) is NULL", lpc); 	
			continue;
			
		} else if(is_active(cons) == FALSE) {
			cl_log(LOG_INFO, "Constraint (%d) is not active", lpc); 	
			// warning
			continue;
		}
    
		resource_t *rsc_lh = cons->rsc_lh;
		if(rsc_lh == NULL) {
			cl_log(LOG_ERR, "LHS of rsc_to_node (%s) is NULL", cons->id); 	
			continue;
		}

		GSListPtr rsc_cons_list = cons->rsc_lh->constraints;
		rsc_lh->constraints = g_slist_append(rsc_cons_list, cons);

		if(cons->type == rsc_to_rsc) {
			// nothing 
			cl_log(LOG_DEBUG, "nothing to do");
			continue;
			
		} else if(cons->type == rsc_to_node) {
			if(cons->node_rh == NULL) {
				cl_log(LOG_ERR,
				       "RHS of rsc_to_node (%s) is NULL",
				       cons->id);
				continue;
			} else if(cons->node_rh->fixed) {
				// warning
				cl_log(LOG_WARNING,
				       "Constraint %s is irrelevant as the"
				       " weight of node %s is fixed as %f.",
				       cons->id,
				       cons->node_rh->id,
				       cons->node_rh->weight);
			} else {
				node_t *node_rh =
					pe_find_node(cons->rsc_lh->allowed_nodes,
						     cons->node_rh->id);				
				cl_log(LOG_DEBUG,
				       "Constraint %s: node %s weight %s %f.",
				       cons->id,
				       cons->node_rh->id,
				       modifier2text(cons->modifier),
				       cons->node_rh->weight);
				switch(cons->modifier) {
					case set:
						node_rh->weight = cons->weight;
						node_rh->fixed = TRUE;
						break;
					case inc:
						node_rh->weight += cons->weight;
						break;
					case dec:
						node_rh->weight -= cons->weight;
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
filter_nodes(resource_t *rsc)
{
	cl_log(LOG_DEBUG, "Filtering nodes... %s", __FUNCTION__);

	int lpc2 = 0;
	print_resource(rsc, FALSE);
	
	for(lpc2 = 0; lpc2 < g_slist_length(rsc->allowed_nodes); lpc2++) {
		node_t *node = g_slist_nth_data(rsc->allowed_nodes, lpc2);
		print_node(node);
		if(node == NULL) {
			cl_log(LOG_ERR, "Invalid NULL node");
			
		} else if(node->weight < 0.0) {
			cl_log(LOG_DEBUG, "removing:");
			print_node(node);
			rsc->allowed_nodes = g_slist_remove(rsc->allowed_nodes,node);
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
		if(rsc != NULL && safe_str_eq(rsc->id, id_rh)){
			cl_log(LOG_DEBUG, "Resource %s found at %d...",
			       id_rh, lpc);
			return rsc;
		}
	}
	// error
	return NULL;
}
node_t *
pe_find_node(GSListPtr nodes, const char *id)
{
	int lpc = 0;
  
	for(lpc = 0; lpc < g_slist_length(nodes); lpc++) {
		node_t *node = g_slist_nth_data(nodes, lpc);
		if(safe_str_eq(node->id, id)) {
			return node;
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
	cl_log(LOG_DEBUG, "Begining unpack... %s", __FUNCTION__);

	while(status != NULL) {
		const char *id = xmlGetProp(status, "id");
		const char *state = xmlGetProp(status, "state");
		const char *exp_state = xmlGetProp(status, "exp_state");
		xmlNodePtr lrm_state = find_xml_node(status, "lrm");
		lrm_state = find_xml_node(lrm_state, "lrm_resource");
		lrm_state = find_xml_node(lrm_state, "rsc_state");
		status = status->next;
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
					new_cons->node_rh = pe_find_node(new_cons->rsc_lh->allowed_nodes, node_id);
					new_cons->modifier = inc;
	 
					cons_list = g_slist_append(cons_list, new_cons);

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
				stonith_list = g_slist_append(stonith_list, node);
			}

		}

	}
	cons_list = g_slist_sort(cons_list, sort_cons_strength);

	return TRUE;
	
}


color_t *
find_color(GSListPtr candidate_colors, color_t *other_color)
{
	int lpc = 0;
	slist_iter(color, color_t, candidate_colors, lpc,
		   if(color->id == other_color->id) {
			   return color;
		   }
		);
	return NULL;
}

gboolean
is_active(rsc_constraint_t *cons)
{
	return TRUE;
}

gint sort_rsc_priority(gconstpointer a, gconstpointer b)
{
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;
	if(a == NULL) return 1;
	if(b == NULL) return -1;
  
	if(resource1->priority > resource2->priority)
		return -1;

	if(resource1->priority < resource2->priority)
		return 1;

	return 0;
}

gint sort_cons_strength(gconstpointer a, gconstpointer b)
{
	const rsc_constraint_t *rsc_constraint1 = (const rsc_constraint_t*)a;
	const rsc_constraint_t *rsc_constraint2 = (const rsc_constraint_t*)b;
  
	if(rsc_constraint1->strength > rsc_constraint2->strength)
		return 1;

	if(rsc_constraint1->strength < rsc_constraint2->strength)
		return -1;
	return 0;
}

gint sort_color_weight(gconstpointer a, gconstpointer b)
{
	const color_t *color1 = (const color_t*)a;
	const color_t *color2 = (const color_t*)b;
	if(a == NULL) return 1;
	if(b == NULL) return -1;
  
	if(color1->local_weight > color2->local_weight)
		return -1;

	if(color1->local_weight < color2->local_weight)
		return 1;

	return 0;
}

gint sort_node_weight(gconstpointer a, gconstpointer b)
{
	const node_t *node1 = (const node_t*)a;
	const node_t *node2 = (const node_t*)b;

	if(a == NULL) return 1;
	if(b == NULL) return -1;
	
	if(node1->weight > node2->weight)
		return -1;

	if(node1->weight < node2->weight)
		return 1;
  

	return 0;
}

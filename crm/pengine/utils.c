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


gboolean unpack_rsc_to_attr(xmlNodePtr xml_obj);
gboolean unpack_rsc_to_node(xmlNodePtr xml_obj);
gboolean choose_color(resource_t *lh_resource, GSListPtr candidate_colors);
gboolean strict_postproc(rsc_constraint_t *constraint,
			 color_t *local_color,
			 color_t *other_color);
gboolean strict_preproc(rsc_constraint_t *constraint,
			color_t *local_color,
			color_t *other_color);
gboolean update_node_weight(rsc_constraint_t *cons, node_t *node_rh);
gboolean add_positive_preference(xmlNodePtr lrm_state);

/* only for rsc_to_rsc constraints */
rsc_constraint_t *
invert_constraint(rsc_constraint_t *constraint) 
{
	pdebug(cl_log(LOG_DEBUG, "Inverting constraint"));
	rsc_constraint_t *inverted_con =
		cl_malloc(sizeof(rsc_constraint_t));

	inverted_con->id = cl_strdup(constraint->id);
	inverted_con->type = constraint->type;
	inverted_con->strength = constraint->strength;
	inverted_con->is_placement = constraint->is_placement;

	// swap the direction
	inverted_con->rsc_lh = constraint->rsc_rh;
	inverted_con->rsc_rh = constraint->rsc_lh;

	inverted_con->node_list_rh = NULL;
	inverted_con->modifier = modifier_none;
	inverted_con->weight = 0.0;
  
	pdebug(print_cons("Inverted constraint", inverted_con, FALSE));
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

	copied_con->node_list_rh = constraint->node_list_rh;
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
  
	pdebug(cl_log(LOG_DEBUG, "Minus result len: %d",
		      g_slist_length(result)));
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
  
	pdebug(cl_log(LOG_DEBUG, "Xor result len: %d",
		      g_slist_length(result)));
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
		print_node("Failed copy of", this_node);
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

	pdebug(print_color("Created color", new_color, FALSE));
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
filter_nodes(resource_t *rsc)
{
	int lpc2 = 0;
	pdebug(print_resource("Filtering nodes for", rsc, FALSE));
	slist_iter(
		node, node_t, rsc->allowed_nodes, lpc2,
		if(node == NULL) {
			cl_log(LOG_ERR, "Invalid NULL node");
			
		} else if(node->weight < 0.0) {
			pdebug(print_node("Removing", node));
			rsc->allowed_nodes = g_slist_remove(rsc->allowed_nodes,node);
		}
		);

	return TRUE;
}

resource_t *
pe_find_resource(GSListPtr rsc_list, const char *id_rh)
{
	int lpc = 0;
	for(lpc = 0; lpc < g_slist_length(rsc_list); lpc++) {
		resource_t *rsc = g_slist_nth_data(rsc_list, lpc);
		if(rsc != NULL && safe_str_eq(rsc->id, id_rh)){
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

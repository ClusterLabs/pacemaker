#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>
#include <crm/common/crmutils.h>
#include <crm/cib.h>
#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>

void print_str_str(gpointer key, gpointer value, gpointer user_data);

/* only for rsc_to_rsc constraints */
rsc_to_rsc_t *
invert_constraint(rsc_to_rsc_t *constraint) 
{
	pdebug("Inverting constraint");
	rsc_to_rsc_t *inverted_con =
		crm_malloc(sizeof(rsc_to_node_t));

	inverted_con->id = crm_strdup(constraint->id);
	inverted_con->strength = constraint->strength;

	// swap the direction
	inverted_con->rsc_lh = constraint->rsc_rh;
	inverted_con->rsc_rh = constraint->rsc_lh;

	pdebug_action(
		print_rsc_to_rsc("Inverted constraint", inverted_con, FALSE)
		);
	return inverted_con;
}

rsc_to_node_t *
copy_constraint(rsc_to_node_t *constraint) 
{
	rsc_to_node_t *copied_con = crm_malloc(sizeof(rsc_to_node_t));

	copied_con->id		 = crm_strdup(constraint->id);

	copied_con->rsc_lh = constraint->rsc_lh;
	copied_con->node_list_rh = constraint->node_list_rh;
	copied_con->modifier	 = constraint->modifier;
	copied_con->weight	 = constraint->weight;
  
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
	cl_log(LOG_ERR, "Not yet implemented");
 
	return g_slist_length(result) != 0;
}

/* the intersection of list1 and list2 
 * when merging weights, nodes set to < 0  in either list will always
 * have their weight set to -1 in the result
 */
GSListPtr
node_list_and(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = NULL;
	int lpc = 0;

	for(lpc = 0; lpc < g_slist_length(list1); lpc++) {
		node_t *node = (node_t*)g_slist_nth_data(list1, lpc);
		node_t *new_node = NULL;
		node_t *other_node = find_list_node(list2, node->details->id);

		if(node == NULL || other_node == NULL) {
			continue;
			
			// merge node weights
		} else if(node->weight < 0 || other_node->weight < 0) {
			new_node = node_copy(node);
			new_node->weight = -1;
		} else {
			new_node = node_copy(node);
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
	slist_iter(
		thing, node_t, list, lpc,
		if(safe_str_eq(thing->details->id, id)) {
			return thing;
		}
		);
	
	return NULL;
}

/* list1 - list2 */
GSListPtr
node_list_minus(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = NULL;
	int lpc = 0;

	slist_iter(
		node, node_t, list1, lpc,
		node_t *other_node = find_list_node(list2, node->details->id);
		
		if(node == NULL || other_node != NULL) {
			continue;
			
		}
		node_t *new_node = node_copy(node);
		result = g_slist_append(result, new_node);
		);
  
	pdebug("Minus result len: %d",
		      g_slist_length(result));

	return result;
}

/* list1 + list2 - (intersection of list1 and list2) */
GSListPtr
node_list_xor(GSListPtr list1, GSListPtr list2)
{
	GSListPtr result = NULL;
	int lpc = 0;
	
	slist_iter(
		node, node_t, list1, lpc,
		node_t *other_node = (node_t*)find_list_node(list2, node->details->id);

		if(node == NULL || other_node != NULL) {
			continue;
		}
		node_t *new_node = node_copy(node);
		result = g_slist_append(result, new_node);
		);
	
 
	slist_iter(
		node, node_t, list1, lpc,
		node_t *other_node = (node_t*)find_list_node(list1, node->details->id);

		if(node == NULL || other_node != NULL) {
			continue;
		}
		node_t *new_node = node_copy(node);
		result = g_slist_append(result, new_node);
		);
  
	pdebug("Xor result len: %d", g_slist_length(result));
	return result;
}

GSListPtr 
node_list_dup(GSListPtr list1)
{
	GSListPtr result = NULL;
	int lpc = 0;
	slist_iter(
		this_node, node_t, list1, lpc,
		node_t *new_node = node_copy(this_node);
		if(new_node != NULL) {
			result = g_slist_append(result, new_node);
		}
		);

	return result;
}

node_t *
node_copy(node_t *this_node) 
{
	if(this_node == NULL) {
		print_node("Failed copy of", this_node, TRUE);
		return NULL;
	}
	node_t *new_node = crm_malloc(sizeof(node_t));
	new_node->weight = this_node->weight; 
	new_node->fixed  = this_node->fixed;
	new_node->details = this_node->details; 

	return new_node;
}

static int color_id = 0;

/*
 * Create a new color with the contents of "nodes" as the list of
 *  possible nodes that resources with this color can be run on.
 *
 * Typically, when creating a color you will provide the node list from
 *  the resource you will first assign the color to.
 *
 * If "colors" != NULL, it will be added to that list
 * If "resources" != NULL, it will be added to every provisional resource
 *  in that list
 */
color_t *
create_color(GSListPtr *colors, GSListPtr nodes, GSListPtr resources)
{
	color_t *new_color = crm_malloc(sizeof(color_t));

	new_color->id = color_id++;
	new_color->local_weight = 1.0;
	new_color->details = crm_malloc(sizeof(struct color_shared_s));
	new_color->details->id = new_color->id; 
	new_color->details->chosen_node = NULL; 
	new_color->details->candidate_nodes = node_list_dup(nodes);

	pdebug_action(print_color("Created color", new_color, TRUE));

	if(colors != NULL) {
		*colors = g_slist_append(*colors, new_color);      
	}
	
	if(resources != NULL) {
		/* Add any new color to the list of candidate_colors for
		 * resources that havent been decided yet 
		 */
		int lpc;
		slist_iter(
			rsc, resource_t, resources, lpc,
			if(rsc->provisional && rsc->runnable) {
				color_t *color_copy = (color_t *)
					cl_malloc(sizeof(color_t));

				color_copy->id      = new_color->id;
				color_copy->details = new_color->details;
				color_copy->local_weight = 1.0; 

				rsc->candidate_colors =
					g_slist_append(rsc->candidate_colors,
						       color_copy);
			}
			);
	}
	
	return new_color;
}


/*
 * Remove any nodes with a -ve weight
 */
gboolean
filter_nodes(resource_t *rsc)
{
	int lpc2 = 0;
	pdebug_action(print_resource("Filtering nodes for", rsc, FALSE));
	slist_iter(
		node, node_t, rsc->allowed_nodes, lpc2,
		if(node == NULL) {
			cl_log(LOG_ERR, "Invalid NULL node");
			
		} else if(node->weight < 0.0
			  || node->details->online == FALSE
			  || node->details->type == node_ping) {
			pdebug_action(print_node("Removing", node, FALSE));
			rsc->allowed_nodes =
				g_slist_remove(rsc->allowed_nodes,node);
			crm_free(node);
			lpc2--;
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
		if(safe_str_eq(node->details->id, id)) {
			return node;
		}
	}
	// error
	return NULL;
}

gint gslist_color_compare(gconstpointer a, gconstpointer b);
color_t *
find_color(GSListPtr candidate_colors, color_t *other_color)
{
	GSListPtr tmp = g_slist_find_custom(candidate_colors, other_color,
					    gslist_color_compare);
	if(tmp != NULL) {
		return (color_t *)tmp->data;
	}
	return NULL;
}


gint gslist_color_compare(gconstpointer a, gconstpointer b)
{
	const color_t *color_a = (const color_t*)a;
	const color_t *color_b = (const color_t*)b;
	if(a == b) {
		return 0;
	} else if(a == NULL || b == NULL) {
		return 1;
	} else if(color_a->id == color_b->id) {
		return 0;
	}
	return 1;
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
	const rsc_to_rsc_t *rsc_constraint1 = (const rsc_to_rsc_t*)a;
	const rsc_to_rsc_t *rsc_constraint2 = (const rsc_to_rsc_t*)b;

	if(a == NULL) return 1;
	if(b == NULL) return -1;
  
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

action_t *
action_new(int id, resource_t *rsc, enum action_tasks task)
{
	action_t *action = (action_t*)crm_malloc(sizeof(action_t));
	action->id   = id;
	action->rsc  = rsc;
	action->task = task;
	action->node = NULL; // fill node in later
	action->actions_before   = NULL;
	action->actions_after    = NULL;
	action->failure_is_fatal = TRUE;
	action->discard    = FALSE;
	action->runnable   = FALSE;
	action->processed  = FALSE;
	action->optional   = FALSE;
	action->seen_count = 0;

	return action;
}

const char *
contype2text(enum con_type type)
{
	const char *result = "<unknown>";
	switch(type)
	{
		case type_none:
			result = "none";
			break;
		case rsc_to_rsc:
			result = "rsc_to_rsc";
			break;
		case rsc_to_node:
			result = "rsc_to_node";
			break;
		case rsc_to_attr:
			result = "rsc_to_attr";
			break;
		case base_weight:
			result = "base_weight";
			break;
	}
	return result;
};

const char *
strength2text(enum con_strength strength)
{
	const char *result = "<unknown>";
	switch(strength)
	{
		case ignore:
			result = "ignore";
			break;
		case must:
			result = XML_STRENGTH_VAL_MUST;
			break;
		case should:
			result = XML_STRENGTH_VAL_SHOULD;
			break;
		case should_not:
			result = XML_STRENGTH_VAL_SHOULDNOT;
			break;
		case must_not:
			result = XML_STRENGTH_VAL_MUSTNOT;
			break;
		case startstop:
			result = "start/stop";
			break;
	}
	return result;
};

const char *
modifier2text(enum con_modifier modifier)
{
	const char *result = "<unknown>";
	switch(modifier)
	{
		case modifier_none:
			result = "modifier_none";
			break;
		case set:
			result = "set";
			break;
		case inc:
			result = "inc";
			break;
		case dec: 
			result = "dec";
			break;
	}
	return result;
};

const char *
task2text(enum action_tasks task)
{
	const char *result = "<unknown>";
	switch(task)
	{
		case no_action:
			result = "no_action";
			break;
		case stop_rsc:
			result = "stop";
			break;
		case start_rsc:
			result = "start";
			break;
		case shutdown_crm:
			result = "shutdown_crm";
			break;
		case stonith_op:
			result = "stonith";
			break;
	}
	
	return result;
};


void
print_node(const char *pre_text, node_t *node, gboolean details)
{ 
	if(node == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}

	cl_log(LOG_DEBUG, "%s%s%sNode %s: (weight=%f, fixed=%s)",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       node->details==NULL?"error ":node->details->online?"":"Unavailable/Unclean ",
	       node->details->id, 
	       node->weight,
	       node->fixed?"True":"False"); 

	if(details && node->details != NULL) {
		char *mutable = crm_strdup("\t\t");
		cl_log(LOG_DEBUG, "\t\t===Node Attributes");
		g_hash_table_foreach(node->details->attrs,
				     print_str_str, mutable);
		crm_free(mutable);
	}

	if(details) {
		int lpc = 0;
		cl_log(LOG_DEBUG, "\t\t===Node Attributes");
		slist_iter(
			rsc, resource_t, node->details->running_rsc, lpc,
			print_resource("\t\t", rsc, FALSE);
			);
	}
	
};

/*
 * Used by the HashTable for-loop
 */
void print_str_str(gpointer key, gpointer value, gpointer user_data)
{
	cl_log(LOG_DEBUG, "%s%s %s ==> %s",
	       user_data==NULL?"":(char*)user_data,
	       user_data==NULL?"":": ",
	       (char*)key,
	       (char*)value);
}

void
print_color_details(const char *pre_text,
		    struct color_shared_s *color,
		    gboolean details)
{ 
	if(color == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s%sColor %d: node=%s (from %d candidates)",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       color->id, 
	       color->chosen_node==NULL?"<unset>":color->chosen_node->details->id,
	       g_slist_length(color->candidate_nodes)); 
	if(details) {
		int lpc = 0;
		slist_iter(node, node_t, color->candidate_nodes, lpc,
			   print_node("\t", node, FALSE));
	}
}

void
print_color(const char *pre_text, color_t *color, gboolean details)
{ 
	if(color == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s%sColor %d: (weight=%f, node=%s, possible=%d)",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       color->id, 
	       color->local_weight,
	       color->details->chosen_node==NULL?"<unset>":color->details->chosen_node->details->id,
	       g_slist_length(color->details->candidate_nodes)); 
	if(details) {
		print_color_details("\t", color->details, details);
	}
}

void
print_rsc_to_node(const char *pre_text, rsc_to_node_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s%s%s Constraint %s (%p):",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       "rsc_to_node",
	       cons->id, cons);

	if(details == FALSE) {
		cl_log(LOG_DEBUG,
		       "\t%s --> %s, %f (node placement rule)",
		       cons->rsc_lh->id, 
		       modifier2text(cons->modifier),
		       cons->weight);

		int lpc = 0;
		slist_iter(
			node, node_t, cons->node_list_rh, lpc,
			print_node("\t\t-->", node, FALSE)
			);
	}
}

void
print_rsc_to_rsc(const char *pre_text, rsc_to_rsc_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG, "%s%s%s Constraint %s (%p):",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       "rsc_to_rsc", cons->id, cons);

	if(details == FALSE) {

		cl_log(LOG_DEBUG,
		       "\t%s --> %s, %s",
		       cons->rsc_lh==NULL?"null":cons->rsc_lh->id, 
		       cons->rsc_rh==NULL?"null":cons->rsc_rh->id, 
		       strength2text(cons->strength));
	}
} 

void
print_resource(const char *pre_text, resource_t *rsc, gboolean details)
{ 
	if(rsc == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}
	cl_log(LOG_DEBUG,
	       "%s%s%s%sResource %s: (priority=%f, color=%d, now=%s)",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       rsc->provisional?"Provisional ":"",
	       rsc->runnable?"":"(Non-Startable) ",
	       rsc->id,
	       (double)rsc->priority,
	       safe_val3(-1, rsc, color, id),
	       safe_val4(NULL, rsc, cur_node, details, id));

	cl_log(LOG_DEBUG,
	       "\t%d candidate colors, %d allowed nodes, %d rsc_cons and %d node_cons",
	       g_slist_length(rsc->candidate_colors),
	       g_slist_length(rsc->allowed_nodes),
	       g_slist_length(rsc->rsc_cons),
	       g_slist_length(rsc->node_cons));
	
	if(details) {
		int lpc = 0;
		cl_log(LOG_DEBUG, "\t=== Actions");
		print_action("\tStop: ", rsc->stop, FALSE);
		print_action("\tStart: ", rsc->start, FALSE);
		
		cl_log(LOG_DEBUG, "\t=== Colors");
		slist_iter(
			color, color_t, rsc->candidate_colors, lpc,
			print_color("\t", color, FALSE)
			);
		cl_log(LOG_DEBUG, "\t=== Allowed Nodes");
		slist_iter(
			node, node_t, rsc->allowed_nodes, lpc,
			print_node("\t", node, FALSE);
			);
	}
}



void
print_action(const char *pre_text, action_t *action, gboolean details)
{ 
	if(action == NULL) {
		cl_log(LOG_DEBUG, "%s%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ",
		       __FUNCTION__);
		return;
	}

	switch(action->task) {
		case stonith_op:
		case shutdown_crm:
			cl_log(LOG_DEBUG, "%s%s%sAction %d: %s @ %s",
			       pre_text==NULL?"":pre_text,
			       pre_text==NULL?"":": ",
			       action->discard?"Discarded ":action->optional?"Optional ":action->runnable?action->processed?"":"(Provisional) ":"!!Non-Startable!! ",
			       action->id,
			       task2text(action->task),
			       safe_val4(NULL, action, node, details, id));
			break;
		default:
			cl_log(LOG_DEBUG, "%s%s%sAction %d: %s %s @ %s",
			       pre_text==NULL?"":pre_text,
			       pre_text==NULL?"":": ",
			       action->optional?"Optional ":action->runnable?action->processed?"":"(Provisional) ":"!!Non-Startable!! ",
			       action->id,
			       task2text(action->task),
			       safe_val3(NULL, action, rsc, id),
			       safe_val4(NULL, action, node, details, id));
			
			break;
	}

	if(details) {
		int lpc = 0;
#if 1
		cl_log(LOG_DEBUG, "\t\t====== Preceeding Actions");
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			print_action("\t\t", other->action, FALSE);
			);
		cl_log(LOG_DEBUG, "\t\t====== Subsequent Actions");
		slist_iter(
			other, action_wrapper_t, action->actions_after, lpc,
			print_action("\t\t", other->action, FALSE);
			);		
#else
		cl_log(LOG_DEBUG, "\t\t====== Subsequent Actions");
		slist_iter(
			other, action_wrapper_t, action->actions_after, lpc,
			print_action("\t\t", other->action, FALSE);
			);		
#endif
		cl_log(LOG_DEBUG, "\t\t====== End");

	} else {
		cl_log(LOG_DEBUG, "\t\t(seen=%d, before=%d, after=%d)",
		       action->seen_count,
		       g_slist_length(action->actions_before),
		       g_slist_length(action->actions_after));
	}
}


xmlNodePtr
action2xml(action_t *action)
{
	xmlNodePtr action_xml = NULL;
	
	if(action == NULL) {
		return NULL;
	}
	
	switch(action->task) {
		case stonith_op:
			action_xml = create_xml_node(NULL, "pseduo_event");
			break;
		case shutdown_crm:
			action_xml = create_xml_node(NULL, "crm_event");
			break;
		default:
			action_xml = create_xml_node(NULL, "rsc_op");
			add_node_copy(action_xml, action->rsc->xml);
			
			break;
	}

	set_xml_property_copy(action_xml,
			      XML_LRM_ATTR_TARGET,
			      safe_val4(NULL, action, node, details, id));

	set_xml_property_copy(action_xml,
			      XML_ATTR_ID,
			      crm_itoa(action->id));

	set_xml_property_copy(action_xml,
			      XML_LRM_ATTR_RUNNABLE,
			      action->runnable?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	set_xml_property_copy(action_xml,
			      XML_LRM_ATTR_OPTIONAL,
			      action->optional?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	set_xml_property_copy(action_xml,
			      XML_LRM_ATTR_TASK,
			      task2text(action->task));

	set_xml_property_copy(action_xml,
			      XML_LRM_ATTR_DISCARD,
			      action->discard?XML_BOOLEAN_TRUE:XML_BOOLEAN_FALSE);

	set_xml_property_copy(action_xml,
			      "allow_fail",
			      action->failure_is_fatal?XML_BOOLEAN_FALSE:XML_BOOLEAN_TRUE);

	return action_xml;
}

gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data);

void
pe_free_nodes(GSListPtr nodes)
{
	while(nodes != NULL){
		GSListPtr list_item = nodes;
		node_t *node = (node_t*)list_item->data;
		struct node_shared_s *details = node->details;
		nodes = nodes->next;

		if(details != NULL) {
			crm_free(details->id);
			g_hash_table_foreach_remove(details->attrs,
						    ghash_free_str_str, NULL);

			crm_free(details);
		}
		
		crm_free(node);
	}
	g_slist_free(nodes);
}

gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data)
{
	crm_free(key);
	crm_free(value);
	return TRUE;
}


void
pe_free_colors(GSListPtr colors)
{
	while(colors != NULL) {
		GSListPtr list_item = colors;
		color_t *color = (color_t *)list_item->data;
		struct color_shared_s *details = color->details;
		colors = colors->next;
		
		if(details != NULL) {
			pe_free_shallow(details->candidate_nodes);
			crm_free(details->chosen_node);
			crm_free(details);
		}
		crm_free(color);
	}
	g_slist_free(colors);
}

void
pe_free_shallow(GSListPtr alist)
{
	pe_free_shallow_adv(alist, TRUE);
}

void
pe_free_shallow_adv(GSListPtr alist, gboolean with_data)
{
	GSListPtr item;
	GSListPtr item_next = alist;
	while(item_next != NULL) {
		item = item_next;
		item_next = item_next->next;
		
		if(with_data) {
			crm_free(item->data);
		}
		
		item->data = NULL;
		item->next = NULL;
		g_slist_free(item);
	}
}

void
pe_free_resources(GSListPtr resources)
{ 
	volatile GSListPtr list_item = NULL;
	resource_t *rsc = NULL;
	
	while(resources != NULL) {
		list_item = resources;
		rsc = (resource_t *)list_item->data;
		resources = resources->next;

		crm_free(rsc->id);
		
//		pdebug("color");
//		crm_free(rsc->color);

		int lpc;
		slist_iter(clr, color_t, rsc->candidate_colors, lpc,
			   print_color("deleting", clr, FALSE));
		
//		pe_free_shallow(rsc->candidate_colors);
		pe_free_shallow(rsc->allowed_nodes);

		while(rsc->rsc_cons) {
			pe_free_rsc_to_rsc((rsc_to_rsc_t*)rsc->rsc_cons->data);
			rsc->rsc_cons = rsc->rsc_cons->next;
		}
		g_slist_free(rsc->rsc_cons);
		crm_free(rsc);
	}
	g_slist_free(resources);
	
}


void
pe_free_actions(GSListPtr actions) 
{
	while(actions != NULL) {
		GSListPtr list_item = actions;
		action_t *action = (action_t *)list_item->data;
		actions = actions->next;

		pe_free_shallow(action->actions_before); // action_warpper_t*
		pe_free_shallow(action->actions_after); // action_warpper_t*
		action->actions_before = NULL;
		action->actions_after = NULL;
		crm_free(action);
	}
	g_slist_free(actions);
}



void
pe_free_rsc_to_rsc(rsc_to_rsc_t *cons)
{ 
	if(cons != NULL) {
		crm_free(cons->id);
		crm_free(cons);
	}
}

void
pe_free_rsc_to_node(rsc_to_node_t *cons)
{
	if(cons != NULL) {
		crm_free(cons->id);
		pe_free_shallow(cons->node_list_rh); // node_t*
		crm_free(cons);
	}
}


#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xmlutils.h>
#include <crm/common/crmutils.h>
#include <crm/cib.h>
#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>

void color_resource(resource_t *lh_resource,
		    GSListPtr *colors,
		    GSListPtr resources);

gboolean create_rsc_to_rsc(const char *id, enum con_strength strength,
			   resource_t *rsc_lh, resource_t *rsc_rh);

gboolean create_ordering(const char *id, enum con_strength strength,
			 resource_t *rsc_lh, resource_t *rsc_rh,
			 GSListPtr *action_constraints);

gboolean unpack_constraints(xmlNodePtr xml_constraints,
			    GSListPtr nodes, GSListPtr resources,
			    GSListPtr *node_constraints,
			    GSListPtr *action_constraints);

gboolean unpack_resources(xmlNodePtr xml_resources,
			  GSListPtr *resources,
			  GSListPtr *actions,
			  GSListPtr *action_cons,
			  GSListPtr all_nodes);

gboolean unpack_nodes(xmlNodePtr xml_nodes, GSListPtr *nodes);

gboolean unpack_status(xmlNodePtr status,
		       GSListPtr nodes,
		       GSListPtr rsc_list,
		       GSListPtr *node_constraints);

gboolean apply_node_constraints(GSListPtr constraints, 
				GSListPtr resources,
				GSListPtr nodes);

gboolean is_active(rsc_to_node_t *cons);
gboolean choose_node_from_list(GSListPtr colors,
			       color_t *color,
			       GSListPtr nodes);

gboolean unpack_rsc_to_attr(xmlNodePtr xml_obj,
			    GSListPtr rsc_list,
			    GSListPtr node_list,
			    GSListPtr *node_constraints);

gboolean unpack_rsc_to_node(xmlNodePtr xml_obj,
			    GSListPtr rsc_list,
			    GSListPtr node_list,
			    GSListPtr *node_constraints);

gboolean unpack_rsc_to_rsc(xmlNodePtr xml_obj,
			   GSListPtr rsc_list,
			   GSListPtr *action_constraints);

gboolean choose_color(resource_t *lh_resource, GSListPtr candidate_colors);

gboolean strict_postproc(rsc_to_rsc_t *constraint,
			 color_t *local_color,
			 color_t *other_color,
			 GSListPtr *colors,
			 GSListPtr resources);

gboolean strict_preproc(rsc_to_rsc_t *constraint,
			color_t *local_color,
			color_t *other_color,
			GSListPtr *colors,
			GSListPtr resources);

gboolean update_node_weight(rsc_to_node_t *cons, char *id, GSListPtr nodes);

gboolean process_node_lrm_state(node_t *node,
				xmlNodePtr lrm_state,
				GSListPtr rsc_list,
				GSListPtr nodes,
				GSListPtr *node_constraints);

GSListPtr match_attrs(xmlNodePtr attr_exp, GSListPtr node_list);
gboolean update_runnable(GSListPtr actions);
GSListPtr create_action_set(action_t *action);

/*
  GSListPtr rsc_list = NULL; 
GSListPtr node_list = NULL;
GSListPtr node_cons_list = NULL;
GSListPtr rsc_cons_list = NULL;
GSListPtr action_list = NULL;
GSListPtr action_set_list = NULL;
GSListPtr action_cons_list = NULL;
GSListPtr colors = NULL;
GSListPtr stonith_list = NULL;
GSListPtr shutdown_list = NULL;
color_t *current_color = NULL;
xmlNodePtr xml_set_of_sets = NULL;
*/
color_t *no_color = NULL;
int max_valid_nodes = 0;
int order_id = 1;
int action_id = 1;

gboolean pe_debug = FALSE;
gboolean pe_debug_saved = FALSE;

gboolean
stage0(xmlNodePtr cib,
       GSListPtr *resources,
       GSListPtr *nodes, GSListPtr *node_constraints,
       GSListPtr *actions, GSListPtr *action_constraints,
       GSListPtr *stonith_list, GSListPtr *shutdown_list)
{
	int lpc = 0;
	xmlNodePtr cib_nodes       = get_object_root("nodes",       cib);
	xmlNodePtr cib_status      = get_object_root("status",      cib);
	xmlNodePtr cib_resources   = get_object_root("resources",   cib);
	xmlNodePtr cib_constraints = get_object_root("constraints", cib);

	unpack_nodes(safe_val(NULL, cib_nodes, children), nodes);

	unpack_resources(safe_val(NULL, cib_resources, children),
			 resources, actions, action_constraints, *nodes);

	unpack_status(safe_val(NULL, cib_status, children),
		      *nodes, *resources, node_constraints);

	unpack_constraints(safe_val(NULL, cib_constraints, children),
			   *nodes, *resources,
			   node_constraints,
			   action_constraints);

	slist_iter(
		node, node_t, *nodes, lpc,
		if(node->details->shutdown) {
			*shutdown_list = g_slist_append(*shutdown_list, node);
		} else if(node->details->unclean) {
			*stonith_list = g_slist_append(*stonith_list, node);
		}
		);
	
	return TRUE;
} 

gboolean
stage1(GSListPtr node_constraints, GSListPtr nodes, GSListPtr resources)
{
	int lpc = 0;
	
	slist_iter(
		node, node_t, nodes, lpc,
		if(node == NULL) {
			// error
		} else if(node->weight >= 0.0
			  && node->details->online
			  && node->details->type == node_member) {
			max_valid_nodes++;
		}	
		);

	apply_node_constraints(node_constraints, nodes, resources);

	return TRUE;
} 


gboolean
stage2(GSListPtr sorted_rscs, GSListPtr sorted_nodes, GSListPtr *colors)
{
	int lpc = 0; 
	color_t *current_color = NULL;
	
	// Set initial color
	// Set color.candidate_nodes = all active nodes
	no_color = create_color(colors, NULL, NULL);
	current_color = create_color(colors, sorted_nodes, sorted_rscs);
	
	// Set resource.color = color (all resources)
	// Set resource.provisional = TRUE (all resources)
	slist_iter(
		this_resource, resource_t, sorted_rscs, lpc,

		this_resource->color = current_color;
		this_resource->provisional = TRUE;
		);

	pdebug("initialized resources to default color");
  
	// Take (next) highest resource
	slist_iter(
		lh_resource, resource_t, sorted_rscs, lpc,
		// if resource.provisional == FALSE, repeat 
		if(lh_resource->provisional == FALSE) {
			// already processed this resource
			continue;
		}
		color_resource(lh_resource, colors, sorted_rscs);
		// next resource
		);
	
	return TRUE;
}

gboolean
stage3(GSListPtr colors)
{
	// not sure if this is a good idea or not
	if(g_slist_length(colors) > max_valid_nodes) {
		// we need to consolidate some
	} else if(g_slist_length(colors) < max_valid_nodes) {
		// we can create a few more
	}
	return TRUE;
}

#define color_n_nodes color_n->details->candidate_nodes
#define color_n_plus_1_nodes color_n_plus_1->details->candidate_nodes
gboolean
stage4(GSListPtr colors)
{

	int lpc = 0;
	color_t *color_n = NULL;
	color_t *color_n_plus_1 = NULL;
	
	for(lpc = 0; lpc < g_slist_length(colors); lpc++) {
		color_n = color_n_plus_1;
		color_n_plus_1 = (color_t*)g_slist_nth_data(colors, lpc);

		pdebug_action(print_color("Choose node for...", color_n, FALSE));
//		print_color(color_n_plus_1, FALSE);
		
		if(color_n == NULL) {
			continue;
		}


		GSListPtr xor = node_list_xor(color_n_nodes,
					      color_n_plus_1_nodes);
		GSListPtr minus = node_list_minus(color_n_nodes,
						  color_n_plus_1_nodes);

		if(g_slist_length(xor) == 0 || g_slist_length(minus) == 0) {
			pdebug(				      "Choose any node from our list");
			choose_node_from_list(colors, color_n, color_n_nodes);

		} else {
			pdebug("Choose a node not in n+1");
			choose_node_from_list(colors, color_n, minus);      
		}

	}

	// chose last color
	if(color_n_plus_1 != NULL) {
		pdebug_action(print_color("Choose node for last color...",
				   color_n_plus_1,
				   FALSE));

		choose_node_from_list(colors,
				      color_n_plus_1, 
				      color_n_plus_1_nodes);
	}
	pdebug("done %s", __FUNCTION__);
	return TRUE;
	
}

gboolean
stage5(GSListPtr resources)
{
	
	pdebug("filling in the nodes to perform the actions on");
	int lpc = 0;
	slist_iter(
		rsc, resource_t, resources, lpc,

		print_resource("Processing", rsc, FALSE);
		
		if(safe_val(NULL, rsc, stop) == NULL
		   || safe_val(NULL, rsc, start) == NULL) {
			// error
			continue;
		}
		if(safe_val4(NULL, rsc, color, details, chosen_node) == NULL) {
			rsc->stop->node = safe_val(NULL, rsc, cur_node);
			rsc->start->node = NULL;
			
		} else if(safe_str_eq(safe_val4(NULL, rsc, cur_node, details, id),
				      safe_val6(NULL, rsc, color ,details,
						chosen_node, details, id))){
			cl_log(LOG_DEBUG,
			       "No change for Resource %s (%s)",
			       safe_val(NULL, rsc, id),
			       safe_val4(NULL, rsc, cur_node, details, id));

			rsc->stop->optional = TRUE;
			rsc->start->optional = TRUE;
			rsc->stop->node = safe_val(NULL, rsc, cur_node);
			rsc->start->node = safe_val4(NULL, rsc, color,
						     details, chosen_node);
			
		} else if(safe_val4(NULL, rsc, cur_node, details, id) == NULL) {
			rsc->stop->optional = TRUE;
			rsc->start->node = safe_val4(NULL, rsc, color,
						     details, chosen_node);
			
		} else {
			rsc->stop->node = safe_val(NULL, rsc, cur_node);
			rsc->start->node = safe_val4(NULL, rsc, color,
						     details, chosen_node);
		}

		if(rsc->stop->node != NULL) {
			rsc->stop->runnable = TRUE;
		}
		if(rsc->start->node != NULL) {
			rsc->start->runnable = TRUE;
		}

		);
	
	return TRUE;
}

gboolean
stage6(GSListPtr *actions, GSListPtr *action_constraints,
       GSListPtr stonith_nodes, GSListPtr shutdown_nodes)
{
	int lpc = 0;
	int llpc = 0;
	slist_iter(
		node, node_t, shutdown_nodes, lpc,

		action_t *down_node =
			action_new(action_id++, NULL, shutdown_crm);
		down_node->node = node;
		down_node->runnable = TRUE;

		*actions = g_slist_append(*actions, down_node);
		
		slist_iter(
			rsc, resource_t, node->details->running_rsc, llpc,
			
			order_constraint_t *order = (order_constraint_t*)
				cl_malloc(sizeof(order_constraint_t));

			/* stop resources before shutdown */
			order->id = order_id++;
			order->lh_action = rsc->stop;
			order->rh_action = down_node;
			order->strength = must;
			*action_constraints =
				g_slist_append(*action_constraints, order);
			);
		);

	slist_iter(
		node, node_t, stonith_nodes, lpc,

		action_t *stonith_node =
			action_new(action_id++, NULL, stonith_op);
		stonith_node->node = node;
		stonith_node->runnable = TRUE;

		*actions = g_slist_append(*actions, stonith_node);

		slist_iter(
			rsc, resource_t, node->details->running_rsc, llpc,
			
			order_constraint_t *order = (order_constraint_t*)
				cl_malloc(sizeof(order_constraint_t));

			/* try stopping the resource before stonithing the node
			 *
			 * if the stop succeeds, the transitioner can then
			 * decided if  stonith is needed
			 */
			order->id = order_id++;
			order->lh_action = rsc->stop;
			order->rh_action = stonith_node;
			order->strength = must;
			*action_constraints =
				g_slist_append(*action_constraints, order);

			/* stonith before start */
			order = (order_constraint_t*)
				cl_malloc(sizeof(order_constraint_t));

			// try stopping the node first
			order->id = order_id++;
			order->lh_action = stonith_node;
			order->rh_action = rsc->start;
			order->strength = must;
			*action_constraints =
				g_slist_append(*action_constraints, order);
			);
		);
	

	return TRUE;
}
gboolean
stage7(GSListPtr resources, GSListPtr actions, GSListPtr action_constraints,
	GSListPtr *action_sets)
{
	int lpc = 0;

	slist_iter(
		order, order_constraint_t, action_constraints, lpc,

		action_wrapper_t *wrapper = (action_wrapper_t*)
			cl_malloc(sizeof(action_wrapper_t));
		wrapper->action = order->rh_action;
		wrapper->strength = order->strength;
		
		order->lh_action->actions_after =
			g_slist_append(order->lh_action->actions_after,
				       wrapper);

		wrapper = (action_wrapper_t*)
			cl_malloc(sizeof(action_wrapper_t));
		wrapper->action = order->lh_action;
		wrapper->strength = order->strength;

		order->rh_action->actions_before =
			g_slist_append(order->rh_action->actions_before,
				       wrapper);

		);

	update_runnable(actions);
	
	slist_iter(
		rsc, resource_t, resources, lpc,
		GSListPtr action_set = NULL;
		if(rsc->stop->runnable) {
			action_set = create_action_set(rsc->stop);
			if(action_set != NULL) {
				*action_sets = g_slist_append(*action_sets,
							      action_set);
			} else {
				pdebug("No actions resulting from %s->stop",
				       rsc->id);
			}
			
			
		}
		if(rsc->start->runnable) {
			action_set = create_action_set(rsc->start);
			if(action_set != NULL) {
				*action_sets = g_slist_append(*action_sets,
							      action_set);
			} else {
				pdebug("No actions resulting from %s->start",
				       rsc->id);
			}
		}
		
		);
	
	return TRUE;
}

gboolean
stage8(GSListPtr action_sets, xmlNodePtr *graph)
{
	int lpc = 0;
	xmlNodePtr xml_action_set = NULL;

	*graph = create_xml_node(NULL, "transition_graph");

/* errors...
	slist_iter(action, action_t, action_list, lpc,
		   if(action->optional == FALSE && action->runnable == FALSE) {
			   print_action("Ignoring", action, TRUE);
		   }
		);
*/
	int lpc2;
	slist_iter(action_set, GSList, action_sets, lpc,
		   pdebug("Processing Action Set %d", lpc);
		   xml_action_set = create_xml_node(NULL, "actions");
		   set_xml_property_copy(xml_action_set, "id", crm_itoa(lpc));

		   slist_iter(action, action_t, action_set, lpc2,
			      xmlNodePtr xml_action = action2xml(action);
			      xmlAddChild(xml_action_set, xml_action);
			   )
		   xmlAddChild(*graph, xml_action_set);
		);

	xml_message_debug(*graph, "created action list");
	
	return TRUE;
}



gboolean
summary(GSListPtr resources)
{
	int lpc = 0;
	slist_iter(
		rsc, resource_t, resources, lpc,
		char *rsc_id = safe_val(NULL, rsc, id);
		char *node_id = safe_val4(NULL, rsc, cur_node, details, id);
		char *new_node_id = safe_val6(NULL, rsc, color, details,
					      chosen_node, details, id);
		if(rsc->runnable == FALSE) {
			cl_log(LOG_ERR,
			       "Resource %s was not runnable",
			       rsc_id);
			if(node_id != NULL) {
				cl_log(LOG_WARNING,
				       "Stopping Resource (%s) on node %s",
				       rsc_id,
				       node_id);
			}

		} else if(safe_val4(NULL, rsc, color, details, chosen_node) == NULL) {
			cl_log(LOG_ERR,
			       "Could not allocate Resource %s",
			       rsc_id);
			if(node_id != NULL) {
				
				cl_log(LOG_WARNING,
				       "Stopping Resource (%s) on node %s",
				       rsc_id,
				       node_id);
			}
			
		} else if(safe_str_eq(node_id, new_node_id)){
			cl_log(LOG_DEBUG,
			       "No change for Resource %s (%s)",
			       rsc_id,
			       safe_val4(NULL, rsc, cur_node, details, id));
			
		} else if(node_id == NULL) {
			cl_log(LOG_INFO,
			       "Starting Resource %s on %s",
			       rsc_id,
			       new_node_id);
			
		} else {
			cl_log(LOG_INFO,
			       "Moving Resource %s from %s to %s",
			       rsc_id,
			       node_id,
			       new_node_id);
		}
		);
	
	
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

	slist_iter(
		color_n, color_t, colors, lpc,
		node_t *other_node = pe_find_node(color_n->details->candidate_nodes,
						  color->details->chosen_node->details->id);
		color_n->details->candidate_nodes =
			g_slist_remove(color_n->details->candidate_nodes,
				       other_node);
		);
	
	return TRUE;
}


gboolean
unpack_nodes(xmlNodePtr xml_nodes, GSListPtr *nodes)
{
	pdebug("Begining unpack... %s", __FUNCTION__);
	while(xml_nodes != NULL) {
		pdebug("Processing node...");
		xmlNodePtr xml_obj = xml_nodes;
		xmlNodePtr attrs = xml_obj->children;
		const char *id = xmlGetProp(xml_obj, "id");
		const char *type = xmlGetProp(xml_obj, "type");
		if(attrs != NULL) {
			attrs = attrs->children;
		}
		
		xml_nodes = xml_nodes->next;
	
		if(id == NULL) {
			cl_log(LOG_ERR, "Must specify id tag in <node>");
			continue;
		}
		if(type == NULL) {
			cl_log(LOG_ERR, "Must specify type tag in <node>");
			continue;
		}
		node_t *new_node = cl_malloc(sizeof(node_t));
		new_node->weight = 1.0;
		new_node->fixed = FALSE;
		new_node->details = (struct node_shared_s*)
			cl_malloc(sizeof(struct node_shared_s*));
		new_node->details->online = FALSE;
		new_node->details->unclean = FALSE;
		new_node->details->shutdown = FALSE;
		new_node->details->running_rsc = NULL;
		new_node->details->id = cl_strdup(id);
		new_node->details->attrs =
			g_hash_table_new(g_str_hash, g_str_equal);
		new_node->details->type = node_ping;
		if(safe_str_eq(type, "node")) {
			new_node->details->type = node_member;
		}
		

		while(attrs != NULL){
			const char *name = xmlGetProp(attrs, "name");
			const char *value = xmlGetProp(attrs, "value");
			if(name != NULL && value != NULL) {
				g_hash_table_insert(new_node->details->attrs,
						    cl_strdup(name),
						    cl_strdup(value));
			}
			attrs = attrs->next;
		}
		
		pdebug("Adding node id... %s (%p)", id, new_node);

		*nodes = g_slist_append(*nodes, new_node);    
	}
  
	*nodes = g_slist_sort(*nodes, sort_node_weight);

	return TRUE;
}

gboolean 
unpack_resources(xmlNodePtr xml_resources,
		 GSListPtr *resources,
		 GSListPtr *actions,
		 GSListPtr *action_cons,
		 GSListPtr all_nodes)
{
	pdebug("Begining unpack... %s", __FUNCTION__);
	while(xml_resources != NULL) {
		xmlNodePtr xml_obj = xml_resources;
		const char *id = xmlGetProp(xml_obj, "id");
		const char *priority = xmlGetProp(xml_obj, "priority");
		float priority_f = atof(priority);

		xml_resources = xml_resources->next;

		pdebug("Processing resource...");
		
		if(id == NULL) {
			cl_log(LOG_ERR, "Must specify id tag in <resource>");
			continue;
		}
		resource_t *new_rsc = cl_malloc(sizeof(resource_t));
		new_rsc->xml = xml_obj; // copy first
		new_rsc->priority = priority_f; 
		new_rsc->candidate_colors = NULL;
		new_rsc->color = NULL; 
		new_rsc->runnable = TRUE; 
		new_rsc->provisional = TRUE; 
		new_rsc->allowed_nodes = node_list_dup(all_nodes);    
		new_rsc->rsc_cons = NULL; 
		new_rsc->node_cons = NULL; 
		new_rsc->id = cl_strdup(id);

		
		action_t *action_stop = action_new(action_id++, new_rsc,
						    stop_rsc);

		action_t *action_start = action_new(action_id++, new_rsc,
						    start_rsc);

		new_rsc->stop = action_stop;
		*actions = g_slist_append(*actions, action_stop);

		new_rsc->start = action_start;
		*actions = g_slist_append(*actions, action_start);

		order_constraint_t *order = (order_constraint_t*)
			cl_malloc(sizeof(order_constraint_t));
		order->id = order_id++;
		order->lh_action = action_stop;
		order->rh_action = action_start;
		order->strength = startstop;
		*action_cons = g_slist_append(*action_cons, order);
	
		pdebug_action(print_resource("Added", new_rsc, FALSE));
		*resources = g_slist_append(*resources, new_rsc);
	}
	*resources = g_slist_sort(*resources, sort_rsc_priority);

	return TRUE;
}



gboolean 
unpack_constraints(xmlNodePtr xml_constraints,
		   GSListPtr nodes, GSListPtr resources,
		   GSListPtr *node_constraints,
		   GSListPtr *action_constraints)
{
	pdebug("Begining unpack... %s", __FUNCTION__);
	while(xml_constraints != NULL) {
		const char *id = xmlGetProp(xml_constraints, "id");
		xmlNodePtr xml_obj = xml_constraints;
		xml_constraints = xml_constraints->next;
		if(id == NULL) {
			cl_log(LOG_ERR, "Constraint must have an id");
			continue;
		}

		pdebug("Processing constraint %s %s",
			      xml_obj->name,id);
		if(safe_str_eq("rsc_to_rsc", xml_obj->name)) {
			unpack_rsc_to_rsc(xml_obj, resources,
					  action_constraints);

		} else if(safe_str_eq("rsc_to_node", xml_obj->name)) {
			unpack_rsc_to_node(xml_obj, resources, nodes,
					   node_constraints);
			
		} else if(safe_str_eq("rsc_to_attr", xml_obj->name)) {
			unpack_rsc_to_attr(xml_obj, resources, nodes,
					   node_constraints);
			
		} else {
			cl_log(LOG_ERR, "Unsupported constraint type: %s",
			       xml_obj->name);
		}
	}

	return TRUE;
}


gboolean 
apply_node_constraints(GSListPtr constraints, 
		       GSListPtr resources,
		       GSListPtr nodes)
{
	pdebug("Applying constraints... %s", __FUNCTION__);
	int lpc = 0;
	slist_iter(
		cons, rsc_to_node_t, constraints, lpc,
		pdebug_action(print_rsc_to_node("Applying", cons, FALSE));
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

		cons->rsc_lh->node_cons =
			g_slist_append(cons->rsc_lh->node_cons, cons);

		if(cons->node_list_rh == NULL) {
			cl_log(LOG_ERR,
			       "RHS of rsc_to_node (%s) is NULL",
			       cons->id);
			continue;
		} else {
			int llpc = 0;
			slist_iter(node_rh, node_t, cons->node_list_rh, llpc,
				   update_node_weight(cons,
						      node_rh->details->id,
						      nodes));
		}
		
		/* dont add it to the resource,
		 *  the information is in the resouce's node list
		 */
		);
	
	return TRUE;
	
}


// remove nodes that are down, stopping
// create +ve rsc_to_node constraints between resources and the nodes they are running on
// anything else?
gboolean
unpack_status(xmlNodePtr status,
	      GSListPtr nodes,
	      GSListPtr rsc_list,
	      GSListPtr *node_constraints)
{
	pdebug("Begining unpack %s", __FUNCTION__);
	while(status != NULL) {
		const char *id = xmlGetProp(status, "id");
		const char *state = xmlGetProp(status, "state");
		const char *exp_state = xmlGetProp(status, "exp_state");
		xmlNodePtr lrm_state = find_xml_node(status, "lrm");
		xmlNodePtr attrs = find_xml_node(status, "attributes");

		lrm_state = find_xml_node(lrm_state, "lrm_resources");
		lrm_state = find_xml_node(lrm_state, "rsc_state");
		status = status->next;

		pdebug("Processing node %s", id);

		if(id == NULL){
			// error
			continue;
		}
		pdebug("Processing node attrs");
		
		node_t *this_node = pe_find_node(nodes, id);
		while(attrs != NULL){
			const char *name = xmlGetProp(attrs, "name");
			const char *value = xmlGetProp(attrs, "value");
			
			if(name != NULL && value != NULL
			   && safe_val(NULL, this_node, details) != NULL) {
				pdebug("Adding %s => %s",
					      name, value);
				g_hash_table_insert(this_node->details->attrs,
						    cl_strdup(name),
						    cl_strdup(value));
			}
			attrs = attrs->next;
		}

		pdebug("determining node state");
		
		if(safe_str_eq(exp_state, "active")
		   && safe_str_eq(state, "active")) {
			// process resource, make +ve preference
			this_node->details->online = TRUE;
			
		} else {
			pdebug("remove %s", __FUNCTION__);
			// remove node from contention
			this_node->weight = -1;
			this_node->fixed = TRUE;

			pdebug("state %s, expected %s",
				      state, exp_state);
			
			if(safe_str_eq(state, "shutdown")){
				// create shutdown req
				this_node->details->shutdown = TRUE;

			} else if(safe_str_eq(exp_state, "active")
				  && safe_str_neq(state, "active")) {
				// mark unclean in the xml
				this_node->details->unclean = TRUE;
				
				// remove any running resources from being allocated
			}
		}

		pdebug("Processing node lrm state");
		process_node_lrm_state(this_node, lrm_state,
				       rsc_list,  nodes,
				       node_constraints);
	}

	return TRUE;
	
}

gboolean
is_active(rsc_to_node_t *cons)
{
	return TRUE;
}



gboolean
strict_preproc(rsc_to_rsc_t *constraint,
	       color_t *local_color,
	       color_t *other_color,
	       GSListPtr *colors,
	       GSListPtr resources)
{
	resource_t * lh_resource = constraint->rsc_lh;
	switch(constraint->strength) {
		case must:
			if(constraint->rsc_rh->runnable == FALSE) {
				cl_log(LOG_WARNING,
				       "Resource %s must run on the same node"
				       " as %s (cons %s), but %s is not"
				       " runnable.",
				       constraint->rsc_lh->id,
				       constraint->rsc_rh->id,
				       constraint->id,
				       constraint->rsc_rh->id);
				constraint->rsc_lh->runnable = FALSE;
			}
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
			pdebug("# Colors %d, Nodes %d",
				      g_slist_length(*colors),
				      max_valid_nodes);
			       
			if(g_slist_length(*colors) < max_valid_nodes
//			   && g_slist_length(lh_resource->candidate_colors)==1
				) {
				create_color(colors,
					     lh_resource->allowed_nodes,
					     resources);
			} 
			
			
			break;
		case must_not:
			if(constraint->rsc_rh->provisional == FALSE) {
				lh_resource->candidate_colors =
					g_slist_remove(
						lh_resource->candidate_colors,
						local_color);
			}
			break;
		default:
			// error
			break;
	}
	return TRUE;
}

gboolean
strict_postproc(rsc_to_rsc_t *constraint,
		color_t *local_color,
		color_t *other_color,
		GSListPtr *colors,
		GSListPtr resources)
{
	print_rsc_to_rsc("Post processing", constraint, FALSE);
	
	switch(constraint->strength) {
		case must:
			if(constraint->rsc_rh->provisional == TRUE) {
				constraint->rsc_rh->color = other_color;
				constraint->rsc_rh->provisional = FALSE;
				color_resource(constraint->rsc_rh,
					       colors, resources);
			}
			// else check for error
			if(constraint->rsc_lh->runnable == FALSE) {
				cl_log(LOG_WARNING,
				       "Resource %s must run on the same node"
				       " as %s (cons %s), but %s is not"
				       " runnable.",
				       constraint->rsc_rh->id,
				       constraint->rsc_lh->id,
				       constraint->id,
				       constraint->rsc_lh->id);
				constraint->rsc_rh->runnable = FALSE;
				
			}
			
			break;
			
		case should:
			break;
		case should_not:
			break;
		case must_not:
			if(constraint->rsc_rh->provisional == TRUE) {
				// check for error
			}
			break;
		default:
			// error
			break;
	}
	return TRUE;
}

gboolean
choose_color(resource_t *lh_resource, GSListPtr candidate_colors)
{
	int lpc = 0;

	if(lh_resource->runnable == FALSE) {
		lh_resource->color = no_color;
		lh_resource->provisional = FALSE;
	} else {
		GSListPtr sorted_colors = g_slist_sort(candidate_colors,
						       sort_color_weight);
		
		lh_resource->candidate_colors = sorted_colors;
	
		pdebug(			      "Choose a color from %d possibilities",
			      g_slist_length(sorted_colors));
	}

	if(lh_resource->provisional) {
		slist_iter(
			this_color, color_t,lh_resource->candidate_colors, lpc,
			GSListPtr intersection = node_list_and(
				this_color->details->candidate_nodes, 
				lh_resource->allowed_nodes);

			if(g_slist_length(intersection) != 0) {
				// TODO: merge node weights
				g_slist_free(this_color->details->candidate_nodes);
				this_color->details->candidate_nodes = intersection;
				lh_resource->color = this_color;
				lh_resource->provisional = FALSE;
				break;
			}
			);
	}
	return !lh_resource->provisional;
}

gboolean
unpack_rsc_to_node(xmlNodePtr xml_obj,
		   GSListPtr rsc_list,
		   GSListPtr node_list,
		   GSListPtr *node_constraints)	
{
	
	xmlNodePtr node_ref = xml_obj->children;
	rsc_to_node_t *new_con = cl_malloc(sizeof(rsc_to_node_t));
	const char *id_lh =  xmlGetProp(xml_obj, "from");
	const char *id =  xmlGetProp(xml_obj, "id");

	const char *mod = xmlGetProp(xml_obj, "modifier");
	const char *weight = xmlGetProp(xml_obj, "weight");
	float weight_f = atof(weight);

	resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);
	if(rsc_lh == NULL) {
		cl_log(LOG_ERR, "No resource (con=%s, rsc=%s)",
		       id, id_lh);
	}

	new_con->id = cl_strdup(id);
	new_con->rsc_lh = rsc_lh;
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
/*
  <rsc_to_node>
  <node_ref id= type= name=/>
  <node_ref id= type= name=/>
  <node_ref id= type= name=/>
*/		
//			

	while(node_ref != NULL) {
		const char *id_rh = xmlGetProp(node_ref, "name");
		node_t *node_rh =  pe_find_node(node_list, id_rh);
		if(node_rh == NULL) {
			// error
			cl_log(LOG_ERR,
			       "node %s (from %s) not found",
			       id_rh, node_ref->name);
			continue;
		}
		
		new_con->node_list_rh =
			g_slist_append(new_con->node_list_rh,
				       node_rh);

		
		/* dont add it to the resource,
		 *  the information is in the resouce's node list
		 */
		node_ref = node_ref->next;
	}
	*node_constraints = g_slist_append(*node_constraints, new_con);

	return TRUE;
}


gboolean
unpack_rsc_to_attr(xmlNodePtr xml_obj,
		   GSListPtr rsc_list,
		   GSListPtr node_list,
		   GSListPtr *node_constraints)
{
/*
       <rsc_to_attr id="cons4" from="rsc2" weight="20.0" modifier="inc">
       <attr_expression id="attr_exp_1"/>
          <node_match id="node_match_1" type="has_attr" target="cpu"/>
          <node_match id="node_match_2" type="attr_value" target="kernel" value="2.6"/>
       </attr_expression>
       <attr_expression id="attr_exp_2"/>
          <node_match id="node_match_3" type="has_attr" target="hdd"/>
          <node_match id="node_match_4" type="attr_value" target="kernel" value="2.4"/>
       </attr_expression>

   Translation:
       give any node a +ve weight of 20.0 to run rsc2 if:
          attr "cpu" is set _and_ "kernel"="2.6", _or_
	  attr "hdd" is set _and_ "kernel"="2.4"

   Further translation:
       2 constraints that give any node a +ve weight of 20.0 to run rsc2
       cons1: attr "cpu" is set and "kernel"="2.6"
       cons2: attr "hdd" is set and "kernel"="2.4"
       
 */
	
	xmlNodePtr attr_exp = xml_obj->children;
	const char *id_lh   =  xmlGetProp(xml_obj, "from");
	const char *mod     = xmlGetProp(xml_obj, "modifier");
	const char *weight  = xmlGetProp(xml_obj, "weight");
	const char *id      = xmlGetProp(attr_exp, "id");
	float weight_f = atof(weight);
	enum con_modifier a_modifier = modifier_none;
	
	resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);
	if(rsc_lh == NULL) {
		cl_log(LOG_ERR, "No resource (con=%s, rsc=%s)",
		       id, id_lh);
		return FALSE;
	}
			
	if(safe_str_eq(mod, "set")){
		a_modifier = set;
	} else if(safe_str_eq(mod, "inc")){
		a_modifier = inc;
	} else if(safe_str_eq(mod, "dec")){
		a_modifier = dec;
	} else {
		// error
	}		

	if(attr_exp == NULL) {
		cl_log(LOG_WARNING, "no attrs for constraint %s", id);
	}
	
	while(attr_exp != NULL) {
		const char *id_rh = xmlGetProp(attr_exp, "name");
		const char *id = xmlGetProp(attr_exp, "id");
		rsc_to_node_t *new_con = cl_malloc(sizeof(rsc_to_node_t));
		new_con->id = cl_strdup(id);
		new_con->rsc_lh = rsc_lh;
		new_con->weight = weight_f;
		new_con->modifier = a_modifier;

		new_con->node_list_rh = match_attrs(attr_exp, node_list);
		
		if(new_con->node_list_rh == NULL) {
			// error
			cl_log(LOG_ERR,
			       "node %s (from %s) not found",
			       id_rh, attr_exp->name);
		}
		pdebug_action(print_rsc_to_node("Added", new_con, FALSE));
		*node_constraints = g_slist_append(*node_constraints, new_con);

		/* dont add it to the resource,
		 *  the information is in the resouce's node list
		 */
		attr_exp = attr_exp->next;
	}
	return TRUE;
}

gboolean
update_node_weight(rsc_to_node_t *cons, char *id, GSListPtr nodes)
{
	node_t *node_rh = pe_find_node(cons->rsc_lh->allowed_nodes, id);

	if(node_rh == NULL) {
		node_t *node_tmp = pe_find_node(nodes, id);
		node_rh = node_copy(node_tmp);
		cons->rsc_lh->allowed_nodes =
			g_slist_append(cons->rsc_lh->allowed_nodes,
				       node_rh);
	}

	if(node_rh == NULL) {
		// error
		return FALSE;
	}

	if(node_rh->fixed) {
		// warning
		cl_log(LOG_WARNING,
		       "Constraint %s is irrelevant as the"
		       " weight of node %s is fixed as %f.",
		       cons->id,
		       node_rh->details->id,
		       node_rh->weight);
		return TRUE;
	}
	
	pdebug(		      "Constraint %s: node %s weight %s %f.",
		      cons->id,
		      node_rh->details->id,
		      modifier2text(cons->modifier),
		      node_rh->weight);
	
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
	return TRUE;
}

gboolean
process_node_lrm_state(node_t *node, xmlNodePtr lrm_state,
		       GSListPtr rsc_list, GSListPtr nodes,
		       GSListPtr *node_constraints)
{
	pdebug("here %s", __FUNCTION__);
	
	while(lrm_state != NULL) {
		const char *id    = xmlGetProp(lrm_state, "id");
		const char *rsc_id    = xmlGetProp(lrm_state, "rsc_id");
		const char *node_id   = xmlGetProp(lrm_state, "node_id");
		const char *rsc_state = xmlGetProp(lrm_state, "rsc_state");
		resource_t *rsc_lh = pe_find_resource(rsc_list, rsc_id);
		rsc_lh->cur_node = node;

		node->details->running_rsc =
			g_slist_append(node->details->running_rsc, rsc_lh);

		/* it is runnable, but depends on a stonith op 
		if(safe_val3(FALSE, node, details, unclean)) {
			rsc_lh->runnable = FALSE;
		}
		*/
		
		if((safe_str_eq(rsc_state, "starting"))
		   || (safe_str_eq(rsc_state, "started"))) {
			
			node_t *node_rh;
			rsc_to_node_t *new_cons =
				cl_malloc(sizeof(rsc_to_node_t));
			new_cons->id = cl_strdup(id); // genereate one
			new_cons->weight = 100.0;
			new_cons->modifier = inc;
			
			new_cons->rsc_lh = rsc_lh;
			node_rh = pe_find_node(nodes, node_id);
			
			new_cons->node_list_rh = g_slist_append(NULL, node_rh);
					
			*node_constraints =
				g_slist_append(*node_constraints, new_cons);
			
			pdebug_action(print_rsc_to_node(
					      "Added", new_cons, FALSE));
			
		} else if(safe_str_eq(rsc_state, "stop_fail")) {
			// do soemthing
		} // else no preference

		lrm_state = lrm_state->next;
	}
	return TRUE;
}

GSListPtr
match_attrs(xmlNodePtr attr_exp, GSListPtr node_list)
{
	int lpc = 0;
	GSListPtr result = NULL;
	slist_iter(
		node, node_t, node_list, lpc,
		xmlNodePtr node_match = attr_exp->children;
		gboolean accept = TRUE;
		
		while(accept && node_match != NULL) {
			const char *type =xmlGetProp(node_match, "type");
			const char *value=xmlGetProp(node_match, "value");
			const char *name =xmlGetProp(node_match, "target");
			node_match = node_match->next;
			
			if(name == NULL || type == NULL) {
				// error
				continue;
			}
			
			const char *h_val = (const char*)
				g_hash_table_lookup(node->details->attrs, name);
			
			if(h_val != NULL && safe_str_eq(type, "has_attr")){
				accept = TRUE;
			} else if(h_val == NULL
				     && safe_str_eq(type, "not_attr")) {
				accept = TRUE;
			} else if(h_val != NULL
				  && safe_str_eq(type, "attr_value")
				  && safe_str_eq(h_val, value)) {
				accept = TRUE;
			} else {
				accept = FALSE;
			}
		}
		
		if(accept) {
			result = g_slist_append(result, node);
			
		}		   
		);
	
	return result;
}

gboolean
create_rsc_to_rsc(const char *id, enum con_strength strength,
		  resource_t *rsc_lh, resource_t *rsc_rh)
{
	if(rsc_lh == NULL || rsc_rh == NULL){
		// error
		return FALSE;
	}

	rsc_to_rsc_t *new_con = cl_malloc(sizeof(rsc_to_node_t));
	rsc_to_rsc_t *inverted_con = NULL;

	new_con->id = cl_strdup(id);
	new_con->rsc_lh = rsc_lh;
	new_con->rsc_rh = rsc_rh;
	new_con->strength = strength;
	
	inverted_con = invert_constraint(new_con);

	rsc_lh->rsc_cons = g_slist_insert_sorted(rsc_lh->rsc_cons,
						 inverted_con, sort_cons_strength);
	rsc_rh->rsc_cons = g_slist_insert_sorted(rsc_rh->rsc_cons,
						 new_con, sort_cons_strength);

	return TRUE;
}

gboolean
create_ordering(const char *id, enum con_strength strength,
		resource_t *rsc_lh, resource_t *rsc_rh,
		GSListPtr *action_constraints)
{
	if(rsc_lh == NULL || rsc_rh == NULL){
		// error
		return FALSE;
	}
	
	action_t *lh_stop = rsc_lh->stop;
	action_t *lh_start = rsc_lh->start;
	action_t *rh_stop = rsc_rh->stop;
	action_t *rh_start = rsc_rh->start;
	
	order_constraint_t *order = (order_constraint_t*)
		cl_malloc(sizeof(order_constraint_t));
	order->id = order_id++;
	order->lh_action = lh_stop;
	order->rh_action = rh_stop;
	order->strength = strength;
	*action_constraints = g_slist_append(*action_constraints, order);
	
	order = (order_constraint_t*)
		cl_malloc(sizeof(order_constraint_t));
	order->id = order_id++;
	order->lh_action = rh_start;
	order->rh_action = lh_start;
	order->strength = strength;
	*action_constraints = g_slist_append(*action_constraints, order);

	return TRUE;
}

gboolean
unpack_rsc_to_rsc(xmlNodePtr xml_obj,
		  GSListPtr rsc_list,
		  GSListPtr *action_constraints)
{
	const char *id_lh =  xmlGetProp(xml_obj, "from");
	const char *id =  xmlGetProp(xml_obj, "id");
	resource_t *rsc_lh = pe_find_resource(rsc_list, id_lh);
	const char *id_rh = xmlGetProp(xml_obj, "to");
	resource_t *rsc_rh = pe_find_resource(rsc_list, id_rh);
	const char *strength = xmlGetProp(xml_obj, "strength");
	const char *type = xmlGetProp(xml_obj, "type");
	enum con_strength strength_e = ignore;

	if(rsc_lh == NULL) {
		cl_log(LOG_ERR, "No resource (con=%s, rsc=%s)",
		       id, id_lh);
		return FALSE;
	}
	if(safe_str_eq(strength, "must")) {
		strength_e = must;
		
	} else if(safe_str_eq(strength, "should")) {
		strength_e = should;
		
	} else if(safe_str_eq(strength, "should_not")) {
		strength_e = should_not;
		
	} else if(safe_str_eq(strength, "must_not")) {
		strength_e = must_not;
	} else {
		// error
	}

	if(safe_str_eq(type, "ordering")) {
		// make an action_cons instead
		return create_ordering(id, strength_e, rsc_lh, rsc_rh,
				       action_constraints);
	}

	return create_rsc_to_rsc(id, strength_e, rsc_lh, rsc_rh);
}


GSListPtr
create_action_set(action_t *action)
{
	int lpc = 0;
	GSListPtr result = NULL;
	GSListPtr tmp = NULL;

	if(action->processed) {
		return NULL;
	}

	pdebug_action(print_action("Create action set for", action, FALSE));
	
	// process actions_before
	if(action->seen_count == 0) {
		pdebug("Processing \"before\" for action %d", action->id);
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			tmp = create_action_set(other->action);
			pdebug("%d (%d total) \"before\" actions for %d)",
			       g_slist_length(tmp), g_slist_length(result),action->id);
			result = g_slist_concat(result, tmp);
			);

		// add ourselves
		pdebug("Adding self %d", action->id);
		if(action->processed == FALSE) {
			result = g_slist_append(result, action);
			action->processed = TRUE;
		}
		
	} else {
		pdebug("Already seen action %d", action->id);
		pdebug("Processing \"before\" for action %d", action->id);
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			
			if(other->action->seen_count > action->seen_count
			   && other->strength == must) {
				tmp = create_action_set(other->action);
				pdebug("%d (%d total) \"before\" actions for %d)",
				       g_slist_length(tmp), g_slist_length(result),action->id);
				result = g_slist_concat(result, tmp);
			}
			
			);

		// add ourselves
		pdebug("Adding self %d", action->id);
		if(action->processed == FALSE) {
			result = g_slist_append(result, action);
			action->processed = TRUE;
		}

		// add strength == !MUST
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			
			tmp = create_action_set(other->action);
			pdebug("%d (%d total) post-self \"before\" actions for %d)",
			       g_slist_length(tmp), g_slist_length(result),action->id);
			result = g_slist_concat(result, tmp);
			);
	}
	
	action->seen_count = action->seen_count + 1;
	
	// process actions_after
	pdebug("Processing \"after\" for action %d", action->id);
	slist_iter(
		other, action_wrapper_t, action->actions_after, lpc,
		tmp = create_action_set(other->action);
		pdebug("%d (%d total) \"after\" actions for %d)",
		       g_slist_length(tmp), g_slist_length(result),action->id);
		result = g_slist_concat(result, tmp);
		);
	
	return result;
}


gboolean
update_runnable(GSListPtr actions)
{

	int lpc = 0, lpc2 = 0;
	gboolean change = TRUE;

	while(change) {
		change = FALSE;
		slist_iter(
			action, action_t, actions, lpc,

			if(action->runnable) {
				continue;
			} else if(action->optional) {
				continue;
			}
			
			slist_iter(
				other, action_wrapper_t, action->actions_before, lpc2,
				if(other->action->runnable) {
					change = TRUE;
				}
				other->action->runnable = FALSE;
				);
			);
	}
	return TRUE;
}

void
color_resource(resource_t *lh_resource, GSListPtr *colors, GSListPtr resources)
{
	int lpc = 0;

	pdebug_action(print_resource("Coloring", lh_resource, FALSE));
	
	if(lh_resource->provisional == FALSE) {
			// already processed this resource
		return;
	}
	
	lh_resource->rsc_cons = g_slist_sort(lh_resource->rsc_cons,
					     sort_cons_strength);

	pdebug("=== Pre-processing");
	//------ Pre-processing
	slist_iter(
		constraint, rsc_to_rsc_t, lh_resource->rsc_cons, lpc,
		color_t *other_color = NULL;
		color_t *local_color = NULL;
		if(lh_resource->runnable == FALSE) {
			break;
		}
		pdebug_action(print_rsc_to_rsc(
				      "Processing constraint",
				      constraint, FALSE));
		
		if(constraint->rsc_rh == NULL) {
			cl_log(LOG_ERR,
			       "rsc_rh was NULL for %s",
			       constraint->id);
			continue;
		}
		other_color = constraint->rsc_rh->color;
		local_color = find_color(lh_resource->candidate_colors,
					 other_color);
		strict_preproc(constraint, local_color, other_color,
			       colors, resources);
		);

	
	// filter out nodes with a negative weight
	filter_nodes(lh_resource);
  
	/* Choose a color from the candidates or,
	 *  create a new one if no color is suitable 
	 * (this may need modification pending further napkin drawings)
	 */
	choose_color(lh_resource, lh_resource->candidate_colors);	
  
	pdebug("* Colors %d, Nodes %d",
		      g_slist_length(*colors),
		      max_valid_nodes);
	
	if(lh_resource->provisional
		&& g_slist_length(*colors) < max_valid_nodes) {
		// Create new color
		pdebug("Create a new color");
		lh_resource->color = create_color(colors,
						  lh_resource->allowed_nodes,
						  resources);
		lh_resource->provisional = FALSE;

	} else if(lh_resource->provisional) {
		cl_log(LOG_ERR, "Could not color resource %s", lh_resource->id);
		print_resource("ERROR: No color", lh_resource, FALSE);
		lh_resource->color = no_color;
		lh_resource->provisional = FALSE;
		
	}

	pdebug_action(print_resource("Post-processing", lh_resource, FALSE));

	//------ Post-processing

	color_t *local_color = lh_resource->color;
	slist_iter(
		constraint, rsc_to_rsc_t, lh_resource->rsc_cons, lpc,
		color_t *other_color =
			find_color(constraint->rsc_rh->candidate_colors,
				   local_color);

		strict_postproc(constraint, local_color, other_color,
				colors, resources);
		);
	
	pdebug_action(print_resource("Colored", lh_resource, FALSE));
}

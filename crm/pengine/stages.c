/* $Id: stages.c,v 1.10 2004/07/05 09:51:39 andrew Exp $ */
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>


/*
 * Unpack everything
 * At the end you'll have:
 *  - A list of nodes
 *  - A list of resources (each with any dependancies on other resources)
 *  - A list of constraints between resources and nodes
 *  - A list of constraints between start/stop actions
 *  - A list of nodes that need to be stonith'd
 *  - A list of nodes that need to be shutdown
 *  - A list of the possible stop/start actions (without dependancies)
 */
gboolean
stage0(xmlNodePtr cib,
       GListPtr *resources,
       GListPtr *nodes, GListPtr *node_constraints,
       GListPtr *actions, GListPtr *action_constraints,
       GListPtr *stonith_list, GListPtr *shutdown_list)
{
//	int lpc;
	xmlNodePtr cib_nodes       = get_object_root(
		XML_CIB_TAG_NODES,       cib);
	xmlNodePtr cib_status      = get_object_root(
		XML_CIB_TAG_STATUS,      cib);
	xmlNodePtr cib_resources   = get_object_root(
		XML_CIB_TAG_RESOURCES,   cib);
	xmlNodePtr cib_constraints = get_object_root(
		XML_CIB_TAG_CONSTRAINTS, cib);
	xmlNodePtr config          = get_object_root(
		XML_CIB_TAG_CRMCONFIG,   cib);
	xmlNodePtr agent_defaults  = NULL;
	//get_object_root(XML_CIB_TAG_RA_DEFAULTS, cib);

	/* reset remaining global variables */
	max_valid_nodes = 0;
	order_id = 1;
	action_id = 1;

	unpack_config(config);
	
	unpack_global_defaults(agent_defaults);
	
	unpack_nodes(safe_val(NULL, cib_nodes, children), nodes);

	unpack_resources(safe_val(NULL, cib_resources, children),
			 resources, actions, action_constraints, *nodes);

	int old_log = 0;
	old_log = set_crm_log_level(LOG_TRACE);
	unpack_status(safe_val(NULL, cib_status, children),
		      *nodes, *resources, actions, node_constraints);

	unpack_constraints(safe_val(NULL, cib_constraints, children),
			   *nodes, *resources,
			   node_constraints, action_constraints);

//	set_crm_log_level(old_log);
	return TRUE;
}

/*
 * Count how many valid nodes we have (so we know the maximum number of
 *  colors we can resolve).
 *
 * Apply node constraints (ie. filter the "allowed_nodes" part of resources
 */
gboolean
stage1(GListPtr node_constraints, GListPtr nodes, GListPtr resources)
{
	int lpc = 0;
	
	slist_iter(
		node, node_t, nodes, lpc,
		if(node == NULL) {
			/* error */
		} else if(node->weight >= 0.0 /* global weight */
			  && node->details->online
			  && node->details->type == node_member) {
			max_valid_nodes++;
		}	
		);

	apply_node_constraints(node_constraints, nodes);

	/* will also filter -ve "final" weighted nodes from resources'
	 *   allowed lists while we are there
	 */
	apply_agent_constraints(resources);

	return TRUE;
} 



/*
 * Choose a color for all resources from highest priority and XML_STRENGTH_VAL_MUST
 *  dependancies to lowest, creating new colors as necessary (returned
 *  as "colors").
 *
 * Some nodes may be colored as a "no_color" meaning that it was unresolvable
 *  given the current node stati and constraints.
 */
gboolean
stage2(GListPtr sorted_rscs, GListPtr sorted_nodes, GListPtr *colors)
{
	int lpc;

	crm_trace("setup");
	
	if(no_color != NULL) {
		crm_free(no_color->details);
		crm_free(no_color);
	}
	
	crm_trace("create \"no color\"");
	no_color = create_color(NULL, NULL, NULL);
	
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

/*
 * not sure if this is a good idea or not, but eventually we might like
 *  to utilize as many nodes as possible... and this might be a convienient
 *  hook
 */
gboolean
stage3(GListPtr colors)
{
	// not sure if this is a good idea or not
	if(g_list_length(colors) > max_valid_nodes) {
		// we need to consolidate some
	} else if(g_list_length(colors) < max_valid_nodes) {
		// we can create a few more
	}
	return TRUE;
}

/*
 * Choose a node for each (if possible) color
 */
gboolean
stage4(GListPtr resources)
{
	int lpc = 0;
	int lpc2 = 0;
	slist_iter(
		rsc, resource_t, resources, lpc,

		if(rsc->color == NULL) {
			crm_err("No color associated with %s", rsc->id);
			continue;
			
		} else if(rsc->color->details->pending == FALSE) {
			continue;
		}
		
		choose_node_from_list(rsc->color);
		
		slist_iter(
			constraint, rsc_to_rsc_t, rsc->rsc_cons, lpc2,
			
			if(constraint->variant != same_node) {
				continue;
			}

			/* remove the node from the other color */
			color_t *other_c = constraint->rsc_rh->color;
			
			node_t *other_n = pe_find_node(
				other_c->details->candidate_nodes,
				safe_val6(NULL, rsc, color, details,
					  chosen_node, details, uname));

			if(other_c == NULL) {
				crm_err("No color associated with %s", constraint->id);
				continue;
			} else if(other_n == NULL) {
				crm_err("No node associated with rsc/color %s/%d",
					rsc->id, rsc->color->id);
				continue;
			}
			
			switch(constraint->strength) {
				case pecs_must_not:
					
					other_c->details->candidate_nodes =
						g_list_remove(
							other_c->details->candidate_nodes,
							other_n);
			
					crm_free(other_n);
					break;
				case pecs_should_not:
					other_n->weight = -1;
					break;
				default:
					break;
			}
			

			);
		);
	crm_verbose("done");
	return TRUE;
	
}

/*
 * Attach nodes to the actions that need to be taken
 *
 * Mark actions XML_LRM_ATTR_OPTIONAL if possible (Ie. if the start and stop are
 *  for the same node)
 *
 * Mark unrunnable actions
 */
gboolean
stage5(GListPtr resources)
{
	
	crm_verbose("filling in the nodes to perform the actions on");
	int lpc = 0;
	slist_iter(
		rsc, resource_t, resources, lpc,

		crm_debug_action(print_resource("Processing", rsc, FALSE));
		
		if(safe_val(NULL, rsc, stop) == NULL
		   || safe_val(NULL, rsc, start) == NULL) {
			// error
			crm_err("Either start action (%p) or"
				" stop action (%p) were not defined",
				safe_val(NULL, rsc, stop),
				safe_val(NULL, rsc, start));
			continue;
		}
		if(safe_val4(NULL, rsc, color, details, chosen_node) == NULL){
			rsc->stop->node = safe_val(NULL, rsc, cur_node);
			
			rsc->start->node    = NULL;
			rsc->stop->optional = FALSE;
			crm_warn("Stop resource %s (%s)",
				  safe_val(NULL, rsc, id),
				  safe_val5(NULL, rsc, stop, node,details,uname));

			crm_debug_action(
				print_action(
					CRMD_STATE_ACTIVE, rsc->stop, FALSE));
			
			
		} else if(safe_str_eq(safe_val4(NULL, rsc,cur_node,details,uname),
				      safe_val6(NULL, rsc, color ,details,
						chosen_node, details, uname))){
			crm_verbose("No change for Resource %s (%s)",
				    safe_val(NULL, rsc, id),
				    safe_val4(NULL,rsc,cur_node,details,uname));

			rsc->stop->node  = safe_val(NULL, rsc, cur_node);
			rsc->start->node = safe_val4(NULL, rsc, color,
						     details, chosen_node);
			
		} else if(safe_val4(NULL, rsc,cur_node,details,uname) == NULL) {
			rsc->start->node = safe_val4(NULL, rsc, color,
						     details, chosen_node);

			crm_debug("Start resource %s (%s)",
				  safe_val(NULL, rsc, id),
				  safe_val5(NULL, rsc, start,node,details,uname));
			rsc->start->optional = FALSE;
			
		} else {
			rsc->stop->node = safe_val(NULL, rsc, cur_node);
			rsc->start->node = safe_val4(NULL, rsc, color,
						     details, chosen_node);
			rsc->start->optional = FALSE;
			rsc->stop->optional  = FALSE;

			crm_debug("Move resource %s (%s -> %s)",
				  safe_val(NULL, rsc, id),
				  safe_val5(NULL, rsc, stop, node,details,uname),
				  safe_val5(NULL, rsc, start,node,details,uname));
		}

		if(rsc->stop->node == NULL) {
			rsc->stop->runnable = FALSE;
		}
		if(rsc->start->node == NULL) {
			rsc->start->runnable = FALSE;
		}

		);
	
	return TRUE;
}

/*
 * Create dependacies for stonith and shutdown operations
 */
gboolean
stage6(GListPtr *actions, GListPtr *action_constraints, GListPtr nodes)
{

	int lpc = 0;
	action_t *down_node = NULL;
	action_t *stonith_node = NULL;

	slist_iter(
		node, node_t, nodes, lpc,
		if(node->details->shutdown) {
			crm_warn("Scheduling Node %s for shutdown",
				 node->details->uname);
			
			down_node = action_new(NULL,shutdown_crm);
			down_node->node     = node;
			down_node->runnable = TRUE;
			down_node->optional = FALSE;
			
			*actions = g_list_append(*actions, down_node);
			
			shutdown_constraints(
				node, down_node, action_constraints);
			
		}

		if(node->details->unclean) {
			crm_warn("Scheduling Node %s for STONITH",
				 node->details->uname);

			stonith_node = action_new(NULL,stonith_op);
			stonith_node->node     = node;
			stonith_node->runnable = TRUE;
			stonith_node->optional = FALSE;

			if(down_node != NULL) {
				down_node->failure_is_fatal = FALSE;
			}
			
			*actions = g_list_append(*actions, stonith_node);
			
			stonith_constraints(node, stonith_node, down_node,
					    action_constraints);
		}
		);


	return TRUE;
}

/*
 * Determin the sets of independant actions and the correct order for the
 *  actions in each set.
 *
 * Mark dependancies of un-runnable actions un-runnable
 *
 */
gboolean
stage7(GListPtr resources, GListPtr actions, GListPtr action_constraints,
	GListPtr *action_sets)
{
	int lpc;
	action_wrapper_t *wrapper = NULL;
	GListPtr list = NULL;
	GListPtr action_set = NULL;

/*
	for(lpc = 0; lpc < g_list_length(action_constraints);  lpc++) {
		order_constraint_t *order = (order_constraint_t*)
			g_list_nth_data(action_constraints, lpc);
*/
	slist_iter(
		order, order_constraint_t, action_constraints, lpc,
			
		crm_verbose("%d Processing %d -> %d",
		       order->id,
		       order->lh_action->id,
		       order->rh_action->id);

		crm_debug_action(
			print_action("LH (stage7)", order->lh_action, FALSE));
		crm_debug_action(
			print_action("RH (stage7)", order->rh_action, FALSE));

		wrapper = (action_wrapper_t*)
			crm_malloc(sizeof(action_wrapper_t));
		wrapper->action = order->rh_action;
		wrapper->strength = order->strength;

		list = order->lh_action->actions_after;
		list = g_list_append(list, wrapper);
		order->lh_action->actions_after = list;

		wrapper = (action_wrapper_t*)
			crm_malloc(sizeof(action_wrapper_t));
		wrapper->action = order->lh_action;
		wrapper->strength = order->strength;

		list = order->rh_action->actions_before;
		list = g_list_append(list, wrapper);
		order->rh_action->actions_before = list;
		);
//	}
	
	update_runnable(actions);

	slist_iter(
		rsc, resource_t, resources, lpc,	

		action_set = NULL;
		/* any non-essential stop actions will be marked redundant by
		 *  during stage6
		 */
		action_set = create_action_set(rsc->start);
		if(action_set != NULL) {
			crm_verbose("Created action set for %s->start",
			       rsc->id);
			*action_sets = g_list_append(*action_sets,
						      action_set);
		} else {
			crm_verbose("No actions resulting from %s->start",
			       rsc->id);
		}
		);

	crm_verbose("Processing unconnected actions");
	action_set = NULL;
	slist_iter(
		action, action_t, actions, lpc,

		if(action->runnable && action->processed == FALSE) {
			action_set = g_list_append(action_set, action);
		}
		);
	
	if(action_set != NULL) {
		crm_verbose("Created action set for unconnected actions");
		*action_sets = g_list_append(*action_sets, action_set);
	} else {
		crm_verbose("No unconnected actions");
	}
	
	
	return TRUE;
}

/*
 * Create a dependancy graph to send to the transitioner (via the CRMd)
 */
gboolean
stage8(GListPtr action_sets, xmlNodePtr *graph)
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
	slist_iter(action_set, GList, action_sets, lpc,
		   crm_verbose("Processing Action Set %d", lpc);
		   xml_action_set = create_xml_node(NULL, "actions");
		   set_xml_property_copy(
			   xml_action_set, XML_ATTR_ID, crm_itoa(lpc));

		   slist_iter(action, action_t, action_set, lpc2,
			      xmlNodePtr xml_action = action2xml(action);
			      xmlAddChild(xml_action_set, xml_action);
			   )
		   xmlAddChild(*graph, xml_action_set);
		);

	xml_message_debug(*graph, "created action list");
	
	return TRUE;
}

/*
 * Print a nice human readable high-level summary of what we're going to do 
 */
gboolean
summary(GListPtr resources)
{
	int lpc = 0;
	const char *rsc_id      = NULL;
	const char *node_id     = NULL;
	const char *new_node_id = NULL;
	
	slist_iter(
		rsc, resource_t, resources, lpc,
		rsc_id = safe_val(NULL, rsc, id);
		node_id = safe_val4(NULL, rsc, cur_node, details, uname);
		new_node_id = safe_val6(
			NULL, rsc, color, details, chosen_node, details, uname);

		if(rsc->runnable == FALSE) {
			crm_err("Resource %s was not runnable", rsc_id);
			if(node_id != NULL) {
				crm_warn("Stopping Resource (%s) on node %s",
					 rsc_id, node_id);
			}

		} else if(safe_val4(NULL, rsc, color, details, chosen_node) == NULL) {
			crm_err("Could not allocate Resource %s", rsc_id);
			crm_debug_action(
				print_resource("Could not allocate",rsc,TRUE));
			if(node_id != NULL) {
				
				crm_warn("Stopping Resource (%s) on node %s",
					 rsc_id, node_id);
			}
			
		} else if(safe_str_eq(node_id, new_node_id)){
			crm_debug("No change for Resource %s (%s)",
				  rsc_id,
				  safe_val4(NULL, rsc, cur_node, details, uname));
			
		} else if(node_id == NULL) {
			crm_info("Starting Resource %s on %s",
				 rsc_id, new_node_id);
			
		} else {
			crm_info("Moving Resource %s from %s to %s",
				 rsc_id, node_id, new_node_id);
		}
		);
	
	
	return TRUE;
}

gboolean
choose_node_from_list(color_t *color)
{
	/*
	  1. Sort by weight
	  2. color.chosen_node = highest wieghted node 
	  3. remove color.chosen_node from all other colors
	*/
	GListPtr nodes = color->details->candidate_nodes;
	nodes = g_list_sort(nodes, sort_node_weight);
	color->details->chosen_node =
		node_copy((node_t*)g_list_nth_data(nodes, 0));
	color->details->pending = FALSE;

	if(color->details->chosen_node == NULL) {
		crm_err("Could not allocate a node for color %d",
			color->id);
		return FALSE;
	}
	
	return TRUE;
}

/* $Id: stages.c,v 1.19 2004/09/14 05:54:43 andrew Exp $ */
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
#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>
#include <libxml/tree.h>

#include <pengine.h>
#include <pe_utils.h>

node_t *choose_fencer(action_t *stonith, node_t *node, GListPtr resources);

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
/*	int lpc; */
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
	/*get_object_root(XML_CIB_TAG_RA_DEFAULTS, cib); */

	/* reset remaining global variables */
	max_valid_nodes = 0;
	order_id = 1;
	action_id = 1;

	unpack_config(config);
	
	unpack_global_defaults(agent_defaults);
	
	unpack_nodes(cib_nodes, nodes);

	unpack_resources(cib_resources,
			 resources, actions, action_constraints, *nodes);

	unpack_status(cib_status,
		      *nodes, *resources, actions, node_constraints);

	unpack_constraints(cib_constraints,
			   *nodes, *resources,
			   node_constraints, action_constraints);

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
	
	/* Take (next) highest resource */
	slist_iter(
		lh_resource, resource_t, sorted_rscs, lpc,
		/* if resource.provisional == FALSE, repeat  */
		if(lh_resource->provisional == FALSE) {
			/* already processed this resource */
			continue;
		}
		color_resource(lh_resource, colors, sorted_rscs);
		/* next resource */
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
	/* not sure if this is a good idea or not */
	if(g_list_length(colors) > max_valid_nodes) {
		/* we need to consolidate some */
	} else if(g_list_length(colors) < max_valid_nodes) {
		/* we can create a few more */
	}
	return TRUE;
}

/*
 * Choose a node for each (if possible) color
 */
gboolean
stage4(GListPtr colors)
{
	int lpc = 0, lpc2 = 0;

	slist_iter(
		color, color_t, colors, lpc,

		crm_debug("assigning node to color %d", color->id);
		
		if(color == NULL) {
			crm_err("NULL color detected");
			continue;
			
		} else if(color->details->pending == FALSE) {
			continue;
		}
		
		choose_node_from_list(color);

		crm_debug("assigned %s to color %d",
			  safe_val5(NULL, color, details, chosen_node, details, uname),
			  color->id);

		slist_iter(
			rsc, resource_t, color->details->allocated_resources, lpc2,

			process_colored_constraints(rsc);
			
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
	int lpc = 0;
	int lpc2 = 0;
	node_t *start_node = NULL;
	node_t *stop_node = NULL;
	node_t *default_node = NULL;

	crm_verbose("filling in the nodes to perform the actions on");
	slist_iter(
		rsc, resource_t, resources, lpc,

		crm_debug_action(print_resource("Processing", rsc, FALSE));
		
		default_node = NULL;
		start_node = safe_val4(
			NULL, rsc, color, details, chosen_node);
		stop_node = safe_val(NULL, rsc, cur_node);
		if(stop_node == NULL && start_node == NULL) {
			/* it is not and will not run */
			default_node = NULL;

		} else if(stop_node == NULL) {
			/* it is not running yet, all actions must take place
			 * on the new node and if they fail, they fail
			 */
			default_node = start_node;
			rsc->start->optional = FALSE;
			crm_info("Starting resource %s (%s)",
				  safe_val(NULL, rsc, id),
				  safe_val3(NULL,start_node,details,uname));


		} else if(start_node == NULL) {
			/* it is being stopped, all actions must take place
			 * on the existing node and if they fail, they fail
			 */
			default_node = stop_node;
			rsc->stop->optional  = FALSE;
			crm_warn("Stop resource %s (%s)",
				  safe_val(NULL, rsc, id),
				  safe_val3(NULL, stop_node, details,uname));

		} else if(safe_str_eq(
			   safe_val3(NULL, stop_node, details, uname),
			   safe_val3(NULL, start_node, details, uname))) {

			/* its not moving so choose either copy */
			default_node = start_node;
			crm_verbose("No change (possible restart)"
				    " for Resource %s (%s)",
				    safe_val(NULL, rsc, id),
				    safe_val3(
					    NULL,default_node,details,uname));

			
		} else {
			/* the resource is moving...
			 *
			 * the action was scheduled based on its current
			 * location and or state, actions other than start
			 * and stop *must* be run at the existing location
			 * (ie. stop_node)
			 *
			 */

			default_node = stop_node;
			rsc->stop->optional  = FALSE;
			rsc->start->optional = FALSE;
			
			crm_debug("Move resource %s (%s -> %s)",
				  safe_val(NULL, rsc, id),
				  safe_val3(NULL, stop_node,details,uname),
				  safe_val3(NULL, start_node,details,uname));
		}
		
		
		slist_iter(
			action, action_t, rsc->actions, lpc2,

			switch(action->task) {
				case start_rsc:
					action->node = start_node;
					break;
				case stop_rsc:
					action->node = stop_node;
					break;
				default:
					action->node = default_node;
					break;
			}

			if(action->node == NULL) {
				action->runnable = FALSE;
			}
			
			);
		);
	
	return TRUE;
}

/*
 * Create dependacies for stonith and shutdown operations
 */
gboolean
stage6(GListPtr *actions, GListPtr *action_constraints,
       GListPtr nodes, GListPtr resources)
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
			stonith_node->runnable = TRUE;
			stonith_node->optional = FALSE;
			choose_fencer(
				stonith_node, node, resources);

			set_xml_property_copy(stonith_node->args,
					      "target", node->details->uname);
			
			if(stonith_node->node == NULL) {
				/*stonith_node->runnable = FALSE; */
			}
			
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

// compress(action1, action2)

	
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
/*	} */

	update_action_states(actions);

	return TRUE;
}

/*
 * Create a dependancy graph to send to the transitioner (via the CRMd)
 */
gboolean
stage8(GListPtr actions, xmlNodePtr *graph)
{
	int lpc = 0;
	int lpc2 = 0;

	xmlNodePtr syn = NULL;
	xmlNodePtr set = NULL;
	xmlNodePtr in  = NULL;
	xmlNodePtr input = NULL;
	xmlNodePtr xml_action = NULL;
	
	*graph = create_xml_node(NULL, "transition_graph");
	
/* errors...
	slist_iter(action, action_t, action_list, lpc,
		   if(action->optional == FALSE && action->runnable == FALSE) {
			   print_action("Ignoring", action, TRUE);
		   }
		);
*/
	slist_iter(
		action, action_t, actions, lpc,

		if(action->optional) {
			continue;
		} else if(action->runnable == FALSE) {
			continue;
		}
		
		syn    = create_xml_node(*graph, "synapse");
		set    = create_xml_node(syn, "action_set");
		in     = create_xml_node(syn, "inputs");
		
		xml_action = action2xml(action);
		xmlAddChild(set, xml_action);

		slist_iter(
			wrapper,action_wrapper_t,action->actions_before,lpc2,

			switch(wrapper->strength) {
				case pecs_must_not:
				case pecs_ignore:
					/* ignore both */
					break;
				case pecs_startstop:
					if(wrapper->action->runnable == FALSE){
						break;
					}
					/* keep going */
				case pecs_must:
					input = create_xml_node(in, "trigger");
					
					xml_action=action2xml(wrapper->action);
					xmlAddChild(input, xml_action);
					break;
			}
			
			);

		);

	crm_xml_devel(*graph, "created action list");
	
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

node_t *
choose_fencer(action_t *stonith, node_t *a_node, GListPtr resources)
{
	return NULL;
}

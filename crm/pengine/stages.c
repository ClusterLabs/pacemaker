/* $Id: stages.c,v 1.29 2005/01/06 11:02:24 andrew Exp $ */
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
void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);

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
       GListPtr *nodes, GListPtr *placement_constraints,
       GListPtr *actions, GListPtr *ordering_constraints,
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
	num_synapse = 0;
	max_valid_nodes = 0;
	order_id = 1;
	action_id = 1;

	unpack_config(config);
	
	unpack_global_defaults(agent_defaults);
	
	unpack_nodes(cib_nodes, nodes);

	unpack_resources(cib_resources, resources, actions,
			 ordering_constraints, *nodes);

	unpack_status(cib_status, *nodes, *resources, actions,
		      placement_constraints);

	unpack_constraints(cib_constraints, *nodes, *resources,
			   placement_constraints, ordering_constraints);

	return TRUE;
}

/*
 * Count how many valid nodes we have (so we know the maximum number of
 *  colors we can resolve).
 *
 * Apply node constraints (ie. filter the "allowed_nodes" part of resources
 */
gboolean
stage1(GListPtr placement_constraints, GListPtr nodes, GListPtr resources)
{
	crm_info("Processing stage 1");
	
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

	apply_placement_constraints(placement_constraints, nodes);

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
	crm_info("Processing stage 2");
	
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
	crm_info("Processing stage 3");
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
	crm_info("Processing stage 4");

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
			slist_iter(
				constraint, rsc_dependancy_t, rsc->rsc_cons, lpc,
				rsc->fns->rsc_dependancy_lh(constraint);
				);	
			
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
stage5(GListPtr resources, GListPtr *ordering_constraints)
{
	slist_iter(
		rsc, resource_t, resources, lpc,
		rsc->fns->create_actions(rsc);
		rsc->fns->internal_constraints(rsc, ordering_constraints);
		);
	return TRUE;
}

/*
 * Create dependacies for stonith and shutdown operations
 */
gboolean
stage6(GListPtr *actions, GListPtr *ordering_constraints,
       GListPtr nodes, GListPtr resources)
{

	action_t *down_op = NULL;
	action_t *stonith_op = NULL;
	crm_info("Processing stage 6");

	slist_iter(
		node, node_t, nodes, lpc,
		if(node->details->shutdown) {
			crm_warn("Scheduling Node %s for shutdown",
				 node->details->uname);
			
			down_op = action_new(NULL, shutdown_crm, node);
			down_op->runnable = TRUE;
			
			*actions = g_list_append(*actions, down_op);
			
			shutdown_constraints(
				node, down_op, ordering_constraints);
		}

		if(node->details->unclean && stonith_enabled) {
			crm_warn("Scheduling Node %s for STONITH",
				 node->details->uname);

			stonith_op = action_new(NULL, stonith_node, NULL);
			stonith_op->runnable = TRUE;
			
			set_xml_property_copy(stonith_op->args,
					      "target", node->details->uname);
			
			if(down_op != NULL) {
				down_op->failure_is_fatal = FALSE;
			}
			
			*actions = g_list_append(*actions, stonith_op);
			
			stonith_constraints(node, stonith_op, down_op,
					    ordering_constraints);
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
stage7(GListPtr resources, GListPtr actions, GListPtr ordering_constraints)
{
	crm_info("Processing stage 7");

	slist_iter(
		order, order_constraint_t, ordering_constraints, lpc,

		/* try rsc_action-to-rsc_action */
		resource_t *rsc = order->lh_rsc;
		if(rsc == NULL && order->lh_action) {
			rsc = order->lh_action->rsc;
		}
		
		if(rsc != NULL) {
			rsc->fns->rsc_order_lh(rsc, order);
			continue;
			
		}

		/* try action-to-rsc_action */
		
		/* que off the rh resource */
		rsc = order->rh_rsc;
		if(rsc == NULL && order->rh_action) {
			rsc = order->rh_action->rsc;
		}
		
		if(rsc != NULL) {
			rsc->fns->rsc_order_rh(order->lh_action, rsc, order);
		} else {
			/* fall back to action-to-action */
			order_actions(
				order->lh_action, order->rh_action, order);
		}
		
		);

	update_action_states(actions);

	return TRUE;
}

/*
 * Create a dependancy graph to send to the transitioner (via the CRMd)
 */
gboolean
stage8(GListPtr resources, GListPtr actions, xmlNodePtr *graph)
{
	crm_info("Processing stage 8");
	*graph = create_xml_node(NULL, "transition_graph");
	set_xml_property_copy(
		*graph, "global_timeout", transition_timeout);
	
/* errors...
	slist_iter(action, action_t, action_list, lpc,
		   if(action->optional == FALSE && action->runnable == FALSE) {
			   print_action("Ignoring", action, TRUE);
		   }
		);
*/
	slist_iter(
		rsc, resource_t, resources, lpc,

		crm_debug("processing actions for rsc=%s", rsc->id);
		rsc->fns->expand(rsc, graph);
		);
	crm_xml_devel(*graph, "created resource-driven action list");

	/* catch any non-resource specific actions */
	crm_debug("processing non-resource actions");
	slist_iter(
		action, action_t, actions, lpc,

		graph_element_from_action(action, graph);
		);

	crm_xml_devel(*graph, "created generic action list");
	
	return TRUE;
}

/*
 * Print a nice human readable high-level summary of what we're going to do 
 */
gboolean
summary(GListPtr resources)
{
#if 0
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
	
#endif	
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


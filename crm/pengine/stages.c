/* $Id: stages.c,v 1.46 2005/03/31 16:40:07 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>

node_t *choose_fencer(action_t *stonith, node_t *node, GListPtr resources);
void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);

int order_id        = 1;
int max_valid_nodes = 0;

GListPtr agent_defaults = NULL;

gboolean have_quorum      = FALSE;
gboolean require_quorum   = FALSE;
gboolean stonith_enabled  = FALSE;
gboolean symetric_cluster = TRUE;

char *dc_uuid = NULL;
const char* transition_timeout = "60000"; /* 1 minute */

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
stage0(crm_data_t * cib,
       GListPtr *resources,
       GListPtr *nodes, GListPtr *placement_constraints,
       GListPtr *actions, GListPtr *ordering_constraints,
       GListPtr *stonith_list, GListPtr *shutdown_list)
{
/*	int lpc; */
	crm_data_t * cib_nodes       = get_object_root(
		XML_CIB_TAG_NODES,       cib);
	crm_data_t * cib_status      = get_object_root(
		XML_CIB_TAG_STATUS,      cib);
	crm_data_t * cib_resources   = get_object_root(
		XML_CIB_TAG_RESOURCES,   cib);
	crm_data_t * cib_constraints = get_object_root(
		XML_CIB_TAG_CONSTRAINTS, cib);
	crm_data_t * config          = get_object_root(
		XML_CIB_TAG_CRMCONFIG,   cib);
	crm_data_t * agent_defaults  = NULL;
	/*get_object_root(XML_CIB_TAG_RA_DEFAULTS, cib); */

	crm_free(dc_uuid);
	dc_uuid = NULL;
	if(cib != NULL && crm_element_value(cib, XML_ATTR_DC_UUID) != NULL) {
		/* this should always be present */
		dc_uuid = crm_element_value_copy(cib, XML_ATTR_DC_UUID);
	}	
	
	/* reset remaining global variables */
	num_synapse = 0;
	max_valid_nodes = 0;
	order_id = 1;
	action_id = 1;
	color_id = 0;

	have_quorum      = FALSE;
	require_quorum   = FALSE;
	stonith_enabled  = FALSE;
	
	unpack_config(config);

	if(require_quorum) {
		const char *value = crm_element_value(cib, XML_ATTR_HAVE_QUORUM);
		if(value != NULL) {
			crm_str_to_boolean(value, &have_quorum);
		}
		if(have_quorum == FALSE) {
			crm_warn("We do not have quorum"
				 " - fencing and resource management disabled");
		}
	}
	
	unpack_global_defaults(agent_defaults);
	
	unpack_nodes(cib_nodes, nodes);

	unpack_resources(cib_resources, resources, actions,
			 ordering_constraints, placement_constraints, *nodes);

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
	crm_devel("Processing stage 1");
	
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
	crm_devel("Processing stage 2");
	
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
	crm_devel("Processing stage 3");
	/* not sure if this is a good idea or not */
	if((ssize_t)g_list_length(colors) > max_valid_nodes) {
		/* we need to consolidate some */
	} else if((ssize_t)g_list_length(colors) < max_valid_nodes) {
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
	crm_devel("Processing stage 4");

	slist_iter(
		color, color_t, colors, lpc,

		crm_devel("assigning node to color %d", color->id);
		
		if(color == NULL) {
			crm_err("NULL color detected");
			continue;
			
		} else if(color->details->pending == FALSE) {
			continue;
		}
		
		choose_node_from_list(color);

		crm_devel("assigned %s to color %d",
			  safe_val5(NULL, color, details, chosen_node, details, uname),
			  color->id);

		slist_iter(
			rsc, resource_t, color->details->allocated_resources, lpc2,
			slist_iter(
				constraint, rsc_colocation_t, rsc->rsc_cons, lpc,
				rsc->fns->rsc_colocation_lh(constraint);
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
		rsc->fns->create_actions(rsc, ordering_constraints);
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
	crm_devel("Processing stage 6");

	slist_iter(
		node, node_t, nodes, lpc,
		if(node->details->shutdown) {
			crm_info("Scheduling Node %s for shutdown",
				 node->details->uname);
			
			down_op = action_new(NULL, shutdown_crm, NULL, node);
			down_op->runnable = TRUE;
			
			*actions = g_list_append(*actions, down_op);
			
			shutdown_constraints(
				node, down_op, ordering_constraints);
		}

		if(node->details->unclean && stonith_enabled) {
			crm_warn("Scheduling Node %s for STONITH",
				 node->details->uname);

			stonith_op = action_new(NULL, stonith_node,NULL,NULL);
			stonith_op->runnable = TRUE;

			add_hash_param(
				stonith_op->extra, XML_LRM_ATTR_TARGET,
				node->details->uname);

			add_hash_param(
				stonith_op->extra, XML_LRM_ATTR_TARGET_UUID,
				node->details->id);
			
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
	crm_devel("Processing stage 7");

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
stage8(GListPtr resources, GListPtr actions, crm_data_t * *graph)
{
	crm_devel("Processing stage 8");
	*graph = create_xml_node(NULL, XML_TAG_GRAPH);
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

		crm_devel("processing actions for rsc=%s", rsc->id);
		rsc->fns->expand(rsc, graph);
		);
	crm_xml_devel(*graph, "created resource-driven action list");

	/* catch any non-resource specific actions */
	crm_devel("processing non-resource actions");
	slist_iter(
		action, action_t, actions, lpc,

		graph_element_from_action(action, graph);
		);

	crm_xml_devel(*graph, "created generic action list");
	
	return TRUE;
}


gboolean
choose_node_from_list(color_t *color)
{
	/*
	  1. Sort by weight
	  2. color.chosen_node = the node (of those with the highest wieght)
				   with the fewest resources
	  3. remove color.chosen_node from all other colors
	*/
	GListPtr nodes = color->details->candidate_nodes;
	node_t *chosen = NULL;

	crm_devel("Choosing node for color %d", color->id);
	nodes  = g_list_sort(nodes, sort_node_weight);

	chosen = g_list_nth_data(nodes, 0);

	color->details->chosen_node = NULL;
	color->details->pending = FALSE;

	if(chosen == NULL) {
		crm_debug("Could not allocate a node for color %d", color->id);
		return FALSE;
	}

	/* todo: update the old node for each resource to reflect its
	 * new resource count
	 */
	
	chosen->details->num_resources += color->details->num_resources;
	color->details->chosen_node = node_copy(chosen);
	return TRUE;
}


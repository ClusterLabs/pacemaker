/* $Id: stages.c,v 1.100 2006/05/30 08:54:32 andrew Exp $ */
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

#include <portability.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <clplumbing/cl_misc.h>

#include <glib.h>

#include <pengine.h>
#include <pe_utils.h>

node_t *choose_fencer(action_t *stonith, node_t *node, GListPtr resources);

/*
 * Unpack everything
 * At the end you'll have:
 *  - A list of nodes
 *  - A list of resources (each with any dependencies on other resources)
 *  - A list of constraints between resources and nodes
 *  - A list of constraints between start/stop actions
 *  - A list of nodes that need to be stonith'd
 *  - A list of nodes that need to be shutdown
 *  - A list of the possible stop/start actions (without dependencies)
 */
gboolean
stage0(pe_working_set_t *data_set)
{
/*	int lpc; */
	crm_data_t * config          = get_object_root(
		XML_CIB_TAG_CRMCONFIG,   data_set->input);
	crm_data_t * cib_nodes       = get_object_root(
		XML_CIB_TAG_NODES,       data_set->input);
	crm_data_t * cib_resources   = get_object_root(
		XML_CIB_TAG_RESOURCES,   data_set->input);
	crm_data_t * cib_status      = get_object_root(
		XML_CIB_TAG_STATUS,      data_set->input);
	crm_data_t * cib_constraints = get_object_root(
		XML_CIB_TAG_CONSTRAINTS, data_set->input);
 	const char *value = crm_element_value(
		data_set->input, XML_ATTR_HAVE_QUORUM);
	
	crm_debug_3("Beginning unpack");
	
	/* reset remaining global variables */
	
	if(data_set->input == NULL) {
		return FALSE;
	}

	if(data_set->input != NULL
	   && crm_element_value(data_set->input, XML_ATTR_DC_UUID) != NULL) {
		/* this should always be present */
		data_set->dc_uuid = crm_element_value_copy(
			data_set->input, XML_ATTR_DC_UUID);
	}	
	
	data_set->no_color = create_color(data_set, NULL, NULL);

	unpack_config(config, data_set);

	if(value != NULL) {
		cl_str_to_boolean(value, &data_set->have_quorum);
	}
	
	if(data_set->have_quorum == FALSE
	   && data_set->no_quorum_policy != no_quorum_ignore) {
		crm_warn("We do not have quorum"
			 " - fencing and resource management disabled");
	}
	
	unpack_nodes(cib_nodes, data_set);
	unpack_resources(cib_resources, data_set);
	unpack_status(cib_status, data_set);
	unpack_constraints(cib_constraints, data_set);

	return TRUE;
}

/*
 * Count how many valid nodes we have (so we know the maximum number of
 *  colors we can resolve).
 *
 * Apply node constraints (ie. filter the "allowed_nodes" part of resources
 */
gboolean
stage1(pe_working_set_t *data_set)
{
	crm_debug_3("Applying placement constraints");
	
	slist_iter(
		node, node_t, data_set->nodes, lpc,
		if(node == NULL) {
			/* error */
		} else if(node->weight >= 0.0 /* global weight */
			  && node->details->online
			  && node->details->type == node_member) {
			data_set->max_valid_nodes++;
		}
		);

	apply_placement_constraints(data_set);

	return TRUE;
} 



/*
 * Choose a color for all resources from highest priority and XML_STRENGTH_VAL_MUST
 *  dependencies to lowest, creating new colors as necessary (returned
 *  as "colors").
 *
 * Some nodes may be colored as a "no_color" meaning that it was unresolvable
 *  given the current node stati and constraints.
 */
gboolean
stage2(pe_working_set_t *data_set)
{
	crm_debug_3("Coloring resources");
	
	crm_debug_5("create \"no color\"");
	
	/* Take (next) highest resource */
	slist_iter(
		lh_resource, resource_t, data_set->resources, lpc,
		lh_resource->fns->color(lh_resource, data_set);
		);
	
	return TRUE;
}

/*
 * Check nodes for resources started outside of the LRM
 */
gboolean
stage3(pe_working_set_t *data_set)
{
	action_t *probe_complete = NULL;
	action_t *probe_node_complete = NULL;

	slist_iter(
		node, node_t, data_set->nodes, lpc,
		gboolean force_probe = FALSE;
		const char *probed = g_hash_table_lookup(
			node->details->attrs, CRM_OP_PROBED);

		crm_debug_2("%s probed: %s", node->details->uname, probed);
		if(node->details->online == FALSE) {
			continue;
			
		} else if(node->details->unclean) {
			continue;

		} else if(probe_complete == NULL) {
			probe_complete = custom_action(
				NULL, crm_strdup(CRM_OP_PROBED),
				CRM_OP_PROBED, NULL, FALSE, TRUE,
				data_set);

			probe_complete->pseudo = TRUE;
			probe_complete->optional = TRUE;
		}

		if(probed != NULL && crm_is_true(probed) == FALSE) {
			force_probe = TRUE;
		}
		
		probe_node_complete = custom_action(
			NULL, crm_strdup(CRM_OP_PROBED),
			CRM_OP_PROBED, node, FALSE, TRUE, data_set);
		probe_node_complete->optional = crm_is_true(probed);
		probe_node_complete->priority = INFINITY;
		add_hash_param(probe_node_complete->meta,
			       XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
		
		custom_action_order(NULL, NULL, probe_node_complete,
				    NULL, NULL, probe_complete,
				    pe_ordering_optional, data_set);
		
		slist_iter(
			rsc, resource_t, data_set->resources, lpc2,
			
			if(rsc->fns->create_probe(
				   rsc, node, probe_node_complete,
				   force_probe, data_set)) {

				probe_complete->optional = FALSE;
				probe_node_complete->optional = FALSE;
				custom_action_order(
					NULL, NULL, probe_complete,
					rsc, start_key(rsc), NULL,
					pe_ordering_manditory, data_set);
			}
			);
		);

	return TRUE;
}

/*
 * Choose a node for each (if possible) color
 */
gboolean
stage4(pe_working_set_t *data_set)
{
	node_t *chosen = NULL;
	crm_debug_3("Assigning nodes to colors");

	slist_iter(
		color, color_t, data_set->colors, lpc,

		crm_debug_4("assigning node to color %d", color->id);
		
		if(color == NULL) {
			pe_err("NULL color detected");
			continue;
			
		} else if(color->details->pending == FALSE) {
			continue;
		}
		
		choose_node_from_list(color);
		chosen = color->details->chosen_node;
		
		slist_iter(
			rsc, resource_t, color->details->allocated_resources, lpc2,
			crm_debug_2("Processing colocation constraints for %s"
				    " now that color %d is allocated",
				    rsc->id, color->details->id); 

			if(chosen == NULL) {
				rsc->next_role = RSC_ROLE_STOPPED;

			} else if(rsc->next_role == RSC_ROLE_UNKNOWN) {
				rsc->next_role = RSC_ROLE_STARTED;
			}

			slist_iter(
				constraint, rsc_colocation_t, rsc->rsc_cons, lpc,
				rsc->fns->rsc_colocation_lh(
					rsc, constraint->rsc_rh, constraint);
				);	
			
			);
		);

	crm_debug_3("done");
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
stage5(pe_working_set_t *data_set)
{
	crm_debug_3("Creating actions and internal ording constraints");
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->fns->create_actions(rsc, data_set);
		rsc->fns->internal_constraints(rsc, data_set);
		);
	return TRUE;
}

/*
 * Create dependacies for stonith and shutdown operations
 */
gboolean
stage6(pe_working_set_t *data_set)
{
	action_t *down_op = NULL;
	action_t *stonith_op = NULL;
	action_t *dc_down = NULL;
	
	crm_debug_3("Processing fencing and shutdown cases");
	
	slist_iter(
		node, node_t, data_set->nodes, lpc,
		if(node->details->online && node->details->shutdown) {
			crm_info("Scheduling Node %s for shutdown",
				 node->details->uname);
			
			down_op = custom_action(
				NULL, crm_strdup(CRM_OP_SHUTDOWN),
				CRM_OP_SHUTDOWN, node, FALSE, TRUE, data_set);
			down_op->runnable = TRUE;
			
			shutdown_constraints(
				node, down_op, data_set);

			if(node->details->is_dc) {
				dc_down = down_op;
			}
		}

		if(node->details->unclean
		   && data_set->stonith_enabled == FALSE) {
			pe_err("Node %s is unclean!", node->details->uname);
			pe_warn("YOUR RESOURCES ARE NOW LIKELY COMPROMISED");
			pe_warn("ENABLE STONITH TO KEEP YOUR RESOURCES SAFE");

		} else if(node->details->unclean && data_set->stonith_enabled
		   && (data_set->have_quorum
		       || data_set->no_quorum_policy == no_quorum_ignore)) {
			pe_warn("Scheduling Node %s for STONITH",
				 node->details->uname);

			stonith_op = custom_action(
				NULL, crm_strdup(CRM_OP_FENCE),
				CRM_OP_FENCE, node, FALSE, TRUE, data_set);
			stonith_op->runnable = TRUE;

			add_hash_param(
				stonith_op->meta, XML_LRM_ATTR_TARGET,
				node->details->uname);

			add_hash_param(
				stonith_op->meta, XML_LRM_ATTR_TARGET_UUID,
				node->details->id);

			add_hash_param(
				stonith_op->meta, "stonith_action",
				data_set->stonith_action);
			
			if(down_op != NULL) {
				down_op->failure_is_fatal = FALSE;
			}

			if(node->details->is_dc) {
				dc_down = stonith_op;
			}
		}

		if(node->details->unclean) {
			stonith_constraints(
				node, stonith_op, down_op, data_set);
		}
		
		);

	if(dc_down != NULL) {
		GListPtr shutdown_matches = find_actions(
			data_set->actions, CRM_OP_SHUTDOWN, NULL);

		crm_debug_2("Ordering shutdowns before %s on %s (DC)",
			down_op->task, down_op->node->details->uname);

		add_hash_param(dc_down->meta, XML_ATTR_TE_NOWAIT,
			       XML_BOOLEAN_TRUE);
		
		slist_iter(
			action, action_t, shutdown_matches, lpc,
			if(action->node->details->is_dc) {
				continue;
			}
			crm_debug("Ordering shutdown on %s before %s on %s",
				action->node->details->uname,
				dc_down->task, dc_down->node->details->uname);

			custom_action_order(
				NULL, crm_strdup(action->task), action,
				NULL, crm_strdup(dc_down->task), dc_down,
				pe_ordering_manditory, data_set);
			);
	}

	return TRUE;
}

/*
 * Determin the sets of independant actions and the correct order for the
 *  actions in each set.
 *
 * Mark dependencies of un-runnable actions un-runnable
 *
 */
gboolean
stage7(pe_working_set_t *data_set)
{
	crm_debug_3("Applying ordering constraints");

	slist_iter(
		order, order_constraint_t, data_set->ordering_constraints, lpc,

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
				order->lh_action, order->rh_action, order->type);
		}
		
		);

	update_action_states(data_set->actions);

	return TRUE;
}

int transition_id = -1;
/*
 * Create a dependency graph to send to the transitioner (via the CRMd)
 */
gboolean
stage8(pe_working_set_t *data_set)
{
	char *transition_id_s = NULL;

	transition_id++;
	transition_id_s = crm_itoa(transition_id);
	crm_debug("Creating transition graph %d.", transition_id);
	
	data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);
	crm_xml_add(data_set->graph, "global_timeout", data_set->transition_idle_timeout);
	crm_xml_add(data_set->graph, "transition_id", transition_id_s);
	crm_free(transition_id_s);
	
/* errors...
	slist_iter(action, action_t, action_list, lpc,
		   if(action->optional == FALSE && action->runnable == FALSE) {
			   print_action("Ignoring", action, TRUE);
		   }
		);
*/
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,

		crm_debug_4("processing actions for rsc=%s", rsc->id);
		rsc->fns->expand(rsc, data_set);
		);
	crm_log_xml_debug_3(
		data_set->graph, "created resource-driven action list");

	/* catch any non-resource specific actions */
	crm_debug_4("processing non-resource actions");
	slist_iter(
		action, action_t, data_set->actions, lpc,

		graph_element_from_action(action, data_set);
		);

	crm_log_xml_debug_3(data_set->graph, "created generic action list");
	crm_notice("Created transition graph %d.", transition_id);
	
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
	int multiple = 0;

	crm_debug_2("Choosing node for color %d", color->id);
	color->details->candidate_nodes = g_list_sort(nodes, sort_node_weight);
	nodes = color->details->candidate_nodes;

	chosen = g_list_nth_data(nodes, 0);

	color->details->chosen_node = NULL;
	color->details->pending = FALSE;

	if(chosen == NULL) {
		crm_debug("Could not allocate a node for color %d", color->id);
		return FALSE;

	} else if(chosen->details->unclean || chosen->details->shutdown) {
		crm_debug("All nodes for color %d are unavailable"
			  ", unclean or shutting down", color->id);
		color->details->chosen_node = NULL;
		return FALSE;
		
	} else if(chosen->weight < 0) {
		crm_debug_2("Even highest ranked node for color %d, had weight %d",
			  color->id, chosen->weight);
		color->details->chosen_node = NULL;
		return FALSE;
	}

	slist_iter(candidate, node_t, nodes, lpc, 
		   crm_debug("Color %d, Node %s: %d", color->id,
			     candidate->details->uname, candidate->weight);
		   if(chosen->weight > 0
		      && candidate->details->unclean == FALSE
		      && candidate->weight == chosen->weight) {
			   multiple++;
		   } else {
			   break;
		   }
		);

	if(multiple > 1) {
		int log_level = LOG_INFO;
		char *score = score2char(chosen->weight);
		if(chosen->weight >= INFINITY) {
			log_level = LOG_WARNING;
		}
		
		crm_log_maybe(log_level, "%d nodes with equal score (%s) for"
			      " running the listed resources (chose %s):",
			      multiple, score, chosen->details->uname);
		slist_iter(rsc, resource_t,
			   color->details->allocated_resources, lpc,
			   rsc->fns->print(
				   rsc, "\t", pe_print_log|pe_print_rsconly,
				   &log_level);
			);
		crm_free(score);
	}
	
	/* todo: update the old node for each resource to reflect its
	 * new resource count
	 */

	crm_debug_2("assigned %s to color %d",chosen->details->uname,color->id);
	chosen->details->num_resources += color->details->num_resources;
	color->details->chosen_node = node_copy(chosen);
	
	return TRUE;
}


/* $Id: complex.c,v 1.1 2004/11/09 09:32:14 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>
gboolean update_node_weight(rsc_to_node_t *cons,const char *id,GListPtr nodes);
gboolean is_active(rsc_to_node_t *cons);
gboolean constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_dependancy_t *constraint);
void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);


resource_object_functions_t resource_class_functions[] = {
	{
		native_unpack,
		native_color,
		native_create_actions,
		native_internal_ordering,
		native_rsc_dependancy_lh,
		native_rsc_dependancy_rh,
		native_rsc_order_lh,
		native_rsc_order_rh,
		native_rsc_location,
		native_expand,
		native_dump,
		native_free
	}
/* 	{ */
/* 		group_expand, */
/* 		group_n_colors, */
/* 		group_assign, */
/* 		group_expand, */
/* 		group_internal_constraints, */
/* 		group_rsc_dependancy, */
/* 		group_rsc_order, */
/* 		group_rsc_location, */
/* 		group_dump */
/* 	}, */
/* 	{ */
/* 		incarnation_expand, */
/* 		incarnation_n_colors, */
/* 		incarnation_assign, */
/* 		incarnation_expand, */
/* 		incarnation_internal_constraints, */
/* 		incarnation_rsc_dependancy, */
/* 		incarnation_rsc_order, */
/* 		incarnation_rsc_location, */
/* 		incarnation_dump */
/* 	}, */

};

/* resource_object_functions_t resource_variants[] = resource_class_functions; */


int get_resource_type(const char *name)
{
	if(safe_str_eq(name, "resource")) {
		return pe_native;
	}
	return pe_unknown;
}

gboolean
is_active(rsc_to_node_t *cons)
{
	/* todo: check constraint lifetime */
	return TRUE;
}


gboolean
update_node_weight(rsc_to_node_t *cons, const char *id, GListPtr nodes)
{
	node_t *node_rh = pe_find_node(cons->rsc_lh->allowed_nodes, id);

	if(node_rh == NULL) {
		crm_err("Node not found - cant update");
		return FALSE;
	}

	if(node_rh->fixed) {
		/* warning */
		crm_warn("Constraint %s is irrelevant as the"
			 " weight of node %s is fixed as %f.",
			 cons->id,
			 node_rh->details->uname,
			 node_rh->weight);
		return TRUE;
	}
	
	crm_verbose("Constraint %s (%s): node %s weight %f.",
		    cons->id,
		    cons->can?"can":"cannot",
		    node_rh->details->uname,
		    node_rh->weight);

	if(cons->can == FALSE) {
		node_rh->weight = -1;
	} else {
		node_rh->weight += cons->weight;
	}

	if(node_rh->weight < 0) {
		node_rh->fixed = TRUE;
	}

	crm_debug_action(print_node("Updated", node_rh, FALSE));

	return TRUE;
}

gboolean
constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_dependancy_t *constraint)
{
	GListPtr result = NULL;
	color_t *color_lh = rsc_lh->color;
	color_t *color_rh = rsc_rh->color;

	GListPtr candidate_nodes_lh = NULL;
	GListPtr candidate_nodes_rh = NULL;

	gboolean matched = FALSE;
	if(constraint->strength == pecs_must_not) {
		matched = TRUE;
	}
			
	if(rsc_lh->provisional || rsc_rh->provisional) {
		return FALSE;
	}
	
	if(color_lh->details->pending
	   && color_rh->details->pending) {
		candidate_nodes_lh = color_lh->details->candidate_nodes;
		candidate_nodes_rh = color_rh->details->candidate_nodes;
		
	} else if(color_lh->details->pending == FALSE
		  && color_rh->details->pending == FALSE) {

		if(color_lh == NULL && color_rh == NULL) {
			return matched;
			
		} else if(color_lh == NULL || color_rh == NULL) {
			return !matched;

		} else if(color_lh->details->chosen_node == NULL
			  && color_rh->details->chosen_node == NULL) {
			return matched;

		} else if(color_lh->details->chosen_node == NULL
			  || color_rh->details->chosen_node == NULL) {
			return !matched;

		} else if(safe_str_eq(
				  color_lh->details->chosen_node->details->id,
				  color_rh->details->chosen_node->details->id)) {
			return matched;
		}
		return !matched;
		
	} else if(color_lh->details->pending) {
		candidate_nodes_lh = color_lh->details->candidate_nodes;
		candidate_nodes_rh = g_list_append(
			NULL, color_rh->details->chosen_node);

	} else if(color_rh->details->pending) {
		candidate_nodes_rh = color_rh->details->candidate_nodes;
		candidate_nodes_lh = g_list_append(
			NULL, color_lh->details->chosen_node);
	}

	result = node_list_and(candidate_nodes_lh, candidate_nodes_rh, TRUE);

	if(g_list_length(result) == 0 && constraint->strength == pecs_must) {
		/* free result */
		return TRUE;
	}
	return FALSE;
}

void
order_actions(action_t *lh_action, action_t *rh_action, order_constraint_t *order) 
{
	action_wrapper_t *wrapper = NULL;
	GListPtr list = NULL;
	
	crm_verbose("%d Processing %d -> %d",
		    order->id, lh_action->id, rh_action->id);
	
	crm_debug_action(
		print_action("LH (order_actions)", lh_action, FALSE));

	crm_debug_action(
		print_action("RH (order_actions)", rh_action, FALSE));
	
	crm_malloc(wrapper, sizeof(action_wrapper_t));
	if(wrapper != NULL) {
		wrapper->action = rh_action;
		wrapper->strength = order->strength;
		
		list = lh_action->actions_after;
		list = g_list_append(list, wrapper);
		lh_action->actions_after = list;
	}
	
	crm_malloc(wrapper, sizeof(action_wrapper_t));
	if(wrapper != NULL) {
		wrapper->action = lh_action;
		wrapper->strength = order->strength;
		
		list = rh_action->actions_before;
		list = g_list_append(list, wrapper);
		rh_action->actions_before = list;
	}
}

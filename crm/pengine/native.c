/* $Id: native.c,v 1.3 2004/11/09 14:49:14 andrew Exp $ */
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
#include <crm/msg_xml.h>

extern color_t *add_color(resource_t *rh_resource, color_t *color);

gboolean has_agent(node_t *a_node, lrm_agent_t *an_agent);

gboolean native_choose_color(resource_t *lh_resource);

gboolean native_assign_color(resource_t *rsc, color_t *color);

gboolean native_update_node_weight(
	rsc_to_node_t *cons, const char *id, GListPtr nodes);



void native_rsc_dependancy_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh);

void native_rsc_dependancy_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh);

gboolean filter_nodes(resource_t *rsc);


typedef struct native_variant_data_s
{
		lrm_agent_t *agent;
		GListPtr running_on;       /* node_t*           */
		color_t *color;
		GListPtr node_cons;        /* rsc_to_node_t*    */
		GListPtr allowed_nodes;    /* node_t*         */

} native_variant_data_t;

void
native_add_running(resource_t *rsc, node_t *node)
{
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;
	
	native_data->running_on = g_list_append(native_data->running_on, node);

	if(g_list_length(native_data->running_on) > 1) {
		crm_warn("Resource %s is (potentially) active on %d nodes."
			 "  Latest: %s", rsc->id,
			 g_list_length(native_data->running_on),
			 node->details->id);
	}
}


void native_unpack(resource_t *rsc)
{
	xmlNodePtr xml_obj = rsc->xml;
	native_variant_data_t *native_data = NULL;
	const char *version  = xmlGetProp(xml_obj, XML_ATTR_VERSION);
	
	crm_verbose("Processing resource...");

	crm_malloc(native_data, sizeof(native_variant_data_t));

	crm_malloc(native_data->agent, sizeof(lrm_agent_t));
	native_data->agent->class	= xmlGetProp(xml_obj, "class");
	native_data->agent->type	= xmlGetProp(xml_obj, "type");
	native_data->agent->version	= version?version:"0.0";
	
	native_data->color		= NULL; 
	native_data->allowed_nodes	= NULL;
	native_data->node_cons		= NULL; 
	native_data->running_on		= NULL;

	rsc->variant_opaque = native_data;
}

void native_color(resource_t *rsc, GListPtr *colors)
{
	color_t *new_color = NULL;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	if( native_choose_color(rsc) ) {
		crm_verbose("Colored resource %s with color %d",
			    rsc->id, native_data->color->id);
		
	} else {
		if(native_data->allowed_nodes != NULL) {
			/* filter out nodes with a negative weight */
			filter_nodes(rsc);
			new_color = create_color(
				colors, rsc, native_data->allowed_nodes);
			native_assign_color(rsc, new_color);
		}
		
		if(new_color == NULL) {
			crm_err("Could not color resource %s", rsc->id);
			print_resource("ERROR: No color", rsc, FALSE);
			native_assign_color(rsc, no_color);
		}
	}
	rsc->provisional = FALSE;
	
}

void native_create_actions(resource_t *rsc)
{
	int lpc2, lpc3;
	action_t *start_op = NULL;
	gboolean can_start = FALSE;
	node_t *chosen = NULL;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	if(native_data->color != NULL) {
		chosen = native_data->color->details->chosen_node;
	}
	
	if(chosen != NULL) {
		can_start = TRUE;
	}
	
	if(can_start && g_list_length(native_data->running_on) == 0) {
		/* create start action */
		crm_info("Start resource %s (%s)",
			 rsc->id,
			 safe_val3(NULL, chosen, details, uname));
		start_op = action_new(rsc, start_rsc, chosen);
		
	} else if(g_list_length(native_data->running_on) > 1) {
		crm_info("Attempting recovery of resource %s",
			 rsc->id);
		
		if(rsc->recovery_type == recovery_stop_start
		   || rsc->recovery_type == recovery_stop_only) {
			slist_iter(
				node, node_t,
				native_data->running_on, lpc2,
				
				crm_info("Stop resource %s (%s)",
					 rsc->id,
					 safe_val3(NULL, node, details, uname));
				action_new(rsc, stop_rsc, node);
				);
		}
		
		if(rsc->recovery_type == recovery_stop_start && can_start) {
			crm_info("Start resource %s (%s)",
				 rsc->id,
				 safe_val3(NULL, chosen, details, uname));
			start_op = action_new(
				rsc, start_rsc, chosen);
		}
		
	} else {
		/* stop and or possible restart */
		crm_debug("Stop and possible restart of %s", rsc->id);
		
		slist_iter(
			node, node_t, native_data->running_on, lpc2,				
			
			if(chosen != NULL && safe_str_eq(
				   node->details->id,
				   chosen->details->id)) {
				/* restart */
				crm_info("Leave resource %s alone (%s)", rsc->id,
					 safe_val3(NULL, chosen, details, uname));
				
				
				/* in case the actions already exist */
				slist_iter(
					action, action_t, rsc->actions, lpc3,
					
					if(action->task == start_rsc
					   || action->task == stop_rsc){
						action->optional = TRUE;
					}
					);
				
				continue;
			} else if(chosen != NULL) {
				/* move */
				crm_info("Move resource %s (%s -> %s)", rsc->id,
					 safe_val3(NULL, node, details, uname),
					 safe_val3(NULL, chosen, details, uname));
				action_new(rsc, stop_rsc, node);
				action_new(rsc, start_rsc, chosen);

			} else {
				crm_info("Stop resource %s (%s)", rsc->id,
					 safe_val3(NULL, node, details, uname));
				action_new(rsc, stop_rsc, node);
			}
			
			);	
	}
	
}

void native_internal_constraints(resource_t *rsc, GListPtr *ordering_constraints)
{
	order_new(rsc, stop_rsc, NULL, rsc, start_rsc, NULL,
		  pecs_startstop, ordering_constraints);
}

void native_rsc_dependancy_lh(rsc_dependancy_t *constraint)
{
	resource_t *rsc = constraint->rsc_lh;
	
	if(rsc == NULL) {
		crm_err("No constraints for NULL resource");
		return;
	} else {
		crm_debug("Processing constraints from %s", rsc->id);
	}
	
	constraint->rsc_rh->fns->rsc_dependancy_rh(rsc, constraint);		
}

void native_rsc_dependancy_rh(resource_t *rsc, rsc_dependancy_t *constraint)
{
	gboolean do_check = FALSE;
	gboolean update_lh = FALSE;
	gboolean update_rh = FALSE;
	
	resource_t *rsc_lh = rsc;
	resource_t *rsc_rh = constraint->rsc_rh;

	native_variant_data_t *native_data_lh =
		(native_variant_data_t *)rsc_lh->variant_opaque;

	native_variant_data_t *native_data_rh =
		(native_variant_data_t *)rsc_rh->variant_opaque;
	
	crm_verbose("Processing RH of constraint %s", constraint->id);
	crm_debug_action(print_resource("LHS", rsc_lh, TRUE));
	crm_debug_action(print_resource("RHS", rsc_rh, TRUE));
	
	if(constraint->strength == pecs_ignore
		|| constraint->strength == pecs_startstop){
		crm_debug("Skipping constraint type %d", constraint->strength);
		return;
	}
	
	if(rsc_lh->provisional && rsc_rh->provisional) {
		/* nothing */
		crm_debug("Skipping constraint, both sides provisional");
		return;

	} else if( (!rsc_lh->provisional) && (!rsc_rh->provisional)
		   && (!native_data_lh->color->details->pending)
		   && (!native_data_rh->color->details->pending) ) {
		/* error check */
		do_check = TRUE;
		if(rsc_lh->effective_priority < rsc_rh->effective_priority) {
			update_lh = TRUE;
			
		} else if(rsc_lh->effective_priority
			  > rsc_rh->effective_priority) {
			update_rh = TRUE;

		} else {
			update_lh = TRUE;
			update_rh = TRUE;
		}

	} else if(rsc_lh->provisional == FALSE
		  && native_data_lh->color->details->pending == FALSE) {
		/* update _us_    : postproc color version */
		update_rh = TRUE;

	} else if(rsc_rh->provisional == FALSE
		  && native_data_rh->color->details->pending == FALSE) {
		/* update _them_  : postproc color alt version */
		update_lh = TRUE;

	} else if(rsc_lh->provisional == FALSE) {
		/* update _us_    : preproc version */
		update_rh = TRUE;

	} else if(rsc_rh->provisional == FALSE) {
		/* update _them_  : postproc version */
		update_lh = TRUE;

	} else {
		crm_warn("Un-expected combination of inputs");
		return;
	}
	

	if(update_lh) {
		crm_debug("Updating LHS");
	}
	if(update_rh) {
		crm_debug("Updating RHS");
	}		

	if(do_check) {
		if(native_constraint_violated(
			   rsc_lh, rsc_rh, constraint) == FALSE) {

			crm_debug("Constraint satisfied");
			return;
		}
		/* else constraint cant be satisified */
		crm_warn("Constraint %s could not be satisfied",
			 constraint->id);
		
		if(update_lh) {
			crm_warn("Marking resource %s unrunnable as a result",
				 rsc_lh->id);
			rsc_lh->runnable = FALSE;
		}
		if(update_rh) {
			crm_warn("Marking resource %s unrunnable as a result",
				 rsc_rh->id);
			rsc_rh->runnable = FALSE;
		}		
	}

	if(constraint->strength == pecs_must) {
		native_rsc_dependancy_rh_must(
			rsc_lh, update_lh,rsc_rh, update_rh);
		return;
		
	} else if(constraint->strength != pecs_must_not) {
		/* unknown type */
		crm_err("Unknown constraint type %d", constraint->strength);
		return;
	}

	native_rsc_dependancy_rh_mustnot(rsc_lh, update_lh,rsc_rh, update_rh);
}


void native_rsc_order_lh(resource_t *lh_rsc, order_constraint_t *order)
{
	int lpc;
	GListPtr lh_actions = NULL;
	action_t *lh_action = order->lh_action;

	crm_verbose("Processing LH of ordering constraint %d", order->id);

	if(order->lh_action_task != stop_rsc
	   && order->lh_action_task != start_rsc) {
		crm_err("Task %s from ordering %d isnt a resource action",
			task2text(order->lh_action_task), order->id);
		return;
	}


	if(lh_action != NULL) {
		lh_actions = g_list_append(NULL, lh_action);

	} else if(lh_action == NULL && lh_rsc != NULL) {
		if(order->strength == pecs_must) {
			crm_debug("No LH-Side (%s/%s) found for constraint..."
				  " creating",
				  lh_rsc->id, task2text(order->lh_action_task));

			action_new(lh_rsc, order->lh_action_task, NULL);
		}
			
		lh_actions = find_actions(
			lh_rsc->actions, order->lh_action_task, NULL);

		if(lh_actions == NULL) {
			crm_debug("No LH-Side (%s/%s) found for constraint",
				  lh_rsc->id, task2text(order->lh_action_task));
			return;
		}

	} else {
		crm_warn("No LH-Side (%s) specified for constraint",
			 task2text(order->lh_action_task));
		return;
	}

	slist_iter(
		lh_action_iter, action_t, lh_actions, lpc,

		resource_t *rh_rsc = order->rh_rsc;
		if(rh_rsc == NULL && order->rh_action) {
			rh_rsc = order->rh_action->rsc;
		}
		
		if(rh_rsc) {
			rh_rsc->fns->rsc_order_rh(
				lh_action_iter, rh_rsc, order);

		} else if(order->rh_action) {
			order_actions(lh_action_iter, order->rh_action, order); 

		}
		);

	pe_free_shallow_adv(lh_actions, FALSE);
}

void native_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	int lpc;
	GListPtr rh_actions = NULL;
	action_t *rh_action = order->rh_action;

	crm_verbose("Processing RH of ordering constraint %d", order->id);

	if(rh_action != NULL) {
		rh_actions = g_list_append(NULL, rh_action);

	} else if(rh_action == NULL && rsc != NULL) {
		rh_actions = find_actions(
			rsc->actions, order->rh_action_task, NULL);

		if(rh_actions == NULL) {
			crm_debug("No RH-Side (%s/%s) found for constraint..."
				  " ignoring",
				  rsc->id, task2text(order->rh_action_task));
			return;
		}
			
	}  else if(rh_action == NULL) {
		crm_debug("No RH-Side (%s) specified for constraint..."
			  " ignoring", task2text(order->rh_action_task));
		return;
	} 

	slist_iter(
		rh_action_iter, action_t, rh_actions, lpc,

		order_actions(lh_action, rh_action_iter, order); 
		);

	pe_free_shallow_adv(rh_actions, FALSE);
}

void native_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	int lpc;
	GListPtr or_list;
	resource_t *rsc_lh = rsc;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc_lh->variant_opaque;
	
	crm_debug_action(print_rsc_to_node("Applying", constraint, FALSE));
	/* take "lifetime" into account */
	if(constraint == NULL) {
		crm_err("Constraint is NULL");
		return;
			
	} else if(is_active(constraint) == FALSE) {
		crm_info("Constraint (%s) is not active", constraint->id);
		/* warning */
		return;
	}
    
	rsc_lh = constraint->rsc_lh;
	if(rsc_lh == NULL) {
		crm_err("LHS of rsc_to_node (%s) is NULL", constraint->id);
		return;
	}

	native_data->node_cons =
		g_list_append(native_data->node_cons, constraint);

	if(constraint->node_list_rh == NULL) {
		crm_err("RHS of constraint %s is NULL", constraint->id);
		return;
	}
	crm_debug_action(print_resource("before update", rsc_lh,TRUE));

	or_list = node_list_or(
		native_data->allowed_nodes, constraint->node_list_rh, FALSE);
		
	pe_free_shallow(native_data->allowed_nodes);
	native_data->allowed_nodes = or_list;
	slist_iter(node_rh, node_t, constraint->node_list_rh, lpc,
		   native_update_node_weight(
			   constraint, node_rh->details->uname,
			   native_data->allowed_nodes));

	crm_debug_action(print_resource("after update", rsc_lh, TRUE));

}

void native_expand(resource_t *rsc, xmlNodePtr *graph)
{
	int lpc;
	slist_iter(
		action, action_t, rsc->actions, lpc,
		crm_debug("processing action %d for rsc=%s",
			  action->id, rsc->id);
		graph_element_from_action(action, graph);
		);
}

void native_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	common_dump(rsc, pre_text, details);
	crm_debug("\t%d candidate colors, %d allowed nodes,"
		  " %d rsc_cons and %d node_cons",
		  g_list_length(rsc->candidate_colors),
		  g_list_length(native_data->allowed_nodes),
		  g_list_length(rsc->rsc_cons),
		  g_list_length(native_data->node_cons));
	
	if(details) {
		int lpc = 0;
		
		crm_debug("\t=== Actions");
		slist_iter(
			action, action_t, rsc->actions, lpc, 
			print_action("\trsc action: ", action, FALSE);
			);
		
		crm_debug("\t=== Colors");
		slist_iter(
			color, color_t, rsc->candidate_colors, lpc,
			print_color("\t", color, FALSE)
			);

		crm_debug("\t=== Allowed Nodes");
		slist_iter(
			node, node_t, native_data->allowed_nodes, lpc,
			print_node("\t", node, FALSE);
			);
	}
}

void native_free(resource_t *rsc)
{
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;
	
	crm_debug("Freeing Allowed Nodes");
	pe_free_shallow(native_data->allowed_nodes);
	
	common_free(rsc);	
}


void native_rsc_dependancy_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh)
{
	native_variant_data_t *native_data_lh =
		(native_variant_data_t *)rsc_lh->variant_opaque;

	native_variant_data_t *native_data_rh =
		(native_variant_data_t *)rsc_rh->variant_opaque;

	gboolean do_merge = FALSE;
	GListPtr old_list = NULL;
	GListPtr merged_node_list = NULL;
	float max_pri = rsc_lh->effective_priority;
	if(max_pri < rsc_rh->effective_priority) {
		max_pri = rsc_rh->effective_priority;
	}
	rsc_lh->effective_priority = max_pri;
	rsc_rh->effective_priority = max_pri;

	if(native_data_lh->color && native_data_rh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			native_data_lh->color->details->candidate_nodes,
			native_data_rh->color->details->candidate_nodes, TRUE);
			
	} else if(native_data_lh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			native_data_lh->color->details->candidate_nodes,
			native_data_rh->allowed_nodes, TRUE);

	} else if(native_data_rh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			native_data_lh->allowed_nodes,
			native_data_rh->color->details->candidate_nodes, TRUE);
	}
		
	if(update_lh) {
		crm_free(native_data_lh->color);
		rsc_lh->runnable = rsc_rh->runnable;
		native_data_lh->color    = copy_color(native_data_rh->color);
	}
	if(update_rh) {
		crm_free(native_data_rh->color);
		rsc_rh->runnable = rsc_lh->runnable;
		native_data_rh->color    = copy_color(native_data_lh->color);
	}

	if(do_merge) {
		crm_debug("Merging candidate nodes");
		old_list = native_data_rh->color->details->candidate_nodes;
		native_data_rh->color->details->candidate_nodes = merged_node_list;
		pe_free_shallow(old_list);
	}
		
	crm_debug("Finished processing pecs_must constraint");
}

void native_rsc_dependancy_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh)
{
	color_t *color_lh = NULL;
	color_t *color_rh = NULL;

	native_variant_data_t *native_data_lh =
		(native_variant_data_t *)rsc_lh->variant_opaque;

	native_variant_data_t *native_data_rh =
		(native_variant_data_t *)rsc_rh->variant_opaque;
	
	crm_debug("Processing pecs_must_not constraint");
	/* pecs_must_not */
	if(update_lh) {
		color_rh = native_data_rh->color;

		if(rsc_lh->provisional) {
			color_lh = find_color(
				rsc_lh->candidate_colors, color_rh);

			rsc_lh->candidate_colors = g_list_remove(
				rsc_lh->candidate_colors, color_lh);
			
			crm_debug_action(
				print_color("Removed LH", color_lh, FALSE));
			
			crm_debug_action(
				print_resource("Modified LH", rsc_lh, TRUE));
			
			crm_free(color_lh);
			
		} else if(native_data_lh->color
			  && native_data_lh->color->details->pending) {
			node_t *node_lh = NULL;
			
			color_lh = native_data_lh->color;
			node_lh = pe_find_node(
				color_lh->details->candidate_nodes,
				safe_val5(NULL, color_rh, details,
					  chosen_node, details, uname));
			
			color_lh->details->candidate_nodes =
				g_list_remove(
					color_lh->details->candidate_nodes,
					node_lh);
			
			crm_debug_action(
				print_node("Removed LH", node_lh, FALSE));

			crm_debug_action(
				print_color("Modified LH", color_lh, FALSE));
			
			crm_free(node_lh);
		} else {
			/* error, rsc marked as unrunnable above */
			crm_warn("lh else");
		}
	}
	
	if(update_rh) {
		color_lh = native_data_lh->color;
		if(rsc_rh->provisional) {
			color_rh = find_color(
				rsc_rh->candidate_colors, color_lh);

			rsc_rh->candidate_colors = g_list_remove(
				rsc_rh->candidate_colors, color_rh);
			
			crm_debug_action(
				print_color("Removed RH", color_rh, FALSE));

			crm_debug_action(
				print_resource("Modified RH", rsc_rh, TRUE));
			
			crm_free(color_rh);
			
		} else if(native_data_rh->color
			  && native_data_rh->color->details->pending) {
			node_t *node_rh = NULL;
			color_rh = native_data_rh->color;
			node_rh = pe_find_node(
				color_rh->details->candidate_nodes,
				safe_val5(NULL, color_lh, details,
					  chosen_node, details, uname));
			
			color_rh->details->candidate_nodes =
				g_list_remove(
					color_rh->details->candidate_nodes,
					node_rh);
			
			crm_debug_action(
				print_node("Removed RH", node_rh, FALSE));

			crm_debug_action(
				print_color("Modified RH", color_rh, FALSE));

			crm_free(node_rh);

		} else {
			/* error, rsc marked as unrunnable above */
			crm_warn("rh else");
		}
	}
}


void
native_agent_constraints(resource_t *rsc)
{
	int lpc;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	crm_trace("Applying RA restrictions to %s", rsc->id);
	slist_iter(
		node, node_t, native_data->allowed_nodes, lpc,
		
		crm_trace("Checking if %s supports %s/%s (%s)",
			  node->details->uname,
			  native_data->agent->class,
			  native_data->agent->type,
			  native_data->agent->version);
		
		if(has_agent(node, native_data->agent) == FALSE) {
			/* remove node from contention */
			crm_trace("Marking node %s unavailable for %s",
				  node->details->uname, rsc->id);
			node->weight = -1.0;
			node->fixed = TRUE;
		}
		if(node->fixed && node->weight < 0) {
			/* the structure of the list will have changed
			 * lpc-- might be sufficient
			 */
			crm_debug("Removing node %s from %s",
				  node->details->uname, rsc->id);
			
			lpc = -1;
			native_data->allowed_nodes = g_list_remove(
				native_data->allowed_nodes, node);

			crm_free(node);
		}
		);
}

gboolean
has_agent(node_t *a_node, lrm_agent_t *an_agent)
{
	int lpc;
	if(a_node == NULL || an_agent == NULL || an_agent->type == NULL) {
		crm_warn("Invalid inputs");
		return FALSE;
	}
	
	crm_devel("Checking %d agents on %s",
		  g_list_length(a_node->details->agents),
		  a_node->details->uname);

	slist_iter(
		agent, lrm_agent_t, a_node->details->agents, lpc,

		crm_trace("Checking against  %s/%s (%s)",
			  agent->class, agent->type, agent->version);

		if(safe_str_eq(an_agent->type, agent->type)){
			if(an_agent->class == NULL) {
				return TRUE;
				
			} else if(safe_str_eq(an_agent->class, agent->class)) {
				if(compare_version(
					   an_agent->version, agent->version)
				   <= 0) {
					return TRUE;
				}
			}
		}
		);
	
	crm_verbose("%s doesnt support version %s of %s/%s",
		    a_node->details->uname, an_agent->version,
		    an_agent->class, an_agent->type);
	
	return FALSE;
}
gboolean
native_choose_color(resource_t *rsc)
{
	int lpc = 0;
	GListPtr sorted_colors = NULL;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	if(rsc->runnable == FALSE) {
		native_assign_color(rsc, no_color);
	}

	if(rsc->provisional == FALSE) {
		return !rsc->provisional;
	}
	
	sorted_colors = g_list_sort(
		rsc->candidate_colors, sort_color_weight);
	
	rsc->candidate_colors = sorted_colors;
	
	crm_verbose("Choose a color from %d possibilities",
		    g_list_length(sorted_colors));
	
	slist_iter(
		this_color, color_t, rsc->candidate_colors, lpc,
		GListPtr intersection = NULL;
		GListPtr minus = NULL;
		int len = 0;

		if(this_color == NULL) {
			crm_err("color was NULL");
			continue;
			
		} else if(rsc->effective_priority
		   < this_color->details->highest_priority) {

			minus = node_list_minus(
				this_color->details->candidate_nodes, 
				native_data->allowed_nodes, TRUE);

			len = g_list_length(minus);
			pe_free_shallow(minus);
			
			if(len > 0) {
				native_assign_color(rsc, this_color);
				break;
			}
			
		} else {
			intersection = node_list_and(
				this_color->details->candidate_nodes, 
				native_data->allowed_nodes, TRUE);

			len = g_list_length(intersection);
			pe_free_shallow(intersection);
			
			if(len != 0) {
				native_assign_color(rsc, this_color);
				break;
			}
		}
		);

	return !rsc->provisional;
}


gboolean
native_assign_color(resource_t *rsc, color_t *color) 
{
	color_t *local_color = add_color(rsc, color);
	GListPtr intersection = NULL;
	GListPtr old_list = NULL;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	native_data->color = local_color;
	rsc->provisional = FALSE;

	if(local_color != NULL) {
		local_color->details->allocated_resources =
			g_list_append(
				local_color->details->allocated_resources,rsc);

			intersection = node_list_and(
				local_color->details->candidate_nodes, 
				native_data->allowed_nodes, TRUE);
			   
			old_list = local_color->details->candidate_nodes;
				
			pe_free_shallow(old_list);
			
			local_color->details->candidate_nodes = intersection;
				
			crm_verbose("Colored resource %s with new color %d",
				    rsc->id, native_data->color->id);
			
			crm_debug_action(
				print_resource("Colored Resource", rsc, TRUE));
			
		return TRUE;
	} else {
		crm_err("local color was NULL");
	}
	
	return FALSE;
}

gboolean
native_update_node_weight(rsc_to_node_t *cons, const char *id, GListPtr nodes)
{
	native_variant_data_t *native_data =
		(native_variant_data_t *)cons->rsc_lh->variant_opaque;

	node_t *node_rh = pe_find_node(native_data->allowed_nodes, id);

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
native_constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_dependancy_t *constraint)
{
	native_variant_data_t *native_data_lh =
		(native_variant_data_t *)rsc_lh->variant_opaque;

	native_variant_data_t *native_data_rh =
		(native_variant_data_t *)rsc_rh->variant_opaque;

	GListPtr result = NULL;
	color_t *color_lh = native_data_lh->color;
	color_t *color_rh = native_data_rh->color;

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


/*
 * Remove any nodes with a -ve weight
 */
gboolean
filter_nodes(resource_t *rsc)
{
	int lpc2 = 0;
	native_variant_data_t *native_data =
		(native_variant_data_t *)rsc->variant_opaque;

	crm_debug_action(print_resource("Filtering nodes for", rsc, FALSE));
	slist_iter(
		node, node_t, native_data->allowed_nodes, lpc2,
		if(node == NULL) {
			crm_err("Invalid NULL node");
			
		} else if(node->weight < 0.0
			  || node->details->online == FALSE
			  || node->details->type == node_ping) {
			crm_debug_action(print_node("Removing", node, FALSE));
			native_data->allowed_nodes =
				g_list_remove(native_data->allowed_nodes, node);
			crm_free(node);
			lpc2 = -1; /* restart the loop */
		}
		);

	return TRUE;
}

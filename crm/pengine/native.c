/* $Id: native.c,v 1.1 2004/11/09 09:32:14 andrew Exp $ */
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

extern gboolean choose_color(resource_t *lh_resource);
extern gboolean assign_color(resource_t *rsc, color_t *color);
extern gboolean update_node_weight(
	rsc_to_node_t *cons,const char *id,GListPtr nodes);
extern gboolean is_active(rsc_to_node_t *cons);
extern gboolean constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_dependancy_t *constraint);
extern void order_actions(action_t *lh, action_t *rh, order_constraint_t *order);

void native_rsc_dependancy_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh);

void native_rsc_dependancy_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh);

void native_unpack(resource_t *rsc)
{
	xmlNodePtr xml_obj = rsc->xml;
	
	const char *stopfail   = xmlGetProp(xml_obj, "on_stopfail");
	const char *restart    = xmlGetProp(xml_obj, "restart_type");
	const char *timeout    = xmlGetProp(xml_obj, "timeout");
	const char *version    = xmlGetProp(xml_obj, XML_ATTR_VERSION);
	const char *priority   = xmlGetProp(xml_obj, XML_CIB_ATTR_PRIORITY);	
	
	const char *max_instances      = xmlGetProp(xml_obj, "max_instances");
	const char *max_node_instances = xmlGetProp(xml_obj, "max_node_instances");
	const char *max_masters      = xmlGetProp(xml_obj, "max_masters");
	const char *max_node_masters = xmlGetProp(xml_obj, "max_node_masters");
	
	crm_verbose("Processing resource...");
	
	crm_malloc(rsc->agent, sizeof(lrm_agent_t));
	rsc->agent->class	= xmlGetProp(xml_obj, "class");
	rsc->agent->type	= xmlGetProp(xml_obj, "type");
	rsc->agent->version	= version?version:"0.0";
	
	rsc->priority	        = atoi(priority?priority:"0"); 
	rsc->effective_priority = rsc->priority;
	rsc->recovery_type      = recovery_stop_start;
		
	rsc->max_instances	= atoi(max_instances?max_instances:"1"); 
	rsc->max_node_instances = atoi(max_node_instances?max_node_instances:"1"); 
	rsc->max_masters        = atoi(max_masters?max_masters:"0"); 
	rsc->max_node_masters   = atoi(max_node_masters?max_node_masters:"0"); 
	
	rsc->candidate_colors   = NULL;
	rsc->actions            = NULL;
	rsc->color		= NULL; 
	rsc->runnable		= TRUE; 
	rsc->provisional	= TRUE; 
	rsc->allowed_nodes	= NULL;
	rsc->rsc_cons		= NULL; 
	rsc->node_cons		= NULL; 
	rsc->running_on		= NULL;
	rsc->timeout		= timeout;
	
	if(safe_str_eq(stopfail, "ignore")) {
		rsc->stopfail_type = pesf_ignore;
	} else if(safe_str_eq(stopfail, "stonith")) {
		rsc->stopfail_type = pesf_stonith;
	} else {
		rsc->stopfail_type = pesf_block;
	}
	
	if(safe_str_eq(restart, "restart")) {
		rsc->restart_type = pe_restart_restart;
	} else if(safe_str_eq(restart, "recover")) {
		rsc->restart_type = pe_restart_recover;
	} else {
		rsc->restart_type = pe_restart_ignore;
	}

}

void native_color(resource_t *rsc, GListPtr *colors)
{
	color_t *new_color = NULL;
	if( choose_color(rsc) ) {
		crm_verbose("Colored resource %s with color %d",
			    rsc->id, rsc->color->id);
		
	} else {
		if(rsc->allowed_nodes != NULL) {
			/* filter out nodes with a negative weight */
			filter_nodes(rsc);
			new_color = create_color(colors, rsc, NULL);
			assign_color(rsc, new_color);
		}
		
		if(new_color == NULL) {
			crm_err("Could not color resource %s", rsc->id);
			print_resource("ERROR: No color", rsc, FALSE);
			assign_color(rsc, no_color);
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

	if(rsc->color != NULL) {
		chosen = rsc->color->details->chosen_node;
	}
	
	if(chosen != NULL) {
		can_start = TRUE;
	}
	
	if(can_start && g_list_length(rsc->running_on) == 0) {
		/* create start action */
		crm_info("Start resource %s (%s)",
			 rsc->id,
			 safe_val3(NULL, chosen, details, uname));
		start_op = action_new(rsc, start_rsc, chosen);
		
	} else if(g_list_length(rsc->running_on) > 1) {
		crm_info("Attempting recovery of resource %s",
			 rsc->id);
		
		if(rsc->recovery_type == recovery_stop_start
		   || rsc->recovery_type == recovery_stop_only) {
			slist_iter(
				node, node_t,
				rsc->running_on, lpc2,
				
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
			node, node_t, rsc->running_on, lpc2,				
			
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

void native_internal_ordering(resource_t *rsc, GListPtr *ordering_constraints)
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
		   && (!rsc_lh->color->details->pending)
		   && (!rsc_rh->color->details->pending) ) {
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
		  && rsc_lh->color->details->pending == FALSE) {
		/* update _us_    : postproc color version */
		update_rh = TRUE;

	} else if(rsc_rh->provisional == FALSE
		  && rsc_rh->color->details->pending == FALSE) {
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
		if(constraint_violated(rsc_lh, rsc_rh, constraint) == FALSE) {
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


void native_rsc_order_lh(order_constraint_t *order)
{
	int lpc;
	GListPtr lh_actions = NULL;
	action_t *lh_action = order->lh_action;

	crm_verbose("Processing LH of ordering constraint %d", order->id);

	if(lh_action != NULL) {
		lh_actions = g_list_append(NULL, lh_action);

	} else if(lh_action == NULL && order->lh_rsc != NULL) {
		if(order->strength == pecs_must) {
			crm_debug("No LH-Side (%s/%s) found for constraint..."
				  " creating",
				  order->lh_rsc->id,
				  task2text(order->lh_action_task));

			action_new(order->lh_rsc, order->lh_action_task, NULL);
		}
			
		lh_actions = find_actions_type(
			order->lh_rsc->actions, order->lh_action_task, NULL);

		if(lh_actions == NULL) {
			crm_debug("No LH-Side (%s/%s) found for constraint",
				  order->lh_rsc->id,
				  task2text(order->lh_action_task));
			return;
		}

	} else {
		crm_warn("No LH-Side (%s) specified for constraint",
			 task2text(order->lh_action_task));
		return;
	}

	slist_iter(
		lh_action_iter, action_t, lh_actions, lpc,

		if(order->rh_rsc) {
			order->rh_rsc->fns->rsc_order_rh(lh_action_iter, order);

		} else if(order->rh_action) {
			order_actions(lh_action_iter, order->rh_action, order); 

		}
		);

	pe_free_shallow_adv(lh_actions, FALSE);
}

void native_rsc_order_rh(action_t *lh_action, order_constraint_t *order)
{
	int lpc;
	GListPtr rh_actions = NULL;
	action_t *rh_action = order->rh_action;

	crm_verbose("Processing RH of ordering constraint %d", order->id);

	if(rh_action != NULL) {
		rh_actions = g_list_append(NULL, rh_action);

	} else if(rh_action == NULL && order->rh_rsc != NULL) {
		rh_actions = find_actions_type(
			order->rh_rsc->actions, order->rh_action_task, NULL);

		if(rh_actions == NULL) {
			crm_debug("No RH-Side (%s/%s) found for constraint..."
				  " ignoring",
				  order->rh_rsc->id,
				  task2text(order->rh_action_task));
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

void native_rsc_location(rsc_to_node_t *constraint)
{
	int lpc;
	GListPtr or_list;
	resource_t *rsc_lh = constraint->rsc_lh;
	
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

	constraint->rsc_lh->node_cons =
		g_list_append(constraint->rsc_lh->node_cons, constraint);

	if(constraint->node_list_rh == NULL) {
		crm_err("RHS of constraint %s is NULL", constraint->id);
		return;
	}
	crm_debug_action(print_resource("before update", rsc_lh,TRUE));

	or_list = node_list_or(
		rsc_lh->allowed_nodes, constraint->node_list_rh, FALSE);
		
	pe_free_shallow(rsc_lh->allowed_nodes);
	rsc_lh->allowed_nodes = or_list;
	slist_iter(node_rh, node_t, constraint->node_list_rh, lpc,
		   update_node_weight(constraint, node_rh->details->uname,
				      rsc_lh->allowed_nodes));

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
	
	crm_debug("%s%s%s%sResource %s: (priority=%f, color=%d, now=%d)",
		  pre_text==NULL?"":pre_text,
		  pre_text==NULL?"":": ",
		  rsc->provisional?"Provisional ":"",
		  rsc->runnable?"":"(Non-Startable) ",
		  rsc->id,
		  (double)rsc->priority,
		  safe_val3(-1, rsc, color, id),
		  g_list_length(rsc->running_on));

	crm_debug("\t%d candidate colors, %d allowed nodes,"
		  " %d rsc_cons and %d node_cons",
		  g_list_length(rsc->candidate_colors),
		  g_list_length(rsc->allowed_nodes),
		  g_list_length(rsc->rsc_cons),
		  g_list_length(rsc->node_cons));
	
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
			node, node_t, rsc->allowed_nodes, lpc,
			print_node("\t", node, FALSE);
			);
	}
}

void native_free(resource_t *rsc)
{
	crm_debug("Freeing Allowed Nodes");
	pe_free_shallow(rsc->allowed_nodes);
	
	while(rsc->rsc_cons) {
		crm_debug("Freeing constraint");
 		pe_free_rsc_dependancy((rsc_dependancy_t*)rsc->rsc_cons->data);
		rsc->rsc_cons = rsc->rsc_cons->next;
	}
	crm_debug("Freeing constraint list");
	if(rsc->rsc_cons != NULL) {
		g_list_free(rsc->rsc_cons);
	}
	/* free ourselves? */
}


void native_rsc_dependancy_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh)
{
	gboolean do_merge = FALSE;
	GListPtr old_list = NULL;
	GListPtr merged_node_list = NULL;
	float max_pri = rsc_lh->effective_priority;
	if(max_pri < rsc_rh->effective_priority) {
		max_pri = rsc_rh->effective_priority;
	}
	rsc_lh->effective_priority = max_pri;
	rsc_rh->effective_priority = max_pri;

	if(rsc_lh->color && rsc_rh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			rsc_lh->color->details->candidate_nodes,
			rsc_rh->color->details->candidate_nodes, TRUE);
			
	} else if(rsc_lh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			rsc_lh->color->details->candidate_nodes,
			rsc_rh->allowed_nodes, TRUE);

	} else if(rsc_rh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			rsc_lh->allowed_nodes,
			rsc_rh->color->details->candidate_nodes, TRUE);
	}
		
	if(update_lh) {
		crm_free(rsc_lh->color);
		rsc_lh->runnable = rsc_rh->runnable;
		rsc_lh->color    = copy_color(rsc_rh->color);
	}
	if(update_rh) {
		crm_free(rsc_rh->color);
		rsc_rh->runnable = rsc_lh->runnable;
		rsc_rh->color    = copy_color(rsc_lh->color);
	}

	if(do_merge) {
		crm_debug("Merging candidate nodes");
		old_list = rsc_rh->color->details->candidate_nodes;
		rsc_rh->color->details->candidate_nodes = merged_node_list;
		pe_free_shallow(old_list);
	}
		
	crm_debug("Finished processing pecs_must constraint");
}

void native_rsc_dependancy_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh)
{
	color_t *color_lh = NULL;
	color_t *color_rh = NULL;
	
	crm_debug("Processing pecs_must_not constraint");
	/* pecs_must_not */
	if(update_lh) {
		color_rh = rsc_rh->color;

		if(rsc_lh->provisional) {
			color_lh = find_color(
				rsc_lh->candidate_colors,color_rh);

			rsc_lh->candidate_colors = g_list_remove(
				rsc_lh->candidate_colors, color_lh);
			
			crm_debug_action(
				print_color("Removed LH", color_lh, FALSE));
			
			crm_debug_action(
				print_resource("Modified LH", rsc_lh, TRUE));
			
			crm_free(color_lh);
			
		} else if(rsc_lh->color && rsc_lh->color->details->pending) {
			node_t *node_lh = NULL;
			
			color_lh = rsc_lh->color;
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
		color_lh = rsc_lh->color;
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
			
		} else if(rsc_rh->color && rsc_rh->color->details->pending) {
			node_t *node_rh = NULL;
			color_rh = rsc_rh->color;
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

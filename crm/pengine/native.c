/* $Id: native.c,v 1.55 2005/06/30 11:59:43 andrew Exp $ */
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

#include <pengine.h>
#include <pe_utils.h>
#include <crm/msg_xml.h>

extern color_t *add_color(resource_t *rh_resource, color_t *color);

gboolean native_choose_color(resource_t *lh_resource, color_t *no_color);

void native_assign_color(resource_t *rsc, color_t *color);

void native_update_node_weight(resource_t *rsc, rsc_to_node_t *cons,
			       const char *id, GListPtr nodes);

void native_rsc_colocation_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh);

void native_rsc_colocation_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh);

void filter_nodes(resource_t *rsc);

int num_allowed_nodes4color(color_t *color);

void create_recurring_actions(resource_t *rsc, action_t *start, node_t *node,
			      pe_working_set_t *data_set);
action_t *create_recurring_action(resource_t *rsc, node_t *node,
				  const char *action, const char *key);

extern rsc_to_node_t *
rsc2node_new(const char *id, resource_t *rsc,
	     double weight, node_t *node, pe_working_set_t *data_set);

typedef struct native_variant_data_s
{
		lrm_agent_t *agent;
		GListPtr running_on;       /* node_t*           */
		color_t *color;
		GListPtr node_cons;        /* rsc_to_node_t*    */
		GListPtr allowed_nodes;    /* node_t*         */

} native_variant_data_t;

#define get_native_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_native);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (native_variant_data_t *)rsc->variant_opaque;

void
native_add_running(resource_t *rsc, node_t *node, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	CRM_DEV_ASSERT(node != NULL); if(crm_assert_failed) { return; }
	
	slist_iter(
		a_node, node_t, native_data->running_on, lpc,
		CRM_DEV_ASSERT(a_node != NULL);
		if(safe_str_eq(a_node->details->id, node->details->id)) {
			return;
		}
		);
	
	native_data->running_on = g_list_append(native_data->running_on, node);
	node->details->running_rsc = g_list_append(
		node->details->running_rsc, rsc);

	if(rsc->is_managed == FALSE) {
		rsc2node_new(
			"not_managed_default", rsc, INFINITY, node, data_set);
		return;

	} else if(rsc->stickiness > 0) {
		rsc2node_new("stickiness", rsc, INFINITY, node, data_set);

	} else if(rsc->stickiness < 0) {
		rsc2node_new("stickiness", rsc, -INFINITY, node, data_set);
	}
	
	if(g_list_length(native_data->running_on) > 1) {
		pe_warn("Resource %s is (potentially) active on %d nodes."
			 "  Latest: %s/%s", rsc->id,
			 g_list_length(native_data->running_on),
			 node->details->uname, node->details->id);
	}
}


void native_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	crm_data_t * xml_obj = rsc->xml;
	native_variant_data_t *native_data = NULL;

	const char *version  = crm_element_value(xml_obj, XML_ATTR_VERSION);
	
	crm_debug_3("Processing resource %s...", rsc->id);

	crm_malloc0(native_data, sizeof(native_variant_data_t));

	crm_malloc0(native_data->agent, sizeof(lrm_agent_t));
	native_data->agent->class	= crm_element_value(xml_obj, "class");
	native_data->agent->type	= crm_element_value(xml_obj, "type");
	native_data->agent->version	= version?version:"0.0";

	native_data->color		= NULL; 
	native_data->allowed_nodes	= NULL;
	native_data->node_cons		= NULL; 
	native_data->running_on		= NULL;

	rsc->variant_opaque = native_data;
}

		
resource_t *
native_find_child(resource_t *rsc, const char *id)
{
	return NULL;
}

int native_num_allowed_nodes(resource_t *rsc)
{
	int num_nodes = 0;
	native_variant_data_t *native_data = NULL;
	if(rsc->variant == pe_native) {
		native_data = (native_variant_data_t *)rsc->variant_opaque;
	} else {
		pe_err("Resource %s was not a \"native\" variant",
			rsc->id);
		return 0;
	}

	if(native_data->color) {
		crm_debug_4("Colored case");
		num_nodes = num_allowed_nodes4color(native_data->color);
		
	} else if(rsc->candidate_colors) {
		/* TODO: sort colors first */
		color_t *color = g_list_nth_data(rsc->candidate_colors, 0);
		crm_debug_4("Candidate colors case");
		num_nodes = num_allowed_nodes4color(color);

	} else {
		crm_debug_4("Default case");
		slist_iter(
			this_node, node_t, native_data->allowed_nodes, lpc,
			crm_debug_3("Rsc %s Checking %s: %f",
				    rsc->id, this_node->details->uname,
				    this_node->weight);
			if(this_node->details->shutdown
			   || this_node->details->online == FALSE) {
				this_node->weight = -INFINITY;
			}
			if(this_node->weight < 0) {				
				continue;
/* 			} else if(this_node->details->unclean) { */
/* 				continue; */
			}
			
			num_nodes++;
			);
	}
	crm_debug_2("Resource %s can run on %d nodes", rsc->id, num_nodes);
	return num_nodes;
}

int num_allowed_nodes4color(color_t *color) 
{
	int num_nodes = 0;

	if(color->details->pending == FALSE) {
		if(color->details->chosen_node) {
			return 1;
		}
		return 0;
	}
	
	slist_iter(
		this_node, node_t, color->details->candidate_nodes, lpc,
		crm_debug_3("Checking %s: %f",
			    this_node->details->uname, this_node->weight);
		if(this_node->details->shutdown
		   || this_node->details->online == FALSE) {
			this_node->weight = -INFINITY;
		}
		if(this_node->weight < 0) {
			continue;
/* 		} else if(this_node->details->unclean) { */
/* 			continue; */
		}
		num_nodes++;
		);

	return num_nodes;
}


void native_color(resource_t *rsc, pe_working_set_t *data_set)
{
	color_t *new_color = NULL;
	native_variant_data_t *native_data = NULL;

	get_native_variant_data(native_data, rsc);
	
	if( native_choose_color(rsc, data_set->no_color) ) {
		crm_debug_3("Colored resource %s with color %d",
			    rsc->id, native_data->color->id);
		
	} else {
		if(native_data->allowed_nodes != NULL) {
			/* filter out nodes with a negative weight */
			filter_nodes(rsc);
			new_color = create_color(data_set, rsc,
						 native_data->allowed_nodes);
			native_assign_color(rsc, new_color);
		}
		
		if(new_color == NULL) {
			pe_warn("Resource %s cannot run anywhere", rsc->id);
			print_resource("ERROR: No color", rsc, FALSE);
			native_assign_color(rsc, data_set->no_color);
		}
	}
	rsc->provisional = FALSE;
}

void
create_recurring_actions(resource_t *rsc, action_t *start, node_t *node,
			 pe_working_set_t *data_set) 
{
	action_t *mon = NULL;
	char *key = NULL;
	const char *name = NULL;
	const char *value = NULL;
	
	if(node == NULL || !node->details->online || node->details->unclean) {
		crm_debug_3("Not creating recurring actions");
		return;
	}

	xml_child_iter(
		rsc->ops_xml, operation, "op",

		name = crm_element_value(operation, "name");
		value = crm_element_value(operation, "interval");

		key = generate_op_key(rsc->id, name, crm_get_msec(value));
		mon = custom_action(rsc, key, name, node, start->optional, data_set);

		if(mon->optional == FALSE && node != NULL) {
			crm_info("   %s:\t(%s)", mon->uuid, node->details->uname);
		}
		custom_action_order(rsc, start_key(rsc), NULL,
				    NULL, crm_strdup(key), mon,
				    pe_ordering_manditory, data_set);
		);	
}

void native_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *start = NULL;
	action_t *stop = NULL;
	node_t *chosen = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	if(native_data->color != NULL) {
		chosen = native_data->color->details->chosen_node;
	}

	if(chosen != NULL && g_list_length(native_data->running_on) == 0) {
		start = start_action(rsc, chosen, TRUE);
		if(start->runnable && data_set->have_quorum == FALSE
		   && data_set->no_quorum_policy != no_quorum_ignore) {
			crm_warn("Start resource %s\t(%s) (cancelled : quorum)",
				 rsc->id, chosen->details->uname);
			start->runnable = FALSE;
		} else {
			crm_info("Start resource %s\t(%s)",
				 rsc->id, chosen->details->uname);
			start->optional = FALSE;
			start->rsc->start_pending = TRUE;
		}
		
		
	} else if(g_list_length(native_data->running_on) > 1) {
		pe_err("Attempting recovery of resource %s", rsc->id);
		
		if(rsc->recovery_type == recovery_stop_start
		   || rsc->recovery_type == recovery_stop_only) {
			slist_iter(
				node, node_t,
				native_data->running_on, lpc,
				
				crm_info("Stop  resource %s\t(%s) (recovery)",
					 rsc->id, node->details->uname);
				stop = stop_action(rsc, node, FALSE);
				);
		}
		
		if(rsc->recovery_type == recovery_stop_start && chosen) {
			/* if one of the "stops" is for a node outside
			 * our partition, then this will block anyway
			 */
			start = start_action(rsc, chosen, FALSE);
			if(start->runnable) {
				crm_info("Recover resource %s\t(%s)",
					 rsc->id, chosen->details->uname);
			}
			
			/* make the restart required */
			order_stop_start(rsc, rsc, pe_ordering_manditory);
		}

		if(rsc->recovery_type == recovery_block) {
			pe_warn("RESOURCE %s WILL REMAIN ACTIVE ON MULTIPLE"
				 " NODES PENDING MANUAL INTERVENTION", rsc->id);
			
			slist_iter(
				node, node_t, native_data->running_on, lpc,
				pe_warn("Resource %s active on %s",
					 rsc->id, node->details->uname);
				);
		}
		
	} else if(g_list_length(native_data->running_on) == 1) {
		node_t *node = native_data->running_on->data;
		
		crm_debug_2("Stop%s of %s", chosen?" and restart":"", rsc->id);
		CRM_DEV_ASSERT(node != NULL);

		if(chosen == NULL) {
			crm_info("Stop  resource %s\t(%s)",
				 rsc->id, node->details->uname);
			stop_action(rsc, node, FALSE);

		} else if(safe_str_eq(node->details->id, chosen->details->id)) {
			stop = stop_action(rsc, node, TRUE);
			start = start_action(rsc, chosen, TRUE);

			if(start->runnable == FALSE) {
				crm_info("Stop  resource %s\t(%s)",
					 rsc->id, node->details->uname);
				stop->optional = FALSE;

			} else if(rsc->recover) {
				crm_info("Restart resource %s\t(%s)",
					 rsc->id, node->details->uname);
				/* make the restart required */
				order_stop_start(rsc, rsc, pe_ordering_manditory);
				start->optional = FALSE;
				stop->optional = FALSE;

			} else {
				crm_info("Leave resource %s\t(%s)",
					 rsc->id, node->details->uname);

				if(stop->optional == FALSE) {
 					start->optional = FALSE;

				} else if(rsc->start_pending) { 
 					start->optional = FALSE;
 				}
			}
			
		} else {
			/* move */
			stop = stop_action(rsc, node, FALSE);
			start = start_action(rsc, chosen, FALSE);

			if(start->runnable) {
				crm_info("Move  resource %s\t(%s -> %s)", rsc->id,
					 node->details->uname,
					 chosen->details->uname);
			} else {
				crm_info("Stop  resource %s\t(%s)", rsc->id,
					 node->details->uname);
			}
			
			/* make the restart required */
			order_stop_start(rsc, rsc, pe_ordering_manditory);
			
		}
	}
	
	if(start != NULL && start->runnable) {
		create_recurring_actions(rsc, start, chosen, data_set);
	}
}

void native_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	order_restart(rsc);
}

void native_rsc_colocation_lh(rsc_colocation_t *constraint)
{
	resource_t *rsc = constraint->rsc_lh;
	
	if(rsc == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else {
		crm_debug_4("Processing constraints from %s", rsc->id);
	}
	
	constraint->rsc_rh->fns->rsc_colocation_rh(rsc, constraint);		
}

void native_rsc_colocation_rh(resource_t *rsc, rsc_colocation_t *constraint)
{
	gboolean do_check = FALSE;
	gboolean update_lh = FALSE;
	gboolean update_rh = FALSE;
	
	resource_t *rsc_lh = rsc;
	resource_t *rsc_rh = constraint->rsc_rh;

	native_variant_data_t *native_data_lh = NULL;
	native_variant_data_t *native_data_rh = NULL;

	get_native_variant_data(native_data_lh, rsc_lh);
	get_native_variant_data(native_data_rh, rsc_rh);
	
	crm_debug_2("%sColocating %s with %s",
		    constraint->strength == pecs_must?"":"Anti-",
		    rsc_lh->id, rsc_rh->id);
	
	if(constraint->strength == pecs_ignore
		|| constraint->strength == pecs_startstop){
		crm_debug_4("Skipping constraint type %d", constraint->strength);
		return;
	}

	if(rsc_lh->provisional && rsc_rh->provisional) {
		if(constraint->strength == pecs_must) {
			/* update effective_priorities */
			native_rsc_colocation_rh_must(
				rsc_lh, update_lh, rsc_rh, update_rh);
		} else {
			/* nothing */
			crm_debug_4(
				"Skipping constraint, both sides provisional");
		}
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
		/* update _them_    : postproc color version */
		update_rh = TRUE;
		
	} else if(rsc_rh->provisional == FALSE
		  && native_data_rh->color->details->pending == FALSE) {
		/* update _us_  : postproc color alt version */
		update_lh = TRUE;

	} else if(rsc_lh->provisional == FALSE) {
		/* update _them_    : preproc version */
		update_rh = TRUE;
		
	} else if(rsc_rh->provisional == FALSE) {
		/* update _us_  : postproc version */
		update_lh = TRUE;

	} else {
		pe_warn("Un-expected combination of inputs");
		return;
	}
	

	if(update_lh) {
		crm_debug_4("Updating LHS");
	}
	if(update_rh) {
		crm_debug_4("Updating RHS");
	}		

	if(do_check) {
		if(native_constraint_violated(
			   rsc_lh, rsc_rh, constraint) == FALSE) {

			crm_debug_4("Constraint satisfied");
			return;
		}
		/* else constraint cant be satisified */
		pe_warn("Constraint %s could not be satisfied",
			 constraint->id);
		
		if(update_lh) {
			pe_warn("Marking resource %s unrunnable as a result",
				 rsc_lh->id);
			rsc_lh->runnable = FALSE;
		}
		if(update_rh) {
			pe_warn("Marking resource %s unrunnable as a result",
				 rsc_rh->id);
			rsc_rh->runnable = FALSE;
		}		
	}

	if(constraint->strength == pecs_must) {
		native_rsc_colocation_rh_must(
			rsc_lh, update_lh, rsc_rh, update_rh);
		return;
		
	} else if(constraint->strength != pecs_must_not) {
		/* unknown type */
		pe_err("Unknown constraint type %d", constraint->strength);
		return;
	}

	native_rsc_colocation_rh_mustnot(rsc_lh, update_lh,rsc_rh, update_rh);
}


void native_rsc_order_lh(resource_t *lh_rsc, order_constraint_t *order)
{
	GListPtr lh_actions = NULL;
	action_t *lh_action = order->lh_action;

	crm_debug_3("Processing LH of ordering constraint %d", order->id);

	if(lh_action != NULL) {
		lh_actions = g_list_append(NULL, lh_action);

	} else if(lh_action == NULL && lh_rsc != NULL) {
#if 0
/* this should be safe to remove */
		if(order->strength == pecs_must) {
			crm_debug_4("No LH-Side (%s/%s) found for constraint..."
				  " creating",
				  lh_rsc->id, order->lh_action_task);
			pe_err("BROKEN CODE");
			custom_action(
				lh_rsc, order->lh_action_task, NULL, NULL);
		}
#endif
		lh_actions = find_actions(
			lh_rsc->actions, order->lh_action_task, NULL);

		if(lh_actions == NULL) {
			crm_debug_4("No LH-Side (%s/%s) found for constraint",
				  lh_rsc->id, order->lh_action_task);

			if(order->rh_rsc != NULL) {
				crm_debug_4("RH-Side was: (%s/%s)",
					  order->rh_rsc->id,
					  order->rh_action_task);
				
			} else if(order->rh_action != NULL
				  && order->rh_action->rsc != NULL) {
				crm_debug_4("RH-Side was: (%s/%s)",
					  order->rh_action->rsc->id,
					  order->rh_action_task);
				
			} else if(order->rh_action != NULL) {
				crm_debug_4("RH-Side was: %s",
					  order->rh_action_task);
			} else {
				crm_debug_4("RH-Side was NULL");
			}
			
			return;
		}

	} else {
		pe_warn("No LH-Side (%s) specified for constraint",
			 order->lh_action_task);
		if(order->rh_rsc != NULL) {
			crm_debug_4("RH-Side was: (%s/%s)",
				  order->rh_rsc->id,
				  order->rh_action_task);
				  
		} else if(order->rh_action != NULL
			  && order->rh_action->rsc != NULL) {
			crm_debug_4("RH-Side was: (%s/%s)",
				  order->rh_action->rsc->id,
				  order->rh_action_task);
				  
		} else if(order->rh_action != NULL) {
			crm_debug_4("RH-Side was: %s",
				  order->rh_action_task);
		} else {
			crm_debug_4("RH-Side was NULL");
		}		
		
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
	GListPtr rh_actions = NULL;
	action_t *rh_action = order->rh_action;

	crm_debug_3("Processing RH of ordering constraint %d", order->id);

	if(rh_action != NULL) {
		rh_actions = g_list_append(NULL, rh_action);

	} else if(rh_action == NULL && rsc != NULL) {
		rh_actions = find_actions(
			rsc->actions, order->rh_action_task, NULL);
		
		if(rh_actions == NULL) {
			crm_debug_4("No RH-Side (%s/%s) found for constraint..."
				  " ignoring",
				  rsc->id, order->rh_action_task);
			crm_debug_4("LH-Side was: (%s/%s)",
				  order->lh_rsc?order->lh_rsc->id:order->lh_action?order->lh_action->rsc->id:"<NULL>",
				  order->lh_action_task);
			return;
		}
			
	}  else if(rh_action == NULL) {
		crm_debug_4("No RH-Side (%s) specified for constraint..."
			  " ignoring", order->rh_action_task);
		crm_debug_4("LH-Side was: (%s/%s)",
			  order->lh_rsc?order->lh_rsc->id:order->lh_action?order->lh_action->rsc->id:"<NULL>",
			  order->lh_action_task);
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
	GListPtr or_list;
	native_variant_data_t *native_data = NULL;
	
	crm_action_debug_3(print_rsc_to_node("Applying", constraint, FALSE));
	/* take "lifetime" into account */
	if(constraint == NULL) {
		pe_err("Constraint is NULL");
		return;
			
	} else if(is_active(constraint) == FALSE) {
		crm_debug_2("Constraint (%s) is not active", constraint->id);
		return;
	} else if(rsc == NULL) {
		pe_err("LHS of rsc_to_node (%s) is NULL", constraint->id);
		return;
	}
    
	get_native_variant_data(native_data, rsc);

	native_data->node_cons =
		g_list_append(native_data->node_cons, constraint);

	if(constraint->node_list_rh == NULL) {
		crm_debug_2("RHS of constraint %s is NULL", constraint->id);
		return;
	}
	crm_action_debug_3(print_resource("before update", rsc,TRUE));

	or_list = node_list_or(
		native_data->allowed_nodes, constraint->node_list_rh, FALSE);
		
	pe_free_shallow(native_data->allowed_nodes);
	native_data->allowed_nodes = or_list;

	slist_iter(node_rh, node_t, constraint->node_list_rh, lpc,
		   native_update_node_weight(
			   rsc, constraint, node_rh->details->uname,
			   native_data->allowed_nodes));

	crm_action_debug_3(print_resource("after update", rsc, TRUE));

}

void native_expand(resource_t *rsc, pe_working_set_t *data_set)
{
	slist_iter(
		action, action_t, rsc->actions, lpc,
		crm_debug_4("processing action %d for rsc=%s",
			  action->id, rsc->id);
		graph_element_from_action(action, data_set);
		);
}

void native_printw(resource_t *rsc, const char *pre_text, int *index)
{
#ifdef HAVE_LIBNCURSES
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	common_printw(rsc, pre_text, index);
	if(g_list_length(native_data->running_on) == 0) {
		printw("NOT ACTIVE\n");
		
	} else if(g_list_length(native_data->running_on) == 1) {
		node_t *node = native_data->running_on->data;
		printw("%s (%s)\n", node->details->uname, node->details->id);
		
	} else if(g_list_length(native_data->running_on) == 1) {
		printw("[");
		slist_iter(node, node_t, native_data->running_on, lpc,
			   if(lpc > 0) { printw(", "); }
			   printw("%s (%s)", node->details->uname, node->details->id);
			);
		printw("]\n");
	}
#else
	crm_err("printw support requires ncurses to be available during configure");
#endif
}

void native_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	common_dump(rsc, pre_text, details);
	crm_debug_4("\t%d candidate colors, %d allowed nodes,"
		  " %d rsc_cons and %d node_cons",
		  g_list_length(rsc->candidate_colors),
		  g_list_length(native_data->allowed_nodes),
		  g_list_length(rsc->rsc_cons),
		  g_list_length(native_data->node_cons));
	
	if(details) {
		crm_debug_4("\t=== Actions");
		slist_iter(
			action, action_t, rsc->actions, lpc, 
			print_action("\trsc action: ", action, FALSE);
			);
		
		crm_debug_4("\t=== Colors");
		slist_iter(
			color, color_t, rsc->candidate_colors, lpc,
			print_color("\t", color, FALSE)
			);

		crm_debug_4("\t=== Allowed Nodes");
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
	
	crm_debug_4("Freeing Allowed Nodes & Agent");
	crm_free(native_data->color);
	pe_free_shallow(native_data->allowed_nodes);
	crm_free(native_data->agent);
	common_free(rsc);
}


void native_rsc_colocation_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh)
{
	native_variant_data_t *native_data_lh = NULL;
	native_variant_data_t *native_data_rh = NULL;

	gboolean do_merge = FALSE;
	GListPtr old_list = NULL;
	GListPtr merged_node_list = NULL;
	float max_pri = rsc_lh->effective_priority;
	if(max_pri < rsc_rh->effective_priority) {
		max_pri = rsc_rh->effective_priority;
	}
	rsc_lh->effective_priority = max_pri;
	rsc_rh->effective_priority = max_pri;
	
	get_native_variant_data(native_data_lh, rsc_lh);
	get_native_variant_data(native_data_rh, rsc_rh);

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
		
	if(update_lh && rsc_rh != rsc_lh) {
		CRM_DEV_ASSERT(native_data_lh->color != native_data_rh->color);
		crm_free(native_data_lh->color);
		rsc_lh->runnable      = rsc_rh->runnable;
		rsc_lh->provisional   = rsc_rh->provisional;
		native_data_lh->color = copy_color(native_data_rh->color);
	}
	if(update_rh && rsc_rh != rsc_lh) {
		CRM_DEV_ASSERT(native_data_lh->color != native_data_rh->color);
		crm_free(native_data_rh->color);
		rsc_rh->runnable      = rsc_lh->runnable;
		rsc_rh->provisional   = rsc_lh->provisional;
		native_data_rh->color = copy_color(native_data_lh->color);
	}

	if((update_rh || update_lh) && do_merge) {
		crm_debug_4("Merging candidate nodes");
		old_list = native_data_rh->color->details->candidate_nodes;
		native_data_rh->color->details->candidate_nodes = merged_node_list;
		pe_free_shallow(old_list);
	}
		
	crm_debug_4("Finished processing pecs_must constraint");
}

void native_rsc_colocation_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh)
{
	color_t *color_lh = NULL;
	color_t *color_rh = NULL;

	native_variant_data_t *native_data_lh = NULL;
	native_variant_data_t *native_data_rh = NULL;

	get_native_variant_data(native_data_lh, rsc_lh);
	get_native_variant_data(native_data_rh, rsc_rh);
	
	crm_debug_4("Processing pecs_must_not constraint");
	/* pecs_must_not */
	if(update_lh) {
		color_rh = native_data_rh->color;

		if(rsc_lh->provisional) {
			color_lh = find_color(
				rsc_lh->candidate_colors, color_rh);

			rsc_lh->candidate_colors = g_list_remove(
				rsc_lh->candidate_colors, color_lh);
			
			crm_action_debug_3(
				print_color("Removed LH", color_lh, FALSE));
			
			crm_action_debug_3(
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
			
			crm_action_debug_3(
				print_node("Removed LH", node_lh, FALSE));

			crm_action_debug_3(
				print_color("Modified LH", color_lh, FALSE));
			
			crm_free(node_lh);
		} else {
			/* error, rsc marked as unrunnable above */
			pe_warn("lh else");
		}
	}
	
	if(update_rh) {
		color_lh = native_data_lh->color;
		if(rsc_rh->provisional) {
			color_rh = find_color(
				rsc_rh->candidate_colors, color_lh);

			rsc_rh->candidate_colors = g_list_remove(
				rsc_rh->candidate_colors, color_rh);
			
			crm_action_debug_3(
				print_color("Removed RH", color_rh, FALSE));

			crm_action_debug_3(
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
			
			crm_action_debug_3(
				print_node("Removed RH", node_rh, FALSE));

			crm_action_debug_3(
				print_color("Modified RH", color_rh, FALSE));

			crm_free(node_rh);

		} else {
			/* error, rsc marked as unrunnable above */
			pe_warn("rh else");
		}
	}
}


void
native_agent_constraints(resource_t *rsc)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	crm_debug_5("Applying RA restrictions to %s", rsc->id);
	common_agent_constraints(
		native_data->allowed_nodes, native_data->agent, rsc->id);
}
gboolean
native_choose_color(resource_t *rsc, color_t *no_color)
{
	GListPtr sorted_colors = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	
	if(rsc->runnable == FALSE) {
		native_assign_color(rsc, no_color);
	}

	if(rsc->provisional == FALSE) {
		return !rsc->provisional;
	}
	
	sorted_colors = g_list_sort(
		rsc->candidate_colors, sort_color_weight);
	
	rsc->candidate_colors = sorted_colors;
	
	crm_debug_3("Choose a color from %d possibilities",
		    g_list_length(sorted_colors));
	
	slist_iter(
		this_color, color_t, rsc->candidate_colors, lpc,
		GListPtr intersection = NULL;
		GListPtr minus = NULL;
		int len = 0;

		if(this_color == NULL) {
			pe_err("color was NULL");
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


void
native_assign_color(resource_t *rsc, color_t *color) 
{
	color_t *local_color = add_color(rsc, color);
	GListPtr intersection = NULL;
	GListPtr old_list = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	native_data->color = copy_color(local_color);
	rsc->provisional = FALSE;

	if(local_color != NULL) {
		(local_color->details->num_resources)++;
		local_color->details->allocated_resources =
			g_list_append(
				local_color->details->allocated_resources,rsc);

			intersection = node_list_and(
				local_color->details->candidate_nodes, 
				native_data->allowed_nodes, TRUE);
			   
			old_list = local_color->details->candidate_nodes;
				
			pe_free_shallow(old_list);
			
			local_color->details->candidate_nodes = intersection;
				
			crm_debug_3("Colored resource %s with new color %d",
				    rsc->id, native_data->color->id);
			
			crm_action_debug_3(
				print_resource("Colored Resource", rsc, TRUE));
			
	} else {
		pe_err("local color was NULL");
	}
	
	return;
}

void
native_update_node_weight(resource_t *rsc, rsc_to_node_t *cons,
			  const char *id, GListPtr nodes)
{
	node_t *node_rh = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	node_rh = pe_find_node(native_data->allowed_nodes, id);

	if(node_rh == NULL) {
		pe_err("Node not found - cant update");
		return;
	}

	if(node_rh->weight >= INFINITY && cons->weight == -INFINITY) {
		pe_err("Constraint %s mixes +/- INFINITY", cons->id);
		
	} else if(node_rh->weight <= -INFINITY && cons->weight == INFINITY) {
		pe_err("Constraint %s mixes +/- INFINITY", cons->id);
	}

	if(node_rh->fixed) {
		/* warning */
		crm_debug_2("Constraint %s is irrelevant as the"
			 " weight of node %s is fixed as %f.",
			 cons->id,
			 node_rh->details->uname,
			 node_rh->weight);
		return;
	}

	if(cons->weight != INFINITY && cons->weight != -INFINITY) {
		crm_debug_3("Constraint %s (%f): node %s weight %f.",
			    cons->id,
			    cons->weight,
			    node_rh->details->uname,
			    node_rh->weight);
	} else if(cons->weight == -INFINITY) {
		crm_debug_3("Constraint %s (-INFINITY): node %s weight %f.",
			    cons->id,
			    node_rh->details->uname,
			    node_rh->weight);
	} else {
		crm_debug_3("Constraint %s (+INFINITY): node %s weight %f.",
			    cons->id,
			    node_rh->details->uname,
			    node_rh->weight);
	}
	
	
	node_rh->weight = merge_weights(node_rh->weight, cons->weight);

	if(node_rh->weight < 0) {
		node_rh->fixed = TRUE;
	}

	crm_action_debug_3(print_node("Updated", node_rh, FALSE));

	return;
}

gboolean
native_constraint_violated(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	native_variant_data_t *native_data_lh = NULL;
	native_variant_data_t *native_data_rh = NULL;

	GListPtr result = NULL;
	color_t *color_lh = NULL;
	color_t *color_rh = NULL;

	GListPtr candidate_nodes_lh = NULL;
	GListPtr candidate_nodes_rh = NULL;

	gboolean matched = FALSE;

	get_native_variant_data(native_data_lh, rsc_lh);
	get_native_variant_data(native_data_rh, rsc_rh);

	color_lh = native_data_lh->color;
	color_rh = native_data_rh->color;

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
void
filter_nodes(resource_t *rsc)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	crm_action_debug_3(print_resource("Filtering nodes for", rsc, FALSE));
	slist_iter(
		node, node_t, native_data->allowed_nodes, lpc,
		if(node == NULL) {
			pe_err("Invalid NULL node");
			
		} else if(node->weight < 0.0
			  || node->details->shutdown
			  || node->details->online == FALSE
			  || node->details->type == node_ping) {
			crm_action_debug_3(print_node("Removing", node, FALSE));
			native_data->allowed_nodes =
				g_list_remove(native_data->allowed_nodes, node);
			crm_free(node);
			lpc = -1; /* restart the loop */
		}
		);
}

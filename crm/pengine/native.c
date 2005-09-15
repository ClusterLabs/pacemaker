/* $Id: native.c,v 1.81 2005/09/15 17:13:08 andrew Exp $ */
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

void native_update_node_weight(resource_t *rsc, rsc_to_node_t *cons,
			       node_t *cons_node, GListPtr nodes);

void native_rsc_colocation_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh);

void native_rsc_colocation_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh);

void filter_nodes(resource_t *rsc);

int num_allowed_nodes4color(color_t *color);

void create_notifications(resource_t *rsc, pe_working_set_t *data_set);
void create_recurring_actions(resource_t *rsc, action_t *start, node_t *node,
			      pe_working_set_t *data_set);
void register_state(resource_t *rsc, action_t *op, notify_data_t *n_data);
void register_activity(resource_t *rsc, action_t *op, notify_data_t *n_data);
void pe_pre_notify(
	resource_t *rsc, node_t *node, action_t *op, 
	notify_data_t *n_data, pe_working_set_t *data_set);
void pe_post_notify(
	resource_t *rsc, node_t *node, action_t *op, 
	notify_data_t *n_data, pe_working_set_t *data_set);


extern rsc_to_node_t *
rsc2node_new(const char *id, resource_t *rsc,
	     double weight, node_t *node, pe_working_set_t *data_set);


void NoRoleChange(resource_t *rsc, node_t *current, node_t *next, pe_working_set_t *data_set);
gboolean StopRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean StartRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean DemoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean PromoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean RoleError(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean NullOp(resource_t *rsc, node_t *next, pe_working_set_t *data_set);

enum rsc_role_e rsc_state_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX] = {
/* Current State */	
/*    Next State:  Unknown 	    Stopped	      Started	        Slave	          Master */
/* Unknown */	{ RSC_ROLE_UNKNOWN, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, },
/* Stopped */	{ RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_SLAVE,   RSC_ROLE_SLAVE, },
/* Started */	{ RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_UNKNOWN, RSC_ROLE_UNKNOWN, },
/* Slave */	{ RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_UNKNOWN, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
/* Master */	{ RSC_ROLE_STOPPED, RSC_ROLE_SLAVE,   RSC_ROLE_UNKNOWN, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
};

gboolean (*rsc_action_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX])(resource_t*,node_t*,pe_working_set_t*) = {
/* Current State */	
/*    Next State: Unknown	Stopped		Started		Slave		Master */
/* Unknown */	{ RoleError,	StopRsc,	RoleError,	RoleError,	RoleError,  },
/* Stopped */	{ RoleError,	NullOp,		StartRsc,	StartRsc,	RoleError,  },
/* Started */	{ RoleError,	StopRsc,	NullOp,		RoleError,	RoleError,  },
/* Slave */	{ RoleError,	StopRsc,	RoleError,	NullOp,		PromoteRsc, },
/* Master */	{ RoleError,	RoleError,	RoleError,	DemoteRsc,	NullOp,     },
};


typedef struct native_variant_data_s
{
		GListPtr running_on;       /* node_t*   */
		GListPtr allowed_nodes;    /* node_t*   */

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

	} else if(rsc->stickiness > 0 || rsc->stickiness < 0) {
		rsc2node_new("stickiness", rsc, rsc->stickiness, node,data_set);
		crm_info("Resource %s: preferring current location (%s/%s)",
			 rsc->id, node->details->uname, node->details->id);
	}
	
	if(g_list_length(native_data->running_on) > 1) {
		pe_warn("Resource %s is (potentially) active on %d nodes."
			 "  Latest: %s/%s", rsc->id,
			 g_list_length(native_data->running_on),
			 node->details->uname, node->details->id);

		if(rsc->recovery_type == recovery_stop_only) {
			native_assign_color(rsc, data_set->no_color);
			
		} else if(rsc->recovery_type == recovery_block) {
			rsc->is_managed = FALSE;
		}
	}
}


void native_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;

	crm_debug_3("Processing resource %s...", rsc->id);

	crm_malloc0(native_data, sizeof(native_variant_data_t));

	native_data->allowed_nodes	= NULL;
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
	get_native_variant_data(native_data, rsc);

	if(rsc->color) {
		crm_debug_4("Colored case");
		num_nodes = num_allowed_nodes4color(rsc->color);
		
	} else if(rsc->candidate_colors) {
		/* TODO: sort colors first */
		color_t *color = g_list_nth_data(rsc->candidate_colors, 0);
		crm_debug_4("Candidate colors case");
		num_nodes = num_allowed_nodes4color(color);

	} else {
		crm_debug_4("Default case");
		slist_iter(
			this_node, node_t, native_data->allowed_nodes, lpc,
			crm_debug_3("Rsc %s Checking %s: %d",
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
		crm_debug_3("Checking %s: %d",
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


color_t *
native_color(resource_t *rsc, pe_working_set_t *data_set)
{
	color_t *new_color = NULL;
	native_variant_data_t *native_data = NULL;

	get_native_variant_data(native_data, rsc);

	if(rsc->provisional == FALSE) {
		return rsc->color;
		
	} else if( native_choose_color(rsc, data_set->no_color) ) {
		crm_debug_3("Colored resource %s with color %d",
			    rsc->id, rsc->color->id);
		new_color = rsc->color;
		
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
			new_color = data_set->no_color;
		}
	}
	rsc->provisional = FALSE;
	return new_color;
}

void
create_recurring_actions(resource_t *rsc, action_t *start, node_t *node,
			 pe_working_set_t *data_set) 
{
	char *key = NULL;
	const char *name = NULL;
	const char *value = NULL;
	const char *node_uname = NULL;

	int interval_ms = 0;
	action_t *mon = NULL;
	gboolean is_optional = TRUE;
	GListPtr possible_matches = NULL;
	
	crm_debug_2("Creating recurring actions for %s", rsc->id);
	if(node != NULL) {
		node_uname = node->details->uname;
	}
	
	xml_child_iter(
		rsc->ops_xml, operation, "op",

		name = crm_element_value(operation, "name");
		value = crm_element_value(operation, "interval");
		interval_ms = crm_get_msec(value);

		if(interval_ms <= 0) {
			continue;
		}

		value = crm_element_value(operation, "role");
		if(start != NULL && value != NULL
		   && text2role(value) != start->rsc->next_role) {
			crm_debug_2("Skipping action %s::%s(%s) : %s",
				    start->rsc->id, name, value,
				    role2text(start->rsc->next_role));
			continue;
		}
		
		
		key = generate_op_key(rsc->id, name, interval_ms);
		possible_matches = find_actions(rsc->actions, key, node);
		if(start != NULL) {
			is_optional = start->optional;
		} else {
			is_optional = TRUE;
		}

		/* start a monitor for an already active resource */
		if(possible_matches == NULL) {
			is_optional = FALSE;
		}
		
		mon = custom_action(rsc, key, name, node,
				    is_optional, TRUE, data_set);
		
		if(start == NULL || start->runnable == FALSE) {
			crm_warn("   %s:\t(%s) (cancelled : start un-runnable)",
				 mon->uuid, crm_str(node_uname));
			mon->runnable = FALSE;

		} else if(node == NULL
			  || node->details->online == FALSE
			  || node->details->unclean) {
			crm_warn("   %s:\t(%s) (cancelled : no node available)",
				 mon->uuid, crm_str(node_uname));
			mon->runnable = FALSE;
		
		} else if(mon->optional == FALSE) {
			crm_info("   %s:\t(%s)", mon->uuid, crm_str(node_uname));
		}
		custom_action_order(rsc, start_key(rsc), NULL,
				    NULL, crm_strdup(key), mon,
				    pe_ordering_manditory, data_set);
		);	
}

void native_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *start = NULL;
	node_t *chosen = NULL;
	enum rsc_role_e role = RSC_ROLE_UNKNOWN;
	enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	if(rsc->color != NULL) {
		chosen = rsc->color->details->chosen_node;
	}

	unpack_instance_attributes(
		rsc->xml, XML_TAG_ATTR_SETS, chosen, rsc->parameters,
		NULL, 0, data_set);
	
	if(g_list_length(native_data->running_on) > 1) {
 		if(rsc->recovery_type == recovery_stop_start) {
			pe_err("Attempting recovery of resource %s", rsc->id);
			StopRsc(rsc, NULL, data_set);
			rsc->role = RSC_ROLE_STOPPED;
		}
		
	} else if(native_data->running_on != NULL) {
		node_t *current = native_data->running_on->data;
		NoRoleChange(rsc, current, chosen, data_set);

	} else if(rsc->role == RSC_ROLE_STOPPED && rsc->next_role == RSC_ROLE_STOPPED) {
		char *key = start_key(rsc);
		GListPtr possible_matches = find_actions(rsc->actions, key, NULL);
		slist_iter(
			action, action_t, possible_matches, lpc,
			action->optional = TRUE;
/*			action->pseudo = TRUE; */
			);
		crm_debug_2("Stopping a stopped resource");
		crm_free(key);
		return;
	} 

	role = rsc->role;
	crm_info("%s: %s->%s", rsc->id,
		  role2text(rsc->role), role2text(rsc->next_role));

	while(role != rsc->next_role) {
		next_role = rsc_state_matrix[role][rsc->next_role];
		crm_debug("Executing: %s->%s (%s)",
			  role2text(role), role2text(next_role), rsc->id);
		if(rsc_action_matrix[role][next_role](
			   rsc, chosen, data_set) == FALSE) {
			break;
		}
		role = next_role;
	}

	if(rsc->next_role != RSC_ROLE_STOPPED && rsc->is_managed) {
		start = start_action(rsc, chosen, TRUE);
		create_recurring_actions(rsc, start, chosen, data_set);
	}
}

void native_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	order_restart(rsc);
}

void native_rsc_colocation_lh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	if(rsc_lh == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
	}
	
	crm_debug_2("Processing colocation constraint between %s and %s",
		    rsc_lh->id, rsc_rh->id);
	
	rsc_rh->fns->rsc_colocation_rh(rsc_lh, rsc_rh, constraint);		
}

static gboolean
filter_colocation_constraint(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	if(constraint->strength == pecs_ignore
		|| constraint->strength == pecs_startstop){
		crm_debug_4("Skipping constraint type %d", constraint->strength);
		return FALSE;
	}

	if(constraint->state_lh != NULL
	   && text2role(constraint->state_lh) != rsc_lh->next_role) {
		crm_debug_4("RH: Skipping constraint: \"%s\" state filter",
			    constraint->state_rh);
		return FALSE;
	}
	
	if(constraint->state_rh != NULL
	   && text2role(constraint->state_rh) != rsc_rh->next_role) {
		crm_debug_4("RH: Skipping constraint: \"%s\" state filter",
			    constraint->state_rh);
		return FALSE;
	}
	return TRUE;
}

void native_rsc_colocation_rh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	gboolean do_check = FALSE;
	gboolean update_lh = FALSE;
	gboolean update_rh = FALSE;
	
	native_variant_data_t *native_data_lh = NULL;
	native_variant_data_t *native_data_rh = NULL;

	get_native_variant_data(native_data_lh, rsc_lh);
	get_native_variant_data(native_data_rh, rsc_rh);
	
	crm_debug_2("%sColocating %s with %s (%s)",
		    constraint->strength == pecs_must?"":"Anti-",
		    rsc_lh->id, rsc_rh->id, constraint->id);
	
	if(filter_colocation_constraint(rsc_lh, rsc_rh, constraint) == FALSE) {
		return;
	}
	
	if(rsc_lh->provisional && rsc_rh->provisional) {
		if(constraint->strength == pecs_must) {
			/* update effective_priorities */
			crm_debug_3("Priority update");
			native_rsc_colocation_rh_must(
				rsc_lh, update_lh, rsc_rh, update_rh);
		} else {
			/* nothing */
			crm_debug_4(
				"Skipping constraint, both sides provisional");
		}
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
		/* update _them_    : postproc color version */
		update_rh = TRUE;
		
	} else if(rsc_rh->provisional == FALSE
		  && rsc_rh->color->details->pending == FALSE) {
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

	crm_debug("Applying %s (%s) to %s", constraint->id,
		  role2text(constraint->role_filter), rsc->id);

	/* take "lifetime" into account */
	if(constraint == NULL) {
		pe_err("Constraint is NULL");
		return;

	} else if(rsc == NULL) {
		pe_err("LHS of rsc_to_node (%s) is NULL", constraint->id);
		return;

	} else if(constraint->role_filter > 0
		  && constraint->role_filter != rsc->next_role) {
		crm_debug("Constraint (%s) is not active (role : %s)",
			    constraint->id, role2text(constraint->role_filter));
		return;
		
	} else if(is_active(constraint) == FALSE) {
		crm_debug_2("Constraint (%s) is not active", constraint->id);
		return;
	}
    
	get_native_variant_data(native_data, rsc);

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
		   native_update_node_weight(rsc, constraint, node_rh,
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

gboolean native_active(resource_t *rsc, gboolean all)
{	
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	slist_iter(
		a_node, node_t, native_data->running_on, lpc,

		if(a_node->details->online == FALSE) {
			crm_debug("Resource %s: node %s is offline",
				  rsc->id, a_node->details->uname);
		} else if(a_node->details->unclean) {
			crm_debug("Resource %s: node %s is unclean",
				  rsc->id, a_node->details->uname);
		} else {
			crm_debug("Resource %s active on %s",
				  rsc->id, a_node->details->uname);
			return TRUE;
		}
		);
	
	return FALSE;
}


void native_printw(resource_t *rsc, const char *pre_text, int *index)
{
#if CURSES_ENABLED
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	common_printw(rsc, pre_text, index);
	if(rsc->is_managed == FALSE) {
		printw(" (unmanaged) ");
	}
	if(g_list_length(native_data->running_on) == 0) {
		printw("NOT ACTIVE");
		
	} else if(g_list_length(native_data->running_on) == 1) {
		node_t *node = native_data->running_on->data;
		printw("%s (%s)", node->details->uname, node->details->id);
		if(rsc->state == rsc_state_failed) {
			printw(" FAILED");
		}
		
	} else if(g_list_length(native_data->running_on) == 1) {
		printw("[");
		slist_iter(node, node_t, native_data->running_on, lpc,
			   if(lpc > 0) { printw(", "); }
			   printw("%s (%s)", node->details->uname, node->details->id);
			);
		printw("]");
	}
	printw("\n");
#else
	crm_err("printw support requires ncurses to be available during configure");
#endif
}

void native_html(resource_t *rsc, const char *pre_text, FILE *stream)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	if(rsc->is_managed == FALSE) {
		fprintf(stream, "<font color=\"orange\">");
	}
	common_html(rsc, pre_text, stream);
	if(rsc->is_managed == FALSE) {
		fprintf(stream, " (unmanaged)</font> ");
	}
	
	if(rsc->state == rsc_state_failed) {
		fprintf(stream, "<font color=\"orange\">");
	} else if(g_list_length(native_data->running_on) == 0) {
		fprintf(stream, "<font color=\"red\">");
	} else if(g_list_length(native_data->running_on) > 1) {
		fprintf(stream, "<font color=\"orange\">");
	} else {
		fprintf(stream, "<font color=\"green\">");
	}	
	
	if(g_list_length(native_data->running_on) == 0) {
		fprintf(stream, "<b>NOT ACTIVE</b>");
		
	} else if(g_list_length(native_data->running_on) == 1) {
		node_t *node = native_data->running_on->data;
		fprintf(stream, "%s (%s)",
			node->details->uname, node->details->id);
		
	} else if(g_list_length(native_data->running_on) > 1) {
		fprintf(stream, "<ul>\n");
		slist_iter(node, node_t, native_data->running_on, lpc,
			   fprintf(stream, "<li><b>%s (%s)</b></li>\n",
				   node->details->uname, node->details->id);
			);
		fprintf(stream, "</ul>\n");
	}
	fprintf(stream, "</font><br/>\n");
}

void native_dump(resource_t *rsc, const char *pre_text, gboolean details)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	common_dump(rsc, pre_text, details);
	crm_debug_4("\t%d candidate colors, %d allowed nodes,"
		  " %d rsc_cons",
		  g_list_length(rsc->candidate_colors),
		  g_list_length(native_data->allowed_nodes),
		  g_list_length(rsc->rsc_cons));
	
	if(details) {
		crm_debug_4("\t=== Actions");
		slist_iter(
			action, action_t, rsc->actions, lpc, 
			log_action(LOG_DEBUG_4, "\trsc action: ", action, FALSE);
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
	
	crm_debug_4("Freeing Allowed Nodes");
	crm_free(rsc->color);
	pe_free_shallow(native_data->allowed_nodes);
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
	int max_pri = rsc_lh->effective_priority;
	if(max_pri < rsc_rh->effective_priority) {
		max_pri = rsc_rh->effective_priority;
	}
	rsc_lh->effective_priority = max_pri;
	rsc_rh->effective_priority = max_pri;
	
	get_native_variant_data(native_data_lh, rsc_lh);
	get_native_variant_data(native_data_rh, rsc_rh);

	crm_debug_2("Colocating %s with %s."
		    " Update LHS: %s, Update RHS: %s",
		    rsc_lh->id, rsc_rh->id,
		    update_lh?"true":"false", update_rh?"true":"false");

	
	if(rsc_lh->color && rsc_rh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			rsc_lh->color->details->candidate_nodes,
			rsc_rh->color->details->candidate_nodes, TRUE);
			
	} else if(rsc_lh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			rsc_lh->color->details->candidate_nodes,
			native_data_rh->allowed_nodes, TRUE);

	} else if(rsc_rh->color) {
		do_merge = TRUE;
		merged_node_list = node_list_and(
			native_data_lh->allowed_nodes,
			rsc_rh->color->details->candidate_nodes, TRUE);
	}
		
	if(update_lh && rsc_rh != rsc_lh) {
		CRM_DEV_ASSERT(rsc_lh->color != rsc_rh->color);
		crm_free(rsc_lh->color);
		rsc_lh->runnable      = rsc_rh->runnable;
		rsc_lh->provisional   = rsc_rh->provisional;

		CRM_DEV_ASSERT(rsc_rh->color != NULL);
		native_assign_color(rsc_lh, rsc_rh->color);
	}
	if(update_rh && rsc_rh != rsc_lh) {
		CRM_DEV_ASSERT(rsc_lh->color != rsc_rh->color);
		crm_free(rsc_rh->color);
		rsc_rh->runnable      = rsc_lh->runnable;
		rsc_rh->provisional   = rsc_lh->provisional;

		CRM_DEV_ASSERT(rsc_lh->color != NULL);
		native_assign_color(rsc_rh, rsc_lh->color);
	}

	if((update_rh || update_lh) && do_merge) {
		crm_debug_4("Merging candidate nodes");
		old_list = rsc_rh->color->details->candidate_nodes;
		rsc_rh->color->details->candidate_nodes = merged_node_list;
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
		color_rh = rsc_rh->color;

		if(rsc_lh->provisional && color_rh != NULL) {
			color_lh = add_color(rsc_lh, color_rh);
			color_lh->local_weight = -INFINITY;
			crm_debug_2("LH: Removed color %d from resource %s",
				color_lh->id, rsc_lh->id);
			
			crm_action_debug_3(
				print_color("Removed LH", color_lh, FALSE));
			
			crm_action_debug_3(
				print_resource("Modified LH", rsc_lh, TRUE));

		} else if(rsc_lh->provisional) {
			
		} else if(rsc_lh->color
			  && rsc_lh->color->details->pending) {
			node_t *node_lh = NULL;
			
			color_lh = rsc_lh->color;
			node_lh = pe_find_node_id(
				color_lh->details->candidate_nodes,
				safe_val5(NULL, color_rh, details,
					  chosen_node, details, id));

			if(node_lh != NULL) {
				node_lh->weight = -INFINITY;

				crm_debug_2("LH: Removed node %s from color %d",
					node_lh->details->uname, color_lh->id);
				
				crm_action_debug_3(
					print_node("Removed LH", node_lh, FALSE));
				
				crm_action_debug_3(
					print_color("Modified LH", color_lh, FALSE));
			}
			
		} else {
			/* error, rsc marked as unrunnable above */
			pe_warn("lh else");
		}
	}
	
	if(update_rh) {
		color_lh = rsc_lh->color;
		if(rsc_rh->provisional && color_lh != NULL) {
			color_rh = add_color(rsc_lh, color_lh);
			color_rh->local_weight = -INFINITY;
			crm_debug_2("RH: Removed color %d from resource %s",
				color_rh->id, rsc_rh->id);
			
			crm_action_debug_3(
				print_color("Removed RH", color_rh, FALSE));

			crm_action_debug_3(
				print_resource("Modified RH", rsc_rh, TRUE));

		} else if(rsc_rh->provisional) {
			
		} else if(rsc_rh->color
			  && rsc_rh->color->details->pending) {
			node_t *node_rh = NULL;
			color_rh = rsc_rh->color;
			node_rh = pe_find_node_id(
				color_rh->details->candidate_nodes,
				safe_val5(NULL, color_lh, details,
					  chosen_node, details, id));

			if(node_rh != NULL) {
				node_rh->weight = -INFINITY;
				
				crm_debug_2("RH: Removed node %s from color %d",
					node_rh->details->uname, color_rh->id);
				
				crm_action_debug_3(
					print_node("Removed RH", node_rh, FALSE));
				
				crm_action_debug_3(
					print_color("Modified RH", color_rh, FALSE));
			}

		} else {
			/* error, rsc marked as unrunnable above */
			pe_warn("rh else");
		}
	}
}


void
native_agent_constraints(resource_t *rsc)
{
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
	
	crm_debug("Choose a color from %d possibilities",
		    g_list_length(sorted_colors));
	
	slist_iter(
		this_color, color_t, rsc->candidate_colors, lpc,
		GListPtr intersection = NULL;
		GListPtr minus = NULL;
		int len = 0;

		if(this_color == NULL) {
			pe_err("color was NULL");
			continue;
			
		} else if(this_color->local_weight < 0) {
			/* no valid color available */
			crm_debug("no valid color available");
			break;
			
		} else if(rsc->effective_priority
		   < this_color->details->highest_priority) {

			minus = node_list_minus(
				this_color->details->candidate_nodes, 
				native_data->allowed_nodes, TRUE);

			len = g_list_length(minus);
			pe_free_shallow(minus);
			
		} else {
			intersection = node_list_and(
				this_color->details->candidate_nodes, 
				native_data->allowed_nodes, TRUE);

			len = g_list_length(intersection);
			pe_free_shallow(intersection);
			
		}
		if(len > 0) {
			crm_debug("Assigning color to %s", rsc->id);
			native_assign_color(rsc, this_color);
			break;
		}
		);

	return !rsc->provisional;
}


void
native_assign_color(resource_t *rsc, color_t *color) 
{
	native_variant_data_t *native_data = NULL;
	color_t *local_color = add_color(rsc, color);
	GListPtr intersection = NULL;
	GListPtr old_list = NULL;

	rsc->provisional = FALSE;
	
	CRM_DEV_ASSERT(local_color != NULL);
	if (crm_assert_failed) {
		pe_err("local color was NULL");
		return;
	}

	local_color->details->allocated_resources =
		g_list_append(local_color->details->allocated_resources,rsc);

	if(rsc->variant == pe_native) {
		(local_color->details->num_resources)++;
		get_native_variant_data(native_data, rsc);
		rsc->color = copy_color(local_color);
		crm_debug_3("Created intersection for color %d",
			    local_color->id);
		intersection = node_list_and(
			local_color->details->candidate_nodes, 
			native_data->allowed_nodes, FALSE);
		old_list = local_color->details->candidate_nodes;
		
		pe_free_shallow(old_list);
		
		local_color->details->candidate_nodes = intersection;
	}
	
	crm_debug("Colored resource %s with color %d",
		    rsc->id, local_color->id);
	
	crm_action_debug_3(
		print_resource("Colored Resource", rsc, TRUE));
	
	return;
}

void
native_update_node_weight(resource_t *rsc, rsc_to_node_t *cons,
			  node_t *cons_node, GListPtr nodes)
{
	node_t *node_rh = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	CRM_DEV_ASSERT(cons_node != NULL);
	
	node_rh = pe_find_node_id(
		native_data->allowed_nodes, cons_node->details->id);

	if(node_rh == NULL) {
		pe_err("Node not found - adding %s to %s",
		       cons_node->details->id, rsc->id);
		node_rh = node_copy(cons_node);
		native_data->allowed_nodes = g_list_append(
			native_data->allowed_nodes, node_rh);

		node_rh = pe_find_node_id(
			native_data->allowed_nodes, cons_node->details->id);

		CRM_DEV_ASSERT(node_rh != NULL);
		return;
	}

	CRM_DEV_ASSERT(node_rh != NULL);
	
	if(node_rh == NULL) {
		pe_err("Node not found - cant update");
		return;
	}

	if(node_rh->weight >= INFINITY && cons_node->weight <= -INFINITY) {
		pe_err("Constraint \"%s\" mixes +/- INFINITY (%s)",
		       cons->id, rsc->id);
		
	} else if(node_rh->details->shutdown == TRUE
		  || node_rh->details->online == FALSE
		  || node_rh->details->unclean == TRUE) {

	} else if(node_rh->weight <= -INFINITY && cons_node->weight >= INFINITY) {
		pe_err("Constraint \"%s\" mixes +/- INFINITY (%s)",
			 cons->id, rsc->id);
	}

	if(node_rh->fixed) {
		/* warning */
		crm_debug_2("Constraint %s is irrelevant as the"
			 " weight of node %s is fixed as %d (%s).",
			 cons->id, node_rh->details->uname,
			 node_rh->weight, rsc->id);
		return;
	}	
	
	node_rh->weight = merge_weights(node_rh->weight, cons_node->weight);
	if(node_rh->weight <= -INFINITY) {
		crm_debug_3("Constraint %s (-INFINITY): node %s weight %d (%s).",
			    cons->id, node_rh->details->uname,
			    node_rh->weight, rsc->id);
		
	} else if(node_rh->weight >= INFINITY) {
		crm_debug_3("Constraint %s (+INFINITY): node %s weight %d (%s).",
			    cons->id, node_rh->details->uname,
			    node_rh->weight, rsc->id);

	} else {
		crm_debug_3("Constraint %s (%d): node %s weight %d (%s).",
			    cons->id, cons_node->weight, node_rh->details->uname,
			    node_rh->weight, rsc->id);
	}

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

	color_lh = rsc_lh->color;
	color_rh = rsc_rh->color;

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


rsc_state_t
native_resource_state(resource_t *rsc)
{
	enum action_tasks task = no_action;
	rsc_state_t state = rsc_unknown;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	
	slist_iter(
		action, action_t, rsc->actions, lpc,
		crm_debug_4("processing action %d for rsc=%s",
			  action->id, rsc->id);
		task = text2task(action->task);

		if(action->optional) {
			continue;
		}

		if(task == stop_rsc) {
			if(state == rsc_starting) {
				state = rsc_restart;
				break;
			} else {
				state = rsc_stopping;
			}
		} else if(task == start_rsc) {
			if(state == rsc_stopping) {
				state = rsc_restart;
				break;
			} else {
				state = rsc_starting;
			}
		}
		);

	if(native_data->running_on != NULL) {
		node_t *chosen = NULL;
		node_t *node = native_data->running_on->data;

		if(rsc->color != NULL) {
			chosen = rsc->color->details->chosen_node;
		}
		if(state == rsc_unknown) {
			state = rsc_active;

		} else if(state == rsc_restart) {
			CRM_DEV_ASSERT(chosen != NULL && node != NULL);
			if(crm_assert_failed) {
				crm_err("State for %s is unreliable", rsc->id);
				
			} else if(safe_str_neq(node->details->id,
					chosen->details->id)) {
				state = rsc_move;
			}
		}
		
	} else if(state == rsc_unknown) {
		state = rsc_stopped;
	}
	
	return state;
}

void
create_notifications(resource_t *rsc, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	if(rsc->notify == FALSE) {
		return;
	}
	
/* 	slist_iter( */
/* 		action, action_t, rsc->actions, lpc, */
		
/* 		); */

}



void
native_create_notify_element(resource_t *rsc, action_t *op,
			     notify_data_t *n_data, pe_working_set_t *data_set)
{
	node_t *next = NULL;
	node_t *current = NULL;

	enum action_tasks task;
	rsc_state_t state = rsc->fns->state(rsc);

	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	if(rsc->color != NULL) {
		next = rsc->color->details->chosen_node;
	}
	if(native_data->running_on != NULL) {
		current = native_data->running_on->data;
	}

	if(op->pre_notify == NULL || op->post_notify == NULL) {
		/* no notifications required */
		crm_debug_4("No notificaitons required for %s", op->task);
		return;
	}

	crm_debug_2("Notificaitons required for %s", op->task);
	
	task = text2task(op->task);
	
	switch(state) {
		case rsc_active:
			pe_pre_notify(rsc, current, op, n_data, data_set);
			pe_post_notify(rsc, current, op, n_data, data_set);
			register_state(rsc, op, n_data);
			break;
		case rsc_move:
			if(task == stop_rsc) {
				pe_pre_notify(rsc, current, op,n_data,data_set);
				register_activity(rsc, op, n_data);
			} else {
				pe_post_notify(rsc, next, op, n_data, data_set);
				register_activity(rsc, op, n_data);
			}
			break;
		case rsc_restart:
			register_activity(rsc, op, n_data);
			if(task == stop_rsc) {
				pe_pre_notify(rsc, current, op, n_data, data_set);
			} else {
				pe_post_notify(rsc, current,op,n_data,data_set);
			}
			break;
		case rsc_starting:
			if(task != stop_rsc) {
				register_activity(rsc, op, n_data);
				pe_post_notify(rsc, next, op, n_data, data_set);
			}
			break;
		case rsc_stopping:
			if(task == stop_rsc) {
				register_activity(rsc, op, n_data);
				pe_pre_notify(rsc, current, op,n_data,data_set);
			}
			break;
		case rsc_stopped:
		case rsc_unknown:
			return;
			break;
	}
}


void
register_activity(resource_t *rsc, action_t *op, notify_data_t *n_data)
{
	notify_entry_t *entry = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	
	if(safe_str_eq(op->task, CRMD_ACTION_START)) {
		crm_malloc0(entry, sizeof(notify_entry_t));
		entry->rsc = rsc;
		if(rsc->color != NULL) {
			entry->node = rsc->color->details->chosen_node;
		}
		n_data->start = g_list_append(n_data->start, entry);
		
	} else {
		slist_iter(
			node, node_t, native_data->running_on, lpc,

			crm_malloc0(entry, sizeof(notify_entry_t));
			entry->rsc = rsc;
			entry->node = node;
			n_data->stop=g_list_append(n_data->stop, entry);
			);
	}
}

void
register_state(resource_t *rsc, action_t *op, notify_data_t *n_data)
{
	notify_entry_t *entry = NULL;
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	crm_malloc0(entry, sizeof(notify_entry_t));
	entry->rsc = rsc;
	if(rsc->color != NULL) {
		entry->node = rsc->color->details->chosen_node;
	}

	if(entry->node != NULL) {
		n_data->active = g_list_append(n_data->active, entry);
	} else {
		n_data->inactive = g_list_append(n_data->inactive, entry);
	}
}


static void dup_attr(gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_replace(user_data, crm_strdup(key), crm_strdup(value));
}

static void
pe_notify(resource_t *rsc, node_t *node, action_t *op, action_t *confirm,
	  notify_data_t *n_data, pe_working_set_t *data_set)
{
	char *key = NULL;
	action_t *trigger = NULL;
	action_wrapper_t *wrapper = NULL;
	const char *value = NULL;
	const char *task = NULL;
	
	if(op == NULL || confirm == NULL) {
		return;
	}

	CRM_DEV_ASSERT(node != NULL);

	value = g_hash_table_lookup(op->extra, "notify_type");
	task = g_hash_table_lookup(op->extra, "notify_operation");

	crm_debug_2("Creating actions for %s: %s (%s-%s)",
		    op->uuid, rsc->id, value, task);
	
	key = generate_notify_key(rsc->id, value, task);
	trigger = custom_action(rsc, key, op->task, node,
				op->optional, TRUE, data_set);
	g_hash_table_foreach(op->extra, dup_attr, trigger->extra);
	trigger->notify_keys = n_data->keys;

	/* pseudo_notify before notify */
	crm_debug_3("Ordering %s before %s (%d->%d)",
		op->uuid, trigger->uuid, trigger->id, op->id);

	crm_malloc0(wrapper, sizeof(action_wrapper_t));
	wrapper->action = op;
	wrapper->type = pe_ordering_manditory;
	trigger->actions_before=g_list_append(trigger->actions_before, wrapper);

	wrapper = NULL;
	crm_malloc0(wrapper, sizeof(action_wrapper_t));
	wrapper->action = trigger;
	wrapper->type = pe_ordering_manditory;
	op->actions_after = g_list_append(op->actions_after, wrapper);


	
	value = g_hash_table_lookup(op->extra, "notify_confirm");
	if(crm_is_true(value)) {
		/* notify before pseudo_notified */
		crm_debug_3("Ordering %s before %s (%d->%d)",
			    trigger->uuid, confirm->uuid,
			    confirm->id, trigger->id);

		wrapper = NULL;
		crm_malloc0(wrapper, sizeof(action_wrapper_t));
		wrapper->action = trigger;
		wrapper->type = pe_ordering_manditory;
		confirm->actions_before = g_list_append(
			confirm->actions_before, wrapper);

		wrapper = NULL;
		crm_malloc0(wrapper, sizeof(action_wrapper_t));
		wrapper->action = confirm;
		wrapper->type = pe_ordering_manditory;
		trigger->actions_after = g_list_append(
			trigger->actions_after, wrapper);
	}	
}

void
pe_pre_notify(resource_t *rsc, node_t *node, action_t *op,
	      notify_data_t *n_data, pe_working_set_t *data_set)
{
	pe_notify(rsc, node, op->pre_notify, op->pre_notified,
		  n_data, data_set);
}

void
pe_post_notify(resource_t *rsc, node_t *node, action_t *op, 
	notify_data_t *n_data, pe_working_set_t *data_set)
{
	pe_notify(rsc, node, op->post_notify, op->post_notified,
		  n_data, data_set);
}


void
NoRoleChange(resource_t *rsc, node_t *current, node_t *next, pe_working_set_t *data_set)
{
	action_t *start = NULL;
	action_t *stop = NULL;
	action_t *delete = NULL;

	crm_debug("Executing: %s", rsc->id);

	if(current == NULL || next == NULL) {
		return;
	}

	if(safe_str_neq(current->details->id, next->details->id)) {
		crm_info("Move  resource %s\t(%s -> %s)", rsc->id,
			 current->details->uname,
			 next->details->uname);
		stop = stop_action(rsc, current, FALSE);
		start = start_action(rsc, next, FALSE);

		if(data_set->remove_on_stop) {
			delete = delete_action(rsc, current);
			custom_action_order(
				rsc, NULL, stop, rsc, NULL, delete,
				pe_ordering_manditory, data_set);
		}
		
	} else {
		if(rsc->state == rsc_state_failed) {
			crm_info("Recover resource %s\t(%s)",
				 rsc->id, next->details->uname);
			stop = stop_action(rsc, current, FALSE);
			start = start_action(rsc, next, FALSE);
/* 			/\* make the restart required *\/ */
/* 			order_stop_start(rsc, rsc, pe_ordering_manditory); */
			
		} else if(rsc->state == rsc_state_starting) {
			start = start_action(rsc, next, TRUE);
			if(start->runnable) {
				/* wait for StartRsc() to be called */
				rsc->role = RSC_ROLE_STOPPED;
			} else {
				/* wait for StopRsc() to be called */
				rsc->next_role = RSC_ROLE_STOPPED;
			}
			
		} else {
			crm_info("Leave resource %s\t(%s)",
				 rsc->id, next->details->uname);
			stop = stop_action(rsc, current, TRUE);
			start = start_action(rsc, next, TRUE);
			stop->optional = start->optional;
			if(start->runnable == FALSE) {
				rsc->next_role = RSC_ROLE_STOPPED;
			}
			
		}
	}
}


gboolean
StopRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	action_t *stop = NULL;
	action_t *delete = NULL;
	
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);

	crm_debug("Executing: %s", rsc->id);
	
	slist_iter(
		current, node_t, native_data->running_on, lpc,
		crm_info("Stop  resource %s\t(%s)",
			 rsc->id, current->details->uname);
		stop = stop_action(rsc, current, FALSE);

		if(data_set->remove_on_stop) {
			delete = delete_action(rsc, current);
			custom_action_order(
				rsc, NULL, stop, rsc, NULL, delete,
				pe_ordering_manditory, data_set);
		}
		);
	
	return TRUE;
}

gboolean
StartRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	action_t *start = NULL;
	
	crm_debug("Executing: %s", rsc->id);
	start = start_action(rsc, next, TRUE);
	if(start->runnable) {
		crm_info("Start resource %s\t(%s)",
			 rsc->id, next->details->uname);
		start->optional = FALSE;
	}		
	return TRUE;
}

gboolean
PromoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	crm_debug("Executing: %s", rsc->id);

	CRM_DEV_ASSERT(rsc->next_role == RSC_ROLE_MASTER);
	crm_info("Promote resource %s\t(%s)", rsc->id, next->details->uname);
	promote_action(rsc, next, FALSE);
	return TRUE;
}

gboolean
DemoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	native_variant_data_t *native_data = NULL;
	get_native_variant_data(native_data, rsc);
	crm_debug("Executing: %s", rsc->id);

	CRM_DEV_ASSERT(rsc->next_role == RSC_ROLE_SLAVE);
	slist_iter(
		current, node_t, native_data->running_on, lpc,
		crm_info("Demote resource %s\t(%s)",
			 rsc->id, current->details->uname);
		demote_action(rsc, current, FALSE);
		);
	return TRUE;
}

gboolean
RoleError(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	crm_debug("Executing: %s", rsc->id);
	CRM_DEV_ASSERT(FALSE);
	return FALSE;
}

gboolean
NullOp(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	crm_debug("Executing: %s", rsc->id);
	return FALSE;
}


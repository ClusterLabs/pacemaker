/* $Id: native.c,v 1.161 2006/08/17 07:17:15 andrew Exp $ */
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
#include <crm/pengine/rules.h>
#include <lib/crm/pengine/utils.h>
#include <crm/msg_xml.h>
#include <allocate.h>
#include <utils.h>

#define DELETE_THEN_REFRESH 1

void native_rsc_colocation_rh_must(resource_t *rsc_lh, gboolean update_lh,
				   resource_t *rsc_rh, gboolean update_rh);

void native_rsc_colocation_rh_mustnot(resource_t *rsc_lh, gboolean update_lh,
				      resource_t *rsc_rh, gboolean update_rh);

void filter_nodes(resource_t *rsc);

void create_notifications(resource_t *rsc, pe_working_set_t *data_set);
void Recurring(resource_t *rsc, action_t *start, node_t *node,
			      pe_working_set_t *data_set);
void pe_pre_notify(
	resource_t *rsc, node_t *node, action_t *op, 
	notify_data_t *n_data, pe_working_set_t *data_set);
void pe_post_notify(
	resource_t *rsc, node_t *node, action_t *op, 
	notify_data_t *n_data, pe_working_set_t *data_set);

gboolean DeleteRsc(resource_t *rsc, node_t *node, pe_working_set_t *data_set);
void NoRoleChange(resource_t *rsc, node_t *current, node_t *next, pe_working_set_t *data_set);
gboolean StopRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean StartRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
extern gboolean DemoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean PromoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean RoleError(resource_t *rsc, node_t *next, pe_working_set_t *data_set);
gboolean NullOp(resource_t *rsc, node_t *next, pe_working_set_t *data_set);

enum rsc_role_e rsc_state_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX] = {
/* Current State */	
/*    Next State:  Unknown 	    Stopped	      Started	        Slave	          Master */
/* Unknown */	{ RSC_ROLE_UNKNOWN, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, },
/* Stopped */	{ RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_SLAVE,   RSC_ROLE_SLAVE, },
/* Started */	{ RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_STARTED, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
/* Slave */	{ RSC_ROLE_STOPPED, RSC_ROLE_STOPPED, RSC_ROLE_UNKNOWN, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
/* Master */	{ RSC_ROLE_STOPPED, RSC_ROLE_SLAVE,   RSC_ROLE_UNKNOWN, RSC_ROLE_SLAVE,   RSC_ROLE_MASTER, },
};

gboolean (*rsc_action_matrix[RSC_ROLE_MAX][RSC_ROLE_MAX])(resource_t*,node_t*,pe_working_set_t*) = {
/* Current State */	
/*    Next State: Unknown	Stopped		Started		Slave		Master */
/* Unknown */	{ RoleError,	StopRsc,	RoleError,	RoleError,	RoleError,  },
/* Stopped */	{ RoleError,	NullOp,		StartRsc,	StartRsc,	RoleError,  },
/* Started */	{ RoleError,	StopRsc,	NullOp,		NullOp,	        PromoteRsc,  },
/* Slave */	{ RoleError,	StopRsc,	RoleError,	NullOp,		PromoteRsc, },
/* Master */	{ RoleError,	RoleError,	RoleError,	DemoteRsc,	NullOp,     },
};


typedef struct native_variant_data_s
{
/* 		GListPtr allowed_nodes;    /\* node_t*   *\/ */

} native_variant_data_t;

#define get_native_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_native);				\
	CRM_ASSERT(rsc->variant_opaque != NULL);			\
	data = (native_variant_data_t *)rsc->variant_opaque;


static gboolean
native_choose_node(resource_t *rsc)
{
	/*
	  1. Sort by weight
	  2. color.chosen_node = the node (of those with the highest wieght)
				   with the fewest resources
	  3. remove color.chosen_node from all other colors
	*/
	GListPtr nodes = NULL;
	node_t *chosen = NULL;
	int multiple = 0;

	crm_debug_3("Choosing node for %s from %d candidates",
		    rsc->id, g_list_length(rsc->allowed_nodes));
	if(rsc->allowed_nodes) {
		nodes = g_list_sort(rsc->allowed_nodes, sort_node_weight);
		chosen = g_list_nth_data(nodes, 0);
	}
	
	if(chosen == NULL) {
		crm_debug("Could not allocate a node for %s", rsc->id);
		rsc->next_role = RSC_ROLE_STOPPED;
		return FALSE;

	} else if(chosen->details->unclean
		  || chosen->details->standby
		  || chosen->details->shutdown) {
		crm_debug("All nodes for color %s are unavailable"
			  ", unclean or shutting down", rsc->id);
		rsc->next_role = RSC_ROLE_STOPPED;
		return FALSE;
		
	} else if(chosen->weight < 0) {
		crm_debug_2("Even highest ranked node for color %s, had weight %d",
			  rsc->id, chosen->weight);
		rsc->next_role = RSC_ROLE_STOPPED;
		return FALSE;
	}

	if(rsc->next_role == RSC_ROLE_UNKNOWN) {
		rsc->next_role = RSC_ROLE_STARTED;
	}
	
	slist_iter(candidate, node_t, nodes, lpc, 
		   crm_debug("Color %s, Node[%d] %s: %d", rsc->id, lpc,
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
		crm_free(score);
	}
	
	/* todo: update the old node for each resource to reflect its
	 * new resource count
	 */

	crm_debug("Assigning %s to %s", chosen->details->uname, rsc->id);
	rsc->allocated_to = node_copy(chosen);
	chosen->details->num_resources++;
	
	return TRUE;
}

void native_set_cmds(resource_t *rsc)
{
}

int native_num_allowed_nodes(resource_t *rsc)
{
	int num_nodes = 0;

	if(rsc->next_role == RSC_ROLE_STOPPED) {
		return 0;
	}
	
	crm_debug_4("Default case");
	slist_iter(
		this_node, node_t, rsc->allowed_nodes, lpc,
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

	crm_debug_2("Resource %s can run on %d nodes", rsc->id, num_nodes);
	return num_nodes;
}


node_t *
native_color(resource_t *rsc, pe_working_set_t *data_set)
{
	print_resource(LOG_DEBUG_2, "Allocating: ", rsc, FALSE);
	
	if(rsc->provisional == FALSE) {
		return rsc->allocated_to;
	}
	if(rsc->is_allocating) {
		crm_err("Dependancy loop detected involving %s", rsc->id);
		return NULL;
	}
	
	rsc->is_allocating = TRUE;
	rsc->rsc_cons = g_list_sort(rsc->rsc_cons, sort_cons_strength);

	/*------ Pre-processing ------*/
	slist_iter(
		constraint, rsc_colocation_t, rsc->rsc_cons, lpc,

		crm_debug_3("Pre-Processing %s", constraint->id);		

		rsc->cmds->rsc_colocation_lh(
			rsc, constraint->rsc_rh, constraint);

		if(constraint->strength == pecs_must) {
			/* or use ordering constraints */
			constraint->rsc_rh->cmds->color(constraint->rsc_rh, data_set);
		}

		rsc->cmds->rsc_colocation_lh(
			rsc, constraint->rsc_rh, constraint);
		
		);

	if(native_choose_node(rsc) ) {
		crm_debug_3("Allocated resource %s to %s",
			    rsc->id, rsc->allocated_to->details->uname);
	} else {
		pe_warn("Resource %s cannot run anywhere", rsc->id);
	}
	rsc->provisional = FALSE;
	rsc->is_allocating = FALSE;

	/*------ Post-processing ------*/
	slist_iter(
		constraint, rsc_colocation_t, rsc->rsc_cons, lpc,
		crm_debug_3("Post-Processing %s", constraint->id);
		rsc->cmds->rsc_colocation_lh(
			rsc, constraint->rsc_rh, constraint);
		);
	print_resource(LOG_DEBUG_3, "Allocated ", rsc, TRUE);

	return rsc->allocated_to;
}

void
Recurring(resource_t *rsc, action_t *start, node_t *node,
			 pe_working_set_t *data_set) 
{
	char *key = NULL;
	const char *name = NULL;
	const char *value = NULL;
	const char *interval = NULL;
	const char *node_uname = NULL;

	int interval_ms = 0;
	action_t *mon = NULL;
	gboolean is_optional = TRUE;
	GListPtr possible_matches = NULL;
	
	crm_debug_2("Creating recurring actions for %s", rsc->id);
	if(node != NULL) {
		node_uname = node->details->uname;
	}
	
	xml_child_iter_filter(
		rsc->ops_xml, operation, "op",
		
		is_optional = TRUE;
		name = crm_element_value(operation, "name");
		interval = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
		interval_ms = crm_get_msec(interval);

		if(interval_ms <= 0) {
			continue;
		}

		value = crm_element_value(operation, "disabled");
		if(crm_is_true(value)) {
			continue;
		}
		
		key = generate_op_key(rsc->id, name, interval_ms);
		if(start != NULL) {
			crm_debug_3("Marking %s %s due to %s",
				    key, start->optional?"optional":"manditory",
				    start->uuid);
			is_optional = start->optional;
		} else {
			crm_debug_2("Marking %s optional", key);
			is_optional = TRUE;
		}
		
		/* start a monitor for an already active resource */
		possible_matches = find_actions_exact(rsc->actions, key, node);
		if(possible_matches == NULL) {
			is_optional = FALSE;
			crm_debug_3("Marking %s manditory: not active", key);
		}

		value = crm_element_value(operation, "role");
		if((rsc->next_role == RSC_ROLE_MASTER && value == NULL)
		   || (value != NULL && text2role(value) != rsc->next_role)) {
			int log_level = LOG_DEBUG_2;
			const char *foo = "Ignoring";
			if(is_optional) {
				log_level = LOG_INFO;
				foo = "Cancelling";
				/* its running : cancel it */

				mon = custom_action(
					rsc, crm_strdup(key), CRMD_ACTION_CANCEL, node,
					FALSE, TRUE, data_set);

				mon->task = CRMD_ACTION_CANCEL;
				add_hash_param(mon->meta, XML_LRM_ATTR_INTERVAL, interval);
				add_hash_param(mon->meta, XML_LRM_ATTR_TASK, name);
				
				custom_action_order(
					rsc, NULL, mon,
					rsc, promote_key(rsc), NULL,
					pe_ordering_optional, data_set);

				mon = NULL;
			}
			
			crm_log_maybe(log_level, "%s action %s (%s vs. %s)",
				      foo , key, value?value:role2text(RSC_ROLE_SLAVE),
				      role2text(rsc->next_role));
			crm_free(key);
			key = NULL;
			continue;
		}		
		
		mon = custom_action(rsc, key, name, node,
				    is_optional, TRUE, data_set);

		if(is_optional) {
			crm_debug("%s\t   %s (optional)",
				  crm_str(node_uname), mon->uuid);
		}
		
		if(start == NULL || start->runnable == FALSE) {
			crm_debug("%s\t   %s (cancelled : start un-runnable)",
				  crm_str(node_uname), mon->uuid);
			mon->runnable = FALSE;

		} else if(node == NULL
			  || node->details->online == FALSE
			  || node->details->unclean) {
			crm_debug("%s\t   %s (cancelled : no node available)",
				  crm_str(node_uname), mon->uuid);
			mon->runnable = FALSE;
		
		} else if(mon->optional == FALSE) {
			crm_notice("%s\t   %s", crm_str(node_uname),mon->uuid);
		}

		custom_action_order(rsc, start_key(rsc), NULL,
				    NULL, crm_strdup(key), mon,
				    pe_ordering_restart, data_set);

		if(rsc->next_role == RSC_ROLE_MASTER) {
			char *running_master = crm_itoa(EXECRA_RUNNING_MASTER);
			add_hash_param(mon->meta, XML_ATTR_TE_TARGET_RC, running_master);
			custom_action_order(
				rsc, promote_key(rsc), NULL,
				rsc, NULL, mon,
				pe_ordering_optional, data_set);
			crm_free(running_master);
		}		
		);	
}

void native_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *start = NULL;
	node_t *chosen = NULL;
	enum rsc_role_e role = RSC_ROLE_UNKNOWN;
	enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;

	chosen = rsc->allocated_to;
	if(chosen != NULL) {
		CRM_CHECK(rsc->next_role != RSC_ROLE_UNKNOWN, rsc->next_role = RSC_ROLE_STARTED);
	}

	unpack_instance_attributes(
		rsc->xml, XML_TAG_ATTR_SETS,
		chosen?chosen->details->attrs:NULL,
		rsc->parameters, NULL, data_set->now);

	crm_debug_2("%s: %s->%s", rsc->id,
		    role2text(rsc->role), role2text(rsc->next_role));
	
	if(g_list_length(rsc->running_on) > 1) {
 		if(rsc->recovery_type == recovery_stop_start) {
			pe_proc_err("Attempting recovery of resource %s", rsc->id);
			StopRsc(rsc, NULL, data_set);
			rsc->role = RSC_ROLE_STOPPED;
		}
		
	} else if(rsc->running_on != NULL) {
		node_t *current = rsc->running_on->data;
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

	while(role != rsc->next_role) {
		next_role = rsc_state_matrix[role][rsc->next_role];
		crm_debug_2("Executing: %s->%s (%s)",
			  role2text(role), role2text(next_role), rsc->id);
		if(rsc_action_matrix[role][next_role](
			   rsc, chosen, data_set) == FALSE) {
			break;
		}
		role = next_role;
	}

	if(rsc->next_role != RSC_ROLE_STOPPED && rsc->is_managed) {
		start = start_action(rsc, chosen, TRUE);
		Recurring(rsc, start, chosen, data_set);
	}
}

void native_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	order_restart(rsc);
	custom_action_order(rsc, demote_key(rsc), NULL,
			    rsc, stop_key(rsc), NULL,
			    pe_ordering_manditory, data_set);
	custom_action_order(rsc, start_key(rsc), NULL,
			    rsc, promote_key(rsc), NULL,
			    pe_ordering_optional, data_set);

	custom_action_order(
		rsc, stop_key(rsc), NULL, rsc, delete_key(rsc), NULL, 
		pe_ordering_optional, data_set);

	custom_action_order(
		rsc, delete_key(rsc), NULL, rsc, start_key(rsc), NULL, 
		pe_ordering_manditory, data_set);	
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
	
	rsc_rh->cmds->rsc_colocation_rh(rsc_lh, rsc_rh, constraint);		
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

static void
native_update_node_weight(
	resource_t *rsc, const char *id, node_t *node, int score)
{
	node_t *node_rh = NULL;
	CRM_CHECK(node != NULL, return);
	
	node_rh = pe_find_node_id(
		rsc->allowed_nodes, node->details->id);

	if(node_rh == NULL) {
		pe_err("Node not found - adding %s to %s",
		       node->details->id, rsc->id);
		node_rh = node_copy(node);
		rsc->allowed_nodes = g_list_append(
			rsc->allowed_nodes, node_rh);

		node_rh = pe_find_node_id(
			rsc->allowed_nodes, node->details->id);

		CRM_CHECK(node_rh != NULL, return);
		return;
	}

	CRM_CHECK(node_rh != NULL, return);
	
	if(node_rh == NULL) {
		pe_err("Node not found - cant update");
		return;
	}

	if(node_rh->weight >= INFINITY && score <= -INFINITY) {
		pe_err("Constraint \"%s\" mixes +/- INFINITY (%s)",
		       id, rsc->id);
		
	} else if(node_rh->details->shutdown == TRUE
		  || node_rh->details->online == FALSE
		  || node_rh->details->unclean == TRUE) {

	} else if(node_rh->weight <= -INFINITY && score >= INFINITY) {
		pe_err("Constraint \"%s\" mixes +/- INFINITY (%s)",
			 id, rsc->id);
	}

	if(node_rh->fixed) {
		/* warning */
		crm_debug_2("Constraint %s is irrelevant as the"
			 " weight of node %s is fixed as %d (%s).",
			 id, node_rh->details->uname,
			 node_rh->weight, rsc->id);
		return;
	}	
	
	crm_debug_3("Constraint %s, node %s, rsc %s: %d + %d",
		   id, node_rh->details->uname, rsc->id,
		   node_rh->weight, score);
	node_rh->weight = merge_weights(node_rh->weight, score);
	if(node_rh->weight <= -INFINITY) {
		crm_debug_3("Constraint %s (-INFINITY): node %s weight %d (%s).",
			    id, node_rh->details->uname,
			    node_rh->weight, rsc->id);
		
	} else if(node_rh->weight >= INFINITY) {
		crm_debug_3("Constraint %s (+INFINITY): node %s weight %d (%s).",
			    id, node_rh->details->uname,
			    node_rh->weight, rsc->id);

	} else {
		crm_debug_3("Constraint %s (%d): node %s weight %d (%s).",
			    id, score, node_rh->details->uname,
			    node_rh->weight, rsc->id);
	}

	if(node_rh->weight < 0) {
		node_rh->fixed = TRUE;
	}

	crm_action_debug_3(print_node("Updated", node_rh, FALSE));

	return;
}

void native_rsc_colocation_rh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	crm_debug_2("%sColocating %s with %s (%s)",
		    constraint->strength == pecs_must?"":"Anti-",
		    rsc_lh->id, rsc_rh->id, constraint->id);
	
	if(filter_colocation_constraint(rsc_lh, rsc_rh, constraint) == FALSE) {
		return;
	}
	
	if(rsc_lh->provisional && rsc_rh->provisional) {
		crm_err("combine priorities of %s and %s",
			rsc_lh->id, rsc_rh->id);
		return;

	} else if( (!rsc_lh->provisional) && (!rsc_rh->provisional) ) {
		/* error check */
		if(rsc_lh->allocated_to == rsc_rh->allocated_to) {
			return;

		} else if(rsc_lh->allocated_to && rsc_rh->allocated_to
		   && rsc_lh->allocated_to->details
			  == rsc_rh->allocated_to->details) {
			return;
		}
		
		crm_err("%s and %s are both allocated"
			" but to different nodes: %s vs. %s",
			rsc_lh->id, rsc_rh->id,
			rsc_lh->allocated_to?rsc_lh->allocated_to->details->uname:"n/a",
			rsc_rh->allocated_to?rsc_rh->allocated_to->details->uname:"n/a");
		return;
		
	} else if(rsc_lh->provisional == FALSE) {
		/* update _them_    : postproc color version */
		native_update_node_weight(
			rsc_rh, constraint->id, rsc_lh->allocated_to,
			constraint->strength==pecs_must?INFINITY:-INFINITY);
		
	} else if(rsc_rh->provisional == FALSE) {
		/* update _us_  : postproc color alt version */
		native_update_node_weight(
			rsc_lh, constraint->id, rsc_rh->allocated_to,
			constraint->strength==pecs_must?INFINITY:-INFINITY);

	} else {
		pe_warn("Un-expected combination of inputs");
	}
}


void native_rsc_order_lh(resource_t *lh_rsc, order_constraint_t *order)
{
	GListPtr lh_actions = NULL;
	action_t *lh_action = order->lh_action;

	crm_debug_3("Processing LH of ordering constraint %d", order->id);

	if(lh_action != NULL) {
		lh_actions = g_list_append(NULL, lh_action);

	} else if(lh_action == NULL && lh_rsc != NULL) {
		lh_actions = find_actions(
			lh_rsc->actions, order->lh_action_task, NULL);

		if(lh_actions == NULL) {
			crm_debug_4("No LH-Side (%s/%s) found for constraint",
				  lh_rsc->id, order->lh_action_task);

			if(lh_rsc->next_role == RSC_ROLE_STOPPED) {
				resource_t *rh_rsc = order->rh_rsc;
				if(order->rh_action && order->type == pe_ordering_restart) {
					crm_debug_3("No LH(%s/%s) found for RH(%s)...",
						    lh_rsc->id, order->lh_action_task,
						    order->rh_action->uuid);
					order->rh_action->runnable = FALSE;
					return;
				
				} else if(rh_rsc != NULL) {
					crm_debug_3("No LH(%s/%s) found for RH(%s/%s)...",
						    lh_rsc->id, order->lh_action_task,
						    rh_rsc->id, order->rh_action_task);
					rh_rsc->cmds->rsc_order_rh(NULL, rh_rsc, order);
					return;
				}
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
			rh_rsc->cmds->rsc_order_rh(
				lh_action_iter, rh_rsc, order);

		} else if(order->rh_action) {
			order_actions(lh_action_iter, order->rh_action, order->type); 

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

		if(lh_action) {
		order_actions(lh_action, rh_action_iter, order->type); 

		} else if(order->type == pe_ordering_restart) {
			rh_action_iter->runnable = FALSE;
		}
		
		);

	pe_free_shallow_adv(rh_actions, FALSE);
}

void native_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	GListPtr or_list;

	crm_debug_2("Applying %s (%s) to %s", constraint->id,
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
    
	if(constraint->node_list_rh == NULL) {
		crm_debug_2("RHS of constraint %s is NULL", constraint->id);
		return;
	}
	or_list = node_list_or(
		rsc->allowed_nodes, constraint->node_list_rh, FALSE);
		
	pe_free_shallow(rsc->allowed_nodes);
	rsc->allowed_nodes = or_list;
	slist_iter(node, node_t, or_list, lpc,
		   crm_debug_3("%s + %s : %d", rsc->id, node->details->uname, node->weight);
		);
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



void
native_agent_constraints(resource_t *rsc)
{
}





/*
 * Remove any nodes with a -ve weight
 */
void
filter_nodes(resource_t *rsc)
{
	print_resource(LOG_DEBUG_3, "Filtering nodes for: ", rsc, FALSE);
	slist_iter(
		node, node_t, rsc->allowed_nodes, lpc,
		if(node == NULL) {
			pe_err("Invalid NULL node");
			
		} else if(node->weight < 0.0
			  || node->details->shutdown
			  || node->details->online == FALSE
			  || node->details->type == node_ping) {
			crm_action_debug_3(print_node("Removing", node, FALSE));
			rsc->allowed_nodes =
				g_list_remove(rsc->allowed_nodes, node);
			crm_free(node);
			lpc = -1; /* restart the loop */
		}
		);
}

void
create_notifications(resource_t *rsc, pe_working_set_t *data_set)
{
	if(rsc->notify == FALSE) {
		return;
	}
	
/* 	slist_iter( */
/* 		action, action_t, rsc->actions, lpc, */
		
/* 		); */

}

static void
register_activity(resource_t *rsc, enum action_tasks task, node_t *node, notify_data_t *n_data)
{
	notify_entry_t *entry = NULL;
	crm_malloc0(entry, sizeof(notify_entry_t));
	entry->rsc = rsc;
	entry->node = node;
	switch(task) {
		case start_rsc:
			n_data->start = g_list_append(n_data->start, entry);
			break;
		case stop_rsc:
			n_data->stop = g_list_append(n_data->stop, entry);
			break;
		case action_promote:
			n_data->promote = g_list_append(n_data->promote, entry);
			break;
		case action_demote:
			n_data->demote = g_list_append(n_data->demote, entry);
			break;
		default:
			crm_err("Unsupported notify action: %s", task2text(task));
			break;
	}
	
}


static void
register_state(resource_t *rsc, node_t *on_node, notify_data_t *n_data)
{
	notify_entry_t *entry = NULL;
	crm_malloc0(entry, sizeof(notify_entry_t));
	entry->rsc = rsc;
	entry->node = on_node;

	crm_debug_2("%s state: %s", rsc->id, role2text(rsc->next_role));

	switch(rsc->next_role) {
		case RSC_ROLE_STOPPED:
/* 			n_data->inactive = g_list_append(n_data->inactive, entry); */
			crm_free(entry);
			break;
		case RSC_ROLE_STARTED:
			n_data->active = g_list_append(n_data->active, entry);
			break;
		case RSC_ROLE_SLAVE:
 			n_data->slave = g_list_append(n_data->slave, entry); 
			break;
		case RSC_ROLE_MASTER:
			n_data->master = g_list_append(n_data->master, entry);
			break;
		default:
			crm_err("Unsupported notify role");
			break;
	}
}

void
native_create_notify_element(resource_t *rsc, action_t *op,
			     notify_data_t *n_data, pe_working_set_t *data_set)
{
	node_t *next_node = NULL;
	gboolean registered = FALSE;
	char *op_key = NULL;
	GListPtr possible_matches = NULL;
	enum action_tasks task = text2task(op->task);
	
	if(op->pre_notify == NULL || op->post_notify == NULL) {
		/* no notifications required */
		crm_debug_4("No notificaitons required for %s", op->task);
		return;
	}
	next_node = rsc->allocated_to;
	op_key = generate_op_key(rsc->id, op->task, 0);
	possible_matches = find_actions(rsc->actions, op_key, NULL);
	
	crm_debug_2("Creating notificaitons for: %s (%s->%s)",
		    op->uuid, role2text(rsc->role), role2text(rsc->next_role));

	if(rsc->role == rsc->next_role) {
		register_state(rsc, next_node, n_data);
	}
	
	slist_iter(
		local_op, action_t, possible_matches, lpc,

		local_op->notify_keys = n_data->keys;
		if(local_op->optional == FALSE) {
			registered = TRUE;
			register_activity(rsc, task, local_op->node, n_data);
		}		
		);

	/* stop / demote */
	if(rsc->role != RSC_ROLE_STOPPED) {
		if(task == stop_rsc || task == action_demote) {
			slist_iter(
				current_node, node_t, rsc->running_on, lpc,
				pe_pre_notify(rsc, current_node, op, n_data, data_set);
				if(task == action_demote || registered == FALSE) {
					pe_post_notify(rsc, current_node, op, n_data, data_set);
				}
				);
		}
	}
	
	/* start / promote */
	if(rsc->next_role != RSC_ROLE_STOPPED) {	
		CRM_CHECK(next_node != NULL,;);

		if(next_node == NULL) {
			pe_proc_err("next role: %s", role2text(rsc->next_role));
			
		} else if(task == start_rsc || task == action_promote) {
			if(task != start_rsc || registered == FALSE) {
				pe_pre_notify(rsc, next_node, op, n_data, data_set);
			}
			pe_post_notify(rsc, next_node, op, n_data, data_set);
		}
	}
	
	crm_free(op_key);
	pe_free_shallow_adv(possible_matches, FALSE);
}


static void dup_attr(gpointer key, gpointer value, gpointer user_data)
{
	char *meta_key = crm_concat(CRM_META, key, '_');
	g_hash_table_replace(user_data, meta_key, crm_strdup(value));
}

static action_t *
pe_notify(resource_t *rsc, node_t *node, action_t *op, action_t *confirm,
	  notify_data_t *n_data, pe_working_set_t *data_set)
{
	char *key = NULL;
	action_t *trigger = NULL;
	const char *value = NULL;
	const char *task = NULL;
	
	if(op == NULL || confirm == NULL) {
		crm_debug_2("Op=%p confirm=%p", op, confirm);
		return NULL;
	}

	CRM_CHECK(node != NULL, return NULL);

	if(node->details->online == FALSE) {
		crm_info("Skipping notification for %s", rsc->id);
		return NULL;
	}
	
	value = g_hash_table_lookup(op->meta, "notify_type");
	task = g_hash_table_lookup(op->meta, "notify_operation");

	crm_debug_2("Creating actions for %s: %s (%s-%s)",
		    op->uuid, rsc->id, value, task);
	
	key = generate_notify_key(rsc->id, value, task);
	trigger = custom_action(rsc, key, op->task, node,
				op->optional, TRUE, data_set);
	g_hash_table_foreach(op->meta, dup_attr, trigger->extra);
	trigger->notify_keys = n_data->keys;

	/* pseudo_notify before notify */
	crm_debug_3("Ordering %s before %s (%d->%d)",
		op->uuid, trigger->uuid, trigger->id, op->id);

	order_actions(op, trigger, pe_ordering_manditory);
	
	value = g_hash_table_lookup(op->meta, "notify_confirm");
	if(crm_is_true(value)) {
		/* notify before pseudo_notified */
		crm_debug_3("Ordering %s before %s (%d->%d)",
			    trigger->uuid, confirm->uuid,
			    confirm->id, trigger->id);

		order_actions(trigger, confirm, pe_ordering_manditory);
	}	
	return trigger;
}

void
pe_pre_notify(resource_t *rsc, node_t *node, action_t *op,
	      notify_data_t *n_data, pe_working_set_t *data_set)
{
	crm_debug_2("%s: %s", rsc->id, op->uuid);
	pe_notify(rsc, node, op->pre_notify, op->pre_notified,
		  n_data, data_set);
}

void
pe_post_notify(resource_t *rsc, node_t *node, action_t *op, 
	       notify_data_t *n_data, pe_working_set_t *data_set)
{
	action_t *notify = NULL;

	CRM_CHECK(op != NULL, return);
	CRM_CHECK(rsc != NULL, return);
	
	crm_debug_2("%s: %s", rsc->id, op->uuid);
	notify = pe_notify(rsc, node, op->post_notify, op->post_notified,
			   n_data, data_set);

	if(notify != NULL) {
		notify->priority = INFINITY;
	}
	
	notify = op->post_notified;
	if(notify != NULL) {
		notify->priority = INFINITY;
		slist_iter(
			mon, action_t, rsc->actions, lpc,

			const char *interval = g_hash_table_lookup(mon->meta, "interval");
			if(interval == NULL || safe_str_eq(interval, "0")) {
				crm_debug_3("Skipping %s: interval", mon->uuid); 
				continue;
			} else if(safe_str_eq(mon->task, "cancel")) {
				crm_debug_3("Skipping %s: cancel", mon->uuid); 
				continue;
			}

			order_actions(notify, mon, pe_ordering_optional);
			);
	}
}


void
NoRoleChange(resource_t *rsc, node_t *current, node_t *next,
	     pe_working_set_t *data_set)
{
	action_t *start = NULL;
	action_t *stop = NULL;
	GListPtr possible_matches = NULL;

	crm_debug("Executing: %s (role=%s)",rsc->id, role2text(rsc->next_role));

	if(current == NULL || next == NULL) {
		return;
	}

	/* use StartRsc/StopRsc */
	
	if(safe_str_neq(current->details->id, next->details->id)) {
		crm_notice("Move  resource %s\t(%s -> %s)", rsc->id,
			   current->details->uname, next->details->uname);

		stop = stop_action(rsc, current, FALSE);
		start = start_action(rsc, next, FALSE);

		possible_matches = find_recurring_actions(rsc->actions, next);
		slist_iter(match, action_t, possible_matches, lpc,
			   if(match->optional == FALSE) {
				   crm_err("Found bad recurring action: %s",
					   match->uuid);
				   match->optional = TRUE;
			   }
			);
			
		if(data_set->remove_after_stop) {
			DeleteRsc(rsc, current, data_set);
		}
		
	} else {
		if(rsc->failed) {
			crm_notice("Recover resource %s\t(%s)",
				   rsc->id, next->details->uname);
			stop = stop_action(rsc, current, FALSE);
			start = start_action(rsc, next, FALSE);
/* 			/\* make the restart required *\/ */
/* 			order_stop_start(rsc, rsc, pe_ordering_manditory); */
			
		} else if(rsc->start_pending) {
			start = start_action(rsc, next, TRUE);
			if(start->runnable) {
				/* wait for StartRsc() to be called */
				rsc->role = RSC_ROLE_STOPPED;
			} else {
				/* wait for StopRsc() to be called */
				rsc->next_role = RSC_ROLE_STOPPED;
			}
			
		} else {
			stop = stop_action(rsc, current, TRUE);
			start = start_action(rsc, next, TRUE);
			stop->optional = start->optional;
			
			if(start->runnable == FALSE) {
				rsc->next_role = RSC_ROLE_STOPPED;

			} else if(start->optional) {
				crm_notice("Leave resource %s\t(%s)",
					   rsc->id, next->details->uname);

			} else {
				crm_notice("Restart resource %s\t(%s)",
					   rsc->id, next->details->uname);
			}
		}
	}
}


gboolean
StopRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	action_t *stop = NULL;
	
	crm_debug_2("Executing: %s", rsc->id);
	
	slist_iter(
		current, node_t, rsc->running_on, lpc,
		crm_notice("  %s\tStop %s", current->details->uname, rsc->id);
		stop = stop_action(rsc, current, FALSE);

		if(data_set->remove_after_stop) {
			DeleteRsc(rsc, current, data_set);
		}
		);
	
	return TRUE;
}


gboolean
StartRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	action_t *start = NULL;
	
	crm_debug_2("Executing: %s", rsc->id);
	start = start_action(rsc, next, TRUE);
	if(start->runnable) {
		crm_notice(" %s\tStart %s", next->details->uname, rsc->id);
		start->optional = FALSE;
	}		
	return TRUE;
}

gboolean
PromoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	char *key = NULL;
	gboolean runnable = TRUE;
	GListPtr action_list = NULL;
	crm_debug_2("Executing: %s", rsc->id);

	CRM_CHECK(rsc->next_role == RSC_ROLE_MASTER, return FALSE);

	key = start_key(rsc);
	action_list = find_actions_exact(rsc->actions, key, next);
	crm_free(key);

	slist_iter(start, action_t, action_list, lpc,
		   if(start->runnable == FALSE) {
			   runnable = FALSE;
		   }
		);

	if(runnable) {
		promote_action(rsc, next, FALSE);
		crm_notice("%s\tPromote %s", next->details->uname, rsc->id);
		return TRUE;
	} 

	crm_debug("%s\tPromote %s (canceled)", next->details->uname, rsc->id);

	key = promote_key(rsc);
	action_list = find_actions_exact(rsc->actions, key, next);
	crm_free(key);

	slist_iter(promote, action_t, action_list, lpc,
		   promote->runnable = FALSE;
		);
	
	return TRUE;
}

gboolean
DemoteRsc(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	crm_debug_2("Executing: %s", rsc->id);

/* 	CRM_CHECK(rsc->next_role == RSC_ROLE_SLAVE, return FALSE); */
	slist_iter(
		current, node_t, rsc->running_on, lpc,
		crm_notice("%s\tDeomote %s", current->details->uname, rsc->id);
		demote_action(rsc, current, FALSE);
		);
	return TRUE;
}

gboolean
RoleError(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	crm_debug("Executing: %s", rsc->id);
	CRM_CHECK(FALSE, return FALSE);
	return FALSE;
}

gboolean
NullOp(resource_t *rsc, node_t *next, pe_working_set_t *data_set)
{
	crm_debug("Executing: %s", rsc->id);
	return FALSE;
}


gboolean
native_create_probe(resource_t *rsc, node_t *node, action_t *complete,
		    gboolean force, pe_working_set_t *data_set) 
{
	char *key = NULL;
	char *target_rc = NULL;
	action_t *probe = NULL;
	node_t *running = NULL;

	CRM_CHECK(node != NULL, return FALSE);

	if(rsc->orphan) {
		crm_debug_2("Skipping orphan: %s", rsc->id);
		return FALSE;
	}
	
	running = pe_find_node_id(rsc->known_on, node->details->id);
	if(force == FALSE && running != NULL) {
		/* we already know the status of the resource on this node */
		crm_debug_3("Skipping active: %s", rsc->id);
		return FALSE;
	}

	key = generate_op_key(rsc->id, CRMD_ACTION_STATUS, 0);
	probe = custom_action(rsc, key, CRMD_ACTION_STATUS, node,
			      FALSE, TRUE, data_set);
	probe->priority = INFINITY;

	running = pe_find_node_id(rsc->running_on, node->details->id);
	if(running == NULL) {
		target_rc = crm_itoa(EXECRA_NOT_RUNNING);
		add_hash_param(probe->meta, XML_ATTR_TE_TARGET_RC, target_rc);
		crm_free(target_rc);
	}
	
	crm_notice("%s: Created probe for %s", node->details->uname, rsc->id);
	
	custom_action_order(rsc, NULL, probe, rsc, NULL, complete,
			    pe_ordering_manditory, data_set);

	return TRUE;
}

static void
native_start_constraints(
	resource_t *rsc,  action_t *stonith_op, gboolean is_stonith,
	pe_working_set_t *data_set)
{
	gboolean is_unprotected = FALSE;
	gboolean run_unprotected = TRUE;

	if(is_stonith) {
		char *key = start_key(rsc);
		crm_debug_2("Ordering %s action before stonith events", key);
		custom_action_order(
			rsc, key, NULL,
			NULL, crm_strdup(CRM_OP_FENCE), stonith_op,
			pe_ordering_optional, data_set);

	} else {
		slist_iter(action, action_t, rsc->actions, lpc2,
			   if(action->needs != rsc_req_stonith) {
				   crm_debug_3("%s doesnt need to wait for stonith events", action->uuid);
				   continue;
			   }
			   crm_debug_2("Ordering %s after stonith events", action->uuid);
			   if(stonith_op != NULL) {
				   custom_action_order(
					   NULL, crm_strdup(CRM_OP_FENCE), stonith_op,
					   rsc, NULL, action,
					   pe_ordering_manditory, data_set);
				   
			   } else if(run_unprotected == FALSE) {
				   /* mark the start unrunnable */
				   action->runnable = FALSE;
				   
			   } else {
				   is_unprotected = TRUE;
			   }   
			);
	}
	
	if(is_unprotected) {
		pe_err("SHARED RESOURCE %s IS NOT PROTECTED:"
		       " Stonith disabled", rsc->id);
	}

}

static void
native_stop_constraints(
	resource_t *rsc,  action_t *stonith_op, gboolean is_stonith,
	pe_working_set_t *data_set)
{
	char *key = NULL;
	GListPtr action_list = NULL;
	node_t *node = stonith_op->node;

	key = stop_key(rsc);
	action_list = find_actions(rsc->actions, key, node);
	crm_free(key);

	/* add the stonith OP as a stop pre-req and the mark the stop
	 * as a pseudo op - since its now redundant
	 */
	
	slist_iter(
		action, action_t, action_list, lpc2,
		if(node->details->online == FALSE || rsc->failed) {
			resource_t *parent = NULL;
			crm_warn("Stop of failed resource %s is"
				 " implict after %s is fenced",
				 rsc->id, node->details->uname);
			/* the stop would never complete and is
			 * now implied by the stonith operation
			 */
			action->pseudo = TRUE;
			action->runnable = TRUE;
			if(is_stonith) {
				/* do nothing */
				
			} else {
				custom_action_order(
					NULL, crm_strdup(CRM_OP_FENCE),stonith_op,
					rsc, start_key(rsc), NULL,
					pe_ordering_manditory, data_set);
			}
			
			/* find the top-most resource */
			parent = rsc->parent;
			while(parent != NULL && parent->parent != NULL) {
				parent = parent->parent;
			}
			
			if(parent) {
				crm_info("Re-creating actions for %s",
					 parent->id);
				parent->cmds->create_actions(parent, data_set);
			}
			
		} else if(is_stonith == FALSE) {
			crm_info("Moving healthy resource %s"
				 " off %s before fencing",
				 rsc->id, node->details->uname);
			
			/* stop healthy resources before the
			 * stonith op
			 */
			custom_action_order(
				rsc, stop_key(rsc), NULL,
				NULL,crm_strdup(CRM_OP_FENCE),stonith_op,
				pe_ordering_manditory, data_set);
		}
		);
	
	key = demote_key(rsc);
	action_list = find_actions(rsc->actions, key, node);
	crm_free(key);
	
	slist_iter(
		action, action_t, action_list, lpc2,
		if(node->details->online == FALSE || rsc->failed) {
			crm_info("Demote of failed resource %s is"
				 " implict after %s is fenced",
				 rsc->id, node->details->uname);
			/* the stop would never complete and is
			 * now implied by the stonith operation
			 */
			action->pseudo = TRUE;
			action->runnable = TRUE;
			if(is_stonith == FALSE) {
				custom_action_order(
					NULL, crm_strdup(CRM_OP_FENCE), stonith_op,
					rsc, demote_key(rsc), NULL,
					pe_ordering_manditory, data_set);
			}
		}
		);	
}

void
native_stonith_ordering(
	resource_t *rsc,  action_t *stonith_op, pe_working_set_t *data_set)
{
	gboolean is_stonith = FALSE;
	const char *class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);

	if(rsc->is_managed == FALSE) {
		crm_debug_3("Skipping fencing constraints for unmanaged resource: %s", rsc->id);
		return;
	} 

	if(stonith_op != NULL && safe_str_eq(class, "stonith")) {
		is_stonith = TRUE;
	}
	
	/* Start constraints */
	native_start_constraints(rsc,  stonith_op, is_stonith, data_set);
 
	/* Stop constraints */
	native_stop_constraints(rsc,  stonith_op, is_stonith, data_set);
}


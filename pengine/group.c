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

#include <crm_internal.h>

#include <pengine.h>
#include <lib/pengine/utils.h>
#include <crm/msg_xml.h>

#include <allocate.h>
#include <utils.h>

#define VARIANT_GROUP 1
#include <lib/pengine/variant.h>

node_t *
group_color(resource_t *rsc, pe_working_set_t *data_set)
{
	node_t *node = NULL;
	node_t *group_node = NULL;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	if(is_not_set(rsc->flags, pe_rsc_provisional)) {
		return rsc->allocated_to;
	}
	crm_debug_2("Processing %s", rsc->id);
	if(is_set(rsc->flags, pe_rsc_allocating)) {
		crm_debug("Dependancy loop detected involving %s", rsc->id);
		return NULL;
	}
	
	if(group_data->first_child == NULL) {
	    /* nothign to allocate */
	    clear_bit(rsc->flags, pe_rsc_provisional);
	    return NULL;
	}
	
	set_bit(rsc->flags, pe_rsc_allocating);
	rsc->role = group_data->first_child->role;
	
	group_data->first_child->rsc_cons = g_list_concat(
		group_data->first_child->rsc_cons, rsc->rsc_cons);
	rsc->rsc_cons = NULL;

	group_data->first_child->rsc_cons_lhs = g_list_concat(
		group_data->first_child->rsc_cons_lhs, rsc->rsc_cons_lhs);
	rsc->rsc_cons_lhs = NULL;
	
	dump_node_scores(show_scores?0:scores_log_level, rsc, __PRETTY_FUNCTION__, rsc->allowed_nodes);
	
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		node = child_rsc->cmds->color(child_rsc, data_set);
		if(group_node == NULL) {
		    group_node = node;
		}
		);

	rsc->next_role = group_data->first_child->next_role;	
	clear_bit(rsc->flags, pe_rsc_allocating);
	clear_bit(rsc->flags, pe_rsc_provisional);

	if(group_data->colocated) {
		return group_node;
	} 
	return NULL;
}

void group_update_pseudo_status(resource_t *parent, resource_t *child);

void group_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *op = NULL;
	const char *value = NULL;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_debug_2("Creating actions for %s", rsc->id);
	
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		child_rsc->cmds->create_actions(child_rsc, data_set);
		group_update_pseudo_status(rsc, child_rsc);
		);

	op = start_action(rsc, NULL, TRUE/* !group_data->child_starting */);
	op->pseudo = TRUE;
	op->runnable = TRUE;

	op = custom_action(rsc, started_key(rsc),
			   RSC_STARTED, NULL,
			   TRUE/* !group_data->child_starting */, TRUE, data_set);
	op->pseudo = TRUE;
	op->runnable = TRUE;

	op = stop_action(rsc, NULL, TRUE/* !group_data->child_stopping */);
	op->pseudo = TRUE;
	op->runnable = TRUE;
	
	op = custom_action(rsc, stopped_key(rsc),
			   RSC_STOPPED, NULL,
			   TRUE/* !group_data->child_stopping */, TRUE, data_set);
	op->pseudo = TRUE;
	op->runnable = TRUE;

	value = crm_meta_value(rsc->parameters, "stateful");
	if(crm_is_true(value)) {
	    op = custom_action(rsc, demote_key(rsc), RSC_DEMOTE, NULL, TRUE, TRUE, data_set);
	    op->pseudo = TRUE; op->runnable = TRUE;
	    op = custom_action(rsc, demoted_key(rsc), RSC_DEMOTED, NULL, TRUE, TRUE, data_set);
	    op->pseudo = TRUE; op->runnable = TRUE;

	    op = custom_action(rsc, promote_key(rsc), RSC_PROMOTE, NULL, TRUE, TRUE, data_set);
	    op->pseudo = TRUE; op->runnable = TRUE;
	    op = custom_action(rsc, promoted_key(rsc), RSC_PROMOTED, NULL, TRUE, TRUE, data_set);
	    op->pseudo = TRUE; op->runnable = TRUE;
	}

	
	rsc->actions = rsc->actions;
/* 	rsc->actions = NULL; */
}

void
group_update_pseudo_status(resource_t *parent, resource_t *child) 
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, parent);

	if(group_data->ordered == FALSE) {
	    /* If this group is not ordered, then leave the meta-actions as optional */ 
	    return;
	}
	
	if(group_data->child_stopping && group_data->child_starting) {
		return;
	}
	slist_iter(
		action, action_t, child->actions, lpc,

		if(action->optional) {
			continue;
		}
		if(safe_str_eq(RSC_STOP, action->task) && action->runnable) {
			group_data->child_stopping = TRUE;
			crm_debug_3("Based on %s the group is stopping", action->uuid);

		} else if(safe_str_eq(RSC_START, action->task) && action->runnable) {
			group_data->child_starting = TRUE;
			crm_debug_3("Based on %s the group is starting", action->uuid);
		}
		
		);
}

void group_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	const char *value = NULL;
	gboolean stateful = FALSE;
	resource_t *last_rsc = NULL;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	native_internal_constraints(rsc, data_set);

	value = crm_meta_value(rsc->parameters, "stateful");
	stateful = crm_is_true(value);
	
	new_rsc_order(rsc, RSC_STOPPED, rsc, RSC_START,
		      pe_order_optional, data_set);

	new_rsc_order(rsc, RSC_STOP, rsc, RSC_STOPPED, 
		      pe_order_runnable_left|pe_order_implies_right|pe_order_implies_left, data_set);

	new_rsc_order(rsc, RSC_START, rsc, RSC_STARTED,
		      pe_order_runnable_left, data_set);
	
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		int stop = pe_order_shutdown|pe_order_implies_right;
		int stopped = pe_order_implies_right_printed;
		int start = pe_order_implies_right|pe_order_runnable_left;
		int started = pe_order_runnable_left|pe_order_implies_right|pe_order_implies_right_printed;
		
		child_rsc->cmds->internal_constraints(child_rsc, data_set);

		if(last_rsc == NULL) {
		    if(group_data->ordered) {
			stop |= pe_order_implies_left;
			stopped = pe_order_implies_right;
		    }
		    
		} else if(group_data->colocated) {
			rsc_colocation_new(
				"group:internal_colocation", NULL, INFINITY,
				child_rsc, last_rsc, NULL, NULL, data_set);
		}

		if(stateful) {
		    new_rsc_order(rsc, RSC_DEMOTE, child_rsc, RSC_DEMOTE,
				  stop|pe_order_implies_left_printed, data_set);

		    new_rsc_order(child_rsc, RSC_DEMOTE, rsc, RSC_DEMOTED, stopped, data_set);

		    new_rsc_order(child_rsc, RSC_PROMOTE, rsc, RSC_PROMOTED, started, data_set);

		    new_rsc_order(rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE,
				  pe_order_implies_left_printed, data_set);

		}
		
		order_start_start(rsc, child_rsc, pe_order_implies_left_printed);
		order_stop_stop(rsc, child_rsc, stop|pe_order_implies_left_printed);
		
		new_rsc_order(child_rsc, RSC_STOP, rsc, RSC_STOPPED, stopped, data_set);

		new_rsc_order(child_rsc, RSC_START, rsc, RSC_STARTED, started, data_set);
		
 		if(group_data->ordered == FALSE) {
			order_start_start(rsc, child_rsc, start|pe_order_implies_left_printed);
			if(stateful) {
			    new_rsc_order(rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE,
					  start|pe_order_implies_left_printed, data_set);
			}

		} else if(last_rsc != NULL) {
			child_rsc->restart_type = pe_restart_restart;

			order_start_start(last_rsc, child_rsc, start);
			order_stop_stop(child_rsc, last_rsc, pe_order_implies_left);

			if(stateful) {
			    new_rsc_order(last_rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE, start, data_set);
			    new_rsc_order(child_rsc, RSC_DEMOTE, last_rsc, RSC_DEMOTE, pe_order_implies_left, data_set);
			}

		} else {
			/* If anyone in the group is starting, then
			 *  pe_order_implies_right will cause _everyone_ in the group
			 *  to be sent a start action
			 * But this is safe since starting something that is already
			 *  started is required to be "safe"
			 */
			int flags = pe_order_implies_left|pe_order_implies_right|pe_order_runnable_right|pe_order_runnable_left;
		    
			order_start_start(rsc, child_rsc, flags);
			if(stateful) {
			    new_rsc_order(rsc, RSC_PROMOTE, child_rsc, RSC_PROMOTE, flags, data_set);
			}
			
		}
		
		last_rsc = child_rsc;
		);

	if(group_data->ordered && last_rsc != NULL) {
		int stop_stop_flags = pe_order_implies_right;
		int stop_stopped_flags = pe_order_implies_left;
	    
		order_stop_stop(rsc, last_rsc, stop_stop_flags);
		new_rsc_order(last_rsc, RSC_STOP, rsc,  RSC_STOPPED, stop_stopped_flags, data_set);

		if(stateful) {
		    new_rsc_order(rsc, RSC_DEMOTE, last_rsc, RSC_DEMOTE, stop_stop_flags, data_set);
		    new_rsc_order(last_rsc, RSC_DEMOTE, rsc, RSC_DEMOTED, stop_stopped_flags, data_set);
		}
	}
}


void group_rsc_colocation_lh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	group_variant_data_t *group_data = NULL;
	
	if(rsc_lh == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
	}
		
	crm_debug_4("Processing constraints from %s", rsc_lh->id);

	get_group_variant_data(group_data, rsc_lh);

	if(group_data->colocated) {
		group_data->first_child->cmds->rsc_colocation_lh(
			group_data->first_child, rsc_rh, constraint); 
		return;

	} else if(constraint->score >= INFINITY) {
		crm_config_err("%s: Cannot perform manditory colocation"
			       " between non-colocated group and %s",
			       rsc_lh->id, rsc_rh->id);
		return;
	} 

	slist_iter(
		child_rsc, resource_t, rsc_lh->children, lpc,
		child_rsc->cmds->rsc_colocation_lh(
			child_rsc, rsc_rh, constraint); 
		);
}

void group_rsc_colocation_rh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc_rh);
	CRM_CHECK(rsc_lh->variant == pe_native, return);

	crm_debug_3("Processing RH of constraint %s", constraint->id);
	print_resource(LOG_DEBUG_3, "LHS", rsc_lh, TRUE);

	if(is_set(rsc_rh->flags, pe_rsc_provisional)) {
		return;
	
	} else if(group_data->colocated && group_data->first_child) {
		group_data->first_child->cmds->rsc_colocation_rh(
			rsc_lh, group_data->first_child, constraint); 
		return;

	} else if(constraint->score >= INFINITY) {
		crm_config_err("%s: Cannot perform manditory colocation with"
			       " non-colocated group: %s", rsc_lh->id, rsc_rh->id);
		return;
	} 

	slist_iter(
		child_rsc, resource_t, rsc_rh->children, lpc,
		child_rsc->cmds->rsc_colocation_rh(
			rsc_lh, child_rsc, constraint); 
		);
}

void group_rsc_order_lh(resource_t *rsc, order_constraint_t *order, pe_working_set_t *data_set)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_debug_4("%s->%s", order->lh_action_task, order->rh_action_task);

	if(order->rh_rsc != NULL
	   && (rsc == order->rh_rsc || rsc == order->rh_rsc->parent)) {
		native_rsc_order_lh(rsc, order, data_set);
		return;
	}
#if 0
	if(order->type != pe_order_optional) {
		native_rsc_order_lh(rsc, order, data_set);
	}

	if(order->type & pe_order_implies_left) {
 		native_rsc_order_lh(group_data->first_child, order, data_set);
	}
#endif

	convert_non_atomic_task(rsc, order, TRUE);
	native_rsc_order_lh(rsc, order, data_set);
}

void group_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_debug_4("%s->%s", lh_action->uuid, order->rh_action_task);

	if(rsc == NULL) {
		return;
	}

	if(safe_str_eq(CRM_OP_PROBED, lh_action->uuid)) {
	    slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		child_rsc->cmds->rsc_order_rh(lh_action, child_rsc, order);
		);

	    if(rsc->fns->state(rsc, TRUE) < RSC_ROLE_STARTED
		&& rsc->fns->state(rsc, FALSE) > RSC_ROLE_STOPPED) {
		order->type |= pe_order_implies_right;
	    }
	    
	} else if(lh_action->rsc != NULL
	   && lh_action->rsc != rsc
	   && lh_action->rsc != rsc->parent
	   && lh_action->rsc->parent != rsc) {
	    char *tmp = NULL;
	    char *task_s = NULL;
	    int interval = 0;
	    enum action_tasks task = 0;
	    
	    parse_op_key(order->lh_action_task, &tmp, &task_s, &interval);
	    task = text2task(task_s);
	    crm_free(task_s);
	    crm_free(tmp);
	    
	    switch(task) {
		case no_action:
		case monitor_rsc:
		case action_notify:
		case action_notified:
		case shutdown_crm:
		case stonith_node:
		    break;
		case stop_rsc:
		case stopped_rsc:
		case action_demote:
		case action_demoted:
		    order->type |= pe_order_complex_left;
		    break;
		case start_rsc:
		case started_rsc:
		case action_promote:
		case action_promoted:
		    order->type |= pe_order_complex_right;
		    break;
	    }
	}
	
	native_rsc_order_rh(lh_action, rsc, order);
}

void group_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	GListPtr saved = constraint->node_list_rh;
	GListPtr zero = node_list_dup(constraint->node_list_rh, TRUE, FALSE);
	gboolean reset_scores = TRUE;
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_debug("Processing rsc_location %s for %s",
		  constraint->id, rsc->id);

	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		child_rsc->cmds->rsc_location(child_rsc, constraint);
		if(group_data->colocated && reset_scores) {
			reset_scores = FALSE;
			constraint->node_list_rh = zero;
		}
		);

	constraint->node_list_rh = saved;
	pe_free_shallow_adv(zero, TRUE);
}

void group_expand(resource_t *rsc, pe_working_set_t *data_set)
{
	group_variant_data_t *group_data = NULL;
	get_group_variant_data(group_data, rsc);

	crm_debug_3("Processing actions from %s", rsc->id);

	CRM_CHECK(rsc != NULL, return);
	native_expand(rsc, data_set);
	
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		child_rsc->cmds->expand(child_rsc, data_set);
		);

}

GListPtr
group_merge_weights(
    resource_t *rsc, const char *rhs, GListPtr nodes, const char *attr, int factor, gboolean allow_rollback)
{
    group_variant_data_t *group_data = NULL;
    get_group_variant_data(group_data, rsc);
    
    if(is_set(rsc->flags, pe_rsc_merging)) {
	crm_debug("Breaking dependancy loop with %s at %s", rsc->id, rhs);
	return nodes;

    } else if(is_not_set(rsc->flags, pe_rsc_provisional)) {
	return nodes;
    }

    set_bit(rsc->flags, pe_rsc_merging);

    nodes = group_data->first_child->cmds->merge_weights(
	group_data->first_child, rhs, nodes, attr, factor, allow_rollback);
    
    slist_iter(
	constraint, rsc_colocation_t, rsc->rsc_cons_lhs, lpc,
	
	nodes = native_merge_weights(
	    constraint->rsc_lh, rsc->id, nodes,
	    constraint->node_attribute,
	    constraint->score/INFINITY, allow_rollback);
	);

    clear_bit(rsc->flags, pe_rsc_merging);
    return nodes;
}

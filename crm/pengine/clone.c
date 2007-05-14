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

#include <lha_internal.h>

#include <crm/msg_xml.h>
#include <allocate.h>
#include <utils.h>
#include <lib/crm/pengine/utils.h>

#define VARIANT_CLONE 1
#include <lib/crm/pengine/variant.h>

gint sort_clone_instance(gconstpointer a, gconstpointer b);

void clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set);

void child_stopping_constraints(
	clone_variant_data_t *clone_data, 
	resource_t *self, resource_t *child, resource_t *last,
	pe_working_set_t *data_set);

void child_starting_constraints(
	clone_variant_data_t *clone_data, 
	resource_t *self, resource_t *child, resource_t *last,
	pe_working_set_t *data_set);

void clone_set_cmds(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	clone_data->self->cmds = &resource_class_alloc_functions[clone_data->self->variant];
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		child_rsc->cmds = &resource_class_alloc_functions[child_rsc->variant];
		child_rsc->cmds->set_cmds(child_rsc);
		);
}

int clone_num_allowed_nodes(resource_t *rsc)
{
	gboolean unimplimented = FALSE;
	CRM_ASSERT(unimplimented);
	return 0;
}

static node_t *
parent_node_instance(const resource_t *rsc, node_t *node)
{
	node_t *ret = NULL;
	if(node != NULL) {
		ret = pe_find_node_id(
			rsc->parent->allowed_nodes, node->details->id);
	}
	return ret;
}

gint sort_clone_instance(gconstpointer a, gconstpointer b)
{
	int level = LOG_DEBUG_3;
	node_t *node1 = NULL;
	node_t *node2 = NULL;

	gboolean can1 = TRUE;
	gboolean can2 = TRUE;
	
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	CRM_ASSERT(resource1 != NULL);
	CRM_ASSERT(resource2 != NULL);

	/* allocation order:
	 *  - active instances
	 *  - instances running on nodes with the least copies
	 *  - active instances on nodes that cant support them or are to be fenced
	 *  - failed instances
	 *  - inactive instances
	 */	

	do_crm_log(level+1, "%s ? %s", resource1->id, resource2->id);
	if(resource1->running_on && resource2->running_on) {
		if(g_list_length(resource1->running_on) < g_list_length(resource2->running_on)) {
			do_crm_log(level, "%s < %s: running_on", resource1->id, resource2->id);
			return -1;
			
		} else if(g_list_length(resource1->running_on) > g_list_length(resource2->running_on)) {
			do_crm_log(level, "%s > %s: running_on", resource1->id, resource2->id);
			return 1;
		}
	}
	
	if(resource1->running_on) {
		node1 = resource1->running_on->data;
	}
	if(resource2->running_on) {
		node2 = resource2->running_on->data;
	}
	
	if(node1 != node2) {
		if(node1 == NULL) {
			do_crm_log(level, "%s > %s: active", resource1->id, resource2->id);
			return 1;
		} else if(node2 == NULL) {
			do_crm_log(level, "%s < %s: active", resource1->id, resource2->id);
			return -1;
		}
	}
	
	can1 = can_run_resources(node1);
	can2 = can_run_resources(node2);
	if(can1 != can2) {
		if(can1) {
			do_crm_log(level, "%s < %s: can", resource1->id, resource2->id);
			return -1;
		}
		do_crm_log(level, "%s > %s: can", resource1->id, resource2->id);
		return 1;
	}

	node1 = parent_node_instance(resource1, node1);
	node2 = parent_node_instance(resource2, node2);
	if(node1 != NULL && node2 == NULL) {
		do_crm_log(level, "%s < %s: not allowed", resource1->id, resource2->id);
		return -1;
	} else if(node1 == NULL && node2 != NULL) {
		do_crm_log(level, "%s > %s: not allowed", resource1->id, resource2->id);
		return 1;
	}
	
	if(node1 == NULL) {
		do_crm_log(level, "%s == %s: not allowed", resource1->id, resource2->id);
		return 0;
	}

	if(node1->count < node2->count) {
		do_crm_log(level, "%s < %s: count", resource1->id, resource2->id);
		return -1;

	} else if(node1->count > node2->count) {
		do_crm_log(level, "%s > %s: count", resource1->id, resource2->id);
		return 1;
	}

	if(node1->weight < node2->weight) {
		do_crm_log(level, "%s < %s: score", resource1->id, resource2->id);
		return 1;

	} else if(node1->weight > node2->weight) {
		do_crm_log(level, "%s > %s: score", resource1->id, resource2->id);
		return -1;
	}
	
	do_crm_log(level, "%s == %s: default", resource1->id, resource2->id);
	return 0;
}

static node_t *
can_run_instance(resource_t *rsc, node_t *node)
{
	node_t *local_node = NULL;
	clone_variant_data_t *clone_data = NULL;
	if(can_run_resources(node) == FALSE) {
		goto bail;
	}	

	local_node = parent_node_instance(rsc, node);
	get_clone_variant_data(clone_data, rsc->parent);

	if(local_node == NULL) {
		crm_warn("%s cannot run on %s: node not allowed",
			rsc->id, node->details->uname);
		goto bail;

	} else if(local_node->count < clone_data->clone_node_max) {
		return local_node;

	} else {
		crm_debug_2("%s cannot run on %s: node full",
			    rsc->id, node->details->uname);
	}

  bail:
	if(node) {
		node->weight = -INFINITY;
	}
	return NULL;
}


static node_t *
color_instance(resource_t *rsc, pe_working_set_t *data_set) 
{
	node_t *local_node = NULL;
	node_t *chosen = NULL;

	crm_info("Processing %s", rsc->id);

	if(rsc->provisional == FALSE) {
		return rsc->allocated_to;

	} else if(rsc->is_allocating) {
		crm_debug("Dependancy loop detected involving %s", rsc->id);
		return NULL;
	}

	if(rsc->allowed_nodes) {
		slist_iter(try_node, node_t, rsc->allowed_nodes, lpc,
			   if(can_run_instance(rsc, try_node) == NULL) {
				   try_node->weight = -INFINITY;
			   }
			);
	}

	chosen = rsc->cmds->color(rsc, data_set);
	if(chosen) {
		local_node = pe_find_node_id(
			rsc->parent->allowed_nodes, chosen->details->id);

		if(local_node == NULL) {
			crm_err("%s not found in %s (list=%d)",
				chosen->details->id, rsc->parent->id,
				g_list_length(rsc->parent->allowed_nodes));
			exit(1);
		}
		CRM_ASSERT(local_node);
		local_node->count++;
	}

	return chosen;
}


node_t *
clone_color(resource_t *rsc, pe_working_set_t *data_set)
{
	int allocated = 0;
	resource_t *first_child = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	if(rsc->provisional == FALSE) {
		return NULL;

	} else if(rsc->is_allocating) {
		crm_debug("Dependancy loop detected involving %s", rsc->id);
		return NULL;
	}

	rsc->is_allocating = TRUE;
	crm_debug("Processing %s", rsc->id);
	
	if(TRUE/* rsc->stickiness */) {
		/* count now tracks the number of clones currently allocated */
		slist_iter(node, node_t, rsc->allowed_nodes, lpc,
			   node->count = 0;
			);
		
		slist_iter(child, resource_t, clone_data->child_list, lpc,
			   if(g_list_length(child->running_on) > 0) {
				   node_t *child_node = child->running_on->data;
				   node_t *local_node = parent_node_instance(
					   child, child->running_on->data);
				   if(local_node) {
					   local_node->count++;
				   } else {
					   crm_err("%s is running on %s which isn't allowed",
						   child->id, child_node->details->uname);
				   }
			   }
			);

		clone_data->child_list = g_list_sort(
			clone_data->child_list, sort_clone_instance);
	}

	/* count now tracks the number of clones we have allocated */
	slist_iter(node, node_t, rsc->allowed_nodes, lpc,
		   node->count = 0;
		);

	
	first_child = clone_data->child_list->data;
	first_child->rsc_cons = g_list_concat(
		first_child->rsc_cons, rsc->rsc_cons);
	rsc->rsc_cons = NULL;

	rsc->allowed_nodes = g_list_sort(
		rsc->allowed_nodes, sort_node_weight);

	
	slist_iter(child, resource_t, clone_data->child_list, lpc,
		   if(allocated >= clone_data->clone_max) {
			   crm_debug("Child %s not allocated - limit reached", child->id);
			   resource_location(child, NULL, -INFINITY, "clone_color:limit_reached", data_set);
		   }
		   if(color_instance(child, data_set)) {
			   allocated++;
		   }
		);

	crm_debug("Allocated %d %s instances of a possible %d",
		  allocated, rsc->id, clone_data->clone_max);

	rsc->provisional = FALSE;
	rsc->is_allocating = FALSE;
	
	return NULL;
}

static void
clone_update_pseudo_status(
	resource_t *child, gboolean *stopping, gboolean *starting) 
{
	CRM_ASSERT(stopping != NULL);
	CRM_ASSERT(starting != NULL);

	slist_iter(
		action, action_t, child->actions, lpc,

		if(*starting && *stopping) {
			return;

		} else if(action->optional) {
			crm_debug_3("Skipping optional: %s", action->uuid);
			continue;

		} else if(action->pseudo == FALSE && action->runnable == FALSE){
			crm_debug_3("Skipping unrunnable: %s", action->uuid);
			continue;

		} else if(safe_str_eq(CRMD_ACTION_STOP, action->task)) {
			crm_debug_2("Stopping due to: %s", action->uuid);
			*stopping = TRUE;

		} else if(safe_str_eq(CRMD_ACTION_START, action->task)) {
			if(action->runnable == FALSE) {
				crm_debug_3("Skipping pseudo-op: %s run=%d, pseudo=%d",
					    action->uuid, action->runnable, action->pseudo);
			} else {
				crm_debug_2("Starting due to: %s", action->uuid);
				crm_debug_3("%s run=%d, pseudo=%d",
					    action->uuid, action->runnable, action->pseudo);
				*starting = TRUE;
			}
		}
		);

}

void clone_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	gboolean child_starting = FALSE;
	gboolean child_stopping = FALSE;
	action_t *stop = NULL;
	action_t *start = NULL;
	action_t *action_complete = NULL;
	resource_t *last_start_rsc = NULL;
	resource_t *last_stop_rsc = NULL;
	clone_variant_data_t *clone_data = NULL;

	get_clone_variant_data(clone_data, rsc);

	crm_debug_2("Creating actions for %s", rsc->id);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		child_rsc->cmds->create_actions(child_rsc, data_set);
		clone_update_pseudo_status(
			child_rsc, &child_stopping, &child_starting);
		
		if(child_rsc->starting) {
			last_start_rsc = child_rsc;
		}
		if(child_rsc->stopping) {
			last_stop_rsc = child_rsc;
		}
		);

	/* start */
	start = start_action(rsc, NULL, !child_starting);
	action_complete = custom_action(
		rsc, started_key(rsc),
		CRMD_ACTION_STARTED, NULL, !child_starting, TRUE, data_set);

	start->pseudo = TRUE;
	start->runnable = TRUE;
	action_complete->pseudo = TRUE;
	action_complete->runnable = TRUE;
	action_complete->priority = INFINITY;
/* 	crm_err("Upgrading priority for %s to INFINITY", action_complete->uuid); */
	
	child_starting_constraints(clone_data, rsc, NULL, last_start_rsc, data_set);

	clone_create_notifications(
		rsc, start, action_complete, data_set);	


	/* stop */
	stop = stop_action(rsc, NULL, !child_stopping);
	action_complete = custom_action(
		rsc, stopped_key(rsc),
		CRMD_ACTION_STOPPED, NULL, !child_stopping, TRUE, data_set);

	stop->pseudo = TRUE;
	stop->runnable = TRUE;
	action_complete->pseudo = TRUE;
	action_complete->runnable = TRUE;
	action_complete->priority = INFINITY;
/* 	crm_err("Upgrading priority for %s to INFINITY", action_complete->uuid); */
	
	child_stopping_constraints(clone_data, rsc, NULL, last_stop_rsc, data_set);

	
	clone_create_notifications(rsc, stop, action_complete, data_set);	
	rsc->actions = rsc->actions;	

	if(stop->post_notified != NULL && start->pre_notify != NULL) {
		order_actions(stop->post_notified, start->pre_notify, pe_order_optional);	
	}
}

void
clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set)
{
	/*
	 * pre_notify -> pre_notify_complete -> pseudo_action
	 *   -> (real actions) -> pseudo_action_complete
	 *   -> post_notify -> post_notify_complete
	 *
	 * if the pre_noitfy requires confirmation,
	 *   then a list of confirmations will be added as triggers
	 *   to pseudo_action in clone_expand()
	 */
	action_t *notify = NULL;
	action_t *notify_complete = NULL;
	enum action_tasks task;
	char *notify_key = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	
	if(rsc->notify == FALSE) {
		return;
	}
	
	task = text2task(action->task);

	/* create pre_notify */
	notify_key = generate_notify_key(
		rsc->id, "pre", action->task);
	notify = custom_action(rsc, notify_key,
			       CRMD_ACTION_NOTIFY, NULL,
			       action->optional, TRUE, data_set);
	
	add_hash_param(notify->meta, "notify_type", "pre");
	add_hash_param(notify->meta, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->meta, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->meta, "notify_confirm", "no");
	}

	/* create pre_notify_complete */
	notify_key = generate_notify_key(
		rsc->id, "confirmed-pre", action->task);
	notify_complete = custom_action(rsc, notify_key,
			       CRMD_ACTION_NOTIFIED, NULL,
			       action->optional, TRUE, data_set);
	add_hash_param(notify_complete->meta, "notify_type", "pre");
	add_hash_param(notify_complete->meta, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->meta, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->meta, "notify_confirm", "no");
	}
	notify->pseudo = TRUE;
	notify->runnable = TRUE;
	notify_complete->pseudo = TRUE;
	notify_complete->runnable = TRUE;

	/* pre_notify before pre_notify_complete */
	custom_action_order(
		rsc, NULL, notify,
		rsc, NULL, notify_complete,
		pe_order_implies_left, data_set);
	
	/* pre_notify_complete before action */
	custom_action_order(
		rsc, NULL, notify_complete,
		rsc, NULL, action,
		pe_order_implies_left, data_set);

	action->pre_notify = notify;
	action->pre_notified = notify_complete;
	
	/* create post_notify */
	notify_key = generate_notify_key
		(rsc->id, "post", action->task);
	notify = custom_action(rsc, notify_key,
			       CRMD_ACTION_NOTIFY, NULL,
			       action_complete->optional, TRUE, data_set);
	add_hash_param(notify->meta, "notify_type", "post");
	add_hash_param(notify->meta, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->meta, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->meta, "notify_confirm", "no");
	}

	/* action_complete before post_notify */
	custom_action_order(
		rsc, NULL, action_complete,
		rsc, NULL, notify, 
		pe_order_implies_right, data_set);
	
	/* create post_notify_complete */
	notify_key = generate_notify_key(
		rsc->id, "confirmed-post", action->task);
	notify_complete = custom_action(rsc, notify_key,
			       CRMD_ACTION_NOTIFIED, NULL,
			       action->optional, TRUE, data_set);
	add_hash_param(notify_complete->meta, "notify_type", "pre");
	add_hash_param(notify_complete->meta, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->meta, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->meta, "notify_confirm", "no");
	}

	notify->pseudo = TRUE;
	notify->runnable = TRUE;
	notify->priority = INFINITY;
/* 	crm_err("Upgrading priority for %s to INFINITY", notify->uuid); */

	notify_complete->pseudo = TRUE;
	notify_complete->runnable = TRUE;
	notify_complete->priority = INFINITY;
/* 	crm_err("Upgrading priority for %s to INFINITY", notify_complete->uuid); */

	/* post_notify before post_notify_complete */
	custom_action_order(
		rsc, NULL, notify,
		rsc, NULL, notify_complete,
		pe_order_implies_left, data_set);

	action->post_notify = notify;
	action->post_notified = notify_complete;


	if(safe_str_eq(action->task, CRMD_ACTION_STOP)) {
		/* post_notify_complete before start */
		custom_action_order(
			rsc, NULL, notify_complete,
			rsc, start_key(rsc), NULL,
			pe_order_optional, data_set);

	} else if(safe_str_eq(action->task, CRMD_ACTION_START)) {
		/* post_notify_complete before promote */
		custom_action_order(
			rsc, NULL, notify_complete,
			rsc, promote_key(rsc), NULL,
			pe_order_optional, data_set);

	} else if(safe_str_eq(action->task, CRMD_ACTION_DEMOTE)) {
		/* post_notify_complete before promote */
		custom_action_order(
			rsc, NULL, notify_complete,
			rsc, stop_key(rsc), NULL,
			pe_order_optional, data_set);
	}
}

void
child_starting_constraints(
	clone_variant_data_t *clone_data,
	resource_t *rsc, resource_t *child, resource_t *last,
	pe_working_set_t *data_set)
{
	if(child != NULL) {
		order_start_start(rsc, child, pe_order_optional);
		
		custom_action_order(
			child, start_key(child), NULL,
			rsc, started_key(rsc), NULL,
			pe_order_optional, data_set);
	}
	
	if(clone_data->ordered) {
		if(child == NULL) {
			/* last child start before global started */
			custom_action_order(
				last, start_key(last), NULL,
				rsc, started_key(rsc), NULL,
				pe_order_runnable_left, data_set);

		} else if(last == NULL) {
			/* global start before first child start */
			order_start_start(
				rsc, child, pe_order_implies_left);

		} else {
			/* child/child relative start */
			order_start_start(last, child, pe_order_implies_left);
		}
	}
}

void
child_stopping_constraints(
	clone_variant_data_t *clone_data,
	resource_t *rsc, resource_t *child, resource_t *last,
	pe_working_set_t *data_set)
{
	if(child != NULL) {
		order_stop_stop(rsc, child, pe_order_optional);
		
		custom_action_order(
			child, stop_key(child), NULL,
			rsc, stopped_key(rsc), NULL,
			pe_order_optional, data_set);
	}
	
	if(clone_data->ordered) {
		if(last == NULL) {
			/* first child stop before global stopped */
			custom_action_order(
				child, stop_key(child), NULL,
				rsc, stopped_key(rsc), NULL,
				pe_order_runnable_left, data_set);
			
		} else if(child == NULL) {
			/* global stop before last child stop */
			order_stop_stop(
				rsc, last, pe_order_implies_left);
		} else {
			/* child/child relative stop */
			order_stop_stop(child, last, pe_order_implies_left);
		}
	}
}


void
clone_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	resource_t *last_rsc = NULL;	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	native_internal_constraints(rsc, data_set);
	
	/* global stop before stopped */
	custom_action_order(
		rsc, stop_key(rsc), NULL,
		rsc, stopped_key(rsc), NULL,
		pe_order_runnable_left, data_set);

	/* global start before started */
	custom_action_order(
		rsc, start_key(rsc), NULL,
		rsc, started_key(rsc), NULL,
		pe_order_runnable_left, data_set);
	
	/* global stopped before start */
	custom_action_order(
		rsc, stopped_key(rsc), NULL,
		rsc, start_key(rsc), NULL,
		pe_order_optional, data_set);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		child_rsc->cmds->internal_constraints(child_rsc, data_set);

		child_starting_constraints(
			clone_data, rsc, child_rsc, last_rsc, data_set);

		child_stopping_constraints(
			clone_data, rsc, child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		);
}

static resource_t*
find_compatible_child(resource_t *local_child, resource_t *rsc)
{
	node_t *local_node = NULL;
	node_t *node = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	
	local_node = local_child->allocated_to;
	if(local_node == NULL) {
		crm_debug("Can't colocate unrunnable child %s with %s",
			 local_child->id, rsc->id);
		return NULL;
	}
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		node = child_rsc->allocated_to;
		if(node->details == local_node->details) {
			crm_info("Colocating %s with %s on %s",
				 local_child->id, child_rsc->id, node->details->uname);
			return child_rsc;
		}
		);
	crm_debug("Can't colocate child %s with %s",
		 local_child->id, rsc->id);
	return NULL;
}

void clone_rsc_colocation_lh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	gboolean do_interleave = FALSE;
	resource_t *rsc = constraint->rsc_lh;
	clone_variant_data_t *clone_data = NULL;
	clone_variant_data_t *clone_data_rh = NULL;
	
	if(rsc == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(constraint->rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else {
		crm_debug_4("Processing constraints from %s", rsc->id);
	}
	
	get_clone_variant_data(clone_data, rsc);

	if(constraint->rsc_rh->variant == pe_clone) {
		get_clone_variant_data(
			clone_data_rh, constraint->rsc_rh);
		if(clone_data->clone_node_max
		   != clone_data_rh->clone_node_max) {
			crm_config_err("Cannot interleave "XML_CIB_TAG_INCARNATION
				       " %s and %s because"
				       " they do not support the same number of"
					" resources per node",
				       constraint->rsc_lh->id, constraint->rsc_rh->id);
			
		/* only the LHS side needs to be labeled as interleave */
		} else if(clone_data->interleave) {
			do_interleave = TRUE;

		} else if(constraint->score >= INFINITY) {
			GListPtr lhs = NULL, rhs = NULL;
			lhs = rsc_lh->allowed_nodes;
			
			slist_iter(
				child_rsc, resource_t, clone_data_rh->child_list, lpc,
				if(child_rsc->allocated_to != NULL) {
					rhs = g_list_append(rhs, child_rsc->allocated_to);
				}
				);
			
			rsc_lh->allowed_nodes = node_list_and(lhs, rhs, FALSE);
			
			pe_free_shallow_adv(rhs, FALSE);
			pe_free_shallow(lhs);
			return;
		}

	} else if(constraint->score >= INFINITY) {
		crm_config_err("Manditory co-location of clones (%s) with other"
			       " non-clone (%s) resources is not supported",
			       rsc_lh->id, rsc_rh->id);
		return;
	}
	
	if(do_interleave) {
		resource_t *rh_child = NULL;
		
		slist_iter(lh_child, resource_t, clone_data->child_list, lpc,

			   CRM_ASSERT(lh_child != NULL);
			   rh_child = find_compatible_child(lh_child, rsc_rh);
			   if(rh_child == NULL) {
				   continue;
			   }
			   lh_child->cmds->rsc_colocation_lh(
				   lh_child, rh_child, constraint);
			);
		return;
	}
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->cmds->rsc_colocation_lh(child_rsc, constraint->rsc_rh, constraint);
		);
}



void clone_rsc_colocation_rh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	CRM_CHECK(rsc_lh != NULL, return);
	CRM_CHECK(rsc_lh->variant == pe_native, return);
	
	get_clone_variant_data(clone_data, rsc_rh);
	
	crm_debug_3("Processing constraint %s: %d", constraint->id, constraint->score);

	if(rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else if(rsc_rh->provisional) {
		crm_debug_3("%s is still provisional", rsc_rh->id);
		return;
		
	} else if(constraint->score >= INFINITY) {
		GListPtr lhs = NULL, rhs = NULL;
		lhs = rsc_lh->allowed_nodes;
		
		slist_iter(
			child_rsc, resource_t, clone_data->child_list, lpc,
			if(child_rsc->allocated_to != NULL) {
				rhs = g_list_append(rhs, child_rsc->allocated_to);
			}
			);

		rsc_lh->allowed_nodes = node_list_and(lhs, rhs, FALSE);

		pe_free_shallow_adv(rhs, FALSE);
		pe_free_shallow(lhs);
		return;
	}

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->cmds->rsc_colocation_rh(rsc_lh, child_rsc, constraint);
		);
}

void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order, pe_working_set_t *data_set)
{
	resource_t *r1 = NULL;
	resource_t *r2 = NULL;	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_2("%s->%s", order->lh_action_task, order->rh_action_task);
	
	r1 = uber_parent(rsc);
	r2 = uber_parent(order->rh_rsc);
	
	if(r1 == r2) {
		native_rsc_order_lh(rsc, order, data_set);
		return;
	}

#if 0
	if(order->type != pe_order_optional) {
		crm_debug("Upgraded ordering constraint %d - 0x%.6x", order->id, order->type);
		native_rsc_order_lh(rsc, order, data_set);
	}
#endif
	
	if(order->type & pe_order_implies_left) {
		if(rsc->variant == order->rh_rsc->variant) {
			crm_err("Clone-to-clone ordering: %s -> %s 0x%.6x",
				order->lh_action_task, order->rh_action_task, order->type);
			/* stop instances on the same nodes as stopping RHS instances */
			slist_iter(
				child_rsc, resource_t, clone_data->child_list, lpc,
				native_rsc_order_lh(child_rsc, order, data_set);
				);
		} else {
			/* stop everything */
			crm_err("Clone-to-* ordering: %s -> %s 0x%.6x",
				order->lh_action_task, order->rh_action_task, order->type);
			slist_iter(
				child_rsc, resource_t, clone_data->child_list, lpc,
				native_rsc_order_lh(child_rsc, order, data_set);
				);
		}
	}

	convert_non_atomic_task(rsc, order);
	native_rsc_order_lh(rsc, order, data_set);
}

void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_2("%s->%s", lh_action->uuid, order->rh_action_task);

 	native_rsc_order_rh(lh_action, rsc, order);

}

void clone_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing location constraint %s for %s",
		    constraint->id, rsc->id);

	native_rsc_location(rsc, constraint);
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		child_rsc->cmds->rsc_location(child_rsc, constraint);
		);
}

static gint
sort_notify_entries(gconstpointer a, gconstpointer b)
{
	int tmp;
	const notify_entry_t *entry_a = a;
	const notify_entry_t *entry_b = b;

	if(entry_a == NULL && entry_b == NULL) { return 0; }
	if(entry_a == NULL) { return 1; }
	if(entry_b == NULL) { return -1; }

	if(entry_a->rsc == NULL && entry_b->rsc == NULL) { return 0; }
	if(entry_a->rsc == NULL) { return 1; }
	if(entry_b->rsc == NULL) { return -1; }

	tmp = strcmp(entry_a->rsc->id, entry_b->rsc->id);
	if(tmp != 0) {
		return tmp;
	}

	if(entry_a->node == NULL && entry_b->node == NULL) { return 0; }
	if(entry_a->node == NULL) { return 1; }
	if(entry_b->node == NULL) { return -1; }

	return strcmp(entry_a->node->details->id, entry_b->node->details->id);
}

static void
expand_list(GListPtr list, int clones,
	    char **rsc_list, char **node_list, char **uuid_list)
{
	const char *uname = NULL;
	const char *rsc_id = NULL;
	const char *last_rsc_id = NULL;
	
	CRM_CHECK(list != NULL, return);
	if(rsc_list) {
		CRM_CHECK(*rsc_list == NULL, *rsc_list = NULL);
	}
	if(node_list) {
		CRM_CHECK(*node_list == NULL, *node_list = NULL);
	}
	
	slist_iter(entry, notify_entry_t, list, lpc,

		   CRM_CHECK(entry != NULL, continue);
		   rsc_id = entry->rsc->id;
		   CRM_CHECK(rsc_id != NULL, rsc_id = "__none__");
		   uname = NULL;
		   if(entry->node) {
			   uname = entry->node->details->uname;
		   }
		   CRM_CHECK(uname != NULL, uname = "__none__");

		   /* filter dups */
		   if(safe_str_eq(rsc_id, last_rsc_id)) {
			   continue;
		   }
		   last_rsc_id = rsc_id;

		   if(rsc_list != NULL) {
			   int existing_len = 0;
			   int len = 2 + strlen(rsc_id); /* +1 space, +1 EOS */
			   if(rsc_list && *rsc_list) {
				   existing_len = strlen(*rsc_list);
			   }

			   crm_debug_5("Adding %s (%dc) at offset %d",
				       rsc_id, len-2, existing_len);
			   crm_realloc(*rsc_list, len + existing_len);
			   sprintf(*rsc_list + existing_len, "%s ", rsc_id);
		   }
		   
		   if(node_list != NULL) {
			   int existing_len = 0;
			   int len = 2 + strlen(uname);
			   if(node_list && *node_list) {
				   existing_len = strlen(*node_list);
			   }
			   
			   crm_debug_5("Adding %s (%dc) at offset %d",
				       uname, len-2, existing_len);
			   crm_realloc(*node_list, len + existing_len);
			   sprintf(*node_list + existing_len, "%s ", uname);
		   }
		   );
}

void clone_expand(resource_t *rsc, pe_working_set_t *data_set)
{
	char *rsc_list = NULL;
	char *node_list = NULL;
	char *uuid_list = NULL;	

	notify_data_t *n_data = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_malloc0(n_data, sizeof(notify_data_t));
	n_data->keys = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	
	crm_debug_2("Processing actions from %s", rsc->id);

	
	if(rsc->notify) {
		slist_iter(
			child_rsc, resource_t, clone_data->child_list, lpc,
			
			slist_iter(
				op, action_t, rsc->actions, lpc2,
			
				child_rsc->cmds->create_notify_element(
					child_rsc, op, n_data, data_set);
				);
			);
	}
	
	/* expand the notify data */		
	if(rsc->notify && n_data->stop) {
		n_data->stop = g_list_sort(
			n_data->stop, sort_notify_entries);
		rsc_list = NULL; node_list = NULL;
		expand_list(n_data->stop, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_stop_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_stop_uname"), node_list);
	}

	if(rsc->notify && n_data->start) {
		n_data->start = g_list_sort(
			n_data->start, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; 
		expand_list(n_data->start, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_start_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_start_uname"), node_list);
	}
	
	if(rsc->notify && n_data->demote) {
		n_data->demote = g_list_sort(
			n_data->demote, sort_notify_entries);
		rsc_list = NULL; node_list = NULL;
		expand_list(n_data->demote, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_demote_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_demote_uname"), node_list);
	}
	
	if(rsc->notify && n_data->promote) {
		n_data->promote = g_list_sort(
			n_data->promote, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; uuid_list = NULL;
		expand_list(n_data->promote, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_promote_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_promote_uname"), node_list);
	}
	
	if(rsc->notify && n_data->active) {
		n_data->active = g_list_sort(
			n_data->active, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; uuid_list = NULL;
		expand_list(n_data->active, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_active_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_active_uname"), node_list);
	}

	if(rsc->notify && n_data->slave) {
		n_data->slave = g_list_sort(
			n_data->slave, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; uuid_list = NULL;
		expand_list(n_data->slave, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_slave_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_slave_uname"), node_list);
	}

	if(rsc->notify && n_data->master) {
		n_data->master = g_list_sort(
			n_data->master, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; uuid_list = NULL;
		expand_list(n_data->master, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_master_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_master_uname"), node_list);
	}

	if(rsc->notify && n_data->inactive) {
		n_data->inactive = g_list_sort(
			n_data->inactive, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; uuid_list = NULL;
		expand_list(n_data->inactive, clone_data->clone_max,
			    &rsc_list, &node_list, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_inactive_resource"), rsc_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_inactive_uname"), node_list);
	}
	
	/* yes, we DO need this second loop */
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->cmds->expand(child_rsc, data_set);

		);
	
/* 	slist_iter( */
/* 		action, action_t, rsc->actions, lpc2, */

/* 		if(safe_str_eq(action->task, CRMD_ACTION_NOTIFY)) { */
/* 			action->meta_xml = notify_xml; */
/* 		} */
/* 		); */
	
	native_expand(rsc, data_set);

	/* destroy the notify_data */
	pe_free_shallow(n_data->stop);
	pe_free_shallow(n_data->start);
	pe_free_shallow(n_data->demote);
	pe_free_shallow(n_data->promote);
	pe_free_shallow(n_data->master);
	pe_free_shallow(n_data->slave);
	pe_free_shallow(n_data->active);
	pe_free_shallow(n_data->inactive);
	g_hash_table_destroy(n_data->keys);
	crm_free(n_data);
}


void
clone_agent_constraints(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->cmds->agent_constraints(child_rsc);
		);
}

void
clone_create_notify_element(resource_t *rsc, action_t *op,
			    notify_data_t *n_data, pe_working_set_t *data_set)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->cmds->create_notify_element(
			child_rsc, op, n_data, data_set);
		);
}

static gint sort_rsc_id(gconstpointer a, gconstpointer b)
{
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	CRM_ASSERT(resource1 != NULL);
	CRM_ASSERT(resource2 != NULL);

	return strcmp(resource1->id, resource2->id);
}

gboolean
clone_create_probe(resource_t *rsc, node_t *node, action_t *complete,
		    gboolean force, pe_working_set_t *data_set) 
{
	gboolean any_created = FALSE;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	clone_data->child_list = g_list_sort(
		clone_data->child_list, sort_rsc_id);

	if(rsc->globally_unique == FALSE && clone_data->clone_node_max == 1) {
		/* only look for one copy */	 
		slist_iter(	 
			child_rsc, resource_t, clone_data->child_list, lpc,	 

			if(pe_find_node_id(child_rsc->running_on, node->details->id)) {	 
				return child_rsc->cmds->create_probe(
					child_rsc, node, complete, force, data_set);
			}
			);
	}
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		if(child_rsc->cmds->create_probe(
			   child_rsc, node, complete, force, data_set)) {
			any_created = TRUE;
		}
		
		if(any_created
		   && rsc->globally_unique == FALSE
		   && clone_data->clone_node_max == 1) {
			/* only look for one copy (clone :0) */	 
			break;
		}
		);

	return any_created;
}

void
clone_stonith_ordering(
	resource_t *rsc,  action_t *stonith_op, pe_working_set_t *data_set)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		child_rsc->cmds->stonith_ordering(
			child_rsc, stonith_op, data_set);
		);
}

void
clone_migrate_reload(resource_t *rsc, pe_working_set_t *data_set)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->cmds->migrate_reload(child_rsc, data_set);
		);
}

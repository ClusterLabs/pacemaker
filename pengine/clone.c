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

static gboolean did_fail(const resource_t *rsc)
{
    if(is_set(rsc->flags, pe_rsc_failed)) {
	return TRUE;
    }

    slist_iter(
	child_rsc, resource_t, rsc->children, lpc,
	if(did_fail(child_rsc)) {
	    return TRUE;
	}
	);
    return FALSE;
}


gint sort_clone_instance(gconstpointer a, gconstpointer b)
{
	int level = LOG_DEBUG_3;
	node_t *node1 = NULL;
	node_t *node2 = NULL;

	gboolean can1 = TRUE;
	gboolean can2 = TRUE;
	gboolean with_scores = TRUE;
	
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

	if(node1) {
	    node_t *match = pe_find_node_id(resource1->allowed_nodes, node1->details->id);
	    if(match == NULL || match->weight < 0) {
		do_crm_log(level, "%s: current location is unavailable", resource1->id);
		node1 = NULL;
		can1 = FALSE;
	    }
	}

	if(node2) {
	    node_t *match = pe_find_node_id(resource2->allowed_nodes, node2->details->id);
	    if(match == NULL || match->weight < 0) {
		do_crm_log(level, "%s: current location is unavailable", resource2->id);
		node2 = NULL;
		can2 = FALSE;
	    }
	}

	if(can1 != can2) {
		if(can1) {
			do_crm_log(level, "%s < %s: availability of current location", resource1->id, resource2->id);
			return -1;
		}
		do_crm_log(level, "%s > %s: availability of current location", resource1->id, resource2->id);
		return 1;
	}
	
	if(resource1->priority < resource2->priority) {
		do_crm_log(level, "%s < %s: priority", resource1->id, resource2->id);
		return 1;

	} else if(resource1->priority > resource2->priority) {
		do_crm_log(level, "%s > %s: priority", resource1->id, resource2->id);
		return -1;
	}
	
	if(node1 == NULL && node2 == NULL) {
			do_crm_log(level, "%s == %s: not active",
					   resource1->id, resource2->id);
			return 0;
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

	if(with_scores) {
	    int max = 0;
	    int lpc = 0;
	    GListPtr list1 = node_list_dup(resource1->allowed_nodes, FALSE, FALSE);
	    GListPtr list2 = node_list_dup(resource2->allowed_nodes, FALSE, FALSE);
	    
	    list1 = g_list_sort(list1, sort_node_weight);
	    list2 = g_list_sort(list2, sort_node_weight);
	    max = g_list_length(list1);
	    if(max < g_list_length(list2)) {
		max = g_list_length(list2);
	    }
	    
	    for(;lpc < max; lpc++) {
		node1 = g_list_nth_data(list1, lpc);
		node2 = g_list_nth_data(list2, lpc);
		if(node1 == NULL) {
		    do_crm_log(level, "%s < %s: node score NULL", resource1->id, resource2->id);
		    pe_free_shallow(list1); pe_free_shallow(list2);
		    return 1;
		} else if(node2 == NULL) {
		    do_crm_log(level, "%s > %s: node score NULL", resource1->id, resource2->id);
		    pe_free_shallow(list1); pe_free_shallow(list2);
		    return -1;
		}
		
		if(node1->weight < node2->weight) {
		    do_crm_log(level, "%s < %s: node score", resource1->id, resource2->id);
		    pe_free_shallow(list1); pe_free_shallow(list2);
		    return 1;
		    
		} else if(node1->weight > node2->weight) {
		    do_crm_log(level, "%s > %s: node score", resource1->id, resource2->id);
		    pe_free_shallow(list1); pe_free_shallow(list2);
		    return -1;
		}
	    }

	    pe_free_shallow(list1); pe_free_shallow(list2);
	}

	can1 = did_fail(resource1);
	can2 = did_fail(resource2);
	if(can1 != can2) {
	    if(can1) {
		do_crm_log(level, "%s > %s: failed", resource1->id, resource2->id);
		return 1;
	    }
	    do_crm_log(level, "%s < %s: failed", resource1->id, resource2->id);
	    return -1;
	}

	do_crm_log(level, "%s == %s: default %d", resource1->id, resource2->id, node2->weight);
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
	    common_update_score(rsc, node->details->id, -INFINITY);
	}
	return NULL;
}


static node_t *
color_instance(resource_t *rsc, pe_working_set_t *data_set) 
{
	node_t *chosen = NULL;
	node_t *local_node = NULL;

	crm_debug_2("Processing %s", rsc->id);

	if(is_not_set(rsc->flags, pe_rsc_provisional)) {
		return rsc->fns->location(rsc, NULL, FALSE);

	} else if(is_set(rsc->flags, pe_rsc_allocating)) {
		crm_debug("Dependancy loop detected involving %s", rsc->id);
		return NULL;
	}

	if(rsc->allowed_nodes) {
		slist_iter(try_node, node_t, rsc->allowed_nodes, lpc,
			   can_run_instance(rsc, try_node);
			);
	}

	chosen = rsc->cmds->color(rsc, data_set);
	if(chosen) {
		local_node = pe_find_node_id(
			rsc->parent->allowed_nodes, chosen->details->id);

		if(local_node) {
		    local_node->count++;
		} else if(is_set(rsc->flags, pe_rsc_managed)) {
		    /* what to do? we can't enforce per-node limits in this case */
		    crm_config_err("%s not found in %s (list=%d)",
				   chosen->details->id, rsc->parent->id,
				   g_list_length(rsc->parent->allowed_nodes));
		}
	}

	return chosen;
}

static void append_parent_colocation(resource_t *rsc, resource_t *child, gboolean all) 
{
    slist_iter(cons, rsc_colocation_t, rsc->rsc_cons, lpc,
	       if(all || cons->score < 0 || cons->score == INFINITY) {
		   child->rsc_cons = g_list_append(child->rsc_cons, cons);
	       }
	       
	);
    slist_iter(cons, rsc_colocation_t, rsc->rsc_cons_lhs, lpc,
	       if(all || cons->score < 0) {
		   child->rsc_cons_lhs = g_list_append(child->rsc_cons_lhs, cons);
	       }
	);
}

node_t *
clone_color(resource_t *rsc, pe_working_set_t *data_set)
{
	int allocated = 0;
	int available_nodes = 0;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	if(is_not_set(rsc->flags, pe_rsc_provisional)) {
		return NULL;

	} else if(is_set(rsc->flags, pe_rsc_allocating)) {
		crm_debug("Dependancy loop detected involving %s", rsc->id);
		return NULL;
	}

	set_bit(rsc->flags, pe_rsc_allocating);
	crm_debug_2("Processing %s", rsc->id);

	/* this information is used by sort_clone_instance() when deciding in which 
	 * order to allocate clone instances
	 */
	slist_iter(
	    constraint, rsc_colocation_t, rsc->rsc_cons_lhs, lpc,
	    
	    rsc->allowed_nodes = constraint->rsc_lh->cmds->merge_weights(
		constraint->rsc_lh, rsc->id, rsc->allowed_nodes,
		constraint->score/INFINITY, TRUE);
	    );
	
	dump_node_scores(scores_log_level, rsc, __FUNCTION__, rsc->allowed_nodes);
	
	/* count now tracks the number of clones currently allocated */
	slist_iter(node, node_t, rsc->allowed_nodes, lpc,
		   node->count = 0;
		);
	
	slist_iter(child, resource_t, rsc->children, lpc,
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
	
	rsc->children = g_list_sort(rsc->children, sort_clone_instance);

	/* count now tracks the number of clones we have allocated */
	slist_iter(node, node_t, rsc->allowed_nodes, lpc,
		   node->count = 0;
		);

	rsc->allowed_nodes = g_list_sort(
		rsc->allowed_nodes, sort_node_weight);


	slist_iter(node, node_t, rsc->allowed_nodes, lpc,
		   if(can_run_resources(node) == FALSE) {
		       available_nodes++;
		   }
	    );
	
	slist_iter(child, resource_t, rsc->children, lpc,
		   if(allocated >= clone_data->clone_max) {
			   crm_debug("Child %s not allocated - limit reached", child->id);
			   resource_location(child, NULL, -INFINITY, "clone_color:limit_reached", data_set);

		   } else if (clone_data->clone_max < available_nodes) {
		       /* Only include positive colocation preferences of dependant resources
			* if not every node will get a copy of the clone
			*/
		       append_parent_colocation(rsc, child, TRUE);

		   } else {
		       append_parent_colocation(rsc, child, FALSE);
		   }
		   
		   if(color_instance(child, data_set)) {
			   allocated++;
		   }
		);

	crm_debug("Allocated %d %s instances of a possible %d",
		  allocated, rsc->id, clone_data->clone_max);

	clear_bit(rsc->flags, pe_rsc_provisional);
	clear_bit(rsc->flags, pe_rsc_allocating);
	
	return NULL;
}

static void
clone_update_pseudo_status(
	resource_t *rsc, gboolean *stopping, gboolean *starting) 
{
	if(rsc->children) {
	    slist_iter(child, resource_t, rsc->children, lpc,
		       clone_update_pseudo_status(child, stopping, starting)
		);
	    return;
	}
    
	CRM_ASSERT(stopping != NULL);
	CRM_ASSERT(starting != NULL);

	slist_iter(
		action, action_t, rsc->actions, lpc,

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
		child_rsc, resource_t, rsc->children, lpc,
		child_rsc->cmds->create_actions(child_rsc, data_set);
		clone_update_pseudo_status(
			child_rsc, &child_stopping, &child_starting);
		
		if(is_set(child_rsc->flags, pe_rsc_starting)) {
			last_start_rsc = child_rsc;
		}
		if(is_set(child_rsc->flags, pe_rsc_stopping)) {
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
	
	if(is_not_set(rsc->flags, pe_rsc_notify)) {
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
		pe_order_optional, data_set);
	
	/* pre_notify_complete before action */
	custom_action_order(
		rsc, NULL, notify_complete,
		rsc, NULL, action,
		pe_order_optional, data_set);

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
		pe_order_optional, data_set);
	
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
	notify->runnable = action_complete->runnable;

	notify_complete->pseudo = TRUE;
	notify_complete->runnable = TRUE;
	notify_complete->priority = INFINITY;
 	notify_complete->runnable = action_complete->runnable;

	/* post_notify before post_notify_complete */
	custom_action_order(
		rsc, NULL, notify,
		rsc, NULL, notify_complete,
		pe_order_optional, data_set);

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
	if(child == NULL && last == NULL) {
	    crm_debug("%s has no active children", rsc->id);
	    return;
	}
    
	if(child != NULL) {
		order_start_start(
		    rsc, child, pe_order_runnable_left|pe_order_implies_left_printed);
		
		custom_action_order(
			child, start_key(child), NULL,
			rsc, started_key(rsc), NULL,
			pe_order_implies_right_printed, data_set);
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
	if(child == NULL && last == NULL) {
	    crm_debug("%s has no active children", rsc->id);
	    return;
	}

	if(child != NULL) {
		order_stop_stop(rsc, child, pe_order_shutdown|pe_order_implies_left_printed);
		
		custom_action_order(
			child, stop_key(child), NULL,
			rsc, stopped_key(rsc), NULL,
			pe_order_implies_right_printed, data_set);
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
		child_rsc, resource_t, rsc->children, lpc,

		child_rsc->cmds->internal_constraints(child_rsc, data_set);

		child_starting_constraints(
			clone_data, rsc, child_rsc, last_rsc, data_set);

		child_stopping_constraints(
			clone_data, rsc, child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		);
}

resource_t*
find_compatible_child(
    resource_t *local_child, resource_t *rsc, enum rsc_role_e filter, gboolean current)
{
	node_t *local_node = NULL;
	node_t *node = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	
	local_node = local_child->fns->location(local_child, NULL, current);
	if(local_node == NULL) {
		crm_debug("Can't colocate unrunnable child %s with %s",
			 local_child->id, rsc->id);
		return NULL;
	}
	
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		enum rsc_role_e next_role = child_rsc->fns->state(child_rsc, current);
		node = child_rsc->fns->location(child_rsc, NULL, current);

		if(filter != RSC_ROLE_UNKNOWN && next_role != filter) {
		    crm_debug_2("Filtered %s", child_rsc->id);
		    continue;
		}
		
		if(node && local_node && node->details == local_node->details) {
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

	if(constraint->rsc_rh->variant == pe_clone
	    || constraint->rsc_rh->variant == pe_master) {
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
				child_rsc, resource_t, rsc_rh->children, lpc,
				node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);
				if(chosen != NULL) {
					rhs = g_list_append(rhs, chosen);
				}
				);
			
			rsc_lh->allowed_nodes = node_list_exclude(lhs, rhs);
			
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
		
		slist_iter(lh_child, resource_t, rsc->children, lpc,

			   CRM_ASSERT(lh_child != NULL);
			   rh_child = find_compatible_child(
			       lh_child, rsc_rh, RSC_ROLE_UNKNOWN, FALSE);
			   if(rh_child == NULL) {
			       crm_debug_2("No match found for %s", lh_child->id);
			       continue;
			   }
			   crm_debug("Interleaving %s with %s", lh_child->id, rh_child->id);
			   lh_child->cmds->rsc_colocation_lh(
				   lh_child, rh_child, constraint);
			);
		return;
	}
	
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		
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
		
	} else if(is_set(rsc_rh->flags, pe_rsc_provisional)) {
		crm_debug_3("%s is still provisional", rsc_rh->id);
		return;
		
	} else if(constraint->score >= INFINITY) {
		GListPtr lhs = NULL, rhs = NULL;
		lhs = rsc_lh->allowed_nodes;
		
		slist_iter(
			child_rsc, resource_t, rsc_rh->children, lpc,
			node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);
			if(chosen != NULL) {
				rhs = g_list_append(rhs, chosen);
			}
			);

		rsc_lh->allowed_nodes = node_list_exclude(lhs, rhs);

		pe_free_shallow_adv(rhs, FALSE);
		pe_free_shallow(lhs);
		return;
	}

	slist_iter(
		child_rsc, resource_t, rsc_rh->children, lpc,
		
		child_rsc->cmds->rsc_colocation_rh(rsc_lh, child_rsc, constraint);
		);
}

void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order, pe_working_set_t *data_set)
{
	resource_t *r1 = NULL;
	resource_t *r2 = NULL;	
	gboolean do_interleave = FALSE;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_4("%s->%s", order->lh_action_task, order->rh_action_task);
	
	r1 = uber_parent(rsc);
	r2 = uber_parent(order->rh_rsc);
	
	if(r1 == r2) {
		native_rsc_order_lh(rsc, order, data_set);
		return;
	}

	if(order->rh_rsc->variant == pe_clone
	    || order->rh_rsc->variant == pe_master) {
	    clone_variant_data_t *clone_data_rh = NULL;
	    get_clone_variant_data(clone_data_rh, order->rh_rsc);
	    if(clone_data->clone_node_max != clone_data_rh->clone_node_max) {
		crm_config_err("Cannot interleave "XML_CIB_TAG_INCARNATION
			       " %s and %s because they do not support the same"
			       " number of resources per node",
			       rsc->id, order->rh_rsc->id);
		
		/* only the LHS side needs to be labeled as interleave */
	    } else if(clone_data->interleave) {
		do_interleave = TRUE;
	    }
	}

	if(do_interleave && order->rh_rsc) {
	    resource_t *lh_child = NULL;
	    resource_t *rh_saved = order->rh_rsc;
	    gboolean current = FALSE;
	    if(strstr(order->lh_action_task, "_stop_0") || strstr(order->lh_action_task, "_demote_0")) {
		current = TRUE;
	    }
	    
	    slist_iter(
		rh_child, resource_t, rh_saved->children, lpc,
		
		CRM_ASSERT(rh_child != NULL);
		lh_child = find_compatible_child(rh_child, rsc, RSC_ROLE_UNKNOWN, current);
		if(lh_child == NULL) {
		    crm_debug_2("No match found for %s", rh_child->id);
		    continue;
		}
		crm_debug("Interleaving %s with %s", lh_child->id, rh_child->id);
		order->rh_rsc = rh_child;
		lh_child->cmds->rsc_order_lh(lh_child, order, data_set);
		order->rh_rsc = rh_saved;
		);
	    
	} else {
	    
#if 0
	    if(order->type != pe_order_optional) {
		crm_debug("Upgraded ordering constraint %d - 0x%.6x", order->id, order->type);
		native_rsc_order_lh(rsc, order, data_set);
	    }
#endif
	    
	    if(order->type & pe_order_implies_left) {
		if(rsc->variant == order->rh_rsc->variant) {
			crm_debug_2("Clone-to-clone ordering: %s -> %s 0x%.6x",
				order->lh_action_task, order->rh_action_task, order->type);
			/* stop instances on the same nodes as stopping RHS instances */
			slist_iter(
				child_rsc, resource_t, rsc->children, lpc,
				native_rsc_order_lh(child_rsc, order, data_set);
				);
		} else {
			/* stop everything */
			crm_debug_2("Clone-to-* ordering: %s -> %s 0x%.6x",
				order->lh_action_task, order->rh_action_task, order->type);
			slist_iter(
				child_rsc, resource_t, rsc->children, lpc,
				native_rsc_order_lh(child_rsc, order, data_set);
				);
		}
	    }
	    convert_non_atomic_task(rsc, order, FALSE);
	    native_rsc_order_lh(rsc, order, data_set);
	}	

	if(is_set(rsc->flags, pe_rsc_notify)) {
	    order->type = pe_order_optional;
	    convert_non_atomic_task(rsc, order, TRUE);
	    native_rsc_order_lh(rsc, order, data_set);
	}
}

void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_4("%s->%s", lh_action->uuid, order->rh_action_task);
	if(safe_str_eq(CRM_OP_PROBED, lh_action->uuid)) {
	    slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		child_rsc->cmds->rsc_order_rh(lh_action, child_rsc, order);
		);

	    if(rsc->fns->state(rsc, TRUE) < RSC_ROLE_STARTED
		&& rsc->fns->state(rsc, FALSE) > RSC_ROLE_STOPPED) {
		order->type |= pe_order_implies_right;
	    }
	}
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
		child_rsc, resource_t, rsc->children, lpc,

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
		   CRM_CHECK(entry->rsc != NULL, continue);
		   CRM_CHECK(node_list == NULL || entry->node != NULL, continue);

		   uname = NULL;
		   rsc_id = entry->rsc->id;
		   CRM_ASSERT(rsc_id != NULL);

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

		   if(entry->node != NULL) {
		       uname = entry->node->details->uname;
		   }
		   
		   if(node_list != NULL && uname) {
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

static void mark_notifications_required(resource_t *rsc, enum action_tasks task, gboolean top) 
{
    char *key = NULL;
    char *key_complete = NULL;
    const char *task_s = task2text(task);

    if(top) {
	key = generate_op_key(rsc->id, task_s, 0);
	key_complete = generate_op_key(rsc->id, task2text(task+1), 0);
    }
    
    slist_iter(action, action_t, rsc->actions, lpc,
	       
	       if(action->optional == FALSE) {
		   continue;
	       }
	       
	       if(safe_str_eq(action->uuid, key)
		  || safe_str_eq(action->uuid, key_complete)) {
		   crm_debug_3("Marking top-level action %s as required", action->uuid);
		   action->optional = FALSE;
	       }
	       
	       if(strstr(action->uuid, task_s)) {
		   if(safe_str_eq(CRMD_ACTION_NOTIFIED, action->task)
		      || safe_str_eq(CRMD_ACTION_NOTIFY, action->task)) {
		       crm_debug_3("Marking %s as required", action->uuid);
		       action->optional = FALSE;
		   }   
	       }
	);

    slist_iter(
	child, resource_t, rsc->children, lpc,
	mark_notifications_required(child, task, FALSE);
	);
    
    crm_free(key_complete);
    crm_free(key);
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

	
	if(is_set(rsc->flags, pe_rsc_notify)) {
	    slist_iter(
			child_rsc, resource_t, rsc->children, lpc,
			
			slist_iter(
				op, action_t, rsc->actions, lpc2,
			
				child_rsc->cmds->create_notify_element(
					child_rsc, op, n_data, data_set);
				);
		);
	
	    /* expand the notify data */
	    if(n_data->stop) {
		crm_debug_3("Expanding stop");
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
		if(rsc_list != NULL) {
		    mark_notifications_required(rsc, stop_rsc, TRUE);
		}
	    }

	    if(n_data->start) {
		crm_debug_3("Expanding start");
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
		mark_notifications_required(rsc, start_rsc, TRUE);
	    }
	
	    if(n_data->demote) {
		crm_debug_3("Expanding demote");
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
		mark_notifications_required(rsc, action_demote, TRUE);
	    }
	
	    if(n_data->promote) {
		crm_debug_3("Expanding promote");
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
		mark_notifications_required(rsc, action_promote, TRUE);
	    }
	
	    if(n_data->active) {
		crm_debug_3("Expanding active");
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

	    if(n_data->slave) {
		crm_debug_3("Expanding slave");
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
	    
	    if(n_data->master) {
		crm_debug_3("Expanding master");
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

	    if(n_data->inactive) {
		crm_debug_3("Expanding inactive");
		n_data->inactive = g_list_sort(
			n_data->inactive, sort_notify_entries);
		rsc_list = NULL; node_list = NULL; uuid_list = NULL;
		expand_list(n_data->inactive, clone_data->clone_max,
			    &rsc_list, NULL, &uuid_list);
		g_hash_table_insert(
			n_data->keys,
			crm_strdup("notify_inactive_resource"), rsc_list);
	    }
	    crm_debug_3("Done expanding");
	}
	
	/* yes, we DO need this second loop */
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		
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


static gint sort_rsc_id(gconstpointer a, gconstpointer b)
{
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	CRM_ASSERT(resource1 != NULL);
	CRM_ASSERT(resource2 != NULL);

	return strcmp(resource1->id, resource2->id);
}

static resource_t *find_instance_on(resource_t *rsc, node_t *node)
{
    slist_iter(child, resource_t, rsc->children, lpc,

	       slist_iter(known ,node_t, child->known_on, lpc2,
			  if(node->details == known->details) {
			      return child;
			  }
		   );
	);
    return NULL;
}

gboolean
clone_create_probe(resource_t *rsc, node_t *node, action_t *complete,
		    gboolean force, pe_working_set_t *data_set) 
{
	gboolean any_created = FALSE;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	rsc->children = g_list_sort(rsc->children, sort_rsc_id);
	
	if(is_not_set(rsc->flags, pe_rsc_unique)
	   && clone_data->clone_node_max == 1) {
		/* only look for one copy */	 
		resource_t *child = NULL;

		/* Try whoever we probed last time */
		child = find_instance_on(rsc, node);
		if(child) {
		    return child->cmds->create_probe(
			child, node, complete, force, data_set);
		}

		/* Try whoever we plan on starting there */
		slist_iter(	 
			child_rsc, resource_t, rsc->children, lpc,	 

			node_t *local_node = child_rsc->fns->location(child_rsc, NULL, FALSE);
			if(local_node == NULL) {
			    continue;
			}
			
			if(local_node->details == node->details) {
			    return child_rsc->cmds->create_probe(
				child_rsc, node, complete, force, data_set);
			}
		    );

		/* Fall back to the first clone instance */
		child = rsc->children->data;
		return child->cmds->create_probe(child, node, complete, force, data_set);
		
	}
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		if(child_rsc->cmds->create_probe(
			   child_rsc, node, complete, force, data_set)) {
			any_created = TRUE;
		}
		
		if(any_created
		   && is_not_set(rsc->flags, pe_rsc_unique)
		   && clone_data->clone_node_max == 1) {
			/* only look for one copy (clone :0) */	 
			break;
		}
		);

	return any_created;
}

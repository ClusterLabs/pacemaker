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
#include <lib/crm/pengine/utils.h>
#include <utils.h>

#define VARIANT_CLONE 1
#include <lib/crm/pengine/variant.h>

extern gint sort_clone_instance(gconstpointer a, gconstpointer b);

extern void clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set);

extern int master_score(resource_t *rsc, node_t *node, int not_set_value);

static void
child_promoting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *rsc, resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
/* 	if(clone_data->ordered */
/* 	   || clone_data->self->restart_type == pe_restart_restart) { */
/* 		type = pe_order_implies_left; */
/* 	} */
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* last child promote before promoted started */
			custom_action_order(
				last, promote_key(last), NULL,
				rsc, promoted_key(rsc), NULL,
				type, data_set);
		}
		
	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version");
		if(last == NULL) {
			/* global promote before first child promote */
			last = rsc;

		} /* else: child/child relative promote */

		order_start_start(last, child, type);
		custom_action_order(
			last, promote_key(last), NULL,
			child, promote_key(child), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");
		
		/* child promote before global promoted */
		custom_action_order(
			child, promote_key(child), NULL,
			rsc, promoted_key(rsc), NULL,
			type, data_set);
                
		/* global promote before child promote */
		custom_action_order(
			rsc, promote_key(rsc), NULL,
			child, promote_key(child), NULL,
			type, data_set);

	}
}

static void
child_demoting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *rsc, resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
/* 	if(clone_data->ordered */
/* 	   || clone_data->self->restart_type == pe_restart_restart) { */
/* 		type = pe_order_implies_left; */
/* 	} */
	
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* global demote before first child demote */
			custom_action_order(
				rsc, demote_key(rsc), NULL,
				last, demote_key(last), NULL,
				pe_order_implies_left, data_set);
		}
		
	} else if(clone_data->ordered && last != NULL) {
		crm_debug_4("Ordered version");

		/* child/child relative demote */
		custom_action_order(child, demote_key(child), NULL,
				    last, demote_key(last), NULL,
				    type, data_set);

	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version (1st node)");
		/* first child stop before global stopped */
		custom_action_order(
			child, demote_key(child), NULL,
			rsc, demoted_key(rsc), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");

		/* child demote before global demoted */
		custom_action_order(
			child, demote_key(child), NULL,
			rsc, demoted_key(rsc), NULL,
			type, data_set);
                        
		/* global demote before child demote */
		custom_action_order(
			rsc, demote_key(rsc), NULL,
			child, demote_key(child), NULL,
			type, data_set);
	}
}

static void
master_update_pseudo_status(
	resource_t *child, gboolean *demoting, gboolean *promoting) 
{
	CRM_ASSERT(demoting != NULL);
	CRM_ASSERT(promoting != NULL);

	slist_iter(
		action, action_t, child->actions, lpc,

		if(*promoting && *demoting) {
			return;

		} else if(action->optional) {
			continue;

		} else if(safe_str_eq(CRMD_ACTION_DEMOTE, action->task)) {
			*demoting = TRUE;

		} else if(safe_str_eq(CRMD_ACTION_PROMOTE, action->task)) {
			*promoting = TRUE;
		}
		);

}

#define apply_master_location(list)					\
	slist_iter(							\
		cons, rsc_to_node_t, list, lpc2,			\
		cons_node = NULL;					\
		if(cons->role_filter == RSC_ROLE_MASTER) {		\
			crm_debug("Applying %s to %s",			\
				  cons->id, child_rsc->id);		\
			cons_node = pe_find_node_id(			\
				cons->node_list_rh, chosen->details->id); \
		}							\
		if(cons_node != NULL) {					\
			int new_priority = merge_weights(		\
				child_rsc->priority, cons_node->weight); \
			crm_debug("\t%s: %d->%d (%d)", child_rsc->id,	\
				child_rsc->priority, new_priority, cons_node->weight);	\
			child_rsc->priority = new_priority;		\
		}							\
		);

static node_t *
can_be_master(resource_t *rsc)
{
	node_t *node = NULL;
	node_t *local_node = NULL;
	resource_t *parent = uber_parent(rsc);
	clone_variant_data_t *clone_data = NULL;
	int level = LOG_DEBUG_2;
#if 0
	enum rsc_role_e role = RSC_ROLE_UNKNOWN;
	role = rsc->fns->state(rsc, FALSE);
	crm_info("%s role: %s", rsc->id, role2text(role));
#endif
	
	if(rsc->children) {
	    slist_iter(
		child, resource_t, rsc->children, lpc,
		if(can_be_master(child) == NULL) {
		    do_crm_log(level, "Child %s of %s can't be promoted", child->id, rsc->id);
		    return NULL;
		}
		);
	}
	
	node = rsc->fns->location(rsc, NULL, FALSE);
	if(rsc->priority < 0) {
		do_crm_log(level, "%s cannot be master: preference: %d",
			   rsc->id, rsc->priority);
		return NULL;
	} else if(node == NULL) {
		do_crm_log(level, "%s cannot be master: not allocated",
			    rsc->id);
		return NULL;
	} else if(can_run_resources(node) == FALSE) {
		do_crm_log(level, "Node cant run any resources: %s",
			    node->details->uname);
		return NULL;
	}
	
	get_clone_variant_data(clone_data, parent);
	local_node = pe_find_node_id(
		parent->allowed_nodes, node->details->id);

	if(local_node == NULL) {
		crm_err("%s cannot run on %s: node not allowed",
			rsc->id, node->details->uname);
		return NULL;

	} else if(local_node->count < clone_data->master_node_max) {
		return local_node;

	} else {
		do_crm_log(level, "%s cannot be master on %s: node full",
			    rsc->id, node->details->uname);
	}

	return NULL;
}

static gint sort_master_instance(gconstpointer a, gconstpointer b)
{
	int rc;
	enum rsc_role_e role1 = RSC_ROLE_UNKNOWN;
	enum rsc_role_e role2 = RSC_ROLE_UNKNOWN;

	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	CRM_ASSERT(resource1 != NULL);
	CRM_ASSERT(resource2 != NULL);

	role1 = resource1->fns->state(resource1, TRUE);
	role2 = resource2->fns->state(resource2, TRUE);
	
	rc = sort_rsc_index(a, b);
	if( rc != 0 ) {
		return rc;
	}
	
	if(role1 > role2) {
		return -1;

	} else if(role1 < role2) {
		return 1;
	}
	
	return sort_clone_instance(a, b);
}

static void master_promotion_order(resource_t *rsc) 
{
    node_t *node = NULL;
    node_t *chosen = NULL;
    clone_variant_data_t *clone_data = NULL;
    get_clone_variant_data(clone_data, rsc);

    if(clone_data->merged_master_weights) {
	return;
    }
    clone_data->merged_master_weights = TRUE;
    crm_debug_2("Merging weights for %s", rsc->id);
    slist_iter(
	child, resource_t, rsc->children, lpc,
	crm_debug_2("%s: %d", child->id, child->sort_index);
	);
    dump_node_scores(LOG_DEBUG_3, rsc, "Before", rsc->allowed_nodes);

#if 1
    slist_iter(
	child, resource_t, rsc->children, lpc,

	chosen = child->fns->location(child, NULL, FALSE);
	if(chosen == NULL || child->sort_index < 0) {
	    crm_debug_3("Skipping %s", child->id);
	    continue;
	}

	node = (node_t*)pe_find_node_id(
	    rsc->allowed_nodes, chosen->details->id);
	CRM_ASSERT(node != NULL);
	node->weight = merge_weights(child->sort_index, node->weight);
	);
    
    dump_node_scores(LOG_DEBUG_3, rsc, "Middle", rsc->allowed_nodes);
#endif
    
    slist_iter(
	constraint, rsc_colocation_t, rsc->rsc_cons_lhs, lpc,
	
	if(constraint->role_rh == RSC_ROLE_MASTER) {
	    rsc->allowed_nodes = constraint->rsc_lh->cmds->merge_weights(
		constraint->rsc_lh, rsc->id, rsc->allowed_nodes,
		constraint->score/INFINITY, TRUE);
	}
	);
    
    dump_node_scores(LOG_DEBUG_3, rsc, "After", rsc->allowed_nodes);

    /* write them back and sort */
    slist_iter(
	child, resource_t, rsc->children, lpc,

	chosen = child->fns->location(child, NULL, FALSE);

	if(chosen == NULL || child->sort_index < 0) {
	    crm_debug_2("%s: %d", child->id, child->sort_index);
	    continue;
	}

	node = (node_t*)pe_find_node_id(
	    rsc->allowed_nodes, chosen->details->id);
	CRM_ASSERT(node != NULL);

	child->sort_index = node->weight;
	crm_debug_2("%s: %d", child->id, child->sort_index);
	);

    rsc->children = g_list_sort(rsc->children, sort_master_instance);
}

int
master_score(resource_t *rsc, node_t *node, int not_set_value)
{
	char *attr_name;
	char *name = rsc->id;
	const char *attr_value;
	int score = not_set_value, len = 0;

	if(rsc->fns->state(rsc, TRUE) < RSC_ROLE_STARTED) {
	    return score;
	}

	if(rsc->running_on) {
	    node_t *match = pe_find_node_id(rsc->allowed_nodes, node->details->id);
	    if(match->weight < 0) {
		crm_debug_2("%s on %s has score: %d - ignoring master pref",
			    rsc->id, match->details->uname, match->weight);
		return score;
	    }
	}
	    
#if 0
	if(rsc->clone_name) {
	    name = rsc->clone_name;
	    crm_err("%s ::= %s", rsc->id, rsc->clone_name);
	}
#endif
	len = 8 + strlen(name);
	crm_malloc0(attr_name, len);
	sprintf(attr_name, "master-%s", name);
	
	crm_debug_3("looking for %s on %s", attr_name,
				node->details->uname);
	attr_value = g_hash_table_lookup(
		node->details->attrs, attr_name);
	
	if(attr_value == NULL) {
		crm_free(attr_name);
		len = 8 + strlen(rsc->long_name);
		crm_malloc0(attr_name, len);
		sprintf(attr_name, "master-%s", rsc->long_name);
		crm_debug_3("looking for %s on %s", attr_name,
					node->details->uname);
		attr_value = g_hash_table_lookup(
			node->details->attrs, attr_name);
	}
	
	if(attr_value != NULL) {
		crm_debug_2("%s[%s] = %s", attr_name,
			    node->details->uname, crm_str(attr_value));
		score = char2score(attr_value);
	}

	crm_free(attr_name);
	return score;
}

#define max(a, b) a<b?b:a

static void
apply_master_prefs(resource_t *rsc) 
{
    int score, new_score;
    clone_variant_data_t *clone_data = NULL;
    get_clone_variant_data(clone_data, rsc);
    
    if(clone_data->applied_master_prefs) {
	/* Make sure we only do this once */
	return;
    }
    
    clone_data->applied_master_prefs = TRUE;
    
    slist_iter(
	child_rsc, resource_t, rsc->children, lpc,
	slist_iter(
	    node, node_t, child_rsc->allowed_nodes, lpc,

	    if(can_run_resources(node) == FALSE) {
		/* This node will never be promoted to master,
		 *  so don't apply the master score as that may
		 *  lead to clone shuffling
		 */
		continue;
	    }
	    
	    score = master_score(child_rsc, node, 0);
	    
	    new_score = merge_weights(node->weight, score);
	    if(new_score != node->weight) {
		crm_debug_2("\t%s: Updating preference for %s (%d->%d)",
			  child_rsc->id, node->details->uname, node->weight, new_score);
		node->weight = new_score;
	    }
	    
	    new_score = max(child_rsc->priority, score);
	    if(new_score != child_rsc->priority) {
		crm_debug_2("\t%s: Updating priority (%d->%d)",
			  child_rsc->id, child_rsc->priority, new_score);
		child_rsc->priority = new_score;
	    }
	    );
	);
}

static void set_role(resource_t *rsc, enum rsc_role_e role, gboolean current) 
{
    if(current) {
	if(rsc->variant == pe_native && rsc->running_on != NULL && role > RSC_ROLE_STOPPED) {
	    crm_debug_6("Filtering change %s.role = %s (was %s)", rsc->id, role2text(role), role2text(rsc->role));

	} else if(rsc->role != role) {
	    crm_debug_5("Set %s.role = %s (was %s)", rsc->id, role2text(role), role2text(rsc->role));
	    rsc->role = role;
	}
    } else {
	if(rsc->next_role != role) {
	    crm_debug_5("Set %s.next_role = %s (was %s)", rsc->id, role2text(role), role2text(rsc->next_role));
	    rsc->next_role = role;
	    if(role == RSC_ROLE_MASTER) {
		add_hash_param(rsc->parameters, crm_meta_name("role"), role2text(role));
	    }
	}
    }
    
    slist_iter(
	child_rsc, resource_t, rsc->children, lpc,
	set_role(child_rsc, role, current);
	);
}

node_t *
master_color(resource_t *rsc, pe_working_set_t *data_set)
{
	int promoted = 0;
	node_t *chosen = NULL;
	node_t *cons_node = NULL;
	enum rsc_role_e next_role = RSC_ROLE_UNKNOWN;
	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	apply_master_prefs(rsc);

	clone_color(rsc, data_set);
	
	/* count now tracks the number of masters allocated */
	slist_iter(node, node_t, rsc->allowed_nodes, lpc,
		   node->count = 0;
		);

	/*
	 * assign priority
	 */
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		GListPtr list = NULL;
		crm_debug_2("Assigning priority for %s", child_rsc->id);
		if(child_rsc->fns->state(child_rsc, TRUE) == RSC_ROLE_STARTED) {
		    set_role(child_rsc, RSC_ROLE_SLAVE, TRUE);
		}

		chosen = child_rsc->fns->location(child_rsc, &list, FALSE);
		if(g_list_length(list) > 1) {
		    crm_config_err("Cannot promote non-colocated child %s", child_rsc->id);
		}

		g_list_free(list);
		if(chosen == NULL) {
			continue;
		}
		
		next_role = child_rsc->fns->state(child_rsc, FALSE);
		switch(next_role) {
			case RSC_ROLE_STARTED:
				CRM_CHECK(chosen != NULL, break);
				/*
				 * Default to -1 if no value is set
				 *
				 * This allows master locations to be specified
				 * based solely on rsc_location constraints,
				 * but prevents anyone from being promoted if
				 * neither a constraint nor a master-score is present
				 */
				child_rsc->priority = master_score(child_rsc, chosen, -1);
				break;

			case RSC_ROLE_SLAVE:
			case RSC_ROLE_STOPPED:
				child_rsc->priority = -INFINITY;
				break;
			case RSC_ROLE_MASTER:
				/* the only reason we should be here is if
				 * we're re-creating actions after a stonith
				 */
				promoted++;
				break;
			default:
				CRM_CHECK(FALSE/* unhandled */,
					  crm_err("Unknown resource role: %d for %s",
						  next_role, child_rsc->id));
		}

		apply_master_location(child_rsc->rsc_location);
		apply_master_location(rsc->rsc_location);
		slist_iter(
		    cons, rsc_colocation_t, child_rsc->rsc_cons, lpc2,
		    child_rsc->cmds->rsc_colocation_lh(child_rsc, cons->rsc_rh, cons);
		    );
		
		child_rsc->sort_index = child_rsc->priority;
		crm_debug_2("Assigning priority for %s: %d", child_rsc->id, child_rsc->priority);

		if(next_role == RSC_ROLE_MASTER) {
		    child_rsc->sort_index = INFINITY;
		}

	    );

	master_promotion_order(rsc);	

	/* mark the first N as masters */
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		chosen = NULL;
		crm_debug_2("Processing %s", child_rsc->id);
		if(promoted < clone_data->master_max) {
			chosen = can_be_master(child_rsc);
		}

		crm_debug("%s master score: %d", child_rsc->id, child_rsc->priority);
		
		if(chosen == NULL) {
		    next_role = child_rsc->fns->state(child_rsc, FALSE);
		    if(next_role == RSC_ROLE_STARTED) {
			set_role(child_rsc, RSC_ROLE_SLAVE, FALSE);
		    }
		    continue;
		}

		chosen->count++;
		crm_info("Promoting %s", child_rsc->id);
		set_role(child_rsc, RSC_ROLE_MASTER, FALSE);
		clone_data->masters_allocated++;
		promoted++;		
		);
	
	crm_info("%s: Promoted %d instances of a possible %d to master",
		 rsc->id, promoted, clone_data->master_max);
	return NULL;
}

void master_create_actions(resource_t *rsc, pe_working_set_t *data_set)
{
	action_t *action = NULL;
	action_t *action_complete = NULL;
	gboolean any_promoting = FALSE;
	gboolean any_demoting = FALSE;
	resource_t *last_promote_rsc = NULL;
	resource_t *last_demote_rsc = NULL;

	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	
	crm_debug("Creating actions for %s", rsc->id);

	/* create actions as normal */
	clone_create_actions(rsc, data_set);

	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		gboolean child_promoting = FALSE;
		gboolean child_demoting = FALSE;

		crm_debug_2("Creating actions for %s", child_rsc->id);
		child_rsc->cmds->create_actions(child_rsc, data_set);
		master_update_pseudo_status(
			child_rsc, &child_demoting, &child_promoting);

		any_demoting = any_demoting || child_demoting;
		any_promoting = any_promoting || child_promoting;
		);
	
	/* promote */
	action = promote_action(rsc, NULL, !any_promoting);
	action_complete = custom_action(
		rsc, promoted_key(rsc),
		CRMD_ACTION_PROMOTED, NULL, !any_promoting, TRUE, data_set);

	action->pseudo = TRUE;
	action->runnable = FALSE;
	action_complete->pseudo = TRUE;
	action_complete->runnable = FALSE;
	action_complete->priority = INFINITY;

	if(clone_data->masters_allocated > 0) {
	    action->runnable = TRUE;
	    action_complete->runnable = TRUE;
	}
	
	child_promoting_constraints(clone_data, pe_order_optional, 
				    rsc, NULL, last_promote_rsc, data_set);

	clone_create_notifications(rsc, action, action_complete, data_set);	


	/* demote */
	action = demote_action(rsc, NULL, !any_demoting);
	action_complete = custom_action(
		rsc, demoted_key(rsc),
		CRMD_ACTION_DEMOTED, NULL, !any_demoting, TRUE, data_set);
	action_complete->priority = INFINITY;

	action->pseudo = TRUE;
	action->runnable = TRUE;
	action_complete->pseudo = TRUE;
	action_complete->runnable = TRUE;
	
	child_demoting_constraints(clone_data, pe_order_optional,
				   rsc, NULL, last_demote_rsc, data_set);

	clone_create_notifications(rsc, action, action_complete, data_set);	

	/* restore the correct priority */ 
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		child_rsc->priority = rsc->priority;
	    );
}

void
master_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	resource_t *last_rsc = NULL;	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	clone_internal_constraints(rsc, data_set);
	
	/* global stopped before start */
	custom_action_order(
		rsc, stopped_key(rsc), NULL,
		rsc, start_key(rsc), NULL,
		pe_order_optional, data_set);

	/* global stopped before promote */
	custom_action_order(
		rsc, stopped_key(rsc), NULL,
		rsc, promote_key(rsc), NULL,
		pe_order_optional, data_set);

	/* global demoted before start */
	custom_action_order(
		rsc, demoted_key(rsc), NULL,
		rsc, start_key(rsc), NULL,
		pe_order_optional, data_set);

	/* global started before promote */
	custom_action_order(
		rsc, started_key(rsc), NULL,
		rsc, promote_key(rsc), NULL,
		pe_order_optional, data_set);

	/* global demoted before stop */
	custom_action_order(
		rsc, demoted_key(rsc), NULL,
		rsc, stop_key(rsc), NULL,
		pe_order_optional, data_set);

	/* global demote before demoted */
	custom_action_order(
		rsc, demote_key(rsc), NULL,
		rsc, demoted_key(rsc), NULL,
		pe_order_optional, data_set);

	/* global demoted before promote */
	custom_action_order(
		rsc, demoted_key(rsc), NULL,
		rsc, promote_key(rsc), NULL,
		pe_order_optional, data_set);

	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,

		/* child demote before promote */
		custom_action_order(
			child_rsc, demote_key(child_rsc), NULL,
			child_rsc, promote_key(child_rsc), NULL,
			pe_order_optional, data_set);
		
		child_promoting_constraints(clone_data, pe_order_optional,
					    rsc, child_rsc, last_rsc, data_set);

		child_demoting_constraints(clone_data, pe_order_optional,
					   rsc, child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		
		);
	
}

static void node_list_update_one(GListPtr list1, node_t *other, int score)
{
    node_t *node = NULL;
    
    if(other == NULL) {
	return;
    }
    
    node = (node_t*)pe_find_node_id(list1, other->details->id);
    
    if(node != NULL) {
	crm_debug_2("%s: %d + %d",
		    node->details->uname, node->weight, other->weight);
	node->weight = merge_weights(node->weight, score);
    }	
}

void master_rsc_colocation_rh(
    resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc_rh);

	
	CRM_CHECK(rsc_rh != NULL, return);
	if(is_set(rsc_rh->flags, pe_rsc_provisional)) {
		return;

	} else if(constraint->role_rh == RSC_ROLE_UNKNOWN) {
		crm_debug_3("Handling %s as a clone colocation", constraint->id);
		clone_rsc_colocation_rh(rsc_lh, rsc_rh, constraint);
		return;
	}
	
	CRM_CHECK(rsc_lh != NULL, return);
	CRM_CHECK(rsc_lh->variant == pe_native, return);
	crm_debug_2("Processing constraint %s: %d", constraint->id, constraint->score);

	if(constraint->role_rh == RSC_ROLE_UNKNOWN) {
		slist_iter(
			child_rsc, resource_t, rsc_rh->children, lpc,
			
			child_rsc->cmds->rsc_colocation_rh(rsc_lh, child_rsc, constraint);
			);

	} else if(is_set(rsc_lh->flags, pe_rsc_provisional)) {
		GListPtr lhs = NULL, rhs = NULL;
		lhs = rsc_lh->allowed_nodes;
		
		slist_iter(
			child_rsc, resource_t, rsc_rh->children, lpc,
			node_t *chosen = child_rsc->fns->location(child_rsc, NULL, FALSE);
			enum rsc_role_e next_role = child_rsc->fns->state(child_rsc, FALSE);
			crm_debug_3("Processing: %s", child_rsc->id);
			if(chosen != NULL
			   && next_role == constraint->role_rh) {
			    crm_debug_3("Applying: %s %s", child_rsc->id,
					role2text(next_role));
			    node_list_update_one(rsc_lh->allowed_nodes, chosen, constraint->score);
			    rhs = g_list_append(rhs, chosen);
			}
			);

		/* Only do this if its not a master-master colocation
		 * Doing this unconditionally would prevent the slaves from being started
		 */
		if(constraint->score > 0
		   && (constraint->role_lh != RSC_ROLE_MASTER
		       || constraint->role_rh != RSC_ROLE_MASTER)) {
		    rsc_lh->allowed_nodes = node_list_and(lhs, rhs, FALSE);
		    pe_free_shallow(lhs);
		}
		pe_free_shallow_adv(rhs, FALSE);

	} else if(constraint->role_lh == RSC_ROLE_MASTER) {
	    resource_t *rh_child = find_compatible_child(rsc_lh, rsc_rh, constraint->role_rh, FALSE);
	    if(rh_child == NULL && constraint->score >= INFINITY) {
		crm_debug_2("%s can't be promoted %s", rsc_lh->id, constraint->id);
		rsc_lh->priority = -INFINITY;
		
	    } else if(rh_child != NULL) {
		int new_priority = merge_weights(rsc_lh->priority, constraint->score);
		crm_debug("Applying %s to %s", constraint->id, rsc_lh->id);
		crm_debug("\t%s: %d->%d", rsc_lh->id, rsc_lh->priority, new_priority);
		rsc_lh->priority = new_priority;
	    }
	}

	return;
}

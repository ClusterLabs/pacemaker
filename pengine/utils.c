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
#include <lib/pengine/utils.h>

void
print_rsc_to_node(const char *pre_text, rsc_to_node_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}
	crm_debug_4("%s%s%s Constraint %s (%p) - %d nodes:",
		    pre_text==NULL?"":pre_text,
		    pre_text==NULL?"":": ",
		    "rsc_to_node",
		    cons->id, cons,
		    g_list_length(cons->node_list_rh));

	if(details == FALSE) {
		crm_debug_4("\t%s (node placement rule)",
			  safe_val3(NULL, cons, rsc_lh, id));

		slist_iter(
			node, node_t, cons->node_list_rh, lpc,
			print_node("\t\t-->", node, FALSE)
			);
	}
}

void
print_rsc_colocation(const char *pre_text, rsc_colocation_t *cons, gboolean details)
{ 
	if(cons == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}
	crm_debug_4("%s%s%s Constraint %s (%p):",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       XML_CONS_TAG_RSC_DEPEND, cons->id, cons);

	if(details == FALSE) {

		crm_debug_4("\t%s --> %s, %d",
			  safe_val3(NULL, cons, rsc_lh, id), 
			  safe_val3(NULL, cons, rsc_rh, id), 
			  cons->score);
	}
} 

void
pe_free_ordering(GListPtr constraints) 
{
	GListPtr iterator = constraints;
	while(iterator != NULL) {
		order_constraint_t *order = iterator->data;
		iterator = iterator->next;

		crm_free(order->lh_action_task);
		crm_free(order->rh_action_task);
		crm_free(order);
	}
	if(constraints != NULL) {
		g_list_free(constraints);
	}
}


void
pe_free_rsc_to_node(GListPtr constraints)
{
	GListPtr iterator = constraints;
	while(iterator != NULL) {
		rsc_to_node_t *cons = iterator->data;
		iterator = iterator->next;

		pe_free_shallow(cons->node_list_rh);
		crm_free(cons);
	}
	if(constraints != NULL) {
		g_list_free(constraints);
	}
}


rsc_to_node_t *
rsc2node_new(const char *id, resource_t *rsc,
	     int node_weight, node_t *foo_node, pe_working_set_t *data_set)
{
	rsc_to_node_t *new_con = NULL;

	if(rsc == NULL || id == NULL) {
		pe_err("Invalid constraint %s for rsc=%p", crm_str(id), rsc);
		return NULL;

	} else if(foo_node == NULL) {
		CRM_CHECK(node_weight == 0, return NULL);
	}
	
	crm_malloc0(new_con, sizeof(rsc_to_node_t));
	if(new_con != NULL) {
		new_con->id           = id;
		new_con->rsc_lh       = rsc;
		new_con->node_list_rh = NULL;
		new_con->role_filter = RSC_ROLE_UNKNOWN;
		
		if(foo_node != NULL) {
			node_t *copy = node_copy(foo_node);
			copy->weight = merge_weights(node_weight, foo_node->weight);
			new_con->node_list_rh = g_list_append(NULL, copy);
		}
		
		data_set->placement_constraints = g_list_append(
			data_set->placement_constraints, new_con);
		rsc->rsc_location = g_list_append(rsc->rsc_location, new_con);
	}
	
	return new_con;
}


const char *
ordering_type2text(enum pe_ordering type)
{
	const char *result = "<unknown>";
	if(type & pe_order_implies_left) {
		/* was: mandatory */
		result = "right_implies_left";

	} else if(type & pe_order_implies_right) {
		/* was: recover  */
		result = "left_implies_right";

	} else if(type & pe_order_optional) {
		/* pure ordering, nothing implied */
		result = "optional";
		
	} else if(type & pe_order_runnable_left) {
		result = "runnable";
		
	/* } else { */
	/* 	crm_err("Unknown ordering type: %.3x", type); */
	}
	
	return result;
}


gboolean
can_run_resources(const node_t *node)
{
	if(node == NULL) {
		return FALSE;	
	}

#if 0	
	if(node->weight < 0) {
		return FALSE;	
	}
#endif
	
	if(node->details->online == FALSE
	   || node->details->shutdown
	   || node->details->unclean
	   || node->details->standby) {
		crm_debug_2("%s: online=%d, unclean=%d, standby=%d",
			    node->details->uname, node->details->online,
			    node->details->unclean, node->details->standby);
		return FALSE;
	}
	return TRUE;
}

struct compare_data
{
        const node_t *node1;
        const node_t *node2;
        int result;
};

static void
do_compare_capacity1(gpointer key, gpointer value, gpointer user_data)
{
	int node1_capacity = 0;
	int node2_capacity = 0;
	struct compare_data *data = user_data;

	node1_capacity = crm_parse_int(value, "0");
	node2_capacity = crm_parse_int(g_hash_table_lookup(data->node2->details->utilization, key), "0");

	if (node1_capacity > node2_capacity) {
		data->result--;
	} else if (node1_capacity < node2_capacity) {
		data->result++;
	}
}

static void
do_compare_capacity2(gpointer key, gpointer value, gpointer user_data)
{
	int node1_capacity = 0;
	int node2_capacity = 0;
	struct compare_data *data = user_data;

	if (g_hash_table_lookup_extended(data->node1->details->utilization, key, NULL, NULL)) {
		return;
	}

	node1_capacity = 0;
	node2_capacity = crm_parse_int(value, "0");

	if (node1_capacity > node2_capacity) {
		data->result--;
	} else if (node1_capacity < node2_capacity) {
		data->result++;
	}
}

/* rc < 0 if 'node1' has more capacity remaining
 * rc > 0 if 'node1' has less capacity remaining
 */
static int
compare_capacity(const node_t *node1, const node_t *node2)
{
	struct compare_data data;

	data.node1 = node1;
	data.node2 = node2;
	data.result = 0;

	g_hash_table_foreach(node1->details->utilization, do_compare_capacity1, &data);
	g_hash_table_foreach(node2->details->utilization, do_compare_capacity2, &data);

	return data.result;
}

/* return -1 if 'a' is more preferred
 * return  1 if 'b' is more preferred
 */
gint sort_node_weight(gconstpointer a, gconstpointer b, gpointer data)
{
	int level = LOG_DEBUG_3;
	const node_t *node1 = (const node_t*)a;
	const node_t *node2 = (const node_t*)b;
	const pe_working_set_t *data_set = (const pe_working_set_t*)data;

	int node1_weight = 0;
	int node2_weight = 0;

	int result = 0;
	
	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }
	
	node1_weight = node1->weight;
	node2_weight = node2->weight;
	
	if(can_run_resources(node1) == FALSE) {
		node1_weight  = -INFINITY; 
	}
	if(can_run_resources(node2) == FALSE) {
		node2_weight  = -INFINITY; 
	}

	if(node1_weight > node2_weight) {
		do_crm_log_unlikely(level, "%s (%d) > %s (%d) : weight",
			   node1->details->uname, node1_weight,
			   node2->details->uname, node2_weight);
		return -1;
	}
	
	if(node1_weight < node2_weight) {
		do_crm_log_unlikely(level, "%s (%d) < %s (%d) : weight",
			    node1->details->uname, node1_weight,
			    node2->details->uname, node2_weight);
		return 1;
	}

	do_crm_log_unlikely(level, "%s (%d) == %s (%d) : weight",
		    node1->details->uname, node1_weight,
		    node2->details->uname, node2_weight);

	if (safe_str_eq(data_set->placement_strategy, "minimal")) {
		goto equal;
	}

	if (safe_str_eq(data_set->placement_strategy, "balanced")) {
		result = compare_capacity(node1, node2);
		if (result != 0) {
			return result;
		}
	}
	
	/* now try to balance resources across the cluster */
	if(node1->details->num_resources
	   < node2->details->num_resources) {
		do_crm_log_unlikely(level, "%s (%d) < %s (%d) : resources",
			    node1->details->uname, node1->details->num_resources,
			    node2->details->uname, node2->details->num_resources);
		return -1;
		
	} else if(node1->details->num_resources
		  > node2->details->num_resources) {
		do_crm_log_unlikely(level, "%s (%d) > %s (%d) : resources",
			    node1->details->uname, node1->details->num_resources,
			    node2->details->uname, node2->details->num_resources);
		return 1;
	}
	
equal:	
	do_crm_log_unlikely(level, "%s = %s", node1->details->uname, node2->details->uname);
	return 0;
}

struct calculate_data
{
	node_t *node;
	gboolean allocate;
};

static void
do_calculate_utilization(gpointer key, gpointer value, gpointer user_data)
{
	const char *capacity = NULL;
	char *remain_capacity = NULL;
	struct calculate_data *data = user_data;

	capacity = g_hash_table_lookup(data->node->details->utilization, key);
	if (capacity) {
		if (data->allocate) {
			remain_capacity = crm_itoa(crm_parse_int(capacity, "0") - crm_parse_int(value, "0"));
		} else {
			remain_capacity = crm_itoa(crm_parse_int(capacity, "0") + crm_parse_int(value, "0"));
		}
		g_hash_table_replace(data->node->details->utilization, crm_strdup(key), remain_capacity);
	}
}

/* Specify 'allocate' to TRUE when allocating
 * Otherwise to FALSE when deallocating
 */
static void
calculate_utilization(node_t *node, resource_t *rsc, gboolean allocate)
{
	struct calculate_data data;

	data.node = node;
	data.allocate = allocate;

	g_hash_table_foreach(rsc->utilization, do_calculate_utilization, &data);

	if (allocate) {
		dump_rsc_utilization(show_utilization?0:utilization_log_level, __FUNCTION__, rsc, node);
	}
}

gboolean
native_assign_node(resource_t *rsc, GListPtr nodes, node_t *chosen, gboolean force)
{
	CRM_ASSERT(rsc->variant == pe_native);

	clear_bit(rsc->flags, pe_rsc_provisional);
	
	if(force == FALSE
	   && chosen != NULL
	   && (can_run_resources(chosen) == FALSE || chosen->weight < 0)) {
		crm_debug("All nodes for resource %s are unavailable"
			  ", unclean or shutting down (%s: %d, %d)",
			  rsc->id, chosen->details->uname, can_run_resources(chosen), chosen->weight);
		rsc->next_role = RSC_ROLE_STOPPED;
		chosen = NULL;
	}

	/* todo: update the old node for each resource to reflect its
	 * new resource count
	 */

	if(rsc->allocated_to) {
		node_t *old = rsc->allocated_to;
		crm_info("Deallocating %s from %s", rsc->id, old->details->uname);
		old->details->allocated_rsc = g_list_remove(
			old->details->allocated_rsc, rsc);
		old->details->num_resources--;
		old->count--;
		calculate_utilization(old, rsc, FALSE);
	}
	
	if(chosen == NULL) {
	    char *key = NULL;
	    GListPtr possible_matches = NULL;

	    crm_debug("Could not allocate a node for %s", rsc->id);
	    rsc->next_role = RSC_ROLE_STOPPED;
	    
	    key = generate_op_key(rsc->id, CRMD_ACTION_STOP, 0);
	    possible_matches = find_actions(rsc->actions, key, NULL);

	    slist_iter(
		stop, action_t, possible_matches, lpc,
		stop->optional = FALSE;
		);

	    g_list_free(possible_matches);
	    crm_free(key);

	    key = generate_op_key(rsc->id, CRMD_ACTION_START, 0);
	    possible_matches = find_actions(rsc->actions, key, NULL);

	    slist_iter(
		start, action_t, possible_matches, lpc,
		start->runnable = FALSE;
		);	    

	    g_list_free(possible_matches);
	    crm_free(key);

	    return FALSE;
	}

	crm_debug("Assigning %s to %s", chosen->details->uname, rsc->id);
	crm_free(rsc->allocated_to);
	rsc->allocated_to = node_copy(chosen);

	chosen->details->allocated_rsc = g_list_append(chosen->details->allocated_rsc, rsc);
	chosen->details->num_resources++;
	chosen->count++;
	calculate_utilization(chosen, rsc, TRUE);
	return TRUE;
}

char *
convert_non_atomic_task(char *old_uuid, resource_t *rsc, gboolean allow_notify, gboolean free_original)
{
    int interval = 0;
    char *uuid = NULL;
    char *rid = NULL;
    char *raw_task = NULL;
    int task = no_action;

    crm_debug_3("Processing %s", old_uuid);
    if(old_uuid == NULL) {
	return NULL;

    } else if(strstr(old_uuid, "notify") != NULL) {
	goto done; /* no conversion */

    } else if(rsc->variant < pe_group) {
	goto done; /* no conversion */
    }

    CRM_ASSERT(parse_op_key(old_uuid, &rid, &raw_task, &interval));
    if(interval > 0) {
	goto done; /* no conversion */
    } 
	
    task = text2task(raw_task);
    switch(task) {
	case stop_rsc:
	case start_rsc:
	case action_notify:
	case action_promote:
	case action_demote:
	    break;
	case stopped_rsc:
	case started_rsc:
	case action_notified:
	case action_promoted:
	case action_demoted:
	    task--;
	    break;
	case monitor_rsc:
	case shutdown_crm:
	case stonith_node:
	    task = no_action;
	    break;
	default:
	    crm_err("Unknown action: %s", raw_task);
	    task = no_action;
	    break;
    }
	
    if(task != no_action) {
	if(is_set(rsc->flags, pe_rsc_notify) && allow_notify) {
	    uuid = generate_notify_key(rid, "confirmed-post", task2text(task+1));
	    
	} else {
	    uuid = generate_op_key(rid, task2text(task+1), 0);
	}
	crm_debug_2("Converted %s -> %s", old_uuid, uuid);
    }
	
  done:
    if(uuid == NULL) {
	uuid = crm_strdup(old_uuid);
    }

    if(free_original) {
	crm_free(old_uuid);
    }
    
    crm_free(raw_task);
    crm_free(rid);
    return uuid;
}


void
order_actions(
	action_t *lh_action, action_t *rh_action, enum pe_ordering order) 
{
	action_wrapper_t *wrapper = NULL;
	GListPtr list = NULL;
	static int load_stopped_strlen = 0;

	if (!load_stopped_strlen) {
		load_stopped_strlen = strlen(LOAD_STOPPED);
	}

	if (strncmp(lh_action->uuid, LOAD_STOPPED, load_stopped_strlen) == 0
			|| strncmp(rh_action->uuid, LOAD_STOPPED, load_stopped_strlen) == 0) {
		if (lh_action->node == NULL || rh_action->node == NULL
				|| lh_action->node->details != rh_action->node->details) {
			return;
		}
	}
	
	crm_debug_3("Ordering Action %s before %s",
		    lh_action->uuid, rh_action->uuid);

	log_action(LOG_DEBUG_4, "LH (order_actions)", lh_action, FALSE);
	log_action(LOG_DEBUG_4, "RH (order_actions)", rh_action, FALSE);

	/* Filter dups, otherwise update_action_states() has too much work to do */
	slist_iter(after, action_wrapper_t, lh_action->actions_after, lpc,
		   if(after->action == rh_action && (after->type & order)) {
		       return;
		   }
	    );
	
	crm_malloc0(wrapper, sizeof(action_wrapper_t));
	wrapper->action = rh_action;
	wrapper->type = order;
	
	list = lh_action->actions_after;
	list = g_list_append(list, wrapper);
	lh_action->actions_after = list;

	wrapper = NULL;

/* 	order |= pe_order_implies_right; */
/* 	order ^= pe_order_implies_right; */
	
	crm_malloc0(wrapper, sizeof(action_wrapper_t));
	wrapper->action = lh_action;
	wrapper->type = order;
	list = rh_action->actions_before;
	list = g_list_append(list, wrapper);
	rh_action->actions_before = list;
}


void
log_action(unsigned int log_level, const char *pre_text, action_t *action, gboolean details)
{
	const char *node_uname = NULL;
	const char *node_uuid = NULL;
	
	if(action == NULL) {

		do_crm_log_unlikely(log_level, "%s%s: <NULL>",
			      pre_text==NULL?"":pre_text,
			      pre_text==NULL?"":": ");
		return;
	}


	if(action->pseudo) {
		node_uname = NULL;
		node_uuid = NULL;
		
	} else if(action->node != NULL) {
		node_uname = action->node->details->uname;
		node_uuid = action->node->details->id;
	} else {
		node_uname = "<none>";
		node_uuid = NULL;
	}
	
	switch(text2task(action->task)) {
		case stonith_node:
		case shutdown_crm:
			do_crm_log_unlikely(log_level,
				      "%s%s%sAction %d: %s%s%s%s%s%s",
				      pre_text==NULL?"":pre_text,
				      pre_text==NULL?"":": ",
				      action->pseudo?"Pseduo ":action->optional?"Optional ":action->runnable?action->processed?"":"(Provisional) ":"!!Non-Startable!! ",
				      action->id, action->uuid,
				      node_uname?"\ton ":"",
				      node_uname?node_uname:"",
				      node_uuid?"\t\t(":"",
				      node_uuid?node_uuid:"",
				      node_uuid?")":"");
			break;
		default:
			do_crm_log_unlikely(log_level,
				      "%s%s%sAction %d: %s %s%s%s%s%s%s",
				      pre_text==NULL?"":pre_text,
				      pre_text==NULL?"":": ",
				      action->optional?"Optional ":action->pseudo?"Pseduo ":action->runnable?action->processed?"":"(Provisional) ":"!!Non-Startable!! ",
				      action->id, action->uuid,
				      safe_val3("<none>", action, rsc, id),
				      node_uname?"\ton ":"",
				      node_uname?node_uname:"",
				      node_uuid?"\t\t(":"",
				      node_uuid?node_uuid:"",
				      node_uuid?")":"");
			
			break;
	}

	if(details) {
		do_crm_log_unlikely(log_level+1, "\t\t====== Preceding Actions");
		slist_iter(
			other, action_wrapper_t, action->actions_before, lpc,
			log_action(log_level+1, "\t\t", other->action, FALSE);
			);
		do_crm_log_unlikely(log_level+1, "\t\t====== Subsequent Actions");
		slist_iter(
			other, action_wrapper_t, action->actions_after, lpc,
			log_action(log_level+1, "\t\t", other->action, FALSE);
			);		
		do_crm_log_unlikely(log_level+1, "\t\t====== End");

	} else {
		do_crm_log_unlikely(log_level, "\t\t(seen=%d, before=%d, after=%d)",
			      action->seen_count,
			      g_list_length(action->actions_before),
			      g_list_length(action->actions_after));
	}
}

action_t *get_pseudo_op(const char *name, pe_working_set_t *data_set) 
{
    action_t *op = NULL;
    const char *op_s = name;
    GListPtr possible_matches = NULL;

    possible_matches = find_actions(data_set->actions, name, NULL);
    if(possible_matches != NULL) {
	if(g_list_length(possible_matches) > 1) {
	    pe_warn("Action %s exists %d times",
		    name, g_list_length(possible_matches));
	}
		
	op = g_list_nth_data(possible_matches, 0);
	g_list_free(possible_matches);

    } else {
	op = custom_action(NULL, crm_strdup(op_s), op_s,
			   NULL, TRUE, TRUE, data_set);
	op->pseudo = TRUE;
	op->runnable = TRUE;
    }

    return op;
}

gboolean can_run_any(GListPtr nodes)
{
	if(nodes == NULL) {
	    return FALSE;
	}

	slist_iter(
	    node, node_t, nodes, lpc,
	    if(can_run_resources(node) && node->weight >= 0) {
		return TRUE;
	    }
	    );

	return FALSE;
}

enum rsc_role_e
minimum_resource_state(resource_t *rsc, gboolean current)
{
    enum rsc_role_e min_role = RSC_ROLE_MAX;
    
    if(rsc->children) {
	slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		enum rsc_role_e role = child_rsc->fns->state(child_rsc, current);
		if(role < min_role) {
			min_role = role;
		}
	    );
	return min_role;
    }
    return rsc->fns->state(rsc, current);
}

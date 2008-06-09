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
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

#include <glib.h>

#include <crm/pengine/rules.h>
#include <utils.h>

void print_str_str(gpointer key, gpointer value, gpointer user_data);
gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data);
void unpack_operation(
	action_t *action, xmlNode *xml_obj, pe_working_set_t* data_set);

void
pe_free_shallow(GListPtr alist)
{
	pe_free_shallow_adv(alist, TRUE);
}

void
pe_free_shallow_adv(GListPtr alist, gboolean with_data)
{
	GListPtr item;
	GListPtr item_next = alist;

	if(with_data == FALSE && alist != NULL) {
		g_list_free(alist);
		return;
	}
	
	while(item_next != NULL) {
		item = item_next;
		item_next = item_next->next;
		
		if(with_data) {
/*			crm_debug_5("freeing %p", item->data); */
			crm_free(item->data);
		}
		
		item->data = NULL;
		item->next = NULL;
		g_list_free_1(item);
	}
}


node_t *
node_copy(node_t *this_node) 
{
	node_t *new_node  = NULL;

	CRM_CHECK(this_node != NULL, return NULL);

	crm_malloc0(new_node, sizeof(node_t));
	CRM_ASSERT(new_node != NULL);
	
	crm_debug_5("Copying %p (%s) to %p",
		  this_node, this_node->details->uname, new_node);

	new_node->weight  = this_node->weight; 
	new_node->fixed   = this_node->fixed;
	new_node->details = this_node->details;	
	
	return new_node;
}

/* are the contents of list1 and list2 equal 
 * nodes with weight < 0 are ignored if filter == TRUE
 *
 * slow but linear
 *
 */
gboolean
node_list_eq(GListPtr list1, GListPtr list2, gboolean filter)
{
	node_t *other_node;

	GListPtr lhs = list1;
	GListPtr rhs = list2;
	
	slist_iter(
		node, node_t, lhs, lpc,

		if(node == NULL || (filter && node->weight < 0)) {
			continue;
		}

		other_node = (node_t*)
			pe_find_node_id(rhs, node->details->id);

		if(other_node == NULL || other_node->weight < 0) {
			return FALSE;
		}
		);
	
	lhs = list2;
	rhs = list1;

	slist_iter(
		node, node_t, lhs, lpc,

		if(node == NULL || (filter && node->weight < 0)) {
			continue;
		}

		other_node = (node_t*)
			pe_find_node_id(rhs, node->details->id);

		if(other_node == NULL || other_node->weight < 0) {
			return FALSE;
		}
		);
  
	return TRUE;
}

/* any node in list1 or list2 and not in the other gets a score of -INFINITY */
GListPtr
node_list_exclude(GListPtr list1, GListPtr list2)
{
    node_t *other_node = NULL;
    GListPtr result = NULL;
    
    result = node_list_dup(list1, FALSE, FALSE);
    
    slist_iter(
	node, node_t, result, lpc,
	
	other_node = pe_find_node_id(list2, node->details->id);
	
	if(other_node == NULL) {
	    node->weight = -INFINITY;
	} else {
	    node->weight = merge_weights(node->weight, other_node->weight);
	}
	);
    
    slist_iter(
	node, node_t, list2, lpc,
	
	other_node = pe_find_node_id(result, node->details->id);
	
	if(other_node == NULL) {
	    node_t *new_node = node_copy(node);
	    new_node->weight = -INFINITY;
	    result = g_list_append(result, new_node);
	}
	);

    return result;
}

/* the intersection of list1 and list2 */
GListPtr
node_list_and(GListPtr list1, GListPtr list2, gboolean filter)
{
	GListPtr result = NULL;
	unsigned lpc = 0;

	for(lpc = 0; lpc < g_list_length(list1); lpc++) {
		node_t *node = (node_t*)g_list_nth_data(list1, lpc);
		node_t *other_node = pe_find_node_id(list2, node->details->id);
		node_t *new_node = NULL;

		if(other_node != NULL) {
			new_node = node_copy(node);
		}
		
		if(new_node != NULL) {
			crm_debug_4("%s: %d + %d", node->details->uname, 
				    other_node->weight, new_node->weight);
			new_node->weight = merge_weights(
				new_node->weight, other_node->weight);

			crm_debug_3("New node weight for %s: %d",
				 new_node->details->uname, new_node->weight);
			
			if(filter && new_node->weight < 0) {
				crm_free(new_node);
				new_node = NULL;
			}
		}
		
		if(new_node != NULL) {
			result = g_list_append(result, new_node);
		}
	}

	return result;
}


/* list1 - list2 */
GListPtr
node_list_minus(GListPtr list1, GListPtr list2, gboolean filter)
{
	GListPtr result = NULL;

	slist_iter(
		node, node_t, list1, lpc,
		node_t *other_node = pe_find_node_id(list2, node->details->id);
		node_t *new_node = NULL;
		
		if(node == NULL || other_node != NULL
		   || (filter && node->weight < 0)) {
			continue;
			
		}
		new_node = node_copy(node);
		result = g_list_append(result, new_node);
		);
  
	crm_debug_3("Minus result len: %d", g_list_length(result));

	return result;
}

/* list1 + list2 - (intersection of list1 and list2) */
GListPtr
node_list_xor(GListPtr list1, GListPtr list2, gboolean filter)
{
	GListPtr result = NULL;
	
	slist_iter(
		node, node_t, list1, lpc,
		node_t *new_node = NULL;
		node_t *other_node = (node_t*)
			pe_find_node_id(list2, node->details->id);

		if(node == NULL || other_node != NULL
		   || (filter && node->weight < 0)) {
			continue;
		}
		new_node = node_copy(node);
		result = g_list_append(result, new_node);
		);
	
 
	slist_iter(
		node, node_t, list2, lpc,
		node_t *new_node = NULL;
		node_t *other_node = (node_t*)
			pe_find_node_id(list1, node->details->id);

		if(node == NULL || other_node != NULL
		   || (filter && node->weight < 0)) {
			continue;
		}
		new_node = node_copy(node);
		result = g_list_append(result, new_node);
		);
  
	crm_debug_3("Xor result len: %d", g_list_length(result));
	return result;
}

GListPtr
node_list_or(GListPtr list1, GListPtr list2, gboolean filter)
{
	node_t *other_node = NULL;
	GListPtr result = NULL;
	gboolean needs_filter = FALSE;

	result = node_list_dup(list1, FALSE, filter);

	slist_iter(
		node, node_t, list2, lpc,

		if(node == NULL) {
			continue;
		}

		other_node = (node_t*)pe_find_node_id(
			result, node->details->id);

		if(other_node != NULL) {
			crm_debug_4("%s + %s: %d + %d",
				    node->details->uname, 
				    other_node->details->uname, 
				    node->weight, other_node->weight);
			other_node->weight = merge_weights(
				other_node->weight, node->weight);
			
			if(filter && node->weight < 0) {
				needs_filter = TRUE;
			}

		} else if(filter == FALSE || node->weight >= 0) {
			node_t *new_node = node_copy(node);
			result = g_list_append(result, new_node);
		}
		);

	/* not the neatest way, but the most expedient for now */
	if(filter && needs_filter) {
		GListPtr old_result = result;
		result = node_list_dup(old_result, FALSE, filter);
		pe_free_shallow_adv(old_result, TRUE);
	}
	

	return result;
}

GListPtr 
node_list_dup(GListPtr list1, gboolean reset, gboolean filter)
{
	GListPtr result = NULL;

	slist_iter(
		this_node, node_t, list1, lpc,
		node_t *new_node = NULL;
		if(filter && this_node->weight < 0) {
			continue;
		}
		
		new_node = node_copy(this_node);
		if(reset) {
			new_node->weight = 0;
		}
		if(new_node != NULL) {
			result = g_list_append(result, new_node);
		}
		);

	return result;
}


void dump_node_scores(int level, resource_t *rsc, const char *comment, GListPtr nodes) 
{
    GListPtr list = nodes;
    if(rsc) {
	list = rsc->allowed_nodes;
    }
    
    slist_iter(
	node, node_t, list, lpc,
	if(rsc) {
	    do_crm_log(level, "%s: %s allocation score on %s: %d",
		       comment, rsc->id, node->details->uname, node->weight);
	} else {
	    do_crm_log(level, "%s: %s = %d", comment, node->details->uname, node->weight);
	}
	);

    if(rsc && rsc->children) {
	slist_iter(
	    child, resource_t, rsc->children, lpc,
	    dump_node_scores(level, child, comment, nodes);
	    );
    }
}

gint sort_rsc_index(gconstpointer a, gconstpointer b)
{
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	if(a == NULL && b == NULL) { return 0; }
	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }
  
	if(resource1->sort_index > resource2->sort_index) {
		return -1;
	}
	
	if(resource1->sort_index < resource2->sort_index) {
		return 1;
	}

	return 0;
}

gint sort_rsc_priority(gconstpointer a, gconstpointer b)
{
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	if(a == NULL && b == NULL) { return 0; }
	if(a == NULL) { return 1; }
	if(b == NULL) { return -1; }
  
	if(resource1->priority > resource2->priority) {
		return -1;
	}
	
	if(resource1->priority < resource2->priority) {
		return 1;
	}

	return 0;
}

action_t *
custom_action(resource_t *rsc, char *key, const char *task,
	      node_t *on_node, gboolean optional, gboolean save_action,
	      pe_working_set_t *data_set)
{
	action_t *action = NULL;
	GListPtr possible_matches = NULL;
	CRM_CHECK(key != NULL, return NULL);
	CRM_CHECK(task != NULL, return NULL);

	if(save_action && rsc != NULL) {
		possible_matches = find_actions(rsc->actions, key, on_node);
	}
	
	if(possible_matches != NULL) {
		crm_free(key);
		
		if(g_list_length(possible_matches) > 1) {
			pe_warn("Action %s for %s on %s exists %d times",
				task, rsc?rsc->id:"<NULL>",
				on_node?on_node->details->uname:"<NULL>",
				g_list_length(possible_matches));
		}
		
		action = g_list_nth_data(possible_matches, 0);
		crm_debug_4("Found existing action (%d) %s for %s on %s",
			  action->id, task, rsc?rsc->id:"<NULL>",
			  on_node?on_node->details->uname:"<NULL>");
		g_list_free(possible_matches);
	}

	if(action == NULL) {
		if(save_action) {
			crm_debug_4("Creating%s action %d: %s for %s on %s",
				    optional?"":" manditory", data_set->action_id, key, rsc?rsc->id:"<NULL>",
				    on_node?on_node->details->uname:"<NULL>");
		}
		
		crm_malloc0(action, sizeof(action_t));
		if(save_action) {
			action->id   = data_set->action_id++;
		} else {
			action->id = 0;
		}
		action->rsc  = rsc;
		CRM_ASSERT(task != NULL);
		action->task = crm_strdup(task);
		action->node = on_node;
		action->uuid = key;
		
		action->actions_before   = NULL;
		action->actions_after    = NULL;
		action->failure_is_fatal = TRUE;
		
		action->pseudo     = FALSE;
		action->dumped     = FALSE;
		action->runnable   = TRUE;
		action->processed  = FALSE;
		action->optional   = optional;
		action->seen_count = 0;
		
		action->extra = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		action->meta = g_hash_table_new_full(
			g_str_hash, g_str_equal,
			g_hash_destroy_str, g_hash_destroy_str);
		
		if(save_action) {
			data_set->actions = g_list_append(
				data_set->actions, action);
		}		
		
		if(rsc != NULL) {
			action->op_entry = find_rsc_op_entry(rsc, key);
			
			unpack_operation(
				action, action->op_entry, data_set);
			
			if(save_action) {
				rsc->actions = g_list_append(
					rsc->actions, action);
			}
		}
		
		if(save_action) {
			crm_debug_4("Action %d created", action->id);
		}
	}

	if(optional == FALSE && action->optional) {
		crm_debug_2("Action %d (%s) marked manditory",
			    action->id, action->uuid);
		action->optional = FALSE;
	}
	
	if(rsc != NULL) {
		enum action_tasks a_task = text2task(action->task);
		int warn_level = LOG_DEBUG_3;
		if(save_action) {
			warn_level = LOG_WARNING;
		}

		if(action->node != NULL && action->op_entry != NULL) {
			unpack_instance_attributes(
				action->op_entry, XML_TAG_ATTR_SETS,
				action->node->details->attrs,
				action->extra, NULL, FALSE, data_set->now);
		}

		if(action->pseudo) {
			/* leave untouched */
			
		} else if(action->node == NULL) {
			action->runnable = FALSE;
			
		} else if(is_not_set(rsc->flags, pe_rsc_managed)) {
			do_crm_log(warn_level, "Action %s (unmanaged)",
				 action->uuid);
			action->optional = TRUE;
/*   			action->runnable = FALSE; */

		} else if(action->node->details->online == FALSE) {
			action->runnable = FALSE;
			do_crm_log(warn_level, "Action %s on %s is unrunnable (offline)",
				 action->uuid, action->node->details->uname);
			if(is_set(action->rsc->flags, pe_rsc_managed)
			   && save_action
			   && a_task == stop_rsc) {
				do_crm_log(warn_level, "Marking node %s unclean",
					 action->node->details->uname);
				action->node->details->unclean = TRUE;
			}
			
		} else if(action->node->details->pending) {
			action->runnable = FALSE;
			do_crm_log(warn_level, "Action %s on %s is unrunnable (pending)",
				 action->uuid, action->node->details->uname);

		} else if(action->needs == rsc_req_nothing) {
			crm_debug_3("Action %s doesnt require anything",
				  action->uuid);
			action->runnable = TRUE;
#if 0
			/*
			 * No point checking this
			 * - if we dont have quorum we cant stonith anyway
			 */
		} else if(action->needs == rsc_req_stonith) {
			crm_debug_3("Action %s requires only stonith", action->uuid);
			action->runnable = TRUE;
#endif
		} else if(data_set->have_quorum == FALSE
			&& data_set->no_quorum_policy == no_quorum_stop) {
			action->runnable = FALSE;
			crm_debug("%s\t%s (cancelled : quorum)",
				  action->node->details->uname,
				  action->uuid);
			
		} else if(data_set->have_quorum == FALSE
			&& data_set->no_quorum_policy == no_quorum_freeze) {
			crm_debug_3("Check resource is already active");
			if(rsc->fns->active(rsc, TRUE) == FALSE) {
				action->runnable = FALSE;
				crm_debug("%s\t%s (cancelled : quorum freeze)",
					  action->node->details->uname,
					  action->uuid);
			}

		} else {
			crm_debug_3("Action %s is runnable", action->uuid);
			action->runnable = TRUE;
		}

		if(save_action) {
			switch(a_task) {
				case stop_rsc:
				    set_bit(rsc->flags, pe_rsc_stopping);
				    break;
				case start_rsc:
				    clear_bit(rsc->flags, pe_rsc_starting);
				    if(action->runnable) {
					set_bit(rsc->flags, pe_rsc_starting);
				    }
				    break;
				default:
					break;
			}
		}
	}
	return action;
}

void
unpack_operation(
	action_t *action, xmlNode *xml_obj, pe_working_set_t* data_set)
{
	int value_i = 0;
	int start_delay = 0;
	char *value_ms = NULL;
	const char *class = NULL;
	const char *value = NULL;
	const char *field = NULL;
	
	CRM_CHECK(action->rsc != NULL, return);
	class = g_hash_table_lookup(action->rsc->meta, "class");
	
	if(xml_obj != NULL) {
		value = crm_element_value(xml_obj, "prereq");
	}
	
	if(value == NULL && safe_str_neq(action->task, CRMD_ACTION_START)) {
		/* todo: integrate stop as an option? */
		action->needs = rsc_req_nothing;
		value = "nothing (default)";

	} else if(safe_str_eq(value, "nothing")) {
		action->needs = rsc_req_nothing;

	} else if(safe_str_eq(value, "quorum")) {
		action->needs = rsc_req_quorum;

	} else if(safe_str_eq(value, "fencing")) {
		action->needs = rsc_req_stonith;
		
	} else if(data_set->no_quorum_policy == no_quorum_ignore
	    || safe_str_eq(class, "stonith")) {
		action->needs = rsc_req_nothing;
		value = "nothing (default)";
		
	} else if(data_set->no_quorum_policy == no_quorum_freeze
		  && data_set->stonith_enabled) {
		action->needs = rsc_req_stonith;
		value = "fencing (default)";

	} else {
		action->needs = rsc_req_quorum;
		value = "quorum (default)";
	}

	if(safe_str_eq(class, "stonith")) {
		if(action->needs == rsc_req_stonith) {
			crm_config_err("Stonith resources (eg. %s) cannot require"
				      " fencing to start", action->rsc->id);
		}
		action->needs = rsc_req_nothing;
		value = "nothing (fencing override)";
	}
	crm_debug_3("\tAction %s requires: %s", action->task, value);

	value = NULL;
	if(xml_obj != NULL) {
		value = crm_element_value(xml_obj, XML_OP_ATTR_ON_FAIL);
	}
	if(value == NULL) {

	} else if(safe_str_eq(value, "block")) {
		action->on_fail = action_fail_block;

	} else if(safe_str_eq(value, "fence")) {
		action->on_fail = action_fail_fence;
		value = "node fencing";
		
		if(data_set->stonith_enabled == FALSE) {
		    crm_config_err("Specifying on_fail=fence and"
				   " stonith-enabled=false makes no sense");
		    action->on_fail = action_fail_stop;
		    action->fail_role = RSC_ROLE_STOPPED;
		    value = "stop resource";
		}
		
	} else if(safe_str_eq(value, "ignore")
		|| safe_str_eq(value, "nothing")) {
		action->on_fail = action_fail_ignore;
		value = "ignore";

	} else if(safe_str_eq(value, "migrate")) {
		action->on_fail = action_fail_migrate;
		value = "force migration";
		
	} else if(safe_str_eq(value, "stop")) {
		action->on_fail = action_fail_stop;
		action->fail_role = RSC_ROLE_STOPPED;
		value = "stop resource";
		
	} else if(safe_str_eq(value, "restart")) {
		action->on_fail = action_fail_recover;
		value = "restart (and possibly migrate)";
		
	} else {
		pe_err("Resource %s: Unknown failure type (%s)",
		       action->rsc->id, value);
		value = NULL;
	}
	
	/* defaults */
	if(value == NULL && safe_str_eq(action->task, CRMD_ACTION_STOP)) {
		if(data_set->stonith_enabled) {
			action->on_fail = action_fail_fence;		
			value = "resource fence (default)";
			
		} else {
			action->on_fail = action_fail_block;		
			value = "resource block (default)";
		}
		
	} else if(value == NULL
		  && safe_str_eq(action->task, CRMD_ACTION_MIGRATED)) {
		action->on_fail = action_migrate_failure;		
		value = "atomic migration recovery (default)";
		
	} else if(value == NULL) {
		action->on_fail = action_fail_recover;		
		value = "restart (and possibly migrate) (default)";
	}
	
	crm_debug_3("\t%s failure handling: %s", action->task, value);

	value = NULL;
	if(xml_obj != NULL) {
		value = crm_element_value(xml_obj, "role_after_failure");
	}
	if(value != NULL && action->fail_role == RSC_ROLE_UNKNOWN) {
		action->fail_role = text2role(value);
	}
	/* defaults */
	if(action->fail_role == RSC_ROLE_UNKNOWN) {
		if(safe_str_eq(action->task, CRMD_ACTION_PROMOTE)) {
			action->fail_role = RSC_ROLE_SLAVE;
		} else {
			action->fail_role = RSC_ROLE_STARTED;
		}
	}
	crm_debug_3("\t%s failure results in: %s",
		    action->task, role2text(action->fail_role));
	
	if(xml_obj != NULL) {
		xml_prop_iter(xml_obj, p_name, p_value,
			      if(p_value != NULL) {
				      g_hash_table_insert(action->meta, crm_strdup(p_name),
							  crm_strdup(p_value));
			      }
			);

		g_hash_table_remove(action->meta, "id");
		
		unpack_instance_attributes(xml_obj, XML_TAG_META_SETS,
					   NULL, action->meta, NULL, FALSE, data_set->now);
		
		unpack_instance_attributes(xml_obj, XML_TAG_ATTR_SETS,
					   NULL, action->meta, NULL, FALSE, data_set->now);
	}

	field = XML_LRM_ATTR_INTERVAL;
	value = g_hash_table_lookup(action->meta, field);
	if(value != NULL) {
		value_i = crm_get_msec(value);
		CRM_CHECK(value_i >= 0, value_i = 0);
		value_ms = crm_itoa(value_i);
		if(value_i > 0) {
		    g_hash_table_replace(action->meta, crm_strdup(field), value_ms);
		} else {
		    g_hash_table_remove(action->meta, field);
		}
	}

	field = XML_OP_ATTR_START_DELAY;
	value = g_hash_table_lookup(action->meta, field);
	if(value != NULL) {
		value_i = crm_get_msec(value);
		if(value_i < 0) {
			value_i = 0;
		}
		start_delay = value_i;
		value_ms = crm_itoa(value_i);
		g_hash_table_replace(action->meta, crm_strdup(field), value_ms);
	}

	field = XML_ATTR_TIMEOUT;
	value = g_hash_table_lookup(action->meta, field);
	if(value == NULL) {
		value = pe_pref(
			data_set->config_hash, "default-action-timeout");
	}
	value_i = crm_get_msec(value);
	if(value_i < 0) {
		value_i = 0;
	}
	value_i += start_delay;
	value_ms = crm_itoa(value_i);
	g_hash_table_replace(action->meta, crm_strdup(field), value_ms);
}

xmlNode *
find_rsc_op_entry(resource_t *rsc, const char *key) 
{
	int number = 0;
	const char *name = NULL;
	const char *value = NULL;
	const char *interval = NULL;
	char *match_key = NULL;
	xmlNode *op = NULL;
	
	xml_child_iter_filter(
		rsc->ops_xml, operation, "op",

		name = crm_element_value(operation, "name");
		interval = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
		value = crm_element_value(operation, "disabled");
		if(crm_is_true(value)) {
			crm_debug_2("%s disabled", ID(operation));
			continue;
		}

		number = crm_get_msec(interval);
		if(number < 0) {
		    continue;
		}
		
		match_key = generate_op_key(rsc->id, name, number);

		if(safe_str_eq(key, match_key)) {
			op = operation;
		}
		crm_free(match_key);

		if(op != NULL) {
			return op;
		}
		);
	crm_debug_3("No match for %s", key);
	return op;
}

void
print_node(const char *pre_text, node_t *node, gboolean details)
{ 
	if(node == NULL) {
		crm_debug_4("%s%s: <NULL>",
		       pre_text==NULL?"":pre_text,
		       pre_text==NULL?"":": ");
		return;
	}

	crm_debug_4("%s%s%sNode %s: (weight=%d, fixed=%s)",
	       pre_text==NULL?"":pre_text,
	       pre_text==NULL?"":": ",
	       node->details==NULL?"error ":node->details->online?"":"Unavailable/Unclean ",
	       node->details->uname, 
	       node->weight,
	       node->fixed?"True":"False"); 

	if(details && node != NULL && node->details != NULL) {
		char *pe_mutable = crm_strdup("\t\t");
		crm_debug_4("\t\t===Node Attributes");
		g_hash_table_foreach(node->details->attrs,
				     print_str_str, pe_mutable);
		crm_free(pe_mutable);

		crm_debug_4("\t\t=== Resources");
		slist_iter(
			rsc, resource_t, node->details->running_rsc, lpc,
			print_resource(LOG_DEBUG_4, "\t\t", rsc, FALSE);
			);
	}
}

/*
 * Used by the HashTable for-loop
 */
void print_str_str(gpointer key, gpointer value, gpointer user_data)
{
	crm_debug_4("%s%s %s ==> %s",
	       user_data==NULL?"":(char*)user_data,
	       user_data==NULL?"":": ",
	       (char*)key,
	       (char*)value);
}

void
print_resource(
	int log_level, const char *pre_text, resource_t *rsc, gboolean details)
{
	long options = pe_print_log;
	
	if(rsc == NULL) {
		do_crm_log(log_level-1, "%s%s: <NULL>",
			      pre_text==NULL?"":pre_text,
			      pre_text==NULL?"":": ");
		return;
	}
	if(details) {
		options |= pe_print_details;
	}
	rsc->fns->print(rsc, pre_text, options, &log_level);
}

void
pe_free_action(action_t *action) 
{
	if(action == NULL) {
		return;
	}
	pe_free_shallow(action->actions_before);/* action_warpper_t* */
	pe_free_shallow(action->actions_after); /* action_warpper_t* */
	g_hash_table_destroy(action->extra);
	g_hash_table_destroy(action->meta);
	crm_free(action->task);
	crm_free(action->uuid);
	crm_free(action);
}

GListPtr
find_recurring_actions(GListPtr input, node_t *not_on_node)
{
	const char *value = NULL;
	GListPtr result = NULL;
	CRM_CHECK(input != NULL, return NULL);
	
	slist_iter(
		action, action_t, input, lpc,
		value = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL);
		if(value == NULL) {
			/* skip */
		} else if(safe_str_eq(value, "0")) {
			/* skip */
		} else if(safe_str_eq(CRMD_ACTION_CANCEL, action->task)) {
			/* skip */
		} else if(not_on_node == NULL) {
			crm_debug_5("(null) Found: %s", action->uuid);
			result = g_list_append(result, action);
			
		} else if(action->node == NULL) {
			/* skip */
		} else if(action->node->details != not_on_node->details) {
			crm_debug_5("Found: %s", action->uuid);
			result = g_list_append(result, action);
		}
		);

	return result;
}

GListPtr
find_actions(GListPtr input, const char *key, node_t *on_node)
{
	GListPtr result = NULL;
	CRM_CHECK(key != NULL, return NULL);
	
	slist_iter(
		action, action_t, input, lpc,
		crm_debug_5("Matching %s against %s", key, action->uuid);
		if(safe_str_neq(key, action->uuid)) {
			continue;
			
		} else if(on_node == NULL) {
			result = g_list_append(result, action);
			
		} else if(action->node == NULL) {
			/* skip */
			crm_debug_2("While looking for %s action on %s, "
				    "found an unallocated one.  Assigning"
				    " it to the requested node...",
				    key, on_node->details->uname);

			action->node = on_node;
			result = g_list_append(result, action);
			
		} else if(safe_str_eq(on_node->details->id,
				      action->node->details->id)) {
			result = g_list_append(result, action);
		}
		);

	return result;
}


GListPtr
find_actions_exact(GListPtr input, const char *key, node_t *on_node)
{
	GListPtr result = NULL;
	CRM_CHECK(key != NULL, return NULL);
	
	slist_iter(
		action, action_t, input, lpc,
		crm_debug_5("Matching %s against %s", key, action->uuid);
		if(safe_str_neq(key, action->uuid)) {
			crm_debug_3("Key mismatch: %s vs. %s",
				    key, action->uuid);
			continue;
			
		} else if(on_node == NULL  || action->node == NULL) {
			crm_debug_3("on_node=%p, action->node=%p",
				    on_node, action->node);
			continue;

		} else if(safe_str_eq(on_node->details->id,
				      action->node->details->id)) {
			result = g_list_append(result, action);
		}
		crm_debug_2("Node mismatch: %s vs. %s",
			    on_node->details->id, action->node->details->id);
		);

	return result;
}

void
set_id(xmlNode * xml_obj, const char *prefix, int child) 
{
	int id_len = 0;
	gboolean use_prefix = TRUE;
	gboolean use_child = TRUE;

	char *new_id   = NULL;
	const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
	
	id_len = 1 + strlen(id);

	if(child > 999) {
		pe_err("Are you insane?!?"
			" The CRM does not support > 1000 children per resource");
		return;
		
	} else if(child < 0) {
		use_child = FALSE;
		
	} else {
		id_len += 4; /* child */
	}
	
	if(prefix == NULL || safe_str_eq(id, prefix)) {
		use_prefix = FALSE;
	} else {
		id_len += (1 + strlen(prefix));
	}
	
	crm_malloc0(new_id, id_len);

	if(use_child) {
		snprintf(new_id, id_len, "%s%s%s:%d",
			 use_prefix?prefix:"", use_prefix?":":"", id, child);
	} else {
		snprintf(new_id, id_len, "%s%s%s",
			 use_prefix?prefix:"", use_prefix?":":"", id);
	}
	
	crm_xml_add(xml_obj, XML_ATTR_ID, new_id);
	crm_free(new_id);
}

static void
resource_node_score(resource_t *rsc, node_t *node, int score, const char *tag) 
{
	node_t *match = NULL;

	if(rsc->children) {
	    slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		resource_node_score(child_rsc, node, score, tag);
		);
	}
	
	crm_debug_2("Setting %s for %s on %s: %d",
		    tag, rsc->id, node->details->uname, score);
	match = pe_find_node_id(rsc->allowed_nodes, node->details->id);
	if(match == NULL) {
		match = node_copy(node);
		match->weight = 0;
		rsc->allowed_nodes = g_list_append(rsc->allowed_nodes, match);
	}
	match->weight = merge_weights(match->weight, score);
}

void
resource_location(resource_t *rsc, node_t *node, int score, const char *tag,
		  pe_working_set_t *data_set) 
{
	if(node != NULL) {
		resource_node_score(rsc, node, score, tag);

	} else if(data_set != NULL) {
		slist_iter(
			node, node_t, data_set->nodes, lpc,
			resource_node_score(rsc, node, score, tag);
			);
	} else {
		slist_iter(
			node, node_t, rsc->allowed_nodes, lpc,
			resource_node_score(rsc, node, score, tag);
			);
	}

	if(node == NULL && score == -INFINITY) {
		if(rsc->allocated_to) {
			crm_info("Deallocating %s from %s", rsc->id, rsc->allocated_to->details->uname);
			crm_free(rsc->allocated_to);
			rsc->allocated_to = NULL;
		}
	}
}

#define sort_return(an_int) crm_free(a_uuid); crm_free(b_uuid); return an_int

gint
sort_op_by_callid(gconstpointer a, gconstpointer b)
{
	char *a_uuid = NULL;
	char *b_uuid = NULL;
	const xmlNode *xml_a = a;
	const xmlNode *xml_b = b;
	
 	const char *a_xml_id = crm_element_value_const(xml_a, XML_ATTR_ID);
 	const char *b_xml_id = crm_element_value_const(xml_b, XML_ATTR_ID);

 	const char *a_task_id = crm_element_value_const(xml_a, XML_LRM_ATTR_CALLID);
 	const char *b_task_id = crm_element_value_const(xml_b, XML_LRM_ATTR_CALLID);

	const char *a_key = crm_element_value_const(xml_a, XML_ATTR_TRANSITION_MAGIC);
 	const char *b_key = crm_element_value_const(xml_b, XML_ATTR_TRANSITION_MAGIC);

	int dummy = -1;
	
	int a_id = -1;
	int b_id = -1;

	int a_rc = -1;
	int b_rc = -1;

	int a_status = -1;
	int b_status = -1;
	
	int a_call_id = -1;
	int b_call_id = -1;

	if(safe_str_eq(a_xml_id, b_xml_id)) {
		/* We have duplicate lrm_rsc_op entries in the status
		 *    section which is unliklely to be a good thing
		 *    - we can handle it easily enough, but we need to get
		 *    to the bottom of why its happening.
		 */
		pe_err("Duplicate lrm_rsc_op entries named %s", a_xml_id);
		sort_return(0);
	}
	
	CRM_CHECK(a_task_id != NULL && b_task_id != NULL,
		  crm_err("a: %s, b: %s", crm_str(a_xml_id), crm_str(b_xml_id));
		  sort_return(0));	
	a_call_id = crm_parse_int(a_task_id, NULL);
	b_call_id = crm_parse_int(b_task_id, NULL);
	
	if(a_call_id == -1 && b_call_id == -1) {
		/* both are pending ops so it doesnt matter since
		 *   stops are never pending
		 */
		sort_return(0);

	} else if(a_call_id >= 0 && a_call_id < b_call_id) {
		crm_debug_4("%s (%d) < %s (%d) : call id",
			    a_xml_id, a_call_id, b_xml_id, b_call_id);
		sort_return(-1);

	} else if(b_call_id >= 0 && a_call_id > b_call_id) {
		crm_debug_4("%s (%d) > %s (%d) : call id",
			    a_xml_id, a_call_id, b_xml_id, b_call_id);
		sort_return(1);
	}

	crm_debug_5("%s (%d) == %s (%d) : continuing",
		    a_xml_id, a_call_id, b_xml_id, b_call_id);
	
	/* now process pending ops */
	CRM_CHECK(a_key != NULL && b_key != NULL, sort_return(0));
	CRM_CHECK(decode_transition_magic(
		      a_key, &a_uuid, &a_id, &dummy, &a_status, &a_rc, &dummy),
		  sort_return(0));
	CRM_CHECK(decode_transition_magic(
		      b_key, &b_uuid, &b_id, &dummy, &b_status, &b_rc, &dummy),
		  sort_return(0));

	/* try and determin the relative age of the operation...
	 * some pending operations (ie. a start) may have been supuerceeded
	 *   by a subsequent stop
	 *
	 * [a|b]_id == -1 means its a shutdown operation and _always_ comes last
	 */
	if(safe_str_neq(a_uuid, b_uuid) || a_id == b_id) {
		/*
		 * some of the logic in here may be redundant...
		 *
		 * if the UUID from the TE doesnt match then one better
		 *   be a pending operation.
		 * pending operations dont survive between elections and joins
		 *   because we query the LRM directly
		 */
		
		CRM_CHECK(a_call_id == -1 || b_call_id == -1,
			  crm_err("a: %s=%d, b: %s=%d",
				  crm_str(a_xml_id), a_call_id, crm_str(b_xml_id), b_call_id);
			  sort_return(0));
		CRM_CHECK(a_call_id >= 0  || b_call_id >= 0, sort_return(0));

		if(b_call_id == -1) {
			crm_debug_2("%s (%d) < %s (%d) : transition + call id",
				    a_xml_id, a_call_id, b_xml_id, b_call_id);
			sort_return(-1);
		}

		if(a_call_id == -1) {
			crm_debug_2("%s (%d) > %s (%d) : transition + call id",
				    a_xml_id, a_call_id, b_xml_id, b_call_id);
			sort_return(1);
		}
		
	} else if((a_id >= 0 && a_id < b_id) || b_id == -1) {
		crm_debug_3("%s (%d) < %s (%d) : transition",
			    a_xml_id, a_id, b_xml_id, b_id);
		sort_return(-1);

	} else if((b_id >= 0 && a_id > b_id) || a_id == -1) {
		crm_debug_3("%s (%d) > %s (%d) : transition",
			    a_xml_id, a_id, b_xml_id, b_id);
		sort_return(1);
	}

	/* we should never end up here */
	crm_err("%s (%d:%d:%s) ?? %s (%d:%d:%s) : default",
		a_xml_id, a_call_id, a_id, a_uuid, b_xml_id, b_call_id, b_id, b_uuid);
	CRM_CHECK(FALSE, sort_return(0)); 
}

time_t get_timet_now(pe_working_set_t *data_set) 
{
    time_t now = 0;
    if(data_set && data_set->now) {
	now = data_set->now->tm_now;
    }
    
    if(now == 0) {
	/* eventually we should convert data_set->now into time_tm
	 * for now, its only triggered by PE regression tests
	 */
	now = time(NULL);
	crm_crit("Defaulting to 'now'");
	if(data_set && data_set->now) {
	    data_set->now->tm_now = now;
	}
    }
    return now;
}


int get_failcount(node_t *node, resource_t *rsc, int *last_failure, pe_working_set_t *data_set) 
{
    int last = 0;
    int fail_count = 0;
    resource_t *failed = rsc;
    char *fail_attr = crm_concat("fail-count", rsc->id, '-');
    const char *value = g_hash_table_lookup(node->details->attrs, fail_attr);

    if(is_not_set(rsc->flags, pe_rsc_unique)) {
	failed = uber_parent(rsc);
    }
    
    if(value != NULL) {
	fail_count = char2score(value);
	crm_info("%s has failed %d times on %s",
		 rsc->id, fail_count, node->details->uname);
    }
    crm_free(fail_attr);
    
    fail_attr = crm_concat("last-failure", rsc->id, '-');
    value = g_hash_table_lookup(node->details->attrs, fail_attr);
    if(value != NULL && rsc->failure_timeout) {
	last = crm_parse_int(value, NULL);
	if(last_failure) {
	    *last_failure = last;
	}
	if(last > 0) {
	    time_t now = get_timet_now(data_set);		
	    if(now > (last + rsc->failure_timeout)) {
		crm_notice("Failcount for %s on %s has expired (limit was %ds)",
			   failed->id, node->details->uname, rsc->failure_timeout);
		fail_count = 0;
	    }
	}
    }
    
    crm_free(fail_attr);
    return fail_count;
}

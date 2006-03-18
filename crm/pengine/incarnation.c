/* $Id: incarnation.c,v 1.74 2006/03/18 17:23:48 andrew Exp $ */
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

void clone_create_notifications(
	resource_t *rsc, action_t *action, action_t *action_complete,
	pe_working_set_t *data_set);

extern gboolean rsc_colocation_new(
	const char *id, enum con_strength strength,
	resource_t *rsc_lh, resource_t *rsc_rh,
	const char *state_lh, const char *state_rh);

typedef struct clone_variant_data_s
{
		resource_t *self;

		int clone_max;
		int clone_node_max;

		int active_clones;
		int max_nodes;
		
		gboolean interleave;
		gboolean ordered;

		crm_data_t *xml_obj_child;
		
		gboolean notify_confirm;
		
		GListPtr child_list; /* resource_t* */
		
} clone_variant_data_t;

void child_stopping_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);

void child_starting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set);


#define get_clone_variant_data(data, rsc)				\
	CRM_ASSERT(rsc->variant == pe_clone || rsc->variant == pe_master); \
	data = (clone_variant_data_t *)rsc->variant_opaque;


static gboolean
create_child_clone(resource_t *rsc, int sub_id, pe_working_set_t *data_set) 
{
	resource_t *child_rsc = NULL;
	crm_data_t * child_copy = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	CRM_CHECK(clone_data->xml_obj_child != NULL, return FALSE);
	child_copy = copy_xml(clone_data->xml_obj_child);
	if(data_set->short_rsc_names) {
		set_id(child_copy, NULL, sub_id);
	} else {
		set_id(child_copy, rsc->id, sub_id);
	}
	
	if(common_unpack(child_copy, &child_rsc,
			 clone_data->self->parameters, data_set)) {
		char *inc_num = crm_itoa(sub_id);
		char *inc_max = crm_itoa(clone_data->clone_max);
		
		crm_debug_3("Setting clone attributes for: %s", child_rsc->id);
		clone_data->child_list = g_list_append(
			clone_data->child_list, child_rsc);

		child_rsc->parent = rsc;

		add_rsc_param(
			child_rsc, XML_RSC_ATTR_INCARNATION, inc_num);
		add_rsc_param(
			child_rsc, XML_RSC_ATTR_INCARNATION_MAX, inc_max);
		
		print_resource(LOG_DEBUG_3, "Added", child_rsc, FALSE);
		
		crm_free(inc_num);
		crm_free(inc_max);
		
	} else {
		pe_err("Failed unpacking resource %s",
		       crm_element_value(child_copy, XML_ATTR_ID));
		return FALSE;
	}
	
	return TRUE;
}

void clone_unpack(resource_t *rsc, pe_working_set_t *data_set)
{
	int lpc = 0;
	crm_data_t * xml_tmp = NULL;
	crm_data_t * xml_obj = rsc->xml;
	crm_data_t *xml_self = copy_xml(rsc->xml);
	clone_variant_data_t *clone_data = NULL;
	resource_t *self = NULL;

	const char *ordered =
		crm_element_value(xml_obj, XML_RSC_ATTR_ORDERED);
	const char *interleave =
		crm_element_value(xml_obj, XML_RSC_ATTR_INTERLEAVE);

	const char *max_clones = g_hash_table_lookup(
		rsc->parameters, XML_RSC_ATTR_INCARNATION_MAX);
	const char *max_clones_node = g_hash_table_lookup(
		rsc->parameters, XML_RSC_ATTR_INCARNATION_NODEMAX);

	crm_debug_3("Processing resource %s...", rsc->id);

	crm_malloc0(clone_data, sizeof(clone_variant_data_t));
	clone_data->child_list  = NULL;
	clone_data->interleave  = FALSE;
	clone_data->ordered     = FALSE;
	
	clone_data->active_clones  = 0;
	clone_data->xml_obj_child  = NULL;
	clone_data->clone_max      = crm_parse_int(max_clones,     "1");
	clone_data->clone_node_max = crm_parse_int(max_clones_node,"1");
	
	/* this is a bit of a hack - but simplifies everything else */
	ha_msg_mod(xml_self, F_XML_TAGNAME, XML_CIB_TAG_RESOURCE);
/* 	set_id(xml_self, "self", -1); */
	xml_tmp = find_xml_node(xml_obj, "operations", FALSE);
	if(xml_tmp != NULL) {
		add_node_copy(xml_self, xml_tmp);
	}

	clone_data->xml_obj_child = find_xml_node(
		xml_obj, XML_CIB_TAG_GROUP, FALSE);

	if(clone_data->xml_obj_child == NULL) {
		clone_data->xml_obj_child = find_xml_node(
			xml_obj, XML_CIB_TAG_RESOURCE, TRUE);
	}

	CRM_CHECK(clone_data->xml_obj_child != NULL, return);

	if(common_unpack(xml_self, &self, NULL, data_set)) {
		clone_data->self = self;

	} else {
		crm_log_xml_err(xml_self, "Couldnt unpack dummy child");
		return;
	}
	
	if(crm_is_true(interleave)) {
		clone_data->interleave = TRUE;
	}
	if(crm_is_true(ordered)) {
		clone_data->ordered = TRUE;
	}

	clone_data->notify_confirm = clone_data->self->notify;

	rsc->variant_opaque = clone_data;

/* 	clone_data->gloabally_unique && */
	for(lpc = 0; lpc < clone_data->clone_max; lpc++) {
		create_child_clone(rsc, lpc, data_set);
	}
	
	crm_debug_3("Added %d children to resource %s...",
		    clone_data->clone_max, rsc->id);
}

resource_t *
clone_find_child(resource_t *rsc, const char *id)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	return pe_find_resource(clone_data->child_list, id);
}

GListPtr clone_children(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	return clone_data->child_list;
}

int clone_num_allowed_nodes(resource_t *rsc)
{
	int num_nodes = 0;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	/* what *should* we return here? */
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		int tmp_num_nodes = child_rsc->fns->num_allowed_nodes(child_rsc);
		if(tmp_num_nodes > num_nodes) {
			num_nodes = tmp_num_nodes;
		}
		);

	return num_nodes;
}

static gint sort_rsc_provisional(gconstpointer a, gconstpointer b)
{
	const resource_t *resource1 = (const resource_t*)a;
	const resource_t *resource2 = (const resource_t*)b;

	CRM_ASSERT(resource1 != NULL);
	CRM_ASSERT(resource2 != NULL);

	if(resource1->provisional == resource2->provisional) {
		return 0;

	} else if(resource1->provisional) {
		return 1;

	} else if(resource2->provisional) {
		return -1;
	}
	CRM_CHECK(FALSE, return 0);
	return 0;
}

static gboolean
can_run_resources(node_t *node)
{
	if(node->details->online == FALSE
	   ||  node->details->unclean
	   ||  node->details->standby) {
		return FALSE;
	}
	return TRUE;
}

static GListPtr
next_color(GListPtr head, GListPtr iter, int max)
{
	color_t *color = NULL;
	GListPtr local_iter = iter;
	crm_debug_4("Checking iter: %p", iter);
	if(local_iter != NULL) {
		local_iter = local_iter->next;
	}	
	for(; local_iter != NULL; local_iter = local_iter->next) {
		color = local_iter->data;
		crm_debug_5("Color %d: %d",
			  color->details->id, color->details->num_resources);
		if(color->details->num_resources < max) {
			return local_iter;
		}
	}
	
	local_iter = head;
	crm_debug_4("Now checking head: %p", head);
	for(; local_iter != NULL; local_iter = local_iter->next) {
		color = local_iter->data;
		crm_debug_5("Color %d: %d",
			  color->details->id, color->details->num_resources);
		if(color->details->num_resources < max) {
			return local_iter;
		}
	}	

	crm_debug_3("Nothing available: %p", head);
	return NULL;
}


color_t *
clone_color(resource_t *rsc, pe_working_set_t *data_set)
{
	GListPtr color_ptr = NULL;
	GListPtr child_colors = NULL;
	int local_node_max = 0;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	if(clone_data->self->provisional == FALSE) {
		return NULL;
	}
	local_node_max = clone_data->clone_node_max; 
	clone_data->max_nodes = rsc->fns->num_allowed_nodes(rsc);
	
	/* give already allocated resources every chance to run on the node
	 *   specified.  other resources can be moved/started where we want
	 *   as required
	 */
	clone_data->child_list = g_list_sort(
 		clone_data->child_list, sort_rsc_provisional);

	crm_debug_2("Coloring children of: %s", rsc->id);
	
	if(rsc->stickiness <= 0) {
		while(local_node_max > 1
		      && clone_data->max_nodes * (local_node_max -1)
		      >= clone_data->clone_max) {			
			local_node_max--;
			crm_debug("Dropped the effective value of"
				  " clone_node_max to: %d",
				  local_node_max);
		}
	}

	clone_data->self->allowed_nodes = g_list_sort(
		clone_data->self->allowed_nodes, sort_node_weight);
	
	slist_iter(a_node, node_t, clone_data->self->allowed_nodes, lpc,
		   color_t *new_color = NULL;
		   if(can_run_resources(a_node) == FALSE) {
			   crm_debug_2("Node cant run resources: %s",
				       a_node->details->uname);
			   continue;
		   }
		   crm_debug_3("Processing node %s for: %s",
			       a_node->details->uname, rsc->id);

		   new_color = create_color(data_set, NULL, NULL);
		   new_color->details->candidate_nodes = g_list_append(
			   NULL, node_copy(a_node));

		   slist_iter(child, resource_t, clone_data->child_list, lpc2,
			      node_t *current = NULL;
			      if(child->provisional == FALSE) {
				      CRM_CHECK(child->color != NULL, continue);
				      current = child->color->details->chosen_node;
			      } else if(child->running_on != NULL) {
				      current = child->running_on->data;
			      }
			      
			      if(current == NULL) {
				      crm_debug_2("Not active: %s", child->id);
				      continue;

			      } else if(current->details != a_node->details) {
				      crm_debug_2("Wrong node: %s", child->id);
				      continue;

			      } else if(child->provisional == FALSE) {
				      /* make sure it shows up */
				      native_assign_color(child, new_color);
				      crm_debug("Previously colored: %s",
						child->id);
				      
				      continue;
				      
			      } else if(g_list_length(child->running_on) != 1) {
				      crm_debug("active != 1: %s", child->id);
				      
				      continue;

			      } else if(new_color->details->num_resources
					>= local_node_max) {
				      crm_warn("Node %s too full for: %s",
					       a_node->details->uname,
					       child->id);
				      continue;
			      }

			      native_assign_color(child, new_color);
			      
			   );
		   native_assign_color(rsc, new_color);
		   child_colors = g_list_append(child_colors, new_color);
		);


	while(local_node_max > 1
	      && clone_data->max_nodes * (local_node_max -1)
	      >= clone_data->clone_max) {
		local_node_max--;
		crm_debug("Dropped the effective value of clone_node_max to: %d",
			  local_node_max);
	}
	
	/* allocate the rest */
	slist_iter(child, resource_t, clone_data->child_list, lpc2,
		   if(child->provisional == FALSE) {
			   continue;
		   }
		   crm_debug_2("Processing unalloc'd resource: %s", child->id);
		   color_ptr = next_color(
			   child_colors, color_ptr, local_node_max);
		   if(color_ptr == NULL) {
			   native_assign_color(child, data_set->no_color);
		   } else {
			   native_assign_color(child, color_ptr->data);
		   }
		);

	clone_data->self->provisional = FALSE;
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
				crm_debug_3("Skipping pseduo-op: %s run=%d, pseudo=%d",
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
	action_t *action = NULL;
	action_t *action_complete = NULL;
	resource_t *last_start_rsc = NULL;
	resource_t *last_stop_rsc = NULL;
	clone_variant_data_t *clone_data = NULL;

	get_clone_variant_data(clone_data, rsc);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		child_rsc->fns->create_actions(child_rsc, data_set);
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
	action = start_action(clone_data->self, NULL, !child_starting);
	action_complete = custom_action(
		clone_data->self, started_key(rsc),
		CRMD_ACTION_STARTED, NULL, !child_starting, TRUE, data_set);

	action->pseudo = TRUE;
	action_complete->pseudo = TRUE;
	
	child_starting_constraints(clone_data, pe_ordering_optional, 
				   NULL, last_start_rsc, data_set);

	clone_create_notifications(rsc, action, action_complete, data_set);	


	/* stop */
	action = stop_action(clone_data->self, NULL, !child_stopping);
	action_complete = custom_action(
		clone_data->self, stopped_key(rsc),
		CRMD_ACTION_STOPPED, NULL, !child_stopping, TRUE, data_set);

	action->pseudo = TRUE;
	action_complete->pseudo = TRUE;
	
	child_stopping_constraints(clone_data, pe_ordering_optional,
				   NULL, last_stop_rsc, data_set);

	clone_create_notifications(rsc, action, action_complete, data_set);	

	rsc->actions = clone_data->self->actions;	
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
		clone_data->self->id, "pre", action->task);
	notify = custom_action(clone_data->self, notify_key,
			       CRMD_ACTION_NOTIFY, NULL,
			       action->optional, TRUE, data_set);
	add_hash_param(notify->extra, "notify_type", "pre");
	add_hash_param(notify->extra, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->extra, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->extra, "notify_confirm", "no");
	}
	notify->pseudo = TRUE;

	/* create pre_notify_complete */
	notify_key = generate_notify_key(
		clone_data->self->id, "confirmed-pre", action->task);
	notify_complete = custom_action(clone_data->self, notify_key,
			       CRMD_ACTION_NOTIFIED, NULL,
			       action->optional, TRUE, data_set);
	add_hash_param(notify_complete->extra, "notify_type", "pre");
	add_hash_param(notify_complete->extra, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->extra, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->extra, "notify_confirm", "no");
	}
	notify->pseudo = TRUE;
	notify_complete->pseudo = TRUE;

	/* pre_notify before pre_notify_complete */
	custom_action_order(
		clone_data->self, NULL, notify,
		clone_data->self, NULL, notify_complete,
		pe_ordering_manditory, data_set);
	
	/* pre_notify_complete before action */
	custom_action_order(
		clone_data->self, NULL, notify_complete,
		clone_data->self, NULL, action,
		pe_ordering_manditory, data_set);

	action->pre_notify = notify;
	action->pre_notified = notify_complete;
	
	/* create post_notify */
	notify_key = generate_notify_key
		(clone_data->self->id, "post", action->task);
	notify = custom_action(clone_data->self, notify_key,
			       CRMD_ACTION_NOTIFY, NULL,
			       action_complete->optional, TRUE, data_set);
	add_hash_param(notify->extra, "notify_type", "post");
	add_hash_param(notify->extra, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->extra, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->extra, "notify_confirm", "no");
	}
	notify->pseudo = TRUE;

	/* action_complete before post_notify */
	custom_action_order(
		clone_data->self, NULL, action_complete,
		clone_data->self, NULL, notify, 
		pe_ordering_postnotify, data_set);
	
	/* create post_notify_complete */
	notify_key = generate_notify_key(
		clone_data->self->id, "confirmed-post", action->task);
	notify_complete = custom_action(clone_data->self, notify_key,
			       CRMD_ACTION_NOTIFIED, NULL,
			       action->optional, TRUE, data_set);
	add_hash_param(notify_complete->extra, "notify_type", "pre");
	add_hash_param(notify_complete->extra, "notify_operation", action->task);
	if(clone_data->notify_confirm) {
		add_hash_param(notify->extra, "notify_confirm", "yes");
	} else {
		add_hash_param(notify->extra, "notify_confirm", "no");
	}
	notify_complete->pseudo = TRUE;

	/* post_notify before post_notify_complete */
	custom_action_order(
		clone_data->self, NULL, notify,
		clone_data->self, NULL, notify_complete,
		pe_ordering_manditory, data_set);

	action->post_notify = notify;
	action->post_notified = notify_complete;


	if(safe_str_eq(action->task, CRMD_ACTION_STOP)) {
		/* post_notify_complete before start */
		custom_action_order(
			clone_data->self, NULL, notify_complete,
			clone_data->self, start_key(clone_data->self), NULL,
			pe_ordering_optional, data_set);

	} else if(safe_str_eq(action->task, CRMD_ACTION_START)) {
		/* post_notify_complete before promote */
		custom_action_order(
			clone_data->self, NULL, notify_complete,
			clone_data->self, promote_key(clone_data->self), NULL,
			pe_ordering_optional, data_set);

	} else if(safe_str_eq(action->task, CRMD_ACTION_DEMOTE)) {
		/* post_notify_complete before promote */
		custom_action_order(
			clone_data->self, NULL, notify_complete,
			clone_data->self, stop_key(clone_data->self), NULL,
			pe_ordering_optional, data_set);
	}
}

void
child_starting_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
	if(clone_data->ordered
	   || clone_data->self->restart_type == pe_restart_restart) {
		type = pe_ordering_manditory;
	}
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* last child start before global started */
			custom_action_order(
				last, start_key(last), NULL,
				clone_data->self, started_key(clone_data->self), NULL,
				type, data_set);
		}
		
	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version");
		if(last == NULL) {
			/* global start before first child start */
			last = clone_data->self;

		} /* else: child/child relative start */

		order_start_start(last, child, type);

	} else {
		crm_debug_4("Un-ordered version");
		
		/* child start before global started */
		custom_action_order(
			child, start_key(child), NULL,
			clone_data->self, started_key(clone_data->self), NULL,
			type, data_set);
                
		/* global start before child start */
/* 		order_start_start(clone_data->self, child, type); */
		order_start_start(
			clone_data->self, child, pe_ordering_manditory);
	}
}

void
child_stopping_constraints(
	clone_variant_data_t *clone_data, enum pe_ordering type,
	resource_t *child, resource_t *last, pe_working_set_t *data_set)
{
	if(clone_data->ordered
	   || clone_data->self->restart_type == pe_restart_restart) {
		type = pe_ordering_manditory;
	}
	
	if(child == NULL) {
		if(clone_data->ordered && last != NULL) {
			crm_debug_4("Ordered version (last node)");
			/* global stop before first child stop */
			order_stop_stop(clone_data->self, last,
					pe_ordering_manditory);
		}
		
	} else if(clone_data->ordered && last != NULL) {
		crm_debug_4("Ordered version");

		/* child/child relative stop */
		order_stop_stop(child, last, type);

	} else if(clone_data->ordered) {
		crm_debug_4("Ordered version (1st node)");
		/* first child stop before global stopped */
		custom_action_order(
			child, stop_key(child), NULL,
			clone_data->self, stopped_key(clone_data->self), NULL,
			type, data_set);

	} else {
		crm_debug_4("Un-ordered version");

		/* child stop before global stopped */
		custom_action_order(
			child, stop_key(child), NULL,
			clone_data->self, stopped_key(clone_data->self), NULL,
			type, data_set);
                        
		/* global stop before child stop */
		order_stop_stop(clone_data->self, child, type);
	}
}


void
clone_internal_constraints(resource_t *rsc, pe_working_set_t *data_set)
{
	resource_t *last_rsc = NULL;	
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	/* global stop before stopped */
	custom_action_order(
		clone_data->self, stop_key(clone_data->self), NULL,
		clone_data->self, stopped_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);

	/* global start before started */
	custom_action_order(
		clone_data->self, start_key(clone_data->self), NULL,
		clone_data->self, started_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);
	
	/* global stopped before start */
	custom_action_order(
		clone_data->self, stopped_key(clone_data->self), NULL,
		clone_data->self, start_key(clone_data->self), NULL,
		pe_ordering_optional, data_set);
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		/* child stop before start */
		order_restart(child_rsc);

		child_starting_constraints(
			clone_data, pe_ordering_optional,
			child_rsc, last_rsc, data_set);

		child_stopping_constraints(
			clone_data, pe_ordering_optional,
			child_rsc, last_rsc, data_set);

		last_rsc = child_rsc;
		
		);
	
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
			pe_err("Cannot interleave "XML_CIB_TAG_INCARNATION" %s and %s because"
			       " they do not support the same number of"
			       " resources per node",
			       constraint->rsc_lh->id, constraint->rsc_rh->id);
			
		/* only the LHS side needs to be labeled as interleave */
		} else if(clone_data->interleave) {
			do_interleave = TRUE;

		} else if(constraint->strength != pecs_must_not) {
			pe_warn("rsc_colocations other than \"-INFINITY\""
				" are not supported for non-interleaved "
				XML_CIB_TAG_INCARNATION" resources");
			return;
		}

	} else if(constraint->strength != pecs_must_not) {
		pe_warn("Co-location scores other than \"-INFINITY\" are not "
			" allowed for non-"XML_CIB_TAG_INCARNATION" resources");
		return;
	}
	
	
	if(do_interleave) {
		resource_t *child_lh = NULL;
		resource_t *child_rh = NULL;
		
		GListPtr iter_lh = clone_data->child_list;
		GListPtr iter_rh = clone_data_rh->child_list;

		crm_debug_2("Interleaving %s with %s",
			    constraint->rsc_lh->id, constraint->rsc_rh->id);
		/* If the resource have different numbers of incarnations,
		 *   then just do as many as are available
		 */
		while(iter_lh != NULL && iter_rh != NULL) {
			child_lh = iter_lh->data;
			child_rh = iter_rh->data;
			iter_lh = iter_lh->next;
			iter_rh = iter_rh->next;
			
			crm_debug_3("Colocating %s with %s", child_lh->id, child_rh->id);
			child_lh->fns->rsc_colocation_lh(child_lh, child_rh, constraint);
		}
		return;

	}
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		print_resource(LOG_DEBUG_3, "LHS", child_rsc, TRUE);
		child_rsc->fns->rsc_colocation_lh(child_rsc, constraint->rsc_rh, constraint);
		);
}

void clone_rsc_colocation_rh(
	resource_t *rsc_lh, resource_t *rsc_rh, rsc_colocation_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	CRM_CHECK(rsc_lh->variant == pe_native, return);
	
	crm_debug_3("Processing RH of constraint %s", constraint->id);

	if(rsc_lh == NULL) {
		pe_err("rsc_lh was NULL for %s", constraint->id);
		return;

	} else if(rsc_rh == NULL) {
		pe_err("rsc_rh was NULL for %s", constraint->id);
		return;
		
	} else if(constraint->strength != pecs_must_not) {
		pe_warn("rsc_dependencies other than \"must_not\" "
			"are not supported for clone resources");
		return;
		
	} else {
		print_resource(LOG_DEBUG_3, "LHS", rsc_lh, FALSE);
	}
	
	get_clone_variant_data(clone_data, rsc_rh);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		print_resource(LOG_DEBUG_3, "RHS", child_rsc, FALSE);
		child_rsc->fns->rsc_colocation_rh(rsc_lh, child_rsc, constraint);
		);
}


void clone_rsc_order_lh(resource_t *rsc, order_constraint_t *order)
{
	char *stop_id = NULL;
	char *start_id = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing LH of ordering constraint %d", order->id);

	stop_id = stop_key(rsc);
	start_id = start_key(rsc);
	
	if(safe_str_eq(order->lh_action_task, start_id)) {
		crm_free(order->lh_action_task);
		order->lh_action_task = started_key(rsc);

	} else if(safe_str_eq(order->lh_action_task, stop_id)) {
		crm_free(order->lh_action_task);
		order->lh_action_task = stopped_key(rsc);
	}

	crm_free(start_id);
	crm_free(stop_id);
	
	clone_data->self->fns->rsc_order_lh(clone_data->self, order);
}

void clone_rsc_order_rh(
	action_t *lh_action, resource_t *rsc, order_constraint_t *order)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing RH of ordering constraint %d", order->id);

 	clone_data->self->fns->rsc_order_rh(lh_action, clone_data->self, order);

}

void clone_rsc_location(resource_t *rsc, rsc_to_node_t *constraint)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Processing actions from %s", rsc->id);

	clone_data->self->fns->rsc_location(clone_data->self, constraint);
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		child_rsc->fns->rsc_location(child_rsc, constraint);
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
	int rsc_len = 0;
	int node_len = 0;
	int list_len = 100 * clones;

	char *rsc_list_s = NULL;
	char *node_list_s = NULL;

	const char *uname = NULL;
	const char *rsc_id = NULL;

	const char *last_rsc_id = NULL;
	
  clone_expand_reallocate:
	if(rsc_list != NULL) {
		crm_free(*rsc_list);
		crm_malloc0(*rsc_list, sizeof(char)*list_len);
		CRM_ASSERT(*rsc_list != NULL);
		rsc_list_s = *rsc_list;
		rsc_len = 0;
	}
	if(node_list != NULL) {
		crm_free(*node_list);
		crm_malloc0(*node_list, sizeof(char)*list_len);
		CRM_ASSERT(*node_list != NULL);
		node_list_s = *node_list;
		node_len = 0;
	}
	/* keep BEAM extra happy */
	if(rsc_list_s == NULL || node_list_s == NULL) {
		return;
	}
	
	slist_iter(entry, notify_entry_t, list, lpc,

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
			   if(rsc_len + 1 + strlen(rsc_id) >= list_len) {
				   list_len *= 2;
				   goto clone_expand_reallocate;
			   }
			   sprintf(rsc_list_s, "%s ", rsc_id);
			   rsc_list_s += strlen(rsc_id);
			   rsc_len += strlen(rsc_id);
			   rsc_list_s++;
			   rsc_len++;
		   }
		   
		   if(node_list != NULL) {
			   if(node_len + 1 + strlen(uname) >= list_len) {
				   list_len *= 2;
				   goto clone_expand_reallocate;
			   }
			   sprintf(node_list_s, "%s ", uname);
			   node_list_s += strlen(uname);
			   node_len += strlen(uname);
			   node_list_s++;
			   node_len++;
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
				op, action_t, clone_data->self->actions, lpc2,
			
				child_rsc->fns->create_notify_element(
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
		
		child_rsc->fns->expand(child_rsc, data_set);

		);
	
/* 	slist_iter( */
/* 		action, action_t, clone_data->self->actions, lpc2, */

/* 		if(safe_str_eq(action->task, CRMD_ACTION_NOTIFY)) { */
/* 			action->extra_xml = notify_xml; */
/* 		} */
/* 		); */
	
	clone_data->self->fns->expand(clone_data->self, data_set);

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

gboolean clone_active(resource_t *rsc, gboolean all)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		gboolean child_active = child_rsc->fns->active(child_rsc, all);
		if(all == FALSE && child_active) {
			return TRUE;
		} else if(all && child_active == FALSE) {
			return FALSE;
		}
		);
	if(all) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void clone_print(
	resource_t *rsc, const char *pre_text, long options, void *print_data)
{
	const char *child_text = NULL;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);
	if(pre_text != NULL) {
		child_text = "        ";
	} else {
		child_text = "    ";
	}

	if(rsc->variant == pe_master) {
		status_print("%sMaster/Slave Set: %s",
			     pre_text?pre_text:"", clone_data->self->id);

	} else {
		status_print("%sClone Set: %s",
			     pre_text?pre_text:"", clone_data->self->id);
	}
	
	if(options & pe_print_html) {
		status_print("\n<ul>\n");

	} else if((options & pe_print_log) == 0) {
		status_print("\n");
	}
	
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		if(options & pe_print_html) {
			status_print("<li>\n");
		}
		child_rsc->fns->print(
			child_rsc, child_text, options, print_data);
		if(options & pe_print_html) {
			status_print("</li>\n");
		}
		);

	if(options & pe_print_html) {
		status_print("</ul>\n");
	}
}

void clone_free(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	crm_debug_3("Freeing %s", rsc->id);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		crm_debug_3("Freeing child %s", child_rsc->id);
		free_xml(child_rsc->xml);
		child_rsc->fns->free(child_rsc);
		);

	crm_debug_3("Freeing child list");
	pe_free_shallow_adv(clone_data->child_list, FALSE);

	free_xml(clone_data->self->xml);
	clone_data->self->fns->free(clone_data->self);

	common_free(rsc);
}


void
clone_agent_constraints(resource_t *rsc)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->fns->agent_constraints(child_rsc);
		);
}

enum rsc_role_e
clone_resource_state(resource_t *rsc)
{
	return RSC_ROLE_UNKNOWN;
}

void
clone_create_notify_element(resource_t *rsc, action_t *op,
			    notify_data_t *n_data, pe_working_set_t *data_set)
{
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,
		
		child_rsc->fns->create_notify_element(
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
		    pe_working_set_t *data_set) 
{
	int num_probes = 0;
	gboolean any_created = FALSE;
	clone_variant_data_t *clone_data = NULL;
	get_clone_variant_data(clone_data, rsc);

	/* we may already be running but under different names */
	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		if(num_probes >= clone_data->clone_node_max) {
			return FALSE;
		}
		if(pe_find_node_id(child_rsc->running_on, node->details->id)) {
			num_probes++;
		}
		);
	
	clone_data->child_list = g_list_sort(
		clone_data->child_list, sort_rsc_id);

	slist_iter(
		child_rsc, resource_t, clone_data->child_list, lpc,

		if(num_probes >= clone_data->clone_node_max) {
			break;
		}
		if(child_rsc->fns->create_probe(
			   child_rsc, node, complete, data_set)) {
			any_created = TRUE;
			num_probes++;
		}
		);

	return any_created;
}

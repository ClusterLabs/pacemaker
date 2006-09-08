/* $Id: allocate.c,v 1.12 2006/08/14 09:06:31 andrew Exp $ */
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

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>
#include <clplumbing/cl_misc.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pengine.h>
#include <allocate.h>
#include <utils.h>
#include <lib/crm/pengine/utils.h>

void set_alloc_actions(pe_working_set_t *data_set);

resource_alloc_functions_t resource_class_alloc_functions[] = {
	{
		native_set_cmds,
		native_num_allowed_nodes,
		native_color,
		native_create_actions,
		native_create_probe,
		native_internal_constraints,
		native_agent_constraints,
		native_rsc_colocation_lh,
		native_rsc_colocation_rh,
		native_rsc_order_lh,
		native_rsc_order_rh,
		native_rsc_location,
		native_expand,
		native_stonith_ordering,
		native_create_notify_element,
	},
	{
 		group_set_cmds,
		group_num_allowed_nodes,
		group_color,
		group_create_actions,
		group_create_probe,
		group_internal_constraints,
		group_agent_constraints,
		group_rsc_colocation_lh,
		group_rsc_colocation_rh,
		group_rsc_order_lh,
		group_rsc_order_rh,
		group_rsc_location,
		group_expand,
		group_stonith_ordering,
		group_create_notify_element,
	},
	{
 		clone_set_cmds,
		clone_num_allowed_nodes,
		clone_color,
		clone_create_actions,
		clone_create_probe,
		clone_internal_constraints,
		clone_agent_constraints,
		clone_rsc_colocation_lh,
		clone_rsc_colocation_rh,
		clone_rsc_order_lh,
		clone_rsc_order_rh,
		clone_rsc_location,
		clone_expand,
		clone_stonith_ordering,
		clone_create_notify_element,
	},
	{
 		clone_set_cmds,
		clone_num_allowed_nodes,
		clone_color,
		master_create_actions,
		clone_create_probe,
		master_internal_constraints,
		clone_agent_constraints,
		clone_rsc_colocation_lh,
		clone_rsc_colocation_rh,
		clone_rsc_order_lh,
		clone_rsc_order_rh,
		clone_rsc_location,
		clone_expand,
		clone_stonith_ordering,
		clone_create_notify_element,
	}
};

color_t *add_color(resource_t *rh_resource, color_t *color);

gboolean 
apply_placement_constraints(pe_working_set_t *data_set)
{
	crm_debug_3("Applying constraints...");
	slist_iter(
		cons, rsc_to_node_t, data_set->placement_constraints, lpc,

		cons->rsc_lh->cmds->rsc_location(cons->rsc_lh, cons);
		);
	
	return TRUE;
	
}

color_t *
add_color(resource_t *resource, color_t *color)
{
	color_t *local_color = NULL;

	if(color == NULL) {
		pe_err("Cannot add NULL color");
		return NULL;
	}
	
	local_color = find_color(resource->candidate_colors, color);

	if(local_color == NULL) {
		crm_debug_4("Adding color %d", color->id);
		
		local_color = copy_color(color);
		resource->candidate_colors =
			g_list_append(resource->candidate_colors, local_color);

	} else {
		crm_debug_4("Color %d already present", color->id);
	}

	return local_color;
}

void
set_alloc_actions(pe_working_set_t *data_set) 
{
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->cmds = &resource_class_alloc_functions[rsc->variant];
		rsc->cmds->set_cmds(rsc);
		);
}

gboolean
stage0(pe_working_set_t *data_set)
{
	crm_data_t * cib_constraints = get_object_root(
		XML_CIB_TAG_CONSTRAINTS, data_set->input);

	if(data_set->input == NULL) {
		return FALSE;
	}

	cluster_status(data_set);
	
	set_alloc_actions(data_set);
	data_set->no_color = create_color(data_set, NULL, NULL);

	unpack_constraints(cib_constraints, data_set);
	return TRUE;
}

/*
 * Count how many valid nodes we have (so we know the maximum number of
 *  colors we can resolve).
 *
 * Apply node constraints (ie. filter the "allowed_nodes" part of resources
 */
gboolean
stage1(pe_working_set_t *data_set)
{
	crm_debug_3("Applying placement constraints");	
	
	slist_iter(
		node, node_t, data_set->nodes, lpc,
		if(node == NULL) {
			/* error */
		} else if(node->weight >= 0.0 /* global weight */
			  && node->details->online
			  && node->details->type == node_member) {
			data_set->max_valid_nodes++;
		}
		);

	apply_placement_constraints(data_set);

	return TRUE;
}

/*
 * Choose a color for all resources from highest priority and XML_STRENGTH_VAL_MUST
 *  dependencies to lowest, creating new colors as necessary (returned
 *  as "colors").
 *
 * Some nodes may be colored as a "no_color" meaning that it was unresolvable
 *  given the current node stati and constraints.
 */
gboolean
stage3(pe_working_set_t *data_set)
{
	crm_debug_3("Coloring resources");
	
	crm_debug_5("create \"no color\"");
	
	/* Take (next) highest resource */
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->cmds->internal_constraints(rsc, data_set);
		rsc->cmds->color(rsc, data_set);
		);
	
	return TRUE;
}

/*
 * Check nodes for resources started outside of the LRM
 */
gboolean
stage2(pe_working_set_t *data_set)
{
	action_t *probe_complete = NULL;
	action_t *probe_node_complete = NULL;

	slist_iter(
		node, node_t, data_set->nodes, lpc,
		gboolean force_probe = FALSE;
		const char *probed = g_hash_table_lookup(
			node->details->attrs, CRM_OP_PROBED);

		crm_debug_2("%s probed: %s", node->details->uname, probed);
		if(node->details->online == FALSE) {
			continue;
			
		} else if(node->details->unclean) {
			continue;

		} else if(probe_complete == NULL) {
			probe_complete = custom_action(
				NULL, crm_strdup(CRM_OP_PROBED),
				CRM_OP_PROBED, NULL, FALSE, TRUE,
				data_set);

			probe_complete->pseudo = TRUE;
			probe_complete->optional = TRUE;
		}

		if(probed != NULL && crm_is_true(probed) == FALSE) {
			force_probe = TRUE;
		}
		
		probe_node_complete = custom_action(
			NULL, crm_strdup(CRM_OP_PROBED),
			CRM_OP_PROBED, node, FALSE, TRUE, data_set);
		probe_node_complete->optional = crm_is_true(probed);
		probe_node_complete->priority = INFINITY;
		add_hash_param(probe_node_complete->meta,
			       XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
		
		custom_action_order(NULL, NULL, probe_node_complete,
				    NULL, NULL, probe_complete,
				    pe_ordering_optional, data_set);
		
		slist_iter(
			rsc, resource_t, data_set->resources, lpc2,
			
			if(rsc->cmds->create_probe(
				   rsc, node, probe_node_complete,
				   force_probe, data_set)) {

				probe_complete->optional = FALSE;
				probe_node_complete->optional = FALSE;
				custom_action_order(
					NULL, NULL, probe_complete,
					rsc, start_key(rsc), NULL,
					pe_ordering_manditory, data_set);
			}
			);
		);

	return TRUE;
}

/*
 * Choose a node for each (if possible) color
 */
gboolean
stage4(pe_working_set_t *data_set)
{
	node_t *chosen = NULL;
	crm_debug_3("Assigning nodes to colors");

	slist_iter(
		color, color_t, data_set->colors, lpc,

		crm_debug_4("assigning node to color %d", color->id);
		
		if(color == NULL) {
			pe_err("NULL color detected");
			continue;
			
		} else if(color->details->pending == FALSE) {
			continue;
		}
		
		choose_node_from_list(color);
		
		slist_iter(
			rsc, resource_t, color->details->allocated_resources, lpc2,
			crm_debug_2("Processing colocation constraints for %s"
				    " now that color %d is allocated",
				    rsc->id, color->details->id);
			
			slist_iter(
				constraint, rsc_colocation_t, rsc->rsc_cons, lpc,
				rsc->cmds->rsc_colocation_lh(
					rsc, constraint->rsc_rh, constraint);
				);	
			
			);

		chosen = color->details->chosen_node;
		
		slist_iter(
			rsc, resource_t, color->details->allocated_resources, lpc2,
			if(chosen == NULL) {
				rsc->next_role = RSC_ROLE_STOPPED;

			} else if(rsc->next_role == RSC_ROLE_UNKNOWN) {
				rsc->next_role = RSC_ROLE_STARTED;
			}
			);
		);

	crm_debug_3("done");
	return TRUE;
	
}

static gboolean
check_rsc_parameters(resource_t *rsc, node_t *node, crm_data_t *rsc_entry,
		     pe_working_set_t *data_set) 
{
	int attr_lpc = 0;
	gboolean force_restart = FALSE;
	gboolean delete_resource = FALSE;
	
	const char *value = NULL;
	const char *old_value = NULL;
	const char *attr_list[] = {
		XML_ATTR_TYPE, 
		XML_AGENT_ATTR_CLASS,
 		XML_AGENT_ATTR_PROVIDER
	};

	for(; attr_lpc < DIMOF(attr_list); attr_lpc++) {
		value = crm_element_value(rsc->xml, attr_list[attr_lpc]);
		old_value = crm_element_value(rsc_entry, attr_list[attr_lpc]);
		if(safe_str_eq(value, old_value)) {
			continue;
		}
		
		force_restart = TRUE;
		crm_notice("Forcing restart of %s on %s, %s changed: %s -> %s",
			   rsc->id, node->details->uname, attr_list[attr_lpc],
			   crm_str(old_value), crm_str(value));
	}
	if(force_restart) {
		/* make sure the restart happens */
		stop_action(rsc, node, FALSE);
		rsc->start_pending = TRUE;
		delete_resource = TRUE;
	}
	return delete_resource;
}

static gboolean
check_action_definition(resource_t *rsc, node_t *active_node, crm_data_t *xml_op,
			pe_working_set_t *data_set)
{
	char *key = NULL;
	int interval = 0;
	const char *interval_s = NULL;
	
	gboolean did_change = FALSE;

	crm_data_t *pnow = NULL;
	GHashTable *local_rsc_params = NULL;
	
	char *pnow_digest = NULL;
	const char *param_digest = NULL;
	char *local_param_digest = NULL;

#if CRM_DEPRECATED_SINCE_2_0_4
	crm_data_t *params = NULL;
#endif

	action_t *action = NULL;
	const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
	const char *op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);

	CRM_CHECK(active_node != NULL, return FALSE);

	interval_s = get_interval(xml_op);
	interval = crm_parse_int(interval_s, "0");
	key = generate_op_key(rsc->id, task, interval);

	if(interval > 0) {
		crm_data_t *op_match = NULL;

		crm_debug_2("Checking parameters for %s %s", key, task);
		op_match = find_rsc_op_entry(rsc, key);

		if(op_match == NULL && data_set->stop_action_orphans) {
			/* create a cancel action */
			action_t *cancel = NULL;
			char *cancel_key = NULL;
			
			crm_info("Orphan action will be stopped: %s on %s",
				 key, active_node->details->uname);

			cancel_key = generate_op_key(rsc->id, CRMD_ACTION_CANCEL, interval);

			cancel = custom_action(
				rsc, cancel_key, CRMD_ACTION_CANCEL,
				active_node, FALSE, TRUE, data_set);

			add_hash_param(cancel->meta, XML_LRM_ATTR_TASK, task);
			add_hash_param(cancel->meta,
				       XML_LRM_ATTR_INTERVAL, interval_s);

			custom_action_order(
				rsc, NULL, cancel,
				rsc, stop_key(rsc), NULL,
				pe_ordering_optional, data_set);
		}
		if(op_match == NULL) {
			crm_debug("Orphan action detected: %s on %s",
				  key, active_node->details->uname);
			crm_free(key); key = NULL;
			return TRUE;
		}
	}

	action = custom_action(rsc, key, task, active_node, TRUE, FALSE, data_set);
	
	local_rsc_params = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	
	unpack_instance_attributes(
		rsc->xml, XML_TAG_ATTR_SETS, active_node->details->attrs,
		local_rsc_params, NULL, data_set->now);
	
	pnow = create_xml_node(NULL, XML_TAG_PARAMS);
	g_hash_table_foreach(action->extra, hash2field, pnow);
	g_hash_table_foreach(rsc->parameters, hash2field, pnow);
	g_hash_table_foreach(local_rsc_params, hash2field, pnow);

	filter_action_parameters(pnow, op_version);
	pnow_digest = calculate_xml_digest(pnow, TRUE);
	param_digest = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);

#if CRM_DEPRECATED_SINCE_2_0_4
	if(param_digest == NULL) {
		params = find_xml_node(xml_op, XML_TAG_PARAMS, TRUE);
	}
	if(params != NULL) {
		crm_data_t *local_params = copy_xml(params);

		crm_warn("Faking parameter digest creation for %s", ID(xml_op));		
		filter_action_parameters(local_params, op_version);
		xml_remove_prop(local_params, "interval");
		xml_remove_prop(local_params, "timeout");
		crm_log_xml_warn(local_params, "params:used");

		local_param_digest = calculate_xml_digest(local_params, TRUE);
		param_digest = local_param_digest;
		
		free_xml(local_params);
	}
#endif

	if(safe_str_neq(pnow_digest, param_digest)) {
		did_change = TRUE;
		crm_log_xml_info(pnow, "params:calc");
 		crm_warn("Parameters to %s on %s changed: recorded %s vs. calculated %s",
			 ID(xml_op), active_node->details->uname,
			 crm_str(param_digest), pnow_digest);

		key = generate_op_key(rsc->id, task, interval);
		custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
	}

	free_xml(pnow);
	crm_free(pnow_digest);
	crm_free(local_param_digest);
	g_hash_table_destroy(local_rsc_params);

	pe_free_action(action);
	
	return did_change;
}

extern gboolean DeleteRsc(resource_t *rsc, node_t *node, pe_working_set_t *data_set);

static void
check_actions_for(crm_data_t *rsc_entry, node_t *node, pe_working_set_t *data_set)
{
	const char *id = NULL;
	const char *task = NULL;
	int interval = 0;
	const char *interval_s = NULL;
	GListPtr op_list = NULL;
	GListPtr sorted_op_list = NULL;
	const char *rsc_id = ID(rsc_entry);
	gboolean is_probe = FALSE;
	resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

	CRM_CHECK(rsc_id != NULL, return);
	if(rsc == NULL) {
		crm_warn("Skipping param check for resource with no actions");
		return;

	} else if(rsc->orphan) {
		crm_debug_2("Skipping param check for orphan: %s %s",
			    rsc->id, task);
		return;
	}

	crm_debug_2("Processing %s on %s", rsc->id, node->details->uname);
	
	if(check_rsc_parameters(rsc, node, rsc_entry, data_set)) {
		DeleteRsc(rsc, node, data_set);
	}
	
	xml_child_iter_filter(
		rsc_entry, rsc_op, XML_LRM_TAG_RSC_OP,
		op_list = g_list_append(op_list, rsc_op);
		);

	sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
	slist_iter(
		rsc_op, crm_data_t, sorted_op_list, lpc,

		id   = ID(rsc_op);
		is_probe = FALSE;
		task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);

		interval_s = get_interval(rsc_op);
		interval = crm_parse_int(interval_s, "0");
		
		if(interval == 0 && safe_str_eq(task, CRMD_ACTION_STATUS)) {
			is_probe = TRUE;
		}
		
		if(is_probe || safe_str_eq(task, CRMD_ACTION_START) || interval > 0) {
			crm_debug_2("Checking resource definition: %s", rsc->id);
			check_action_definition(rsc, node, rsc_op, data_set);
		}
		crm_debug_3("Ignoring %s params: %s", task, id);
		);

	g_list_free(sorted_op_list);
	
}

static void
check_actions(pe_working_set_t *data_set)
{
	const char *id = NULL;
	node_t *node = NULL;
	crm_data_t *lrm_rscs = NULL;
	crm_data_t *status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

	xml_child_iter_filter(
		status, node_state, XML_CIB_TAG_STATE,

		id       = crm_element_value(node_state, XML_ATTR_ID);
		lrm_rscs = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		lrm_rscs = find_xml_node(lrm_rscs, XML_LRM_TAG_RESOURCES, FALSE);

		node = pe_find_node_id(data_set->nodes, id);

		if(node == NULL) {
			continue;
		}
		crm_debug("Processing node %s", node->details->uname);
		if(node->details->online || data_set->stonith_enabled) {
			xml_child_iter_filter(
				lrm_rscs, rsc_entry, XML_LRM_TAG_RESOURCE,
				check_actions_for(rsc_entry, node, data_set);
				);
		}
		);
}


/*
 * Attach nodes to the actions that need to be taken
 *
 * Mark actions XML_LRM_ATTR_OPTIONAL if possible (Ie. if the start and stop are
 *  for the same node)
 *
 * Mark unrunnable actions
 */
gboolean
stage5(pe_working_set_t *data_set)
{
	crm_debug_3("Creating actions and internal ording constraints");
	
	check_actions(data_set);
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->cmds->create_actions(rsc, data_set);
		);
	return TRUE;
}


/*
 * Create dependacies for stonith and shutdown operations
 */
gboolean
stage6(pe_working_set_t *data_set)
{
	action_t *dc_down = NULL;
	action_t *stonith_op = NULL;
	action_t *last_stonith = NULL;
	gboolean integrity_lost = FALSE;
	
	crm_debug_3("Processing fencing and shutdown cases");
	
	slist_iter(
		node, node_t, data_set->nodes, lpc,

		stonith_op = NULL;
		if(node->details->unclean && data_set->stonith_enabled
		   && (data_set->have_quorum
		       || data_set->no_quorum_policy == no_quorum_ignore)) {
			pe_warn("Scheduling Node %s for STONITH",
				 node->details->uname);

			stonith_op = custom_action(
				NULL, crm_strdup(CRM_OP_FENCE),
				CRM_OP_FENCE, node, FALSE, TRUE, data_set);

			add_hash_param(
				stonith_op->meta, XML_LRM_ATTR_TARGET,
				node->details->uname);

			add_hash_param(
				stonith_op->meta, XML_LRM_ATTR_TARGET_UUID,
				node->details->id);

			add_hash_param(
				stonith_op->meta, "stonith_action",
				data_set->stonith_action);
			
			stonith_constraints(node, stonith_op, data_set);

			if(node->details->is_dc) {
				dc_down = stonith_op;

			} else {
				if(last_stonith) {
					order_actions(last_stonith, stonith_op, pe_ordering_manditory);
				}
				last_stonith = stonith_op;			
			}

		} else if(node->details->online && node->details->shutdown) {			
			action_t *down_op = NULL;	
			crm_info("Scheduling Node %s for shutdown",
				 node->details->uname);

			down_op = custom_action(
				NULL, crm_strdup(CRM_OP_SHUTDOWN),
				CRM_OP_SHUTDOWN, node, FALSE, TRUE, data_set);

			shutdown_constraints(node, down_op, data_set);

			if(node->details->is_dc) {
				dc_down = down_op;
			}
		}

		if(node->details->unclean && stonith_op == NULL) {
			integrity_lost = TRUE;
			pe_warn("Node %s is unclean!", node->details->uname);
		}
		);

	if(integrity_lost) {
		if(data_set->have_quorum == FALSE) {
			crm_notice("Cannot fence unclean nodes until quorum is"
				   " attained (or no_quorum_policy is set to ignore)");

		} else if(data_set->stonith_enabled == FALSE) {
			pe_warn("YOUR RESOURCES ARE NOW LIKELY COMPROMISED");
			pe_err("ENABLE STONITH TO KEEP YOUR RESOURCES SAFE");
		}
	}
	
	if(dc_down != NULL) {
		GListPtr shutdown_matches = find_actions(
			data_set->actions, CRM_OP_SHUTDOWN, NULL);
		crm_debug_2("Ordering shutdowns before %s on %s (DC)",
			dc_down->task, dc_down->node->details->uname);

		add_hash_param(dc_down->meta, XML_ATTR_TE_NOWAIT,
			       XML_BOOLEAN_TRUE);
		
		slist_iter(
			node_stop, action_t, shutdown_matches, lpc,
			if(node_stop->node->details->is_dc) {
				continue;
			}
			crm_debug("Ordering shutdown on %s before %s on %s",
				node_stop->node->details->uname,
				dc_down->task, dc_down->node->details->uname);

			order_actions(node_stop, dc_down, pe_ordering_manditory);
			);

		if(last_stonith && dc_down != last_stonith) {
			order_actions(last_stonith, dc_down, pe_ordering_manditory);
		}
	}

	return TRUE;
}

/*
 * Determin the sets of independant actions and the correct order for the
 *  actions in each set.
 *
 * Mark dependencies of un-runnable actions un-runnable
 *
 */
gboolean
stage7(pe_working_set_t *data_set)
{
	crm_debug_3("Applying ordering constraints");

	slist_iter(
		order, order_constraint_t, data_set->ordering_constraints, lpc,

		/* try rsc_action-to-rsc_action */
		resource_t *rsc = order->lh_rsc;
		if(rsc == NULL && order->lh_action) {
			rsc = order->lh_action->rsc;
		}
		
		if(rsc != NULL) {
			rsc->cmds->rsc_order_lh(rsc, order);
			continue;
		}

		/* try action-to-rsc_action */
		
		/* que off the rh resource */
		rsc = order->rh_rsc;
		if(rsc == NULL && order->rh_action) {
			rsc = order->rh_action->rsc;
		}
		
		if(rsc != NULL) {
			rsc->cmds->rsc_order_rh(order->lh_action, rsc, order);
		} else {
			/* fall back to action-to-action */
			order_actions(
				order->lh_action, order->rh_action, order->type);
		}
		
		);

	update_action_states(data_set->actions);

	return TRUE;
}

int transition_id = -1;
/*
 * Create a dependency graph to send to the transitioner (via the CRMd)
 */
gboolean
stage8(pe_working_set_t *data_set)
{
	const char *value = NULL;
	char *transition_id_s = NULL;

	transition_id++;
	transition_id_s = crm_itoa(transition_id);
	value = pe_pref(data_set->config_hash, "network-delay");
	crm_debug("Creating transition graph %d.", transition_id);
	
	data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);
	crm_xml_add(data_set->graph, "network-delay", value);
	crm_xml_add(data_set->graph, "transition_id", transition_id_s);
	crm_free(transition_id_s);
	
/* errors...
	slist_iter(action, action_t, action_list, lpc,
		   if(action->optional == FALSE && action->runnable == FALSE) {
			   print_action("Ignoring", action, TRUE);
		   }
		);
*/
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,

		crm_debug_4("processing actions for rsc=%s", rsc->id);
		rsc->cmds->expand(rsc, data_set);
		);
	crm_log_xml_debug_3(
		data_set->graph, "created resource-driven action list");

	/* catch any non-resource specific actions */
	crm_debug_4("processing non-resource actions");
	slist_iter(
		action, action_t, data_set->actions, lpc,

		graph_element_from_action(action, data_set);
		);

	crm_log_xml_debug_3(data_set->graph, "created generic action list");
	crm_notice("Created transition graph %d.", transition_id);
	
	return TRUE;
}


gboolean
choose_node_from_list(color_t *color)
{
	/*
	  1. Sort by weight
	  2. color.chosen_node = the node (of those with the highest wieght)
				   with the fewest resources
	  3. remove color.chosen_node from all other colors
	*/
	GListPtr nodes = color->details->candidate_nodes;
	node_t *chosen = NULL;
	int multiple = 0;

	crm_debug_3("Choosing node for color %d", color->id);
	color->details->candidate_nodes = g_list_sort(nodes, sort_node_weight);
	nodes = color->details->candidate_nodes;

	chosen = g_list_nth_data(nodes, 0);

	color->details->chosen_node = NULL;
	color->details->pending = FALSE;

	if(chosen == NULL) {
		if(color->id != 0) {
			crm_debug("Could not allocate a node for color %d", color->id);
		}
		return FALSE;

	} else if(chosen->details->unclean
		  || chosen->details->standby
		  || chosen->details->shutdown) {
		crm_debug("All nodes for color %d are unavailable"
			  ", unclean or shutting down", color->id);
		color->details->chosen_node = NULL;
		return FALSE;
		
	} else if(chosen->weight < 0) {
		crm_debug_2("Even highest ranked node for color %d, had weight %d",
			  color->id, chosen->weight);
		color->details->chosen_node = NULL;
		return FALSE;
	}

	slist_iter(candidate, node_t, nodes, lpc, 
		   crm_debug("Color %d, Node[%d] %s: %d", color->id, lpc,
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
		slist_iter(rsc, resource_t,
			   color->details->allocated_resources, lpc,
			   rsc->fns->print(
				   rsc, "\t", pe_print_log|pe_print_rsconly,
				   &log_level);
			);
		crm_free(score);
	}
	
	/* todo: update the old node for each resource to reflect its
	 * new resource count
	 */

	chosen->details->num_resources += color->details->num_resources;
	color->details->chosen_node = node_copy(chosen);
	
	return TRUE;
}

void
cleanup_alloc_calculations(pe_working_set_t *data_set)
{
	if(data_set == NULL) {
		return;
	}

	crm_debug_3("deleting order cons: %p", data_set->ordering_constraints);
	pe_free_ordering(data_set->ordering_constraints);
	data_set->ordering_constraints = NULL;
	
	crm_debug_3("deleting colors: %p", data_set->colors);
	pe_free_colors(data_set->colors);
	data_set->colors = NULL;
	
	crm_debug_3("deleting node cons: %p", data_set->placement_constraints);
	pe_free_rsc_to_node(data_set->placement_constraints);
	data_set->placement_constraints = NULL;
	
	cleanup_calculations(data_set);
}

gboolean 
unpack_constraints(crm_data_t * xml_constraints, pe_working_set_t *data_set)
{
	crm_data_t *lifetime = NULL;
	crm_debug_2("Begining unpack... %s",
		    xml_constraints?crm_element_name(xml_constraints):"<none>");
	xml_child_iter(
		xml_constraints, xml_obj, 

		const char *id = crm_element_value(xml_obj, XML_ATTR_ID);
		if(id == NULL) {
			crm_config_err("Constraint <%s...> must have an id",
				crm_element_name(xml_obj));
			continue;
		}

		crm_debug_3("Processing constraint %s %s",
			    crm_element_name(xml_obj),id);

		lifetime = cl_get_struct(xml_obj, "lifetime");

		if(test_ruleset(lifetime, NULL, data_set->now) == FALSE) {
			crm_info("Constraint %s %s is not active",
				 crm_element_name(xml_obj), id);

		} else if(safe_str_eq(XML_CONS_TAG_RSC_ORDER,
				      crm_element_name(xml_obj))) {
			unpack_rsc_order(xml_obj, data_set);

		} else if(safe_str_eq(XML_CONS_TAG_RSC_DEPEND,
				      crm_element_name(xml_obj))) {
			unpack_rsc_colocation(xml_obj, data_set);

		} else if(safe_str_eq(XML_CONS_TAG_RSC_LOCATION,
				      crm_element_name(xml_obj))) {
			unpack_rsc_location(xml_obj, data_set);

		} else {
			pe_err("Unsupported constraint type: %s",
				crm_element_name(xml_obj));
		}
		);

	return TRUE;
}

static const char *
invert_action(const char *action) 
{
	if(safe_str_eq(action, CRMD_ACTION_START)) {
		return CRMD_ACTION_STOP;

	} else if(safe_str_eq(action, CRMD_ACTION_STOP)) {
		return CRMD_ACTION_START;
		
	} else if(safe_str_eq(action, CRMD_ACTION_PROMOTE)) {
		return CRMD_ACTION_DEMOTE;
		
	} else if(safe_str_eq(action, CRMD_ACTION_DEMOTE)) {
		return CRMD_ACTION_PROMOTE;

	} else if(safe_str_eq(action, CRMD_ACTION_STARTED)) {
		return CRMD_ACTION_STOPPED;
		
	} else if(safe_str_eq(action, CRMD_ACTION_STOPPED)) {
		return CRMD_ACTION_STARTED;
		
	}
	pe_err("Unknown action: %s", action);
	return NULL;
}

gboolean
unpack_rsc_order(crm_data_t * xml_obj, pe_working_set_t *data_set)
{
	gboolean symmetrical_bool = TRUE;
	enum pe_ordering cons_weight = pe_ordering_optional;
	
	const char *id     = crm_element_value(xml_obj, XML_ATTR_ID);
	const char *type   = crm_element_value(xml_obj, XML_ATTR_TYPE);
	const char *id_rh  = crm_element_value(xml_obj, XML_CONS_ATTR_TO);
	const char *id_lh  = crm_element_value(xml_obj, XML_CONS_ATTR_FROM);
	const char *score  = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
	const char *action = crm_element_value(xml_obj, XML_CONS_ATTR_ACTION);
	const char *action_rh = crm_element_value(xml_obj, XML_CONS_ATTR_TOACTION);

	const char *symmetrical = crm_element_value(
		xml_obj, XML_CONS_ATTR_SYMMETRICAL);

	resource_t *rsc_lh   = NULL;
	resource_t *rsc_rh   = NULL;

	if(xml_obj == NULL) {
		crm_config_err("No constraint object to process.");
		return FALSE;

	} else if(id == NULL) {
		crm_config_err("%s constraint must have an id",
			crm_element_name(xml_obj));
		return FALSE;
		
	} else if(id_lh == NULL || id_rh == NULL) {
		crm_config_err("Constraint %s needs two sides lh: %s rh: %s",
			      id, crm_str(id_lh), crm_str(id_rh));
		return FALSE;
	}

	if(action == NULL) {
		action = CRMD_ACTION_START;
	}
	if(action_rh == NULL) {
		action_rh = action;
	}
	CRM_CHECK(action != NULL, return FALSE);
	CRM_CHECK(action_rh != NULL, return FALSE);
	
	if(safe_str_eq(type, "before")) {
		id_lh  = crm_element_value(xml_obj, XML_CONS_ATTR_TO);
		id_rh  = crm_element_value(xml_obj, XML_CONS_ATTR_FROM);
		action = crm_element_value(xml_obj, XML_CONS_ATTR_TOACTION);
		action_rh = crm_element_value(xml_obj, XML_CONS_ATTR_ACTION);
		if(action_rh == NULL) {
			action_rh = CRMD_ACTION_START;
		}
		if(action == NULL) {
			action = action_rh;
		}
	}

	CRM_CHECK(action != NULL, return FALSE);
	CRM_CHECK(action_rh != NULL, return FALSE);
	
	rsc_lh   = pe_find_resource(data_set->resources, id_rh);
	rsc_rh   = pe_find_resource(data_set->resources, id_lh);

	if(rsc_lh == NULL) {
		crm_config_err("Constraint %s: no resource found for LHS of %s", id, id_lh);
		return FALSE;
	
	} else if(rsc_rh == NULL) {
		crm_config_err("Constraint %s: no resource found for RHS of %s", id, id_rh);
		return FALSE;
	}

	if(crm_atoi(score, "0") > 0) {
		/* the name seems weird but the effect is correct */
		cons_weight = pe_ordering_restart;
	}
	
	custom_action_order(
		rsc_lh, generate_op_key(rsc_lh->id, action, 0), NULL,
		rsc_rh, generate_op_key(rsc_rh->id, action_rh, 0), NULL,
		cons_weight, data_set);

	if(rsc_rh->restart_type == pe_restart_restart
	   && safe_str_eq(action, action_rh)) {
		if(safe_str_eq(action, CRMD_ACTION_START)) {
			crm_debug_2("Recover start-start: %s-%s",
				rsc_lh->id, rsc_rh->id);
  			order_start_start(rsc_lh, rsc_rh, pe_ordering_recover);
 		} else if(safe_str_eq(action, CRMD_ACTION_STOP)) {
			crm_debug_2("Recover stop-stop: %s-%s",
				rsc_rh->id, rsc_lh->id);
  			order_stop_stop(rsc_rh, rsc_lh, pe_ordering_recover); 
		}
	}

	cl_str_to_boolean(symmetrical, &symmetrical_bool);
	if(symmetrical_bool == FALSE) {
		return TRUE;
	}
	
	action = invert_action(action);
	action_rh = invert_action(action_rh);
	
	custom_action_order(
		rsc_rh, generate_op_key(rsc_rh->id, action_rh, 0), NULL,
		rsc_lh, generate_op_key(rsc_lh->id, action, 0), NULL,
		cons_weight, data_set);

	if(rsc_lh->restart_type == pe_restart_restart
	   && safe_str_eq(action, action_rh)) {
		if(safe_str_eq(action, CRMD_ACTION_START)) {
			crm_debug_2("Recover start-start (2): %s-%s",
				rsc_lh->id, rsc_rh->id);
  			order_start_start(rsc_lh, rsc_rh, pe_ordering_recover);
		} else if(safe_str_eq(action, CRMD_ACTION_STOP)) { 
			crm_debug_2("Recover stop-stop (2): %s-%s",
				rsc_rh->id, rsc_lh->id);
  			order_stop_stop(rsc_rh, rsc_lh, pe_ordering_recover); 
		}
	}
	
	return TRUE;
}

gboolean
unpack_rsc_location(crm_data_t * xml_obj, pe_working_set_t *data_set)
{
	gboolean empty = TRUE;
	const char *id_lh   = crm_element_value(xml_obj, "rsc");
	const char *id      = crm_element_value(xml_obj, XML_ATTR_ID);
	resource_t *rsc_lh  = pe_find_resource(data_set->resources, id_lh);
	
	if(rsc_lh == NULL) {
		/* only a warn as BSC adds the constraint then the resource */
		crm_config_warn("No resource (con=%s, rsc=%s)", id, id_lh);
		return FALSE;

	} else if(rsc_lh->is_managed == FALSE) {
		crm_debug_2("Ignoring constraint %s: resource %s not managed",
			    id, id_lh);
		return FALSE;
	}

	xml_child_iter_filter(
		xml_obj, rule_xml, XML_TAG_RULE,
		empty = FALSE;
		crm_debug_2("Unpacking %s/%s", id, ID(rule_xml));
		generate_location_rule(rsc_lh, rule_xml, data_set);
		);

	if(empty) {
		crm_config_err("Invalid location constraint %s:"
			      " rsc_location must contain at least one rule",
			      ID(xml_obj));
	}
	return TRUE;
}

rsc_to_node_t *
generate_location_rule(
	resource_t *rsc, crm_data_t *rule_xml, pe_working_set_t *data_set)
{	
	const char *rule_id = NULL;
	const char *score   = NULL;
	const char *boolean = NULL;
	const char *role    = NULL;
	const char *attr_score = NULL;

	GListPtr match_L  = NULL;
	
	int score_f   = 0;
	gboolean do_and = TRUE;
	gboolean accept = TRUE;
	gboolean raw_score = TRUE;
	
	rsc_to_node_t *location_rule = NULL;
	
	rule_id = crm_element_value(rule_xml, XML_ATTR_ID);
	boolean = crm_element_value(rule_xml, XML_RULE_ATTR_BOOLEAN_OP);
	role = crm_element_value(rule_xml, XML_RULE_ATTR_ROLE);

	crm_debug_2("Processing rule: %s", rule_id);

	if(role != NULL && text2role(role) == RSC_ROLE_UNKNOWN) {
		pe_err("Bad role specified for %s: %s", rule_id, role);
		return NULL;
	}
	
	score = crm_element_value(rule_xml, XML_RULE_ATTR_SCORE);
	if(score != NULL) {
		score_f = char2score(score);
		
	} else {
		score = crm_element_value(
			rule_xml, XML_RULE_ATTR_SCORE_ATTRIBUTE);
		if(score == NULL) {
			score = crm_element_value(
				rule_xml, XML_RULE_ATTR_SCORE_MANGLED);
		}
		if(score != NULL) {
			raw_score = FALSE;
		}
	}
	if(safe_str_eq(boolean, "or")) {
		do_and = FALSE;
	}
	
	location_rule = rsc2node_new(rule_id, rsc, 0, NULL, data_set);
	
	if(location_rule == NULL) {
		return NULL;
	}
	if(role != NULL) {
		crm_debug_2("Setting role filter: %s", role);
		location_rule->role_filter = text2role(role);
	}
	if(do_and) {
		match_L = node_list_dup(data_set->nodes, TRUE, FALSE);
		slist_iter(
			node, node_t, match_L, lpc,
			node->weight = score_f;
			);
	}

	xml_child_iter(
		rule_xml, expr, 		

		enum expression_type type = find_expression_type(expr);
		if(type == not_expr) {
			pe_err("Expression <%s id=%s...> is not valid",
			       crm_element_name(expr), crm_str(ID(expr)));
			continue;	
		}	
		
		slist_iter(
			node, node_t, data_set->nodes, lpc,

			if(type == nested_rule) {
				accept = test_rule(
					expr, node->details->attrs,
					RSC_ROLE_UNKNOWN, data_set->now);
			} else {
				accept = test_expression(
					expr, node->details->attrs,
					RSC_ROLE_UNKNOWN, data_set->now);
			}
			
			if(raw_score == FALSE) {
				attr_score = g_hash_table_lookup(
					node->details->attrs, score);
				if(attr_score == NULL) {
					accept = FALSE;
					pe_warn("node %s did not have a value"
						" for %s",
						node->details->uname, score);
				} else {
					crm_debug("Rule %s: node %s had value %s for %s",
						  rule_id, node->details->uname, attr_score, score);
					score_f = char2score(attr_score);
				}
			}
			
			if(accept) {
				node_t *local = pe_find_node_id(
					match_L, node->details->id);
				if(local == NULL && do_and) {
					continue;
					
				} else if(local == NULL) {
					local = node_copy(node);
					match_L = g_list_append(match_L, local);
				}
				
				local->weight = merge_weights(
					local->weight, score_f);
				crm_debug_3("node %s now has weight %d",
					    node->details->uname,local->weight);
				
			} else if(do_and && !accept) {
				/* remove it */
				node_t *delete = pe_find_node_id(
					match_L, node->details->id);
				if(delete != NULL) {
					match_L = g_list_remove(match_L,delete);
					crm_debug_5("node %s did not match",
						    node->details->uname);
				}
				crm_free(delete);
			}
			);
		);
	
	location_rule->node_list_rh = match_L;
	if(location_rule->node_list_rh == NULL) {
		crm_debug_2("No matching nodes for rule %s", rule_id);
		return NULL;
	} 

	crm_debug_3("%s: %d nodes matched",
		    rule_id, g_list_length(location_rule->node_list_rh));
	crm_action_debug_3(print_rsc_to_node("Added", location_rule, FALSE));
	return location_rule;
}

gboolean
rsc_colocation_new(const char *id, enum con_strength strength,
		   resource_t *rsc_lh, resource_t *rsc_rh,
		   const char *state_lh, const char *state_rh)
{
	rsc_colocation_t *new_con      = NULL;
 	rsc_colocation_t *inverted_con = NULL; 

	if(rsc_lh == NULL){
		crm_config_err("No resource found for LHS %s", id);
		return FALSE;

	} else if(rsc_rh == NULL){
		crm_config_err("No resource found for RHS of %s", id);
		return FALSE;
	}

	crm_malloc0(new_con, sizeof(rsc_colocation_t));
	if(new_con == NULL) {
		return FALSE;
	}
	if(safe_str_eq(state_lh, CRMD_ACTION_STARTED)) {
		state_lh = NULL;
	}
	if(safe_str_eq(state_rh, CRMD_ACTION_STARTED)) {
		state_rh = NULL;
	}

	new_con->id       = id;
	new_con->rsc_lh   = rsc_lh;
	new_con->rsc_rh   = rsc_rh;
	new_con->strength = strength;
	new_con->state_lh = state_lh;
	new_con->state_rh = state_rh;

	inverted_con = invert_constraint(new_con);
	
	crm_debug_4("Adding constraint %s (%p) to %s",
		  new_con->id, new_con, rsc_lh->id);
	
	rsc_lh->rsc_cons = g_list_insert_sorted(
		rsc_lh->rsc_cons, new_con, sort_cons_strength);
	
	crm_debug_4("Adding constraint %s (%p) to %s",
		  inverted_con->id, inverted_con, rsc_rh->id);
	
	rsc_rh->rsc_cons = g_list_insert_sorted(
		rsc_rh->rsc_cons, inverted_con, sort_cons_strength);
	
	return TRUE;
}

/* LHS before RHS */
gboolean
custom_action_order(
	resource_t *lh_rsc, char *lh_action_task, action_t *lh_action,
	resource_t *rh_rsc, char *rh_action_task, action_t *rh_action,
	enum pe_ordering type, pe_working_set_t *data_set)
{
	order_constraint_t *order = NULL;

	if((lh_action == NULL && lh_rsc == NULL)
	   || (rh_action == NULL && rh_rsc == NULL)){
		crm_config_err("Invalid inputs lh_rsc=%p, lh_a=%p,"
			      " rh_rsc=%p, rh_a=%p",
			      lh_rsc, lh_action, rh_rsc, rh_action);
		crm_free(lh_action_task);
		crm_free(rh_action_task);
		return FALSE;
	}

	crm_malloc0(order, sizeof(order_constraint_t));
	if(order == NULL) { return FALSE; }
	
	order->id             = data_set->order_id++;
	order->type           = type;
	order->lh_rsc         = lh_rsc;
	order->rh_rsc         = rh_rsc;
	order->lh_action      = lh_action;
	order->rh_action      = rh_action;
	order->lh_action_task = lh_action_task;
	order->rh_action_task = rh_action_task;
	
	data_set->ordering_constraints = g_list_append(
		data_set->ordering_constraints, order);
	
	if(lh_rsc != NULL && rh_rsc != NULL) {
		crm_debug_4("Created ordering constraint %d (%s):"
			 " %s/%s before %s/%s",
			 order->id, ordering_type2text(order->type),
			 lh_rsc->id, lh_action_task,
			 rh_rsc->id, rh_action_task);
		
	} else if(lh_rsc != NULL) {
		crm_debug_4("Created ordering constraint %d (%s):"
			 " %s/%s before action %d (%s)",
			 order->id, ordering_type2text(order->type),
			 lh_rsc->id, lh_action_task,
			 rh_action->id, rh_action_task);
		
	} else if(rh_rsc != NULL) {
		crm_debug_4("Created ordering constraint %d (%s):"
			 " action %d (%s) before %s/%s",
			 order->id, ordering_type2text(order->type),
			 lh_action->id, lh_action_task,
			 rh_rsc->id, rh_action_task);
		
	} else {
		crm_debug_4("Created ordering constraint %d (%s):"
			 " action %d (%s) before action %d (%s)",
			 order->id, ordering_type2text(order->type),
			 lh_action->id, lh_action_task,
			 rh_action->id, rh_action_task);
	}
	
	return TRUE;
}

gboolean
unpack_rsc_colocation(crm_data_t * xml_obj, pe_working_set_t *data_set)
{
	enum con_strength strength_e = pecs_ignore;

	const char *id    = crm_element_value(xml_obj, XML_ATTR_ID);
	const char *id_rh = crm_element_value(xml_obj, XML_CONS_ATTR_TO);
	const char *id_lh = crm_element_value(xml_obj, XML_CONS_ATTR_FROM);
	const char *score = crm_element_value(xml_obj, XML_RULE_ATTR_SCORE);
	const char *state_lh = crm_element_value(xml_obj, XML_RULE_ATTR_FROMSTATE);
	const char *state_rh = crm_element_value(xml_obj, XML_RULE_ATTR_TOSTATE);

	resource_t *rsc_lh = pe_find_resource(data_set->resources, id_lh);
	resource_t *rsc_rh = pe_find_resource(data_set->resources, id_rh);
 
	if(rsc_lh == NULL) {
		crm_config_err("No resource (con=%s, rsc=%s)", id, id_lh);
		return FALSE;
		
	} else if(rsc_rh == NULL) {
		crm_config_err("No resource (con=%s, rsc=%s)", id, id_rh);
		return FALSE;
	}

	/* the docs indicate that only +/- INFINITY are allowed,
	 *   but no-one ever reads the docs so all positive values will
	 *   count as "must" and negative values as "must not"
	 */
	if(score == NULL || score[0] != '-') {
		strength_e = pecs_must;
	} else {
		strength_e = pecs_must_not;
	}
	return rsc_colocation_new(id, strength_e, rsc_lh, rsc_rh,
				  state_lh, state_rh);
}

gboolean is_active(rsc_to_node_t *cons)
{
	return TRUE;
}

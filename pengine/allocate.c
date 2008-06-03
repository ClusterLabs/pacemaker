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
void migrate_reload_madness(pe_working_set_t *data_set);

resource_alloc_functions_t resource_class_alloc_functions[] = {
	{
		native_merge_weights,
		native_color,
		native_create_actions,
		native_create_probe,
		native_internal_constraints,
		native_rsc_colocation_lh,
		native_rsc_colocation_rh,
		native_rsc_order_lh,
		native_rsc_order_rh,
		native_rsc_location,
		native_expand,
		complex_migrate_reload,
		complex_stonith_ordering,
		complex_create_notify_element,
	},
	{
		group_merge_weights,
		group_color,
		group_create_actions,
		native_create_probe,
		group_internal_constraints,
		group_rsc_colocation_lh,
		group_rsc_colocation_rh,
		group_rsc_order_lh,
		group_rsc_order_rh,
		group_rsc_location,
		group_expand,
		complex_migrate_reload,
		complex_stonith_ordering,
		complex_create_notify_element,
	},
	{
		native_merge_weights,
		clone_color,
		clone_create_actions,
		clone_create_probe,
		clone_internal_constraints,
		clone_rsc_colocation_lh,
		clone_rsc_colocation_rh,
		clone_rsc_order_lh,
		clone_rsc_order_rh,
		clone_rsc_location,
		clone_expand,
		complex_migrate_reload,
		complex_stonith_ordering,
		complex_create_notify_element,
	},
	{
		native_merge_weights,
		master_color,
		master_create_actions,
		clone_create_probe,
		master_internal_constraints,
		clone_rsc_colocation_lh,
		master_rsc_colocation_rh,
		clone_rsc_order_lh,
		clone_rsc_order_rh,
		clone_rsc_location,
		clone_expand,
		complex_migrate_reload,
		complex_stonith_ordering,
		complex_create_notify_element,
	}
};

static gboolean
check_rsc_parameters(resource_t *rsc, node_t *node, xmlNode *rsc_entry,
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
		if(value == old_value /* ie. NULL */
		   || crm_str_eq(value, old_value, TRUE)) {
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
		set_bit(rsc->flags, pe_rsc_start_pending);
		delete_resource = TRUE;
	}
	return delete_resource;
}

static gboolean
check_action_definition(resource_t *rsc, node_t *active_node, xmlNode *xml_op,
			pe_working_set_t *data_set)
{
	char *key = NULL;
	int interval = 0;
	const char *interval_s = NULL;
	
	gboolean did_change = FALSE;
	gboolean start_op = FALSE;

	xmlNode *params_all = NULL;
	xmlNode *params_restart = NULL;
	GHashTable *local_rsc_params = NULL;
	
	char *digest_all_calc = NULL;
	const char *digest_all = NULL;

	const char *restart_list = NULL;
	const char *digest_restart = NULL;
	char *digest_restart_calc = NULL;

	action_t *action = NULL;
	const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
	const char *op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);

	CRM_CHECK(active_node != NULL, return FALSE);

	interval_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);
	interval = crm_parse_int(interval_s, "0");
	/* we need to reconstruct the key because of the way we used to construct resource IDs */
	key = generate_op_key(rsc->id, task, interval);

	if(interval > 0) {
		xmlNode *op_match = NULL;

		crm_debug_2("Checking parameters for %s", key);
		op_match = find_rsc_op_entry(rsc, key);

		if(op_match == NULL && data_set->stop_action_orphans) {
			/* create a cancel action */
			action_t *cancel = NULL;
			char *cancel_key = crm_strdup(key);
			const char *call_id = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
			
			crm_info("Orphan action will be stopped: %s on %s",
				 key, active_node->details->uname);

			/* cancel_key = generate_op_key( */
			/* 	rsc->id, RSC_CANCEL, interval); */

			cancel = custom_action(
				rsc, cancel_key, RSC_CANCEL,
				active_node, FALSE, TRUE, data_set);

			crm_free(cancel->task);
			cancel->task = crm_strdup(RSC_CANCEL);
			
			add_hash_param(cancel->meta, XML_LRM_ATTR_TASK,     task);
			add_hash_param(cancel->meta, XML_LRM_ATTR_CALLID,   call_id);
			add_hash_param(cancel->meta, XML_LRM_ATTR_INTERVAL, interval_s);

			custom_action_order(	
				rsc, stop_key(rsc), NULL,
				rsc, NULL, cancel,
				pe_order_optional, data_set);
			crm_free(key); key = NULL;
			return TRUE;

		} else if(op_match == NULL) {
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
		local_rsc_params, NULL, FALSE, data_set->now);
	
	params_all = create_xml_node(NULL, XML_TAG_PARAMS);
	g_hash_table_foreach(action->extra, hash2field, params_all);
	g_hash_table_foreach(rsc->parameters, hash2field, params_all);
	g_hash_table_foreach(action->meta, hash2metafield, params_all);
	g_hash_table_foreach(local_rsc_params, hash2field, params_all);

	filter_action_parameters(params_all, op_version);
	digest_all_calc = calculate_xml_digest(params_all, TRUE, FALSE);
	digest_all = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);
	digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);
	restart_list = crm_element_value(xml_op, XML_LRM_ATTR_OP_RESTART);

	if(crm_str_eq(task, RSC_START, TRUE)) {
		start_op = TRUE;
	}
	
	if(start_op && digest_restart) {
		params_restart = copy_xml(params_all);
		if(restart_list) {
			filter_reload_parameters(params_restart, restart_list);
		}

		digest_restart_calc = calculate_xml_digest(params_restart, TRUE, FALSE);
		if(safe_str_neq(digest_restart_calc, digest_restart)) {
			did_change = TRUE;
			crm_log_xml_info(params_restart, "params:restart");
			crm_warn("Parameters to %s on %s changed: recorded %s vs. %s (restart:%s) %s",
				 key, active_node->details->uname,
				 crm_str(digest_restart), digest_restart_calc,
				 op_version, crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
			
			key = generate_op_key(rsc->id, task, interval);
			custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
			goto cleanup;
		}
	}

	if(safe_str_neq(digest_all_calc, digest_all)) {
		action_t *op = NULL;
		did_change = TRUE;
		crm_log_xml_info(params_all, "params:all");
 		crm_warn("Parameters to %s on %s changed: recorded %s vs. %s (all:%s) %s",
			 key, active_node->details->uname,
			 crm_str(digest_all), digest_all_calc, op_version,
			 crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
		
		key = generate_op_key(rsc->id, task, interval);
		op = custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
		if(start_op && digest_restart) {
			op->allow_reload_conversion = TRUE;

		} else if(interval > 0) {
			custom_action_order(rsc, start_key(rsc), NULL,
					    NULL, crm_strdup(op->task), op,
					    pe_order_runnable_left, data_set);
		}
		
	}

  cleanup:
	free_xml(params_all);
	free_xml(params_restart);
	crm_free(digest_all_calc);
	crm_free(digest_restart_calc);
	g_hash_table_destroy(local_rsc_params);

	pe_free_action(action);
	
	return did_change;
}

extern gboolean DeleteRsc(resource_t *rsc, node_t *node, gboolean optional, pe_working_set_t *data_set);

static void
check_actions_for(xmlNode *rsc_entry, node_t *node, pe_working_set_t *data_set)
{
	const char *id = NULL;
	const char *task = NULL;
	int interval = 0;
	const char *interval_s = NULL;
	GListPtr op_list = NULL;
	GListPtr sorted_op_list = NULL;
	const char *rsc_id = ID(rsc_entry);
	gboolean is_probe = FALSE;
	int start_index = 0, stop_index = 0;
	resource_t *rsc = pe_find_resource(data_set->resources, rsc_id);

	CRM_CHECK(rsc != NULL, return);
	CRM_CHECK(node != NULL, return);
	CRM_CHECK(rsc_id != NULL, return);
	if(is_set(rsc->flags, pe_rsc_orphan)) {
		crm_debug_2("Skipping param check for %s: orphan", rsc->id);
		return;
		
	} else if(pe_find_node_id(rsc->running_on, node->details->id) == NULL) {
		crm_debug_2("Skipping param check for %s: no longer active on %s",
			    rsc->id, node->details->uname);
		return;
	}
	
	crm_debug_3("Processing %s on %s", rsc->id, node->details->uname);
	
	if(check_rsc_parameters(rsc, node, rsc_entry, data_set)) {
	    DeleteRsc(rsc, node, FALSE, data_set);
	}
	
	xml_child_iter_filter(
		rsc_entry, rsc_op, XML_LRM_TAG_RSC_OP,
		op_list = g_list_append(op_list, rsc_op);
		);

	sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
	calculate_active_ops(sorted_op_list, &start_index, &stop_index);

	slist_iter(
		rsc_op, xmlNode, sorted_op_list, lpc,

		if(start_index < stop_index) {
			/* stopped */
			continue;
		} else if(lpc < start_index) {
			/* action occurred prior to a start */
			continue;
		}
		
		id   = ID(rsc_op);
		is_probe = FALSE;
		task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);

		interval_s = crm_element_value(rsc_op, XML_LRM_ATTR_INTERVAL);
		interval = crm_parse_int(interval_s, "0");
		
		if(interval == 0 && safe_str_eq(task, RSC_STATUS)) {
			is_probe = TRUE;
		}
		
		if(is_probe || safe_str_eq(task, RSC_START) || interval > 0) {
			check_action_definition(rsc, node, rsc_op, data_set);
		}
		);

	g_list_free(sorted_op_list);
	
}

static void
check_actions(pe_working_set_t *data_set)
{
	const char *id = NULL;
	node_t *node = NULL;
	xmlNode *lrm_rscs = NULL;
	xmlNode *status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

	xml_child_iter_filter(
		status, node_state, XML_CIB_TAG_STATE,

		id       = crm_element_value(node_state, XML_ATTR_ID);
		lrm_rscs = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
		lrm_rscs = find_xml_node(lrm_rscs, XML_LRM_TAG_RESOURCES, FALSE);

		node = pe_find_node_id(data_set->nodes, id);

		if(node == NULL) {
			continue;

		} else if(can_run_resources(node) == FALSE) {
			crm_debug_2("Skipping param check for %s: cant run resources",
				    node->details->uname);
			continue;
		}
		crm_debug_2("Processing node %s", node->details->uname);
		if(node->details->online || data_set->stonith_enabled) {
			xml_child_iter_filter(
				lrm_rscs, rsc_entry, XML_LRM_TAG_RESOURCE,
				if(xml_has_children(rsc_entry)) {
					check_actions_for(rsc_entry, node, data_set);
				}
				);
		}
		);
}

static gboolean 
apply_placement_constraints(pe_working_set_t *data_set)
{
	crm_debug_3("Applying constraints...");
	slist_iter(
		cons, rsc_to_node_t, data_set->placement_constraints, lpc,

		cons->rsc_lh->cmds->rsc_location(cons->rsc_lh, cons);
		);
	
	return TRUE;
	
}

static void
common_apply_stickiness(resource_t *rsc, node_t *node, pe_working_set_t *data_set) 
{
	int fail_count = 0;
	const char *value = NULL;
	resource_t *failed = rsc;
	GHashTable *meta_hash = NULL;

	if(rsc->children) {
	    slist_iter(
		child_rsc, resource_t, rsc->children, lpc,
		common_apply_stickiness(child_rsc, node, data_set);
		);
	    return;
	}

	meta_hash = g_hash_table_new_full(
		g_str_hash, g_str_equal,
		g_hash_destroy_str, g_hash_destroy_str);
	get_meta_attributes(meta_hash, rsc, node, data_set);

	/* update resource preferences that relate to the current node */	    
	value = g_hash_table_lookup(meta_hash, XML_RSC_ATTR_STICKINESS);
	if(value != NULL && safe_str_neq("default", value)) {
		rsc->stickiness = char2score(value);
	} else {
		rsc->stickiness = data_set->default_resource_stickiness;
	}

	value = g_hash_table_lookup(meta_hash, XML_RSC_ATTR_FAIL_STICKINESS);
	if(value != NULL && safe_str_neq("default", value)) {
		rsc->migration_threshold = char2score(value);
	} else {
		rsc->migration_threshold = data_set->default_migration_threshold;
	}

	if(is_not_set(rsc->flags, pe_rsc_unique)) {
	    failed = uber_parent(rsc);
	}
	    
	fail_count = get_failcount(node, rsc, NULL, data_set);	

	if(fail_count > 0 && rsc->migration_threshold != 0) {
	    if(rsc->migration_threshold <= fail_count) {
		resource_location(failed, node, -INFINITY, "__fail_limit__", data_set);
		crm_warn("Forcing %s away from %s after %d failures (max=%d)",
			 failed->id, node->details->uname, fail_count, rsc->migration_threshold);
	    } else {
		crm_notice("%s can fail %d more times on %s before being forced off",
			   failed->id, rsc->migration_threshold - fail_count, node->details->uname);
	    }
	}
	
	g_hash_table_destroy(meta_hash);
}

static void complex_set_cmds(resource_t *rsc)
{
    rsc->cmds = &resource_class_alloc_functions[rsc->variant];
    slist_iter(
	child_rsc, resource_t, rsc->children, lpc,
	complex_set_cmds(child_rsc);
	);
}

void
set_alloc_actions(pe_working_set_t *data_set) 
{
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		complex_set_cmds(rsc);
		);
}

gboolean
stage0(pe_working_set_t *data_set)
{
	xmlNode * cib_constraints = get_object_root(
		XML_CIB_TAG_CONSTRAINTS, data_set->input);

	if(data_set->input == NULL) {
		return FALSE;
	}

	cluster_status(data_set);
	
	set_alloc_actions(data_set);

	slist_iter(node, node_t, data_set->nodes, lpc,
		   slist_iter(
		       rsc, resource_t, data_set->resources, lpc2,
		       common_apply_stickiness(rsc, node, data_set);
		       );
	    );
	
	unpack_constraints(cib_constraints, data_set);
	return TRUE;
}

/*
 * Check nodes for resources started outside of the LRM
 */
gboolean
probe_resources(pe_working_set_t *data_set)
{
	action_t *probe_complete = NULL;
	action_t *probe_node_complete = NULL;

	slist_iter(
		node, node_t, data_set->nodes, lpc,
		gboolean force_probe = FALSE;
		const char *probed = g_hash_table_lookup(
			node->details->attrs, CRM_OP_PROBED);

		if(node->details->online == FALSE) {
			continue;
			
		} else if(node->details->unclean) {
			continue;

		} else if(probe_complete == NULL) {
			probe_complete = get_pseudo_op(CRM_OP_PROBED, data_set);
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
		
		order_actions(probe_node_complete, probe_complete, pe_order_optional);
		
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
					pe_order_optional, data_set);
			}
			);
		);

	return TRUE;
}


/*
 * Count how many valid nodes we have (so we know the maximum number of
 *  colors we can resolve).
 *
 * Apply node constraints (ie. filter the "allowed_nodes" part of resources
 */
gboolean
stage2(pe_working_set_t *data_set)
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
 * Create internal resource constraints before allocation
 */
gboolean
stage3(pe_working_set_t *data_set)
{
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->cmds->internal_constraints(rsc, data_set);
		);
	
	return TRUE;
}

/*
 * Check for orphaned or redefined actions
 */
gboolean
stage4(pe_working_set_t *data_set)
{
	check_actions(data_set);
	return TRUE;
}

gboolean
stage5(pe_working_set_t *data_set)
{
	/* Take (next) highest resource, assign it and create its actions */
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->cmds->color(rsc, data_set);
		);

	probe_resources(data_set);
	
	slist_iter(
		rsc, resource_t, data_set->resources, lpc,
		rsc->cmds->create_actions(rsc, data_set);	
		);

	return TRUE;
}

static gboolean is_managed(const resource_t *rsc)
{
    if(is_set(rsc->flags, pe_rsc_managed)) {
	return TRUE;
    }
    
    slist_iter(
	child_rsc, resource_t, rsc->children, lpc,
	if(is_managed(child_rsc)) {
	    return TRUE;
	}
	);
    
    return FALSE;
}

static gboolean any_managed_resouces(pe_working_set_t *data_set)
{
    slist_iter(
	rsc, resource_t, data_set->resources, lpc,
	if(is_managed(rsc)) {
	    return TRUE;
	}
	);
    return FALSE;
}

/*
 * Create dependancies for stonith and shutdown operations
 */
gboolean
stage6(pe_working_set_t *data_set)
{
	action_t *dc_down = NULL;
	action_t *stonith_op = NULL;
	action_t *last_stonith = NULL;
	gboolean integrity_lost = FALSE;
	action_t *ready = get_pseudo_op(STONITH_UP, data_set);
	action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);
	gboolean need_stonith = FALSE;
	
	crm_debug_3("Processing fencing and shutdown cases");

	if(data_set->stonith_enabled
	   && (data_set->have_quorum
	       || data_set->no_quorum_policy == no_quorum_ignore)) {
	    need_stonith = TRUE;
	}
	
	if(need_stonith && any_managed_resouces(data_set) == FALSE) {
	    crm_crit("Delaying fencing operations until there are resources to manage");
	    need_stonith = FALSE;
	}
	
	slist_iter(
		node, node_t, data_set->nodes, lpc,

		stonith_op = NULL;
		if(node->details->unclean && need_stonith) {
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
			order_actions(ready, stonith_op, pe_order_implies_left);
			order_actions(stonith_op, all_stopped, pe_order_implies_right);

			if(node->details->is_dc) {
				dc_down = stonith_op;

			} else {
				if(last_stonith) {
					order_actions(last_stonith, stonith_op, pe_order_implies_left);
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

			order_actions(node_stop, dc_down, pe_order_implies_left);
			);

		if(last_stonith && dc_down != last_stonith) {
			order_actions(last_stonith, dc_down, pe_order_implies_left);
		}
		g_list_free(shutdown_matches);
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
	crm_debug_4("Applying ordering constraints");

	slist_iter(
		order, order_constraint_t, data_set->ordering_constraints, lpc,

		resource_t *rsc = order->lh_rsc;
		crm_debug_3("Applying ordering constraint: %d", order->id);
		
		if(rsc != NULL) {
			crm_debug_4("rsc_action-to-*");
			rsc->cmds->rsc_order_lh(rsc, order, data_set);
			continue;
		}

		rsc = order->rh_rsc;
		if(rsc != NULL) {
			crm_debug_4("action-to-rsc_action");
			rsc->cmds->rsc_order_rh(order->lh_action, rsc, order);

		} else {
			crm_debug_4("action-to-action");
			order_actions(
				order->lh_action, order->rh_action, order->type);
		}
		);

	update_action_states(data_set->actions);

	slist_iter(
		rsc, resource_t, data_set->resources, lpc,

		rsc->cmds->migrate_reload(rsc, data_set);
		);

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

	transition_id++;
	crm_debug_2("Creating transition graph %d.", transition_id);
	
	data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);

	value = pe_pref(data_set->config_hash, "cluster-delay");
	crm_xml_add(data_set->graph, "cluster-delay", value);

	crm_xml_add(data_set->graph, "failed-stop-offset", "INFINITY");

	value = pe_pref(data_set->config_hash, "start-failure-is-fatal");
	if(crm_is_true(value)) {
	    crm_xml_add(data_set->graph, "failed-start-offset", "INFINITY");
	} else {
	    crm_xml_add(data_set->graph, "failed-start-offset", "1");
	}
	
	value = pe_pref(data_set->config_hash, "batch-limit");
	crm_xml_add(data_set->graph, "batch-limit", value);

	crm_xml_add_int(data_set->graph, "transition_id", transition_id);
	
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
	crm_debug_2("Created transition graph %d.", transition_id);
	
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
	
	crm_debug_3("deleting node cons: %p", data_set->placement_constraints);
	pe_free_rsc_to_node(data_set->placement_constraints);
	data_set->placement_constraints = NULL;

	crm_debug_3("deleting inter-resource cons: %p", data_set->colocation_constraints);
  	pe_free_shallow(data_set->colocation_constraints);
	data_set->colocation_constraints = NULL;
	
	cleanup_calculations(data_set);
}

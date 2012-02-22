/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/msg.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pengine.h>
#include <allocate.h>
#include <utils.h>
#include <lib/pengine/utils.h>

CRM_TRACE_INIT_DATA(pe_allocate);

void set_alloc_actions(pe_working_set_t * data_set);
void migrate_reload_madness(pe_working_set_t * data_set);

resource_alloc_functions_t resource_class_alloc_functions[] = {
    {
     native_merge_weights,
     native_color,
     native_create_actions,
     native_create_probe,
     native_internal_constraints,
     native_rsc_colocation_lh,
     native_rsc_colocation_rh,
     native_rsc_location,
     native_action_flags,
     native_update_actions,
     native_expand,
     native_append_meta,
     },
    {
     group_merge_weights,
     group_color,
     group_create_actions,
     native_create_probe,
     group_internal_constraints,
     group_rsc_colocation_lh,
     group_rsc_colocation_rh,
     group_rsc_location,
     group_action_flags,
     group_update_actions,
     group_expand,
     group_append_meta,
     },
    {
     native_merge_weights,
     clone_color,
     clone_create_actions,
     clone_create_probe,
     clone_internal_constraints,
     clone_rsc_colocation_lh,
     clone_rsc_colocation_rh,
     clone_rsc_location,
     clone_action_flags,
     clone_update_actions,
     clone_expand,
     clone_append_meta,
     },
    {
     native_merge_weights,
     master_color,
     master_create_actions,
     clone_create_probe,
     master_internal_constraints,
     clone_rsc_colocation_lh,
     master_rsc_colocation_rh,
     clone_rsc_location,
     clone_action_flags,
     clone_update_actions,
     clone_expand,
     master_append_meta,
     }
};

static gboolean
check_rsc_parameters(resource_t * rsc, node_t * node, xmlNode * rsc_entry,
                     pe_working_set_t * data_set)
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

    for (; attr_lpc < DIMOF(attr_list); attr_lpc++) {
        value = crm_element_value(rsc->xml, attr_list[attr_lpc]);
        old_value = crm_element_value(rsc_entry, attr_list[attr_lpc]);
        if (value == old_value  /* ie. NULL */
            || crm_str_eq(value, old_value, TRUE)) {
            continue;
        }

        force_restart = TRUE;
        crm_notice("Forcing restart of %s on %s, %s changed: %s -> %s",
                   rsc->id, node->details->uname, attr_list[attr_lpc],
                   crm_str(old_value), crm_str(value));
    }
    if (force_restart) {
        /* make sure the restart happens */
        stop_action(rsc, node, FALSE);
        set_bit(rsc->flags, pe_rsc_start_pending);
        delete_resource = TRUE;
    }
    return delete_resource;
}

static void
CancelXmlOp(resource_t * rsc, xmlNode * xml_op, node_t * active_node,
            const char *reason, pe_working_set_t * data_set)
{
    int interval = 0;
    action_t *cancel = NULL;

    char *key = NULL;
    const char *task = NULL;
    const char *call_id = NULL;
    const char *interval_s = NULL;

    CRM_CHECK(xml_op != NULL, return);
    CRM_CHECK(active_node != NULL, return);

    task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    call_id = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    interval_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);

    interval = crm_parse_int(interval_s, "0");

    /* we need to reconstruct the key because of the way we used to construct resource IDs */
    key = generate_op_key(rsc->id, task, interval);

    crm_info("Action %s on %s will be stopped: %s",
             key, active_node->details->uname, reason ? reason : "unknown");

    cancel = custom_action(rsc, crm_strdup(key), RSC_CANCEL, active_node, FALSE, TRUE, data_set);

    crm_free(cancel->task);
    cancel->task = crm_strdup(RSC_CANCEL);

    add_hash_param(cancel->meta, XML_LRM_ATTR_TASK, task);
    add_hash_param(cancel->meta, XML_LRM_ATTR_CALLID, call_id);
    add_hash_param(cancel->meta, XML_LRM_ATTR_INTERVAL, interval_s);

    custom_action_order(rsc, stop_key(rsc), NULL, rsc, NULL, cancel, pe_order_optional, data_set);
    crm_free(key);
    key = NULL;
}

static gboolean
check_action_definition(resource_t * rsc, node_t * active_node, xmlNode * xml_op,
                        pe_working_set_t * data_set)
{
    char *key = NULL;
    int interval = 0;
    const char *interval_s = NULL;

    gboolean did_change = FALSE;

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
    if (safe_str_eq(task, RSC_STOP)) {
        return FALSE;
    }

    interval_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);
    interval = crm_parse_int(interval_s, "0");
    /* we need to reconstruct the key because of the way we used to construct resource IDs */
    key = generate_op_key(rsc->id, task, interval);

    if (interval > 0) {
        xmlNode *op_match = NULL;

        crm_trace("Checking parameters for %s", key);
        op_match = find_rsc_op_entry(rsc, key);

        if (op_match == NULL && is_set(data_set->flags, pe_flag_stop_action_orphans)) {
            CancelXmlOp(rsc, xml_op, active_node, "orphan", data_set);
            crm_free(key);
            key = NULL;
            return TRUE;

        } else if (op_match == NULL) {
            crm_debug("Orphan action detected: %s on %s", key, active_node->details->uname);
            crm_free(key);
            key = NULL;
            return TRUE;
        }
    }

    action = custom_action(rsc, key, task, active_node, TRUE, FALSE, data_set);

    local_rsc_params = g_hash_table_new_full(crm_str_hash, g_str_equal,
                                             g_hash_destroy_str, g_hash_destroy_str);

    get_rsc_attributes(local_rsc_params, rsc, active_node, data_set);

    params_all = create_xml_node(NULL, XML_TAG_PARAMS);
    g_hash_table_foreach(local_rsc_params, hash2field, params_all);
    g_hash_table_foreach(action->extra, hash2field, params_all);
    g_hash_table_foreach(rsc->parameters, hash2field, params_all);
    g_hash_table_foreach(action->meta, hash2metafield, params_all);

    filter_action_parameters(params_all, op_version);
    digest_all_calc = calculate_operation_digest(params_all, op_version);
    digest_all = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);
    digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);
    restart_list = crm_element_value(xml_op, XML_LRM_ATTR_OP_RESTART);

    if (interval == 0 && safe_str_eq(task, RSC_STATUS)) {
        /* Reload based on the start action not a probe */
        task = RSC_START;

    } else if (interval == 0 && safe_str_eq(task, RSC_MIGRATED)) {
        /* Reload based on the start action not a migrate */
        task = RSC_START;
    }

    if (digest_restart) {
        /* Changes that force a restart */
        params_restart = copy_xml(params_all);
        if (restart_list) {
            filter_reload_parameters(params_restart, restart_list);
        }

        digest_restart_calc = calculate_operation_digest(params_restart, op_version);
        if (safe_str_neq(digest_restart_calc, digest_restart)) {
            did_change = TRUE;
            crm_log_xml_info(params_restart, "params:restart");
            crm_info("Parameters to %s on %s changed: was %s vs. now %s (restart:%s) %s",
                     key, active_node->details->uname,
                     crm_str(digest_restart), digest_restart_calc,
                     op_version, crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));

            key = generate_op_key(rsc->id, task, interval);
            custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
            goto cleanup;
        }
    }

    if (safe_str_neq(digest_all_calc, digest_all)) {
        /* Changes that can potentially be handled by a reload */
        did_change = TRUE;
        crm_log_xml_info(params_all, "params:reload");
        crm_info("Parameters to %s on %s changed: was %s vs. now %s (reload:%s) %s",
                 key, active_node->details->uname,
                 crm_str(digest_all), digest_all_calc, op_version,
                 crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));

        if (interval > 0) {
            action_t *op = NULL;
#if 0
            /* Always reload/restart the entire resource */
            op = custom_action(rsc, start_key(rsc), RSC_START, NULL, FALSE, TRUE, data_set);
            update_action_flags(op, pe_action_allow_reload_conversion);
#else
            /* Re-sending the recurring op is sufficient - the old one will be cancelled automatically */
            key = generate_op_key(rsc->id, task, interval);
            op = custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
            custom_action_order(rsc, start_key(rsc), NULL,
                                NULL, NULL, op, pe_order_runnable_left, data_set);
#endif

        } else if (digest_restart) {
            crm_trace("Reloading '%s' action for resource %s", task, rsc->id);

            /* Allow this resource to reload - unless something else causes a full restart */
            set_bit(rsc->flags, pe_rsc_try_reload);

            /* Create these for now, it keeps the action IDs the same in the regression outputs */
            key = generate_op_key(rsc->id, task, interval);
            custom_action(rsc, key, task, NULL, TRUE, TRUE, data_set);

        } else {
            crm_trace("Resource %s doesn't know how to reload", rsc->id);

            /* Re-send the start/demote/promote op
             * Recurring ops will be detected independantly
             */
            key = generate_op_key(rsc->id, task, interval);
            custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
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

extern gboolean DeleteRsc(resource_t * rsc, node_t * node, gboolean optional,
                          pe_working_set_t * data_set);

static void
check_actions_for(xmlNode * rsc_entry, resource_t * rsc, node_t * node, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    int offset = -1;
    int interval = 0;
    int stop_index = 0;
    int start_index = 0;

    const char *task = NULL;
    const char *interval_s = NULL;

    xmlNode *rsc_op = NULL;
    GListPtr op_list = NULL;
    GListPtr sorted_op_list = NULL;
    gboolean is_probe = FALSE;

    CRM_CHECK(node != NULL, return);

    if (is_set(rsc->flags, pe_rsc_orphan)) {
        crm_trace("Skipping param check for %s: orphan", rsc->id);
        return;

    } else if (pe_find_node_id(rsc->running_on, node->details->id) == NULL) {
        crm_trace("Skipping param check for %s: no longer active on %s",
                    rsc->id, node->details->uname);
        return;
    }

    crm_trace("Processing %s on %s", rsc->id, node->details->uname);

    if (check_rsc_parameters(rsc, node, rsc_entry, data_set)) {
        DeleteRsc(rsc, node, FALSE, data_set);
    }

    for (rsc_op = __xml_first_child(rsc_entry); rsc_op != NULL; rsc_op = __xml_next(rsc_op)) {
        if (crm_str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, TRUE)) {
            op_list = g_list_prepend(op_list, rsc_op);
        }
    }

    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;

        offset++;

        if (start_index < stop_index) {
            /* stopped */
            continue;
        } else if (offset < start_index) {
            /* action occurred prior to a start */
            continue;
        }

        is_probe = FALSE;
        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);

        interval_s = crm_element_value(rsc_op, XML_LRM_ATTR_INTERVAL);
        interval = crm_parse_int(interval_s, "0");

        if (interval == 0 && safe_str_eq(task, RSC_STATUS)) {
            is_probe = TRUE;
        }

        if (interval > 0 && is_set(data_set->flags, pe_flag_maintenance_mode)) {
            CancelXmlOp(rsc, rsc_op, node, "maintenance mode", data_set);

        } else if (is_probe || safe_str_eq(task, RSC_START) || interval > 0 || safe_str_eq(task, RSC_MIGRATED)) {
            check_action_definition(rsc, node, rsc_op, data_set);
        }
    }

    g_list_free(sorted_op_list);

}

static GListPtr
find_rsc_list(GListPtr result, resource_t * rsc, const char *id, gboolean renamed_clones,
              gboolean partial, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    gboolean match = FALSE;

    if (id == NULL) {
        return NULL;

    } else if (rsc == NULL && data_set) {

        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            result = find_rsc_list(result, child, id, renamed_clones, partial, NULL);
        }

        return result;

    } else if (rsc == NULL) {
        return NULL;
    }

    if (partial) {
        if (strstr(rsc->id, id)) {
            match = TRUE;

        } else if (rsc->long_name && strstr(rsc->long_name, id)) {
            match = TRUE;

        } else if (renamed_clones && rsc->clone_name && strstr(rsc->clone_name, id)) {
            match = TRUE;
        }

    } else {
        if (strcmp(rsc->id, id) == 0) {
            match = TRUE;

        } else if (rsc->long_name && strcmp(rsc->long_name, id) == 0) {
            match = TRUE;

        } else if (renamed_clones && rsc->clone_name && strcmp(rsc->clone_name, id) == 0) {
            match = TRUE;
        }
    }

    if (match) {
        result = g_list_prepend(result, rsc);
    }

    if (rsc->children) {
        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            result = find_rsc_list(result, child, id, renamed_clones, partial, NULL);
        }
    }

    return result;
}

static void
check_actions(pe_working_set_t * data_set)
{
    const char *id = NULL;
    node_t *node = NULL;
    xmlNode *lrm_rscs = NULL;
    xmlNode *status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

    xmlNode *node_state = NULL;

    for (node_state = __xml_first_child(status); node_state != NULL;
         node_state = __xml_next(node_state)) {
        if (crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            id = crm_element_value(node_state, XML_ATTR_ID);
            lrm_rscs = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
            lrm_rscs = find_xml_node(lrm_rscs, XML_LRM_TAG_RESOURCES, FALSE);

            node = pe_find_node_id(data_set->nodes, id);

            if (node == NULL) {
                continue;

            } else if (can_run_resources(node) == FALSE) {
                crm_trace("Skipping param check for %s: cant run resources",
                            node->details->uname);
                continue;
            }

            crm_trace("Processing node %s", node->details->uname);
            if (node->details->online || is_set(data_set->flags, pe_flag_stonith_enabled)) {
                xmlNode *rsc_entry = NULL;

                for (rsc_entry = __xml_first_child(lrm_rscs); rsc_entry != NULL;
                     rsc_entry = __xml_next(rsc_entry)) {
                    if (crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {

                        if (xml_has_children(rsc_entry)) {
                            GListPtr gIter = NULL;
                            GListPtr result = NULL;
                            const char *rsc_id = ID(rsc_entry);

                            CRM_CHECK(rsc_id != NULL, return);

                            result = find_rsc_list(NULL, NULL, rsc_id, TRUE, FALSE, data_set);
                            for (gIter = result; gIter != NULL; gIter = gIter->next) {
                                resource_t *rsc = (resource_t *) gIter->data;

                                check_actions_for(rsc_entry, rsc, node, data_set);
                            }
                            g_list_free(result);
                        }
                    }
                }
            }
        }
    }
}

static gboolean
apply_placement_constraints(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    crm_trace("Applying constraints...");

    for (gIter = data_set->placement_constraints; gIter != NULL; gIter = gIter->next) {
        rsc_to_node_t *cons = (rsc_to_node_t *) gIter->data;

        cons->rsc_lh->cmds->rsc_location(cons->rsc_lh, cons);
    }

    return TRUE;

}

static void
common_apply_stickiness(resource_t * rsc, node_t * node, pe_working_set_t * data_set)
{
    int fail_count = 0;
    resource_t *failed = rsc;

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            common_apply_stickiness(child_rsc, node, data_set);
        }
        return;
    }

    if (is_set(rsc->flags, pe_rsc_managed)
        && rsc->stickiness != 0 && g_list_length(rsc->running_on) == 1) {
        node_t *current = pe_find_node_id(rsc->running_on, node->details->id);
        node_t *match = pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);

        if (current == NULL) {

        } else if (match != NULL || is_set(data_set->flags, pe_flag_symmetric_cluster)) {
            resource_t *sticky_rsc = rsc;

            resource_location(sticky_rsc, node, rsc->stickiness, "stickiness", data_set);
            crm_debug("Resource %s: preferring current location"
                      " (node=%s, weight=%d)", sticky_rsc->id,
                      node->details->uname, rsc->stickiness);
        } else {
            GHashTableIter iter;
            node_t *nIter = NULL;

            crm_debug("Ignoring stickiness for %s: the cluster is asymmetric"
                      " and node %s is not explicitly allowed", rsc->id, node->details->uname);
            g_hash_table_iter_init(&iter, rsc->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (void **)&nIter)) {
                crm_err("%s[%s] = %d", rsc->id, nIter->details->uname, nIter->weight);
            }
        }
    }

    if (is_not_set(rsc->flags, pe_rsc_unique)) {
        failed = uber_parent(rsc);
    }

    fail_count = get_failcount(node, rsc, NULL, data_set);
    if (fail_count > 0 && rsc->migration_threshold != 0) {
        if (rsc->migration_threshold <= fail_count) {
            resource_location(failed, node, -INFINITY, "__fail_limit__", data_set);
            crm_warn("Forcing %s away from %s after %d failures (max=%d)",
                     failed->id, node->details->uname, fail_count, rsc->migration_threshold);
        } else {
            crm_notice("%s can fail %d more times on %s before being forced off",
                       failed->id, rsc->migration_threshold - fail_count, node->details->uname);
        }
    }
}

static void
complex_set_cmds(resource_t * rsc)
{
    GListPtr gIter = rsc->children;

    rsc->cmds = &resource_class_alloc_functions[rsc->variant];

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        complex_set_cmds(child_rsc);
    }
}

void
set_alloc_actions(pe_working_set_t * data_set)
{

    GListPtr gIter = data_set->resources;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        complex_set_cmds(rsc);
    }
}

static void
calculate_system_health(gpointer gKey, gpointer gValue, gpointer user_data)
{
    const char *key = (const char *)gKey;
    const char *value = (const char *)gValue;
    int *system_health = (int *)user_data;

    if (!gKey || !gValue || !user_data) {
        return;
    }

    /* Does it start with #health? */
    if (0 == strncmp(key, "#health", 7)) {
        int score;

        /* Convert the value into an integer */
        score = char2score(value);

        /* Add it to the running total */
        *system_health = merge_weights(score, *system_health);
    }
}

static gboolean
apply_system_health(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    const char *health_strategy = pe_pref(data_set->config_hash, "node-health-strategy");

    if (health_strategy == NULL || safe_str_eq(health_strategy, "none")) {
        /* Prevent any accidental health -> score translation */
        node_score_red = 0;
        node_score_yellow = 0;
        node_score_green = 0;
        return TRUE;

    } else if (safe_str_eq(health_strategy, "migrate-on-red")) {

        /* Resources on nodes which have health values of red are
         * weighted away from that node.
         */
        node_score_red = -INFINITY;
        node_score_yellow = 0;
        node_score_green = 0;

    } else if (safe_str_eq(health_strategy, "only-green")) {

        /* Resources on nodes which have health values of red or yellow
         * are forced away from that node.
         */
        node_score_red = -INFINITY;
        node_score_yellow = -INFINITY;
        node_score_green = 0;

    } else if (safe_str_eq(health_strategy, "progressive")) {
        /* Same as the above, but use the r/y/g scores provided by the user
         * Defaults are provided by the pe_prefs table
         */

    } else if (safe_str_eq(health_strategy, "custom")) {

        /* Requires the admin to configure the rsc_location constaints for
         * processing the stored health scores
         */
        /* TODO: Check for the existance of appropriate node health constraints */
        return TRUE;

    } else {
        crm_err("Unknown node health strategy: %s", health_strategy);
        return FALSE;
    }

    crm_info("Applying automated node health strategy: %s", health_strategy);

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        int system_health = 0;
        node_t *node = (node_t *) gIter->data;

        /* Search through the node hash table for system health entries. */
        g_hash_table_foreach(node->details->attrs, calculate_system_health, &system_health);

        crm_info(" Node %s has an combined system health of %d",
                 node->details->uname, system_health);

        /* If the health is non-zero, then create a new rsc2node so that the
         * weight will be added later on.
         */
        if (system_health != 0) {

            GListPtr gIter2 = data_set->resources;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                resource_t *rsc = (resource_t *) gIter2->data;

                rsc2node_new(health_strategy, rsc, system_health, node, data_set);
            }
        }

    }

    return TRUE;
}

gboolean
stage0(pe_working_set_t * data_set)
{
    xmlNode *cib_constraints = get_object_root(XML_CIB_TAG_CONSTRAINTS, data_set->input);

    if (data_set->input == NULL) {
        return FALSE;
    }

    if (is_set(data_set->flags, pe_flag_have_status) == FALSE) {
        crm_trace("Calculating status");
        cluster_status(data_set);
    }

    set_alloc_actions(data_set);
    apply_system_health(data_set);
    unpack_constraints(cib_constraints, data_set);

    return TRUE;
}

static void
wait_for_probe(resource_t * rsc, const char *action, action_t * probe_complete,
               pe_working_set_t * data_set)
{
    if (probe_complete == NULL) {
        return;
    }

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            wait_for_probe(child, action, probe_complete, data_set);
        }

    } else {
        char *key = generate_op_key(rsc->id, action, 0);

        custom_action_order(NULL, NULL, probe_complete, rsc, key, NULL,
                            pe_order_optional, data_set);
    }
}

/*
 * Check nodes for resources started outside of the LRM
 */
gboolean
probe_resources(pe_working_set_t * data_set)
{
    action_t *probe_complete = NULL;
    action_t *probe_node_complete = NULL;

    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *probed = g_hash_table_lookup(node->details->attrs, CRM_OP_PROBED);

        if (node->details->online == FALSE) {
            continue;

        } else if (node->details->unclean) {
            continue;

        } else if (probe_complete == NULL) {
            probe_complete = get_pseudo_op(CRM_OP_PROBED, data_set);
        }

        if (probed != NULL && crm_is_true(probed) == FALSE) {
            action_t *probe_op = custom_action(NULL, crm_strdup(CRM_OP_REPROBE),
                                               CRM_OP_REPROBE, node, FALSE, TRUE, data_set);

            add_hash_param(probe_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
            continue;
        }

        probe_node_complete = custom_action(NULL, crm_strdup(CRM_OP_PROBED),
                                            CRM_OP_PROBED, node, FALSE, TRUE, data_set);
        if (crm_is_true(probed)) {
            crm_trace("unset");
            update_action_flags(probe_node_complete, pe_action_optional);
        } else {
            crm_trace("set");
            update_action_flags(probe_node_complete, pe_action_optional | pe_action_clear);
        }
        crm_trace("%s - %d", node->details->uname, probe_node_complete->flags & pe_action_optional);
        probe_node_complete->priority = INFINITY;
        add_hash_param(probe_node_complete->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);

        if (node->details->pending) {
            update_action_flags(probe_node_complete, pe_action_runnable | pe_action_clear);
            crm_info("Action %s on %s is unrunnable (pending)",
                     probe_node_complete->uuid, probe_node_complete->node->details->uname);
        }

        order_actions(probe_node_complete, probe_complete,
                      pe_order_runnable_left /*|pe_order_implies_then */ );

        gIter2 = data_set->resources;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            resource_t *rsc = (resource_t *) gIter2->data;

            if (rsc->cmds->create_probe(rsc, node, probe_node_complete, FALSE, data_set)) {

                update_action_flags(probe_complete, pe_action_optional | pe_action_clear);
                update_action_flags(probe_node_complete, pe_action_optional | pe_action_clear);

                wait_for_probe(rsc, RSC_START, probe_complete, data_set);
            }
        }
    }

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        wait_for_probe(rsc, RSC_STOP, probe_complete, data_set);
    }

    return TRUE;
}

/*
 * Count how many valid nodes we have (so we know the maximum number of
 *  colors we can resolve).
 *
 * Apply node constraints (ie. filter the "allowed_nodes" part of resources
 */
gboolean
stage2(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    crm_trace("Applying placement constraints");

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        if (node == NULL) {
            /* error */

        } else if (node->weight >= 0.0  /* global weight */
                   && node->details->online && node->details->type == node_member) {
            data_set->max_valid_nodes++;
        }
    }

    apply_placement_constraints(data_set);

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        GListPtr gIter2 = NULL;
        node_t *node = (node_t *) gIter->data;

        gIter2 = data_set->resources;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            resource_t *rsc = (resource_t *) gIter2->data;

            common_apply_stickiness(rsc, node, data_set);
        }
    }

    return TRUE;
}

/*
 * Create internal resource constraints before allocation
 */
gboolean
stage3(pe_working_set_t * data_set)
{

    GListPtr gIter = data_set->resources;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        rsc->cmds->internal_constraints(rsc, data_set);
    }

    return TRUE;
}

/*
 * Check for orphaned or redefined actions
 */
gboolean
stage4(pe_working_set_t * data_set)
{
    check_actions(data_set);
    return TRUE;
}

static gint
sort_rsc_process_order(gconstpointer a, gconstpointer b, gpointer data)
{
    int rc = 0;
    int r1_weight = -INFINITY;
    int r2_weight = -INFINITY;

    const char *reason = "existance";

    const GListPtr nodes = (GListPtr) data;
    resource_t *resource1 = (resource_t *) convert_const_pointer(a);
    resource_t *resource2 = (resource_t *) convert_const_pointer(b);

    node_t *node = NULL;
    GListPtr gIter = NULL;
    GHashTable *r1_nodes = NULL;
    GHashTable *r2_nodes = NULL;

    if (a == NULL && b == NULL) {
        goto done;
    }
    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    reason = "priority";
    r1_weight = resource1->priority;
    r2_weight = resource2->priority;

    if (r1_weight > r2_weight) {
        rc = -1;
        goto done;
    }

    if (r1_weight < r2_weight) {
        rc = 1;
        goto done;
    }

    reason = "no node list";
    if (nodes == NULL) {
        goto done;
    }

    r1_nodes =
        rsc_merge_weights(resource1, resource1->id, NULL, NULL, 1,
                          pe_weights_forward | pe_weights_init);
    dump_node_scores(LOG_TRACE, NULL, resource1->id, r1_nodes);
    r2_nodes =
        rsc_merge_weights(resource2, resource2->id, NULL, NULL, 1,
                          pe_weights_forward | pe_weights_init);
    dump_node_scores(LOG_TRACE, NULL, resource2->id, r2_nodes);

    /* Current location score */
    reason = "current location";
    r1_weight = -INFINITY;
    r2_weight = -INFINITY;

    if (resource1->running_on) {
        node = g_list_nth_data(resource1->running_on, 0);
        node = g_hash_table_lookup(r1_nodes, node->details->id);
        r1_weight = node->weight;
    }
    if (resource2->running_on) {
        node = g_list_nth_data(resource2->running_on, 0);
        node = g_hash_table_lookup(r2_nodes, node->details->id);
        r2_weight = node->weight;
    }

    if (r1_weight > r2_weight) {
        rc = -1;
        goto done;
    }

    if (r1_weight < r2_weight) {
        rc = 1;
        goto done;
    }

    reason = "score";
    for (gIter = nodes; gIter != NULL; gIter = gIter->next) {
        node_t *r1_node = NULL;
        node_t *r2_node = NULL;

        node = (node_t *) gIter->data;

        r1_weight = -INFINITY;
        if (r1_nodes) {
            r1_node = g_hash_table_lookup(r1_nodes, node->details->id);
        }
        if (r1_node) {
            r1_weight = r1_node->weight;
        }

        r2_weight = -INFINITY;
        if (r2_nodes) {
            r2_node = g_hash_table_lookup(r2_nodes, node->details->id);
        }
        if (r2_node) {
            r2_weight = r2_node->weight;
        }

        if (r1_weight > r2_weight) {
            rc = -1;
            goto done;
        }

        if (r1_weight < r2_weight) {
            rc = 1;
            goto done;
        }
    }

  done:
    if (r1_nodes) {
        g_hash_table_destroy(r1_nodes);
    }
    if (r2_nodes) {
        g_hash_table_destroy(r2_nodes);
    }

    crm_trace( "%s (%d) %c %s (%d) on %s: %s",
                        resource1->id, r1_weight, rc < 0 ? '>' : rc > 0 ? '<' : '=',
                        resource2->id, r2_weight, node ? node->details->id : "n/a", reason);
    return rc;
}

gboolean
stage5(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    if (safe_str_neq(data_set->placement_strategy, "default")) {
        GListPtr nodes = g_list_copy(data_set->nodes);

        nodes = g_list_sort_with_data(nodes, sort_node_weight, NULL);

        data_set->resources =
            g_list_sort_with_data(data_set->resources, sort_rsc_process_order, nodes);

        g_list_free(nodes);
    }

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        dump_node_capacity(show_utilization ? 0 : utilization_log_level, "Original", node);
    }

    crm_trace("Allocating services");
    /* Take (next) highest resource, assign it and create its actions */

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        crm_trace("Allocating: %s", rsc->id);
        rsc->cmds->allocate(rsc, NULL, data_set);
    }

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        dump_node_capacity(show_utilization ? 0 : utilization_log_level, "Remaining", node);
    }

    if (is_set(data_set->flags, pe_flag_startup_probes)) {
        crm_trace("Calculating needed probes");
        /* This code probably needs optimization
         * ptest -x with 100 nodes, 100 clones and clone-max=100:

         With probes:

         ptest[14781]: 2010/09/27_17:56:46 notice: TRACE: do_calculations: pengine.c:258 Calculate cluster status
         ptest[14781]: 2010/09/27_17:56:46 notice: TRACE: do_calculations: pengine.c:278 Applying placement constraints
         ptest[14781]: 2010/09/27_17:56:47 notice: TRACE: do_calculations: pengine.c:285 Create internal constraints
         ptest[14781]: 2010/09/27_17:56:47 notice: TRACE: do_calculations: pengine.c:292 Check actions
         ptest[14781]: 2010/09/27_17:56:48 notice: TRACE: do_calculations: pengine.c:299 Allocate resources
         ptest[14781]: 2010/09/27_17:56:48 notice: TRACE: stage5: allocate.c:881 Allocating services
         ptest[14781]: 2010/09/27_17:56:49 notice: TRACE: stage5: allocate.c:894 Calculating needed probes
         ptest[14781]: 2010/09/27_17:56:51 notice: TRACE: stage5: allocate.c:899 Creating actions
         ptest[14781]: 2010/09/27_17:56:52 notice: TRACE: stage5: allocate.c:905 Creating done
         ptest[14781]: 2010/09/27_17:56:52 notice: TRACE: do_calculations: pengine.c:306 Processing fencing and shutdown cases
         ptest[14781]: 2010/09/27_17:56:52 notice: TRACE: do_calculations: pengine.c:313 Applying ordering constraints
         36s
         ptest[14781]: 2010/09/27_17:57:28 notice: TRACE: do_calculations: pengine.c:320 Create transition graph

         Without probes:

         ptest[14637]: 2010/09/27_17:56:21 notice: TRACE: do_calculations: pengine.c:258 Calculate cluster status
         ptest[14637]: 2010/09/27_17:56:22 notice: TRACE: do_calculations: pengine.c:278 Applying placement constraints
         ptest[14637]: 2010/09/27_17:56:22 notice: TRACE: do_calculations: pengine.c:285 Create internal constraints
         ptest[14637]: 2010/09/27_17:56:22 notice: TRACE: do_calculations: pengine.c:292 Check actions
         ptest[14637]: 2010/09/27_17:56:23 notice: TRACE: do_calculations: pengine.c:299 Allocate resources
         ptest[14637]: 2010/09/27_17:56:23 notice: TRACE: stage5: allocate.c:881 Allocating services
         ptest[14637]: 2010/09/27_17:56:24 notice: TRACE: stage5: allocate.c:899 Creating actions
         ptest[14637]: 2010/09/27_17:56:25 notice: TRACE: stage5: allocate.c:905 Creating done
         ptest[14637]: 2010/09/27_17:56:25 notice: TRACE: do_calculations: pengine.c:306 Processing fencing and shutdown cases
         ptest[14637]: 2010/09/27_17:56:25 notice: TRACE: do_calculations: pengine.c:313 Applying ordering constraints
         ptest[14637]: 2010/09/27_17:56:25 notice: TRACE: do_calculations: pengine.c:320 Create transition graph
         */

        probe_resources(data_set);
    }

    crm_trace("Creating actions");

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        rsc->cmds->create_actions(rsc, data_set);
    }

    crm_trace("Creating done");
    return TRUE;
}

static gboolean
is_managed(const resource_t * rsc)
{
    GListPtr gIter = rsc->children;

    if (is_set(rsc->flags, pe_rsc_managed)) {
        return TRUE;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        if (is_managed(child_rsc)) {
            return TRUE;
        }
    }

    return FALSE;
}

static gboolean
any_managed_resouces(pe_working_set_t * data_set)
{

    GListPtr gIter = data_set->resources;

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        if (is_managed(rsc)) {
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * Create dependancies for stonith and shutdown operations
 */
gboolean
stage6(pe_working_set_t * data_set)
{
    action_t *dc_down = NULL;
    action_t *dc_fence = NULL;
    action_t *stonith_op = NULL;
    action_t *last_stonith = NULL;
    gboolean integrity_lost = FALSE;
    action_t *ready = get_pseudo_op(STONITH_UP, data_set);
    action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);
    action_t *done = get_pseudo_op(STONITH_DONE, data_set);
    gboolean need_stonith = FALSE;
    GListPtr gIter = data_set->nodes;

    crm_trace("Processing fencing and shutdown cases");

    if (is_set(data_set->flags, pe_flag_stonith_enabled)
        && (is_set(data_set->flags, pe_flag_have_quorum)
            || data_set->no_quorum_policy == no_quorum_ignore
            || data_set->no_quorum_policy == no_quorum_suicide)) {
        need_stonith = TRUE;
    }

    if (need_stonith && any_managed_resouces(data_set) == FALSE) {
        crm_notice("Delaying fencing operations until there are resources to manage");
        need_stonith = FALSE;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        stonith_op = NULL;
        if (node->details->unclean && need_stonith) {
            pe_warn("Scheduling Node %s for STONITH", node->details->uname);

            stonith_op = custom_action(NULL, crm_strdup(CRM_OP_FENCE),
                                       CRM_OP_FENCE, node, FALSE, TRUE, data_set);

            add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET, node->details->uname);

            add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET_UUID, node->details->id);

            add_hash_param(stonith_op->meta, "stonith_action", data_set->stonith_action);

            stonith_constraints(node, stonith_op, data_set);
            order_actions(ready, stonith_op, pe_order_runnable_left);
            order_actions(stonith_op, all_stopped, pe_order_implies_then);

            clear_bit_inplace(ready->flags, pe_action_optional);

            if (node->details->is_dc) {
                dc_down = stonith_op;
                dc_fence = stonith_op;

            } else {
                if (last_stonith) {
                    order_actions(last_stonith, stonith_op, pe_order_optional);
                }
                last_stonith = stonith_op;
            }

        } else if (node->details->online && node->details->shutdown) {
            action_t *down_op = NULL;

            crm_notice("Scheduling Node %s for shutdown", node->details->uname);

            down_op = custom_action(NULL, crm_strdup(CRM_OP_SHUTDOWN),
                                    CRM_OP_SHUTDOWN, node, FALSE, TRUE, data_set);

            shutdown_constraints(node, down_op, data_set);
            add_hash_param(down_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);

            if (node->details->is_dc) {
                dc_down = down_op;
            }
        }

        if (node->details->unclean && stonith_op == NULL) {
            integrity_lost = TRUE;
            pe_warn("Node %s is unclean!", node->details->uname);
        }
    }

    if (integrity_lost) {
        if (is_set(data_set->flags, pe_flag_stonith_enabled) == FALSE) {
            pe_warn("YOUR RESOURCES ARE NOW LIKELY COMPROMISED");
            pe_err("ENABLE STONITH TO KEEP YOUR RESOURCES SAFE");

        } else if (is_set(data_set->flags, pe_flag_have_quorum) == FALSE) {
            crm_notice("Cannot fence unclean nodes until quorum is"
                       " attained (or no-quorum-policy is set to ignore)");
        }
    }

    if (dc_down != NULL) {
        GListPtr shutdown_matches = find_actions(data_set->actions, CRM_OP_SHUTDOWN, NULL);

        crm_trace("Ordering shutdowns before %s on %s (DC)",
                    dc_down->task, dc_down->node->details->uname);

        add_hash_param(dc_down->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);

        gIter = shutdown_matches;
        for (; gIter != NULL; gIter = gIter->next) {
            action_t *node_stop = (action_t *) gIter->data;

            if (node_stop->node->details->is_dc) {
                continue;
            }
            crm_debug("Ordering shutdown on %s before %s on %s",
                      node_stop->node->details->uname,
                      dc_down->task, dc_down->node->details->uname);

            order_actions(node_stop, dc_down, pe_order_optional);
        }

        if (last_stonith && dc_down != last_stonith) {
            order_actions(last_stonith, dc_down, pe_order_optional);
        }
        g_list_free(shutdown_matches);
    }

    if (last_stonith) {
        order_actions(last_stonith, done, pe_order_implies_then);

    } else if (dc_fence) {
        order_actions(dc_down, done, pe_order_implies_then);
    }
    order_actions(ready, done, pe_order_optional);
    return TRUE;
}

/*
 * Determin the sets of independant actions and the correct order for the
 *  actions in each set.
 *
 * Mark dependencies of un-runnable actions un-runnable
 *
 */
static GListPtr
find_actions_by_task(GListPtr actions, resource_t * rsc, const char *original_key)
{
    GListPtr list = NULL;

    list = find_actions(actions, original_key, NULL);
    if (list == NULL) {
        /* we're potentially searching a child of the original resource */
        char *key = NULL;
        char *tmp = NULL;
        char *task = NULL;
        int interval = 0;

        if (parse_op_key(original_key, &tmp, &task, &interval)) {
            key = generate_op_key(rsc->id, task, interval);
            /* crm_err("looking up %s instead of %s", key, original_key); */
            /* slist_iter(action, action_t, actions, lpc, */
            /*         crm_err("  - %s", action->uuid)); */
            list = find_actions(actions, key, NULL);

        } else {
            crm_err("search key: %s", original_key);
        }

        crm_free(key);
        crm_free(tmp);
        crm_free(task);
    }

    return list;
}

static void
rsc_order_then(action_t * lh_action, resource_t * rsc, order_constraint_t * order)
{
    GListPtr gIter = NULL;
    GListPtr rh_actions = NULL;
    action_t *rh_action = NULL;
    enum pe_ordering type = order->type;

    CRM_CHECK(rsc != NULL, return);
    CRM_CHECK(order != NULL, return);

    rh_action = order->rh_action;
    crm_trace("Processing RH of ordering constraint %d", order->id);

    if (rh_action != NULL) {
        rh_actions = g_list_prepend(NULL, rh_action);

    } else if (rsc != NULL) {
        rh_actions = find_actions_by_task(rsc->actions, rsc, order->rh_action_task);
    }

    if (rh_actions == NULL) {
        crm_trace("No RH-Side (%s/%s) found for constraint..."
                    " ignoring", rsc->id, order->rh_action_task);
        if (lh_action) {
            crm_trace("LH-Side was: %s", lh_action->uuid);
        }
        return;
    }

    if (lh_action && lh_action->rsc == rsc && is_set(lh_action->flags, pe_action_dangle)) {
        crm_trace("Detected dangling operation %s -> %s", lh_action->uuid, order->rh_action_task);
        clear_bit_inplace(type, pe_order_implies_then);
    }

    gIter = rh_actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *rh_action_iter = (action_t *) gIter->data;

        if (lh_action) {
            order_actions(lh_action, rh_action_iter, type);

        } else if (type & pe_order_implies_then) {
            update_action_flags(rh_action_iter, pe_action_runnable | pe_action_clear);
            crm_warn("Unrunnable %s 0x%.6x", rh_action_iter->uuid, type);
        } else {
            crm_warn("neither %s 0x%.6x", rh_action_iter->uuid, type);
        }
    }

    g_list_free(rh_actions);
}

static void
rsc_order_first(resource_t * lh_rsc, order_constraint_t * order, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    GListPtr lh_actions = NULL;
    action_t *lh_action = order->lh_action;
    resource_t *rh_rsc = order->rh_rsc;

    crm_trace("Processing LH of ordering constraint %d", order->id);
    CRM_ASSERT(lh_rsc != NULL);

    if (lh_action != NULL) {
        lh_actions = g_list_prepend(NULL, lh_action);

    } else if (lh_action == NULL) {
        lh_actions = find_actions_by_task(lh_rsc->actions, lh_rsc, order->lh_action_task);
    }

    if (lh_actions == NULL && lh_rsc != rh_rsc) {
        char *key = NULL;
        char *rsc_id = NULL;
        char *op_type = NULL;
        int interval = 0;

        parse_op_key(order->lh_action_task, &rsc_id, &op_type, &interval);
        key = generate_op_key(lh_rsc->id, op_type, interval);

        if (lh_rsc->fns->state(lh_rsc, TRUE) != RSC_ROLE_STOPPED || safe_str_neq(op_type, RSC_STOP)) {
            crm_trace("No LH-Side (%s/%s) found for constraint %d with %s - creating",
                        lh_rsc->id, order->lh_action_task, order->id, order->rh_action_task);
            lh_action = custom_action(lh_rsc, key, op_type, NULL, TRUE, TRUE, data_set);
            lh_actions = g_list_prepend(NULL, lh_action);
        } else {
            crm_free(key);
            crm_trace("No LH-Side (%s/%s) found for constraint %d with %s - ignoring",
                        lh_rsc->id, order->lh_action_task, order->id, order->rh_action_task);
        }

        crm_free(op_type);
        crm_free(rsc_id);
    }

    gIter = lh_actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *lh_action_iter = (action_t *) gIter->data;

        if (rh_rsc == NULL && order->rh_action) {
            rh_rsc = order->rh_action->rsc;
        }
        if (rh_rsc) {
            rsc_order_then(lh_action_iter, rh_rsc, order);

        } else if (order->rh_action) {
            order_actions(lh_action_iter, order->rh_action, order->type);
        }
    }

    g_list_free(lh_actions);
}

extern gboolean update_action(action_t * action);

static int
handle_non_symmetrical_order(order_constraint_t *order)
{
    resource_t *lh_rsc = order->lh_rsc;
    resource_t *rh_rsc = order->rh_rsc;
    enum rsc_role_e lh_rsc_role_next;
    enum rsc_role_e rh_rsc_role;
    char *op_type = NULL;
    char *rsc_id = NULL;
    int interval = 0;
    int res = 0;

    if (!lh_rsc || !rh_rsc) {
        return res;
    }

    lh_rsc_role_next = lh_rsc->fns->state(lh_rsc, FALSE);
    rh_rsc_role = rh_rsc->fns->state(lh_rsc, TRUE);
    parse_op_key(order->lh_action_task, &rsc_id, &op_type, &interval);

    if (safe_str_eq(op_type, RSC_STOP) && (rh_rsc_role == RSC_ROLE_STOPPED) && (lh_rsc_role_next == RSC_ROLE_STARTED)) {
        res = 1;
    } else if (safe_str_eq(op_type, RSC_START) && (rh_rsc_role == RSC_ROLE_STARTED) && (lh_rsc_role_next == RSC_ROLE_STOPPED)) {
        res = 1;
    }

    crm_free(op_type);
    return res;
}

gboolean
stage7(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    crm_trace("Applying ordering constraints");

    /* Don't ask me why, but apparently they need to be processed in
     * the order they were created in... go figure
     *
     * Also g_list_prepend() has horrendous performance characteristics
     * So we need to use g_list_prepend() and then reverse the list here
     */
    data_set->ordering_constraints = g_list_reverse(data_set->ordering_constraints);

    gIter = data_set->ordering_constraints;
    for (; gIter != NULL; gIter = gIter->next) {
        order_constraint_t *order = (order_constraint_t *) gIter->data;
        resource_t *rsc = order->lh_rsc;

        crm_trace("Applying ordering constraint: %d", order->id);

        if ((order->type & pe_order_non_symmetrical) && handle_non_symmetrical_order(order)) {
            crm_trace("Skipping non-symmetrical order constraint: %d", order->id);
            continue;
        }

        if (rsc != NULL) {
            crm_trace("rsc_action-to-*");
            rsc_order_first(rsc, order, data_set);
            continue;
        }

        rsc = order->rh_rsc;
        if (rsc != NULL) {
            crm_trace("action-to-rsc_action");
            rsc_order_then(order->lh_action, rsc, order);

        } else {
            crm_trace("action-to-action");
            order_actions(order->lh_action, order->rh_action, order->type);
        }
    }

    crm_trace("Updating %d actions", g_list_length(data_set->actions));

    gIter = data_set->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        update_action(action);
    }

    crm_trace("Processing migrations");

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        rsc_migrate_reload(rsc, data_set);
        LogActions(rsc, data_set);
    }

    return TRUE;
}

static gint
sort_notify_entries(gconstpointer a, gconstpointer b)
{
    int tmp;
    const notify_entry_t *entry_a = a;
    const notify_entry_t *entry_b = b;

    if (entry_a == NULL && entry_b == NULL) {
        return 0;
    }
    if (entry_a == NULL) {
        return 1;
    }
    if (entry_b == NULL) {
        return -1;
    }

    if (entry_a->rsc == NULL && entry_b->rsc == NULL) {
        return 0;
    }
    if (entry_a->rsc == NULL) {
        return 1;
    }
    if (entry_b->rsc == NULL) {
        return -1;
    }

    tmp = strcmp(entry_a->rsc->id, entry_b->rsc->id);
    if (tmp != 0) {
        return tmp;
    }

    if (entry_a->node == NULL && entry_b->node == NULL) {
        return 0;
    }
    if (entry_a->node == NULL) {
        return 1;
    }
    if (entry_b->node == NULL) {
        return -1;
    }

    return strcmp(entry_a->node->details->id, entry_b->node->details->id);
}

static void
expand_list(GListPtr list, char **rsc_list, char **node_list)
{
    GListPtr gIter = list;
    const char *uname = NULL;
    const char *rsc_id = NULL;
    const char *last_rsc_id = NULL;

    if (rsc_list) {
        *rsc_list = NULL;
    }

    if (list == NULL) {
        if (rsc_list) {
            *rsc_list = crm_strdup(" ");
        }
        if (node_list) {
            *node_list = crm_strdup(" ");
        }
        return;
    }

    if (node_list) {
        *node_list = NULL;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        notify_entry_t *entry = (notify_entry_t *) gIter->data;

        CRM_CHECK(entry != NULL, continue);
        CRM_CHECK(entry->rsc != NULL, continue);
        CRM_CHECK(node_list == NULL || entry->node != NULL, continue);

        uname = NULL;
        rsc_id = entry->rsc->id;
        CRM_ASSERT(rsc_id != NULL);

        /* filter dups */
        if (safe_str_eq(rsc_id, last_rsc_id)) {
            continue;
        }
        last_rsc_id = rsc_id;

        if (rsc_list != NULL) {
            int existing_len = 0;
            int len = 2 + strlen(rsc_id);       /* +1 space, +1 EOS */

            if (rsc_list && *rsc_list) {
                existing_len = strlen(*rsc_list);
            }

            crm_trace("Adding %s (%dc) at offset %d", rsc_id, len - 2, existing_len);
            crm_realloc(*rsc_list, len + existing_len);
            sprintf(*rsc_list + existing_len, "%s ", rsc_id);
        }

        if (entry->node != NULL) {
            uname = entry->node->details->uname;
        }

        if (node_list != NULL && uname) {
            int existing_len = 0;
            int len = 2 + strlen(uname);

            if (node_list && *node_list) {
                existing_len = strlen(*node_list);
            }

            crm_trace("Adding %s (%dc) at offset %d", uname, len - 2, existing_len);
            crm_realloc(*node_list, len + existing_len);
            sprintf(*node_list + existing_len, "%s ", uname);
        }
    }

}

static void
dup_attr(gpointer key, gpointer value, gpointer user_data)
{
    add_hash_param(user_data, key, value);
}

static action_t *
pe_notify(resource_t * rsc, node_t * node, action_t * op, action_t * confirm,
          notify_data_t * n_data, pe_working_set_t * data_set)
{
    char *key = NULL;
    action_t *trigger = NULL;
    const char *value = NULL;
    const char *task = NULL;

    if (op == NULL || confirm == NULL) {
        crm_trace("Op=%p confirm=%p", op, confirm);
        return NULL;
    }

    CRM_CHECK(node != NULL, return NULL);

    if (node->details->online == FALSE) {
        crm_trace("Skipping notification for %s: node offline", rsc->id);
        return NULL;
    } else if (is_set(op->flags, pe_action_runnable) == FALSE) {
        crm_trace("Skipping notification for %s: not runnable", op->uuid);
        return NULL;
    }

    value = g_hash_table_lookup(op->meta, "notify_type");
    task = g_hash_table_lookup(op->meta, "notify_operation");

    crm_trace("Creating notify actions for %s: %s (%s-%s)", op->uuid, rsc->id, value, task);

    key = generate_notify_key(rsc->id, value, task);
    trigger = custom_action(rsc, key, op->task, node,
                            is_set(op->flags, pe_action_optional), TRUE, data_set);
    g_hash_table_foreach(op->meta, dup_attr, trigger->meta);
    g_hash_table_foreach(n_data->keys, dup_attr, trigger->meta);

    /* pseudo_notify before notify */
    crm_trace("Ordering %s before %s (%d->%d)", op->uuid, trigger->uuid, trigger->id, op->id);

    order_actions(op, trigger, pe_order_optional);
    order_actions(trigger, confirm, pe_order_optional);
    return trigger;
}

static void
pe_post_notify(resource_t * rsc, node_t * node, notify_data_t * n_data, pe_working_set_t * data_set)
{
    action_t *notify = NULL;

    CRM_CHECK(rsc != NULL, return);

    if (n_data->post == NULL) {
        return;                 /* Nothing to do */
    }

    notify = pe_notify(rsc, node, n_data->post, n_data->post_done, n_data, data_set);

    if (notify != NULL) {
        notify->priority = INFINITY;
    }

    if (n_data->post_done) {
        GListPtr gIter = rsc->actions;

        for (; gIter != NULL; gIter = gIter->next) {
            action_t *mon = (action_t *) gIter->data;
            const char *interval = g_hash_table_lookup(mon->meta, "interval");

            if (interval == NULL || safe_str_eq(interval, "0")) {
                crm_trace("Skipping %s: interval", mon->uuid);
                continue;
            } else if (safe_str_eq(mon->task, "cancel")) {
                crm_trace("Skipping %s: cancel", mon->uuid);
                continue;
            }

            order_actions(n_data->post_done, mon, pe_order_optional);
        }
    }
}

notify_data_t *
create_notification_boundaries(resource_t * rsc, const char *action, action_t * start,
                               action_t * end, pe_working_set_t * data_set)
{
    /* Create the pseudo ops that preceed and follow the actual notifications */

    /*
     * Creates two sequences (conditional on start and end being supplied):
     *   pre_notify -> pre_notify_complete -> start, and
     *   end -> post_notify -> post_notify_complete
     *
     * 'start' and 'end' may be the same event or ${X} and ${X}ed as per clones
     */
    char *key = NULL;
    notify_data_t *n_data = NULL;

    if (is_not_set(rsc->flags, pe_rsc_notify)) {
        return NULL;
    }

    crm_malloc0(n_data, sizeof(notify_data_t));
    n_data->action = action;
    n_data->keys =
        g_hash_table_new_full(crm_str_hash, g_str_equal, g_hash_destroy_str, g_hash_destroy_str);

    if (start) {
        /* create pre-event notification wrappers */
        key = generate_notify_key(rsc->id, "pre", start->task);
        n_data->pre =
            custom_action(rsc, key, RSC_NOTIFY, NULL, is_set(start->flags, pe_action_optional),
                          TRUE, data_set);

        update_action_flags(n_data->pre, pe_action_pseudo);
        update_action_flags(n_data->pre, pe_action_runnable);
        add_hash_param(n_data->pre->meta, "notify_type", "pre");
        add_hash_param(n_data->pre->meta, "notify_operation", n_data->action);

        /* create pre_notify_complete */
        key = generate_notify_key(rsc->id, "confirmed-pre", start->task);
        n_data->pre_done =
            custom_action(rsc, key, RSC_NOTIFIED, NULL, is_set(start->flags, pe_action_optional),
                          TRUE, data_set);

        update_action_flags(n_data->pre_done, pe_action_pseudo);
        update_action_flags(n_data->pre_done, pe_action_runnable);
        add_hash_param(n_data->pre_done->meta, "notify_type", "pre");
        add_hash_param(n_data->pre_done->meta, "notify_operation", n_data->action);

        order_actions(n_data->pre_done, start, pe_order_optional);
        order_actions(n_data->pre, n_data->pre_done, pe_order_optional);
    }

    if (end) {
        /* create post-event notification wrappers */
        key = generate_notify_key(rsc->id, "post", end->task);
        n_data->post =
            custom_action(rsc, key, RSC_NOTIFY, NULL, is_set(end->flags, pe_action_optional), TRUE,
                          data_set);

        n_data->post->priority = INFINITY;
        update_action_flags(n_data->post, pe_action_pseudo);
        if (is_set(end->flags, pe_action_runnable)) {
            update_action_flags(n_data->post, pe_action_runnable);
        } else {
            update_action_flags(n_data->post, pe_action_runnable | pe_action_clear);
        }

        add_hash_param(n_data->post->meta, "notify_type", "post");
        add_hash_param(n_data->post->meta, "notify_operation", n_data->action);

        /* create post_notify_complete */
        key = generate_notify_key(rsc->id, "confirmed-post", end->task);
        n_data->post_done =
            custom_action(rsc, key, RSC_NOTIFIED, NULL, is_set(end->flags, pe_action_optional),
                          TRUE, data_set);

        n_data->post_done->priority = INFINITY;
        update_action_flags(n_data->post_done, pe_action_pseudo);
        if (is_set(end->flags, pe_action_runnable)) {
            update_action_flags(n_data->post_done, pe_action_runnable);
        } else {
            update_action_flags(n_data->post_done, pe_action_runnable | pe_action_clear);
        }

        add_hash_param(n_data->post_done->meta, "notify_type", "pre");
        add_hash_param(n_data->post_done->meta, "notify_operation", n_data->action);

        order_actions(end, n_data->post, pe_order_implies_then);
        order_actions(n_data->post, n_data->post_done, pe_order_implies_then);
    }

    if (start && end) {
        order_actions(n_data->pre_done, n_data->post, pe_order_optional);
    }

    if (safe_str_eq(action, RSC_STOP)) {
        action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);

        order_actions(n_data->post_done, all_stopped, pe_order_optional);
    }

    return n_data;
}

void
collect_notification_data(resource_t * rsc, gboolean state, gboolean activity,
                          notify_data_t * n_data)
{

    if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            collect_notification_data(child, state, activity, n_data);
        }
        return;
    }

    if (state) {
        notify_entry_t *entry = NULL;

        crm_malloc0(entry, sizeof(notify_entry_t));
        entry->rsc = rsc;
        if (rsc->running_on) {
            /* we only take the first one */
            entry->node = rsc->running_on->data;
        }

        crm_trace("%s state: %s", rsc->id, role2text(rsc->role));

        switch (rsc->role) {
            case RSC_ROLE_STOPPED:
                n_data->inactive = g_list_prepend(n_data->inactive, entry);
                break;
            case RSC_ROLE_STARTED:
                n_data->active = g_list_prepend(n_data->active, entry);
                break;
            case RSC_ROLE_SLAVE:
                n_data->slave = g_list_prepend(n_data->slave, entry);
                break;
            case RSC_ROLE_MASTER:
                n_data->master = g_list_prepend(n_data->master, entry);
                break;
            default:
                crm_err("Unsupported notify role");
                crm_free(entry);
                break;
        }
    }

    if (activity) {
        notify_entry_t *entry = NULL;
        enum action_tasks task;

        GListPtr gIter = rsc->actions;

        for (; gIter != NULL; gIter = gIter->next) {
            action_t *op = (action_t *) gIter->data;

            if (is_set(op->flags, pe_action_optional) == FALSE && op->node != NULL) {

                crm_malloc0(entry, sizeof(notify_entry_t));
                entry->node = op->node;
                entry->rsc = rsc;

                task = text2task(op->task);
                switch (task) {
                    case start_rsc:
                        n_data->start = g_list_prepend(n_data->start, entry);
                        break;
                    case stop_rsc:
                        n_data->stop = g_list_prepend(n_data->stop, entry);
                        break;
                    case action_promote:
                        n_data->promote = g_list_prepend(n_data->promote, entry);
                        break;
                    case action_demote:
                        n_data->demote = g_list_prepend(n_data->demote, entry);
                        break;
                    default:
                        crm_free(entry);
                        break;
                }
            }
        }
    }
}

gboolean
expand_notification_data(notify_data_t * n_data)
{
    /* Expand the notification entries into a key=value hashtable
     * This hashtable is later used in action2xml()
     */
    gboolean required = FALSE;
    char *rsc_list = NULL;
    char *node_list = NULL;

    if (n_data->stop) {
        n_data->stop = g_list_sort(n_data->stop, sort_notify_entries);
    }
    expand_list(n_data->stop, &rsc_list, &node_list);
    if (rsc_list != NULL && safe_str_neq(" ", rsc_list)) {
        if (safe_str_eq(n_data->action, RSC_STOP)) {
            required = TRUE;
        }
    }
    g_hash_table_insert(n_data->keys, crm_strdup("notify_stop_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_stop_uname"), node_list);

    if (n_data->start) {
        n_data->start = g_list_sort(n_data->start, sort_notify_entries);
        if (rsc_list && safe_str_eq(n_data->action, RSC_START)) {
            required = TRUE;
        }
    }
    expand_list(n_data->start, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_start_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_start_uname"), node_list);

    if (n_data->demote) {
        n_data->demote = g_list_sort(n_data->demote, sort_notify_entries);
        if (safe_str_eq(n_data->action, RSC_DEMOTE)) {
            required = TRUE;
        }
    }

    expand_list(n_data->demote, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_demote_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_demote_uname"), node_list);

    if (n_data->promote) {
        n_data->promote = g_list_sort(n_data->promote, sort_notify_entries);
        if (safe_str_eq(n_data->action, RSC_PROMOTE)) {
            required = TRUE;
        }
    }
    expand_list(n_data->promote, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_promote_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_promote_uname"), node_list);

    if (n_data->active) {
        n_data->active = g_list_sort(n_data->active, sort_notify_entries);
    }
    expand_list(n_data->active, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_active_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_active_uname"), node_list);

    if (n_data->slave) {
        n_data->slave = g_list_sort(n_data->slave, sort_notify_entries);
    }
    expand_list(n_data->slave, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_slave_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_slave_uname"), node_list);

    if (n_data->master) {
        n_data->master = g_list_sort(n_data->master, sort_notify_entries);
    }
    expand_list(n_data->master, &rsc_list, &node_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_master_resource"), rsc_list);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_master_uname"), node_list);

    if (n_data->inactive) {
        n_data->inactive = g_list_sort(n_data->inactive, sort_notify_entries);
    }
    expand_list(n_data->inactive, &rsc_list, NULL);
    g_hash_table_insert(n_data->keys, crm_strdup("notify_inactive_resource"), rsc_list);

    if (required && n_data->pre) {
        update_action_flags(n_data->pre, pe_action_optional | pe_action_clear);
        update_action_flags(n_data->pre_done, pe_action_optional | pe_action_clear);
    }

    if (required && n_data->post) {
        update_action_flags(n_data->post, pe_action_optional | pe_action_clear);
        update_action_flags(n_data->post_done, pe_action_optional | pe_action_clear);
    }
    return required;
}

void
create_notifications(resource_t * rsc, notify_data_t * n_data, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    action_t *stop = NULL;
    action_t *start = NULL;
    enum action_tasks task = text2task(n_data->action);

    if (rsc->children) {
        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            create_notifications(child, n_data, data_set);
        }
        return;
    }

    /* Copy notification details into standard ops */

    gIter = rsc->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *op = (action_t *) gIter->data;

        if (is_set(op->flags, pe_action_optional) == FALSE && op->node != NULL) {
            enum action_tasks t = text2task(op->task);

            switch (t) {
                case start_rsc:
                case stop_rsc:
                case action_promote:
                case action_demote:
                    g_hash_table_foreach(n_data->keys, dup_attr, op->meta);
                    break;
                default:
                    break;
            }
        }
    }

    crm_trace("Creating notificaitons for: %s.%s (%s->%s)",
                n_data->action, rsc->id, role2text(rsc->role), role2text(rsc->next_role));

    stop = find_first_action(rsc->actions, NULL, RSC_STOP, NULL);
    start = find_first_action(rsc->actions, NULL, RSC_START, NULL);

    /* stop / demote */
    if (rsc->role != RSC_ROLE_STOPPED) {
        if (task == stop_rsc || task == action_demote) {
            gIter = rsc->running_on;
            for (; gIter != NULL; gIter = gIter->next) {
                node_t *current_node = (node_t *) gIter->data;

                pe_notify(rsc, current_node, n_data->pre, n_data->pre_done, n_data, data_set);
                if (task == action_demote || stop == NULL
                    || is_set(stop->flags, pe_action_optional)) {
                    pe_post_notify(rsc, current_node, n_data, data_set);
                }
            }
        }
    }

    /* start / promote */
    if (rsc->next_role != RSC_ROLE_STOPPED) {
        if (rsc->allocated_to == NULL) {
            pe_proc_err("Next role '%s' but %s is not allocated", role2text(rsc->next_role),
                        rsc->id);

        } else if (task == start_rsc || task == action_promote) {
            if (task != start_rsc || start == NULL || is_set(start->flags, pe_action_optional)) {
                pe_notify(rsc, rsc->allocated_to, n_data->pre, n_data->pre_done, n_data, data_set);
            }
            pe_post_notify(rsc, rsc->allocated_to, n_data, data_set);
        }
    }
}

void
free_notification_data(notify_data_t * n_data)
{
    if (n_data == NULL) {
        return;
    }

    slist_basic_destroy(n_data->stop);
    slist_basic_destroy(n_data->start);
    slist_basic_destroy(n_data->demote);
    slist_basic_destroy(n_data->promote);
    slist_basic_destroy(n_data->master);
    slist_basic_destroy(n_data->slave);
    slist_basic_destroy(n_data->active);
    slist_basic_destroy(n_data->inactive);
    g_hash_table_destroy(n_data->keys);
    crm_free(n_data);
}

int transition_id = -1;

/*
 * Create a dependency graph to send to the transitioner (via the CRMd)
 */
gboolean
stage8(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;
    const char *value = NULL;

    transition_id++;
    crm_trace("Creating transition graph %d.", transition_id);

    data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);

    value = pe_pref(data_set->config_hash, "cluster-delay");
    crm_xml_add(data_set->graph, "cluster-delay", value);

    value = pe_pref(data_set->config_hash, "stonith-timeout");
    crm_xml_add(data_set->graph, "stonith-timeout", value);

    crm_xml_add(data_set->graph, "failed-stop-offset", "INFINITY");

    if (is_set(data_set->flags, pe_flag_start_failure_fatal)) {
        crm_xml_add(data_set->graph, "failed-start-offset", "INFINITY");
    } else {
        crm_xml_add(data_set->graph, "failed-start-offset", "1");
    }

    value = pe_pref(data_set->config_hash, "batch-limit");
    crm_xml_add(data_set->graph, "batch-limit", value);

    crm_xml_add_int(data_set->graph, "transition_id", transition_id);

    value = pe_pref(data_set->config_hash, "migration-limit");
    if (crm_int_helper(value, NULL) > 0) {
        crm_xml_add(data_set->graph, "migration-limit", value);
    }

/* errors...
   slist_iter(action, action_t, action_list, lpc,
   if(action->optional == FALSE && action->runnable == FALSE) {
   print_action("Ignoring", action, TRUE);
   }
   );
*/

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        crm_trace("processing actions for rsc=%s", rsc->id);
        rsc->cmds->expand(rsc, data_set);
    }

    crm_log_xml_trace(data_set->graph, "created resource-driven action list");

    /* catch any non-resource specific actions */
    crm_trace("processing non-resource actions");

    gIter = data_set->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        graph_element_from_action(action, data_set);
    }

    crm_log_xml_trace(data_set->graph, "created generic action list");
    crm_trace("Created transition graph %d.", transition_id);

    return TRUE;
}

void
cleanup_alloc_calculations(pe_working_set_t * data_set)
{
    if (data_set == NULL) {
        return;
    }

    crm_trace("deleting %d order cons: %p",
                g_list_length(data_set->ordering_constraints), data_set->ordering_constraints);
    pe_free_ordering(data_set->ordering_constraints);
    data_set->ordering_constraints = NULL;

    crm_trace("deleting %d node cons: %p",
                g_list_length(data_set->placement_constraints), data_set->placement_constraints);
    pe_free_rsc_to_node(data_set->placement_constraints);
    data_set->placement_constraints = NULL;

    crm_trace("deleting %d inter-resource cons: %p",
                g_list_length(data_set->colocation_constraints), data_set->colocation_constraints);
    slist_basic_destroy(data_set->colocation_constraints);
    data_set->colocation_constraints = NULL;

    crm_trace("deleting %d ticket deps: %p",
                g_list_length(data_set->ticket_constraints), data_set->ticket_constraints);
    slist_basic_destroy(data_set->ticket_constraints);
    data_set->ticket_constraints = NULL;

    cleanup_calculations(data_set);
}

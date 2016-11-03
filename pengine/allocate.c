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

#include <glib.h>

#include <crm/pengine/status.h>
#include <pengine.h>
#include <allocate.h>
#include <utils.h>

CRM_TRACE_INIT_DATA(pe_allocate);

void set_alloc_actions(pe_working_set_t * data_set);
void migrate_reload_madness(pe_working_set_t * data_set);
extern void ReloadRsc(resource_t * rsc, node_t *node, pe_working_set_t * data_set);
extern gboolean DeleteRsc(resource_t * rsc, node_t * node, gboolean optional, pe_working_set_t * data_set);

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
     clone_merge_weights,
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
     master_merge_weights,
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

gboolean
update_action_flags(action_t * action, enum pe_action_flags flags, const char *source)
{
    static unsigned long calls = 0;
    gboolean changed = FALSE;
    gboolean clear = is_set(flags, pe_action_clear);
    enum pe_action_flags last = action->flags;

    if (clear) {
        action->flags = crm_clear_bit(source, action->uuid, action->flags, flags);
    } else {
        action->flags = crm_set_bit(source, action->uuid, action->flags, flags);
    }

    if (last != action->flags) {
        calls++;
        changed = TRUE;
        /* Useful for tracking down _who_ changed a specific flag */
        /* CRM_ASSERT(calls != 534); */
        clear_bit(flags, pe_action_clear);
        crm_trace("%s on %s: %sset flags 0x%.6x (was 0x%.6x, now 0x%.6x, %lu, %s)",
                  action->uuid, action->node ? action->node->details->uname : "[none]",
                  clear ? "un-" : "", flags, last, action->flags, calls, source);
    }

    return changed;
}

static gboolean
check_rsc_parameters(resource_t * rsc, node_t * node, xmlNode * rsc_entry,
                     gboolean active_here, pe_working_set_t * data_set)
{
    int attr_lpc = 0;
    gboolean force_restart = FALSE;
    gboolean delete_resource = FALSE;
    gboolean changed = FALSE;

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

        changed = TRUE;
        trigger_unfencing(rsc, node, "Device definition changed", NULL, data_set);
        if (active_here) {
            force_restart = TRUE;
            crm_notice("Forcing restart of %s on %s, %s changed: %s -> %s",
                       rsc->id, node->details->uname, attr_list[attr_lpc],
                       crm_str(old_value), crm_str(value));
        }
    }
    if (force_restart) {
        /* make sure the restart happens */
        stop_action(rsc, node, FALSE);
        set_bit(rsc->flags, pe_rsc_start_pending);
        delete_resource = TRUE;

    } else if (changed) {
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

    /* TODO: This looks highly dangerous if we ever try to schedule 'key' too */
    cancel = custom_action(rsc, strdup(key), RSC_CANCEL, active_node, FALSE, TRUE, data_set);

    free(cancel->task);
    free(cancel->cancel_task);
    cancel->task = strdup(RSC_CANCEL);
    cancel->cancel_task = strdup(task);

    add_hash_param(cancel->meta, XML_LRM_ATTR_TASK, task);
    add_hash_param(cancel->meta, XML_LRM_ATTR_CALLID, call_id);
    add_hash_param(cancel->meta, XML_LRM_ATTR_INTERVAL, interval_s);

    custom_action_order(rsc, stop_key(rsc), NULL, rsc, NULL, cancel, pe_order_optional, data_set);
    free(key);
    key = NULL;
}

static gboolean
check_action_definition(resource_t * rsc, node_t * active_node, xmlNode * xml_op,
                        pe_working_set_t * data_set)
{
    char *key = NULL;
    int interval = 0;
    const char *interval_s = NULL;
    const op_digest_cache_t *digest_data = NULL;
    gboolean did_change = FALSE;

    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *op_version;
    const char *digest_secure = NULL;

    CRM_CHECK(active_node != NULL, return FALSE);
    if (safe_str_eq(task, RSC_STOP)) {
        return FALSE;
    }

    interval_s = crm_element_value(xml_op, XML_LRM_ATTR_INTERVAL);
    interval = crm_parse_int(interval_s, "0");

    if (interval > 0) {
        xmlNode *op_match = NULL;

        /* we need to reconstruct the key because of the way we used to construct resource IDs */
        key = generate_op_key(rsc->id, task, interval);

        pe_rsc_trace(rsc, "Checking parameters for %s", key);
        op_match = find_rsc_op_entry(rsc, key);

        if (op_match == NULL && is_set(data_set->flags, pe_flag_stop_action_orphans)) {
            CancelXmlOp(rsc, xml_op, active_node, "orphan", data_set);
            free(key);
            return TRUE;

        } else if (op_match == NULL) {
            pe_rsc_debug(rsc, "Orphan action detected: %s on %s", key, active_node->details->uname);
            free(key);
            return TRUE;
        }
        free(key);
        key = NULL;
    }

    crm_trace("Testing %s_%s_%d on %s", rsc->id, task, interval, active_node?active_node->details->uname:"N/A");
    if (interval == 0 && safe_str_eq(task, RSC_STATUS)) {
        /* Reload based on the start action not a probe */
        task = RSC_START;

    } else if (interval == 0 && safe_str_eq(task, RSC_MIGRATED)) {
        /* Reload based on the start action not a migrate */
        task = RSC_START;
    } else if (interval == 0 && safe_str_eq(task, RSC_PROMOTE)) {
        /* Reload based on the start action not a promote */
        task = RSC_START;
    }

    op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
    digest_data = rsc_action_digest_cmp(rsc, xml_op, active_node, data_set);

    if(is_set(data_set->flags, pe_flag_sanitized)) {
        digest_secure = crm_element_value(xml_op, XML_LRM_ATTR_SECURE_DIGEST);
    }

    if(digest_data->rc != RSC_DIGEST_MATCH
       && digest_secure
       && digest_data->digest_secure_calc
       && strcmp(digest_data->digest_secure_calc, digest_secure) == 0) {
        fprintf(stdout, "Only 'private' parameters to %s_%s_%d on %s changed: %s\n",
                rsc->id, task, interval, active_node->details->uname,
                crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));

    } else if (digest_data->rc == RSC_DIGEST_RESTART) {
        /* Changes that force a restart */
        const char *digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);

        did_change = TRUE;
        key = generate_op_key(rsc->id, task, interval);
        crm_log_xml_info(digest_data->params_restart, "params:restart");
        pe_rsc_info(rsc, "Parameters to %s on %s changed: was %s vs. now %s (restart:%s) %s",
                 key, active_node->details->uname,
                 crm_str(digest_restart), digest_data->digest_restart_calc,
                 op_version, crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));

        custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
        trigger_unfencing(rsc, NULL, "Device parameters changed", NULL, data_set);

    } else if ((digest_data->rc == RSC_DIGEST_ALL) || (digest_data->rc == RSC_DIGEST_UNKNOWN)) {
        /* Changes that can potentially be handled by a reload */
        const char *digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);
        const char *digest_all = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);

        did_change = TRUE;
        trigger_unfencing(rsc, NULL, "Device parameters changed (reload)", NULL, data_set);
        crm_log_xml_info(digest_data->params_all, "params:reload");
        key = generate_op_key(rsc->id, task, interval);
        pe_rsc_info(rsc, "Parameters to %s on %s changed: was %s vs. now %s (reload:%s) %s",
                 key, active_node->details->uname,
                 crm_str(digest_all), digest_data->digest_all_calc, op_version,
                 crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));

        if (interval > 0) {
            action_t *op = NULL;

#if 0
            /* Always reload/restart the entire resource */
            ReloadRsc(rsc, active_node, data_set);
#else
            /* Re-sending the recurring op is sufficient - the old one will be cancelled automatically */
            op = custom_action(rsc, key, task, active_node, TRUE, TRUE, data_set);
            set_bit(op->flags, pe_action_reschedule);
#endif

        } else if (digest_restart && rsc->isolation_wrapper == NULL && (uber_parent(rsc))->isolation_wrapper == NULL) {
            pe_rsc_trace(rsc, "Reloading '%s' action for resource %s", task, rsc->id);

            /* Reload this resource */
            ReloadRsc(rsc, active_node, data_set);
            free(key);

        } else {
            pe_rsc_trace(rsc, "Resource %s doesn't know how to reload", rsc->id);

            /* Re-send the start/demote/promote op
             * Recurring ops will be detected independently
             */
            custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
        }
    }

    return did_change;
}


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
    gboolean did_change = FALSE;

    CRM_CHECK(node != NULL, return);

    if (is_set(rsc->flags, pe_rsc_orphan)) {
        resource_t *parent = uber_parent(rsc);
        if(parent == NULL
           || parent->variant < pe_clone
           || is_set(parent->flags, pe_rsc_unique)) {
            pe_rsc_trace(rsc, "Skipping param check for %s and deleting: orphan", rsc->id);
            DeleteRsc(rsc, node, FALSE, data_set);
        } else {
            pe_rsc_trace(rsc, "Skipping param check for %s (orphan clone)", rsc->id);
        }
        return;

    } else if (pe_find_node_id(rsc->running_on, node->details->id) == NULL) {
        if (check_rsc_parameters(rsc, node, rsc_entry, FALSE, data_set)) {
            DeleteRsc(rsc, node, FALSE, data_set);
        }
        pe_rsc_trace(rsc, "Skipping param check for %s: no longer active on %s",
                     rsc->id, node->details->uname);
        return;
    }

    pe_rsc_trace(rsc, "Processing %s on %s", rsc->id, node->details->uname);

    if (check_rsc_parameters(rsc, node, rsc_entry, TRUE, data_set)) {
        DeleteRsc(rsc, node, FALSE, data_set);
    }

    for (rsc_op = __xml_first_child(rsc_entry); rsc_op != NULL; rsc_op = __xml_next_element(rsc_op)) {
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
        did_change = FALSE;
        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);

        interval_s = crm_element_value(rsc_op, XML_LRM_ATTR_INTERVAL);
        interval = crm_parse_int(interval_s, "0");

        if (interval == 0 && safe_str_eq(task, RSC_STATUS)) {
            is_probe = TRUE;
        }

        if (interval > 0 &&
            (is_set(rsc->flags, pe_rsc_maintenance) || node->details->maintenance)) {
            CancelXmlOp(rsc, rsc_op, node, "maintenance mode", data_set);

        } else if (is_probe || safe_str_eq(task, RSC_START) || safe_str_eq(task, RSC_PROMOTE) || interval > 0
                   || safe_str_eq(task, RSC_MIGRATED)) {
            did_change = check_action_definition(rsc, node, rsc_op, data_set);
        }

        if (did_change && get_failcount(node, rsc, NULL, data_set)) {
            char *key = NULL;
            action_t *action_clear = NULL;

            key = generate_op_key(rsc->id, CRM_OP_CLEAR_FAILCOUNT, 0);
            action_clear =
                custom_action(rsc, key, CRM_OP_CLEAR_FAILCOUNT, node, FALSE, TRUE, data_set);
            set_bit(action_clear->flags, pe_action_runnable);
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

        } else if (renamed_clones && rsc->clone_name && strstr(rsc->clone_name, id)) {
            match = TRUE;
        }

    } else {
        if (strcmp(rsc->id, id) == 0) {
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
         node_state = __xml_next_element(node_state)) {
        if (crm_str_eq((const char *)node_state->name, XML_CIB_TAG_STATE, TRUE)) {
            id = crm_element_value(node_state, XML_ATTR_ID);
            lrm_rscs = find_xml_node(node_state, XML_CIB_TAG_LRM, FALSE);
            lrm_rscs = find_xml_node(lrm_rscs, XML_LRM_TAG_RESOURCES, FALSE);

            node = pe_find_node_id(data_set->nodes, id);

            if (node == NULL) {
                continue;

            /* Still need to check actions for a maintenance node to cancel existing monitor operations */
            } else if (can_run_resources(node) == FALSE && node->details->maintenance == FALSE) {
                crm_trace("Skipping param check for %s: can't run resources",
                          node->details->uname);
                continue;
            }

            crm_trace("Processing node %s", node->details->uname);
            if (node->details->online || is_set(data_set->flags, pe_flag_stonith_enabled)) {
                xmlNode *rsc_entry = NULL;

                for (rsc_entry = __xml_first_child(lrm_rscs); rsc_entry != NULL;
                     rsc_entry = __xml_next_element(rsc_entry)) {
                    if (crm_str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, TRUE)) {

                        if (xml_has_children(rsc_entry)) {
                            GListPtr gIter = NULL;
                            GListPtr result = NULL;
                            const char *rsc_id = ID(rsc_entry);

                            CRM_CHECK(rsc_id != NULL, return);

                            result = find_rsc_list(NULL, NULL, rsc_id, TRUE, FALSE, data_set);
                            for (gIter = result; gIter != NULL; gIter = gIter->next) {
                                resource_t *rsc = (resource_t *) gIter->data;

                                if (rsc->variant != pe_native) {
                                    continue;
                                }
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

static gboolean
failcount_clear_action_exists(node_t * node, resource_t * rsc)
{
    gboolean rc = FALSE;
    char *key = crm_concat(rsc->id, CRM_OP_CLEAR_FAILCOUNT, '_');
    GListPtr list = find_actions_exact(rsc->actions, key, node);

    if (list) {
        rc = TRUE;
    }
    g_list_free(list);
    free(key);

    return rc;
}

/*!
 * \internal
 * \brief Force resource away if failures hit migration threshold
 *
 * \param[in,out] rsc       Resource to check for failures
 * \param[in,out] node      Node to check for failures
 * \param[in,out] data_set  Cluster working set to update
 */
static void
check_migration_threshold(resource_t *rsc, node_t *node,
                          pe_working_set_t *data_set)
{
    int fail_count, countdown;
    resource_t *failed;

    /* Migration threshold of 0 means never force away */
    if (rsc->migration_threshold == 0) {
        return;
    }

    /* If there are no failures, there's no need to force away */
    fail_count = get_failcount_all(node, rsc, NULL, data_set);
    if (fail_count <= 0) {
        return;
    }

    /* How many more times recovery will be tried on this node */
    countdown = QB_MAX(rsc->migration_threshold - fail_count, 0);

    /* If failed resource has a parent, we'll force the parent away */
    failed = rsc;
    if (is_not_set(rsc->flags, pe_rsc_unique)) {
        failed = uber_parent(rsc);
    }

    if (countdown == 0) {
        resource_location(failed, node, -INFINITY, "__fail_limit__", data_set);
        crm_warn("Forcing %s away from %s after %d failures (max=%d)",
                 failed->id, node->details->uname, fail_count,
                 rsc->migration_threshold);
    } else {
        crm_info("%s can fail %d more times on %s before being forced off",
                 failed->id, countdown, node->details->uname);
    }
}

static void
common_apply_stickiness(resource_t * rsc, node_t * node, pe_working_set_t * data_set)
{
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
            pe_rsc_debug(sticky_rsc, "Resource %s: preferring current location"
                         " (node=%s, weight=%d)", sticky_rsc->id,
                         node->details->uname, rsc->stickiness);
        } else {
            GHashTableIter iter;
            node_t *nIter = NULL;

            pe_rsc_debug(rsc, "Ignoring stickiness for %s: the cluster is asymmetric"
                         " and node %s is not explicitly allowed", rsc->id, node->details->uname);
            g_hash_table_iter_init(&iter, rsc->allowed_nodes);
            while (g_hash_table_iter_next(&iter, NULL, (void **)&nIter)) {
                crm_err("%s[%s] = %d", rsc->id, nIter->details->uname, nIter->weight);
            }
        }
    }

    /* Check the migration threshold only if a failcount clear action
     * has not already been placed for this resource on the node.
     * There is no sense in potentially forcing the resource from this
     * node if the failcount is being reset anyway. */
    if (failcount_clear_action_exists(node, rsc) == FALSE) {
        check_migration_threshold(rsc, node, data_set);
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
    int base_health = 0;

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
         * Also, custom health "base score" can be used
         */
        base_health = crm_parse_int(pe_pref(data_set->config_hash, "node-health-base"), "0");

    } else if (safe_str_eq(health_strategy, "custom")) {

        /* Requires the admin to configure the rsc_location constaints for
         * processing the stored health scores
         */
        /* TODO: Check for the existence of appropriate node health constraints */
        return TRUE;

    } else {
        crm_err("Unknown node health strategy: %s", health_strategy);
        return FALSE;
    }

    crm_info("Applying automated node health strategy: %s", health_strategy);

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        int system_health = base_health;
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

                rsc2node_new(health_strategy, rsc, system_health, NULL, node, data_set);
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

/*
 * Check nodes for resources started outside of the LRM
 */
gboolean
probe_resources(pe_working_set_t * data_set)
{
    action_t *probe_node_complete = NULL;

    GListPtr gIter = NULL;
    GListPtr gIter2 = NULL;

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        const char *probed = g_hash_table_lookup(node->details->attrs, CRM_OP_PROBED);

        if (node->details->online == FALSE) {
            continue;

        } else if (node->details->unclean) {
            continue;

        } else if (is_remote_node(node) && node->details->shutdown) {
            /* Don't probe a Pacemaker Remote node we're shutting down.
             * It causes constraint conflicts to try to run any action
             * other than "stop" on resources living within such a node when
             * it is shutting down. */
            continue;

        } else if (is_container_remote_node(node)) {
            /* TODO enable guest node probes once ordered probing is implemented */
            continue;

        } else if (node->details->rsc_discovery_enabled == FALSE) {
            /* resource discovery is disabled for this node */
            continue;
        }

        if (probed != NULL && crm_is_true(probed) == FALSE) {
            action_t *probe_op = custom_action(NULL, crm_strdup_printf("%s-%s", CRM_OP_REPROBE, node->details->uname),
                                               CRM_OP_REPROBE, node, FALSE, TRUE, data_set);

            add_hash_param(probe_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
            continue;
        }

        for (gIter2 = data_set->resources; gIter2 != NULL; gIter2 = gIter2->next) {
            resource_t *rsc = (resource_t *) gIter2->data;

            rsc->cmds->create_probe(rsc, node, probe_node_complete, FALSE, data_set);
        }
    }
    return TRUE;
}

static void
rsc_discover_filter(resource_t *rsc, node_t *node)
{
    GListPtr gIter = rsc->children;
    resource_t *top = uber_parent(rsc);
    node_t *match;

    if (rsc->exclusive_discover == FALSE && top->exclusive_discover == FALSE) {
        return;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;
        rsc_discover_filter(child_rsc, node);
    }

    match = g_hash_table_lookup(rsc->allowed_nodes, node->details->id);
    if (match && match->rsc_discover_mode != discover_exclusive) {
        match->weight = -INFINITY;
    }
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
                   && node->details->online && node->details->type != node_ping) {
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
            rsc_discover_filter(rsc, node);
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

    const char *reason = "existence";

    const GListPtr nodes = (GListPtr) data;
    resource_t *resource1 = (resource_t *) convert_const_pointer(a);
    resource_t *resource2 = (resource_t *) convert_const_pointer(b);

    node_t *r1_node = NULL;
    node_t *r2_node = NULL;
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
        r1_node = g_list_nth_data(resource1->running_on, 0);
        r1_node = g_hash_table_lookup(r1_nodes, r1_node->details->id);
        if (r1_node != NULL) {
            r1_weight = r1_node->weight;
        }
    }
    if (resource2->running_on) {
        r2_node = g_list_nth_data(resource2->running_on, 0);
        r2_node = g_hash_table_lookup(r2_nodes, r2_node->details->id);
        if (r2_node != NULL) {
            r2_weight = r2_node->weight;
        }
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
        node_t *node = (node_t *) gIter->data;

        r1_node = NULL;
        r2_node = NULL;

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
    crm_trace("%s (%d) on %s %c %s (%d) on %s: %s",
              resource1->id, r1_weight, r1_node ? r1_node->details->id : "n/a",
              rc < 0 ? '>' : rc > 0 ? '<' : '=',
              resource2->id, r2_weight, r2_node ? r2_node->details->id : "n/a", reason);

    if (r1_nodes) {
        g_hash_table_destroy(r1_nodes);
    }
    if (r2_nodes) {
        g_hash_table_destroy(r2_nodes);
    }

    return rc;
}

static void
allocate_resources(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    if (is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        /* Force remote connection resources to be allocated first. This
         * also forces any colocation dependencies to be allocated as well */
        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;
            if (rsc->is_remote_node == FALSE) {
                continue;
            }
            pe_rsc_trace(rsc, "Allocating: %s", rsc->id);
            /* For remote node connection resources, always prefer the partial
             * migration target during resource allocation, if the rsc is in the
             * middle of a migration.
             */
            rsc->cmds->allocate(rsc, rsc->partial_migration_target, data_set);
        }
    }

    /* now do the rest of the resources */
    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;
        if (rsc->is_remote_node == TRUE) {
            continue;
        }
        pe_rsc_trace(rsc, "Allocating: %s", rsc->id);
        rsc->cmds->allocate(rsc, NULL, data_set);
    }
}

static void
cleanup_orphans(resource_t * rsc, pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    if (is_set(data_set->flags, pe_flag_stop_rsc_orphans) == FALSE) {
        return;
    }

    /* Don't recurse into ->children, those are just unallocated clone instances */
    if(is_not_set(rsc->flags, pe_rsc_orphan)) {
        return;
    }

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        if (node->details->online && get_failcount(node, rsc, NULL, data_set)) {
            action_t *clear_op = NULL;

            clear_op = custom_action(rsc, crm_concat(rsc->id, CRM_OP_CLEAR_FAILCOUNT, '_'),
                                     CRM_OP_CLEAR_FAILCOUNT, node, FALSE, TRUE, data_set);

            add_hash_param(clear_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
            pe_rsc_info(rsc, "Clearing failcount (%d) for orphaned resource %s on %s (%s)",
                        get_failcount(node, rsc, NULL, data_set), rsc->id, node->details->uname,
                        clear_op->uuid);

            custom_action_order(rsc, NULL, clear_op,
                            rsc, generate_op_key(rsc->id, RSC_STOP, 0), NULL,
                            pe_order_optional, data_set);
        }
    }
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

    allocate_resources(data_set);

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

    crm_trace("Handle orphans");

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;
        cleanup_orphans(rsc, data_set);
    }

    crm_trace("Creating actions");

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
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
any_managed_resources(pe_working_set_t * data_set)
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
 * Create dependencies for stonith and shutdown operations
 */
gboolean
stage6(pe_working_set_t * data_set)
{
    action_t *dc_down = NULL;
    action_t *dc_fence = NULL;
    action_t *stonith_op = NULL;
    action_t *last_stonith = NULL;
    gboolean integrity_lost = FALSE;
    action_t *all_stopped = get_pseudo_op(ALL_STOPPED, data_set);
    action_t *done = get_pseudo_op(STONITH_DONE, data_set);
    gboolean need_stonith = TRUE;
    GListPtr gIter;
    GListPtr stonith_ops = NULL;

    crm_trace("Processing fencing and shutdown cases");

    if (any_managed_resources(data_set) == FALSE) {
        crm_notice("Delaying fencing operations until there are resources to manage");
        need_stonith = FALSE;
    }

    /* Check each node for stonith/shutdown */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        /* Guest nodes are "fenced" by recovering their container resource.
         * The container stop may be explicit, or implied by the fencing of the
         * guest's host.
         */
        if (is_container_remote_node(node)) {
            /* Guest */
            if (need_stonith
                && node->details->remote_requires_reset
                && pe_can_fence(data_set, node)) {
                resource_t *container = node->details->remote_rsc->container;
                char *key = stop_key(container);
                GListPtr stop_list = find_actions(container->actions, key, NULL);

                crm_info("Implying node %s is down when container %s is stopped (%p)",
                         node->details->uname, container->id, stop_list);
                if(stop_list) {
                    stonith_constraints(node, stop_list->data, data_set);
                }

                g_list_free(stop_list);
                free(key);
            }
            continue;
        }

        stonith_op = NULL;

        if (node->details->unclean
            && need_stonith && pe_can_fence(data_set, node)) {

            pe_warn("Scheduling Node %s for STONITH", node->details->uname);

            stonith_op = pe_fence_op(node, NULL, FALSE, data_set);

            stonith_constraints(node, stonith_op, data_set);

            if (node->details->is_dc) {
                dc_down = stonith_op;
                dc_fence = stonith_op;

            } else if (is_set(data_set->flags, pe_flag_concurrent_fencing) == FALSE) {
                if (last_stonith) {
                    order_actions(last_stonith, stonith_op, pe_order_optional);
                }
                last_stonith = stonith_op;

            } else {
                order_actions(stonith_op, done, pe_order_implies_then);
                stonith_ops = g_list_append(stonith_ops, stonith_op);
            }

        } else if (node->details->online && node->details->shutdown &&
                /* TODO define what a shutdown op means for a remote node.
                 * For now we do not send shutdown operations for remote nodes, but
                 * if we can come up with a good use for this in the future, we will. */
                    is_remote_node(node) == FALSE) {

            action_t *down_op = NULL;

            crm_notice("Scheduling Node %s for shutdown", node->details->uname);

            down_op = custom_action(NULL, crm_strdup_printf("%s-%s", CRM_OP_SHUTDOWN, node->details->uname),
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
        GListPtr gIter = NULL;

        crm_trace("Ordering shutdowns before %s on %s (DC)",
                  dc_down->task, dc_down->node->details->uname);

        add_hash_param(dc_down->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);

        for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
            action_t *node_stop = (action_t *) gIter->data;

            if (safe_str_neq(CRM_OP_SHUTDOWN, node_stop->task)) {
                continue;
            } else if (node_stop->node->details->is_dc) {
                continue;
            }

            crm_debug("Ordering shutdown on %s before %s on %s",
                      node_stop->node->details->uname,
                      dc_down->task, dc_down->node->details->uname);

            order_actions(node_stop, dc_down, pe_order_optional);
        }

        if (last_stonith) {
            if (dc_down != last_stonith) {
                order_actions(last_stonith, dc_down, pe_order_optional);
            }

        } else {
            GListPtr gIter2 = NULL;

            for (gIter2 = stonith_ops; gIter2 != NULL; gIter2 = gIter2->next) {
                stonith_op = (action_t *) gIter2->data;

                if (dc_down != stonith_op) {
                    order_actions(stonith_op, dc_down, pe_order_optional);
                }
            }
        }
    }


    if (dc_fence) {
        order_actions(dc_down, done, pe_order_implies_then);

    } else if (last_stonith) {
        order_actions(last_stonith, done, pe_order_implies_then);
    }

    order_actions(done, all_stopped, pe_order_implies_then);

    g_list_free(stonith_ops);
    return TRUE;
}

/*
 * Determine the sets of independent actions and the correct order for the
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

        free(key);
        free(tmp);
        free(task);
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
        pe_rsc_trace(rsc, "No RH-Side (%s/%s) found for constraint..."
                     " ignoring", rsc->id, order->rh_action_task);
        if (lh_action) {
            pe_rsc_trace(rsc, "LH-Side was: %s", lh_action->uuid);
        }
        return;
    }

    if (lh_action && lh_action->rsc == rsc && is_set(lh_action->flags, pe_action_dangle)) {
        pe_rsc_trace(rsc, "Detected dangling operation %s -> %s", lh_action->uuid,
                     order->rh_action_task);
        clear_bit(type, pe_order_implies_then);
    }

    gIter = rh_actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *rh_action_iter = (action_t *) gIter->data;

        if (lh_action) {
            order_actions(lh_action, rh_action_iter, type);

        } else if (type & pe_order_implies_then) {
            update_action_flags(rh_action_iter, pe_action_runnable | pe_action_clear, __FUNCTION__);
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

        if (lh_rsc->fns->state(lh_rsc, TRUE) == RSC_ROLE_STOPPED && safe_str_eq(op_type, RSC_STOP)) {
            free(key);
            pe_rsc_trace(lh_rsc, "No LH-Side (%s/%s) found for constraint %d with %s - ignoring",
                         lh_rsc->id, order->lh_action_task, order->id, order->rh_action_task);

        } else if (lh_rsc->fns->state(lh_rsc, TRUE) == RSC_ROLE_SLAVE && safe_str_eq(op_type, RSC_DEMOTE)) {
            free(key);
            pe_rsc_trace(lh_rsc, "No LH-Side (%s/%s) found for constraint %d with %s - ignoring",
                         lh_rsc->id, order->lh_action_task, order->id, order->rh_action_task);

        } else {
            pe_rsc_trace(lh_rsc, "No LH-Side (%s/%s) found for constraint %d with %s - creating",
                         lh_rsc->id, order->lh_action_task, order->id, order->rh_action_task);
            lh_action = custom_action(lh_rsc, key, op_type, NULL, TRUE, TRUE, data_set);
            lh_actions = g_list_prepend(NULL, lh_action);
        }

        free(op_type);
        free(rsc_id);
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
extern void update_colo_start_chain(action_t * action);

static void
apply_remote_node_ordering(pe_working_set_t *data_set)
{
    GListPtr gIter = data_set->actions;

    if (is_set(data_set->flags, pe_flag_have_remote_nodes) == FALSE) {
        return;
    }
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;
        resource_t *remote_rsc = NULL;
        resource_t *container = NULL;

        if (action->rsc == NULL) {
            continue;
        }

        /* Special case. */
        if (action->rsc &&
            action->rsc->is_remote_node &&
            safe_str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT)) {

            /* If we are clearing the failcount of an actual remote node
             * connection resource, then make sure this happens before allowing
             * the connection to start if we are planning on starting the
             * connection during this transition.
             */
            custom_action_order(action->rsc,
                NULL,
                action,
                action->rsc,
                generate_op_key(action->rsc->id, RSC_START, 0),
                NULL,
                pe_order_optional,
                data_set);

                continue;
        }

        /* If the action occurs on a Pacemaker Remote node, create
         * ordering constraints that guarantee the action occurs while the node
         * is active (after start, before stop ... things like that).
         */
        if (action->node == NULL ||
            is_remote_node(action->node) == FALSE ||
            action->node->details->remote_rsc == NULL ||
            is_set(action->flags, pe_action_pseudo)) {
            continue;
        }

        remote_rsc = action->node->details->remote_rsc;
        container = remote_rsc->container;

        if (safe_str_eq(action->task, "monitor") ||
            safe_str_eq(action->task, "start") ||
            safe_str_eq(action->task, "promote") ||
            safe_str_eq(action->task, "notify") ||
            safe_str_eq(action->task, CRM_OP_LRM_REFRESH) ||
            safe_str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT) ||
            safe_str_eq(action->task, "delete")) {

            custom_action_order(remote_rsc,
                generate_op_key(remote_rsc->id, RSC_START, 0),
                NULL,
                action->rsc,
                NULL,
                action,
                pe_order_preserve | pe_order_implies_then | pe_order_runnable_left,
                data_set);

        } else if (safe_str_eq(action->task, "demote")) {

            /* If the connection is being torn down, we don't want
             * to build a constraint between a resource's demotion and
             * the connection resource starting... because the connection
             * resource can not start. The connection might already be up,
             * but the "start" action would not be allowed, which in turn would
             * block the demotion of any resources living in the node.
             *
             * In this case, only build the constraint between the demotion and
             * the connection's "stop" action. This allows the connection and
             * all the resources within the node to be torn down properly.
             */
            if (remote_rsc->next_role == RSC_ROLE_STOPPED) {
                custom_action_order(action->rsc,
                    NULL,
                    action,
                    remote_rsc,
                    generate_op_key(remote_rsc->id, RSC_STOP, 0),
                    NULL,
                    pe_order_preserve | pe_order_implies_first,
                    data_set);
            }

            if(container && is_set(container->flags, pe_rsc_failed)) {
                /* Just like a stop, the demote is implied by the
                 * container having failed/stopped
                 *
                 * If we really wanted to we would order the demote
                 * after the stop, IFF the containers current role was
                 * stopped (otherwise we re-introduce an ordering
                 * loop)
                 */
                pe_set_action_bit(action, pe_action_pseudo);
            }

        } else if (safe_str_eq(action->task, "stop") &&
                   container &&
                   is_set(container->flags, pe_rsc_failed)) {

            /* When the container representing a guest node fails, the stop
             * action for all the resources living in that container is implied
             * by the container stopping. This is similar to how fencing
             * operations work for cluster nodes.
             */
            pe_set_action_bit(action, pe_action_pseudo);
            custom_action_order(container,
                generate_op_key(container->id, RSC_STOP, 0),
                NULL,
                action->rsc,
                NULL,
                action,
                pe_order_preserve | pe_order_implies_then | pe_order_runnable_left,
                data_set);
        } else if (safe_str_eq(action->task, "stop")) {
            gboolean after_start = FALSE;

            /* Handle special case with remote node where stop actions need to be
             * ordered after the connection resource starts somewhere else.
             */
            if (is_baremetal_remote_node(action->node)) {
                node_t *cluster_node = remote_rsc->running_on ? remote_rsc->running_on->data : NULL;

                /* If the cluster node the remote connection resource resides on
                 * is unclean or went offline, we can't process any operations
                 * on that remote node until after it starts elsewhere.
                 */
                if (cluster_node == NULL ||
                    cluster_node->details->unclean == TRUE ||
                    cluster_node->details->online == FALSE) {
                    after_start = TRUE;
                } else if (g_list_length(remote_rsc->running_on) > 1 &&
                           remote_rsc->partial_migration_source &&
                            remote_rsc->partial_migration_target) {
                    /* if we're caught in the middle of migrating a connection resource,
                     * then we have to wait until after the resource migrates before performing
                     * any actions. */
                    after_start = TRUE;
                }
            }

            if (after_start) {
                custom_action_order(remote_rsc,
                    generate_op_key(remote_rsc->id, RSC_START, 0),
                    NULL,
                    action->rsc,
                    NULL,
                    action,
                    pe_order_preserve | pe_order_implies_then | pe_order_runnable_left,
                    data_set);
            } else {
                custom_action_order(action->rsc,
                    NULL,
                    action,
                    remote_rsc,
                    generate_op_key(remote_rsc->id, RSC_STOP, 0),
                    NULL,
                    pe_order_preserve | pe_order_implies_first,
                    data_set);
            }
        }
    }
}

static void
order_probes(pe_working_set_t * data_set) 
{
#if 0
    GListPtr gIter = NULL;

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        /* Given "A then B", we would prefer to wait for A to be
         * started before probing B.
         *
         * If A was a filesystem on which the binaries and data for B
         * lived, it would have been useful if the author of B's agent
         * could assume that A is running before B.monitor will be
         * called.
         *
         * However we can't _only_ probe once A is running, otherwise
         * we'd not detect the state of B if A could not be started
         * for some reason.
         *
         * In practice however, we cannot even do an opportunistic
         * version of this because B may be moving:
         *
         *   B.probe -> B.start
         *   B.probe -> B.stop
         *   B.stop -> B.start
         *   A.stop -> A.start
         *   A.start -> B.probe
         *
         * So far so good, but if we add the result of this code:
         *
         *   B.stop -> A.stop
         *
         * Then we get a loop:
         *
         *   B.probe -> B.stop -> A.stop -> A.start -> B.probe
         *
         * We could kill the 'B.probe -> B.stop' dependency, but that
         * could mean stopping B "too" soon, because B.start must wait
         * for the probes to complete.
         *
         * Another option is to allow it only if A is a non-unique
         * clone with clone-max == node-max (since we'll never be
         * moving it).  However, we could still be stopping one
         * instance at the same time as starting another.

         * The complexity of checking for allowed conditions combined
         * with the ever narrowing usecase suggests that this code
         * should remain disabled until someone gets smarter.
         */
        action_t *start = NULL;
        GListPtr actions = NULL;
        GListPtr probes = NULL;
        char *key = NULL;

        key = start_key(rsc);
        actions = find_actions(rsc->actions, key, NULL);
        free(key);

        if (actions) {
            start = actions->data;
            g_list_free(actions);
        }

        if(start == NULL) {
            crm_err("No start action for %s", rsc->id);
            continue;
        }

        key = generate_op_key(rsc->id, CRMD_ACTION_STATUS, 0);
        probes = find_actions(rsc->actions, key, NULL);
        free(key);

        for (actions = start->actions_before; actions != NULL; actions = actions->next) {
            action_wrapper_t *before = (action_wrapper_t *) actions->data;

            GListPtr pIter = NULL;
            action_t *first = before->action;
            resource_t *first_rsc = first->rsc;

            if(first->required_runnable_before) {
                GListPtr clone_actions = NULL;
                for (clone_actions = first->actions_before; clone_actions != NULL; clone_actions = clone_actions->next) {
                    before = (action_wrapper_t *) clone_actions->data;

                    crm_trace("Testing %s -> %s (%p) for %s", first->uuid, before->action->uuid, before->action->rsc, start->uuid);

                    CRM_ASSERT(before->action->rsc);
                    first_rsc = before->action->rsc;
                    break;
                }

            } else if(safe_str_neq(first->task, RSC_START)) {
                crm_trace("Not a start op %s for %s", first->uuid, start->uuid);
            }

            if(first_rsc == NULL) {
                continue;

            } else if(uber_parent(first_rsc) == uber_parent(start->rsc)) {
                crm_trace("Same parent %s for %s", first_rsc->id, start->uuid);
                continue;

            } else if(FALSE && uber_parent(first_rsc)->variant < pe_clone) {
                crm_trace("Not a clone %s for %s", first_rsc->id, start->uuid);
                continue;
            }

            crm_err("Appplying %s before %s %d", first->uuid, start->uuid, uber_parent(first_rsc)->variant);

            for (pIter = probes; pIter != NULL; pIter = pIter->next) {
                action_t *probe = (action_t *) pIter->data;

                crm_err("Ordering %s before %s", first->uuid, probe->uuid);
                order_actions(first, probe, pe_order_optional);
            }
        }
    }
#endif
}

gboolean
stage7(pe_working_set_t * data_set)
{
    GListPtr gIter = NULL;

    apply_remote_node_ordering(data_set);
    crm_trace("Applying ordering constraints");

    /* Don't ask me why, but apparently they need to be processed in
     * the order they were created in... go figure
     *
     * Also g_list_append() has horrendous performance characteristics
     * So we need to use g_list_prepend() and then reverse the list here
     */
    data_set->ordering_constraints = g_list_reverse(data_set->ordering_constraints);

    for (gIter = data_set->ordering_constraints; gIter != NULL; gIter = gIter->next) {
        order_constraint_t *order = (order_constraint_t *) gIter->data;
        resource_t *rsc = order->lh_rsc;

        crm_trace("Applying ordering constraint: %d", order->id);

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

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        update_colo_start_chain(action);
    }

    crm_trace("Ordering probes");
    order_probes(data_set);

    crm_trace("Updating %d actions", g_list_length(data_set->actions));

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        update_action(action);
    }

    crm_trace("Processing reloads");

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        resource_t *rsc = (resource_t *) gIter->data;

        LogActions(rsc, data_set, FALSE);
    }
    return TRUE;
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

        pe_rsc_trace(rsc, "processing actions for rsc=%s", rsc->id);
        rsc->cmds->expand(rsc, data_set);
    }

    crm_log_xml_trace(data_set->graph, "created resource-driven action list");

    /* catch any non-resource specific actions */
    crm_trace("processing non-resource actions");

    gIter = data_set->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (action->rsc
            && action->node
            && action->node->details->shutdown
            && is_not_set(action->rsc->flags, pe_rsc_maintenance)
            && is_not_set(action->flags, pe_action_optional)
            && is_not_set(action->flags, pe_action_runnable)
            && crm_str_eq(action->task, RSC_STOP, TRUE)
            ) {
            /* Eventually we should just ignore the 'fence' case
             * But for now it's the best way to detect (in CTS) when
             * CIB resource updates are being lost
             */
            if (is_set(data_set->flags, pe_flag_have_quorum)
                || data_set->no_quorum_policy == no_quorum_ignore) {
                crm_crit("Cannot %s node '%s' because of %s:%s%s",
                         action->node->details->unclean ? "fence" : "shut down",
                         action->node->details->uname, action->rsc->id,
                         is_not_set(action->rsc->flags, pe_rsc_managed) ? " unmanaged" : " blocked",
                         is_set(action->rsc->flags, pe_rsc_failed) ? " failed" : "");
            }
        }

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
    g_list_free_full(data_set->colocation_constraints, free);
    data_set->colocation_constraints = NULL;

    crm_trace("deleting %d ticket deps: %p",
              g_list_length(data_set->ticket_constraints), data_set->ticket_constraints);
    g_list_free_full(data_set->ticket_constraints, free);
    data_set->ticket_constraints = NULL;

    cleanup_calculations(data_set);
}

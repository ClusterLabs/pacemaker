/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>

#include <crm/crm.h>
#include <crm/cib.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>

#include <glib.h>

#include <crm/pengine/status.h>
#include <pacemaker-internal.h>
#include "libpacemaker_private.h"

CRM_TRACE_INIT_DATA(pacemaker);

extern bool pcmk__is_daemon;

void set_alloc_actions(pe_working_set_t * data_set);
extern void ReloadRsc(pe_resource_t * rsc, pe_node_t *node, pe_working_set_t * data_set);
extern gboolean DeleteRsc(pe_resource_t * rsc, pe_node_t * node, gboolean optional, pe_working_set_t * data_set);
static void apply_remote_node_ordering(pe_working_set_t *data_set);
static enum remote_connection_state get_remote_node_state(pe_node_t *node);

enum remote_connection_state {
    remote_state_unknown = 0,
    remote_state_alive = 1,
    remote_state_resting = 2,
    remote_state_failed = 3,
    remote_state_stopped = 4
};

static const char *
state2text(enum remote_connection_state state)
{
    switch (state) {
        case remote_state_unknown:
            return "unknown";
        case remote_state_alive:
            return "alive";
        case remote_state_resting:
            return "resting";
        case remote_state_failed:
            return "failed";
        case remote_state_stopped:
            return "stopped";
    }

    return "impossible";
}

resource_alloc_functions_t resource_class_alloc_functions[] = {
    {
     pcmk__native_merge_weights,
     pcmk__native_allocate,
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
     pcmk__group_merge_weights,
     pcmk__group_allocate,
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
     pcmk__native_merge_weights,
     pcmk__clone_allocate,
     clone_create_actions,
     clone_create_probe,
     clone_internal_constraints,
     clone_rsc_colocation_lh,
     clone_rsc_colocation_rh,
     clone_rsc_location,
     clone_action_flags,
     pcmk__multi_update_actions,
     clone_expand,
     clone_append_meta,
     },
    {
     pcmk__native_merge_weights,
     pcmk__bundle_allocate,
     pcmk__bundle_create_actions,
     pcmk__bundle_create_probe,
     pcmk__bundle_internal_constraints,
     pcmk__bundle_rsc_colocation_lh,
     pcmk__bundle_rsc_colocation_rh,
     pcmk__bundle_rsc_location,
     pcmk__bundle_action_flags,
     pcmk__multi_update_actions,
     pcmk__bundle_expand,
     pcmk__bundle_append_meta,
     }
};

static gboolean
check_rsc_parameters(pe_resource_t * rsc, pe_node_t * node, xmlNode * rsc_entry,
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

    for (; attr_lpc < PCMK__NELEM(attr_list); attr_lpc++) {
        value = crm_element_value(rsc->xml, attr_list[attr_lpc]);
        old_value = crm_element_value(rsc_entry, attr_list[attr_lpc]);
        if (value == old_value  /* i.e. NULL */
            || pcmk__str_eq(value, old_value, pcmk__str_none)) {
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
        pe__set_resource_flags(rsc, pe_rsc_start_pending);
        delete_resource = TRUE;

    } else if (changed) {
        delete_resource = TRUE;
    }
    return delete_resource;
}

static void
CancelXmlOp(pe_resource_t * rsc, xmlNode * xml_op, pe_node_t * active_node,
            const char *reason, pe_working_set_t * data_set)
{
    guint interval_ms = 0;
    pe_action_t *cancel = NULL;

    const char *task = NULL;
    const char *call_id = NULL;

    CRM_CHECK(xml_op != NULL, return);
    CRM_CHECK(active_node != NULL, return);

    task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    call_id = crm_element_value(xml_op, XML_LRM_ATTR_CALLID);
    crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

    crm_info("Action " PCMK__OP_FMT " on %s will be stopped: %s",
             rsc->id, task, interval_ms,
             active_node->details->uname, (reason? reason : "unknown"));

    cancel = pe_cancel_op(rsc, task, interval_ms, active_node, data_set);
    add_hash_param(cancel->meta, XML_LRM_ATTR_CALLID, call_id);
    pcmk__new_ordering(rsc, stop_key(rsc), NULL, rsc, NULL, cancel,
                       pe_order_optional, data_set);
}

static gboolean
check_action_definition(pe_resource_t * rsc, pe_node_t * active_node, xmlNode * xml_op,
                        pe_working_set_t * data_set)
{
    char *key = NULL;
    guint interval_ms = 0;
    const op_digest_cache_t *digest_data = NULL;
    gboolean did_change = FALSE;

    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *digest_secure = NULL;

    CRM_CHECK(active_node != NULL, return FALSE);

    crm_element_value_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);
    if (interval_ms > 0) {
        xmlNode *op_match = NULL;

        /* we need to reconstruct the key because of the way we used to construct resource IDs */
        key = pcmk__op_key(rsc->id, task, interval_ms);

        pe_rsc_trace(rsc, "Checking parameters for %s", key);
        op_match = find_rsc_op_entry(rsc, key);

        if ((op_match == NULL)
            && pcmk_is_set(data_set->flags, pe_flag_stop_action_orphans)) {
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

    crm_trace("Testing " PCMK__OP_FMT " on %s",
              rsc->id, task, interval_ms, active_node->details->uname);
    if ((interval_ms == 0) && pcmk__str_eq(task, RSC_STATUS, pcmk__str_casei)) {
        /* Reload based on the start action not a probe */
        task = RSC_START;

    } else if ((interval_ms == 0) && pcmk__str_eq(task, RSC_MIGRATED, pcmk__str_casei)) {
        /* Reload based on the start action not a migrate */
        task = RSC_START;
    } else if ((interval_ms == 0) && pcmk__str_eq(task, RSC_PROMOTE, pcmk__str_casei)) {
        /* Reload based on the start action not a promote */
        task = RSC_START;
    }

    digest_data = rsc_action_digest_cmp(rsc, xml_op, active_node, data_set);

    if (pcmk_is_set(data_set->flags, pe_flag_sanitized)) {
        digest_secure = crm_element_value(xml_op, XML_LRM_ATTR_SECURE_DIGEST);
    }

    if(digest_data->rc != RSC_DIGEST_MATCH
       && digest_secure
       && digest_data->digest_secure_calc
       && strcmp(digest_data->digest_secure_calc, digest_secure) == 0) {
        if (!pcmk__is_daemon && data_set->priv != NULL) {
            pcmk__output_t *out = data_set->priv;
            out->info(out, "Only 'private' parameters to "
                      PCMK__OP_FMT " on %s changed: %s", rsc->id, task,
                      interval_ms, active_node->details->uname,
                      crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        }

    } else if (digest_data->rc == RSC_DIGEST_RESTART) {
        /* Changes that force a restart */
        pe_action_t *required = NULL;

        did_change = TRUE;
        key = pcmk__op_key(rsc->id, task, interval_ms);
        crm_log_xml_info(digest_data->params_restart, "params:restart");
        required = custom_action(rsc, key, task, NULL, FALSE, TRUE, data_set);
        pe_action_set_reason(required, "resource definition change", true);
        trigger_unfencing(rsc, active_node, "Device parameters changed", NULL, data_set);

    } else if ((digest_data->rc == RSC_DIGEST_ALL) || (digest_data->rc == RSC_DIGEST_UNKNOWN)) {
        // Changes that can potentially be handled by an agent reload
        const char *digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);

        did_change = TRUE;
        trigger_unfencing(rsc, active_node, "Device parameters changed (reload)", NULL, data_set);
        crm_log_xml_info(digest_data->params_all, "params:reload");
        key = pcmk__op_key(rsc->id, task, interval_ms);

        if (interval_ms > 0) {
            pe_action_t *op = NULL;

#if 0
            /* Always reload/restart the entire resource */
            ReloadRsc(rsc, active_node, data_set);
#else
            /* Re-sending the recurring op is sufficient - the old one will be cancelled automatically */
            op = custom_action(rsc, key, task, active_node, TRUE, TRUE, data_set);
            pe__set_action_flags(op, pe_action_reschedule);
#endif

        } else if (digest_restart) {
            pe_rsc_trace(rsc, "Reloading '%s' action for resource %s", task, rsc->id);

            /* Reload this resource */
            ReloadRsc(rsc, active_node, data_set);
            free(key);

        } else {
            pe_action_t *required = NULL;
            pe_rsc_trace(rsc, "Resource %s doesn't support agent reloads",
                         rsc->id);

            /* Re-send the start/demote/promote op
             * Recurring ops will be detected independently
             */
            required = custom_action(rsc, key, task, NULL, FALSE, TRUE,
                                     data_set);
            pe_action_set_reason(required, "resource definition change", true);
        }
    }

    return did_change;
}

/*!
 * \internal
 * \brief Do deferred action checks after allocation
 *
 * \param[in] data_set  Working set for cluster
 */
static void
check_params(pe_resource_t *rsc, pe_node_t *node, xmlNode *rsc_op,
             enum pe_check_parameters check, pe_working_set_t *data_set)
{
    const char *reason = NULL;
    op_digest_cache_t *digest_data = NULL;

    switch (check) {
        case pe_check_active:
            if (check_action_definition(rsc, node, rsc_op, data_set)
                && pe_get_failcount(node, rsc, NULL, pe_fc_effective, NULL,
                                    data_set)) {

                reason = "action definition changed";
            }
            break;

        case pe_check_last_failure:
            digest_data = rsc_action_digest_cmp(rsc, rsc_op, node, data_set);
            switch (digest_data->rc) {
                case RSC_DIGEST_UNKNOWN:
                    crm_trace("Resource %s history entry %s on %s has no digest to compare",
                              rsc->id, ID(rsc_op), node->details->id);
                    break;
                case RSC_DIGEST_MATCH:
                    break;
                default:
                    reason = "resource parameters have changed";
                    break;
            }
            break;
    }

    if (reason) {
        pe__clear_failcount(rsc, node, reason, data_set);
    }
}

static void
check_actions_for(xmlNode * rsc_entry, pe_resource_t * rsc, pe_node_t * node, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    int offset = -1;
    int stop_index = 0;
    int start_index = 0;

    const char *task = NULL;

    xmlNode *rsc_op = NULL;
    GList *op_list = NULL;
    GList *sorted_op_list = NULL;

    CRM_CHECK(node != NULL, return);

    if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
        pe_resource_t *parent = uber_parent(rsc);
        if(parent == NULL
           || pe_rsc_is_clone(parent) == FALSE
           || pcmk_is_set(parent->flags, pe_rsc_unique)) {
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

    for (rsc_op = pcmk__xe_first_child(rsc_entry); rsc_op != NULL;
         rsc_op = pcmk__xe_next(rsc_op)) {

        if (pcmk__str_eq((const char *)rsc_op->name, XML_LRM_TAG_RSC_OP, pcmk__str_none)) {
            op_list = g_list_prepend(op_list, rsc_op);
        }
    }

    sorted_op_list = g_list_sort(op_list, sort_op_by_callid);
    calculate_active_ops(sorted_op_list, &start_index, &stop_index);

    for (gIter = sorted_op_list; gIter != NULL; gIter = gIter->next) {
        xmlNode *rsc_op = (xmlNode *) gIter->data;
        guint interval_ms = 0;

        offset++;

        if (start_index < stop_index) {
            /* stopped */
            continue;
        } else if (offset < start_index) {
            /* action occurred prior to a start */
            continue;
        }

        task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
        crm_element_value_ms(rsc_op, XML_LRM_ATTR_INTERVAL_MS, &interval_ms);

        if ((interval_ms > 0) &&
            (pcmk_is_set(rsc->flags, pe_rsc_maintenance) || node->details->maintenance)) {
            // Maintenance mode cancels recurring operations
            CancelXmlOp(rsc, rsc_op, node, "maintenance mode", data_set);

        } else if ((interval_ms > 0) || pcmk__strcase_any_of(task, RSC_STATUS, RSC_START,
                                                             RSC_PROMOTE, RSC_MIGRATED, NULL)) {
            /* If a resource operation failed, and the operation's definition
             * has changed, clear any fail count so they can be retried fresh.
             */

            if (pe__bundle_needs_remote_name(rsc, data_set)) {
                /* We haven't allocated resources to nodes yet, so if the
                 * REMOTE_CONTAINER_HACK is used, we may calculate the digest
                 * based on the literal "#uname" value rather than the properly
                 * substituted value. That would mistakenly make the action
                 * definition appear to have been changed. Defer the check until
                 * later in this case.
                 */
                pe__add_param_check(rsc_op, rsc, node, pe_check_active,
                                    data_set);

            } else if (check_action_definition(rsc, node, rsc_op, data_set)
                && pe_get_failcount(node, rsc, NULL, pe_fc_effective, NULL,
                                    data_set)) {
                pe__clear_failcount(rsc, node, "action definition changed",
                                    data_set);
            }
        }
    }
    g_list_free(sorted_op_list);
}

static GList *
find_rsc_list(GList *result, pe_resource_t * rsc, const char *id, gboolean renamed_clones,
              gboolean partial, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    gboolean match = FALSE;

    if (id == NULL) {
        return NULL;
    }

    if (rsc == NULL) {
        if (data_set == NULL) {
            return NULL;
        }
        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            result = find_rsc_list(result, child, id, renamed_clones, partial,
                                   NULL);
        }
        return result;
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
            pe_resource_t *child = (pe_resource_t *) gIter->data;

            result = find_rsc_list(result, child, id, renamed_clones, partial, NULL);
        }
    }

    return result;
}

static void
check_actions(pe_working_set_t * data_set)
{
    const char *id = NULL;
    pe_node_t *node = NULL;
    xmlNode *lrm_rscs = NULL;
    xmlNode *status = get_object_root(XML_CIB_TAG_STATUS, data_set->input);

    xmlNode *node_state = NULL;

    for (node_state = pcmk__xe_first_child(status); node_state != NULL;
         node_state = pcmk__xe_next(node_state)) {

        if (pcmk__str_eq((const char *)node_state->name, XML_CIB_TAG_STATE,
                         pcmk__str_none)) {
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
            if (node->details->online
                || pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
                xmlNode *rsc_entry = NULL;

                for (rsc_entry = pcmk__xe_first_child(lrm_rscs);
                     rsc_entry != NULL;
                     rsc_entry = pcmk__xe_next(rsc_entry)) {

                    if (pcmk__str_eq((const char *)rsc_entry->name, XML_LRM_TAG_RESOURCE, pcmk__str_none)) {

                        if (xml_has_children(rsc_entry)) {
                            GList *gIter = NULL;
                            GList *result = NULL;
                            const char *rsc_id = ID(rsc_entry);

                            CRM_CHECK(rsc_id != NULL, return);

                            result = find_rsc_list(NULL, NULL, rsc_id, TRUE, FALSE, data_set);
                            for (gIter = result; gIter != NULL; gIter = gIter->next) {
                                pe_resource_t *rsc = (pe_resource_t *) gIter->data;

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

static void
apply_placement_constraints(pe_working_set_t * data_set)
{
    for (GList *gIter = data_set->placement_constraints;
         gIter != NULL; gIter = gIter->next) {
        pe__location_t *cons = gIter->data;

        cons->rsc_lh->cmds->rsc_location(cons->rsc_lh, cons);
    }
}

static gboolean
failcount_clear_action_exists(pe_node_t * node, pe_resource_t * rsc)
{
    gboolean rc = FALSE;
    GList *list = pe__resource_actions(rsc, node, CRM_OP_CLEAR_FAILCOUNT, TRUE);

    if (list) {
        rc = TRUE;
    }
    g_list_free(list);
    return rc;
}

static void
common_apply_stickiness(pe_resource_t * rsc, pe_node_t * node, pe_working_set_t * data_set)
{
    if (rsc->children) {
        GList *gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

            common_apply_stickiness(child_rsc, node, data_set);
        }
        return;
    }

    if (pcmk_is_set(rsc->flags, pe_rsc_managed)
        && rsc->stickiness != 0 && pcmk__list_of_1(rsc->running_on)) {
        pe_node_t *current = pe_find_node_id(rsc->running_on, node->details->id);
        pe_node_t *match = pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);

        if (current == NULL) {

        } else if ((match != NULL)
                   || pcmk_is_set(data_set->flags, pe_flag_symmetric_cluster)) {
            pe_resource_t *sticky_rsc = rsc;

            resource_location(sticky_rsc, node, rsc->stickiness, "stickiness", data_set);
            pe_rsc_debug(sticky_rsc, "Resource %s: preferring current location"
                         " (node=%s, weight=%d)", sticky_rsc->id,
                         node->details->uname, rsc->stickiness);
        } else {
            GHashTableIter iter;
            pe_node_t *nIter = NULL;

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
     * node if the failcount is being reset anyway.
     *
     * @TODO A clear_failcount operation can be scheduled in stage4() via
     * check_actions_for(), or in stage5() via check_params(). This runs in
     * stage2(), so it cannot detect those, meaning we might check the migration
     * threshold when we shouldn't -- worst case, we stop or move the resource,
     * then move it back next transition.
     */
    if (failcount_clear_action_exists(node, rsc) == FALSE) {
        pe_resource_t *failed = NULL;

        if (pcmk__threshold_reached(rsc, node, data_set, &failed)) {
            resource_location(failed, node, -INFINITY, "__fail_limit__",
                              data_set);
        }
    }
}

void
complex_set_cmds(pe_resource_t * rsc)
{
    GList *gIter = rsc->children;

    rsc->cmds = &resource_class_alloc_functions[rsc->variant];

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        complex_set_cmds(child_rsc);
    }
}

void
set_alloc_actions(pe_working_set_t * data_set)
{

    GList *gIter = data_set->resources;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

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

    if (pcmk__starts_with(key, "#health")) {
        int score;

        /* Convert the value into an integer */
        score = char2score(value);

        /* Add it to the running total */
        *system_health = pe__add_scores(score, *system_health);
    }
}

static gboolean
apply_system_health(pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    const char *health_strategy = pe_pref(data_set->config_hash, "node-health-strategy");
    int base_health = 0;

    if (pcmk__str_eq(health_strategy, "none", pcmk__str_null_matches | pcmk__str_casei)) {
        /* Prevent any accidental health -> score translation */
        pcmk__score_red = 0;
        pcmk__score_yellow = 0;
        pcmk__score_green = 0;
        return TRUE;

    } else if (pcmk__str_eq(health_strategy, "migrate-on-red", pcmk__str_casei)) {

        /* Resources on nodes which have health values of red are
         * weighted away from that node.
         */
        pcmk__score_red = -INFINITY;
        pcmk__score_yellow = 0;
        pcmk__score_green = 0;

    } else if (pcmk__str_eq(health_strategy, "only-green", pcmk__str_casei)) {

        /* Resources on nodes which have health values of red or yellow
         * are forced away from that node.
         */
        pcmk__score_red = -INFINITY;
        pcmk__score_yellow = -INFINITY;
        pcmk__score_green = 0;

    } else if (pcmk__str_eq(health_strategy, "progressive", pcmk__str_casei)) {
        /* Same as the above, but use the r/y/g scores provided by the user
         * Defaults are provided by the pe_prefs table
         * Also, custom health "base score" can be used
         */
        base_health = char2score(pe_pref(data_set->config_hash,
                                         "node-health-base"));

    } else if (pcmk__str_eq(health_strategy, "custom", pcmk__str_casei)) {

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
        pe_node_t *node = (pe_node_t *) gIter->data;

        /* Search through the node hash table for system health entries. */
        g_hash_table_foreach(node->details->attrs, calculate_system_health, &system_health);

        crm_info(" Node %s has an combined system health of %d",
                 node->details->uname, system_health);

        /* If the health is non-zero, then create a new location constraint so
         * that the weight will be added later on.
         */
        if (system_health != 0) {

            GList *gIter2 = data_set->resources;

            for (; gIter2 != NULL; gIter2 = gIter2->next) {
                pe_resource_t *rsc = (pe_resource_t *) gIter2->data;

                pcmk__new_location(health_strategy, rsc, system_health, NULL,
                                   node, data_set);
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

    if (!pcmk_is_set(data_set->flags, pe_flag_have_status)) {
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
    pe_action_t *probe_node_complete = NULL;

    for (GList *gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;
        const char *probed = pe_node_attribute_raw(node, CRM_OP_PROBED);

        if (node->details->online == FALSE) {

            if (pe__is_remote_node(node) && node->details->remote_rsc
                && (get_remote_node_state(node) == remote_state_failed)) {

                pe_fence_node(data_set, node, "the connection is unrecoverable", FALSE);
            }
            continue;

        } else if (node->details->unclean) {
            continue;

        } else if (node->details->rsc_discovery_enabled == FALSE) {
            /* resource discovery is disabled for this node */
            continue;
        }

        if (probed != NULL && crm_is_true(probed) == FALSE) {
            pe_action_t *probe_op = custom_action(NULL, crm_strdup_printf("%s-%s", CRM_OP_REPROBE, node->details->uname),
                                                  CRM_OP_REPROBE, node, FALSE, TRUE, data_set);

            add_hash_param(probe_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
            continue;
        }

        for (GList *gIter2 = data_set->resources; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_resource_t *rsc = (pe_resource_t *) gIter2->data;

            rsc->cmds->create_probe(rsc, node, probe_node_complete, FALSE, data_set);
        }
    }
    return TRUE;
}

static void
rsc_discover_filter(pe_resource_t *rsc, pe_node_t *node)
{
    pe_resource_t *top = uber_parent(rsc);
    pe_node_t *match;

    if (rsc->exclusive_discover == FALSE && top->exclusive_discover == FALSE) {
        return;
    }

    g_list_foreach(rsc->children, (GFunc) rsc_discover_filter, node);

    match = g_hash_table_lookup(rsc->allowed_nodes, node->details->id);
    if (match && match->rsc_discover_mode != pe_discover_exclusive) {
        match->weight = -INFINITY;
    }
}

static time_t
shutdown_time(pe_node_t *node, pe_working_set_t *data_set)
{
    const char *shutdown = pe_node_attribute_raw(node, XML_CIB_ATTR_SHUTDOWN);
    time_t result = 0;

    if (shutdown) {
        long long result_ll;

        if (pcmk__scan_ll(shutdown, &result_ll, 0LL) == pcmk_rc_ok) {
            result = (time_t) result_ll;
        }
    }
    return result? result : get_effective_time(data_set);
}

static void
apply_shutdown_lock(pe_resource_t *rsc, pe_working_set_t *data_set)
{
    const char *class;

    // Only primitives and (uncloned) groups may be locked
    if (rsc->variant == pe_group) {
        g_list_foreach(rsc->children, (GFunc) apply_shutdown_lock, data_set);
    } else if (rsc->variant != pe_native) {
        return;
    }

    // Fence devices and remote connections can't be locked
    class = crm_element_value(rsc->xml, XML_AGENT_ATTR_CLASS);
    if (pcmk__str_eq(class, PCMK_RESOURCE_CLASS_STONITH, pcmk__str_null_matches)
        || pe__resource_is_remote_conn(rsc, data_set)) {
        return;
    }

    if (rsc->lock_node != NULL) {
        // The lock was obtained from resource history

        if (rsc->running_on != NULL) {
            /* The resource was started elsewhere even though it is now
             * considered locked. This shouldn't be possible, but as a
             * failsafe, we don't want to disturb the resource now.
             */
            pe_rsc_info(rsc,
                        "Cancelling shutdown lock because %s is already active",
                        rsc->id);
            pe__clear_resource_history(rsc, rsc->lock_node, data_set);
            rsc->lock_node = NULL;
            rsc->lock_time = 0;
        }

    // Only a resource active on exactly one node can be locked
    } else if (pcmk__list_of_1(rsc->running_on)) {
        pe_node_t *node = rsc->running_on->data;

        if (node->details->shutdown) {
            if (node->details->unclean) {
                pe_rsc_debug(rsc, "Not locking %s to unclean %s for shutdown",
                             rsc->id, node->details->uname);
            } else {
                rsc->lock_node = node;
                rsc->lock_time = shutdown_time(node, data_set);
            }
        }
    }

    if (rsc->lock_node == NULL) {
        // No lock needed
        return;
    }

    if (data_set->shutdown_lock > 0) {
        time_t lock_expiration = rsc->lock_time + data_set->shutdown_lock;

        pe_rsc_info(rsc, "Locking %s to %s due to shutdown (expires @%lld)",
                    rsc->id, rsc->lock_node->details->uname,
                    (long long) lock_expiration);
        pe__update_recheck_time(++lock_expiration, data_set);
    } else {
        pe_rsc_info(rsc, "Locking %s to %s due to shutdown",
                    rsc->id, rsc->lock_node->details->uname);
    }

    // If resource is locked to one node, ban it from all other nodes
    for (GList *item = data_set->nodes; item != NULL; item = item->next) {
        pe_node_t *node = item->data;

        if (strcmp(node->details->uname, rsc->lock_node->details->uname)) {
            resource_location(rsc, node, -CRM_SCORE_INFINITY,
                              XML_CONFIG_ATTR_SHUTDOWN_LOCK, data_set);
        }
    }
}

/*
 * \internal
 * \brief Stage 2 of cluster status: apply node-specific criteria
 *
 * Count known nodes, and apply location constraints, stickiness, and exclusive
 * resource discovery.
 */
gboolean
stage2(pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    if (pcmk_is_set(data_set->flags, pe_flag_shutdown_lock)) {
        g_list_foreach(data_set->resources, (GFunc) apply_shutdown_lock, data_set);
    }

    if (!pcmk_is_set(data_set->flags, pe_flag_no_compat)) {
        // @COMPAT API backward compatibility
        for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
            pe_node_t *node = (pe_node_t *) gIter->data;

            if (node && (node->weight >= 0) && node->details->online
                && (node->details->type != node_ping)) {
                data_set->max_valid_nodes++;
            }
        }
    }

    apply_placement_constraints(data_set);

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        GList *gIter2 = NULL;
        pe_node_t *node = (pe_node_t *) gIter->data;

        gIter2 = data_set->resources;
        for (; gIter2 != NULL; gIter2 = gIter2->next) {
            pe_resource_t *rsc = (pe_resource_t *) gIter2->data;

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

    GList *gIter = data_set->resources;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

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

static void *
convert_const_pointer(const void *ptr)
{
    /* Worst function ever */
    return (void *)ptr;
}

static gint
sort_rsc_process_order(gconstpointer a, gconstpointer b, gpointer data)
{
    int rc = 0;
    int r1_weight = -INFINITY;
    int r2_weight = -INFINITY;

    const char *reason = "existence";

    GList *nodes = (GList *) data;
    const pe_resource_t *resource1 = a;
    const pe_resource_t *resource2 = b;

    pe_node_t *r1_node = NULL;
    pe_node_t *r2_node = NULL;
    GList *gIter = NULL;
    GHashTable *r1_nodes = NULL;
    GHashTable *r2_nodes = NULL;

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

    r1_nodes = pcmk__native_merge_weights(convert_const_pointer(resource1),
                                          resource1->id, NULL, NULL, 1,
                                          pe_weights_forward | pe_weights_init);
    pe__show_node_weights(true, NULL, resource1->id, r1_nodes,
                          resource1->cluster);

    r2_nodes = pcmk__native_merge_weights(convert_const_pointer(resource2),
                                          resource2->id, NULL, NULL, 1,
                                          pe_weights_forward | pe_weights_init);
    pe__show_node_weights(true, NULL, resource2->id, r2_nodes,
                          resource2->cluster);

    /* Current location score */
    reason = "current location";
    r1_weight = -INFINITY;
    r2_weight = -INFINITY;

    if (resource1->running_on) {
        r1_node = pe__current_node(resource1);
        r1_node = g_hash_table_lookup(r1_nodes, r1_node->details->id);
        if (r1_node != NULL) {
            r1_weight = r1_node->weight;
        }
    }
    if (resource2->running_on) {
        r2_node = pe__current_node(resource2);
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
        pe_node_t *node = (pe_node_t *) gIter->data;

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
    GList *gIter = NULL;

    if (pcmk_is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        /* Allocate remote connection resources first (which will also allocate
         * any colocation dependencies). If the connection is migrating, always
         * prefer the partial migration target.
         */
        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *rsc = (pe_resource_t *) gIter->data;
            if (rsc->is_remote_node == FALSE) {
                continue;
            }
            pe_rsc_trace(rsc, "Allocating remote connection resource '%s'",
                         rsc->id);
            rsc->cmds->allocate(rsc, rsc->partial_migration_target, data_set);
        }
    }

    /* now do the rest of the resources */
    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;
        if (rsc->is_remote_node == TRUE) {
            continue;
        }
        pe_rsc_trace(rsc, "Allocating %s resource '%s'",
                     crm_element_name(rsc->xml), rsc->id);
        rsc->cmds->allocate(rsc, NULL, data_set);
    }
}

/* We always use pe_order_preserve with these convenience functions to exempt
 * internally generated constraints from the prohibition of user constraints
 * involving remote connection resources.
 *
 * The start ordering additionally uses pe_order_runnable_left so that the
 * specified action is not runnable if the start is not runnable.
 */

static inline void
order_start_then_action(pe_resource_t *lh_rsc, pe_action_t *rh_action,
                        enum pe_ordering extra, pe_working_set_t *data_set)
{
    if (lh_rsc && rh_action && data_set) {
        pcmk__new_ordering(lh_rsc, start_key(lh_rsc), NULL,
                           rh_action->rsc, NULL, rh_action,
                           pe_order_preserve|pe_order_runnable_left|extra,
                           data_set);
    }
}

static inline void
order_action_then_stop(pe_action_t *lh_action, pe_resource_t *rh_rsc,
                       enum pe_ordering extra, pe_working_set_t *data_set)
{
    if (lh_action && rh_rsc && data_set) {
        pcmk__new_ordering(lh_action->rsc, NULL, lh_action,
                           rh_rsc, stop_key(rh_rsc), NULL,
                           pe_order_preserve|extra, data_set);
    }
}

// Clear fail counts for orphaned rsc on all online nodes
static void
cleanup_orphans(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (node->details->online
            && pe_get_failcount(node, rsc, NULL, pe_fc_effective, NULL,
                                data_set)) {

            pe_action_t *clear_op = NULL;

            clear_op = pe__clear_failcount(rsc, node, "it is orphaned",
                                           data_set);

            /* We can't use order_action_then_stop() here because its
             * pe_order_preserve breaks things
             */
            pcmk__new_ordering(clear_op->rsc, NULL, clear_op,
                               rsc, stop_key(rsc), NULL,
                               pe_order_optional, data_set);
        }
    }
}

gboolean
stage5(pe_working_set_t * data_set)
{
    pcmk__output_t *out = data_set->priv;
    GList *gIter = NULL;

    if (!pcmk__str_eq(data_set->placement_strategy, "default", pcmk__str_casei)) {
        GList *nodes = g_list_copy(data_set->nodes);

        nodes = sort_nodes_by_weight(nodes, NULL, data_set);
        data_set->resources =
            g_list_sort_with_data(data_set->resources, sort_rsc_process_order, nodes);

        g_list_free(nodes);
    }

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (pcmk_is_set(data_set->flags, pe_flag_show_utilization)) {
            out->message(out, "node-capacity", node, "Original");
        }
    }

    crm_trace("Allocating services");
    /* Take (next) highest resource, assign it and create its actions */

    allocate_resources(data_set);

    gIter = data_set->nodes;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        if (pcmk_is_set(data_set->flags, pe_flag_show_utilization)) {
            out->message(out, "node-capacity", node, "Remaining");
        }
    }

    // Process deferred action checks
    pe__foreach_param_check(data_set, check_params);
    pe__free_param_checks(data_set);

    if (pcmk_is_set(data_set->flags, pe_flag_startup_probes)) {
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
    if (pcmk_is_set(data_set->flags, pe_flag_stop_rsc_orphans)) {
        for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
            pe_resource_t *rsc = (pe_resource_t *) gIter->data;

            /* There's no need to recurse into rsc->children because those
             * should just be unallocated clone instances.
             */
            if (pcmk_is_set(rsc->flags, pe_rsc_orphan)) {
                cleanup_orphans(rsc, data_set);
            }
        }
    }

    crm_trace("Creating actions");

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        rsc->cmds->create_actions(rsc, data_set);
    }

    crm_trace("Creating done");
    return TRUE;
}

static gboolean
is_managed(const pe_resource_t * rsc)
{
    GList *gIter = rsc->children;

    if (pcmk_is_set(rsc->flags, pe_rsc_managed)) {
        return TRUE;
    }

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *child_rsc = (pe_resource_t *) gIter->data;

        if (is_managed(child_rsc)) {
            return TRUE;
        }
    }

    return FALSE;
}

static gboolean
any_managed_resources(pe_working_set_t * data_set)
{

    GList *gIter = data_set->resources;

    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

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
    pe_action_t *dc_down = NULL;
    pe_action_t *stonith_op = NULL;
    gboolean integrity_lost = FALSE;
    gboolean need_stonith = TRUE;
    GList *gIter;
    GList *stonith_ops = NULL;
    GList *shutdown_ops = NULL;

    /* Remote ordering constraints need to happen prior to calculating fencing
     * because it is one more place we will mark the node as dirty.
     *
     * A nice side effect of doing them early is that apply_*_ordering() can be
     * simpler because pe_fence_node() has already done some of the work.
     */
    crm_trace("Creating remote ordering constraints");
    apply_remote_node_ordering(data_set);

    crm_trace("Processing fencing and shutdown cases");
    if (any_managed_resources(data_set) == FALSE) {
        crm_notice("Delaying fencing operations until there are resources to manage");
        need_stonith = FALSE;
    }

    /* Check each node for stonith/shutdown */
    for (gIter = data_set->nodes; gIter != NULL; gIter = gIter->next) {
        pe_node_t *node = (pe_node_t *) gIter->data;

        /* Guest nodes are "fenced" by recovering their container resource,
         * so handle them separately.
         */
        if (pe__is_guest_node(node)) {
            if (node->details->remote_requires_reset && need_stonith
                && pe_can_fence(data_set, node)) {
                pcmk__fence_guest(node, data_set);
            }
            continue;
        }

        stonith_op = NULL;

        if (node->details->unclean
            && need_stonith && pe_can_fence(data_set, node)) {

            stonith_op = pe_fence_op(node, NULL, FALSE, "node is unclean", FALSE, data_set);
            pe_warn("Scheduling Node %s for STONITH", node->details->uname);

            pcmk__order_vs_fence(stonith_op, data_set);

            if (node->details->is_dc) {
                // Remember if the DC is being fenced
                dc_down = stonith_op;

            } else {

                if (!pcmk_is_set(data_set->flags, pe_flag_concurrent_fencing)
                    && (stonith_ops != NULL)) {
                    /* Concurrent fencing is disabled, so order each non-DC
                     * fencing in a chain. If there is any DC fencing or
                     * shutdown, it will be ordered after the last action in the
                     * chain later.
                     */
                    order_actions((pe_action_t *) stonith_ops->data,
                                  stonith_op, pe_order_optional);
                }

                // Remember all non-DC fencing actions in a separate list
                stonith_ops = g_list_prepend(stonith_ops, stonith_op);
            }

        } else if (node->details->online && node->details->shutdown &&
                /* TODO define what a shutdown op means for a remote node.
                 * For now we do not send shutdown operations for remote nodes, but
                 * if we can come up with a good use for this in the future, we will. */
                    pe__is_guest_or_remote_node(node) == FALSE) {

            pe_action_t *down_op = sched_shutdown_op(node, data_set);

            if (node->details->is_dc) {
                // Remember if the DC is being shut down
                dc_down = down_op;
            } else {
                // Remember non-DC shutdowns for later ordering
                shutdown_ops = g_list_prepend(shutdown_ops, down_op);
            }
        }

        if (node->details->unclean && stonith_op == NULL) {
            integrity_lost = TRUE;
            pe_warn("Node %s is unclean!", node->details->uname);
        }
    }

    if (integrity_lost) {
        if (!pcmk_is_set(data_set->flags, pe_flag_stonith_enabled)) {
            pe_warn("YOUR RESOURCES ARE NOW LIKELY COMPROMISED");
            pe_err("ENABLE STONITH TO KEEP YOUR RESOURCES SAFE");

        } else if (!pcmk_is_set(data_set->flags, pe_flag_have_quorum)) {
            crm_notice("Cannot fence unclean nodes until quorum is"
                       " attained (or no-quorum-policy is set to ignore)");
        }
    }

    if (dc_down != NULL) {
        /* Order any non-DC shutdowns before any DC shutdown, to avoid repeated
         * DC elections. However, we don't want to order non-DC shutdowns before
         * a DC *fencing*, because even though we don't want a node that's
         * shutting down to become DC, the DC fencing could be ordered before a
         * clone stop that's also ordered before the shutdowns, thus leading to
         * a graph loop.
         */
        if (pcmk__str_eq(dc_down->task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
            for (gIter = shutdown_ops; gIter != NULL; gIter = gIter->next) {
                pe_action_t *node_stop = (pe_action_t *) gIter->data;

                crm_debug("Ordering shutdown on %s before %s on DC %s",
                          node_stop->node->details->uname,
                          dc_down->task, dc_down->node->details->uname);

                order_actions(node_stop, dc_down, pe_order_optional);
            }
        }

        // Order any non-DC fencing before any DC fencing or shutdown

        if (pcmk_is_set(data_set->flags, pe_flag_concurrent_fencing)) {
            /* With concurrent fencing, order each non-DC fencing action
             * separately before any DC fencing or shutdown.
             */
            for (gIter = stonith_ops; gIter != NULL; gIter = gIter->next) {
                order_actions((pe_action_t *) gIter->data, dc_down,
                              pe_order_optional);
            }
        } else if (stonith_ops) {
            /* Without concurrent fencing, the non-DC fencing actions are
             * already ordered relative to each other, so we just need to order
             * the DC fencing after the last action in the chain (which is the
             * first item in the list).
             */
            order_actions((pe_action_t *) stonith_ops->data, dc_down,
                          pe_order_optional);
        }
    }
    g_list_free(stonith_ops);
    g_list_free(shutdown_ops);
    return TRUE;
}

/*
 * Determine the sets of independent actions and the correct order for the
 *  actions in each set.
 *
 * Mark dependencies of un-runnable actions un-runnable
 *
 */
static GList *
find_actions_by_task(GList *actions, pe_resource_t * rsc, const char *original_key)
{
    GList *list = NULL;

    list = find_actions(actions, original_key, NULL);
    if (list == NULL) {
        /* we're potentially searching a child of the original resource */
        char *key = NULL;
        char *task = NULL;
        guint interval_ms = 0;

        if (parse_op_key(original_key, NULL, &task, &interval_ms)) {
            key = pcmk__op_key(rsc->id, task, interval_ms);
            list = find_actions(actions, key, NULL);

        } else {
            crm_err("search key: %s", original_key);
        }

        free(key);
        free(task);
    }

    return list;
}

static void
rsc_order_then(pe_action_t *lh_action, pe_resource_t *rsc,
               pe__ordering_t *order)
{
    GList *gIter = NULL;
    GList *rh_actions = NULL;
    pe_action_t *rh_action = NULL;
    enum pe_ordering type;

    CRM_CHECK(rsc != NULL, return);
    CRM_CHECK(order != NULL, return);

    type = order->type;
    rh_action = order->rh_action;
    crm_trace("Applying ordering constraint %d (then: %s)", order->id, rsc->id);

    if (rh_action != NULL) {
        rh_actions = g_list_prepend(NULL, rh_action);

    } else if (rsc != NULL) {
        rh_actions = find_actions_by_task(rsc->actions, rsc, order->rh_action_task);
    }

    if (rh_actions == NULL) {
        pe_rsc_trace(rsc,
                     "Ignoring constraint %d: then (%s for %s) not found",
                     order->id, order->rh_action_task, rsc->id);
        return;
    }

    if ((lh_action != NULL) && (lh_action->rsc == rsc)
        && pcmk_is_set(lh_action->flags, pe_action_dangle)) {

        pe_rsc_trace(rsc, "Detected dangling operation %s -> %s", lh_action->uuid,
                     order->rh_action_task);
        pe__clear_order_flags(type, pe_order_implies_then);
    }

    gIter = rh_actions;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *rh_action_iter = (pe_action_t *) gIter->data;

        if (lh_action) {
            order_actions(lh_action, rh_action_iter, type);

        } else if (type & pe_order_implies_then) {
            pe__clear_action_flags(rh_action_iter, pe_action_runnable);
            crm_warn("Unrunnable %s 0x%.6x", rh_action_iter->uuid, type);
        } else {
            crm_warn("neither %s 0x%.6x", rh_action_iter->uuid, type);
        }
    }

    g_list_free(rh_actions);
}

static void
rsc_order_first(pe_resource_t *lh_rsc, pe__ordering_t *order,
                pe_working_set_t *data_set)
{
    GList *lh_actions = NULL;
    pe_action_t *lh_action = order->lh_action;
    pe_resource_t *rh_rsc = order->rh_rsc;

    CRM_ASSERT(lh_rsc != NULL);
    pe_rsc_trace(lh_rsc, "Applying ordering constraint %d (first: %s)",
                 order->id, lh_rsc->id);

    if (lh_action != NULL) {
        lh_actions = g_list_prepend(NULL, lh_action);

    } else {
        lh_actions = find_actions_by_task(lh_rsc->actions, lh_rsc, order->lh_action_task);
    }

    if ((lh_actions == NULL) && (lh_rsc == rh_rsc)) {
        pe_rsc_trace(lh_rsc,
                     "Ignoring constraint %d: first (%s for %s) not found",
                     order->id, order->lh_action_task, lh_rsc->id);

    } else if (lh_actions == NULL) {
        char *key = NULL;
        char *op_type = NULL;
        guint interval_ms = 0;

        parse_op_key(order->lh_action_task, NULL, &op_type, &interval_ms);
        key = pcmk__op_key(lh_rsc->id, op_type, interval_ms);

        if (lh_rsc->fns->state(lh_rsc, TRUE) == RSC_ROLE_STOPPED && pcmk__str_eq(op_type, RSC_STOP, pcmk__str_casei)) {
            free(key);
            pe_rsc_trace(lh_rsc,
                         "Ignoring constraint %d: first (%s for %s) not found",
                         order->id, order->lh_action_task, lh_rsc->id);

        } else if ((lh_rsc->fns->state(lh_rsc, TRUE) == RSC_ROLE_UNPROMOTED)
                   && pcmk__str_eq(op_type, RSC_DEMOTE, pcmk__str_casei)) {
            free(key);
            pe_rsc_trace(lh_rsc,
                         "Ignoring constraint %d: first (%s for %s) not found",
                         order->id, order->lh_action_task, lh_rsc->id);

        } else {
            pe_rsc_trace(lh_rsc,
                         "Creating first (%s for %s) for constraint %d ",
                         order->lh_action_task, lh_rsc->id, order->id);
            lh_action = custom_action(lh_rsc, key, op_type, NULL, TRUE, TRUE, data_set);
            lh_actions = g_list_prepend(NULL, lh_action);
        }

        free(op_type);
    }

    if (rh_rsc == NULL) {
        if (order->rh_action == NULL) {
            pe_rsc_trace(lh_rsc, "Ignoring constraint %d: then not found",
                         order->id);
            return;
        }
        rh_rsc = order->rh_action->rsc;
    }
    for (GList *gIter = lh_actions; gIter != NULL; gIter = gIter->next) {
        lh_action = (pe_action_t *) gIter->data;

        if (rh_rsc == NULL) {
            order_actions(lh_action, order->rh_action, order->type);

        } else {
            rsc_order_then(lh_action, rh_rsc, order);
        }
    }

    g_list_free(lh_actions);
}

static int
is_recurring_action(pe_action_t *action)
{
    guint interval_ms;

    if (pcmk__guint_from_hash(action->meta,
                              XML_LRM_ATTR_INTERVAL_MS, 0,
                              &interval_ms) != pcmk_rc_ok) {
        return 0;
    }
    return (interval_ms > 0);
}

static void
apply_container_ordering(pe_action_t *action, pe_working_set_t *data_set)
{
    /* VMs are also classified as containers for these purposes... in
     * that they both involve a 'thing' running on a real or remote
     * cluster node.
     *
     * This allows us to be smarter about the type and extent of
     * recovery actions required in various scenarios
     */
    pe_resource_t *remote_rsc = NULL;
    pe_resource_t *container = NULL;
    enum action_tasks task = text2task(action->task);

    CRM_ASSERT(action->rsc);
    CRM_ASSERT(action->node);
    CRM_ASSERT(pe__is_guest_or_remote_node(action->node));

    remote_rsc = action->node->details->remote_rsc;
    CRM_ASSERT(remote_rsc);

    container = remote_rsc->container;
    CRM_ASSERT(container);

    if (pcmk_is_set(container->flags, pe_rsc_failed)) {
        pe_fence_node(data_set, action->node, "container failed", FALSE);
    }

    crm_trace("Order %s action %s relative to %s%s for %s%s",
              action->task, action->uuid,
              pcmk_is_set(remote_rsc->flags, pe_rsc_failed)? "failed " : "",
              remote_rsc->id,
              pcmk_is_set(container->flags, pe_rsc_failed)? "failed " : "",
              container->id);

    if (pcmk__strcase_any_of(action->task, CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED, NULL)) {
        /* Migration ops map to "no_action", but we need to apply the same
         * ordering as for stop or demote (see get_router_node()).
         */
        task = stop_rsc;
    }

    switch (task) {
        case start_rsc:
        case action_promote:
            /* Force resource recovery if the container is recovered */
            order_start_then_action(container, action, pe_order_implies_then,
                                    data_set);

            /* Wait for the connection resource to be up too */
            order_start_then_action(remote_rsc, action, pe_order_none,
                                    data_set);
            break;

        case stop_rsc:
        case action_demote:
            if (pcmk_is_set(container->flags, pe_rsc_failed)) {
                /* When the container representing a guest node fails, any stop
                 * or demote actions for resources running on the guest node
                 * are implied by the container stopping. This is similar to
                 * how fencing operations work for cluster nodes and remote
                 * nodes.
                 */
            } else {
                /* Ensure the operation happens before the connection is brought
                 * down.
                 *
                 * If we really wanted to, we could order these after the
                 * connection start, IFF the container's current role was
                 * stopped (otherwise we re-introduce an ordering loop when the
                 * connection is restarting).
                 */
                order_action_then_stop(action, remote_rsc, pe_order_none,
                                       data_set);
            }
            break;

        default:
            /* Wait for the connection resource to be up */
            if (is_recurring_action(action)) {
                /* In case we ever get the recovery logic wrong, force
                 * recurring monitors to be restarted, even if just
                 * the connection was re-established
                 */
                if(task != no_action) {
                    order_start_then_action(remote_rsc, action,
                                            pe_order_implies_then, data_set);
                }
            } else {
                order_start_then_action(remote_rsc, action, pe_order_none,
                                        data_set);
            }
            break;
    }
}

static enum remote_connection_state
get_remote_node_state(pe_node_t *node) 
{
    pe_resource_t *remote_rsc = NULL;
    pe_node_t *cluster_node = NULL;

    CRM_ASSERT(node);

    remote_rsc = node->details->remote_rsc;
    CRM_ASSERT(remote_rsc);

    cluster_node = pe__current_node(remote_rsc);

    /* If the cluster node the remote connection resource resides on
     * is unclean or went offline, we can't process any operations
     * on that remote node until after it starts elsewhere.
     */
    if(remote_rsc->next_role == RSC_ROLE_STOPPED || remote_rsc->allocated_to == NULL) {
        /* The connection resource is not going to run anywhere */

        if (cluster_node && cluster_node->details->unclean) {
            /* The remote connection is failed because its resource is on a
             * failed node and can't be recovered elsewhere, so we must fence.
             */
            return remote_state_failed;
        }

        if (!pcmk_is_set(remote_rsc->flags, pe_rsc_failed)) {
            /* Connection resource is cleanly stopped */
            return remote_state_stopped;
        }

        /* Connection resource is failed */

        if ((remote_rsc->next_role == RSC_ROLE_STOPPED)
            && remote_rsc->remote_reconnect_ms
            && node->details->remote_was_fenced
            && !pe__shutdown_requested(node)) {

            /* We won't know whether the connection is recoverable until the
             * reconnect interval expires and we reattempt connection.
             */
            return remote_state_unknown;
        }

        /* The remote connection is in a failed state. If there are any
         * resources known to be active on it (stop) or in an unknown state
         * (probe), we must assume the worst and fence it.
         */
        return remote_state_failed;

    } else if (cluster_node == NULL) {
        /* Connection is recoverable but not currently running anywhere, see if we can recover it first */
        return remote_state_unknown;

    } else if(cluster_node->details->unclean == TRUE
              || cluster_node->details->online == FALSE) {
        /* Connection is running on a dead node, see if we can recover it first */
        return remote_state_resting;

    } else if (pcmk__list_of_multiple(remote_rsc->running_on)
               && remote_rsc->partial_migration_source
               && remote_rsc->partial_migration_target) {
        /* We're in the middle of migrating a connection resource,
         * wait until after the resource migrates before performing
         * any actions.
         */
        return remote_state_resting;

    }
    return remote_state_alive;
}

/*!
 * \internal
 * \brief Order actions on remote node relative to actions for the connection
 */
static void
apply_remote_ordering(pe_action_t *action, pe_working_set_t *data_set)
{
    pe_resource_t *remote_rsc = NULL;
    enum action_tasks task = text2task(action->task);
    enum remote_connection_state state = get_remote_node_state(action->node);

    enum pe_ordering order_opts = pe_order_none;

    if (action->rsc == NULL) {
        return;
    }

    CRM_ASSERT(action->node);
    CRM_ASSERT(pe__is_guest_or_remote_node(action->node));

    remote_rsc = action->node->details->remote_rsc;
    CRM_ASSERT(remote_rsc);

    crm_trace("Order %s action %s relative to %s%s (state: %s)",
              action->task, action->uuid,
              pcmk_is_set(remote_rsc->flags, pe_rsc_failed)? "failed " : "",
              remote_rsc->id, state2text(state));

    if (pcmk__strcase_any_of(action->task, CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED, NULL)) {
        /* Migration ops map to "no_action", but we need to apply the same
         * ordering as for stop or demote (see get_router_node()).
         */
        task = stop_rsc;
    }

    switch (task) {
        case start_rsc:
        case action_promote:
            order_opts = pe_order_none;

            if (state == remote_state_failed) {
                /* Force recovery, by making this action required */
                pe__set_order_flags(order_opts, pe_order_implies_then);
            }

            /* Ensure connection is up before running this action */
            order_start_then_action(remote_rsc, action, order_opts, data_set);
            break;

        case stop_rsc:
            if(state == remote_state_alive) {
                order_action_then_stop(action, remote_rsc,
                                       pe_order_implies_first, data_set);

            } else if(state == remote_state_failed) {
                /* The resource is active on the node, but since we don't have a
                 * valid connection, the only way to stop the resource is by
                 * fencing the node. There is no need to order the stop relative
                 * to the remote connection, since the stop will become implied
                 * by the fencing.
                 */
                pe_fence_node(data_set, action->node, "resources are active and the connection is unrecoverable", FALSE);

            } else if(remote_rsc->next_role == RSC_ROLE_STOPPED) {
                /* State must be remote_state_unknown or remote_state_stopped.
                 * Since the connection is not coming back up in this
                 * transition, stop this resource first.
                 */
                order_action_then_stop(action, remote_rsc,
                                       pe_order_implies_first, data_set);

            } else {
                /* The connection is going to be started somewhere else, so
                 * stop this resource after that completes.
                 */
                order_start_then_action(remote_rsc, action, pe_order_none, data_set);
            }
            break;

        case action_demote:
            /* Only order this demote relative to the connection start if the
             * connection isn't being torn down. Otherwise, the demote would be
             * blocked because the connection start would not be allowed.
             */
            if(state == remote_state_resting || state == remote_state_unknown) {
                order_start_then_action(remote_rsc, action, pe_order_none,
                                        data_set);
            } /* Otherwise we can rely on the stop ordering */
            break;

        default:
            /* Wait for the connection resource to be up */
            if (is_recurring_action(action)) {
                /* In case we ever get the recovery logic wrong, force
                 * recurring monitors to be restarted, even if just
                 * the connection was re-established
                 */
                order_start_then_action(remote_rsc, action,
                                        pe_order_implies_then, data_set);

            } else {
                pe_node_t *cluster_node = pe__current_node(remote_rsc);

                if(task == monitor_rsc && state == remote_state_failed) {
                    /* We would only be here if we do not know the
                     * state of the resource on the remote node.
                     * Since we have no way to find out, it is
                     * necessary to fence the node.
                     */
                    pe_fence_node(data_set, action->node, "resources are in an unknown state and the connection is unrecoverable", FALSE);
                }

                if(cluster_node && state == remote_state_stopped) {
                    /* The connection is currently up, but is going
                     * down permanently.
                     *
                     * Make sure we check services are actually
                     * stopped _before_ we let the connection get
                     * closed
                     */
                    order_action_then_stop(action, remote_rsc,
                                           pe_order_runnable_left, data_set);

                } else {
                    order_start_then_action(remote_rsc, action, pe_order_none,
                                            data_set);
                }
            }
            break;
    }
}

static void
apply_remote_node_ordering(pe_working_set_t *data_set)
{
    if (!pcmk_is_set(data_set->flags, pe_flag_have_remote_nodes)) {
        return;
    }

    for (GList *gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;
        pe_resource_t *remote = NULL;

        // We are only interested in resource actions
        if (action->rsc == NULL) {
            continue;
        }

        /* Special case: If we are clearing the failcount of an actual
         * remote connection resource, then make sure this happens before
         * any start of the resource in this transition.
         */
        if (action->rsc->is_remote_node &&
            pcmk__str_eq(action->task, CRM_OP_CLEAR_FAILCOUNT, pcmk__str_casei)) {

            pcmk__new_ordering(action->rsc, NULL, action, action->rsc,
                               pcmk__op_key(action->rsc->id, RSC_START, 0),
                               NULL, pe_order_optional, data_set);

            continue;
        }

        // We are only interested in actions allocated to a node
        if (action->node == NULL) {
            continue;
        }

        if (!pe__is_guest_or_remote_node(action->node)) {
            continue;
        }

        /* We are only interested in real actions.
         *
         * @TODO This is probably wrong; pseudo-actions might be converted to
         * real actions and vice versa later in update_actions() at the end of
         * stage7().
         */
        if (pcmk_is_set(action->flags, pe_action_pseudo)) {
            continue;
        }

        remote = action->node->details->remote_rsc;
        if (remote == NULL) {
            // Orphaned
            continue;
        }

        /* Another special case: if a resource is moving to a Pacemaker Remote
         * node, order the stop on the original node after any start of the
         * remote connection. This ensures that if the connection fails to
         * start, we leave the resource running on the original node.
         */
        if (pcmk__str_eq(action->task, RSC_START, pcmk__str_casei)) {
            for (GList *item = action->rsc->actions; item != NULL;
                 item = item->next) {
                pe_action_t *rsc_action = item->data;

                if ((rsc_action->node->details != action->node->details)
                    && pcmk__str_eq(rsc_action->task, RSC_STOP, pcmk__str_casei)) {
                    pcmk__new_ordering(remote, start_key(remote), NULL,
                                       action->rsc, NULL, rsc_action,
                                       pe_order_optional, data_set);
                }
            }
        }

        /* The action occurs across a remote connection, so create
         * ordering constraints that guarantee the action occurs while the node
         * is active (after start, before stop ... things like that).
         *
         * This is somewhat brittle in that we need to make sure the results of
         * this ordering are compatible with the result of get_router_node().
         * It would probably be better to add XML_LRM_ATTR_ROUTER_NODE as part
         * of this logic rather than action2xml().
         */
        if (remote->container) {
            crm_trace("Container ordering for %s", action->uuid);
            apply_container_ordering(action, data_set);

        } else {
            crm_trace("Remote ordering for %s", action->uuid);
            apply_remote_ordering(action, data_set);
        }
    }
}

static gboolean
order_first_probe_unneeded(pe_action_t * probe, pe_action_t * rh_action)
{
    /* No need to probe the resource on the node that is being
     * unfenced. Otherwise it might introduce transition loop
     * since probe will be performed after the node is
     * unfenced.
     */
    if (pcmk__str_eq(rh_action->task, CRM_OP_FENCE, pcmk__str_casei)
         && probe->node && rh_action->node
         && probe->node->details == rh_action->node->details) {
        const char *op = g_hash_table_lookup(rh_action->meta, "stonith_action");

        if (pcmk__str_eq(op, "on", pcmk__str_casei)) {
            return TRUE;
        }
    }

    // Shutdown waits for probe to complete only if it's on the same node
    if ((pcmk__str_eq(rh_action->task, CRM_OP_SHUTDOWN, pcmk__str_casei))
        && probe->node && rh_action->node
        && probe->node->details != rh_action->node->details) {
        return TRUE;
    }
    return FALSE;
}

static void
order_first_probes_imply_stops(pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    for (gIter = data_set->ordering_constraints; gIter != NULL; gIter = gIter->next) {
        pe__ordering_t *order = gIter->data;
        enum pe_ordering order_type = pe_order_optional;

        pe_resource_t *lh_rsc = order->lh_rsc;
        pe_resource_t *rh_rsc = order->rh_rsc;
        pe_action_t *lh_action = order->lh_action;
        pe_action_t *rh_action = order->rh_action;
        const char *lh_action_task = order->lh_action_task;
        const char *rh_action_task = order->rh_action_task;

        GList *probes = NULL;
        GList *rh_actions = NULL;

        GList *pIter = NULL;

        if (lh_rsc == NULL) {
            continue;

        } else if (rh_rsc && lh_rsc == rh_rsc) {
            continue;
        }

        if (lh_action == NULL && lh_action_task == NULL) {
            continue;
        }

        if (rh_action == NULL && rh_action_task == NULL) {
            continue;
        }

        /* Technically probe is expected to return "not running", which could be
         * the alternative of stop action if the status of the resource is
         * unknown yet.
         */
        if (lh_action && !pcmk__str_eq(lh_action->task, RSC_STOP, pcmk__str_casei)) {
            continue;

        } else if (lh_action == NULL
                   && lh_action_task
                   && !pcmk__ends_with(lh_action_task, "_" RSC_STOP "_0")) {
            continue;
        }

        /* Do not probe the resource inside of a stopping container. Otherwise
         * it might introduce transition loop since probe will be performed
         * after the container starts again.
         */
        if (rh_rsc && lh_rsc->container == rh_rsc) {
            if (rh_action && pcmk__str_eq(rh_action->task, RSC_STOP, pcmk__str_casei)) {
                continue;

            } else if (rh_action == NULL && rh_action_task
                       && pcmk__ends_with(rh_action_task,"_" RSC_STOP "_0")) {
                continue;
            }
        }

        if (order->type == pe_order_none) {
            continue;
        }

        // Preserve the order options for future filtering
        if (pcmk_is_set(order->type, pe_order_apply_first_non_migratable)) {
            pe__set_order_flags(order_type,
                                pe_order_apply_first_non_migratable);
        }

        if (pcmk_is_set(order->type, pe_order_same_node)) {
            pe__set_order_flags(order_type, pe_order_same_node);
        }

        // Keep the order types for future filtering
        if (order->type == pe_order_anti_colocation
                   || order->type == pe_order_load) {
            order_type = order->type;
        }

        probes = pe__resource_actions(lh_rsc, NULL, RSC_STATUS, FALSE);
        if (probes == NULL) {
            continue;
        }

        if (rh_action) {
            rh_actions = g_list_prepend(rh_actions, rh_action);

        } else if (rh_rsc && rh_action_task) {
            rh_actions = find_actions(rh_rsc->actions, rh_action_task, NULL);
        }

        if (rh_actions == NULL) {
            g_list_free(probes);
            continue;
        }

        crm_trace("Processing for LH probe based on ordering constraint %s -> %s"
                  " (id=%d, type=%.6x)",
                  lh_action ? lh_action->uuid : lh_action_task,
                  rh_action ? rh_action->uuid : rh_action_task,
                  order->id, order->type);

        for (pIter = probes; pIter != NULL; pIter = pIter->next) {
            pe_action_t *probe = (pe_action_t *) pIter->data;
            GList *rIter = NULL;

            for (rIter = rh_actions; rIter != NULL; rIter = rIter->next) {
                pe_action_t *rh_action_iter = (pe_action_t *) rIter->data;

                if (order_first_probe_unneeded(probe, rh_action_iter)) {
                    continue;
                }
                order_actions(probe, rh_action_iter, order_type);
            }
        }

        g_list_free(rh_actions);
        g_list_free(probes);
    }
}

static void
order_first_probe_then_restart_repromote(pe_action_t * probe,
                                         pe_action_t * after,
                                         pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    bool interleave = FALSE;
    pe_resource_t *compatible_rsc = NULL;

    if (probe == NULL
        || probe->rsc == NULL
        || probe->rsc->variant != pe_native) {
        return;
    }

    if (after == NULL
        // Avoid running into any possible loop
        || pcmk_is_set(after->flags, pe_action_tracking)) {
        return;
    }

    if (!pcmk__str_eq(probe->task, RSC_STATUS, pcmk__str_casei)) {
        return;
    }

    pe__set_action_flags(after, pe_action_tracking);

    crm_trace("Processing based on %s %s -> %s %s",
              probe->uuid,
              probe->node ? probe->node->details->uname: "",
              after->uuid,
              after->node ? after->node->details->uname : "");

    if (after->rsc
        /* Better not build a dependency directly with a clone/group.
         * We are going to proceed through the ordering chain and build
         * dependencies with its children.
         */
        && after->rsc->variant == pe_native
        && probe->rsc != after->rsc) {

            GList *then_actions = NULL;
            enum pe_ordering probe_order_type = pe_order_optional;

            if (pcmk__str_eq(after->task, RSC_START, pcmk__str_casei)) {
                then_actions = pe__resource_actions(after->rsc, NULL, RSC_STOP, FALSE);

            } else if (pcmk__str_eq(after->task, RSC_PROMOTE, pcmk__str_casei)) {
                then_actions = pe__resource_actions(after->rsc, NULL, RSC_DEMOTE, FALSE);
            }

            for (gIter = then_actions; gIter != NULL; gIter = gIter->next) {
                pe_action_t *then = (pe_action_t *) gIter->data;

                // Skip any pseudo action which for example is implied by fencing
                if (pcmk_is_set(then->flags, pe_action_pseudo)) {
                    continue;
                }

                order_actions(probe, then, probe_order_type);
            }
            g_list_free(then_actions);
    }

    if (after->rsc
        && after->rsc->variant > pe_group) {
        const char *interleave_s = g_hash_table_lookup(after->rsc->meta,
                                                       XML_RSC_ATTR_INTERLEAVE);

        interleave = crm_is_true(interleave_s);

        if (interleave) {
            /* For an interleaved clone, we should build a dependency only
             * with the relevant clone child.
             */
            compatible_rsc = find_compatible_child(probe->rsc,
                                                   after->rsc,
                                                   RSC_ROLE_UNKNOWN,
                                                   FALSE, data_set);
        }
    }

    for (gIter = after->actions_after; gIter != NULL; gIter = gIter->next) {
        pe_action_wrapper_t *after_wrapper = (pe_action_wrapper_t *) gIter->data;
        /* pe_order_implies_then is the reason why a required A.start
         * implies/enforces B.start to be required too, which is the cause of
         * B.restart/re-promote.
         *
         * Not sure about pe_order_implies_then_on_node though. It's now only
         * used for unfencing case, which tends to introduce transition
         * loops...
         */

        if (!pcmk_is_set(after_wrapper->type, pe_order_implies_then)) {
            /* The order type between a group/clone and its child such as
             * B.start-> B_child.start is:
             * pe_order_implies_first_printed | pe_order_runnable_left
             *
             * Proceed through the ordering chain and build dependencies with
             * its children.
             */
            if (after->rsc == NULL
                || after->rsc->variant < pe_group
                || probe->rsc->parent == after->rsc
                || after_wrapper->action->rsc == NULL
                || after_wrapper->action->rsc->variant > pe_group
                || after->rsc != after_wrapper->action->rsc->parent) {
                continue;
            }

            /* Proceed to the children of a group or a non-interleaved clone.
             * For an interleaved clone, proceed only to the relevant child.
             */
            if (after->rsc->variant > pe_group
                && interleave == TRUE
                && (compatible_rsc == NULL
                    || compatible_rsc != after_wrapper->action->rsc)) {
                continue;
            }
        }

        crm_trace("Proceeding through %s %s -> %s %s (type=0x%.6x)",
                  after->uuid,
                  after->node ? after->node->details->uname: "",
                  after_wrapper->action->uuid,
                  after_wrapper->action->node ? after_wrapper->action->node->details->uname : "",
                  after_wrapper->type);

        order_first_probe_then_restart_repromote(probe, after_wrapper->action, data_set);
    }
}

static void clear_actions_tracking_flag(pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (pcmk_is_set(action->flags, pe_action_tracking)) {
            pe__clear_action_flags(action, pe_action_tracking);
        }
    }
}

static void
order_first_rsc_probes(pe_resource_t * rsc, pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    GList *probes = NULL;

    g_list_foreach(rsc->children, (GFunc) order_first_rsc_probes, data_set);

    if (rsc->variant != pe_native) {
        return;
    }

    probes = pe__resource_actions(rsc, NULL, RSC_STATUS, FALSE);

    for (gIter = probes; gIter != NULL; gIter= gIter->next) {
        pe_action_t *probe = (pe_action_t *) gIter->data;
        GList *aIter = NULL;

        for (aIter = probe->actions_after; aIter != NULL; aIter = aIter->next) {
            pe_action_wrapper_t *after_wrapper = (pe_action_wrapper_t *) aIter->data;

            order_first_probe_then_restart_repromote(probe, after_wrapper->action, data_set);
            clear_actions_tracking_flag(data_set);
        }
    }

    g_list_free(probes);
}

static void
order_first_probes(pe_working_set_t * data_set)
{
    GList *gIter = NULL;

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        order_first_rsc_probes(rsc, data_set);
    }

    order_first_probes_imply_stops(data_set);
}

static void
order_then_probes(pe_working_set_t * data_set)
{
#if 0
    GList *gIter = NULL;

    for (gIter = data_set->resources; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

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
        pe_action_t *start = NULL;
        GList *actions = NULL;
        GList *probes = NULL;

        actions = pe__resource_actions(rsc, NULL, RSC_START, FALSE);

        if (actions) {
            start = actions->data;
            g_list_free(actions);
        }

        if(start == NULL) {
            crm_err("No start action for %s", rsc->id);
            continue;
        }

        probes = pe__resource_actions(rsc, NULL, RSC_STATUS, FALSE);

        for (actions = start->actions_before; actions != NULL; actions = actions->next) {
            pe_action_wrapper_t *before = (pe_action_wrapper_t *) actions->data;

            GList *pIter = NULL;
            pe_action_t *first = before->action;
            pe_resource_t *first_rsc = first->rsc;

            if(first->required_runnable_before) {
                GList *clone_actions = NULL;
                for (clone_actions = first->actions_before; clone_actions != NULL; clone_actions = clone_actions->next) {
                    before = (pe_action_wrapper_t *) clone_actions->data;

                    crm_trace("Testing %s -> %s (%p) for %s", first->uuid, before->action->uuid, before->action->rsc, start->uuid);

                    CRM_ASSERT(before->action->rsc);
                    first_rsc = before->action->rsc;
                    break;
                }

            } else if(!pcmk__str_eq(first->task, RSC_START, pcmk__str_casei)) {
                crm_trace("Not a start op %s for %s", first->uuid, start->uuid);
            }

            if(first_rsc == NULL) {
                continue;

            } else if(uber_parent(first_rsc) == uber_parent(start->rsc)) {
                crm_trace("Same parent %s for %s", first_rsc->id, start->uuid);
                continue;

            } else if(FALSE && pe_rsc_is_clone(uber_parent(first_rsc)) == FALSE) {
                crm_trace("Not a clone %s for %s", first_rsc->id, start->uuid);
                continue;
            }

            crm_err("Applying %s before %s %d", first->uuid, start->uuid, uber_parent(first_rsc)->variant);

            for (pIter = probes; pIter != NULL; pIter = pIter->next) {
                pe_action_t *probe = (pe_action_t *) pIter->data;

                crm_err("Ordering %s before %s", first->uuid, probe->uuid);
                order_actions(first, probe, pe_order_optional);
            }
        }
    }
#endif
}

static void
order_probes(pe_working_set_t * data_set)
{
    order_first_probes(data_set);
    order_then_probes(data_set);
}

gboolean
stage7(pe_working_set_t * data_set)
{
    pcmk__output_t *prev_out = data_set->priv;
    pcmk__output_t *out = NULL;
    GList *gIter = NULL;

    crm_trace("Applying ordering constraints");

    /* Don't ask me why, but apparently they need to be processed in
     * the order they were created in... go figure
     *
     * Also g_list_append() has horrendous performance characteristics
     * So we need to use g_list_prepend() and then reverse the list here
     */
    data_set->ordering_constraints = g_list_reverse(data_set->ordering_constraints);

    for (gIter = data_set->ordering_constraints; gIter != NULL; gIter = gIter->next) {
        pe__ordering_t *order = gIter->data;
        pe_resource_t *rsc = order->lh_rsc;

        if (rsc != NULL) {
            rsc_order_first(rsc, order, data_set);
            continue;
        }

        rsc = order->rh_rsc;
        if (rsc != NULL) {
            rsc_order_then(order->lh_action, rsc, order);

        } else {
            crm_trace("Applying ordering constraint %d (non-resource actions)",
                      order->id);
            order_actions(order->lh_action, order->rh_action, order->type);
        }
    }

    g_list_foreach(data_set->actions, (GFunc) pcmk__block_colocated_starts,
                   data_set);

    crm_trace("Ordering probes");
    order_probes(data_set);

    crm_trace("Updating %d actions", g_list_length(data_set->actions));
    g_list_foreach(data_set->actions, (GFunc) update_action, data_set);

    pcmk__disable_invalid_orderings(data_set);

    /* stage7 only ever outputs to the log, so ignore whatever output object was
     * previously set and just log instead.
     */
    out = pcmk__new_logger();
    if (out == NULL) {
        return FALSE;
    }

    pcmk__output_set_log_level(out, LOG_NOTICE);
    data_set->priv = out;

    out->begin_list(out, NULL, NULL, "Actions");
    LogNodeActions(data_set);

    g_list_foreach(data_set->resources, (GFunc) LogActions, data_set);

    out->end_list(out);
    out->finish(out, CRM_EX_OK, true, NULL);
    pcmk__output_free(out);

    data_set->priv = prev_out;
    return TRUE;
}

static int transition_id = -1;

/*!
 * \internal
 * \brief Log a message after calculating a transition
 *
 * \param[in] filename  Where transition input is stored
 */
void
pcmk__log_transition_summary(const char *filename)
{
    if (was_processing_error) {
        crm_err("Calculated transition %d (with errors)%s%s",
                transition_id,
                (filename == NULL)? "" : ", saving inputs in ",
                (filename == NULL)? "" : filename);

    } else if (was_processing_warning) {
        crm_warn("Calculated transition %d (with warnings)%s%s",
                 transition_id,
                 (filename == NULL)? "" : ", saving inputs in ",
                 (filename == NULL)? "" : filename);

    } else {
        crm_notice("Calculated transition %d%s%s",
                   transition_id,
                   (filename == NULL)? "" : ", saving inputs in ",
                   (filename == NULL)? "" : filename);
    }
    if (crm_config_error) {
        crm_notice("Configuration errors found during scheduler processing,"
                   "  please run \"crm_verify -L\" to identify issues");
    }
}

/*
 * Create a dependency graph to send to the transitioner (via the controller)
 */
gboolean
stage8(pe_working_set_t * data_set)
{
    GList *gIter = NULL;
    const char *value = NULL;
    long long limit = 0LL;

    transition_id++;
    crm_trace("Creating transition graph %d.", transition_id);

    data_set->graph = create_xml_node(NULL, XML_TAG_GRAPH);

    value = pe_pref(data_set->config_hash, "cluster-delay");
    crm_xml_add(data_set->graph, "cluster-delay", value);

    value = pe_pref(data_set->config_hash, "stonith-timeout");
    crm_xml_add(data_set->graph, "stonith-timeout", value);

    crm_xml_add(data_set->graph, "failed-stop-offset", "INFINITY");

    if (pcmk_is_set(data_set->flags, pe_flag_start_failure_fatal)) {
        crm_xml_add(data_set->graph, "failed-start-offset", "INFINITY");
    } else {
        crm_xml_add(data_set->graph, "failed-start-offset", "1");
    }

    value = pe_pref(data_set->config_hash, "batch-limit");
    crm_xml_add(data_set->graph, "batch-limit", value);

    crm_xml_add_int(data_set->graph, "transition_id", transition_id);

    value = pe_pref(data_set->config_hash, "migration-limit");
    if ((pcmk__scan_ll(value, &limit, 0LL) == pcmk_rc_ok) && (limit > 0)) {
        crm_xml_add(data_set->graph, "migration-limit", value);
    }

    if (data_set->recheck_by > 0) {
        char *recheck_epoch = NULL;

        recheck_epoch = crm_strdup_printf("%llu",
                                          (long long) data_set->recheck_by);
        crm_xml_add(data_set->graph, "recheck-by", recheck_epoch);
        free(recheck_epoch);
    }

    /* The following code will de-duplicate action inputs, so nothing past this
     * should rely on the action input type flags retaining their original
     * values.
     */

    gIter = data_set->resources;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_resource_t *rsc = (pe_resource_t *) gIter->data;

        pe_rsc_trace(rsc, "processing actions for rsc=%s", rsc->id);
        rsc->cmds->expand(rsc, data_set);
    }

    crm_log_xml_trace(data_set->graph, "created resource-driven action list");

    /* pseudo action to distribute list of nodes with maintenance state update */
    add_maintenance_update(data_set);

    /* catch any non-resource specific actions */
    crm_trace("processing non-resource actions");

    gIter = data_set->actions;
    for (; gIter != NULL; gIter = gIter->next) {
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (action->rsc
            && action->node
            && action->node->details->shutdown
            && !pcmk_is_set(action->rsc->flags, pe_rsc_maintenance)
            && !pcmk_any_flags_set(action->flags,
                                   pe_action_optional|pe_action_runnable)
            && pcmk__str_eq(action->task, RSC_STOP, pcmk__str_none)
            ) {
            /* Eventually we should just ignore the 'fence' case
             * But for now it's the best way to detect (in CTS) when
             * CIB resource updates are being lost
             */
            if (pcmk_is_set(data_set->flags, pe_flag_have_quorum)
                || data_set->no_quorum_policy == no_quorum_ignore) {
                crm_crit("Cannot %s node '%s' because of %s:%s%s (%s)",
                         action->node->details->unclean ? "fence" : "shut down",
                         action->node->details->uname, action->rsc->id,
                         pcmk_is_set(action->rsc->flags, pe_rsc_managed)? " blocked" : " unmanaged",
                         pcmk_is_set(action->rsc->flags, pe_rsc_failed)? " failed" : "",
                         action->uuid);
            }
        }

        graph_element_from_action(action, data_set);
    }

    crm_log_xml_trace(data_set->graph, "created generic action list");
    crm_trace("Created transition graph %d.", transition_id);

    return TRUE;
}

void
LogNodeActions(pe_working_set_t * data_set)
{
    pcmk__output_t *out = data_set->priv;
    GList *gIter = NULL;

    for (gIter = data_set->actions; gIter != NULL; gIter = gIter->next) {
        char *node_name = NULL;
        char *task = NULL;
        pe_action_t *action = (pe_action_t *) gIter->data;

        if (action->rsc != NULL) {
            continue;
        } else if (pcmk_is_set(action->flags, pe_action_optional)) {
            continue;
        }

        if (pe__is_guest_node(action->node)) {
            node_name = crm_strdup_printf("%s (resource: %s)", action->node->details->uname, action->node->details->remote_rsc->container->id);
        } else if(action->node) {
            node_name = crm_strdup_printf("%s", action->node->details->uname);
        }


        if (pcmk__str_eq(action->task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
            task = strdup("Shutdown");
        } else if (pcmk__str_eq(action->task, CRM_OP_FENCE, pcmk__str_casei)) {
            const char *op = g_hash_table_lookup(action->meta, "stonith_action");
            task = crm_strdup_printf("Fence (%s)", op);
        }

        out->message(out, "node-action", task, node_name, action->reason);

        free(node_name);
        free(task);
    }
}

/*
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/util.h>

#include <glib.h>

#include <crm/pengine/rules.h>
#include <crm/pengine/internal.h>

#include <unpack.h>

pe_working_set_t *pe_dataset = NULL;

extern xmlNode *get_object_root(const char *object_type, xmlNode * the_root);
void print_str_str(gpointer key, gpointer value, gpointer user_data);
gboolean ghash_free_str_str(gpointer key, gpointer value, gpointer user_data);
void unpack_operation(action_t * action, xmlNode * xml_obj, resource_t * container,
                      pe_working_set_t * data_set);
static xmlNode *find_rsc_op_entry_helper(resource_t * rsc, const char *key,
                                         gboolean include_disabled);

#if ENABLE_VERSIONED_ATTRS
pe_rsc_action_details_t *
pe_rsc_action_details(pe_action_t *action)
{
    pe_rsc_action_details_t *details;

    CRM_CHECK(action != NULL, return NULL);

    if (action->action_details == NULL) {
        action->action_details = calloc(1, sizeof(pe_rsc_action_details_t));
        CRM_CHECK(action->action_details != NULL, return NULL);
    }

    details = (pe_rsc_action_details_t *) action->action_details;
    if (details->versioned_parameters == NULL) {
        details->versioned_parameters = create_xml_node(NULL,
                                                        XML_TAG_OP_VER_ATTRS);
    }
    if (details->versioned_meta == NULL) {
        details->versioned_meta = create_xml_node(NULL, XML_TAG_OP_VER_META);
    }
    return details;
}

static void
pe_free_rsc_action_details(pe_action_t *action)
{
    pe_rsc_action_details_t *details;

    if ((action == NULL) || (action->action_details == NULL)) {
        return;
    }

    details = (pe_rsc_action_details_t *) action->action_details;

    if (details->versioned_parameters) {
        free_xml(details->versioned_parameters);
    }
    if (details->versioned_meta) {
        free_xml(details->versioned_meta);
    }

    action->action_details = NULL;
}
#endif

/*!
 * \internal
 * \brief Check whether we can fence a particular node
 *
 * \param[in] data_set  Working set for cluster
 * \param[in] node      Name of node to check
 *
 * \return TRUE if node can be fenced, FALSE otherwise
 *
 * \note This function should only be called for cluster nodes and baremetal
 *       remote nodes; guest nodes are fenced by stopping their container
 *       resource, so fence execution requirements do not apply to them.
 */
bool pe_can_fence(pe_working_set_t * data_set, node_t *node)
{
    if(is_not_set(data_set->flags, pe_flag_stonith_enabled)) {
        return FALSE; /* Turned off */

    } else if (is_not_set(data_set->flags, pe_flag_have_stonith_resource)) {
        return FALSE; /* No devices */

    } else if (is_set(data_set->flags, pe_flag_have_quorum)) {
        return TRUE;

    } else if (data_set->no_quorum_policy == no_quorum_ignore) {
        return TRUE;

    } else if(node == NULL) {
        return FALSE;

    } else if(node->details->online) {
        crm_notice("We can fence %s without quorum because they're in our membership", node->details->uname);
        return TRUE;
    }

    crm_trace("Cannot fence %s", node->details->uname);
    return FALSE;
}

node_t *
node_copy(const node_t *this_node)
{
    node_t *new_node = NULL;

    CRM_CHECK(this_node != NULL, return NULL);

    new_node = calloc(1, sizeof(node_t));
    CRM_ASSERT(new_node != NULL);

    crm_trace("Copying %p (%s) to %p", this_node, this_node->details->uname, new_node);

    new_node->rsc_discover_mode = this_node->rsc_discover_mode;
    new_node->weight = this_node->weight;
    new_node->fixed = this_node->fixed;
    new_node->details = this_node->details;

    return new_node;
}

/* any node in list1 or list2 and not in the other gets a score of -INFINITY */
void
node_list_exclude(GHashTable * hash, GListPtr list, gboolean merge_scores)
{
    GHashTable *result = hash;
    node_t *other_node = NULL;
    GListPtr gIter = list;

    GHashTableIter iter;
    node_t *node = NULL;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {

        other_node = pe_find_node_id(list, node->details->id);
        if (other_node == NULL) {
            node->weight = -INFINITY;
        } else if (merge_scores) {
            node->weight = merge_weights(node->weight, other_node->weight);
        }
    }

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;

        other_node = pe_hash_table_lookup(result, node->details->id);

        if (other_node == NULL) {
            node_t *new_node = node_copy(node);

            new_node->weight = -INFINITY;
            g_hash_table_insert(result, (gpointer) new_node->details->id, new_node);
        }
    }
}

GHashTable *
node_hash_from_list(GListPtr list)
{
    GListPtr gIter = list;
    GHashTable *result = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL,
                                               free);

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *node = (node_t *) gIter->data;
        node_t *n = node_copy(node);

        g_hash_table_insert(result, (gpointer) n->details->id, n);
    }

    return result;
}

GListPtr
node_list_dup(GListPtr list1, gboolean reset, gboolean filter)
{
    GListPtr result = NULL;
    GListPtr gIter = list1;

    for (; gIter != NULL; gIter = gIter->next) {
        node_t *new_node = NULL;
        node_t *this_node = (node_t *) gIter->data;

        if (filter && this_node->weight < 0) {
            continue;
        }

        new_node = node_copy(this_node);
        if (reset) {
            new_node->weight = 0;
        }
        if (new_node != NULL) {
            result = g_list_prepend(result, new_node);
        }
    }

    return result;
}

gint
sort_node_uname(gconstpointer a, gconstpointer b)
{
    const node_t *node_a = a;
    const node_t *node_b = b;

    return strcmp(node_a->details->uname, node_b->details->uname);
}

void
dump_node_scores_worker(int level, const char *file, const char *function, int line,
                        resource_t * rsc, const char *comment, GHashTable * nodes)
{
    GHashTable *hash = nodes;
    GHashTableIter iter;
    node_t *node = NULL;

    if (rsc) {
        hash = rsc->allowed_nodes;
    }

    if (rsc && is_set(rsc->flags, pe_rsc_orphan)) {
        /* Don't show the allocation scores for orphans */
        return;
    }

    if (level == 0) {
        char score[128];
        int len = sizeof(score);
        /* For now we want this in sorted order to keep the regression tests happy */
        GListPtr gIter = NULL;
        GListPtr list = g_hash_table_get_values(hash);

        list = g_list_sort(list, sort_node_uname);

        gIter = list;
        for (; gIter != NULL; gIter = gIter->next) {
            node_t *node = (node_t *) gIter->data;
            /* This function is called a whole lot, use stack allocated score */
            score2char_stack(node->weight, score, len);

            if (rsc) {
                printf("%s: %s allocation score on %s: %s\n",
                       comment, rsc->id, node->details->uname, score);
            } else {
                printf("%s: %s = %s\n", comment, node->details->uname, score);
            }
        }

        g_list_free(list);

    } else if (hash) {
        char score[128];
        int len = sizeof(score);
        g_hash_table_iter_init(&iter, hash);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            /* This function is called a whole lot, use stack allocated score */
            score2char_stack(node->weight, score, len);

            if (rsc) {
                do_crm_log_alias(LOG_TRACE, file, function, line,
                                 "%s: %s allocation score on %s: %s", comment, rsc->id,
                                 node->details->uname, score);
            } else {
                do_crm_log_alias(LOG_TRACE, file, function, line + 1, "%s: %s = %s", comment,
                                 node->details->uname, score);
            }
        }
    }

    if (rsc && rsc->children) {
        GListPtr gIter = NULL;

        gIter = rsc->children;
        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child = (resource_t *) gIter->data;

            dump_node_scores_worker(level, file, function, line, child, comment, nodes);
        }
    }
}

static void
append_dump_text(gpointer key, gpointer value, gpointer user_data)
{
    char **dump_text = user_data;
    char *new_text = crm_strdup_printf("%s %s=%s",
                                       *dump_text, (char *)key, (char *)value);

    free(*dump_text);
    *dump_text = new_text;
}

void
dump_node_capacity(int level, const char *comment, node_t * node)
{
    char *dump_text = crm_strdup_printf("%s: %s capacity:",
                                        comment, node->details->uname);

    g_hash_table_foreach(node->details->utilization, append_dump_text, &dump_text);

    if (level == 0) {
        fprintf(stdout, "%s\n", dump_text);
    } else {
        crm_trace("%s", dump_text);
    }

    free(dump_text);
}

void
dump_rsc_utilization(int level, const char *comment, resource_t * rsc, node_t * node)
{
    char *dump_text = crm_strdup_printf("%s: %s utilization on %s:",
                                        comment, rsc->id, node->details->uname);

    g_hash_table_foreach(rsc->utilization, append_dump_text, &dump_text);

    if (level == 0) {
        fprintf(stdout, "%s\n", dump_text);
    } else {
        crm_trace("%s", dump_text);
    }

    free(dump_text);
}

gint
sort_rsc_index(gconstpointer a, gconstpointer b)
{
    const resource_t *resource1 = (const resource_t *)a;
    const resource_t *resource2 = (const resource_t *)b;

    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (resource1->sort_index > resource2->sort_index) {
        return -1;
    }

    if (resource1->sort_index < resource2->sort_index) {
        return 1;
    }

    return 0;
}

gint
sort_rsc_priority(gconstpointer a, gconstpointer b)
{
    const resource_t *resource1 = (const resource_t *)a;
    const resource_t *resource2 = (const resource_t *)b;

    if (a == NULL && b == NULL) {
        return 0;
    }
    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    if (resource1->priority > resource2->priority) {
        return -1;
    }

    if (resource1->priority < resource2->priority) {
        return 1;
    }

    return 0;
}

action_t *
custom_action(resource_t * rsc, char *key, const char *task,
              node_t * on_node, gboolean optional, gboolean save_action,
              pe_working_set_t * data_set)
{
    action_t *action = NULL;
    GListPtr possible_matches = NULL;

    CRM_CHECK(key != NULL, return NULL);
    CRM_CHECK(task != NULL, free(key); return NULL);

    if (save_action && rsc != NULL) {
        possible_matches = find_actions(rsc->actions, key, on_node);
    } else if(save_action) {
#if 0
        action = g_hash_table_lookup(data_set->singletons, key);
#else
        /* More expensive but takes 'node' into account */
        possible_matches = find_actions(data_set->actions, key, on_node);
#endif
    }

    if(data_set->singletons == NULL) {
        data_set->singletons = g_hash_table_new_full(crm_str_hash, g_str_equal, NULL, NULL);
    }

    if (possible_matches != NULL) {
        if (g_list_length(possible_matches) > 1) {
            pe_warn("Action %s for %s on %s exists %d times",
                    task, rsc ? rsc->id : "<NULL>",
                    on_node ? on_node->details->uname : "<NULL>", g_list_length(possible_matches));
        }

        action = g_list_nth_data(possible_matches, 0);
        pe_rsc_trace(rsc, "Found existing action (%d) %s for %s on %s",
                     action->id, task, rsc ? rsc->id : "<NULL>",
                     on_node ? on_node->details->uname : "<NULL>");
        g_list_free(possible_matches);
    }

    if (action == NULL) {
        if (save_action) {
            pe_rsc_trace(rsc, "Creating%s action %d: %s for %s on %s %d",
                         optional ? "" : " mandatory", data_set->action_id, key,
                         rsc ? rsc->id : "<NULL>", on_node ? on_node->details->uname : "<NULL>", optional);
        }

        action = calloc(1, sizeof(action_t));
        if (save_action) {
            action->id = data_set->action_id++;
        } else {
            action->id = 0;
        }
        action->rsc = rsc;
        CRM_ASSERT(task != NULL);
        action->task = strdup(task);
        if (on_node) {
            action->node = node_copy(on_node);
        }
        action->uuid = strdup(key);

        pe_set_action_bit(action, pe_action_runnable);
        if (optional) {
            pe_rsc_trace(rsc, "Set optional on %s", action->uuid);
            pe_set_action_bit(action, pe_action_optional);
        } else {
            pe_clear_action_bit(action, pe_action_optional);
            pe_rsc_trace(rsc, "Unset optional on %s", action->uuid);
        }

/*
  Implied by calloc()...
  action->actions_before   = NULL;
  action->actions_after    = NULL;

  action->pseudo     = FALSE;
  action->dumped     = FALSE;
  action->processed  = FALSE;
  action->seen_count = 0;
*/

        action->extra = crm_str_table_new();
        action->meta = crm_str_table_new();

        if (save_action) {
            data_set->actions = g_list_prepend(data_set->actions, action);
            if(rsc == NULL) {
                g_hash_table_insert(data_set->singletons, action->uuid, action);
            }
        }

        if (rsc != NULL) {
            action->op_entry = find_rsc_op_entry_helper(rsc, key, TRUE);

            unpack_operation(action, action->op_entry, rsc->container, data_set);

            if (save_action) {
                rsc->actions = g_list_prepend(rsc->actions, action);
            }
        }

        if (save_action) {
            pe_rsc_trace(rsc, "Action %d created", action->id);
        }
    }

    if (optional == FALSE) {
        pe_rsc_trace(rsc, "Unset optional on %s", action->uuid);
        pe_clear_action_bit(action, pe_action_optional);
    }

    if (rsc != NULL) {
        enum action_tasks a_task = text2task(action->task);
        int warn_level = LOG_TRACE;

        if (save_action) {
            warn_level = LOG_WARNING;
        }

        if (is_set(action->flags, pe_action_have_node_attrs) == FALSE
            && action->node != NULL && action->op_entry != NULL) {
            pe_set_action_bit(action, pe_action_have_node_attrs);
            unpack_instance_attributes(data_set->input, action->op_entry, XML_TAG_ATTR_SETS,
                                       action->node->details->attrs,
                                       action->extra, NULL, FALSE, data_set->now);
        }

        if (is_set(action->flags, pe_action_pseudo)) {
            /* leave untouched */

        } else if (action->node == NULL) {
            pe_rsc_trace(rsc, "Unset runnable on %s", action->uuid);
            pe_clear_action_bit(action, pe_action_runnable);

        } else if (is_not_set(rsc->flags, pe_rsc_managed)
                   && g_hash_table_lookup(action->meta,
                                          XML_LRM_ATTR_INTERVAL_MS) == NULL) {
            crm_debug("Action %s (unmanaged)", action->uuid);
            pe_rsc_trace(rsc, "Set optional on %s", action->uuid);
            pe_set_action_bit(action, pe_action_optional);
/*   			action->runnable = FALSE; */

        } else if (action->node->details->online == FALSE
                   && (!is_container_remote_node(action->node) || action->node->details->remote_requires_reset)) {
            pe_clear_action_bit(action, pe_action_runnable);
            do_crm_log(warn_level, "Action %s on %s is unrunnable (offline)",
                       action->uuid, action->node->details->uname);
            if (is_set(action->rsc->flags, pe_rsc_managed)
                && save_action && a_task == stop_rsc
                && action->node->details->unclean == FALSE) {
                pe_fence_node(data_set, action->node, "resource actions are unrunnable");
            }

        } else if (action->node->details->pending) {
            pe_clear_action_bit(action, pe_action_runnable);
            do_crm_log(warn_level, "Action %s on %s is unrunnable (pending)",
                       action->uuid, action->node->details->uname);

        } else if (action->needs == rsc_req_nothing) {
            pe_rsc_trace(rsc, "Action %s does not require anything", action->uuid);
            pe_action_set_reason(action, NULL, TRUE);
            pe_set_action_bit(action, pe_action_runnable);
#if 0
            /*
             * No point checking this
             * - if we don't have quorum we can't stonith anyway
             */
        } else if (action->needs == rsc_req_stonith) {
            crm_trace("Action %s requires only stonith", action->uuid);
            action->runnable = TRUE;
#endif
        } else if (is_set(data_set->flags, pe_flag_have_quorum) == FALSE
                   && data_set->no_quorum_policy == no_quorum_stop) {
            pe_action_set_flag_reason(__FUNCTION__, __LINE__, action, NULL, "no quorum", pe_action_runnable, TRUE);
            crm_debug("%s\t%s (cancelled : quorum)", action->node->details->uname, action->uuid);

        } else if (is_set(data_set->flags, pe_flag_have_quorum) == FALSE
                   && data_set->no_quorum_policy == no_quorum_freeze) {
            pe_rsc_trace(rsc, "Check resource is already active: %s %s %s %s", rsc->id, action->uuid, role2text(rsc->next_role), role2text(rsc->role));
            if (rsc->fns->active(rsc, TRUE) == FALSE || rsc->next_role > rsc->role) {
                pe_action_set_flag_reason(__FUNCTION__, __LINE__, action, NULL, "quorum freeze", pe_action_runnable, TRUE);
                pe_rsc_debug(rsc, "%s\t%s (cancelled : quorum freeze)",
                             action->node->details->uname, action->uuid);
            }

        } else if(is_not_set(action->flags, pe_action_runnable)) {
            pe_rsc_trace(rsc, "Action %s is runnable", action->uuid);
            //pe_action_set_reason(action, NULL, TRUE);
            pe_set_action_bit(action, pe_action_runnable);
        }

        if (save_action) {
            switch (a_task) {
                case stop_rsc:
                    set_bit(rsc->flags, pe_rsc_stopping);
                    break;
                case start_rsc:
                    clear_bit(rsc->flags, pe_rsc_starting);
                    if (is_set(action->flags, pe_action_runnable)) {
                        set_bit(rsc->flags, pe_rsc_starting);
                    }
                    break;
                default:
                    break;
            }
        }
    }

    free(key);
    return action;
}

static const char *
unpack_operation_on_fail(action_t * action)
{

    const char *value = g_hash_table_lookup(action->meta, XML_OP_ATTR_ON_FAIL);

    if (safe_str_eq(action->task, CRMD_ACTION_STOP) && safe_str_eq(value, "standby")) {
        crm_config_err("on-fail=standby is not allowed for stop actions: %s", action->rsc->id);
        return NULL;
    } else if (safe_str_eq(action->task, CRMD_ACTION_DEMOTE) && !value) {
        /* demote on_fail defaults to master monitor value if present */
        xmlNode *operation = NULL;
        const char *name = NULL;
        const char *role = NULL;
        const char *on_fail = NULL;
        const char *interval_spec = NULL;
        const char *enabled = NULL;

        CRM_CHECK(action->rsc != NULL, return NULL);

        for (operation = __xml_first_child(action->rsc->ops_xml);
             operation && !value; operation = __xml_next_element(operation)) {

            if (!crm_str_eq((const char *)operation->name, "op", TRUE)) {
                continue;
            }
            name = crm_element_value(operation, "name");
            role = crm_element_value(operation, "role");
            on_fail = crm_element_value(operation, XML_OP_ATTR_ON_FAIL);
            enabled = crm_element_value(operation, "enabled");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            if (!on_fail) {
                continue;
            } else if (enabled && !crm_is_true(enabled)) {
                continue;
            } else if (safe_str_neq(name, "monitor") || safe_str_neq(role, "Master")) {
                continue;
            } else if (crm_parse_interval_spec(interval_spec) == 0) {
                continue;
            }

            value = on_fail;
        }
    }

    return value;
}

static xmlNode *
find_min_interval_mon(resource_t * rsc, gboolean include_disabled)
{
    guint interval_ms = 0;
    guint min_interval_ms = G_MAXUINT;
    const char *name = NULL;
    const char *value = NULL;
    const char *interval_spec = NULL;
    xmlNode *op = NULL;
    xmlNode *operation = NULL;

    for (operation = __xml_first_child(rsc->ops_xml); operation != NULL;
         operation = __xml_next_element(operation)) {

        if (crm_str_eq((const char *)operation->name, "op", TRUE)) {
            name = crm_element_value(operation, "name");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            value = crm_element_value(operation, "enabled");
            if (!include_disabled && value && crm_is_true(value) == FALSE) {
                continue;
            }

            if (safe_str_neq(name, RSC_STATUS)) {
                continue;
            }

            interval_ms = crm_parse_interval_spec(interval_spec);
            if (interval_ms < 0) {
                continue;
            }

            if (min_interval_ms < 0 || interval_ms < min_interval_ms) {
                min_interval_ms = interval_ms;
                op = operation;
            }
        }
    }

    return op;
}

static int
unpack_start_delay(const char *value, GHashTable *meta)
{
    int start_delay = 0;

    if (value != NULL) {
        start_delay = crm_get_msec(value);

        if (start_delay < 0) {
            start_delay = 0;
        }

        if (meta) {
            g_hash_table_replace(meta, strdup(XML_OP_ATTR_START_DELAY), crm_itoa(start_delay));
        }
    }

    return start_delay;
}

static int
unpack_interval_origin(const char *value, GHashTable *meta, xmlNode *xml_obj,
                       guint interval_ms, crm_time_t *now)
{
    int start_delay = 0;

    if ((interval_ms > 0) && (value != NULL)) {
        crm_time_t *origin = crm_time_new(value);

        if (origin && now) {
            crm_time_t *delay = NULL;
            int rc = crm_time_compare(origin, now);
            long long delay_s = 0;
            int interval_sec = interval_ms / 1000;

            crm_trace("Origin: %s, interval: %d", value, interval_sec);

            /* If 'origin' is in the future, find the most recent "multiple" that occurred in the past */
            while(rc > 0) {
                crm_time_add_seconds(origin, -interval_sec);
                rc = crm_time_compare(origin, now);
            }

            /* Now find the first "multiple" that occurs after 'now' */
            while (rc < 0) {
                crm_time_add_seconds(origin, interval_sec);
                rc = crm_time_compare(origin, now);
            }

            delay = crm_time_calculate_duration(origin, now);

            crm_time_log(LOG_TRACE, "origin", origin,
                         crm_time_log_date | crm_time_log_timeofday |
                         crm_time_log_with_timezone);
            crm_time_log(LOG_TRACE, "now", now,
                         crm_time_log_date | crm_time_log_timeofday |
                         crm_time_log_with_timezone);
            crm_time_log(LOG_TRACE, "delay", delay, crm_time_log_duration);

            delay_s = crm_time_get_seconds(delay);

            CRM_CHECK(delay_s >= 0, delay_s = 0);
            start_delay = delay_s * 1000;

            if (xml_obj) {
                crm_info("Calculated a start delay of %llds for %s", delay_s, ID(xml_obj));
            }

            if (meta) {
                g_hash_table_replace(meta, strdup(XML_OP_ATTR_START_DELAY),
                                     crm_itoa(start_delay));
            }

            crm_time_free(origin);
            crm_time_free(delay);
        } else if (!origin && xml_obj) {
            crm_config_err("Operation %s contained an invalid " XML_OP_ATTR_ORIGIN ": %s",
                           ID(xml_obj), value);
        }
    }

    return start_delay;
}

static int
unpack_timeout(const char *value)
{
    int timeout = 0;

    if (value == NULL) {
        value = CRM_DEFAULT_OP_TIMEOUT_S;
    }

    timeout = crm_get_msec(value);
    if (timeout < 0) {
        timeout = 0;
    }

    return timeout;
}

int
pe_get_configured_timeout(resource_t *rsc, const char *action, pe_working_set_t *data_set)
{
    xmlNode *child = NULL;
    const char *timeout = NULL;
    int timeout_ms = 0;

    for (child = first_named_child(rsc->ops_xml, XML_ATTR_OP);
         child != NULL; child = crm_next_same_xml(child)) {
        if (safe_str_eq(action, crm_element_value(child, XML_NVPAIR_ATTR_NAME))) {
            timeout = crm_element_value(child, XML_ATTR_TIMEOUT);
            break;
        }
    }

    if (timeout == NULL && data_set->op_defaults) {
        GHashTable *action_meta = crm_str_table_new();
        unpack_instance_attributes(data_set->input, data_set->op_defaults, XML_TAG_META_SETS,
                                   NULL, action_meta, NULL, FALSE, data_set->now);
        timeout = g_hash_table_lookup(action_meta, XML_ATTR_TIMEOUT);
    }

    if (timeout == NULL) {
        timeout = CRM_DEFAULT_OP_TIMEOUT_S;
    }

    timeout_ms = crm_get_msec(timeout);
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }

    return timeout_ms;
}

#if ENABLE_VERSIONED_ATTRS
static void
unpack_versioned_meta(xmlNode *versioned_meta, xmlNode *xml_obj,
                      guint interval_ms, crm_time_t *now)
{
    xmlNode *attrs = NULL;
    xmlNode *attr = NULL;

    for (attrs = __xml_first_child(versioned_meta); attrs != NULL; attrs = __xml_next_element(attrs)) {
        for (attr = __xml_first_child(attrs); attr != NULL; attr = __xml_next_element(attr)) {
            const char *name = crm_element_value(attr, XML_NVPAIR_ATTR_NAME);
            const char *value = crm_element_value(attr, XML_NVPAIR_ATTR_VALUE);

            if (safe_str_eq(name, XML_OP_ATTR_START_DELAY)) {
                int start_delay = unpack_start_delay(value, NULL);

                crm_xml_add_int(attr, XML_NVPAIR_ATTR_VALUE, start_delay);
            } else if (safe_str_eq(name, XML_OP_ATTR_ORIGIN)) {
                int start_delay = unpack_interval_origin(value, NULL, xml_obj,
                                                         interval_ms, now);

                crm_xml_add(attr, XML_NVPAIR_ATTR_NAME, XML_OP_ATTR_START_DELAY);
                crm_xml_add_int(attr, XML_NVPAIR_ATTR_VALUE, start_delay);
            } else if (safe_str_eq(name, XML_ATTR_TIMEOUT)) {
                int timeout = unpack_timeout(value);

                crm_xml_add_int(attr, XML_NVPAIR_ATTR_VALUE, timeout);
            }
        }
    }
}
#endif

/*!
 * \brief Unpack operation XML into an action structure
 *
 * Unpack an operation's meta-attributes (normalizing the interval, timeout,
 * and start delay values as integer milliseconds), requirements, and
 * failure policy.
 *
 * \param[in,out] action     Action to unpack into
 * \param[in]     xml_obj    Operation XML (or NULL if all defaults)
 * \param[in]     container  Resource that contains affected resource, if any
 * \param[in]     data_set   Cluster state
 */
void
unpack_operation(action_t * action, xmlNode * xml_obj, resource_t * container,
                 pe_working_set_t * data_set)
{
    guint interval_ms = 0;
    int timeout = 0;
    char *value_ms = NULL;
    const char *value = NULL;
    const char *field = NULL;
    char *default_timeout = NULL;
#if ENABLE_VERSIONED_ATTRS
    pe_rsc_action_details_t *rsc_details = NULL;
#endif

    CRM_CHECK(action && action->rsc, return);

    // Cluster-wide <op_defaults> <meta_attributes>
    unpack_instance_attributes(data_set->input, data_set->op_defaults, XML_TAG_META_SETS, NULL,
                               action->meta, NULL, FALSE, data_set->now);

    // Probe timeouts default differently, so handle timeout default later
    default_timeout = g_hash_table_lookup(action->meta, XML_ATTR_TIMEOUT);
    if (default_timeout) {
        default_timeout = strdup(default_timeout);
        g_hash_table_remove(action->meta, XML_ATTR_TIMEOUT);
    }

    // <op> <meta_attributes> take precedence over defaults
    unpack_instance_attributes(data_set->input, xml_obj, XML_TAG_META_SETS,
                               NULL, action->meta, NULL, TRUE, data_set->now);

#if ENABLE_VERSIONED_ATTRS
    rsc_details = pe_rsc_action_details(action);
    pe_unpack_versioned_attributes(data_set->input, xml_obj, XML_TAG_ATTR_SETS, NULL,
                                   rsc_details->versioned_parameters, data_set->now);
    pe_unpack_versioned_attributes(data_set->input, xml_obj, XML_TAG_META_SETS, NULL,
                                   rsc_details->versioned_meta, data_set->now);
#endif

    /* Anything set as an <op> XML property has highest precedence.
     * This ensures we use the name and interval from the <op> tag.
     */
    if (xml_obj) {
        xmlAttrPtr xIter = NULL;

        for (xIter = xml_obj->properties; xIter; xIter = xIter->next) {
            const char *prop_name = (const char *)xIter->name;
            const char *prop_value = crm_element_value(xml_obj, prop_name);

            g_hash_table_replace(action->meta, strdup(prop_name), strdup(prop_value));
        }
    }

    g_hash_table_remove(action->meta, "id");

    // Normalize interval to milliseconds
    field = XML_LRM_ATTR_INTERVAL;
    value = g_hash_table_lookup(action->meta, field);
    if (value != NULL) {
        interval_ms = crm_parse_interval_spec(value);
        if (interval_ms > 0) {
            value_ms = crm_strdup_printf("%u", interval_ms);
            g_hash_table_replace(action->meta, strdup(field), value_ms);

        } else {
            g_hash_table_remove(action->meta, field);
        }
    }

    // Handle timeout default, now that we know the interval
    if (g_hash_table_lookup(action->meta, XML_ATTR_TIMEOUT)) {
        free(default_timeout);

    } else {
        // Probe timeouts default to minimum-interval monitor's
        if (safe_str_eq(action->task, RSC_STATUS) && (interval_ms == 0)) {

            xmlNode *min_interval_mon = find_min_interval_mon(action->rsc, FALSE);

            if (min_interval_mon) {
                value = crm_element_value(min_interval_mon, XML_ATTR_TIMEOUT);
                if (value) {
                    crm_trace("\t%s defaults to minimum-interval monitor's timeout '%s'",
                              action->uuid, value);
                    free(default_timeout);
                    default_timeout = strdup(value);
                }
            }
        }

        if (default_timeout) {
            g_hash_table_insert(action->meta, strdup(XML_ATTR_TIMEOUT),
                                default_timeout);
        }
    }

    if (safe_str_neq(action->task, RSC_START)
        && safe_str_neq(action->task, RSC_PROMOTE)) {
        action->needs = rsc_req_nothing;
        value = "nothing (not start/promote)";

    } else if (is_set(action->rsc->flags, pe_rsc_needs_fencing)) {
        action->needs = rsc_req_stonith;
        value = "fencing (resource)";

    } else if (is_set(action->rsc->flags, pe_rsc_needs_quorum)) {
        action->needs = rsc_req_quorum;
        value = "quorum (resource)";

    } else {
        action->needs = rsc_req_nothing;
        value = "nothing (resource)";
    }

    pe_rsc_trace(action->rsc, "\tAction %s requires: %s", action->uuid, value);

    value = unpack_operation_on_fail(action);

    if (value == NULL) {

    } else if (safe_str_eq(value, "block")) {
        action->on_fail = action_fail_block;
        g_hash_table_insert(action->meta, strdup(XML_OP_ATTR_ON_FAIL), strdup("block"));

    } else if (safe_str_eq(value, "fence")) {
        action->on_fail = action_fail_fence;
        value = "node fencing";

        if (is_set(data_set->flags, pe_flag_stonith_enabled) == FALSE) {
            crm_config_err("Specifying on_fail=fence and" " stonith-enabled=false makes no sense");
            action->on_fail = action_fail_stop;
            action->fail_role = RSC_ROLE_STOPPED;
            value = "stop resource";
        }

    } else if (safe_str_eq(value, "standby")) {
        action->on_fail = action_fail_standby;
        value = "node standby";

    } else if (safe_str_eq(value, "ignore")
               || safe_str_eq(value, "nothing")) {
        action->on_fail = action_fail_ignore;
        value = "ignore";

    } else if (safe_str_eq(value, "migrate")) {
        action->on_fail = action_fail_migrate;
        value = "force migration";

    } else if (safe_str_eq(value, "stop")) {
        action->on_fail = action_fail_stop;
        action->fail_role = RSC_ROLE_STOPPED;
        value = "stop resource";

    } else if (safe_str_eq(value, "restart")) {
        action->on_fail = action_fail_recover;
        value = "restart (and possibly migrate)";

    } else if (safe_str_eq(value, "restart-container")) {
        if (container) {
            action->on_fail = action_fail_restart_container;
            value = "restart container (and possibly migrate)";

        } else {
            value = NULL;
        }

    } else {
        pe_err("Resource %s: Unknown failure type (%s)", action->rsc->id, value);
        value = NULL;
    }

    /* defaults */
    if (value == NULL && container) {
        action->on_fail = action_fail_restart_container;
        value = "restart container (and possibly migrate) (default)";

    /* for baremetal remote nodes, ensure that any failure that results in
     * dropping an active connection to a remote node results in fencing of
     * the remote node.
     *
     * There are only two action failures that don't result in fencing.
     * 1. probes - probe failures are expected.
     * 2. start - a start failure indicates that an active connection does not already
     * exist. The user can set op on-fail=fence if they really want to fence start
     * failures. */
    } else if (((value == NULL) || !is_set(action->rsc->flags, pe_rsc_managed)) &&
                (is_rsc_baremetal_remote_node(action->rsc, data_set) &&
               !(safe_str_eq(action->task, CRMD_ACTION_STATUS) && (interval_ms == 0)) &&
                (safe_str_neq(action->task, CRMD_ACTION_START)))) {

        if (!is_set(action->rsc->flags, pe_rsc_managed)) {
            action->on_fail = action_fail_stop;
            action->fail_role = RSC_ROLE_STOPPED;
            value = "stop unmanaged baremetal remote node (enforcing default)";

        } else {
            if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
                value = "fence baremetal remote node (default)";
            } else {
                value = "recover baremetal remote node connection (default)";
            }

            if (action->rsc->remote_reconnect_interval) {
                action->fail_role = RSC_ROLE_STOPPED;
            }
            action->on_fail = action_fail_reset_remote;
        }

    } else if (value == NULL && safe_str_eq(action->task, CRMD_ACTION_STOP)) {
        if (is_set(data_set->flags, pe_flag_stonith_enabled)) {
            action->on_fail = action_fail_fence;
            value = "resource fence (default)";

        } else {
            action->on_fail = action_fail_block;
            value = "resource block (default)";
        }

    } else if (value == NULL) {
        action->on_fail = action_fail_recover;
        value = "restart (and possibly migrate) (default)";
    }

    pe_rsc_trace(action->rsc, "\t%s failure handling: %s", action->task, value);

    value = NULL;
    if (xml_obj != NULL) {
        value = g_hash_table_lookup(action->meta, "role_after_failure");
        if (value) {
            pe_warn_once(pe_wo_role_after,
                        "Support for role_after_failure is deprecated and will be removed in a future release");
        }
    }
    if (value != NULL && action->fail_role == RSC_ROLE_UNKNOWN) {
        action->fail_role = text2role(value);
    }
    /* defaults */
    if (action->fail_role == RSC_ROLE_UNKNOWN) {
        if (safe_str_eq(action->task, CRMD_ACTION_PROMOTE)) {
            action->fail_role = RSC_ROLE_SLAVE;
        } else {
            action->fail_role = RSC_ROLE_STARTED;
        }
    }
    pe_rsc_trace(action->rsc, "\t%s failure results in: %s", action->task,
                 role2text(action->fail_role));

    value = g_hash_table_lookup(action->meta, XML_OP_ATTR_START_DELAY);
    if (value) {
        unpack_start_delay(value, action->meta);
    } else {
        value = g_hash_table_lookup(action->meta, XML_OP_ATTR_ORIGIN);
        unpack_interval_origin(value, action->meta, xml_obj, interval_ms,
                               data_set->now);
    }

    value = g_hash_table_lookup(action->meta, XML_ATTR_TIMEOUT);
    timeout = unpack_timeout(value);
    g_hash_table_replace(action->meta, strdup(XML_ATTR_TIMEOUT), crm_itoa(timeout));

#if ENABLE_VERSIONED_ATTRS
    unpack_versioned_meta(rsc_details->versioned_meta, xml_obj, interval_ms,
                          data_set->now);
#endif
}

static xmlNode *
find_rsc_op_entry_helper(resource_t * rsc, const char *key, gboolean include_disabled)
{
    guint interval_ms = 0;
    gboolean do_retry = TRUE;
    char *local_key = NULL;
    const char *name = NULL;
    const char *value = NULL;
    const char *interval_spec = NULL;
    char *match_key = NULL;
    xmlNode *op = NULL;
    xmlNode *operation = NULL;

  retry:
    for (operation = __xml_first_child(rsc->ops_xml); operation != NULL;
         operation = __xml_next_element(operation)) {
        if (crm_str_eq((const char *)operation->name, "op", TRUE)) {
            name = crm_element_value(operation, "name");
            interval_spec = crm_element_value(operation, XML_LRM_ATTR_INTERVAL);
            value = crm_element_value(operation, "enabled");
            if (!include_disabled && value && crm_is_true(value) == FALSE) {
                continue;
            }

            interval_ms = crm_parse_interval_spec(interval_spec);
            match_key = generate_op_key(rsc->id, name, interval_ms);
            if (safe_str_eq(key, match_key)) {
                op = operation;
            }
            free(match_key);

            if (rsc->clone_name) {
                match_key = generate_op_key(rsc->clone_name, name, interval_ms);
                if (safe_str_eq(key, match_key)) {
                    op = operation;
                }
                free(match_key);
            }

            if (op != NULL) {
                free(local_key);
                return op;
            }
        }
    }

    free(local_key);
    if (do_retry == FALSE) {
        return NULL;
    }

    do_retry = FALSE;
    if (strstr(key, CRMD_ACTION_MIGRATE) || strstr(key, CRMD_ACTION_MIGRATED)) {
        local_key = generate_op_key(rsc->id, "migrate", 0);
        key = local_key;
        goto retry;

    } else if (strstr(key, "_notify_")) {
        local_key = generate_op_key(rsc->id, "notify", 0);
        key = local_key;
        goto retry;
    }

    return NULL;
}

xmlNode *
find_rsc_op_entry(resource_t * rsc, const char *key)
{
    return find_rsc_op_entry_helper(rsc, key, FALSE);
}

void
print_node(const char *pre_text, node_t * node, gboolean details)
{
    if (node == NULL) {
        crm_trace("%s%s: <NULL>", pre_text == NULL ? "" : pre_text, pre_text == NULL ? "" : ": ");
        return;
    }

    CRM_ASSERT(node->details);
    crm_trace("%s%s%sNode %s: (weight=%d, fixed=%s)",
              pre_text == NULL ? "" : pre_text,
              pre_text == NULL ? "" : ": ",
              node->details->online ? "" : "Unavailable/Unclean ",
              node->details->uname, node->weight, node->fixed ? "True" : "False");

    if (details) {
        char *pe_mutable = strdup("\t\t");
        GListPtr gIter = node->details->running_rsc;

        crm_trace("\t\t===Node Attributes");
        g_hash_table_foreach(node->details->attrs, print_str_str, pe_mutable);
        free(pe_mutable);

        crm_trace("\t\t=== Resources");

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *rsc = (resource_t *) gIter->data;

            print_resource(LOG_TRACE, "\t\t", rsc, FALSE);
        }
    }
}

/*
 * Used by the HashTable for-loop
 */
void
print_str_str(gpointer key, gpointer value, gpointer user_data)
{
    crm_trace("%s%s %s ==> %s",
              user_data == NULL ? "" : (char *)user_data,
              user_data == NULL ? "" : ": ", (char *)key, (char *)value);
}

void
print_resource(int log_level, const char *pre_text, resource_t * rsc, gboolean details)
{
    long options = pe_print_log | pe_print_pending;

    if (rsc == NULL) {
        do_crm_log(log_level - 1, "%s%s: <NULL>",
                   pre_text == NULL ? "" : pre_text, pre_text == NULL ? "" : ": ");
        return;
    }
    if (details) {
        options |= pe_print_details;
    }
    rsc->fns->print(rsc, pre_text, options, &log_level);
}

void
pe_free_action(action_t * action)
{
    if (action == NULL) {
        return;
    }
    g_list_free_full(action->actions_before, free);     /* action_wrapper_t* */
    g_list_free_full(action->actions_after, free);      /* action_wrapper_t* */
    if (action->extra) {
        g_hash_table_destroy(action->extra);
    }
    if (action->meta) {
        g_hash_table_destroy(action->meta);
    }
#if ENABLE_VERSIONED_ATTRS
    if (action->rsc) {
        pe_free_rsc_action_details(action);
    }
#endif
    free(action->cancel_task);
    free(action->reason);
    free(action->task);
    free(action->uuid);
    free(action->node);
    free(action);
}

GListPtr
find_recurring_actions(GListPtr input, node_t * not_on_node)
{
    const char *value = NULL;
    GListPtr result = NULL;
    GListPtr gIter = input;

    CRM_CHECK(input != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        value = g_hash_table_lookup(action->meta, XML_LRM_ATTR_INTERVAL_MS);
        if (value == NULL) {
            /* skip */
        } else if (safe_str_eq(value, "0")) {
            /* skip */
        } else if (safe_str_eq(CRMD_ACTION_CANCEL, action->task)) {
            /* skip */
        } else if (not_on_node == NULL) {
            crm_trace("(null) Found: %s", action->uuid);
            result = g_list_prepend(result, action);

        } else if (action->node == NULL) {
            /* skip */
        } else if (action->node->details != not_on_node->details) {
            crm_trace("Found: %s", action->uuid);
            result = g_list_prepend(result, action);
        }
    }

    return result;
}

enum action_tasks
get_complex_task(resource_t * rsc, const char *name, gboolean allow_non_atomic)
{
    enum action_tasks task = text2task(name);

    if (rsc == NULL) {
        return task;

    } else if (allow_non_atomic == FALSE || rsc->variant == pe_native) {
        switch (task) {
            case stopped_rsc:
            case started_rsc:
            case action_demoted:
            case action_promoted:
                crm_trace("Folding %s back into its atomic counterpart for %s", name, rsc->id);
                return task - 1;
                break;
            default:
                break;
        }
    }
    return task;
}

action_t *
find_first_action(GListPtr input, const char *uuid, const char *task, node_t * on_node)
{
    GListPtr gIter = NULL;

    CRM_CHECK(uuid || task, return NULL);

    for (gIter = input; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (uuid != NULL && safe_str_neq(uuid, action->uuid)) {
            continue;

        } else if (task != NULL && safe_str_neq(task, action->task)) {
            continue;

        } else if (on_node == NULL) {
            return action;

        } else if (action->node == NULL) {
            continue;

        } else if (on_node->details == action->node->details) {
            return action;
        }
    }

    return NULL;
}

GListPtr
find_actions(GListPtr input, const char *key, const node_t *on_node)
{
    GListPtr gIter = input;
    GListPtr result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        if (safe_str_neq(key, action->uuid)) {
            crm_trace("%s does not match action %s", key, action->uuid);
            continue;

        } else if (on_node == NULL) {
            crm_trace("Action %s matches (ignoring node)", key);
            result = g_list_prepend(result, action);

        } else if (action->node == NULL) {
            crm_trace("Action %s matches (unallocated, assigning to %s)",
                      key, on_node->details->uname);

            action->node = node_copy(on_node);
            result = g_list_prepend(result, action);

        } else if (on_node->details == action->node->details) {
            crm_trace("Action %s on %s matches", key, on_node->details->uname);
            result = g_list_prepend(result, action);

        } else {
            crm_trace("Action %s on node %s does not match requested node %s",
                      key, action->node->details->uname,
                      on_node->details->uname);
        }
    }

    return result;
}

GListPtr
find_actions_exact(GListPtr input, const char *key, node_t * on_node)
{
    GListPtr gIter = input;
    GListPtr result = NULL;

    CRM_CHECK(key != NULL, return NULL);

    for (; gIter != NULL; gIter = gIter->next) {
        action_t *action = (action_t *) gIter->data;

        crm_trace("Matching %s against %s", key, action->uuid);
        if (safe_str_neq(key, action->uuid)) {
            crm_trace("Key mismatch: %s vs. %s", key, action->uuid);
            continue;

        } else if (on_node == NULL || action->node == NULL) {
            crm_trace("on_node=%p, action->node=%p", on_node, action->node);
            continue;

        } else if (safe_str_eq(on_node->details->id, action->node->details->id)) {
            result = g_list_prepend(result, action);
        }
        crm_trace("Node mismatch: %s vs. %s", on_node->details->id, action->node->details->id);
    }

    return result;
}

static void
resource_node_score(resource_t * rsc, node_t * node, int score, const char *tag)
{
    node_t *match = NULL;

    if ((rsc->exclusive_discover || (node->rsc_discover_mode == pe_discover_never))
        && safe_str_eq(tag, "symmetric_default")) {
        /* This string comparision may be fragile, but exclusive resources and
         * exclusive nodes should not have the symmetric_default constraint
         * applied to them.
         */
        return;

    } else if (rsc->children) {
        GListPtr gIter = rsc->children;

        for (; gIter != NULL; gIter = gIter->next) {
            resource_t *child_rsc = (resource_t *) gIter->data;

            resource_node_score(child_rsc, node, score, tag);
        }
    }

    pe_rsc_trace(rsc, "Setting %s for %s on %s: %d", tag, rsc->id, node->details->uname, score);
    match = pe_hash_table_lookup(rsc->allowed_nodes, node->details->id);
    if (match == NULL) {
        match = node_copy(node);
        g_hash_table_insert(rsc->allowed_nodes, (gpointer) match->details->id, match);
    }
    match->weight = merge_weights(match->weight, score);
}

void
resource_location(resource_t * rsc, node_t * node, int score, const char *tag,
                  pe_working_set_t * data_set)
{
    if (node != NULL) {
        resource_node_score(rsc, node, score, tag);

    } else if (data_set != NULL) {
        GListPtr gIter = data_set->nodes;

        for (; gIter != NULL; gIter = gIter->next) {
            node_t *node_iter = (node_t *) gIter->data;

            resource_node_score(rsc, node_iter, score, tag);
        }

    } else {
        GHashTableIter iter;
        node_t *node_iter = NULL;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node_iter)) {
            resource_node_score(rsc, node_iter, score, tag);
        }
    }

    if (node == NULL && score == -INFINITY) {
        if (rsc->allocated_to) {
            crm_info("Deallocating %s from %s", rsc->id, rsc->allocated_to->details->uname);
            free(rsc->allocated_to);
            rsc->allocated_to = NULL;
        }
    }
}

#define sort_return(an_int, why) do {					\
	free(a_uuid);						\
	free(b_uuid);						\
	crm_trace("%s (%d) %c %s (%d) : %s",				\
		  a_xml_id, a_call_id, an_int>0?'>':an_int<0?'<':'=',	\
		  b_xml_id, b_call_id, why);				\
	return an_int;							\
    } while(0)

gint
sort_op_by_callid(gconstpointer a, gconstpointer b)
{
    int a_call_id = -1;
    int b_call_id = -1;

    char *a_uuid = NULL;
    char *b_uuid = NULL;

    const xmlNode *xml_a = a;
    const xmlNode *xml_b = b;

    const char *a_xml_id = crm_element_value(xml_a, XML_ATTR_ID);
    const char *b_xml_id = crm_element_value(xml_b, XML_ATTR_ID);

    if (safe_str_eq(a_xml_id, b_xml_id)) {
        /* We have duplicate lrm_rsc_op entries in the status
         *    section which is unliklely to be a good thing
         *    - we can handle it easily enough, but we need to get
         *    to the bottom of why it's happening.
         */
        pe_err("Duplicate lrm_rsc_op entries named %s", a_xml_id);
        sort_return(0, "duplicate");
    }

    crm_element_value_int(xml_a, XML_LRM_ATTR_CALLID, &a_call_id);
    crm_element_value_int(xml_b, XML_LRM_ATTR_CALLID, &b_call_id);

    if (a_call_id == -1 && b_call_id == -1) {
        /* both are pending ops so it doesn't matter since
         *   stops are never pending
         */
        sort_return(0, "pending");

    } else if (a_call_id >= 0 && a_call_id < b_call_id) {
        sort_return(-1, "call id");

    } else if (b_call_id >= 0 && a_call_id > b_call_id) {
        sort_return(1, "call id");

    } else if (b_call_id >= 0 && a_call_id == b_call_id) {
        /*
         * The op and last_failed_op are the same
         * Order on last-rc-change
         */
        int last_a = -1;
        int last_b = -1;

        crm_element_value_int(xml_a, XML_RSC_OP_LAST_CHANGE, &last_a);
        crm_element_value_int(xml_b, XML_RSC_OP_LAST_CHANGE, &last_b);

        crm_trace("rc-change: %d vs %d", last_a, last_b);
        if (last_a >= 0 && last_a < last_b) {
            sort_return(-1, "rc-change");

        } else if (last_b >= 0 && last_a > last_b) {
            sort_return(1, "rc-change");
        }
        sort_return(0, "rc-change");

    } else {
        /* One of the inputs is a pending operation
         * Attempt to use XML_ATTR_TRANSITION_MAGIC to determine its age relative to the other
         */

        int a_id = -1;
        int b_id = -1;
        int dummy = -1;

        const char *a_magic = crm_element_value(xml_a, XML_ATTR_TRANSITION_MAGIC);
        const char *b_magic = crm_element_value(xml_b, XML_ATTR_TRANSITION_MAGIC);

        CRM_CHECK(a_magic != NULL && b_magic != NULL, sort_return(0, "No magic"));
        if(!decode_transition_magic(a_magic, &a_uuid, &a_id, &dummy, &dummy, &dummy, &dummy)) {
            sort_return(0, "bad magic a");
        }
        if(!decode_transition_magic(b_magic, &b_uuid, &b_id, &dummy, &dummy, &dummy, &dummy)) {
            sort_return(0, "bad magic b");
        }
        /* try to determine the relative age of the operation...
         * some pending operations (e.g. a start) may have been superseded
         *   by a subsequent stop
         *
         * [a|b]_id == -1 means it's a shutdown operation and _always_ comes last
         */
        if (safe_str_neq(a_uuid, b_uuid) || a_id == b_id) {
            /*
             * some of the logic in here may be redundant...
             *
             * if the UUID from the TE doesn't match then one better
             *   be a pending operation.
             * pending operations don't survive between elections and joins
             *   because we query the LRM directly
             */

            if (b_call_id == -1) {
                sort_return(-1, "transition + call");

            } else if (a_call_id == -1) {
                sort_return(1, "transition + call");
            }

        } else if ((a_id >= 0 && a_id < b_id) || b_id == -1) {
            sort_return(-1, "transition");

        } else if ((b_id >= 0 && a_id > b_id) || a_id == -1) {
            sort_return(1, "transition");
        }
    }

    /* we should never end up here */
    CRM_CHECK(FALSE, sort_return(0, "default"));

}

time_t
get_effective_time(pe_working_set_t * data_set)
{
    if(data_set) {
        if (data_set->now == NULL) {
            crm_trace("Recording a new 'now'");
            data_set->now = crm_time_new(NULL);
        }
        return crm_time_get_seconds_since_epoch(data_set->now);
    }

    crm_trace("Defaulting to 'now'");
    return time(NULL);
}

gboolean
get_target_role(resource_t * rsc, enum rsc_role_e * role)
{
    enum rsc_role_e local_role = RSC_ROLE_UNKNOWN;
    const char *value = g_hash_table_lookup(rsc->meta, XML_RSC_ATTR_TARGET_ROLE);

    CRM_CHECK(role != NULL, return FALSE);

    if (value == NULL || safe_str_eq("started", value)
        || safe_str_eq("default", value)) {
        return FALSE;
    }

    local_role = text2role(value);
    if (local_role == RSC_ROLE_UNKNOWN) {
        crm_config_err("%s: Unknown value for %s: %s", rsc->id, XML_RSC_ATTR_TARGET_ROLE, value);
        return FALSE;

    } else if (local_role > RSC_ROLE_STARTED) {
        if (is_set(uber_parent(rsc)->flags, pe_rsc_promotable)) {
            if (local_role > RSC_ROLE_SLAVE) {
                /* This is what we'd do anyway, just leave the default to avoid messing up the placement algorithm */
                return FALSE;
            }

        } else {
            crm_config_err("%s is not part of a promotable clone resource, a %s of '%s' makes no sense",
                           rsc->id, XML_RSC_ATTR_TARGET_ROLE, value);
            return FALSE;
        }
    }

    *role = local_role;
    return TRUE;
}

gboolean
order_actions(action_t * lh_action, action_t * rh_action, enum pe_ordering order)
{
    GListPtr gIter = NULL;
    action_wrapper_t *wrapper = NULL;
    GListPtr list = NULL;

    if (order == pe_order_none) {
        return FALSE;
    }

    if (lh_action == NULL || rh_action == NULL) {
        return FALSE;
    }

    crm_trace("Ordering Action %s before %s", lh_action->uuid, rh_action->uuid);

    /* Ensure we never create a dependency on ourselves... it's happened */
    CRM_ASSERT(lh_action != rh_action);

    /* Filter dups, otherwise update_action_states() has too much work to do */
    gIter = lh_action->actions_after;
    for (; gIter != NULL; gIter = gIter->next) {
        action_wrapper_t *after = (action_wrapper_t *) gIter->data;

        if (after->action == rh_action && (after->type & order)) {
            return FALSE;
        }
    }

    wrapper = calloc(1, sizeof(action_wrapper_t));
    wrapper->action = rh_action;
    wrapper->type = order;

    list = lh_action->actions_after;
    list = g_list_prepend(list, wrapper);
    lh_action->actions_after = list;

    wrapper = NULL;

/* 	order |= pe_order_implies_then; */
/* 	order ^= pe_order_implies_then; */

    wrapper = calloc(1, sizeof(action_wrapper_t));
    wrapper->action = lh_action;
    wrapper->type = order;
    list = rh_action->actions_before;
    list = g_list_prepend(list, wrapper);
    rh_action->actions_before = list;
    return TRUE;
}

action_t *
get_pseudo_op(const char *name, pe_working_set_t * data_set)
{
    action_t *op = NULL;

    if(data_set->singletons) {
        op = g_hash_table_lookup(data_set->singletons, name);
    }
    if (op == NULL) {
        op = custom_action(NULL, strdup(name), name, NULL, TRUE, TRUE, data_set);
        set_bit(op->flags, pe_action_pseudo);
        set_bit(op->flags, pe_action_runnable);
    }

    return op;
}

void
destroy_ticket(gpointer data)
{
    ticket_t *ticket = data;

    if (ticket->state) {
        g_hash_table_destroy(ticket->state);
    }
    free(ticket->id);
    free(ticket);
}

ticket_t *
ticket_new(const char *ticket_id, pe_working_set_t * data_set)
{
    ticket_t *ticket = NULL;

    if (ticket_id == NULL || strlen(ticket_id) == 0) {
        return NULL;
    }

    if (data_set->tickets == NULL) {
        data_set->tickets =
            g_hash_table_new_full(crm_str_hash, g_str_equal, free,
                                  destroy_ticket);
    }

    ticket = g_hash_table_lookup(data_set->tickets, ticket_id);
    if (ticket == NULL) {

        ticket = calloc(1, sizeof(ticket_t));
        if (ticket == NULL) {
            crm_err("Cannot allocate ticket '%s'", ticket_id);
            return NULL;
        }

        crm_trace("Creaing ticket entry for %s", ticket_id);

        ticket->id = strdup(ticket_id);
        ticket->granted = FALSE;
        ticket->last_granted = -1;
        ticket->standby = FALSE;
        ticket->state = crm_str_table_new();

        g_hash_table_insert(data_set->tickets, strdup(ticket->id), ticket);
    }

    return ticket;
}

static void
filter_parameters(xmlNode * param_set, const char *param_string, bool need_present)
{
    if (param_set && param_string) {
        xmlAttrPtr xIter = param_set->properties;

        while (xIter) {
            const char *prop_name = (const char *)xIter->name;
            char *name = crm_strdup_printf(" %s ", prop_name);
            char *match = strstr(param_string, name);

            free(name);

            //  Do now, because current entry might get removed below
            xIter = xIter->next;

            if (need_present && match == NULL) {
                crm_trace("%s not found in %s", prop_name, param_string);
                xml_remove_prop(param_set, prop_name);

            } else if (need_present == FALSE && match) {
                crm_trace("%s found in %s", prop_name, param_string);
                xml_remove_prop(param_set, prop_name);
            }
        }
    }
}

#if ENABLE_VERSIONED_ATTRS
static void
append_versioned_params(xmlNode *versioned_params, const char *ra_version, xmlNode *params)
{
    GHashTable *hash = pe_unpack_versioned_parameters(versioned_params, ra_version);
    char *key = NULL;
    char *value = NULL;
    GHashTableIter iter;

    g_hash_table_iter_init(&iter, hash);
    while (g_hash_table_iter_next(&iter, (gpointer *) &key, (gpointer *) &value)) {
        crm_xml_add(params, key, value);
    }
    g_hash_table_destroy(hash);
}
#endif

static op_digest_cache_t *
rsc_action_digest(resource_t * rsc, const char *task, const char *key,
                  node_t * node, xmlNode * xml_op, pe_working_set_t * data_set) 
{
    op_digest_cache_t *data = NULL;

    data = g_hash_table_lookup(node->details->digest_cache, key);
    if (data == NULL) {
        GHashTable *local_rsc_params = crm_str_table_new();
        action_t *action = custom_action(rsc, strdup(key), task, node, TRUE, FALSE, data_set);
#if ENABLE_VERSIONED_ATTRS
        xmlNode *local_versioned_params = create_xml_node(NULL, XML_TAG_RSC_VER_ATTRS);
        const char *ra_version = NULL;
#endif

        const char *op_version;
        const char *restart_list = NULL;
        const char *secure_list = " passwd password ";

        data = calloc(1, sizeof(op_digest_cache_t));
        CRM_ASSERT(data != NULL);

        get_rsc_attributes(local_rsc_params, rsc, node, data_set);
#if ENABLE_VERSIONED_ATTRS
        pe_get_versioned_attributes(local_versioned_params, rsc, node, data_set);
#endif

        data->params_all = create_xml_node(NULL, XML_TAG_PARAMS);

        // REMOTE_CONTAINER_HACK: Allow remote nodes that start containers with pacemaker remote inside
        if (container_fix_remote_addr_in(rsc, data->params_all, "addr")) {
            crm_trace("Fixed addr for %s on %s", rsc->id, node->details->uname);
        }

        g_hash_table_foreach(local_rsc_params, hash2field, data->params_all);
        g_hash_table_foreach(action->extra, hash2field, data->params_all);
        g_hash_table_foreach(rsc->parameters, hash2field, data->params_all);
        g_hash_table_foreach(action->meta, hash2metafield, data->params_all);

        if(xml_op) {
            secure_list = crm_element_value(xml_op, XML_LRM_ATTR_OP_SECURE);
            restart_list = crm_element_value(xml_op, XML_LRM_ATTR_OP_RESTART);

            op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
#if ENABLE_VERSIONED_ATTRS
            ra_version = crm_element_value(xml_op, XML_ATTR_RA_VERSION);
#endif

        } else {
            op_version = CRM_FEATURE_SET;
        }

#if ENABLE_VERSIONED_ATTRS
        append_versioned_params(local_versioned_params, ra_version, data->params_all);
        append_versioned_params(rsc->versioned_parameters, ra_version, data->params_all);

        {
            pe_rsc_action_details_t *details = pe_rsc_action_details(action);
            append_versioned_params(details->versioned_parameters, ra_version, data->params_all);
        }
#endif

        filter_action_parameters(data->params_all, op_version);

        g_hash_table_destroy(local_rsc_params);
        pe_free_action(action);

        data->digest_all_calc = calculate_operation_digest(data->params_all, op_version);

        if (is_set(data_set->flags, pe_flag_sanitized)) {
            data->params_secure = copy_xml(data->params_all);
            if(secure_list) {
                filter_parameters(data->params_secure, secure_list, FALSE);
            }
            data->digest_secure_calc = calculate_operation_digest(data->params_secure, op_version);
        }

        if(xml_op && crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST) != NULL) {
            data->params_restart = copy_xml(data->params_all);
            if (restart_list) {
                filter_parameters(data->params_restart, restart_list, TRUE);
            }
            data->digest_restart_calc = calculate_operation_digest(data->params_restart, op_version);
        }

        g_hash_table_insert(node->details->digest_cache, strdup(key), data);
    }

    return data;
}

op_digest_cache_t *
rsc_action_digest_cmp(resource_t * rsc, xmlNode * xml_op, node_t * node,
                      pe_working_set_t * data_set)
{
    op_digest_cache_t *data = NULL;

    char *key = NULL;
    guint interval_ms = 0;

    const char *op_version;
    const char *task = crm_element_value(xml_op, XML_LRM_ATTR_TASK);
    const char *interval_ms_s = crm_element_value(xml_op,
                                                  XML_LRM_ATTR_INTERVAL_MS);
    const char *digest_all;
    const char *digest_restart;

    CRM_ASSERT(node != NULL);

    op_version = crm_element_value(xml_op, XML_ATTR_CRM_VERSION);
    digest_all = crm_element_value(xml_op, XML_LRM_ATTR_OP_DIGEST);
    digest_restart = crm_element_value(xml_op, XML_LRM_ATTR_RESTART_DIGEST);

    interval_ms = crm_parse_ms(interval_ms_s);
    key = generate_op_key(rsc->id, task, interval_ms);
    data = rsc_action_digest(rsc, task, key, node, xml_op, data_set);

    data->rc = RSC_DIGEST_MATCH;
    if (digest_restart && data->digest_restart_calc && strcmp(data->digest_restart_calc, digest_restart) != 0) {
        pe_rsc_info(rsc, "Parameters to %s on %s changed: was %s vs. now %s (restart:%s) %s",
                 key, node->details->uname,
                 crm_str(digest_restart), data->digest_restart_calc,
                 op_version, crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        data->rc = RSC_DIGEST_RESTART;

    } else if (digest_all == NULL) {
        /* it is unknown what the previous op digest was */
        data->rc = RSC_DIGEST_UNKNOWN;

    } else if (strcmp(digest_all, data->digest_all_calc) != 0) {
        pe_rsc_info(rsc, "Parameters to %s on %s changed: was %s vs. now %s (%s:%s) %s",
                 key, node->details->uname,
                 crm_str(digest_all), data->digest_all_calc,
                 (interval_ms > 0)? "reschedule" : "reload",
                 op_version, crm_element_value(xml_op, XML_ATTR_TRANSITION_MAGIC));
        data->rc = RSC_DIGEST_ALL;
    }

    free(key);
    return data;
}

#define STONITH_DIGEST_TASK "stonith-on"

static op_digest_cache_t *
fencing_action_digest_cmp(resource_t * rsc, node_t * node, pe_working_set_t * data_set)
{
    char *key = generate_op_key(rsc->id, STONITH_DIGEST_TASK, 0);
    op_digest_cache_t *data = rsc_action_digest(rsc, STONITH_DIGEST_TASK, key, node, NULL, data_set);

    const char *digest_all = pe_node_attribute_raw(node, CRM_ATTR_DIGESTS_ALL);
    const char *digest_secure = pe_node_attribute_raw(node, CRM_ATTR_DIGESTS_SECURE);

    /* No 'reloads' for fencing device changes
     *
     * We use the resource id + agent + digest so that we can detect
     * changes to the agent and/or the parameters used
     */
    char *search_all = crm_strdup_printf("%s:%s:%s", rsc->id, (const char*)g_hash_table_lookup(rsc->meta, XML_ATTR_TYPE), data->digest_all_calc);
    char *search_secure = crm_strdup_printf("%s:%s:%s", rsc->id, (const char*)g_hash_table_lookup(rsc->meta, XML_ATTR_TYPE), data->digest_secure_calc);

    data->rc = RSC_DIGEST_ALL;
    if (digest_all == NULL) {
        /* it is unknown what the previous op digest was */
        data->rc = RSC_DIGEST_UNKNOWN;

    } else if (strstr(digest_all, search_all)) {
        data->rc = RSC_DIGEST_MATCH;

    } else if(digest_secure && data->digest_secure_calc) {
        if(strstr(digest_secure, search_secure)) {
            if (is_set(data_set->flags, pe_flag_sanitized)) {
                printf("Only 'private' parameters to %s for unfencing %s changed\n",
                       rsc->id, node->details->uname);
            }
            data->rc = RSC_DIGEST_MATCH;
        }
    }

    if (data->rc == RSC_DIGEST_ALL && is_set(data_set->flags, pe_flag_sanitized) && data->digest_secure_calc) {
        if (is_set(data_set->flags, pe_flag_sanitized)) {
            printf("Parameters to %s for unfencing %s changed, try '%s:%s:%s'\n",
                   rsc->id, node->details->uname, rsc->id,
                   (const char *) g_hash_table_lookup(rsc->meta, XML_ATTR_TYPE),
                   data->digest_secure_calc);
        }
    }

    free(key);
    free(search_all);
    free(search_secure);

    return data;
}

const char *rsc_printable_id(resource_t *rsc)
{
    if (is_not_set(rsc->flags, pe_rsc_unique)) {
        return ID(rsc->xml);
    }
    return rsc->id;
}

void
clear_bit_recursive(resource_t * rsc, unsigned long long flag)
{
    GListPtr gIter = rsc->children;

    clear_bit(rsc->flags, flag);
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        clear_bit_recursive(child_rsc, flag);
    }
}

void
set_bit_recursive(resource_t * rsc, unsigned long long flag)
{
    GListPtr gIter = rsc->children;

    set_bit(rsc->flags, flag);
    for (; gIter != NULL; gIter = gIter->next) {
        resource_t *child_rsc = (resource_t *) gIter->data;

        set_bit_recursive(child_rsc, flag);
    }
}

static GListPtr
find_unfencing_devices(GListPtr candidates, GListPtr matches) 
{
    for (GListPtr gIter = candidates; gIter != NULL; gIter = gIter->next) {
        resource_t *candidate = gIter->data;
        const char *provides = g_hash_table_lookup(candidate->meta, XML_RSC_ATTR_PROVIDES);
        const char *requires = g_hash_table_lookup(candidate->meta, XML_RSC_ATTR_REQUIRES);

        if(candidate->children) {
            matches = find_unfencing_devices(candidate->children, matches);
        } else if (is_not_set(candidate->flags, pe_rsc_fence_device)) {
            continue;

        } else if (crm_str_eq(provides, "unfencing", FALSE) || crm_str_eq(requires, "unfencing", FALSE)) {
            matches = g_list_prepend(matches, candidate);
        }
    }
    return matches;
}


action_t *
pe_fence_op(node_t * node, const char *op, bool optional, const char *reason, pe_working_set_t * data_set)
{
    char *op_key = NULL;
    action_t *stonith_op = NULL;

    if(op == NULL) {
        op = data_set->stonith_action;
    }

    op_key = crm_strdup_printf("%s-%s-%s", CRM_OP_FENCE, node->details->uname, op);

    if(data_set->singletons) {
        stonith_op = g_hash_table_lookup(data_set->singletons, op_key);
    }

    if(stonith_op == NULL) {
        stonith_op = custom_action(NULL, op_key, CRM_OP_FENCE, node, TRUE, TRUE, data_set);

        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET, node->details->uname);
        add_hash_param(stonith_op->meta, XML_LRM_ATTR_TARGET_UUID, node->details->id);
        add_hash_param(stonith_op->meta, "stonith_action", op);

        if(is_remote_node(node) && is_set(data_set->flags, pe_flag_enable_unfencing)) {
            /* Extra work to detect device changes on remotes
             *
             * We may do this for all nodes in the future, but for now
             * the check_action_definition() based stuff works fine.
             *
             * Use "stonith-on" to avoid creating cache entries for
             * operations check_action_definition() would look for.
             */
            long max = 1024;
            long digests_all_offset = 0;
            long digests_secure_offset = 0;

            char *digests_all = malloc(max);
            char *digests_secure = malloc(max);
            GListPtr matches = find_unfencing_devices(data_set->resources, NULL);

            for (GListPtr gIter = matches; gIter != NULL; gIter = gIter->next) {
                resource_t *match = gIter->data;
                op_digest_cache_t *data = fencing_action_digest_cmp(match, node, data_set);

                if(data->rc == RSC_DIGEST_ALL) {
                    optional = FALSE;
                    crm_notice("Unfencing %s (remote): because the definition of %s changed", node->details->uname, match->id);
                    if (is_set(data_set->flags, pe_flag_sanitized)) {
                        /* Extra detail for those running from the commandline */
                        fprintf(stdout, "  notice: Unfencing %s (remote): because the definition of %s changed\n", node->details->uname, match->id);
                    }
                }

                digests_all_offset += snprintf(
                    digests_all+digests_all_offset, max-digests_all_offset,
                    "%s:%s:%s,", match->id, (const char*)g_hash_table_lookup(match->meta, XML_ATTR_TYPE), data->digest_all_calc);

                digests_secure_offset += snprintf(
                    digests_secure+digests_secure_offset, max-digests_secure_offset,
                    "%s:%s:%s,", match->id, (const char*)g_hash_table_lookup(match->meta, XML_ATTR_TYPE), data->digest_secure_calc);
            }
            g_hash_table_insert(stonith_op->meta,
                                strdup(XML_OP_ATTR_DIGESTS_ALL),
                                digests_all);
            g_hash_table_insert(stonith_op->meta,
                                strdup(XML_OP_ATTR_DIGESTS_SECURE),
                                digests_secure);
        }

    } else {
        free(op_key);
    }

    if(optional == FALSE && pe_can_fence(data_set, node)) {
        pe_action_required(stonith_op, NULL, reason);
    } else if(reason && stonith_op->reason == NULL) {
        stonith_op->reason = strdup(reason);
    }

    return stonith_op;
}

void
trigger_unfencing(
    resource_t * rsc, node_t *node, const char *reason, action_t *dependency, pe_working_set_t * data_set) 
{
    if(is_not_set(data_set->flags, pe_flag_enable_unfencing)) {
        /* No resources require it */
        return;

    } else if (rsc != NULL && is_not_set(rsc->flags, pe_rsc_fence_device)) {
        /* Wasn't a stonith device */
        return;

    } else if(node
              && node->details->online
              && node->details->unclean == FALSE
              && node->details->shutdown == FALSE) {
        action_t *unfence = pe_fence_op(node, "on", FALSE, reason, data_set);

        if(dependency) {
            order_actions(unfence, dependency, pe_order_optional);
        }

    } else if(rsc) {
        GHashTableIter iter;

        g_hash_table_iter_init(&iter, rsc->allowed_nodes);
        while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
            if(node->details->online && node->details->unclean == FALSE && node->details->shutdown == FALSE) {
                trigger_unfencing(rsc, node, reason, dependency, data_set);
            }
        }
    }
}

gboolean
add_tag_ref(GHashTable * tags, const char * tag_name,  const char * obj_ref)
{
    tag_t *tag = NULL;
    GListPtr gIter = NULL;
    gboolean is_existing = FALSE;

    CRM_CHECK(tags && tag_name && obj_ref, return FALSE);

    tag = g_hash_table_lookup(tags, tag_name);
    if (tag == NULL) {
        tag = calloc(1, sizeof(tag_t));
        if (tag == NULL) {
            return FALSE;
        }
        tag->id = strdup(tag_name);
        tag->refs = NULL;
        g_hash_table_insert(tags, strdup(tag_name), tag);
    }

    for (gIter = tag->refs; gIter != NULL; gIter = gIter->next) {
        const char *existing_ref = (const char *) gIter->data;

        if (crm_str_eq(existing_ref, obj_ref, TRUE)){
            is_existing = TRUE;
            break;
        }
    }

    if (is_existing == FALSE) {
        tag->refs = g_list_append(tag->refs, strdup(obj_ref));
        crm_trace("Added: tag=%s ref=%s", tag->id, obj_ref);
    }

    return TRUE;
}

void pe_action_set_flag_reason(const char *function, long line,
                               pe_action_t *action, pe_action_t *reason, const char *text,
                               enum pe_action_flags flags, bool overwrite)
{
    bool unset = FALSE;
    bool update = FALSE;
    const char *change = NULL;

    if(is_set(flags, pe_action_runnable)) {
        unset = TRUE;
        change = "unrunnable";
    } else if(is_set(flags, pe_action_optional)) {
        unset = TRUE;
        change = "required";
    } else if(is_set(flags, pe_action_migrate_runnable)) {
        unset = TRUE;
        overwrite = TRUE;
        change = "unrunnable";
    } else if(is_set(flags, pe_action_dangle)) {
        change = "dangling";
    } else if(is_set(flags, pe_action_requires_any)) {
        change = "required";
    } else {
        crm_err("Unknown flag change to %s by %s: 0x%.16x",
                flags, action->uuid, (reason? reason->uuid : 0));
    }

    if(unset) {
        if(is_set(action->flags, flags)) {
            action->flags = crm_clear_bit(function, line, action->uuid, action->flags, flags);
            update = TRUE;
        }

    } else {
        if(is_not_set(action->flags, flags)) {
            action->flags = crm_set_bit(function, line, action->uuid, action->flags, flags);
            update = TRUE;
        }
    }

    if((change && update) || text) {
        char *reason_text = NULL;
        if(reason == NULL) {
            pe_action_set_reason(action, text, overwrite);

        } else if(reason->rsc == NULL) {
            reason_text = crm_strdup_printf("%s %s%c %s", change, reason->task, text?':':0, text?text:"");
        } else {
            reason_text = crm_strdup_printf("%s %s %s%c %s", change, reason->rsc->id, reason->task, text?':':0, text?text:"NA");
        }

        if(reason_text && action->rsc != reason->rsc) {
            pe_action_set_reason(action, reason_text, overwrite);
        }
        free(reason_text);
    }
 }

void pe_action_set_reason(pe_action_t *action, const char *reason, bool overwrite) 
{
    if(action->reason && overwrite) {
        pe_rsc_trace(action->rsc, "Changing %s reason from '%s' to '%s'", action->uuid, action->reason, reason);
        free(action->reason);
        action->reason = NULL;
    }
    if(action->reason == NULL) {
        if(reason) {
            pe_rsc_trace(action->rsc, "Set %s reason to '%s'", action->uuid, reason);
            action->reason = strdup(reason);
        } else {
            action->reason = NULL;
        }
    }
}

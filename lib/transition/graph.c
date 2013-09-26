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
#include <crm/transition.h>
/* #include <sys/param.h> */
/*  */

#include <graph.h>

crm_graph_functions_t *graph_fns = NULL;

static gboolean
update_synapse_ready(synapse_t * synapse, int action_id)
{
    GListPtr lpc = NULL;
    gboolean updates = FALSE;

    CRM_CHECK(synapse->executed == FALSE, return FALSE);
    CRM_CHECK(synapse->confirmed == FALSE, return FALSE);

    synapse->ready = TRUE;
    for (lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        crm_action_t *prereq = (crm_action_t *) lpc->data;

        crm_trace("Processing input %d", prereq->id);

        if (prereq->id == action_id) {
            crm_trace("Marking input %d of synapse %d confirmed", action_id, synapse->id);
            prereq->confirmed = TRUE;
            updates = TRUE;

        } else if (prereq->confirmed == FALSE) {
            synapse->ready = FALSE;
        }

    }

    if (updates) {
        crm_trace("Updated synapse %d", synapse->id);
    }
    return updates;
}

static gboolean
update_synapse_confirmed(synapse_t * synapse, int action_id)
{
    GListPtr lpc = NULL;
    gboolean updates = FALSE;
    gboolean is_confirmed = TRUE;

    CRM_CHECK(synapse->executed, return FALSE);
    CRM_CHECK(synapse->confirmed == FALSE, return TRUE);

    is_confirmed = TRUE;
    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        crm_trace("Processing action %d", action->id);

        if (action->id == action_id) {
            crm_trace("Confirmed: Action %d of Synapse %d", action_id, synapse->id);
            action->confirmed = TRUE;
            updates = TRUE;

        } else if (action->confirmed == FALSE) {
            is_confirmed = FALSE;
            crm_trace("Synapse %d still not confirmed after action %d", synapse->id, action_id);
        }
    }

    if (is_confirmed && synapse->confirmed == FALSE) {
        crm_trace("Confirmed: Synapse %d", synapse->id);
        synapse->confirmed = TRUE;
        updates = TRUE;
    }

    if (updates) {
        crm_trace("Updated synapse %d", synapse->id);
    }
    return updates;
}

gboolean
update_graph(crm_graph_t * graph, crm_action_t * action)
{
    gboolean rc = FALSE;
    gboolean updates = FALSE;
    GListPtr lpc = NULL;

    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        synapse_t *synapse = (synapse_t *) lpc->data;

        if (synapse->confirmed || synapse->failed) {
            crm_trace("Synapse complete");

        } else if (synapse->executed) {
            crm_trace("Synapse executed");
            rc = update_synapse_confirmed(synapse, action->id);

        } else if (action->failed == FALSE || synapse->priority == INFINITY) {
            rc = update_synapse_ready(synapse, action->id);
        }
        updates = updates || rc;
    }

    if (updates) {
        crm_trace("Updated graph with completed action %d", action->id);
    }
    return updates;
}

static gboolean
should_fire_synapse(synapse_t * synapse)
{
    GListPtr lpc = NULL;

    CRM_CHECK(synapse->executed == FALSE, return FALSE);
    CRM_CHECK(synapse->confirmed == FALSE, return FALSE);

    crm_trace("Checking pre-reqs for %d", synapse->id);
    /* lookup prereqs */
    synapse->ready = TRUE;
    for (lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        crm_action_t *prereq = (crm_action_t *) lpc->data;

        crm_trace("Processing input %d", prereq->id);
        if (prereq->confirmed == FALSE) {
            crm_trace("Inputs for synapse %d not satisfied", synapse->id);
            synapse->ready = FALSE;
            break;
        }
    }

    return synapse->ready;
}

static gboolean
initiate_action(crm_graph_t * graph, crm_action_t * action)
{
    const char *id = NULL;

    CRM_CHECK(action->executed == FALSE, return FALSE);

    id = ID(action->xml);
    CRM_CHECK(id != NULL, return FALSE);

    action->executed = TRUE;
    if (action->type == action_type_pseudo) {
        crm_trace("Executing pseudo-event: %d", action->id);
        return graph_fns->pseudo(graph, action);

    } else if (action->type == action_type_rsc) {
        crm_trace("Executing rsc-event: %d", action->id);
        return graph_fns->rsc(graph, action);

    } else if (action->type == action_type_crm) {
        const char *task = NULL;

        task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
        CRM_CHECK(task != NULL, return FALSE);

        if (safe_str_eq(task, CRM_OP_FENCE)) {
            crm_trace("Executing STONITH-event: %d", action->id);
            return graph_fns->stonith(graph, action);
        }

        crm_trace("Executing crm-event: %d", action->id);
        return graph_fns->crmd(graph, action);
    }

    crm_err("Failed on unsupported command type: %s (id=%s)", crm_element_name(action->xml), id);
    return FALSE;
}

static gboolean
fire_synapse(crm_graph_t * graph, synapse_t * synapse)
{
    GListPtr lpc = NULL;

    CRM_CHECK(synapse != NULL, return FALSE);
    CRM_CHECK(synapse->ready, return FALSE);
    CRM_CHECK(synapse->confirmed == FALSE, return TRUE);

    crm_trace("Synapse %d fired", synapse->id);
    synapse->executed = TRUE;
    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        /* allow some leeway */
        gboolean passed = FALSE;

        /* Invoke the action and start the timer */
        passed = initiate_action(graph, action);
        if (passed == FALSE) {
            crm_err("Failed initiating <%s id=%d> in synapse %d",
                    crm_element_name(action->xml), action->id, synapse->id);
            synapse->confirmed = TRUE;
            action->confirmed = TRUE;
            action->failed = TRUE;
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
count_actions(crm_graph_t * graph, synapse_t * synapse)
{
    GListPtr lpc = NULL;

    CRM_CHECK(synapse != NULL, return FALSE);

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        const char *task = NULL;
        const char *node = NULL;
        GListPtr lpc2 = NULL;

        if (action->type != action_type_rsc) {
            continue;
        }

        task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
        node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

        for (lpc2 = graph->action_counters; lpc2 != NULL; lpc2 = lpc2->next) {
            action_counter_t *action_counter = (action_counter_t *) lpc2->data;
            gboolean matched = FALSE;

            if (action_counter->tasks == NULL || g_list_length(action_counter->tasks) == 0) {
                matched = TRUE;

            } else {
                GListPtr lpc3 = NULL;

                for (lpc3 = action_counter->tasks; lpc3 != NULL; lpc3 = lpc3->next) {
                    const char *counter_task = (const char *) lpc3->data;

                    if (safe_str_eq(task, counter_task)) {
                        matched = TRUE;
                        break;
                    }
                }
            }

            if (matched) {
                int *count = g_hash_table_lookup(action_counter->counts, node);

                if (count == NULL) {
                    count = calloc(1, sizeof(int));
                    g_hash_table_insert(action_counter->counts, strdup(node), count);
                }

                (*count)++;
            }
        }
    }
    return TRUE;
}

static int
get_num_cpus(void)
{
    int nprocs = -1;

#ifdef _SC_NPROCESSORS_ONLN
    nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs < 1) {
        crm_debug("Couldn't get the number of processors");

    } else {
	crm_trace("%d processors online", nprocs);
    }
#else
    crm_debug("Cannot get the number of processors on this platform");
#endif

    return nprocs;
}

static gboolean
action_overrun(crm_graph_t * graph, synapse_t * synapse)
{
    int num_cpus = get_num_cpus();
    GListPtr lpc = NULL;

    CRM_CHECK(synapse != NULL, return FALSE);

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;

        const char *task = NULL;
        const char *node = NULL;
        const char *node_name = NULL;
        const char *value = NULL;
        int actions_limit = 0;
        int migration_limit = 0;
        GListPtr lpc2 = NULL;

        if (action->type != action_type_rsc) {
            continue;
        }

        task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
        node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);
        node_name = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

        value = crm_element_value(action->xml, "actions-limit");
        /* If set to zero or unset, defaults to at least 4 or twice the number of CPU cores on the DC. */
        if (value == NULL || crm_int_helper(value, NULL) == 0) {
            actions_limit = num_cpus > 1 ? num_cpus * 2 : 4;

        } else {
            actions_limit = crm_int_helper(value, NULL);
        }

        value = crm_element_value(action->xml, "migration-limit");
        /* If set to zero or unset, defaults to half the number of CPU cores on the DC, or 1. */
        if (value == NULL || crm_int_helper(value, NULL) == 0) {
            migration_limit = num_cpus > 1 ? num_cpus / 2 : 1;

        } else {
            migration_limit = crm_int_helper(value, NULL);
        }

        for (lpc2 = graph->action_counters; lpc2 != NULL; lpc2 = lpc2->next) {
            action_counter_t *action_counter = (action_counter_t *) lpc2->data;
            int *count = g_hash_table_lookup(action_counter->counts, node);

            if (action_counter->tasks == NULL || g_list_length(action_counter->tasks) == 0) {

                /* unlimited */
                if (actions_limit < 0) {
                    continue;
                }

                if (count && *count >= actions_limit) {
                    crm_debug("Throttling output: actions limit (%d) reached on node %s",
                               actions_limit, node_name);
                    return TRUE;
                }

            } else if (safe_str_eq(g_list_nth_data(action_counter->tasks, 0), CRMD_ACTION_MIGRATE)
                       && safe_str_eq(g_list_nth_data(action_counter->tasks, 1), CRMD_ACTION_MIGRATED)) {

                /* unlimited */
                if (migration_limit < 0) {
                    continue;
                }

                if (safe_str_neq(task, CRMD_ACTION_MIGRATE)
                    && safe_str_neq(task, CRMD_ACTION_MIGRATED)) {
                    continue;
                }
            
                if (count && *count >= migration_limit) {
                    crm_debug("Throttling output: migration limit (%d) reached on node %s",
                               migration_limit, node_name);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

static GListPtr
action_counters_init(GListPtr action_counters)
{
    if (action_counters == NULL) {
        int lpc = 0;

        for (lpc = 0; lpc < 2; lpc++) {
            action_counter_t *action_counter = calloc(1, sizeof(action_counter_t));

            switch (lpc) {
                case 0:
                    action_counter->tasks = NULL;
                    break;
                case 1:
                    action_counter->tasks = g_list_append(action_counter->tasks, strdup(CRMD_ACTION_MIGRATE));
                    action_counter->tasks = g_list_append(action_counter->tasks, strdup(CRMD_ACTION_MIGRATED));
                    break;
            }

            action_counter->counts = g_hash_table_new_full(crm_str_hash, g_str_equal, free, free);

            action_counters = g_list_append(action_counters, action_counter);
        }

    } else {
        GListPtr lpc2 = NULL;

        for (lpc2 = action_counters; lpc2 != NULL; lpc2 = lpc2->next) {
            action_counter_t *action_counter = (action_counter_t *) lpc2->data;

            if (action_counter->counts) {
                g_hash_table_remove_all(action_counter->counts);
            }
        }
    }

    return action_counters;
}

int
run_graph(crm_graph_t * graph)
{
    GListPtr lpc = NULL;
    int stat_log_level = LOG_DEBUG;
    int pass_result = transition_active;

    const char *status = "In-progress";

    if (graph_fns == NULL) {
        set_default_graph_functions();
    }
    if (graph == NULL) {
        return transition_complete;
    }

    graph->fired = 0;
    graph->pending = 0;
    graph->skipped = 0;
    graph->completed = 0;
    graph->incomplete = 0;

    graph->action_counters = action_counters_init(graph->action_counters);

    crm_trace("Entering graph %d callback", graph->id);

    /* Pre-calculate the number of completed and in-flight operations */
    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        synapse_t *synapse = (synapse_t *) lpc->data;

        if (synapse->confirmed) {
            crm_trace("Synapse %d complete", synapse->id);
            graph->completed++;

        } else if (synapse->failed == FALSE && synapse->executed) {
            crm_trace("Synapse %d: confirmation pending", synapse->id);
            graph->pending++;

            count_actions(graph, synapse);
        }
    }

    /* Now check if there is work to do */
    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        synapse_t *synapse = (synapse_t *) lpc->data;

        if (graph->batch_limit > 0 && graph->pending >= graph->batch_limit) {
            crm_debug("Throttling output: batch limit (%d) reached", graph->batch_limit);
            break;
        } else if (action_overrun(graph, synapse)) {
            break;

        } else if (synapse->failed) {
            graph->skipped++;
            continue;

        } else if (synapse->confirmed || synapse->executed) {
            /* Already handled */
            continue;
        }

        if (synapse->priority < graph->abort_priority) {
            crm_trace("Skipping synapse %d: aborting", synapse->id);
            graph->skipped++;

        } else if (should_fire_synapse(synapse)) {
            crm_trace("Synapse %d fired", synapse->id);
            graph->fired++;
            if(fire_synapse(graph, synapse) == FALSE) {
                crm_err("Synapse %d failed to fire", synapse->id);
                stat_log_level = LOG_ERR;
                graph->abort_priority = INFINITY;
                graph->incomplete++;
                graph->fired--;
            }

            if (synapse->confirmed == FALSE) {
                graph->pending++;

                count_actions(graph, synapse);
            }

        } else {
            crm_trace("Synapse %d cannot fire", synapse->id);
            graph->incomplete++;
        }
    }

    if (graph->pending == 0 && graph->fired == 0) {
        graph->complete = TRUE;
        stat_log_level = LOG_NOTICE;
        pass_result = transition_complete;
        status = "Complete";

        if (graph->incomplete != 0 && graph->abort_priority <= 0) {
            stat_log_level = LOG_WARNING;
            pass_result = transition_terminated;
            status = "Terminated";

        } else if (graph->skipped != 0) {
            status = "Stopped";
        }

    } else if (graph->fired == 0) {
        pass_result = transition_pending;
    }

    do_crm_log(stat_log_level,
               "Transition %d (Complete=%d, Pending=%d,"
               " Fired=%d, Skipped=%d, Incomplete=%d, Source=%s): %s",
               graph->id, graph->completed, graph->pending, graph->fired,
               graph->skipped, graph->incomplete, graph->source, status);

    return pass_result;
}

/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <sys/param.h>
#include <sys/stat.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <pacemaker-internal.h>

static crm_graph_functions_t *graph_fns = NULL;

static gboolean
update_synapse_ready(synapse_t *synapse, int action_id)
{
    GList *lpc = NULL;
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
    GList *lpc = NULL;
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
    GList *lpc = NULL;

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
should_fire_synapse(crm_graph_t * graph, synapse_t * synapse)
{
    GList *lpc = NULL;

    CRM_CHECK(synapse->executed == FALSE, return FALSE);
    CRM_CHECK(synapse->confirmed == FALSE, return FALSE);

    crm_trace("Checking pre-reqs for synapse %d", synapse->id);
    /* lookup prereqs */
    synapse->ready = TRUE;
    for (lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        crm_action_t *prereq = (crm_action_t *) lpc->data;

        crm_trace("Processing input %d", prereq->id);
        if (prereq->confirmed == FALSE) {
            crm_trace("Input %d for synapse %d not satisfied: not confirmed", prereq->id, synapse->id);
            synapse->ready = FALSE;
            break;
        } else if(prereq->failed && prereq->can_fail == FALSE) {
            crm_trace("Input %d for synapse %d not satisfied: failed", prereq->id, synapse->id);
            synapse->ready = FALSE;
            break;
        }
    }

    for (lpc = synapse->actions; synapse->ready && lpc != NULL; lpc = lpc->next) {
        crm_action_t *a = (crm_action_t *) lpc->data;

        if (a->type == action_type_pseudo) {
            /* None of the below applies to pseudo ops */

        } else if (synapse->priority < graph->abort_priority) {
            crm_trace("Skipping synapse %d: abort level %d", synapse->id, graph->abort_priority);
            graph->skipped++;
            return FALSE;

        } else if(graph_fns->allowed && graph_fns->allowed(graph, a) == FALSE) {
            crm_trace("Deferring synapse %d: allowed", synapse->id);
            return FALSE;
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
        crm_trace("Executing pseudo-event: %s (%d)", id, action->id);
        return graph_fns->pseudo(graph, action);

    } else if (action->type == action_type_rsc) {
        crm_trace("Executing rsc-event: %s (%d)", id, action->id);
        return graph_fns->rsc(graph, action);

    } else if (action->type == action_type_crm) {
        const char *task = NULL;

        task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
        CRM_CHECK(task != NULL, return FALSE);

        if (pcmk__str_eq(task, CRM_OP_FENCE, pcmk__str_casei)) {
            crm_trace("Executing STONITH-event: %s (%d)", id, action->id);
            return graph_fns->stonith(graph, action);
        }

        crm_trace("Executing crm-event: %s (%d)", id, action->id);
        return graph_fns->crmd(graph, action);
    }

    crm_err("Failed on unsupported command type: %s (id=%s)", crm_element_name(action->xml), id);
    return FALSE;
}

static gboolean
fire_synapse(crm_graph_t * graph, synapse_t * synapse)
{
    GList *lpc = NULL;

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
pseudo_action_dummy(crm_graph_t * graph, crm_action_t * action)
{
    static int fail = -1;

    if (fail < 0) {
        long long fail_ll;

        if ((pcmk__scan_ll(getenv("PE_fail"), &fail_ll, 0LL) == pcmk_rc_ok)
            && (fail_ll > 0LL) && (fail_ll <= INT_MAX)) {
            fail = (int) fail_ll;
        } else {
            fail = 0;
        }
    }

    crm_trace("Dummy event handler: action %d executed", action->id);
    if (action->id == fail) {
        crm_err("Dummy event handler: pretending action %d failed", action->id);
        action->failed = TRUE;
        graph->abort_priority = INFINITY;
    }
    action->confirmed = TRUE;
    update_graph(graph, action);
    return TRUE;
}

static crm_graph_functions_t default_fns = {
    pseudo_action_dummy,
    pseudo_action_dummy,
    pseudo_action_dummy,
    pseudo_action_dummy
};

int
run_graph(crm_graph_t * graph)
{
    GList *lpc = NULL;
    int stat_log_level = LOG_DEBUG;
    int pass_result = transition_active;

    const char *status = "In-progress";

    if (graph_fns == NULL) {
        graph_fns = &default_fns;
    }
    if (graph == NULL) {
        return transition_complete;
    }

    graph->fired = 0;
    graph->pending = 0;
    graph->skipped = 0;
    graph->completed = 0;
    graph->incomplete = 0;
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
        }
    }

    /* Now check if there is work to do */
    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        synapse_t *synapse = (synapse_t *) lpc->data;

        if (graph->batch_limit > 0 && graph->pending >= graph->batch_limit) {
            crm_debug("Throttling output: batch limit (%d) reached", graph->batch_limit);
            break;
        } else if (synapse->failed) {
            graph->skipped++;
            continue;

        } else if (synapse->confirmed || synapse->executed) {
            /* Already handled */
            continue;
        }

        if (should_fire_synapse(graph, synapse)) {
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

static crm_action_t *
unpack_action(synapse_t * parent, xmlNode * xml_action)
{
    crm_action_t *action = NULL;
    const char *value = crm_element_value(xml_action, XML_ATTR_ID);

    if (value == NULL) {
        crm_err("Actions must have an id!");
        crm_log_xml_trace(xml_action, "Action with missing id");
        return NULL;
    }

    action = calloc(1, sizeof(crm_action_t));
    if (action == NULL) {
        crm_perror(LOG_CRIT, "Cannot unpack action");
        crm_log_xml_trace(xml_action, "Lost action");
        return NULL;
    }

    pcmk__scan_min_int(value, &(action->id), -1);
    action->type = action_type_rsc;
    action->xml = copy_xml(xml_action);
    action->synapse = parent;

    if (pcmk__str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_RSC_OP, pcmk__str_casei)) {
        action->type = action_type_rsc;

    } else if (pcmk__str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_PSEUDO_EVENT, pcmk__str_casei)) {
        action->type = action_type_pseudo;

    } else if (pcmk__str_eq(crm_element_name(action->xml), XML_GRAPH_TAG_CRM_EVENT, pcmk__str_casei)) {
        action->type = action_type_crm;
    }

    action->params = xml2list(action->xml);

    value = g_hash_table_lookup(action->params, "CRM_meta_timeout");
    pcmk__scan_min_int(value, &(action->timeout), 0);

    /* Take start-delay into account for the timeout of the action timer */
    value = g_hash_table_lookup(action->params, "CRM_meta_start_delay");
    {
        int start_delay;

        pcmk__scan_min_int(value, &start_delay, 0);
        action->timeout += start_delay;
    }

    if (pcmk__guint_from_hash(action->params,
                              CRM_META "_" XML_LRM_ATTR_INTERVAL, 0,
                              &(action->interval_ms)) != pcmk_rc_ok) {
        action->interval_ms = 0;
    }

    value = g_hash_table_lookup(action->params, "CRM_meta_can_fail");
    if (value != NULL) {
        crm_str_to_boolean(value, &(action->can_fail));
#ifndef PCMK__COMPAT_2_0
        if (action->can_fail) {
            crm_warn("Support for the can_fail meta-attribute is deprecated"
                     " and will be removed in a future release");
        }
#endif
    }

    crm_trace("Action %d has timer set to %dms", action->id, action->timeout);

    return action;
}

static synapse_t *
unpack_synapse(crm_graph_t * new_graph, xmlNode * xml_synapse)
{
    const char *value = NULL;
    xmlNode *inputs = NULL;
    xmlNode *action_set = NULL;
    synapse_t *new_synapse = NULL;

    CRM_CHECK(xml_synapse != NULL, return NULL);
    crm_trace("looking in synapse %s", ID(xml_synapse));

    new_synapse = calloc(1, sizeof(synapse_t));
    pcmk__scan_min_int(ID(xml_synapse), &(new_synapse->id), 0);

    value = crm_element_value(xml_synapse, XML_CIB_ATTR_PRIORITY);
    pcmk__scan_min_int(value, &(new_synapse->priority), 0);

    CRM_CHECK(new_synapse->id >= 0, free(new_synapse);
              return NULL);

    new_graph->num_synapses++;

    crm_trace("look for actions in synapse %s", crm_element_value(xml_synapse, XML_ATTR_ID));

    for (action_set = pcmk__xml_first_child(xml_synapse); action_set != NULL;
         action_set = pcmk__xml_next(action_set)) {

        if (pcmk__str_eq((const char *)action_set->name, "action_set",
                         pcmk__str_none)) {
            xmlNode *action = NULL;

            for (action = pcmk__xml_first_child(action_set); action != NULL;
                 action = pcmk__xml_next(action)) {
                crm_action_t *new_action = unpack_action(new_synapse, action);

                if (new_action == NULL) {
                    continue;
                }

                new_graph->num_actions++;

                crm_trace("Adding action %d to synapse %d", new_action->id, new_synapse->id);

                new_synapse->actions = g_list_append(new_synapse->actions, new_action);
            }
        }
    }

    crm_trace("look for inputs in synapse %s", ID(xml_synapse));

    for (inputs = pcmk__xml_first_child(xml_synapse); inputs != NULL;
         inputs = pcmk__xml_next(inputs)) {

        if (pcmk__str_eq((const char *)inputs->name, "inputs", pcmk__str_none)) {
            xmlNode *trigger = NULL;

            for (trigger = pcmk__xml_first_child(inputs); trigger != NULL;
                 trigger = pcmk__xml_next(trigger)) {
                xmlNode *input = NULL;

                for (input = pcmk__xml_first_child(trigger); input != NULL;
                     input = pcmk__xml_next(input)) {
                    crm_action_t *new_input = unpack_action(new_synapse, input);

                    if (new_input == NULL) {
                        continue;
                    }

                    crm_trace("Adding input %d to synapse %d", new_input->id, new_synapse->id);

                    new_synapse->inputs = g_list_append(new_synapse->inputs, new_input);
                }
            }
        }
    }

    return new_synapse;
}

crm_graph_t *
unpack_graph(xmlNode * xml_graph, const char *reference)
{
/*
  <transition_graph>
  <synapse>
  <action_set>
  <rsc_op id="2"
  ...
  <inputs>
  <rsc_op id="2"
  ...
*/
    crm_graph_t *new_graph = NULL;
    const char *t_id = NULL;
    const char *time = NULL;
    xmlNode *synapse = NULL;

    new_graph = calloc(1, sizeof(crm_graph_t));

    new_graph->id = -1;
    new_graph->abort_priority = 0;
    new_graph->network_delay = 0;
    new_graph->stonith_timeout = 0;
    new_graph->completion_action = tg_done;

    if (reference) {
        new_graph->source = strdup(reference);
    } else {
        new_graph->source = strdup("unknown");
    }

    if (xml_graph != NULL) {
        t_id = crm_element_value(xml_graph, "transition_id");
        CRM_CHECK(t_id != NULL, free(new_graph);
                  return NULL);
        pcmk__scan_min_int(t_id, &(new_graph->id), -1);

        time = crm_element_value(xml_graph, "cluster-delay");
        CRM_CHECK(time != NULL, free(new_graph);
                  return NULL);
        new_graph->network_delay = crm_parse_interval_spec(time);

        time = crm_element_value(xml_graph, "stonith-timeout");
        if (time == NULL) {
            new_graph->stonith_timeout = new_graph->network_delay;
        } else {
            new_graph->stonith_timeout = crm_parse_interval_spec(time);
        }

        // Use 0 (dynamic limit) as default/invalid, -1 (no limit) as minimum
        t_id = crm_element_value(xml_graph, "batch-limit");
        if ((t_id == NULL)
            || (pcmk__scan_min_int(t_id, &(new_graph->batch_limit),
                                   -1) != pcmk_rc_ok)) {
            new_graph->batch_limit = 0;
        }

        t_id = crm_element_value(xml_graph, "migration-limit");
        pcmk__scan_min_int(t_id, &(new_graph->migration_limit), -1);
    }

    for (synapse = pcmk__xml_first_child(xml_graph); synapse != NULL;
         synapse = pcmk__xml_next(synapse)) {

        if (pcmk__str_eq((const char *)synapse->name, "synapse", pcmk__str_none)) {
            synapse_t *new_synapse = unpack_synapse(new_graph, synapse);

            if (new_synapse != NULL) {
                new_graph->synapses = g_list_append(new_graph->synapses, new_synapse);
            }
        }
    }

    crm_debug("Unpacked transition %d: %d actions in %d synapses",
              new_graph->id, new_graph->num_actions, new_graph->num_synapses);

    return new_graph;
}

static void
destroy_action(crm_action_t * action)
{
    if (action->timer && action->timer->source_id != 0) {
        crm_warn("Cancelling timer for action %d (src=%d)", action->id, action->timer->source_id);
        g_source_remove(action->timer->source_id);
    }
    if (action->params) {
        g_hash_table_destroy(action->params);
    }
    free_xml(action->xml);
    free(action->timer);
    free(action);
}

static void
destroy_synapse(synapse_t * synapse)
{
    while (synapse->actions != NULL) {
        crm_action_t *action = g_list_nth_data(synapse->actions, 0);

        synapse->actions = g_list_remove(synapse->actions, action);
        destroy_action(action);
    }

    while (synapse->inputs != NULL) {
        crm_action_t *action = g_list_nth_data(synapse->inputs, 0);

        synapse->inputs = g_list_remove(synapse->inputs, action);
        destroy_action(action);
    }
    free(synapse);
}

void
destroy_graph(crm_graph_t * graph)
{
    if (graph == NULL) {
        return;
    }
    while (graph->synapses != NULL) {
        synapse_t *synapse = g_list_nth_data(graph->synapses, 0);

        graph->synapses = g_list_remove(graph->synapses, synapse);
        destroy_synapse(synapse);
    }

    free(graph->source);
    free(graph);
}

lrmd_event_data_t *
convert_graph_action(xmlNode * resource, crm_action_t * action, int status, int rc)
{
    xmlNode *xop = NULL;
    lrmd_event_data_t *op = NULL;
    GHashTableIter iter;
    const char *name = NULL;
    const char *value = NULL;
    xmlNode *action_resource = NULL;

    CRM_CHECK(action != NULL, return NULL);
    CRM_CHECK(action->type == action_type_rsc, return NULL);

    action_resource = first_named_child(action->xml, XML_CIB_TAG_RESOURCE);
    CRM_CHECK(action_resource != NULL, crm_log_xml_warn(action->xml, "Bad");
              return NULL);

    op = lrmd_new_event(ID(action_resource),
                        crm_element_value(action->xml, XML_LRM_ATTR_TASK),
                        action->interval_ms);
    op->rc = rc;
    op->op_status = status;
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;
    op->params = pcmk__strkey_table(free, free);

    g_hash_table_iter_init(&iter, action->params);
    while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
        g_hash_table_insert(op->params, strdup(name), strdup(value));
    }

    for (xop = pcmk__xml_first_child(resource); xop != NULL;
         xop = pcmk__xml_next(xop)) {
        int tmp = 0;

        crm_element_value_int(xop, XML_LRM_ATTR_CALLID, &tmp);
        crm_debug("Got call_id=%d for %s", tmp, ID(resource));
        if (tmp > op->call_id) {
            op->call_id = tmp;
        }
    }

    op->call_id++;
    return op;
}

void
set_graph_functions(crm_graph_functions_t * fns)
{
    crm_info("Setting custom graph functions");
    graph_fns = fns;

    CRM_ASSERT(graph_fns != NULL);
    CRM_ASSERT(graph_fns->rsc != NULL);
    CRM_ASSERT(graph_fns->crmd != NULL);
    CRM_ASSERT(graph_fns->pseudo != NULL);
    CRM_ASSERT(graph_fns->stonith != NULL);
}

static const char *
abort2text(enum transition_action abort_action)
{
    switch (abort_action) {
        case tg_done:
            return "done";
        case tg_stop:
            return "stop";
        case tg_restart:
            return "restart";
        case tg_shutdown:
            return "shutdown";
    }
    return "unknown";
}

bool
update_abort_priority(crm_graph_t * graph, int priority,
                      enum transition_action action, const char *abort_reason)
{
    bool change = FALSE;

    if (graph == NULL) {
        return change;
    }

    if (graph->abort_priority < priority) {
        crm_debug("Abort priority upgraded from %d to %d", graph->abort_priority, priority);
        graph->abort_priority = priority;
        if (graph->abort_reason != NULL) {
            crm_debug("'%s' abort superseded by %s", graph->abort_reason, abort_reason);
        }
        graph->abort_reason = abort_reason;
        change = TRUE;
    }

    if (graph->completion_action < action) {
        crm_debug("Abort action %s superseded by %s: %s",
                  abort2text(graph->completion_action), abort2text(action), abort_reason);
        graph->completion_action = action;
        change = TRUE;
    }

    return change;
}

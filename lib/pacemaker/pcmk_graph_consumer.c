/*
 * Copyright 2004-2025 the Pacemaker project contributors
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
#include <crm/common/xml.h>
#include <crm/common/xml_internal.h>
#include <crm/lrmd_internal.h>
#include <pacemaker-internal.h>


/*
 * Functions for freeing transition graph objects
 */

/*!
 * \internal
 * \brief Free a transition graph action object
 *
 * \param[in,out] user_data  Action to free
 */
static void
free_graph_action(gpointer user_data)
{
    pcmk__graph_action_t *action = user_data;

    if (action->timer != 0) {
        crm_warn("Cancelling timer for graph action %d", action->id);
        g_source_remove(action->timer);
    }
    if (action->params != NULL) {
        g_hash_table_destroy(action->params);
    }
    pcmk__xml_free(action->xml);
    free(action);
}

/*!
 * \internal
 * \brief Free a transition graph synapse object
 *
 * \param[in,out] user_data  Synapse to free
 */
static void
free_graph_synapse(gpointer user_data)
{
    pcmk__graph_synapse_t *synapse = user_data;

    g_list_free_full(synapse->actions, free_graph_action);
    g_list_free_full(synapse->inputs, free_graph_action);
    free(synapse);
}

/*!
 * \internal
 * \brief Free a transition graph object
 *
 * \param[in,out] graph  Transition graph to free
 */
void
pcmk__free_graph(pcmk__graph_t *graph)
{
    if (graph != NULL) {
        g_list_free_full(graph->synapses, free_graph_synapse);
        free(graph->source);
        free(graph->failed_stop_offset);
        free(graph->failed_start_offset);
        free(graph);
    }
}


/*
 * Functions for updating graph
 */

/*!
 * \internal
 * \brief Update synapse after completed prerequisite
 *
 * A synapse is ready to be executed once all its prerequisite actions (inputs)
 * complete. Given a completed action, check whether it is an input for a given
 * synapse, and if so, mark the input as confirmed, and mark the synapse as
 * ready if appropriate.
 *
 * \param[in,out] synapse    Transition graph synapse to update
 * \param[in]     action_id  ID of an action that completed
 *
 * \note The only substantial effect here is confirming synapse inputs.
 *       should_fire_synapse() will recalculate pcmk__synapse_ready, so the only
 *       thing that uses the pcmk__synapse_ready from here is
 *       synapse_state_str().
 */
static void
update_synapse_ready(pcmk__graph_synapse_t *synapse, int action_id)
{
    if (pcmk_is_set(synapse->flags, pcmk__synapse_ready)) {
        return; // All inputs have already been confirmed
    }

    // Presume ready until proven otherwise
    pcmk__set_synapse_flags(synapse, pcmk__synapse_ready);

    for (GList *lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_action_t *prereq = (pcmk__graph_action_t *) lpc->data;

        if (prereq->id == action_id) {
            crm_trace("Confirming input %d of synapse %d",
                      action_id, synapse->id);
            pcmk__set_graph_action_flags(prereq, pcmk__graph_action_confirmed);

        } else if (!pcmk_is_set(prereq->flags, pcmk__graph_action_confirmed)) {
            pcmk__clear_synapse_flags(synapse, pcmk__synapse_ready);
            crm_trace("Synapse %d still not ready after action %d",
                      synapse->id, action_id);
        }
    }
    if (pcmk_is_set(synapse->flags, pcmk__synapse_ready)) {
        crm_trace("Synapse %d is now ready to execute", synapse->id);
    }
}

/*!
 * \internal
 * \brief Update action and synapse confirmation after action completion
 *
 * \param[in,out] synapse    Transition graph synapse that action belongs to
 * \param[in]     action_id  ID of action that completed
 */
static void
update_synapse_confirmed(pcmk__graph_synapse_t *synapse, int action_id)
{
    bool all_confirmed = true;

    for (GList *lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_action_t *action = (pcmk__graph_action_t *) lpc->data;

        if (action->id == action_id) {
            crm_trace("Confirmed action %d of synapse %d",
                      action_id, synapse->id);
            pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);

        } else if (all_confirmed &&
                   !pcmk_is_set(action->flags, pcmk__graph_action_confirmed)) {
            all_confirmed = false;
            crm_trace("Synapse %d still not confirmed after action %d",
                      synapse->id, action_id);
        }
    }

    if (all_confirmed
        && !pcmk_is_set(synapse->flags, pcmk__synapse_confirmed)) {
        crm_trace("Confirmed synapse %d", synapse->id);
        pcmk__set_synapse_flags(synapse, pcmk__synapse_confirmed);
    }
}

/*!
 * \internal
 * \brief Update the transition graph with a completed action result
 *
 * \param[in,out] graph   Transition graph to update
 * \param[in]     action  Action that completed
 */
void
pcmk__update_graph(pcmk__graph_t *graph, const pcmk__graph_action_t *action)
{
    for (GList *lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) lpc->data;

        if (pcmk_any_flags_set(synapse->flags,
                               pcmk__synapse_confirmed|pcmk__synapse_failed)) {
            continue; // This synapse already completed

        } else if (pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
            update_synapse_confirmed(synapse, action->id);

        } else if (!pcmk_is_set(action->flags, pcmk__graph_action_failed)
                   || (synapse->priority == PCMK_SCORE_INFINITY)) {
            update_synapse_ready(synapse, action->id);
        }
    }
}


/*
 * Functions for executing graph
 */

/* A transition graph consists of various types of actions. The library caller
 * registers execution functions for each action type, which will be stored
 * here.
 */
static pcmk__graph_functions_t *graph_fns = NULL;

/*!
 * \internal
 * \brief Set transition graph execution functions
 *
 * \param[in]  Execution functions to use
 */
void
pcmk__set_graph_functions(pcmk__graph_functions_t *fns)
{

    pcmk__assert((fns != NULL) && (fns->rsc != NULL) && (fns->cluster != NULL)
                 && (fns->pseudo != NULL) && (fns->fence != NULL));
    crm_debug("Setting custom functions for executing transition graphs");
    graph_fns = fns;
}

/*!
 * \internal
 * \brief Check whether a graph synapse is ready to be executed
 *
 * \param[in,out] graph    Transition graph that synapse is part of
 * \param[in,out] synapse  Synapse to check
 *
 * \return true if synapse is ready, false otherwise
 */
static bool
should_fire_synapse(pcmk__graph_t *graph, pcmk__graph_synapse_t *synapse)
{
    GList *lpc = NULL;

    pcmk__set_synapse_flags(synapse, pcmk__synapse_ready);
    for (lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_action_t *prereq = (pcmk__graph_action_t *) lpc->data;

        if (!(pcmk_is_set(prereq->flags, pcmk__graph_action_confirmed))) {
            crm_trace("Input %d for synapse %d not yet confirmed",
                      prereq->id, synapse->id);
            pcmk__clear_synapse_flags(synapse, pcmk__synapse_ready);
            break;

        } else if (pcmk_is_set(prereq->flags, pcmk__graph_action_failed)) {
            crm_trace("Input %d for synapse %d confirmed but failed",
                      prereq->id, synapse->id);
            pcmk__clear_synapse_flags(synapse, pcmk__synapse_ready);
            break;
        }
    }
    if (pcmk_is_set(synapse->flags, pcmk__synapse_ready)) {
        crm_trace("Synapse %d is ready to execute", synapse->id);
    } else {
        return false;
    }

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_action_t *a = (pcmk__graph_action_t *) lpc->data;

        if (a->type == pcmk__pseudo_graph_action) {
            /* None of the below applies to pseudo ops */

        } else if (synapse->priority < graph->abort_priority) {
            crm_trace("Skipping synapse %d: priority %d is less than "
                      "abort priority %d",
                      synapse->id, synapse->priority, graph->abort_priority);
            graph->skipped++;
            return false;

        } else if (graph_fns->allowed && !(graph_fns->allowed(graph, a))) {
            crm_trace("Deferring synapse %d: not allowed", synapse->id);
            return false;
        }
    }

    return true;
}

/*!
 * \internal
 * \brief Initiate an action from a transition graph
 *
 * \param[in,out] graph   Transition graph containing action
 * \param[in,out] action  Action to execute
 *
 * \return Standard Pacemaker return code
 */
static int
initiate_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    const char *id = pcmk__xe_id(action->xml);

    CRM_CHECK(id != NULL, return EINVAL);
    CRM_CHECK(!pcmk_is_set(action->flags, pcmk__graph_action_executed),
              return pcmk_rc_already);

    pcmk__set_graph_action_flags(action, pcmk__graph_action_executed);
    switch (action->type) {
        case pcmk__pseudo_graph_action:
            crm_trace("Executing pseudo-action %d (%s)", action->id, id);
            return graph_fns->pseudo(graph, action);

        case pcmk__rsc_graph_action:
            crm_trace("Executing resource action %d (%s)", action->id, id);
            return graph_fns->rsc(graph, action);

        case pcmk__cluster_graph_action:
            if (pcmk__str_eq(crm_element_value(action->xml, PCMK_XA_OPERATION),
                             PCMK_ACTION_STONITH, pcmk__str_none)) {
                crm_trace("Executing fencing action %d (%s)",
                          action->id, id);
                return graph_fns->fence(graph, action);
            }
            crm_trace("Executing cluster action %d (%s)", action->id, id);
            return graph_fns->cluster(graph, action);

        default:
            crm_err("Unsupported graph action type <%s " PCMK_XA_ID "='%s'> "
                    "(bug?)",
                    action->xml->name, id);
            return EINVAL;
    }
}

/*!
 * \internal
 * \brief Execute a graph synapse
 *
 * \param[in,out] graph    Transition graph with synapse to execute
 * \param[in,out] synapse  Synapse to execute
 *
 * \return Standard Pacemaker return value
 */
static int
fire_synapse(pcmk__graph_t *graph, pcmk__graph_synapse_t *synapse)
{
    pcmk__set_synapse_flags(synapse, pcmk__synapse_executed);
    for (GList *lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_action_t *action = (pcmk__graph_action_t *) lpc->data;
        int rc = initiate_action(graph, action);

        if (rc != pcmk_rc_ok) {
            crm_err("Failed initiating <%s " PCMK_XA_ID "=%d> in synapse %d: "
                    "%s",
                    action->xml->name, action->id, synapse->id,
                    pcmk_rc_str(rc));
            pcmk__set_synapse_flags(synapse, pcmk__synapse_confirmed);
            pcmk__set_graph_action_flags(action,
                                         pcmk__graph_action_confirmed
                                         |pcmk__graph_action_failed);
            return pcmk_rc_error;
        }
    }
    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Dummy graph method that can be used with simulations
 *
 * \param[in,out] graph   Transition graph containing action
 * \param[in,out] action  Graph action to be initiated
 *
 * \return Standard Pacemaker return code
 * \note If the PE_fail environment variable is set to the action ID,
 *       then the graph action will be marked as failed.
 */
static int
pseudo_action_dummy(pcmk__graph_t *graph, pcmk__graph_action_t *action)
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

    if (action->id == fail) {
        crm_err("Dummy event handler: pretending action %d failed", action->id);
        pcmk__set_graph_action_flags(action, pcmk__graph_action_failed);
        graph->abort_priority = PCMK_SCORE_INFINITY;
    } else {
        crm_trace("Dummy event handler: action %d initiated", action->id);
    }
    pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    pcmk__update_graph(graph, action);
    return pcmk_rc_ok;
}

static pcmk__graph_functions_t default_fns = {
    pseudo_action_dummy,
    pseudo_action_dummy,
    pseudo_action_dummy,
    pseudo_action_dummy
};

/*!
 * \internal
 * \brief Execute all actions in a transition graph
 *
 * \param[in,out] graph  Transition graph to execute
 *
 * \return Status of transition after execution
 */
enum pcmk__graph_status
pcmk__execute_graph(pcmk__graph_t *graph)
{
    GList *lpc = NULL;
    int log_level = LOG_DEBUG;
    enum pcmk__graph_status pass_result = pcmk__graph_active;
    const char *status = "In progress";

    if (graph_fns == NULL) {
        graph_fns = &default_fns;
    }
    if (graph == NULL) {
        return pcmk__graph_complete;
    }

    graph->fired = 0;
    graph->pending = 0;
    graph->skipped = 0;
    graph->completed = 0;
    graph->incomplete = 0;

    // Count completed and in-flight synapses
    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) lpc->data;

        if (pcmk_is_set(synapse->flags, pcmk__synapse_confirmed)) {
            graph->completed++;

        } else if (!pcmk_is_set(synapse->flags, pcmk__synapse_failed)
                   && pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
            graph->pending++;
        }
    }
    crm_trace("Executing graph %d (%d synapses already completed, %d pending)",
              graph->id, graph->completed, graph->pending);

    // Execute any synapses that are ready
    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_synapse_t *synapse = (pcmk__graph_synapse_t *) lpc->data;

        if ((graph->batch_limit > 0)
            && (graph->pending >= graph->batch_limit)) {

            crm_debug("Throttling graph execution: batch limit (%d) reached",
                      graph->batch_limit);
            break;

        } else if (pcmk_is_set(synapse->flags, pcmk__synapse_failed)) {
            graph->skipped++;
            continue;

        } else if (pcmk_any_flags_set(synapse->flags,
                                      pcmk__synapse_confirmed
                                      |pcmk__synapse_executed)) {
            continue; // Already handled

        } else if (should_fire_synapse(graph, synapse)) {
            graph->fired++;
            if (fire_synapse(graph, synapse) != pcmk_rc_ok) {
                crm_err("Synapse %d failed to fire", synapse->id);
                log_level = LOG_ERR;
                graph->abort_priority = PCMK_SCORE_INFINITY;
                graph->incomplete++;
                graph->fired--;
            }

            if (!(pcmk_is_set(synapse->flags, pcmk__synapse_confirmed))) {
                graph->pending++;
            }

        } else {
            crm_trace("Synapse %d cannot fire", synapse->id);
            graph->incomplete++;
        }
    }

    if ((graph->pending == 0) && (graph->fired == 0)) {
        graph->complete = true;

        if ((graph->incomplete != 0) && (graph->abort_priority <= 0)) {
            log_level = LOG_WARNING;
            pass_result = pcmk__graph_terminated;
            status = "Terminated";

        } else if (graph->skipped != 0) {
            log_level = LOG_NOTICE;
            pass_result = pcmk__graph_complete;
            status = "Stopped";

        } else {
            log_level = LOG_NOTICE;
            pass_result = pcmk__graph_complete;
            status = "Complete";
        }

    } else if (graph->fired == 0) {
        pass_result = pcmk__graph_pending;
    }

    do_crm_log(log_level,
               "Transition %d (Complete=%d, Pending=%d,"
               " Fired=%d, Skipped=%d, Incomplete=%d, Source=%s): %s",
               graph->id, graph->completed, graph->pending, graph->fired,
               graph->skipped, graph->incomplete, graph->source, status);

    return pass_result;
}


/*
 * Functions for unpacking transition graph XML into structs
 */

/*!
 * \internal
 * \brief Unpack a transition graph action from XML
 *
 * \param[in] parent      Synapse that action is part of
 * \param[in] xml_action  Action XML to unparse
 *
 * \return Newly allocated action on success, or NULL otherwise
 */
static pcmk__graph_action_t *
unpack_action(pcmk__graph_synapse_t *parent, xmlNode *xml_action)
{
    enum pcmk__graph_action_type action_type;
    pcmk__graph_action_t *action = NULL;
    const char *value = pcmk__xe_id(xml_action);

    if (value == NULL) {
        crm_err("Ignoring transition graph action without " PCMK_XA_ID
                " (bug?)");
        crm_log_xml_trace(xml_action, "invalid");
        return NULL;
    }

    if (pcmk__xe_is(xml_action, PCMK__XE_RSC_OP)) {
        action_type = pcmk__rsc_graph_action;

    } else if (pcmk__xe_is(xml_action, PCMK__XE_PSEUDO_EVENT)) {
        action_type = pcmk__pseudo_graph_action;

    } else if (pcmk__xe_is(xml_action, PCMK__XE_CRM_EVENT)) {
        action_type = pcmk__cluster_graph_action;

    } else {
        crm_err("Ignoring transition graph action of unknown type '%s' (bug?)",
                xml_action->name);
        crm_log_xml_trace(xml_action, "invalid");
        return NULL;
    }

    action = calloc(1, sizeof(pcmk__graph_action_t));
    if (action == NULL) {
        crm_perror(LOG_CRIT, "Cannot unpack transition graph action");
        crm_log_xml_trace(xml_action, "lost");
        return NULL;
    }

    pcmk__scan_min_int(value, &(action->id), -1);
    action->type = pcmk__rsc_graph_action;
    action->xml = pcmk__xml_copy(NULL, xml_action);
    action->synapse = parent;
    action->type = action_type;
    action->params = xml2list(action->xml);

    value = crm_meta_value(action->params, PCMK_META_TIMEOUT);
    pcmk__scan_min_int(value, &(action->timeout), 0);

    /* Take PCMK_META_START_DELAY into account for the timeout of the action
     * timer
     */
    value = crm_meta_value(action->params, PCMK_META_START_DELAY);
    {
        int start_delay;

        pcmk__scan_min_int(value, &start_delay, 0);
        action->timeout += start_delay;
    }

    if (pcmk__guint_from_hash(action->params, CRM_META "_" PCMK_META_INTERVAL,
                              0, &(action->interval_ms)) != pcmk_rc_ok) {
        action->interval_ms = 0;
    }

    crm_trace("Action %d has timer set to %dms", action->id, action->timeout);

    return action;
}

/*!
 * \internal
 * \brief Unpack transition graph synapse from XML
 *
 * \param[in,out] new_graph    Transition graph that synapse is part of
 * \param[in]     xml_synapse  Synapse XML
 *
 * \return Newly allocated synapse on success, or NULL otherwise
 */
static pcmk__graph_synapse_t *
unpack_synapse(pcmk__graph_t *new_graph, const xmlNode *xml_synapse)
{
    const char *value = NULL;
    xmlNode *action_set = NULL;
    pcmk__graph_synapse_t *new_synapse = NULL;

    crm_trace("Unpacking synapse %s", pcmk__xe_id(xml_synapse));

    new_synapse = calloc(1, sizeof(pcmk__graph_synapse_t));
    if (new_synapse == NULL) {
        return NULL;
    }

    pcmk__scan_min_int(pcmk__xe_id(xml_synapse), &(new_synapse->id), 0);

    value = crm_element_value(xml_synapse, PCMK__XA_PRIORITY);
    pcmk__scan_min_int(value, &(new_synapse->priority), 0);

    CRM_CHECK(new_synapse->id >= 0,
              free_graph_synapse((gpointer) new_synapse); return NULL);

    new_graph->num_synapses++;

    crm_trace("Unpacking synapse %s action sets",
              crm_element_value(xml_synapse, PCMK_XA_ID));

    for (action_set = pcmk__xe_first_child(xml_synapse, PCMK__XE_ACTION_SET,
                                           NULL, NULL);
         action_set != NULL;
         action_set = pcmk__xe_next(action_set, PCMK__XE_ACTION_SET)) {

        for (xmlNode *action = pcmk__xe_first_child(action_set, NULL, NULL,
                                                    NULL);
             action != NULL; action = pcmk__xe_next(action, NULL)) {

            pcmk__graph_action_t *new_action = unpack_action(new_synapse,
                                                             action);

            if (new_action == NULL) {
                continue;
            }

            crm_trace("Adding action %d to synapse %d",
                      new_action->id, new_synapse->id);
            new_graph->num_actions++;
            new_synapse->actions = g_list_append(new_synapse->actions,
                                                 new_action);
        }
    }

    crm_trace("Unpacking synapse %s inputs", pcmk__xe_id(xml_synapse));

    for (xmlNode *inputs = pcmk__xe_first_child(xml_synapse, PCMK__XE_INPUTS,
                                                NULL, NULL);
         inputs != NULL; inputs = pcmk__xe_next(inputs, PCMK__XE_INPUTS)) {

        for (xmlNode *trigger = pcmk__xe_first_child(inputs, PCMK__XE_TRIGGER,
                                                     NULL, NULL);
             trigger != NULL;
             trigger = pcmk__xe_next(trigger, PCMK__XE_TRIGGER)) {

            for (xmlNode *input = pcmk__xe_first_child(trigger, NULL, NULL,
                                                       NULL);
                 input != NULL; input = pcmk__xe_next(input, NULL)) {

                pcmk__graph_action_t *new_input = unpack_action(new_synapse,
                                                                input);

                if (new_input == NULL) {
                    continue;
                }

                crm_trace("Adding input %d to synapse %d",
                           new_input->id, new_synapse->id);

                new_synapse->inputs = g_list_append(new_synapse->inputs,
                                                    new_input);
            }
        }
    }

    return new_synapse;
}

/*!
 * \internal
 * \brief Unpack transition graph XML
 *
 * \param[in] xml_graph  Transition graph XML to unpack
 * \param[in] reference  Where the XML came from (for logging)
 *
 * \return Newly allocated transition graph on success, NULL otherwise
 * \note The caller is responsible for freeing the return value using
 *       pcmk__free_graph().
 * \note The XML is expected to be structured like:
         <transition_graph ...>
           <synapse id="0">
             <action_set>
               <rsc_op id="2" ...>
               ...
             </action_set>
             <inputs>
                 <rsc_op id="1" ...
                 ...
             </inputs>
           </synapse>
           ...
         </transition_graph>
 */
pcmk__graph_t *
pcmk__unpack_graph(const xmlNode *xml_graph, const char *reference)
{
    pcmk__graph_t *new_graph = NULL;

    new_graph = calloc(1, sizeof(pcmk__graph_t));
    if (new_graph == NULL) {
        return NULL;
    }

    new_graph->source = strdup(pcmk__s(reference, "unknown"));
    if (new_graph->source == NULL) {
        pcmk__free_graph(new_graph);
        return NULL;
    }

    new_graph->completion_action = pcmk__graph_done;

    // Parse top-level attributes from PCMK__XE_TRANSITION_GRAPH
    if (xml_graph != NULL) {
        const char *buf = crm_element_value(xml_graph, "transition_id");

        CRM_CHECK(buf != NULL,
                  pcmk__free_graph(new_graph); return NULL);
        pcmk__scan_min_int(buf, &(new_graph->id), 1);

        buf = crm_element_value(xml_graph, PCMK_OPT_CLUSTER_DELAY);
        CRM_CHECK(buf != NULL,
                  pcmk__free_graph(new_graph); return NULL);
        pcmk_parse_interval_spec(buf, &(new_graph->network_delay));

        buf = crm_element_value(xml_graph, PCMK_OPT_STONITH_TIMEOUT);
        if (buf == NULL) {
            new_graph->stonith_timeout = new_graph->network_delay;
        } else {
            pcmk_parse_interval_spec(buf, &(new_graph->stonith_timeout));
        }

        // Use 0 (dynamic limit) as default/invalid, -1 (no limit) as minimum
        buf = crm_element_value(xml_graph, PCMK_OPT_BATCH_LIMIT);
        if ((buf == NULL)
            || (pcmk__scan_min_int(buf, &(new_graph->batch_limit),
                                   -1) != pcmk_rc_ok)) {
            new_graph->batch_limit = 0;
        }

        buf = crm_element_value(xml_graph, PCMK_OPT_MIGRATION_LIMIT);
        pcmk__scan_min_int(buf, &(new_graph->migration_limit), -1);

        new_graph->failed_stop_offset =
            crm_element_value_copy(xml_graph, PCMK__XA_FAILED_STOP_OFFSET);
        new_graph->failed_start_offset =
            crm_element_value_copy(xml_graph, PCMK__XA_FAILED_START_OFFSET);

        pcmk__xe_get_time(xml_graph, "recheck-by", &(new_graph->recheck_by));
    }

    // Unpack each child <synapse> element
    for (const xmlNode *synapse_xml = pcmk__xe_first_child(xml_graph,
                                                           PCMK__XE_SYNAPSE,
                                                           NULL, NULL);
         synapse_xml != NULL;
         synapse_xml = pcmk__xe_next(synapse_xml, PCMK__XE_SYNAPSE)) {

        pcmk__graph_synapse_t *new_synapse = unpack_synapse(new_graph,
                                                            synapse_xml);

        if (new_synapse != NULL) {
            new_graph->synapses = g_list_append(new_graph->synapses,
                                                new_synapse);
        }
    }

    crm_debug("Unpacked transition %d from %s: %d actions in %d synapses",
              new_graph->id, new_graph->source, new_graph->num_actions,
              new_graph->num_synapses);

    return new_graph;
}


/*
 * Other transition graph utilities
 */

/*!
 * \internal
 * \brief Synthesize an executor event from a graph action
 *
 * \param[in] resource     If not NULL, use greater call ID than in this XML
 * \param[in] action       Graph action
 * \param[in] status       What to use as event execution status
 * \param[in] rc           What to use as event exit status
 * \param[in] exit_reason  What to use as event exit reason
 *
 * \return Newly allocated executor event on success, or NULL otherwise
 */
lrmd_event_data_t *
pcmk__event_from_graph_action(const xmlNode *resource,
                              const pcmk__graph_action_t *action,
                              int status, int rc, const char *exit_reason)
{
    lrmd_event_data_t *op = NULL;
    GHashTableIter iter;
    const char *name = NULL;
    const char *value = NULL;
    xmlNode *action_resource = NULL;

    CRM_CHECK(action != NULL, return NULL);
    CRM_CHECK(action->type == pcmk__rsc_graph_action, return NULL);

    action_resource = pcmk__xe_first_child(action->xml, PCMK_XE_PRIMITIVE, NULL,
                                           NULL);
    CRM_CHECK(action_resource != NULL, crm_log_xml_warn(action->xml, "invalid");
                                       return NULL);

    op = lrmd_new_event(pcmk__xe_id(action_resource),
                        crm_element_value(action->xml, PCMK_XA_OPERATION),
                        action->interval_ms);
    lrmd__set_result(op, rc, status, exit_reason);
    op->t_run = time(NULL);
    op->t_rcchange = op->t_run;
    op->params = pcmk__strkey_table(free, free);

    g_hash_table_iter_init(&iter, action->params);
    while (g_hash_table_iter_next(&iter, (void **)&name, (void **)&value)) {
        pcmk__insert_dup(op->params, name, value);
    }

    for (xmlNode *xop = pcmk__xe_first_child(resource, NULL, NULL, NULL);
         xop != NULL; xop = pcmk__xe_next(xop, NULL)) {

        int tmp = 0;

        crm_element_value_int(xop, PCMK__XA_CALL_ID, &tmp);
        crm_debug("Got call_id=%d for %s", tmp, pcmk__xe_id(resource));
        if (tmp > op->call_id) {
            op->call_id = tmp;
        }
    }

    op->call_id++;
    return op;
}

/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU Lesser General Public License
 * version 2.1 or later (LGPLv2.1+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <pacemaker-internal.h>

/*!
 * \internal
 * \brief Return text equivalent of an enum pcmk__graph_status for logging
 *
 * \param[in] state  Transition status
 *
 * \return Human-readable text equivalent of \p state
 */
const char *
pcmk__graph_status2text(enum pcmk__graph_status state)
{
    switch (state) {
        case pcmk__graph_active:
            return "active";
        case pcmk__graph_pending:
            return "pending";
        case pcmk__graph_complete:
            return "complete";
        case pcmk__graph_terminated:
            return "terminated";
    }
    return "unknown";
}

static const char *
actiontype2text(enum pcmk__graph_action_type type)
{
    switch (type) {
        case pcmk__pseudo_graph_action:
            return "pseudo";
        case pcmk__rsc_graph_action:
            return "resource";
        case pcmk__cluster_graph_action:
            return "cluster";
    }
    return "invalid";
}

/*!
 * \internal
 * \brief Find a transition graph action by ID
 *
 * \param[in] graph  Transition graph to search
 * \param[in] id     Action ID to search for
 *
 * \return Transition graph action corresponding to \p id, or NULL if none
 */
static const pcmk__graph_action_t *
find_graph_action_by_id(const pcmk__graph_t *graph, int id)
{
    if (graph == NULL) {
        return NULL;
    }

    for (const GList *sIter = graph->synapses; sIter != NULL;
         sIter = sIter->next) {

        const pcmk__graph_synapse_t *synapse = NULL;

        synapse = (const pcmk__graph_synapse_t *) sIter->data;
        for (const GList *aIter = synapse->actions; aIter != NULL;
             aIter = aIter->next) {

            const pcmk__graph_action_t *action = NULL;

            action = (const pcmk__graph_action_t *) aIter->data;
            if (action->id == id) {
                return action;
            }
        }
    }
    return NULL;
}

static const char *
synapse_state_str(pcmk__graph_synapse_t *synapse)
{
    if (pcmk_is_set(synapse->flags, pcmk__synapse_failed)) {
        return "Failed";

    } else if (pcmk_is_set(synapse->flags, pcmk__synapse_confirmed)) {
        return "Completed";

    } else if (pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
        return "In-flight";

    } else if (pcmk_is_set(synapse->flags, pcmk__synapse_ready)) {
        return "Ready";
    }
    return "Pending";
}

/*!
 * \internal
 * \brief List the action IDs of pending inputs to a transition graph synapse
 *
 * \param[in] graph    Transition graph to which \p synapse belongs
 * \param[in] synapse  Synapse whose inputs to check
 *
 * \return A \p GString containing the space-delimited action IDs of inputs to
 *         \p synapse that haven't completed successfully
 *
 * \note The caller is responsible for freeing the return value using
 *       \p g_string_free().
 */
static GString *
synapse_pending_inputs(const pcmk__graph_t *graph,
                       const pcmk__graph_synapse_t *synapse)
{
    GString *pending = NULL;

    for (const GList *lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        const pcmk__graph_action_t *input = (pcmk__graph_action_t *) lpc->data;

        if (pcmk_is_set(input->flags, pcmk__graph_action_failed)) {
            pcmk__add_word(&pending, 1024, ID(input->xml));

        } else if (pcmk_is_set(input->flags, pcmk__graph_action_confirmed)) {
            // Confirmed successful inputs are not pending

        } else if (find_graph_action_by_id(graph, input->id) != NULL) {
            // In-flight or pending
            pcmk__add_word(&pending, 1024, ID(input->xml));
        }
    }
    return pending;
}

// Log synapse inputs that aren't in graph
static void
log_unresolved_inputs(unsigned int log_level, pcmk__graph_t *graph,
                      pcmk__graph_synapse_t *synapse)
{
    for (GList *lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        pcmk__graph_action_t *input = (pcmk__graph_action_t *) lpc->data;
        const char *key = crm_element_value(input->xml, XML_LRM_ATTR_TASK_KEY);
        const char *host = crm_element_value(input->xml, XML_LRM_ATTR_TARGET);

        if (find_graph_action_by_id(graph, input->id) == NULL) {
            do_crm_log(log_level,
                       " * [Input %2d]: Unresolved dependency %s op %s%s%s",
                       input->id, actiontype2text(input->type), key,
                       (host? " on " : ""), (host? host : ""));
        }
    }
}

static void
log_synapse_action(unsigned int log_level, pcmk__graph_synapse_t *synapse,
                   pcmk__graph_action_t *action, const char *pending_inputs)
{
    const char *key = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
    const char *host = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    char *desc = crm_strdup_printf("%s %s op %s",
                                   synapse_state_str(synapse),
                                   actiontype2text(action->type), key);

    do_crm_log(log_level,
               "[Action %4d]: %-50s%s%s (priority: %d, waiting: %s)",
               action->id, desc, (host? " on " : ""), (host? host : ""),
               synapse->priority, pending_inputs);
    free(desc);
}

static void
log_synapse(unsigned int log_level, pcmk__graph_t *graph,
            pcmk__graph_synapse_t *synapse)
{
    GString *g_pending = NULL;
    const char *pending = "none";

    if (!pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
        g_pending = synapse_pending_inputs(graph, synapse);

        if (g_pending != NULL) {
            pending = (const char *) g_pending->str;
        }
    }

    for (GList *lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        log_synapse_action(log_level, synapse,
                           (pcmk__graph_action_t *) lpc->data, pending);
    }

    if (g_pending != NULL) {
        g_string_free(g_pending, TRUE);
    }

    if (!pcmk_is_set(synapse->flags, pcmk__synapse_executed)) {
        log_unresolved_inputs(log_level, graph, synapse);
    }
}

void
pcmk__log_graph_action(int log_level, pcmk__graph_action_t *action)
{
    log_synapse(log_level, NULL, action->synapse);
}

void
pcmk__log_graph(unsigned int log_level, pcmk__graph_t *graph)
{
    if ((graph == NULL) || (graph->num_actions == 0)) {
        if (log_level == LOG_TRACE) {
            crm_debug("Empty transition graph");
        }
        return;
    }

    do_crm_log(log_level, "Graph %d with %d actions:"
               " batch-limit=%d jobs, network-delay=%ums",
               graph->id, graph->num_actions,
               graph->batch_limit, graph->network_delay);

    for (GList *lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        log_synapse(log_level, graph, (pcmk__graph_synapse_t *) lpc->data);
    }
}

/*
 * Copyright 2004-2021 the Pacemaker project contributors
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

extern crm_graph_functions_t *graph_fns;

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

crm_graph_functions_t default_fns = {
    pseudo_action_dummy,
    pseudo_action_dummy,
    pseudo_action_dummy,
    pseudo_action_dummy
};

void
set_default_graph_functions(void)
{
    graph_fns = &default_fns;
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

const char *
transition_status(enum transition_status state)
{
    switch (state) {
        case transition_active:
            return "active";
        case transition_pending:
            return "pending";
        case transition_complete:
            return "complete";
        case transition_stopped:
            return "stopped";
        case transition_terminated:
            return "terminated";
        case transition_action_failed:
            return "failed (action)";
        case transition_failed:
            return "failed";
    }
    return "unknown";
}

const char *
actiontype2text(action_type_e type)
{
    switch (type) {
        case action_type_pseudo:
            return "pseudo";
        case action_type_rsc:
            return "resource";
        case action_type_crm:
            return "cluster";
    }
    return "invalid";
}

static crm_action_t *
find_action(crm_graph_t * graph, int id)
{
    GList *sIter = NULL;

    if (graph == NULL) {
        return NULL;
    }

    for (sIter = graph->synapses; sIter != NULL; sIter = sIter->next) {
        GList *aIter = NULL;
        synapse_t *synapse = (synapse_t *) sIter->data;

        for (aIter = synapse->actions; aIter != NULL; aIter = aIter->next) {
            crm_action_t *action = (crm_action_t *) aIter->data;

            if (action->id == id) {
                return action;
            }
        }
    }
    return NULL;
}

static const char *
synapse_state_str(synapse_t *synapse)
{
    if (synapse->failed) {
        return "Failed";

    } else if (synapse->confirmed) {
        return "Completed";

    } else if (synapse->executed) {
        return "In-flight";

    } else if (synapse->ready) {
        return "Ready";
    }
    return "Pending";
}

// List action IDs of inputs in graph that haven't completed successfully
static char *
synapse_pending_inputs(crm_graph_t *graph, synapse_t *synapse)
{
    char *pending = NULL;
    size_t pending_len = 0;

    for (GList *lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        crm_action_t *input = (crm_action_t *) lpc->data;

        if (input->failed) {
            pcmk__add_word(&pending, &pending_len, ID(input->xml));

        } else if (input->confirmed) {
            // Confirmed successful inputs are not pending

        } else if (find_action(graph, input->id) != NULL) {
            // In-flight or pending
            pcmk__add_word(&pending, &pending_len, ID(input->xml));
        }
    }
    if (pending == NULL) {
        pending = strdup("none");
    }
    return pending;
}

// Log synapse inputs that aren't in graph
static void
log_unresolved_inputs(unsigned int log_level, crm_graph_t *graph,
                      synapse_t *synapse)
{
    for (GList *lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
        crm_action_t *input = (crm_action_t *) lpc->data;
        const char *key = crm_element_value(input->xml, XML_LRM_ATTR_TASK_KEY);
        const char *host = crm_element_value(input->xml, XML_LRM_ATTR_TARGET);

        if (find_action(graph, input->id) == NULL) {
            do_crm_log(log_level,
                       " * [Input %2d]: Unresolved dependency %s op %s%s%s",
                       input->id, actiontype2text(input->type), key,
                       (host? " on " : ""), (host? host : ""));
        }
    }
}

static void
log_synapse_action(unsigned int log_level, synapse_t *synapse,
                   crm_action_t *action, const char *pending_inputs)
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
print_synapse(unsigned int log_level, crm_graph_t * graph, synapse_t * synapse)
{
    char *pending = NULL;

    if (!synapse->executed) {
        pending = synapse_pending_inputs(graph, synapse);
    }
    for (GList *lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        log_synapse_action(log_level, synapse, (crm_action_t *) lpc->data,
                           pending);
    }
    free(pending);
    if (!synapse->executed) {
        log_unresolved_inputs(log_level, graph, synapse);
    }
}

void
print_action(int log_level, const char *prefix, crm_action_t * action)
{
    print_synapse(log_level, NULL, action->synapse);
}

void
print_graph(unsigned int log_level, crm_graph_t * graph)
{
    GList *lpc = NULL;

    if (graph == NULL || graph->num_actions == 0) {
        if (log_level == LOG_TRACE) {
            crm_debug("Empty transition graph");
        }
        return;
    }

    do_crm_log(log_level, "Graph %d with %d actions:"
               " batch-limit=%d jobs, network-delay=%ums",
               graph->id, graph->num_actions,
               graph->batch_limit, graph->network_delay);

    for (lpc = graph->synapses; lpc != NULL; lpc = lpc->next) {
        synapse_t *synapse = (synapse_t *) lpc->data;

        print_synapse(log_level, graph, synapse);
    }
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

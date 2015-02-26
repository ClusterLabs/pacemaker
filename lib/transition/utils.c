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

extern crm_graph_functions_t *graph_fns;

static gboolean
pseudo_action_dummy(crm_graph_t * graph, crm_action_t * action)
{
    static int fail = -1;

    if (fail < 0) {
        char *fail_s = getenv("PE_fail");

        if (fail_s) {
            fail = crm_int_helper(fail_s, NULL);
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
            return "rsc";
        case action_type_crm:
            return "crm";

    }
    return "<unknown>";
}

static crm_action_t *
find_action(crm_graph_t * graph, int id)
{
    GListPtr sIter = NULL;

    if (graph == NULL) {
        return NULL;
    }

    for (sIter = graph->synapses; sIter != NULL; sIter = sIter->next) {
        GListPtr aIter = NULL;
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

static void
print_synapse(unsigned int log_level, crm_graph_t * graph, synapse_t * synapse)
{
    GListPtr lpc = NULL;
    char *pending = NULL;
    const char *state = "Pending";

    if (synapse->failed) {
        state = "Failed";

    } else if (synapse->confirmed) {
        state = "Completed";

    } else if (synapse->executed) {
        state = "In-flight";

    } else if (synapse->ready) {
        state = "Ready";
    }

    if (synapse->executed == FALSE) {
        for (lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
            crm_action_t *input = (crm_action_t *) lpc->data;
            const char *id_string = crm_element_value(input->xml, XML_ATTR_ID);

            if (input->failed) {
                pending = add_list_element(pending, id_string);

            } else if (input->confirmed) {
                /* Confirmed, skip */

            } else if (find_action(graph, input->id)) {
                /* In-flight or pending */
                pending = add_list_element(pending, id_string);
            }
        }
    }

    for (lpc = synapse->actions; lpc != NULL; lpc = lpc->next) {
        crm_action_t *action = (crm_action_t *) lpc->data;
        const char *key = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
        const char *host = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
        char *desc = crm_strdup_printf("%s %s op %s", state, actiontype2text(action->type), key);

        do_crm_log(log_level,
                   "[Action %4d]: %-50s on %s (priority: %d, waiting: %s)",
                   action->id, desc, host ? host : "N/A",
                   synapse->priority, pending ? pending : "none");

        free(desc);
    }

    if (synapse->executed == FALSE) {
        for (lpc = synapse->inputs; lpc != NULL; lpc = lpc->next) {
            crm_action_t *input = (crm_action_t *) lpc->data;
            const char *key = crm_element_value(input->xml, XML_LRM_ATTR_TASK_KEY);
            const char *host = crm_element_value(input->xml, XML_LRM_ATTR_TARGET);

            if (find_action(graph, input->id) == NULL) {
                if (host == NULL) {
                    do_crm_log(log_level, " * [Input %2d]: Unresolved dependancy %s op %s",
                               input->id, actiontype2text(input->type), key);
                } else {
                    do_crm_log(log_level, " * [Input %2d]: Unresolved dependancy %s op %s on %s",
                               input->id, actiontype2text(input->type), key, host);
                }
            }
        }
    }

    free(pending);
}

void
print_action(int log_level, const char *prefix, crm_action_t * action)
{
    print_synapse(log_level, NULL, action->synapse);
}

void
print_graph(unsigned int log_level, crm_graph_t * graph)
{
    GListPtr lpc = NULL;

    if (graph == NULL || graph->num_actions == 0) {
        if (log_level > LOG_DEBUG) {
            crm_debug("Empty transition graph");
        }
        return;
    }

    do_crm_log(log_level, "Graph %d with %d actions:"
               " batch-limit=%d jobs, network-delay=%dms",
               graph->id, graph->num_actions, graph->num_synapses,
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

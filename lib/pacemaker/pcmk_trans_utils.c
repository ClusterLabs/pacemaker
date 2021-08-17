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

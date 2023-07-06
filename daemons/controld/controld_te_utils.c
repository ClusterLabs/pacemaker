/*
 * Copyright 2004-2023 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/crm.h>
#include <crm/msg_xml.h>
#include <crm/common/xml.h>

#include <pacemaker-controld.h>

//! Triggers transition graph processing
static crm_trigger_t *transition_trigger = NULL;

static GHashTable *node_pending_timers = NULL;

gboolean
stop_te_timer(pcmk__graph_action_t *action)
{
    if (action == NULL) {
        return FALSE;
    }
    if (action->timer != 0) {
        crm_trace("Stopping action timer");
        g_source_remove(action->timer);
        action->timer = 0;
    } else {
        crm_trace("Action timer was already stopped");
        return FALSE;
    }
    return TRUE;
}

static gboolean
te_graph_trigger(gpointer user_data)
{
    if (controld_globals.transition_graph == NULL) {
        crm_debug("Nothing to do");
        return TRUE;
    }

    crm_trace("Invoking graph %d in state %s",
              controld_globals.transition_graph->id,
              fsa_state2string(controld_globals.fsa_state));

    switch (controld_globals.fsa_state) {
        case S_STARTING:
        case S_PENDING:
        case S_NOT_DC:
        case S_HALT:
        case S_ILLEGAL:
        case S_STOPPING:
        case S_TERMINATE:
            return TRUE;
        default:
            break;
    }

    if (!controld_globals.transition_graph->complete) {
        enum pcmk__graph_status graph_rc;
        int orig_limit = controld_globals.transition_graph->batch_limit;
        int throttled_limit = throttle_get_total_job_limit(orig_limit);

        controld_globals.transition_graph->batch_limit = throttled_limit;
        graph_rc = pcmk__execute_graph(controld_globals.transition_graph);
        controld_globals.transition_graph->batch_limit = orig_limit;

        if (graph_rc == pcmk__graph_active) {
            crm_trace("Transition not yet complete");
            return TRUE;

        } else if (graph_rc == pcmk__graph_pending) {
            crm_trace("Transition not yet complete - no actions fired");
            return TRUE;
        }

        if (graph_rc != pcmk__graph_complete) {
            crm_warn("Transition failed: %s",
                     pcmk__graph_status2text(graph_rc));
            pcmk__log_graph(LOG_NOTICE, controld_globals.transition_graph);
        }
    }

    crm_debug("Transition %d is now complete",
              controld_globals.transition_graph->id);
    controld_globals.transition_graph->complete = true;
    notify_crmd(controld_globals.transition_graph);

    return TRUE;
}

/*!
 * \internal
 * \brief Initialize transition trigger
 */
void
controld_init_transition_trigger(void)
{
    transition_trigger = mainloop_add_trigger(G_PRIORITY_LOW, te_graph_trigger,
                                              NULL);
}

/*!
 * \internal
 * \brief Destroy transition trigger
 */
void
controld_destroy_transition_trigger(void)
{
    mainloop_destroy_trigger(transition_trigger);
    transition_trigger = NULL;
}

void
controld_trigger_graph_as(const char *fn, int line)
{
    crm_trace("%s:%d - Triggered graph processing", fn, line);
    mainloop_set_trigger(transition_trigger);
}

static struct abort_timer_s {
    bool aborted;
    guint id;
    int priority;
    enum pcmk__graph_next action;
    const char *text;
} abort_timer = { 0, };

static gboolean
abort_timer_popped(gpointer data)
{
    struct abort_timer_s *abort_timer = (struct abort_timer_s *) data;

    if (AM_I_DC && (abort_timer->aborted == FALSE)) {
        abort_transition(abort_timer->priority, abort_timer->action,
                         abort_timer->text, NULL);
    }
    abort_timer->id = 0;
    return FALSE; // do not immediately reschedule timer
}

/*!
 * \internal
 * \brief Abort transition after delay, if not already aborted in that time
 *
 * \param[in] abort_text  Must be literal string
 */
void
abort_after_delay(int abort_priority, enum pcmk__graph_next abort_action,
                  const char *abort_text, guint delay_ms)
{
    if (abort_timer.id) {
        // Timer already in progress, stop and reschedule
        g_source_remove(abort_timer.id);
    }
    abort_timer.aborted = FALSE;
    abort_timer.priority = abort_priority;
    abort_timer.action = abort_action;
    abort_timer.text = abort_text;
    abort_timer.id = g_timeout_add(delay_ms, abort_timer_popped, &abort_timer);
}

static void
free_node_pending_timer(gpointer data)
{
    struct abort_timer_s *node_pending_timer = (struct abort_timer_s *) data;

    if (node_pending_timer->id != 0) {
        g_source_remove(node_pending_timer->id);
        node_pending_timer->id = 0;
    }

    free(node_pending_timer);
}

static gboolean
node_pending_timer_popped(gpointer key)
{
    struct abort_timer_s *node_pending_timer = NULL;

    if (node_pending_timers == NULL) {
        return FALSE;
    }

    node_pending_timer = g_hash_table_lookup(node_pending_timers, key);
    if (node_pending_timer == NULL) {
        return FALSE;
    }

    crm_warn("Node with id '%s' pending timed out (%us) on joining the process "
             "group",
             (const char *) key, controld_globals.node_pending_timeout);

    abort_timer_popped(node_pending_timer);

    g_hash_table_remove(node_pending_timers, key);

    return FALSE; // do not reschedule timer
}

static void
init_node_pending_timer(const crm_node_t *node, guint timeout)
{
    struct abort_timer_s *node_pending_timer = NULL;
    char *key = NULL;

    if (node->uuid == NULL) {
        return;
    }

    if (node_pending_timers == NULL) {
        node_pending_timers = pcmk__strikey_table(free,
                                                  free_node_pending_timer);

    // The timer is somehow already existing
    } else if (g_hash_table_lookup(node_pending_timers, node->uuid) != NULL) {
        return;
    }

    crm_notice("Waiting for pending %s with id '%s' to join the process "
               "group (timeout=%us)",
               node->uname ? node->uname : "node", node->uuid,
               controld_globals.node_pending_timeout);

    node_pending_timer = calloc(1, sizeof(struct abort_timer_s));
    CRM_ASSERT(node_pending_timer != NULL);

    node_pending_timer->aborted = FALSE;
    node_pending_timer->priority = INFINITY;
    node_pending_timer->action = pcmk__graph_restart;
    node_pending_timer->text = "Node pending timed out";

    key = strdup(node->uuid);
    CRM_ASSERT(key != NULL);

    g_hash_table_replace(node_pending_timers, key, node_pending_timer);

    node_pending_timer->id = g_timeout_add_seconds(timeout,
                                                   node_pending_timer_popped,
                                                   key);
    CRM_ASSERT(node_pending_timer->id != 0);
}

static void
remove_node_pending_timer(const char *node_uuid)
{
    if (node_pending_timers == NULL) {
        return;
    }

    g_hash_table_remove(node_pending_timers, node_uuid);
}

void
controld_node_pending_timer(const crm_node_t *node)
{
    long long remaining_timeout = 0;

    /* Node is either not even a cluster member or it's as well online in CPG.
     * Free any node pending timer of it.
     */
    if (node->when_member <= 0 || node->when_online != 0) {
        remove_node_pending_timer(node->uuid);
        return;
    }
    // Node is a cluster member but offline in CPG

    remaining_timeout = node->when_member - time(NULL)
                        + controld_globals.node_pending_timeout;

    /* It already passed node pending timeout somehow.
     * Free any node pending timer of it.
     */
    if (remaining_timeout <= 0) {
        remove_node_pending_timer(node->uuid);
        return;
    }

    init_node_pending_timer(node, remaining_timeout);
}

void
controld_free_node_pending_timers(void)
{
    if (node_pending_timers == NULL) {
        return;
    }

    g_hash_table_destroy(node_pending_timers);
    node_pending_timers = NULL;
}

static const char *
abort2text(enum pcmk__graph_next abort_action)
{
    switch (abort_action) {
        case pcmk__graph_done:      return "done";
        case pcmk__graph_wait:      return "stop";
        case pcmk__graph_restart:   return "restart";
        case pcmk__graph_shutdown:  return "shutdown";
    }
    return "unknown";
}

static bool
update_abort_priority(pcmk__graph_t *graph, int priority,
                      enum pcmk__graph_next action, const char *abort_reason)
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

void
abort_transition_graph(int abort_priority, enum pcmk__graph_next abort_action,
                       const char *abort_text, const xmlNode *reason,
                       const char *fn, int line)
{
    int add[] = { 0, 0, 0 };
    int del[] = { 0, 0, 0 };
    int level = LOG_INFO;
    const xmlNode *diff = NULL;
    const xmlNode *change = NULL;

    CRM_CHECK(controld_globals.transition_graph != NULL, return);

    switch (controld_globals.fsa_state) {
        case S_STARTING:
        case S_PENDING:
        case S_NOT_DC:
        case S_HALT:
        case S_ILLEGAL:
        case S_STOPPING:
        case S_TERMINATE:
            crm_info("Abort %s suppressed: state=%s (%scomplete)",
                     abort_text, fsa_state2string(controld_globals.fsa_state),
                     (controld_globals.transition_graph->complete? "" : "in"));
            return;
        default:
            break;
    }

    abort_timer.aborted = TRUE;
    controld_expect_sched_reply(NULL);

    if (!controld_globals.transition_graph->complete
        && update_abort_priority(controld_globals.transition_graph,
                                 abort_priority, abort_action,
                                 abort_text)) {
        level = LOG_NOTICE;
    }

    if (reason != NULL) {
        const xmlNode *search = NULL;

        for(search = reason; search; search = search->parent) {
            if (pcmk__xe_is(search, XML_TAG_DIFF)) {
                diff = search;
                break;
            }
        }

        if(diff) {
            xml_patch_versions(diff, add, del);
            for(search = reason; search; search = search->parent) {
                if (pcmk__xe_is(search, XML_DIFF_CHANGE)) {
                    change = search;
                    break;
                }
            }
        }
    }

    if (reason == NULL) {
        do_crm_log(level,
                   "Transition %d aborted: %s " CRM_XS " source=%s:%d "
                   "complete=%s", controld_globals.transition_graph->id,
                   abort_text, fn, line,
                   pcmk__btoa(controld_globals.transition_graph->complete));

    } else if(change == NULL) {
        GString *local_path = pcmk__element_xpath(reason);
        CRM_ASSERT(local_path != NULL);

        do_crm_log(level, "Transition %d aborted by %s.%s: %s "
                   CRM_XS " cib=%d.%d.%d source=%s:%d path=%s complete=%s",
                   controld_globals.transition_graph->id, TYPE(reason),
                   ID(reason), abort_text, add[0], add[1], add[2], fn, line,
                   (const char *) local_path->str,
                   pcmk__btoa(controld_globals.transition_graph->complete));
        g_string_free(local_path, TRUE);

    } else {
        const char *op = crm_element_value(change, XML_DIFF_OP);
        const char *path = crm_element_value(change, XML_DIFF_PATH);

        if(change == reason) {
            if(strcmp(op, "create") == 0) {
                reason = reason->children;

            } else if(strcmp(op, "modify") == 0) {
                reason = first_named_child(reason, XML_DIFF_RESULT);
                if(reason) {
                    reason = reason->children;
                }
            }
        }

        if(strcmp(op, "delete") == 0) {
            const char *shortpath = strrchr(path, '/');

            do_crm_log(level, "Transition %d aborted by deletion of %s: %s "
                       CRM_XS " cib=%d.%d.%d source=%s:%d path=%s complete=%s",
                       controld_globals.transition_graph->id,
                       (shortpath? (shortpath + 1) : path), abort_text,
                       add[0], add[1], add[2], fn, line, path,
                       pcmk__btoa(controld_globals.transition_graph->complete));

        } else if (pcmk__xe_is(reason, XML_CIB_TAG_NVPAIR)) {
            do_crm_log(level, "Transition %d aborted by %s doing %s %s=%s: %s "
                       CRM_XS " cib=%d.%d.%d source=%s:%d path=%s complete=%s",
                       controld_globals.transition_graph->id,
                       crm_element_value(reason, XML_ATTR_ID), op,
                       crm_element_value(reason, XML_NVPAIR_ATTR_NAME),
                       crm_element_value(reason, XML_NVPAIR_ATTR_VALUE),
                       abort_text, add[0], add[1], add[2], fn, line, path,
                       pcmk__btoa(controld_globals.transition_graph->complete));

        } else if (pcmk__xe_is(reason, XML_LRM_TAG_RSC_OP)) {
            const char *magic = crm_element_value(reason, XML_ATTR_TRANSITION_MAGIC);

            do_crm_log(level, "Transition %d aborted by operation %s '%s' on %s: %s "
                       CRM_XS " magic=%s cib=%d.%d.%d source=%s:%d complete=%s",
                       controld_globals.transition_graph->id,
                       crm_element_value(reason, XML_LRM_ATTR_TASK_KEY), op,
                       crm_element_value(reason, XML_LRM_ATTR_TARGET), abort_text,
                       magic, add[0], add[1], add[2], fn, line,
                       pcmk__btoa(controld_globals.transition_graph->complete));

        } else if (pcmk__str_any_of(crm_element_name(reason),
                   XML_CIB_TAG_STATE, XML_CIB_TAG_NODE, NULL)) {
            const char *uname = crm_peer_uname(ID(reason));

            do_crm_log(level, "Transition %d aborted by %s '%s' on %s: %s "
                       CRM_XS " cib=%d.%d.%d source=%s:%d complete=%s",
                       controld_globals.transition_graph->id,
                       crm_element_name(reason), op, pcmk__s(uname, ID(reason)),
                       abort_text, add[0], add[1], add[2], fn, line,
                       pcmk__btoa(controld_globals.transition_graph->complete));

        } else {
            const char *id = ID(reason);

            do_crm_log(level, "Transition %d aborted by %s.%s '%s': %s "
                       CRM_XS " cib=%d.%d.%d source=%s:%d path=%s complete=%s",
                       controld_globals.transition_graph->id,
                       TYPE(reason), (id? id : ""), (op? op : "change"),
                       abort_text, add[0], add[1], add[2], fn, line, path,
                       pcmk__btoa(controld_globals.transition_graph->complete));
        }
    }

    if (controld_globals.transition_graph->complete) {
        if (controld_get_period_transition_timer() > 0) {
            controld_stop_transition_timer();
            controld_start_transition_timer();
        } else {
            register_fsa_input(C_FSA_INTERNAL, I_PE_CALC, NULL);
        }
        return;
    }

    trigger_graph();
}

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
#include <crm/lrmd.h>               // lrmd_event_data_t, lrmd_free_event()
#include <crm/msg_xml.h>
#include <crm/common/xml.h>
#include <crm/cluster.h>

#include <pacemaker-internal.h>
#include <pacemaker-controld.h>

char *te_uuid = NULL;
GHashTable *te_targets = NULL;
void send_rsc_command(crm_action_t * action);
static void te_update_job_count(crm_action_t * action, int offset);

static void
te_start_action_timer(crm_graph_t * graph, crm_action_t * action)
{
    action->timer = calloc(1, sizeof(crm_action_timer_t));
    action->timer->timeout = action->timeout;
    action->timer->action = action;
    action->timer->source_id = g_timeout_add(action->timer->timeout + graph->network_delay,
                                             action_timer_callback, (void *)action->timer);

    CRM_ASSERT(action->timer->source_id != 0);
}

static gboolean
te_pseudo_action(crm_graph_t * graph, crm_action_t * pseudo)
{
    const char *task = crm_element_value(pseudo->xml, XML_LRM_ATTR_TASK);

    /* send to peers as well? */
    if (pcmk__str_eq(task, CRM_OP_MAINTENANCE_NODES, pcmk__str_casei)) {
        GHashTableIter iter;
        crm_node_t *node = NULL;

        g_hash_table_iter_init(&iter, crm_peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            xmlNode *cmd = NULL;

            if (pcmk__str_eq(fsa_our_uname, node->uname, pcmk__str_casei)) {
                continue;
            }

            cmd = create_request(task, pseudo->xml, node->uname,
                                 CRM_SYSTEM_CRMD, CRM_SYSTEM_TENGINE, NULL);
            send_cluster_message(node, crm_msg_crmd, cmd, FALSE);
            free_xml(cmd);
        }

        remote_ra_process_maintenance_nodes(pseudo->xml);
    } else {
        /* Check action for Pacemaker Remote node side effects */
        remote_ra_process_pseudo(pseudo->xml);
    }

    crm_debug("Pseudo-action %d (%s) fired and confirmed", pseudo->id,
              crm_element_value(pseudo->xml, XML_LRM_ATTR_TASK_KEY));
    te_action_confirmed(pseudo, graph);
    return TRUE;
}

static int
get_target_rc(crm_action_t * action)
{
    int exit_status;

    pcmk__scan_min_int(crm_meta_value(action->params, XML_ATTR_TE_TARGET_RC),
                       &exit_status, 0);
    return exit_status;
}

static gboolean
te_crm_command(crm_graph_t * graph, crm_action_t * action)
{
    char *counter = NULL;
    xmlNode *cmd = NULL;
    gboolean is_local = FALSE;

    const char *id = NULL;
    const char *task = NULL;
    const char *value = NULL;
    const char *on_node = NULL;
    const char *router_node = NULL;

    gboolean rc = TRUE;
    gboolean no_wait = FALSE;

    id = ID(action->xml);
    task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
    on_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    router_node = crm_element_value(action->xml, XML_LRM_ATTR_ROUTER_NODE);

    if (!router_node) {
        router_node = on_node;
        if (pcmk__str_eq(task, CRM_OP_LRM_DELETE, pcmk__str_casei)) {
            const char *mode = crm_element_value(action->xml, PCMK__XA_MODE);

            if (pcmk__str_eq(mode, XML_TAG_CIB, pcmk__str_casei)) {
                router_node = fsa_our_uname;
            }
        }
    }

    CRM_CHECK(on_node != NULL && strlen(on_node) != 0,
              crm_err("Corrupted command (id=%s) %s: no node", crm_str(id), crm_str(task));
              return FALSE);

    if (pcmk__str_eq(router_node, fsa_our_uname, pcmk__str_casei)) {
        is_local = TRUE;
    }

    value = crm_meta_value(action->params, XML_ATTR_TE_NOWAIT);
    if (crm_is_true(value)) {
        no_wait = TRUE;
    }

    crm_info("Executing crm-event (%s)%s%s: %s on %s",
             crm_str(id), (is_local? " locally" : ""),
             (no_wait? " without waiting" : ""), crm_str(task), on_node);

    if (is_local && pcmk__str_eq(task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
        /* defer until everything else completes */
        crm_info("crm-event (%s) is a local shutdown", crm_str(id));
        graph->completion_action = tg_shutdown;
        graph->abort_reason = "local shutdown";
        te_action_confirmed(action, graph);
        return TRUE;

    } else if (pcmk__str_eq(task, CRM_OP_SHUTDOWN, pcmk__str_casei)) {
        crm_node_t *peer = crm_get_peer(0, router_node);

        pcmk__update_peer_expected(__func__, peer, CRMD_JOINSTATE_DOWN);
    }

    cmd = create_request(task, action->xml, router_node, CRM_SYSTEM_CRMD, CRM_SYSTEM_TENGINE, NULL);

    counter = pcmk__transition_key(transition_graph->id, action->id,
                                   get_target_rc(action), te_uuid);
    crm_xml_add(cmd, XML_ATTR_TRANSITION_KEY, counter);

    rc = send_cluster_message(crm_get_peer(0, router_node), crm_msg_crmd, cmd, TRUE);
    free(counter);
    free_xml(cmd);

    if (rc == FALSE) {
        crm_err("Action %d failed: send", action->id);
        return FALSE;

    } else if (no_wait) {
        te_action_confirmed(action, graph);

    } else {
        if (action->timeout <= 0) {
            crm_err("Action %d: %s on %s had an invalid timeout (%dms).  Using %ums instead",
                    action->id, task, on_node, action->timeout, graph->network_delay);
            action->timeout = (int) graph->network_delay;
        }
        te_start_action_timer(graph, action);
    }

    return TRUE;
}

void
controld_record_action_timeout(crm_action_t *action)
{
    lrmd_event_data_t *op = NULL;
    xmlNode *state = NULL;
    xmlNode *rsc = NULL;
    xmlNode *xml_op = NULL;
    xmlNode *action_rsc = NULL;

    int rc = pcmk_ok;

    const char *rsc_id = NULL;
    const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    const char *task_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
    const char *target_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TARGET_UUID);

    int call_options = cib_quorum_override | cib_scope_local;
    int target_rc = get_target_rc(action);

    crm_warn("%s %d: %s on %s timed out",
             crm_element_name(action->xml), action->id, task_uuid, target);

    action_rsc = find_xml_node(action->xml, XML_CIB_TAG_RESOURCE, TRUE);
    if (action_rsc == NULL) {
        return;
    }

    rsc_id = ID(action_rsc);
    CRM_CHECK(rsc_id != NULL,
              crm_log_xml_err(action->xml, "Bad:action"); return);

/*
  update the CIB

<node_state id="hadev">
      <lrm>
        <lrm_resources>
          <lrm_resource id="rsc2" last_op="start" op_code="0" target="hadev"/>
*/

    state = create_xml_node(NULL, XML_CIB_TAG_STATE);

    crm_xml_add(state, XML_ATTR_UUID, target_uuid);
    crm_xml_add(state, XML_ATTR_UNAME, target);

    rsc = create_xml_node(state, XML_CIB_TAG_LRM);
    crm_xml_add(rsc, XML_ATTR_ID, target_uuid);

    rsc = create_xml_node(rsc, XML_LRM_TAG_RESOURCES);
    rsc = create_xml_node(rsc, XML_LRM_TAG_RESOURCE);
    crm_xml_add(rsc, XML_ATTR_ID, rsc_id);


    crm_copy_xml_element(action_rsc, rsc, XML_ATTR_TYPE);
    crm_copy_xml_element(action_rsc, rsc, XML_AGENT_ATTR_CLASS);
    crm_copy_xml_element(action_rsc, rsc, XML_AGENT_ATTR_PROVIDER);

    /* If the executor gets a timeout while waiting for the action to complete,
     * that will be reported via the usual callback. This timeout means that we
     * didn't hear from the executor or the controller that relayed the action
     * to the executor.
     */
    op = pcmk__event_from_graph_action(NULL, action, PCMK_EXEC_TIMEOUT,
                                       PCMK_OCF_TIMEOUT,
                                       "Cluster communication timeout "
                                       "(no response from executor)");
    op->call_id = -1;
    op->user_data = pcmk__transition_key(transition_graph->id, action->id,
                                         target_rc, te_uuid);

    xml_op = pcmk__create_history_xml(rsc, op, CRM_FEATURE_SET, target_rc,
                                      target, __func__, LOG_INFO);
    lrmd_free_event(op);

    crm_log_xml_trace(xml_op, "Action timeout");

    rc = fsa_cib_conn->cmds->update(fsa_cib_conn, XML_CIB_TAG_STATUS, state, call_options);
    fsa_register_cib_callback(rc, FALSE, NULL, cib_action_updated);
    free_xml(state);

    crm_trace("Sent CIB update (call ID %d) for timeout of action %d (%s on %s)",
              rc, action->id, task_uuid, target);
    action->sent_update = TRUE;
}

static gboolean
te_rsc_command(crm_graph_t * graph, crm_action_t * action)
{
    /* never overwrite stop actions in the CIB with
     *   anything other than completed results
     *
     * Writing pending stops makes it look like the
     *   resource is running again
     */
    xmlNode *cmd = NULL;
    xmlNode *rsc_op = NULL;

    gboolean rc = TRUE;
    gboolean no_wait = FALSE;
    gboolean is_local = FALSE;

    char *counter = NULL;
    const char *task = NULL;
    const char *value = NULL;
    const char *on_node = NULL;
    const char *router_node = NULL;
    const char *task_uuid = NULL;

    CRM_ASSERT(action != NULL);
    CRM_ASSERT(action->xml != NULL);

    action->executed = FALSE;
    on_node = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

    CRM_CHECK(on_node != NULL && strlen(on_node) != 0,
              crm_err("Corrupted command(id=%s) %s: no node", ID(action->xml), crm_str(task));
              return FALSE);

    rsc_op = action->xml;
    task = crm_element_value(rsc_op, XML_LRM_ATTR_TASK);
    task_uuid = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);
    router_node = crm_element_value(rsc_op, XML_LRM_ATTR_ROUTER_NODE);

    if (!router_node) {
        router_node = on_node;
    }

    counter = pcmk__transition_key(transition_graph->id, action->id,
                                   get_target_rc(action), te_uuid);
    crm_xml_add(rsc_op, XML_ATTR_TRANSITION_KEY, counter);

    if (pcmk__str_eq(router_node, fsa_our_uname, pcmk__str_casei)) {
        is_local = TRUE;
    }

    value = crm_meta_value(action->params, XML_ATTR_TE_NOWAIT);
    if (crm_is_true(value)) {
        no_wait = TRUE;
    }

    crm_notice("Initiating %s operation %s%s on %s%s "CRM_XS" action %d",
               task, task_uuid, (is_local? " locally" : ""), on_node,
               (no_wait? " without waiting" : ""), action->id);

    cmd = create_request(CRM_OP_INVOKE_LRM, rsc_op, router_node,
                         CRM_SYSTEM_LRMD, CRM_SYSTEM_TENGINE, NULL);

    if (is_local) {
        /* shortcut local resource commands */
        ha_msg_input_t data = {
            .msg = cmd,
            .xml = rsc_op,
        };

        fsa_data_t msg = {
            .id = 0,
            .data = &data,
            .data_type = fsa_dt_ha_msg,
            .fsa_input = I_NULL,
            .fsa_cause = C_FSA_INTERNAL,
            .actions = A_LRM_INVOKE,
            .origin = __func__,
        };

        do_lrm_invoke(A_LRM_INVOKE, C_FSA_INTERNAL, fsa_state, I_NULL, &msg);

    } else {
        rc = send_cluster_message(crm_get_peer(0, router_node), crm_msg_lrmd, cmd, TRUE);
    }

    free(counter);
    free_xml(cmd);

    action->executed = TRUE;

    if (rc == FALSE) {
        crm_err("Action %d failed: send", action->id);
        return FALSE;

    } else if (no_wait) {
        crm_info("Action %d confirmed - no wait", action->id);
        action->confirmed = TRUE; /* Just mark confirmed.
                                   * Don't bump the job count only to immediately decrement it
                                   */
        pcmk__update_graph(transition_graph, action);
        trigger_graph();

    } else if (action->confirmed == TRUE) {
        crm_debug("Action %d: %s %s on %s(timeout %dms) was already confirmed.",
                  action->id, task, task_uuid, on_node, action->timeout);
    } else {
        if (action->timeout <= 0) {
            crm_err("Action %d: %s %s on %s had an invalid timeout (%dms).  Using %ums instead",
                    action->id, task, task_uuid, on_node, action->timeout, graph->network_delay);
            action->timeout = (int) graph->network_delay;
        }
        te_update_job_count(action, 1);
        te_start_action_timer(graph, action);
    }

    return TRUE;
}

struct te_peer_s
{
        char *name;
        int jobs;
        int migrate_jobs;
};

static void te_peer_free(gpointer p)
{
    struct te_peer_s *peer = p;

    free(peer->name);
    free(peer);
}

void te_reset_job_counts(void)
{
    GHashTableIter iter;
    struct te_peer_s *peer = NULL;

    if(te_targets == NULL) {
        te_targets = pcmk__strkey_table(NULL, te_peer_free);
    }

    g_hash_table_iter_init(&iter, te_targets);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) & peer)) {
        peer->jobs = 0;
        peer->migrate_jobs = 0;
    }
}

static void
te_update_job_count_on(const char *target, int offset, bool migrate)
{
    struct te_peer_s *r = NULL;

    if(target == NULL || te_targets == NULL) {
        return;
    }

    r = g_hash_table_lookup(te_targets, target);
    if(r == NULL) {
        r = calloc(1, sizeof(struct te_peer_s));
        r->name = strdup(target);
        g_hash_table_insert(te_targets, r->name, r);
    }

    r->jobs += offset;
    if(migrate) {
        r->migrate_jobs += offset;
    }
    crm_trace("jobs[%s] = %d", target, r->jobs);
}

static void
te_update_job_count(crm_action_t * action, int offset)
{
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
    const char *target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);

    if (action->type != action_type_rsc || target == NULL) {
        /* No limit on these */
        return;
    }

    /* if we have a router node, this means the action is performing
     * on a remote node. For now, we count all actions occurring on a
     * remote node against the job list on the cluster node hosting
     * the connection resources */
    target = crm_element_value(action->xml, XML_LRM_ATTR_ROUTER_NODE);

    if ((target == NULL) && pcmk__strcase_any_of(task, CRMD_ACTION_MIGRATE,
                                                 CRMD_ACTION_MIGRATED, NULL)) {

        const char *t1 = crm_meta_value(action->params, XML_LRM_ATTR_MIGRATE_SOURCE);
        const char *t2 = crm_meta_value(action->params, XML_LRM_ATTR_MIGRATE_TARGET);

        te_update_job_count_on(t1, offset, TRUE);
        te_update_job_count_on(t2, offset, TRUE);
        return;
    } else if (target == NULL) {
        target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    }

    te_update_job_count_on(target, offset, FALSE);
}

static gboolean
te_should_perform_action_on(crm_graph_t * graph, crm_action_t * action, const char *target)
{
    int limit = 0;
    struct te_peer_s *r = NULL;
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);
    const char *id = crm_element_value(action->xml, XML_LRM_ATTR_TASK_KEY);

    if(target == NULL) {
        /* No limit on these */
        return TRUE;

    } else if(te_targets == NULL) {
        return FALSE;
    }

    r = g_hash_table_lookup(te_targets, target);
    limit = throttle_get_job_limit(target);

    if(r == NULL) {
        r = calloc(1, sizeof(struct te_peer_s));
        r->name = strdup(target);
        g_hash_table_insert(te_targets, r->name, r);
    }

    if(limit <= r->jobs) {
        crm_trace("Peer %s is over their job limit of %d (%d): deferring %s",
                  target, limit, r->jobs, id);
        return FALSE;

    } else if(graph->migration_limit > 0 && r->migrate_jobs >= graph->migration_limit) {
        if (pcmk__strcase_any_of(task, CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED, NULL)) {
            crm_trace("Peer %s is over their migration job limit of %d (%d): deferring %s",
                      target, graph->migration_limit, r->migrate_jobs, id);
            return FALSE;
        }
    }

    crm_trace("Peer %s has not hit their limit yet. current jobs = %d limit= %d limit", target, r->jobs, limit);

    return TRUE;
}

static gboolean
te_should_perform_action(crm_graph_t * graph, crm_action_t * action)
{
    const char *target = NULL;
    const char *task = crm_element_value(action->xml, XML_LRM_ATTR_TASK);

    if (action->type != action_type_rsc) {
        /* No limit on these */
        return TRUE;
    }

    /* if we have a router node, this means the action is performing
     * on a remote node. For now, we count all actions occurring on a
     * remote node against the job list on the cluster node hosting
     * the connection resources */
    target = crm_element_value(action->xml, XML_LRM_ATTR_ROUTER_NODE);

    if ((target == NULL) && pcmk__strcase_any_of(task, CRMD_ACTION_MIGRATE,
                                                 CRMD_ACTION_MIGRATED, NULL)) {
        target = crm_meta_value(action->params, XML_LRM_ATTR_MIGRATE_SOURCE);
        if(te_should_perform_action_on(graph, action, target) == FALSE) {
            return FALSE;
        }

        target = crm_meta_value(action->params, XML_LRM_ATTR_MIGRATE_TARGET);

    } else if (target == NULL) {
        target = crm_element_value(action->xml, XML_LRM_ATTR_TARGET);
    }

    return te_should_perform_action_on(graph, action, target);
}

/*!
 * \brief Confirm a graph action (and optionally update graph)
 *
 * \param[in] action  Action to confirm
 * \param[in] graph   Update and trigger this graph (if non-NULL)
 */
void
te_action_confirmed(crm_action_t *action, crm_graph_t *graph)
{
    if (action->confirmed == FALSE) {
        if ((action->type == action_type_rsc)
            && (crm_element_value(action->xml, XML_LRM_ATTR_TARGET) != NULL)) {
            te_update_job_count(action, -1);
        }
        action->confirmed = TRUE;
    }
    if (graph) {
        pcmk__update_graph(graph, action);
        trigger_graph();
    }
}


crm_graph_functions_t te_graph_fns = {
    te_pseudo_action,
    te_rsc_command,
    te_crm_command,
    te_fence_node,
    te_should_perform_action,
};

void
notify_crmd(crm_graph_t * graph)
{
    const char *type = "unknown";
    enum crmd_fsa_input event = I_NULL;

    crm_debug("Processing transition completion in state %s", fsa_state2string(fsa_state));

    if (graph->complete == FALSE) {
        CRM_CHECK(graph->complete,);
        graph->complete = TRUE;
    }

    switch (graph->completion_action) {
        case tg_stop:
            type = "stop";
            if (fsa_state == S_TRANSITION_ENGINE) {
                event = I_TE_SUCCESS;
            }
            break;
        case tg_done:
            type = "done";
            if (fsa_state == S_TRANSITION_ENGINE) {
                event = I_TE_SUCCESS;
            }
            break;

        case tg_restart:
            type = "restart";
            if (fsa_state == S_TRANSITION_ENGINE) {
                if (transition_timer->period_ms > 0) {
                    controld_stop_timer(transition_timer);
                    controld_start_timer(transition_timer);
                } else {
                    event = I_PE_CALC;
                }

            } else if (fsa_state == S_POLICY_ENGINE) {
                controld_set_fsa_action_flags(A_PE_INVOKE);
                trigger_fsa();
            }
            break;

        case tg_shutdown:
            type = "shutdown";
            if (pcmk_is_set(fsa_input_register, R_SHUTDOWN)) {
                event = I_STOP;

            } else {
                crm_err("We didn't ask to be shut down, yet the scheduler is telling us to");
                event = I_TERMINATE;
            }
    }

    crm_debug("Transition %d status: %s - %s", graph->id, type, crm_str(graph->abort_reason));

    graph->abort_reason = NULL;
    graph->completion_action = tg_done;
    controld_clear_fsa_input_flags(R_IN_TRANSITION);

    if (event != I_NULL) {
        register_fsa_input(C_FSA_INTERNAL, event, NULL);

    } else if (fsa_source) {
        mainloop_set_trigger(fsa_source);
    }
}

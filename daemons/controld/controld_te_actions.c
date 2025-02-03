/*
 * Copyright 2004-2024 the Pacemaker project contributors
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
#include <crm/common/xml.h>
#include <crm/cluster.h>

#include <pacemaker-internal.h>
#include <pacemaker-controld.h>

static GHashTable *te_targets = NULL;
void send_rsc_command(pcmk__graph_action_t *action);
static void te_update_job_count(pcmk__graph_action_t *action, int offset);

static void
te_start_action_timer(const pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    action->timer = pcmk__create_timer(action->timeout + graph->network_delay,
                                       action_timer_callback, action);
    pcmk__assert(action->timer != 0);
}

/*!
 * \internal
 * \brief Execute a graph pseudo-action
 *
 * \param[in,out] graph   Transition graph being executed
 * \param[in,out] pseudo  Pseudo-action to execute
 *
 * \return Standard Pacemaker return code
 */
static int
execute_pseudo_action(pcmk__graph_t *graph, pcmk__graph_action_t *pseudo)
{
    const char *task = crm_element_value(pseudo->xml, PCMK_XA_OPERATION);

    /* send to peers as well? */
    if (pcmk__str_eq(task, PCMK_ACTION_MAINTENANCE_NODES, pcmk__str_casei)) {
        GHashTableIter iter;
        pcmk__node_status_t *node = NULL;

        g_hash_table_iter_init(&iter, pcmk__peer_cache);
        while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
            xmlNode *cmd = NULL;

            if (controld_is_local_node(node->name)) {
                continue;
            }

            cmd = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_TENGINE,
                                    node->name, CRM_SYSTEM_CRMD, task,
                                    pseudo->xml);
            pcmk__cluster_send_message(node, pcmk_ipc_controld, cmd);
            pcmk__xml_free(cmd);
        }

        remote_ra_process_maintenance_nodes(pseudo->xml);
    } else {
        /* Check action for Pacemaker Remote node side effects */
        remote_ra_process_pseudo(pseudo->xml);
    }

    crm_debug("Pseudo-action %d (%s) fired and confirmed", pseudo->id,
              crm_element_value(pseudo->xml, PCMK__XA_OPERATION_KEY));
    te_action_confirmed(pseudo, graph);
    return pcmk_rc_ok;
}

static int
get_target_rc(pcmk__graph_action_t *action)
{
    int exit_status;

    pcmk__scan_min_int(crm_meta_value(action->params, PCMK__META_OP_TARGET_RC),
                       &exit_status, 0);
    return exit_status;
}

/*!
 * \internal
 * \brief Execute a cluster action from a transition graph
 *
 * \param[in,out] graph   Transition graph being executed
 * \param[in,out] action  Cluster action to execute
 *
 * \return Standard Pacemaker return code
 */
static int
execute_cluster_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
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

    const pcmk__node_status_t *node = NULL;

    id = pcmk__xe_id(action->xml);
    CRM_CHECK(!pcmk__str_empty(id), return EPROTO);

    task = crm_element_value(action->xml, PCMK_XA_OPERATION);
    CRM_CHECK(!pcmk__str_empty(task), return EPROTO);

    on_node = crm_element_value(action->xml, PCMK__META_ON_NODE);
    CRM_CHECK(!pcmk__str_empty(on_node), return pcmk_rc_node_unknown);

    router_node = crm_element_value(action->xml, PCMK__XA_ROUTER_NODE);
    if (router_node == NULL) {
        router_node = on_node;
        if (pcmk__str_eq(task, PCMK_ACTION_LRM_DELETE, pcmk__str_none)) {
            const char *mode = crm_element_value(action->xml, PCMK__XA_MODE);

            if (pcmk__str_eq(mode, PCMK__VALUE_CIB, pcmk__str_none)) {
                router_node = controld_globals.cluster->priv->node_name;
            }
        }
    }

    if (controld_is_local_node(router_node)) {
        is_local = TRUE;
    }

    value = crm_meta_value(action->params, PCMK__META_OP_NO_WAIT);
    if (crm_is_true(value)) {
        no_wait = TRUE;
    }

    crm_info("Handling controller request '%s' (%s on %s)%s%s",
             id, task, on_node, (is_local? " locally" : ""),
             (no_wait? " without waiting" : ""));

    if (is_local
        && pcmk__str_eq(task, PCMK_ACTION_DO_SHUTDOWN, pcmk__str_none)) {
        /* defer until everything else completes */
        crm_info("Controller request '%s' is a local shutdown", id);
        graph->completion_action = pcmk__graph_shutdown;
        graph->abort_reason = "local shutdown";
        te_action_confirmed(action, graph);
        return pcmk_rc_ok;

    } else if (pcmk__str_eq(task, PCMK_ACTION_DO_SHUTDOWN, pcmk__str_none)) {
        pcmk__node_status_t *peer =
            pcmk__get_node(0, router_node, NULL,
                           pcmk__node_search_cluster_member);

        pcmk__update_peer_expected(__func__, peer, CRMD_JOINSTATE_DOWN);
    }

    cmd = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_TENGINE, router_node,
                            CRM_SYSTEM_CRMD, task, action->xml);

    counter = pcmk__transition_key(controld_globals.transition_graph->id,
                                   action->id, get_target_rc(action),
                                   controld_globals.te_uuid);
    crm_xml_add(cmd, PCMK__XA_TRANSITION_KEY, counter);

    node = pcmk__get_node(0, router_node, NULL,
                          pcmk__node_search_cluster_member);
    rc = pcmk__cluster_send_message(node, pcmk_ipc_controld, cmd);
    free(counter);
    pcmk__xml_free(cmd);

    if (rc == FALSE) {
        crm_err("Action %d failed: send", action->id);
        return ECOMM;

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

    return pcmk_rc_ok;
}

/*!
 * \internal
 * \brief Synthesize an executor event for a resource action timeout
 *
 * \param[in] action     Resource action that timed out
 * \param[in] target_rc  Expected result of action that timed out
 *
 * Synthesize an executor event for a resource action timeout. (If the executor
 * gets a timeout while waiting for a resource action to complete, that will be
 * reported via the usual callback. This timeout means we didn't hear from the
 * executor itself or the controller that relayed the action to the executor.)
 *
 * \return Newly created executor event for result of \p action
 * \note The caller is responsible for freeing the return value using
 *       lrmd_free_event().
 */
static lrmd_event_data_t *
synthesize_timeout_event(const pcmk__graph_action_t *action, int target_rc)
{
    lrmd_event_data_t *op = NULL;
    const char *target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    const char *reason = NULL;
    char *dynamic_reason = NULL;

    if (pcmk__str_eq(target, pcmk__cluster_local_node_name(),
                     pcmk__str_casei)) {
        reason = "Local executor did not return result in time";
    } else {
        const char *router_node = NULL;

        router_node = crm_element_value(action->xml, PCMK__XA_ROUTER_NODE);
        if (router_node == NULL) {
            router_node = target;
        }
        dynamic_reason = crm_strdup_printf("Controller on %s did not return "
                                           "result in time", router_node);
        reason = dynamic_reason;
    }

    op = pcmk__event_from_graph_action(NULL, action, PCMK_EXEC_TIMEOUT,
                                       PCMK_OCF_UNKNOWN_ERROR, reason);
    op->call_id = -1;
    op->user_data = pcmk__transition_key(controld_globals.transition_graph->id,
                                         action->id, target_rc,
                                         controld_globals.te_uuid);
    free(dynamic_reason);
    return op;
}

static void
controld_record_action_event(pcmk__graph_action_t *action,
                             lrmd_event_data_t *op)
{
    cib_t *cib_conn = controld_globals.cib_conn;

    xmlNode *state = NULL;
    xmlNode *rsc = NULL;
    xmlNode *action_rsc = NULL;

    int rc = pcmk_ok;

    const char *rsc_id = NULL;
    const char *target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    const char *task_uuid = crm_element_value(action->xml,
                                              PCMK__XA_OPERATION_KEY);
    const char *target_uuid = crm_element_value(action->xml,
                                                PCMK__META_ON_NODE_UUID);

    int target_rc = get_target_rc(action);

    action_rsc = pcmk__xe_first_child(action->xml, PCMK_XE_PRIMITIVE, NULL,
                                      NULL);
    if (action_rsc == NULL) {
        return;
    }

    rsc_id = pcmk__xe_id(action_rsc);
    CRM_CHECK(rsc_id != NULL,
              crm_log_xml_err(action->xml, "Bad:action"); return);

/*
  update the CIB

<node_state id="hadev">
      <lrm>
        <lrm_resources>
          <lrm_resource id="rsc2" last_op="start" op_code="0" target="hadev"/>
*/

    state = pcmk__xe_create(NULL, PCMK__XE_NODE_STATE);

    crm_xml_add(state, PCMK_XA_ID, target_uuid);
    crm_xml_add(state, PCMK_XA_UNAME, target);

    rsc = pcmk__xe_create(state, PCMK__XE_LRM);
    crm_xml_add(rsc, PCMK_XA_ID, target_uuid);

    rsc = pcmk__xe_create(rsc, PCMK__XE_LRM_RESOURCES);
    rsc = pcmk__xe_create(rsc, PCMK__XE_LRM_RESOURCE);
    crm_xml_add(rsc, PCMK_XA_ID, rsc_id);


    crm_copy_xml_element(action_rsc, rsc, PCMK_XA_TYPE);
    crm_copy_xml_element(action_rsc, rsc, PCMK_XA_CLASS);
    crm_copy_xml_element(action_rsc, rsc, PCMK_XA_PROVIDER);

    pcmk__create_history_xml(rsc, op, CRM_FEATURE_SET, target_rc, target,
                             __func__);

    rc = cib_conn->cmds->modify(cib_conn, PCMK_XE_STATUS, state, cib_none);
    fsa_register_cib_callback(rc, NULL, cib_action_updated);
    pcmk__xml_free(state);

    crm_trace("Sent CIB update (call ID %d) for synthesized event of action %d (%s on %s)",
              rc, action->id, task_uuid, target);
    pcmk__set_graph_action_flags(action, pcmk__graph_action_sent_update);
}

void
controld_record_action_timeout(pcmk__graph_action_t *action)
{
    lrmd_event_data_t *op = NULL;

    const char *target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    const char *task_uuid = crm_element_value(action->xml,
                                              PCMK__XA_OPERATION_KEY);

    int target_rc = get_target_rc(action);

    crm_warn("%s %d: %s on %s timed out",
             action->xml->name, action->id, task_uuid, target);

    op = synthesize_timeout_event(action, target_rc);
    controld_record_action_event(action, op);
    lrmd_free_event(op);
}

/*!
 * \internal
 * \brief Execute a resource action from a transition graph
 *
 * \param[in,out] graph   Transition graph being executed
 * \param[in,out] action  Resource action to execute
 *
 * \return Standard Pacemaker return code
 */
static int
execute_rsc_action(pcmk__graph_t *graph, pcmk__graph_action_t *action)
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

    pcmk__assert((action != NULL) && (action->xml != NULL));

    pcmk__clear_graph_action_flags(action, pcmk__graph_action_executed);
    on_node = crm_element_value(action->xml, PCMK__META_ON_NODE);

    CRM_CHECK(!pcmk__str_empty(on_node), return pcmk_rc_node_unknown);

    rsc_op = action->xml;
    task = crm_element_value(rsc_op, PCMK_XA_OPERATION);
    task_uuid = crm_element_value(action->xml, PCMK__XA_OPERATION_KEY);
    router_node = crm_element_value(rsc_op, PCMK__XA_ROUTER_NODE);

    if (!router_node) {
        router_node = on_node;
    }

    counter = pcmk__transition_key(controld_globals.transition_graph->id,
                                   action->id, get_target_rc(action),
                                   controld_globals.te_uuid);
    crm_xml_add(rsc_op, PCMK__XA_TRANSITION_KEY, counter);

    if (controld_is_local_node(router_node)) {
        is_local = TRUE;
    }

    value = crm_meta_value(action->params, PCMK__META_OP_NO_WAIT);
    if (crm_is_true(value)) {
        no_wait = TRUE;
    }

    cmd = pcmk__new_request(pcmk_ipc_controld, CRM_SYSTEM_TENGINE, router_node,
                            CRM_SYSTEM_LRMD, CRM_OP_INVOKE_LRM, rsc_op);

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

        do_lrm_invoke(A_LRM_INVOKE, C_FSA_INTERNAL, controld_globals.fsa_state,
                      I_NULL, &msg);

    } else {
        const pcmk__node_status_t *node =
            pcmk__get_node(0, router_node, NULL,
                           pcmk__node_search_cluster_member);

        crm_notice("Asking %s to execute %s on %s%s "
                   QB_XS " transition %s action %d",
                   router_node, task_uuid, on_node,
                   (no_wait? " without waiting" : ""), counter, action->id);
        rc = pcmk__cluster_send_message(node, pcmk_ipc_execd, cmd);
    }

    free(counter);
    pcmk__xml_free(cmd);

    pcmk__set_graph_action_flags(action, pcmk__graph_action_executed);

    if (rc == FALSE) {
        crm_err("Action %d failed: send", action->id);
        return ECOMM;

    } else if (no_wait) {
        /* Just mark confirmed. Don't bump the job count only to immediately
         * decrement it.
         */
        crm_info("Action %d confirmed - no wait", action->id);
        pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
        pcmk__update_graph(controld_globals.transition_graph, action);
        trigger_graph();

    } else if (pcmk_is_set(action->flags, pcmk__graph_action_confirmed)) {
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

    return pcmk_rc_ok;
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
        r = pcmk__assert_alloc(1, sizeof(struct te_peer_s));
        r->name = pcmk__str_copy(target);
        g_hash_table_insert(te_targets, r->name, r);
    }

    r->jobs += offset;
    if(migrate) {
        r->migrate_jobs += offset;
    }
    crm_trace("jobs[%s] = %d", target, r->jobs);
}

static void
te_update_job_count(pcmk__graph_action_t *action, int offset)
{
    const char *task = crm_element_value(action->xml, PCMK_XA_OPERATION);
    const char *target = crm_element_value(action->xml, PCMK__META_ON_NODE);

    if ((action->type != pcmk__rsc_graph_action) || (target == NULL)) {
        /* No limit on these */
        return;
    }

    /* if we have a router node, this means the action is performing
     * on a remote node. For now, we count all actions occurring on a
     * remote node against the job list on the cluster node hosting
     * the connection resources */
    target = crm_element_value(action->xml, PCMK__XA_ROUTER_NODE);

    if ((target == NULL)
        && pcmk__strcase_any_of(task, PCMK_ACTION_MIGRATE_TO,
                                PCMK_ACTION_MIGRATE_FROM, NULL)) {

        const char *t1 = crm_meta_value(action->params,
                                        PCMK__META_MIGRATE_SOURCE);
        const char *t2 = crm_meta_value(action->params,
                                        PCMK__META_MIGRATE_TARGET);

        te_update_job_count_on(t1, offset, TRUE);
        te_update_job_count_on(t2, offset, TRUE);
        return;
    } else if (target == NULL) {
        target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    }

    te_update_job_count_on(target, offset, FALSE);
}

/*!
 * \internal
 * \brief Check whether a graph action is allowed to be executed on a node
 *
 * \param[in] graph   Transition graph being executed
 * \param[in] action  Graph action being executed
 * \param[in] target  Name of node where action should be executed
 *
 * \return true if action is allowed, otherwise false
 */
static bool
allowed_on_node(const pcmk__graph_t *graph, const pcmk__graph_action_t *action,
                const char *target)
{
    int limit = 0;
    struct te_peer_s *r = NULL;
    const char *task = crm_element_value(action->xml, PCMK_XA_OPERATION);
    const char *id = crm_element_value(action->xml, PCMK__XA_OPERATION_KEY);

    if(target == NULL) {
        /* No limit on these */
        return true;

    } else if(te_targets == NULL) {
        return false;
    }

    r = g_hash_table_lookup(te_targets, target);
    limit = throttle_get_job_limit(target);

    if(r == NULL) {
        r = pcmk__assert_alloc(1, sizeof(struct te_peer_s));
        r->name = pcmk__str_copy(target);
        g_hash_table_insert(te_targets, r->name, r);
    }

    if(limit <= r->jobs) {
        crm_trace("Peer %s is over their job limit of %d (%d): deferring %s",
                  target, limit, r->jobs, id);
        return false;

    } else if(graph->migration_limit > 0 && r->migrate_jobs >= graph->migration_limit) {
        if (pcmk__strcase_any_of(task, PCMK_ACTION_MIGRATE_TO,
                                 PCMK_ACTION_MIGRATE_FROM, NULL)) {
            crm_trace("Peer %s is over their migration job limit of %d (%d): deferring %s",
                      target, graph->migration_limit, r->migrate_jobs, id);
            return false;
        }
    }

    crm_trace("Peer %s has not hit their limit yet. current jobs = %d limit= %d limit", target, r->jobs, limit);

    return true;
}

/*!
 * \internal
 * \brief Check whether a graph action is allowed to be executed
 *
 * \param[in] graph   Transition graph being executed
 * \param[in] action  Graph action being executed
 *
 * \return true if action is allowed, otherwise false
 */
static bool
graph_action_allowed(pcmk__graph_t *graph, pcmk__graph_action_t *action)
{
    const char *target = NULL;
    const char *task = crm_element_value(action->xml, PCMK_XA_OPERATION);

    if (action->type != pcmk__rsc_graph_action) {
        /* No limit on these */
        return true;
    }

    /* if we have a router node, this means the action is performing
     * on a remote node. For now, we count all actions occurring on a
     * remote node against the job list on the cluster node hosting
     * the connection resources */
    target = crm_element_value(action->xml, PCMK__XA_ROUTER_NODE);

    if ((target == NULL)
        && pcmk__strcase_any_of(task, PCMK_ACTION_MIGRATE_TO,
                                PCMK_ACTION_MIGRATE_FROM, NULL)) {
        target = crm_meta_value(action->params, PCMK__META_MIGRATE_SOURCE);
        if (!allowed_on_node(graph, action, target)) {
            return false;
        }

        target = crm_meta_value(action->params, PCMK__META_MIGRATE_TARGET);

    } else if (target == NULL) {
        target = crm_element_value(action->xml, PCMK__META_ON_NODE);
    }

    return allowed_on_node(graph, action, target);
}

/*!
 * \brief Confirm a graph action (and optionally update graph)
 *
 * \param[in,out] action  Action to confirm
 * \param[in,out] graph   Update and trigger this graph (if non-NULL)
 */
void
te_action_confirmed(pcmk__graph_action_t *action, pcmk__graph_t *graph)
{
    if (!pcmk_is_set(action->flags, pcmk__graph_action_confirmed)) {
        if ((action->type == pcmk__rsc_graph_action)
            && (crm_element_value(action->xml, PCMK__META_ON_NODE) != NULL)) {
            te_update_job_count(action, -1);
        }
        pcmk__set_graph_action_flags(action, pcmk__graph_action_confirmed);
    }
    if (graph) {
        pcmk__update_graph(graph, action);
        trigger_graph();
    }
}

static pcmk__graph_functions_t te_graph_fns = {
    execute_pseudo_action,
    execute_rsc_action,
    execute_cluster_action,
    controld_execute_fence_action,
    graph_action_allowed,
};

/*
 * \internal
 * \brief Register the transitioner's graph functions with \p libpacemaker
 */
void
controld_register_graph_functions(void)
{
    pcmk__set_graph_functions(&te_graph_fns);
}

void
notify_crmd(pcmk__graph_t *graph)
{
    const char *type = "unknown";
    enum crmd_fsa_input event = I_NULL;

    crm_debug("Processing transition completion in state %s",
              fsa_state2string(controld_globals.fsa_state));

    CRM_CHECK(graph->complete, graph->complete = true);

    switch (graph->completion_action) {
        case pcmk__graph_wait:
            type = "stop";
            if (controld_globals.fsa_state == S_TRANSITION_ENGINE) {
                event = I_TE_SUCCESS;
            }
            break;
        case pcmk__graph_done:
            type = "done";
            if (controld_globals.fsa_state == S_TRANSITION_ENGINE) {
                event = I_TE_SUCCESS;
            }
            break;

        case pcmk__graph_restart:
            type = "restart";
            if (controld_globals.fsa_state == S_TRANSITION_ENGINE) {
                if (controld_get_period_transition_timer() > 0) {
                    controld_stop_transition_timer();
                    controld_start_transition_timer();
                } else {
                    event = I_PE_CALC;
                }

            } else if (controld_globals.fsa_state == S_POLICY_ENGINE) {
                controld_set_fsa_action_flags(A_PE_INVOKE);
                controld_trigger_fsa();
            }
            break;

        case pcmk__graph_shutdown:
            type = "shutdown";
            if (pcmk_is_set(controld_globals.fsa_input_register, R_SHUTDOWN)) {
                event = I_STOP;

            } else {
                crm_err("We didn't ask to be shut down, yet the scheduler is telling us to");
                event = I_TERMINATE;
            }
    }

    crm_debug("Transition %d status: %s - %s", graph->id, type,
              pcmk__s(graph->abort_reason, "unspecified reason"));

    graph->abort_reason = NULL;
    graph->completion_action = pcmk__graph_done;

    if (event != I_NULL) {
        register_fsa_input(C_FSA_INTERNAL, event, NULL);
    } else {
        controld_trigger_fsa();
    }
}

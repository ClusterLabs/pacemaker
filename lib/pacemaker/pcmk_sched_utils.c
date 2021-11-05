/*
 * Copyright 2004-2021 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>
#include <crm/msg_xml.h>
#include <crm/lrmd.h>       // lrmd_event_data_t
#include <crm/common/xml_internal.h>
#include <crm/lrmd_internal.h>
#include <pacemaker-internal.h>
#include <pacemaker.h>
#include "libpacemaker_private.h"

gboolean
can_run_resources(const pe_node_t * node)
{
    if (node == NULL) {
        return FALSE;
    }
#if 0
    if (node->weight < 0) {
        return FALSE;
    }
#endif

    if (node->details->online == FALSE
        || node->details->shutdown || node->details->unclean
        || node->details->standby || node->details->maintenance) {
        crm_trace("%s: online=%d, unclean=%d, standby=%d, maintenance=%d",
                  node->details->uname, node->details->online,
                  node->details->unclean, node->details->standby, node->details->maintenance);
        return FALSE;
    }
    return TRUE;
}

/*!
 * \internal
 * \brief Copy a hash table of node objects
 *
 * \param[in] nodes  Hash table to copy
 *
 * \return New copy of nodes (or NULL if nodes is NULL)
 */
GHashTable *
pcmk__copy_node_table(GHashTable *nodes)
{
    GHashTable *new_table = NULL;
    GHashTableIter iter;
    pe_node_t *node = NULL;

    if (nodes == NULL) {
        return NULL;
    }
    new_table = pcmk__strkey_table(NULL, free);
    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (gpointer *) &node)) {
        pe_node_t *new_node = pe__copy_node(node);

        g_hash_table_insert(new_table, (gpointer) new_node->details->id,
                            new_node);
    }
    return new_table;
}

/*!
 * \internal
 * \brief Copy a list of node objects
 *
 * \param[in] list   List to copy
 * \param[in] reset  Set copies' scores to 0
 *
 * \return New list of shallow copies of nodes in original list
 */
GList *
pcmk__copy_node_list(const GList *list, bool reset)
{
    GList *result = NULL;

    for (const GList *gIter = list; gIter != NULL; gIter = gIter->next) {
        pe_node_t *new_node = NULL;
        pe_node_t *this_node = (pe_node_t *) gIter->data;

        new_node = pe__copy_node(this_node);
        if (reset) {
            new_node->weight = 0;
        }
        result = g_list_prepend(result, new_node);
    }
    return result;
}

struct node_weight_s {
    pe_node_t *active;
    pe_working_set_t *data_set;
};

/* return -1 if 'a' is more preferred
 * return  1 if 'b' is more preferred
 */

static gint
sort_node_weight(gconstpointer a, gconstpointer b, gpointer data)
{
    const pe_node_t *node1 = (const pe_node_t *)a;
    const pe_node_t *node2 = (const pe_node_t *)b;
    struct node_weight_s *nw = data;

    int node1_weight = 0;
    int node2_weight = 0;

    int result = 0;

    if (a == NULL) {
        return 1;
    }
    if (b == NULL) {
        return -1;
    }

    node1_weight = node1->weight;
    node2_weight = node2->weight;

    if (can_run_resources(node1) == FALSE) {
        node1_weight = -INFINITY;
    }
    if (can_run_resources(node2) == FALSE) {
        node2_weight = -INFINITY;
    }

    if (node1_weight > node2_weight) {
        crm_trace("%s (%d) > %s (%d) : weight",
                  node1->details->uname, node1_weight, node2->details->uname, node2_weight);
        return -1;
    }

    if (node1_weight < node2_weight) {
        crm_trace("%s (%d) < %s (%d) : weight",
                  node1->details->uname, node1_weight, node2->details->uname, node2_weight);
        return 1;
    }

    crm_trace("%s (%d) == %s (%d) : weight",
              node1->details->uname, node1_weight, node2->details->uname, node2_weight);

    if (pcmk__str_eq(nw->data_set->placement_strategy, "minimal", pcmk__str_casei)) {
        goto equal;
    }

    if (pcmk__str_eq(nw->data_set->placement_strategy, "balanced", pcmk__str_casei)) {
        result = compare_capacity(node1, node2);
        if (result < 0) {
            crm_trace("%s > %s : capacity (%d)",
                      node1->details->uname, node2->details->uname, result);
            return -1;
        } else if (result > 0) {
            crm_trace("%s < %s : capacity (%d)",
                      node1->details->uname, node2->details->uname, result);
            return 1;
        }
    }

    /* now try to balance resources across the cluster */
    if (node1->details->num_resources < node2->details->num_resources) {
        crm_trace("%s (%d) > %s (%d) : resources",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return -1;

    } else if (node1->details->num_resources > node2->details->num_resources) {
        crm_trace("%s (%d) < %s (%d) : resources",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return 1;
    }

    if (nw->active && nw->active->details == node1->details) {
        crm_trace("%s (%d) > %s (%d) : active",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return -1;
    } else if (nw->active && nw->active->details == node2->details) {
        crm_trace("%s (%d) < %s (%d) : active",
                  node1->details->uname, node1->details->num_resources,
                  node2->details->uname, node2->details->num_resources);
        return 1;
    }
  equal:
    crm_trace("%s = %s", node1->details->uname, node2->details->uname);
    return strcmp(node1->details->uname, node2->details->uname);
}

GList *
sort_nodes_by_weight(GList *nodes, pe_node_t *active_node,
                     pe_working_set_t *data_set)
{
    struct node_weight_s nw = { active_node, data_set };

    return g_list_sort_with_data(nodes, sort_node_weight, &nw);
}

void
log_action(unsigned int log_level, const char *pre_text, pe_action_t * action, gboolean details)
{
    const char *node_uname = NULL;
    const char *node_uuid = NULL;
    const char *desc = NULL;

    if (action == NULL) {
        crm_trace("%s%s: <NULL>", pre_text == NULL ? "" : pre_text, pre_text == NULL ? "" : ": ");
        return;
    }

    if (pcmk_is_set(action->flags, pe_action_pseudo)) {
        node_uname = NULL;
        node_uuid = NULL;

    } else if (action->node != NULL) {
        node_uname = action->node->details->uname;
        node_uuid = action->node->details->id;
    } else {
        node_uname = "<none>";
        node_uuid = NULL;
    }

    switch (text2task(action->task)) {
        case stonith_node:
        case shutdown_crm:
            if (pcmk_is_set(action->flags, pe_action_pseudo)) {
                desc = "Pseudo ";
            } else if (pcmk_is_set(action->flags, pe_action_optional)) {
                desc = "Optional ";
            } else if (!pcmk_is_set(action->flags, pe_action_runnable)) {
                desc = "!!Non-Startable!! ";
            } else if (pcmk_is_set(action->flags, pe_action_processed)) {
               desc = "";
            } else {
               desc = "(Provisional) ";
            }
            crm_trace("%s%s%sAction %d: %s%s%s%s%s%s",
                      ((pre_text == NULL)? "" : pre_text),
                      ((pre_text == NULL)? "" : ": "),
                      desc, action->id, action->uuid,
                      (node_uname? "\ton " : ""), (node_uname? node_uname : ""),
                      (node_uuid? "\t\t(" : ""), (node_uuid? node_uuid : ""),
                      (node_uuid? ")" : ""));
            break;
        default:
            if (pcmk_is_set(action->flags, pe_action_optional)) {
                desc = "Optional ";
            } else if (pcmk_is_set(action->flags, pe_action_pseudo)) {
                desc = "Pseudo ";
            } else if (!pcmk_is_set(action->flags, pe_action_runnable)) {
                desc = "!!Non-Startable!! ";
            } else if (pcmk_is_set(action->flags, pe_action_processed)) {
               desc = "";
            } else {
               desc = "(Provisional) ";
            }
            crm_trace("%s%s%sAction %d: %s %s%s%s%s%s%s",
                      ((pre_text == NULL)? "" : pre_text),
                      ((pre_text == NULL)? "" : ": "),
                      desc, action->id, action->uuid,
                      (action->rsc? action->rsc->id : "<none>"),
                      (node_uname? "\ton " : ""), (node_uname? node_uname : ""),
                      (node_uuid? "\t\t(" : ""), (node_uuid? node_uuid : ""),
                      (node_uuid? ")" : ""));
            break;
    }

    if (details) {
        GList *gIter = NULL;

        crm_trace("\t\t====== Preceding Actions");

        gIter = action->actions_before;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) gIter->data;

            log_action(log_level + 1, "\t\t", other->action, FALSE);
        }

        crm_trace("\t\t====== Subsequent Actions");

        gIter = action->actions_after;
        for (; gIter != NULL; gIter = gIter->next) {
            pe_action_wrapper_t *other = (pe_action_wrapper_t *) gIter->data;

            log_action(log_level + 1, "\t\t", other->action, FALSE);
        }

        crm_trace("\t\t====== End");

    } else {
        crm_trace("\t\t(before=%d, after=%d)",
                  g_list_length(action->actions_before), g_list_length(action->actions_after));
    }
}

gboolean
can_run_any(GHashTable * nodes)
{
    GHashTableIter iter;
    pe_node_t *node = NULL;

    if (nodes == NULL) {
        return FALSE;
    }

    g_hash_table_iter_init(&iter, nodes);
    while (g_hash_table_iter_next(&iter, NULL, (void **)&node)) {
        if (can_run_resources(node) && node->weight >= 0) {
            return TRUE;
        }
    }

    return FALSE;
}

pe_action_t *
create_pseudo_resource_op(pe_resource_t * rsc, const char *task, bool optional, bool runnable, pe_working_set_t *data_set)
{
    pe_action_t *action = custom_action(rsc, pcmk__op_key(rsc->id, task, 0),
                                        task, NULL, optional, TRUE, data_set);

    pe__set_action_flags(action, pe_action_pseudo);
    if(runnable) {
        pe__set_action_flags(action, pe_action_runnable);
    }
    return action;
}

/*!
 * \internal
 * \brief Create an executor cancel op
 *
 * \param[in] rsc          Resource of action to cancel
 * \param[in] task         Name of action to cancel
 * \param[in] interval_ms  Interval of action to cancel
 * \param[in] node         Node of action to cancel
 * \param[in] data_set     Working set of cluster
 *
 * \return Created op
 */
pe_action_t *
pe_cancel_op(pe_resource_t *rsc, const char *task, guint interval_ms,
             pe_node_t *node, pe_working_set_t *data_set)
{
    pe_action_t *cancel_op;
    char *interval_ms_s = crm_strdup_printf("%u", interval_ms);

    // @TODO dangerous if possible to schedule another action with this key
    char *key = pcmk__op_key(rsc->id, task, interval_ms);

    cancel_op = custom_action(rsc, key, RSC_CANCEL, node, FALSE, TRUE,
                              data_set);

    free(cancel_op->task);
    cancel_op->task = strdup(RSC_CANCEL);

    free(cancel_op->cancel_task);
    cancel_op->cancel_task = strdup(task);

    add_hash_param(cancel_op->meta, XML_LRM_ATTR_TASK, task);
    add_hash_param(cancel_op->meta, XML_LRM_ATTR_INTERVAL_MS, interval_ms_s);
    free(interval_ms_s);

    return cancel_op;
}

/*!
 * \internal
 * \brief Create a shutdown op for a scheduler transition
 *
 * \param[in] node         Node being shut down
 * \param[in] data_set     Working set of cluster
 *
 * \return Created op
 */
pe_action_t *
sched_shutdown_op(pe_node_t *node, pe_working_set_t *data_set)
{
    char *shutdown_id = crm_strdup_printf("%s-%s", CRM_OP_SHUTDOWN,
                                          node->details->uname);

    pe_action_t *shutdown_op = custom_action(NULL, shutdown_id, CRM_OP_SHUTDOWN,
                                             node, FALSE, TRUE, data_set);

    pcmk__order_stops_before_shutdown(node, shutdown_op, data_set);
    add_hash_param(shutdown_op->meta, XML_ATTR_TE_NOWAIT, XML_BOOLEAN_TRUE);
    return shutdown_op;
}

static char *
generate_transition_magic(const char *transition_key, int op_status, int op_rc)
{
    CRM_CHECK(transition_key != NULL, return NULL);
    return crm_strdup_printf("%d:%d;%s", op_status, op_rc, transition_key);
}

static void
append_digest(lrmd_event_data_t *op, xmlNode *update, const char *version,
              const char *magic, int level)
{
    /* this will enable us to later determine that the
     *   resource's parameters have changed and we should force
     *   a restart
     */
    char *digest = NULL;
    xmlNode *args_xml = NULL;

    if (op->params == NULL) {
        return;
    }

    args_xml = create_xml_node(NULL, XML_TAG_PARAMS);
    g_hash_table_foreach(op->params, hash2field, args_xml);
    pcmk__filter_op_for_digest(args_xml);
    digest = calculate_operation_digest(args_xml, version);

#if 0
    if (level < get_crm_log_level()
        && op->interval_ms == 0 && pcmk__str_eq(op->op_type, CRMD_ACTION_START, pcmk__str_none)) {
        char *digest_source = dump_xml_unformatted(args_xml);

        do_crm_log(level, "Calculated digest %s for %s (%s). Source: %s\n",
                   digest, ID(update), magic, digest_source);
        free(digest_source);
    }
#endif
    crm_xml_add(update, XML_LRM_ATTR_OP_DIGEST, digest);

    free_xml(args_xml);
    free(digest);
}

#define FAKE_TE_ID     "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

/*!
 * \internal
 * \brief Create XML for resource operation history update
 *
 * \param[in,out] parent          Parent XML node to add to
 * \param[in,out] op              Operation event data
 * \param[in]     caller_version  DC feature set
 * \param[in]     target_rc       Expected result of operation
 * \param[in]     node            Name of node on which operation was performed
 * \param[in]     origin          Arbitrary description of update source
 * \param[in]     level           A log message will be logged at this level
 *
 * \return Newly created XML node for history update
 */
xmlNode *
pcmk__create_history_xml(xmlNode *parent, lrmd_event_data_t *op,
                         const char *caller_version, int target_rc,
                         const char *node, const char *origin, int level)
{
    char *key = NULL;
    char *magic = NULL;
    char *op_id = NULL;
    char *op_id_additional = NULL;
    char *local_user_data = NULL;
    const char *exit_reason = NULL;

    xmlNode *xml_op = NULL;
    const char *task = NULL;

    CRM_CHECK(op != NULL, return NULL);
    do_crm_log(level, "%s: Updating resource %s after %s op %s (interval=%u)",
               origin, op->rsc_id, op->op_type,
               pcmk_exec_status_str(op->op_status), op->interval_ms);

    crm_trace("DC version: %s", caller_version);

    task = op->op_type;

    /* Record a successful agent reload as a start, and a failed one as a
     * monitor, to make life easier for the scheduler when determining the
     * current state.
     *
     * @COMPAT We should check "reload" here only if the operation was for a
     * pre-OCF-1.1 resource agent, but we don't know that here, and we should
     * only ever get results for actions scheduled by us, so we can reasonably
     * assume any "reload" is actually a pre-1.1 agent reload.
     */
    if (pcmk__str_any_of(task, CRMD_ACTION_RELOAD, CRMD_ACTION_RELOAD_AGENT,
                         NULL)) {
        if (op->op_status == PCMK_EXEC_DONE) {
            task = CRMD_ACTION_START;
        } else {
            task = CRMD_ACTION_STATUS;
        }
    }

    key = pcmk__op_key(op->rsc_id, task, op->interval_ms);
    if (pcmk__str_eq(task, CRMD_ACTION_NOTIFY, pcmk__str_none)) {
        const char *n_type = crm_meta_value(op->params, "notify_type");
        const char *n_task = crm_meta_value(op->params, "notify_operation");

        CRM_LOG_ASSERT(n_type != NULL);
        CRM_LOG_ASSERT(n_task != NULL);
        op_id = pcmk__notify_key(op->rsc_id, n_type, n_task);

        if (op->op_status != PCMK_EXEC_PENDING) {
            /* Ignore notify errors.
             *
             * @TODO It might be better to keep the correct result here, and
             * ignore it in process_graph_event().
             */
            lrmd__set_result(op, PCMK_OCF_OK, PCMK_EXEC_DONE, NULL);
        }

    } else if (did_rsc_op_fail(op, target_rc)) {
        op_id = pcmk__op_key(op->rsc_id, "last_failure", 0);
        if (op->interval_ms == 0) {
            // Ensure 'last' gets updated, in case record-pending is true
            op_id_additional = pcmk__op_key(op->rsc_id, "last", 0);
        }
        exit_reason = op->exit_reason;

    } else if (op->interval_ms > 0) {
        op_id = strdup(key);

    } else {
        op_id = pcmk__op_key(op->rsc_id, "last", 0);
    }

  again:
    xml_op = pcmk__xe_match(parent, XML_LRM_TAG_RSC_OP, XML_ATTR_ID, op_id);
    if (xml_op == NULL) {
        xml_op = create_xml_node(parent, XML_LRM_TAG_RSC_OP);
    }

    if (op->user_data == NULL) {
        crm_debug("Generating fake transition key for: " PCMK__OP_FMT
                  " %d from %s", op->rsc_id, op->op_type, op->interval_ms,
                  op->call_id, origin);
        local_user_data = pcmk__transition_key(-1, op->call_id, target_rc,
                                               FAKE_TE_ID);
        op->user_data = local_user_data;
    }

    if(magic == NULL) {
        magic = generate_transition_magic(op->user_data, op->op_status, op->rc);
    }

    crm_xml_add(xml_op, XML_ATTR_ID, op_id);
    crm_xml_add(xml_op, XML_LRM_ATTR_TASK_KEY, key);
    crm_xml_add(xml_op, XML_LRM_ATTR_TASK, task);
    crm_xml_add(xml_op, XML_ATTR_ORIGIN, origin);
    crm_xml_add(xml_op, XML_ATTR_CRM_VERSION, caller_version);
    crm_xml_add(xml_op, XML_ATTR_TRANSITION_KEY, op->user_data);
    crm_xml_add(xml_op, XML_ATTR_TRANSITION_MAGIC, magic);
    crm_xml_add(xml_op, XML_LRM_ATTR_EXIT_REASON, exit_reason == NULL ? "" : exit_reason);
    crm_xml_add(xml_op, XML_LRM_ATTR_TARGET, node); /* For context during triage */

    crm_xml_add_int(xml_op, XML_LRM_ATTR_CALLID, op->call_id);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_RC, op->rc);
    crm_xml_add_int(xml_op, XML_LRM_ATTR_OPSTATUS, op->op_status);
    crm_xml_add_ms(xml_op, XML_LRM_ATTR_INTERVAL_MS, op->interval_ms);

    if (compare_version("2.1", caller_version) <= 0) {
        if (op->t_run || op->t_rcchange || op->exec_time || op->queue_time) {
            crm_trace("Timing data (" PCMK__OP_FMT
                      "): last=%u change=%u exec=%u queue=%u",
                      op->rsc_id, op->op_type, op->interval_ms,
                      op->t_run, op->t_rcchange, op->exec_time, op->queue_time);

            if ((op->interval_ms != 0) && (op->t_rcchange != 0)) {
                // Recurring ops may have changed rc after initial run
                crm_xml_add_ll(xml_op, XML_RSC_OP_LAST_CHANGE,
                               (long long) op->t_rcchange);
            } else {
                crm_xml_add_ll(xml_op, XML_RSC_OP_LAST_CHANGE,
                               (long long) op->t_run);
            }

            crm_xml_add_int(xml_op, XML_RSC_OP_T_EXEC, op->exec_time);
            crm_xml_add_int(xml_op, XML_RSC_OP_T_QUEUE, op->queue_time);
        }
    }

    if (pcmk__str_any_of(op->op_type, CRMD_ACTION_MIGRATE, CRMD_ACTION_MIGRATED, NULL)) {
        /*
         * Record migrate_source and migrate_target always for migrate ops.
         */
        const char *name = XML_LRM_ATTR_MIGRATE_SOURCE;

        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));

        name = XML_LRM_ATTR_MIGRATE_TARGET;
        crm_xml_add(xml_op, name, crm_meta_value(op->params, name));
    }

    append_digest(op, xml_op, caller_version, magic, LOG_DEBUG);

    if (op_id_additional) {
        free(op_id);
        op_id = op_id_additional;
        op_id_additional = NULL;
        goto again;
    }

    if (local_user_data) {
        free(local_user_data);
        op->user_data = NULL;
    }
    free(magic);
    free(op_id);
    free(key);
    return xml_op;
}

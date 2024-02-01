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
#include <crm/common/xml.h>

#include <glib.h>

#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

// Convenience macros for logging action properties

#define action_type_str(flags) \
    (pcmk_is_set((flags), pcmk_action_pseudo)? "pseudo-action" : "action")

#define action_optional_str(flags) \
    (pcmk_is_set((flags), pcmk_action_optional)? "optional" : "required")

#define action_runnable_str(flags) \
    (pcmk_is_set((flags), pcmk_action_runnable)? "runnable" : "unrunnable")

#define action_node_str(a) \
    (((a)->node == NULL)? "no node" : (a)->node->details->uname)

/*!
 * \internal
 * \brief Add an XML node tag for a specified ID
 *
 * \param[in]     id      Node UUID to add
 * \param[in,out] xml     Parent XML tag to add to
 */
static xmlNode*
add_node_to_xml_by_id(const char *id, xmlNode *xml)
{
    xmlNode *node_xml;

    node_xml = create_xml_node(xml, PCMK_XE_NODE);
    crm_xml_add(node_xml, PCMK_XA_ID, id);

    return node_xml;
}

/*!
 * \internal
 * \brief Add an XML node tag for a specified node
 *
 * \param[in]     node  Node to add
 * \param[in,out] xml   XML to add node to
 */
static void
add_node_to_xml(const pcmk_node_t *node, void *xml)
{
    add_node_to_xml_by_id(node->details->id, (xmlNode *) xml);
}

/*!
 * \internal
 * \brief Count (optionally add to XML) nodes needing maintenance state update
 *
 * \param[in,out] xml        Parent XML tag to add to, if any
 * \param[in]     scheduler  Scheduler data
 *
 * \return Count of nodes added
 * \note Only Pacemaker Remote nodes are considered currently
 */
static int
add_maintenance_nodes(xmlNode *xml, const pcmk_scheduler_t *scheduler)
{
    xmlNode *maintenance = NULL;
    int count = 0;

    if (xml != NULL) {
        maintenance = create_xml_node(xml, PCMK__XE_MAINTENANCE);
    }
    for (const GList *iter = scheduler->nodes;
         iter != NULL; iter = iter->next) {
        const pcmk_node_t *node = iter->data;

        if (pe__is_guest_or_remote_node(node) &&
            (node->details->maintenance != node->details->remote_maintenance)) {

            if (maintenance != NULL) {
                crm_xml_add(add_node_to_xml_by_id(node->details->id,
                                                  maintenance),
                            PCMK__XA_NODE_IN_MAINTENANCE,
                            (node->details->maintenance? "1" : "0"));
            }
            count++;
        }
    }
    crm_trace("%s %d nodes in need of maintenance mode update in state",
              ((maintenance == NULL)? "Counted" : "Added"), count);
    return count;
}

/*!
 * \internal
 * \brief Add pseudo action with nodes needing maintenance state update
 *
 * \param[in,out] scheduler  Scheduler data
 */
static void
add_maintenance_update(pcmk_scheduler_t *scheduler)
{
    pcmk_action_t *action = NULL;

    if (add_maintenance_nodes(NULL, scheduler) != 0) {
        action = get_pseudo_op(PCMK_ACTION_MAINTENANCE_NODES, scheduler);
        pcmk__set_action_flags(action, pcmk_action_always_in_graph);
    }
}

/*!
 * \internal
 * \brief Add XML with nodes that an action is expected to bring down
 *
 * If a specified action is expected to bring any nodes down, add an XML block
 * with their UUIDs. When a node is lost, this allows the controller to
 * determine whether it was expected.
 *
 * \param[in,out] xml       Parent XML tag to add to
 * \param[in]     action    Action to check for downed nodes
 */
static void
add_downed_nodes(xmlNode *xml, const pcmk_action_t *action)
{
    CRM_CHECK((xml != NULL) && (action != NULL) && (action->node != NULL),
              return);

    if (pcmk__str_eq(action->task, PCMK_ACTION_DO_SHUTDOWN, pcmk__str_none)) {

        /* Shutdown makes the action's node down */
        xmlNode *downed = create_xml_node(xml, PCMK__XE_DOWNED);
        add_node_to_xml_by_id(action->node->details->id, downed);

    } else if (pcmk__str_eq(action->task, PCMK_ACTION_STONITH,
                            pcmk__str_none)) {

        /* Fencing makes the action's node and any hosted guest nodes down */
        const char *fence = g_hash_table_lookup(action->meta,
                                                PCMK__META_STONITH_ACTION);

        if (pcmk__is_fencing_action(fence)) {
            xmlNode *downed = create_xml_node(xml, PCMK__XE_DOWNED);
            add_node_to_xml_by_id(action->node->details->id, downed);
            pe_foreach_guest_node(action->node->details->data_set,
                                  action->node, add_node_to_xml, downed);
        }

    } else if (action->rsc && action->rsc->is_remote_node
               && pcmk__str_eq(action->task, PCMK_ACTION_STOP,
                               pcmk__str_none)) {

        /* Stopping a remote connection resource makes connected node down,
         * unless it's part of a migration
         */
        GList *iter;
        pcmk_action_t *input;
        bool migrating = false;

        for (iter = action->actions_before; iter != NULL; iter = iter->next) {
            input = ((pcmk__related_action_t *) iter->data)->action;
            if ((input->rsc != NULL)
                && pcmk__str_eq(action->rsc->id, input->rsc->id, pcmk__str_none)
                && pcmk__str_eq(input->task, PCMK_ACTION_MIGRATE_FROM,
                                pcmk__str_none)) {
                migrating = true;
                break;
            }
        }
        if (!migrating) {
            xmlNode *downed = create_xml_node(xml, PCMK__XE_DOWNED);
            add_node_to_xml_by_id(action->rsc->id, downed);
        }
    }
}

/*!
 * \internal
 * \brief Create a transition graph operation key for a clone action
 *
 * \param[in] action       Clone action
 * \param[in] interval_ms  Action interval in milliseconds
 *
 * \return Newly allocated string with transition graph operation key
 */
static char *
clone_op_key(const pcmk_action_t *action, guint interval_ms)
{
    if (pcmk__str_eq(action->task, PCMK_ACTION_NOTIFY, pcmk__str_none)) {
        const char *n_type = g_hash_table_lookup(action->meta, "notify_type");
        const char *n_task = g_hash_table_lookup(action->meta,
                                                 "notify_operation");

        CRM_LOG_ASSERT((n_type != NULL) && (n_task != NULL));
        return pcmk__notify_key(action->rsc->clone_name, n_type, n_task);

    } else if (action->cancel_task != NULL) {
        return pcmk__op_key(action->rsc->clone_name, action->cancel_task,
                            interval_ms);
    } else {
        return pcmk__op_key(action->rsc->clone_name, action->task, interval_ms);
    }
}

/*!
 * \internal
 * \brief Add node details to transition graph action XML
 *
 * \param[in]     action  Scheduled action
 * \param[in,out] xml     Transition graph action XML for \p action
 */
static void
add_node_details(const pcmk_action_t *action, xmlNode *xml)
{
    pcmk_node_t *router_node = pcmk__connection_host_for_action(action);

    crm_xml_add(xml, PCMK__META_ON_NODE, action->node->details->uname);
    crm_xml_add(xml, PCMK__META_ON_NODE_UUID, action->node->details->id);
    if (router_node != NULL) {
        crm_xml_add(xml, PCMK__XA_ROUTER_NODE, router_node->details->uname);
    }
}

/*!
 * \internal
 * \brief Add resource details to transition graph action XML
 *
 * \param[in]     action      Scheduled action
 * \param[in,out] action_xml  Transition graph action XML for \p action
 */
static void
add_resource_details(const pcmk_action_t *action, xmlNode *action_xml)
{
    xmlNode *rsc_xml = NULL;
    const char *attr_list[] = {
        PCMK_XA_CLASS,
        PCMK_XA_PROVIDER,
        PCMK_XA_TYPE,
    };

    /* If a resource is locked to a node via PCMK_OPT_SHUTDOWN_LOCK, mark its
     * actions so the controller can preserve the lock when the action
     * completes.
     */
    if (pcmk__action_locks_rsc_to_node(action)) {
        crm_xml_add_ll(action_xml, PCMK_OPT_SHUTDOWN_LOCK,
                       (long long) action->rsc->lock_time);
    }

    // List affected resource

    rsc_xml = create_xml_node(action_xml,
                              (const char *) action->rsc->xml->name);
    if (pcmk_is_set(action->rsc->flags, pcmk_rsc_removed)
        && (action->rsc->clone_name != NULL)) {
        /* Use the numbered instance name here, because if there is more
         * than one instance on a node, we need to make sure the command
         * goes to the right one.
         *
         * This is important even for anonymous clones, because the clone's
         * unique meta-attribute might have just been toggled from on to
         * off.
         */
        crm_debug("Using orphan clone name %s instead of %s",
                  action->rsc->id, action->rsc->clone_name);
        crm_xml_add(rsc_xml, PCMK_XA_ID, action->rsc->clone_name);
        crm_xml_add(rsc_xml, PCMK__XA_LONG_ID, action->rsc->id);

    } else if (!pcmk_is_set(action->rsc->flags, pcmk_rsc_unique)) {
        const char *xml_id = pcmk__xe_id(action->rsc->xml);

        crm_debug("Using anonymous clone name %s for %s (aka %s)",
                  xml_id, action->rsc->id, action->rsc->clone_name);

        /* ID is what we'd like client to use
         * LONG_ID is what they might know it as instead
         *
         * LONG_ID is only strictly needed /here/ during the
         * transition period until all nodes in the cluster
         * are running the new software /and/ have rebooted
         * once (meaning that they've only ever spoken to a DC
         * supporting this feature).
         *
         * If anyone toggles the unique flag to 'on', the
         * 'instance free' name will correspond to an orphan
         * and fall into the clause above instead
         */
        crm_xml_add(rsc_xml, PCMK_XA_ID, xml_id);
        if ((action->rsc->clone_name != NULL)
            && !pcmk__str_eq(xml_id, action->rsc->clone_name,
                             pcmk__str_none)) {
            crm_xml_add(rsc_xml, PCMK__XA_LONG_ID, action->rsc->clone_name);
        } else {
            crm_xml_add(rsc_xml, PCMK__XA_LONG_ID, action->rsc->id);
        }

    } else {
        CRM_ASSERT(action->rsc->clone_name == NULL);
        crm_xml_add(rsc_xml, PCMK_XA_ID, action->rsc->id);
    }

    for (int lpc = 0; lpc < PCMK__NELEM(attr_list); lpc++) {
        crm_xml_add(rsc_xml, attr_list[lpc],
                    g_hash_table_lookup(action->rsc->meta, attr_list[lpc]));
    }
}

/*!
 * \internal
 * \brief Add action attributes to transition graph action XML
 *
 * \param[in,out] action      Scheduled action
 * \param[in,out] action_xml  Transition graph action XML for \p action
 */
static void
add_action_attributes(pcmk_action_t *action, xmlNode *action_xml)
{
    xmlNode *args_xml = NULL;

    /* We create free-standing XML to start, so we can sort the attributes
     * before adding it to action_xml, which keeps the scheduler regression
     * test graphs comparable.
     */
    args_xml = create_xml_node(NULL, PCMK__XE_ATTRIBUTES);

    crm_xml_add(args_xml, PCMK_XA_CRM_FEATURE_SET, CRM_FEATURE_SET);
    g_hash_table_foreach(action->extra, hash2field, args_xml);

    if ((action->rsc != NULL) && (action->node != NULL)) {
        // Get the resource instance attributes, evaluated properly for node
        GHashTable *params = pe_rsc_params(action->rsc, action->node,
                                           action->rsc->cluster);

        pcmk__substitute_remote_addr(action->rsc, params);

        g_hash_table_foreach(params, hash2smartfield, args_xml);

    } else if ((action->rsc != NULL)
               && (action->rsc->variant <= pcmk_rsc_variant_primitive)) {
        GHashTable *params = pe_rsc_params(action->rsc, NULL,
                                           action->rsc->cluster);

        g_hash_table_foreach(params, hash2smartfield, args_xml);
    }

    g_hash_table_foreach(action->meta, hash2metafield, args_xml);
    if (action->rsc != NULL) {
        pcmk_resource_t *parent = action->rsc;

        while (parent != NULL) {
            parent->cmds->add_graph_meta(parent, args_xml);
            parent = parent->parent;
        }

        pcmk__add_guest_meta_to_xml(args_xml, action);

    } else if (pcmk__str_eq(action->task, PCMK_ACTION_STONITH, pcmk__str_none)
               && (action->node != NULL)) {
        /* Pass the node's attributes as meta-attributes.
         *
         * @TODO: Determine whether it is still necessary to do this. It was
         * added in 33d99707, probably for the libfence-based implementation in
         * c9a90bd, which is no longer used.
         */
        g_hash_table_foreach(action->node->details->attrs, hash2metafield,
                             args_xml);
    }

    sorted_xml(args_xml, action_xml, FALSE);
    free_xml(args_xml);
}

/*!
 * \internal
 * \brief Create the transition graph XML for a scheduled action
 *
 * \param[in,out] parent        Parent XML element to add action to
 * \param[in,out] action        Scheduled action
 * \param[in]     skip_details  If false, add action details as sub-elements
 * \param[in]     scheduler     Scheduler data
 */
static void
create_graph_action(xmlNode *parent, pcmk_action_t *action, bool skip_details,
                    const pcmk_scheduler_t *scheduler)
{
    bool needs_node_info = true;
    bool needs_maintenance_info = false;
    xmlNode *action_xml = NULL;

    if ((action == NULL) || (scheduler == NULL)) {
        return;
    }

    // Create the top-level element based on task

    if (pcmk__str_eq(action->task, PCMK_ACTION_STONITH, pcmk__str_none)) {
        /* All fences need node info; guest node fences are pseudo-events */
        if (pcmk_is_set(action->flags, pcmk_action_pseudo)) {
            action_xml = create_xml_node(parent, PCMK__XE_PSEUDO_EVENT);
        } else {
            action_xml = create_xml_node(parent, PCMK__XE_CRM_EVENT);
        }

    } else if (pcmk__str_any_of(action->task,
                                PCMK_ACTION_DO_SHUTDOWN,
                                PCMK_ACTION_CLEAR_FAILCOUNT, NULL)) {
        action_xml = create_xml_node(parent, PCMK__XE_CRM_EVENT);

    } else if (pcmk__str_eq(action->task, PCMK_ACTION_LRM_DELETE,
                            pcmk__str_none)) {
        // CIB-only clean-up for shutdown locks
        action_xml = create_xml_node(parent, PCMK__XE_CRM_EVENT);
        crm_xml_add(action_xml, PCMK__XA_MODE, PCMK__VALUE_CIB);

    } else if (pcmk_is_set(action->flags, pcmk_action_pseudo)) {
        if (pcmk__str_eq(action->task, PCMK_ACTION_MAINTENANCE_NODES,
                         pcmk__str_none)) {
            needs_maintenance_info = true;
        }
        action_xml = create_xml_node(parent, PCMK__XE_PSEUDO_EVENT);
        needs_node_info = false;

    } else {
        action_xml = create_xml_node(parent, PCMK__XE_RSC_OP);
    }

    crm_xml_add_int(action_xml, PCMK_XA_ID, action->id);
    crm_xml_add(action_xml, PCMK_XA_OPERATION, action->task);

    if ((action->rsc != NULL) && (action->rsc->clone_name != NULL)) {
        char *clone_key = NULL;
        guint interval_ms;

        if (pcmk__guint_from_hash(action->meta, PCMK_META_INTERVAL, 0,
                                  &interval_ms) != pcmk_rc_ok) {
            interval_ms = 0;
        }
        clone_key = clone_op_key(action, interval_ms);
        crm_xml_add(action_xml, PCMK__XA_OPERATION_KEY, clone_key);
        crm_xml_add(action_xml, "internal_" PCMK__XA_OPERATION_KEY,
                    action->uuid);
        free(clone_key);
    } else {
        crm_xml_add(action_xml, PCMK__XA_OPERATION_KEY, action->uuid);
    }

    if (needs_node_info && (action->node != NULL)) {
        add_node_details(action, action_xml);
        pcmk__insert_dup(action->meta, PCMK__META_ON_NODE,
                         action->node->details->uname);
        pcmk__insert_dup(action->meta, PCMK__META_ON_NODE_UUID,
                         action->node->details->id);
    }

    if (skip_details) {
        return;
    }

    if ((action->rsc != NULL)
        && !pcmk_is_set(action->flags, pcmk_action_pseudo)) {

        // This is a real resource action, so add resource details
        add_resource_details(action, action_xml);
    }

    /* List any attributes in effect */
    add_action_attributes(action, action_xml);

    /* List any nodes this action is expected to make down */
    if (needs_node_info && (action->node != NULL)) {
        add_downed_nodes(action_xml, action);
    }

    if (needs_maintenance_info) {
        add_maintenance_nodes(action_xml, scheduler);
    }
}

/*!
 * \internal
 * \brief Check whether an action should be added to the transition graph
 *
 * \param[in] action  Action to check
 *
 * \return true if action should be added to graph, otherwise false
 */
static bool
should_add_action_to_graph(const pcmk_action_t *action)
{
    if (!pcmk_is_set(action->flags, pcmk_action_runnable)) {
        crm_trace("Ignoring action %s (%d): unrunnable",
                  action->uuid, action->id);
        return false;
    }

    if (pcmk_is_set(action->flags, pcmk_action_optional)
        && !pcmk_is_set(action->flags, pcmk_action_always_in_graph)) {
        crm_trace("Ignoring action %s (%d): optional",
                  action->uuid, action->id);
        return false;
    }

    /* Actions for unmanaged resources should be excluded from the graph,
     * with the exception of monitors and cancellation of recurring monitors.
     */
    if ((action->rsc != NULL)
        && !pcmk_is_set(action->rsc->flags, pcmk_rsc_managed)
        && !pcmk__str_eq(action->task, PCMK_ACTION_MONITOR, pcmk__str_none)) {

        const char *interval_ms_s;

        /* A cancellation of a recurring monitor will get here because the task
         * is cancel rather than monitor, but the interval can still be used to
         * recognize it. The interval has been normalized to milliseconds by
         * this point, so a string comparison is sufficient.
         */
        interval_ms_s = g_hash_table_lookup(action->meta, PCMK_META_INTERVAL);
        if (pcmk__str_eq(interval_ms_s, "0", pcmk__str_null_matches)) {
            crm_trace("Ignoring action %s (%d): for unmanaged resource (%s)",
                      action->uuid, action->id, action->rsc->id);
            return false;
        }
    }

    /* Always add pseudo-actions, fence actions, and shutdown actions (already
     * determined to be required and runnable by this point)
     */
    if (pcmk_is_set(action->flags, pcmk_action_pseudo)
        || pcmk__strcase_any_of(action->task, PCMK_ACTION_STONITH,
                                PCMK_ACTION_DO_SHUTDOWN, NULL)) {
        return true;
    }

    if (action->node == NULL) {
        pcmk__sched_err("Skipping action %s (%d) "
                        "because it was not assigned to a node (bug?)",
                        action->uuid, action->id);
        pcmk__log_action("Unassigned", action, false);
        return false;
    }

    if (pcmk_is_set(action->flags, pcmk_action_on_dc)) {
        crm_trace("Action %s (%d) should be dumped: "
                  "can run on DC instead of %s",
                  action->uuid, action->id, pcmk__node_name(action->node));

    } else if (pcmk__is_guest_or_bundle_node(action->node)
               && !action->node->details->remote_requires_reset) {
        crm_trace("Action %s (%d) should be dumped: "
                  "assuming will be runnable on guest %s",
                  action->uuid, action->id, pcmk__node_name(action->node));

    } else if (!action->node->details->online) {
        pcmk__sched_err("Skipping action %s (%d) "
                        "because it was scheduled for offline node (bug?)",
                        action->uuid, action->id);
        pcmk__log_action("Offline node", action, false);
        return false;

    } else if (action->node->details->unclean) {
        pcmk__sched_err("Skipping action %s (%d) "
                        "because it was scheduled for unclean node (bug?)",
                        action->uuid, action->id);
        pcmk__log_action("Unclean node", action, false);
        return false;
    }
    return true;
}

/*!
 * \internal
 * \brief Check whether an ordering's flags can change an action
 *
 * \param[in] ordering  Ordering to check
 *
 * \return true if ordering has flags that can change an action, false otherwise
 */
static bool
ordering_can_change_actions(const pcmk__related_action_t *ordering)
{
    return pcmk_any_flags_set(ordering->type,
                              ~(pcmk__ar_then_implies_first_graphed
                                |pcmk__ar_first_implies_then_graphed
                                |pcmk__ar_ordered));
}

/*!
 * \internal
 * \brief Check whether an action input should be in the transition graph
 *
 * \param[in]     action  Action to check
 * \param[in,out] input   Action input to check
 *
 * \return true if input should be in graph, false otherwise
 * \note This function may not only check an input, but disable it under certian
 *       circumstances (load or anti-colocation orderings that are not needed).
 */
static bool
should_add_input_to_graph(const pcmk_action_t *action,
                          pcmk__related_action_t *input)
{
    if (input->state == pe_link_dumped) {
        return true;
    }

    if ((uint32_t) input->type == pcmk__ar_none) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "ordering disabled",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (!pcmk_is_set(input->action->flags, pcmk_action_runnable)
               && !ordering_can_change_actions(input)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "optional and input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (!pcmk_is_set(input->action->flags, pcmk_action_runnable)
               && pcmk_is_set(input->type, pcmk__ar_min_runnable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "minimum number of instances required but input unrunnable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (pcmk_is_set(input->type, pcmk__ar_unmigratable_then_blocks)
               && !pcmk_is_set(input->action->flags, pcmk_action_runnable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "input blocked if 'then' unmigratable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (pcmk_is_set(input->type, pcmk__ar_if_first_unmigratable)
               && pcmk_is_set(input->action->flags, pcmk_action_migratable)) {
        crm_trace("Ignoring %s (%d) input %s (%d): ordering applies "
                  "only if input is unmigratable, but it is migratable",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if (((uint32_t) input->type == pcmk__ar_ordered)
               && pcmk_is_set(input->action->flags, pcmk_action_migratable)
               && pcmk__ends_with(input->action->uuid, "_stop_0")) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "optional but stop in migration",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;

    } else if ((uint32_t) input->type == pcmk__ar_if_on_same_node_or_target) {
        pcmk_node_t *input_node = input->action->node;

        if ((action->rsc != NULL)
            && pcmk__str_eq(action->task, PCMK_ACTION_MIGRATE_TO,
                            pcmk__str_none)) {

            pcmk_node_t *assigned = action->rsc->allocated_to;

            /* For load_stopped -> migrate_to orderings, we care about where
             * the resource has been assigned, not where migrate_to will be
             * executed.
             */
            if (!pcmk__same_node(input_node, assigned)) {
                crm_trace("Ignoring %s (%d) input %s (%d): "
                          "migration target %s is not same as input node %s",
                          action->uuid, action->id,
                          input->action->uuid, input->action->id,
                          (assigned? assigned->details->uname : "<none>"),
                          (input_node? input_node->details->uname : "<none>"));
                input->type = (enum pe_ordering) pcmk__ar_none;
                return false;
            }

        } else if (!pcmk__same_node(input_node, action->node)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "not on same node (%s vs %s)",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id,
                      (action->node? action->node->details->uname : "<none>"),
                      (input_node? input_node->details->uname : "<none>"));
            input->type = (enum pe_ordering) pcmk__ar_none;
            return false;

        } else if (pcmk_is_set(input->action->flags, pcmk_action_optional)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "ordering optional",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id);
            input->type = (enum pe_ordering) pcmk__ar_none;
            return false;
        }

    } else if ((uint32_t) input->type == pcmk__ar_if_required_on_same_node) {
        if (input->action->node && action->node
            && !pcmk__same_node(input->action->node, action->node)) {
            crm_trace("Ignoring %s (%d) input %s (%d): "
                      "not on same node (%s vs %s)",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id,
                      pcmk__node_name(action->node),
                      pcmk__node_name(input->action->node));
            input->type = (enum pe_ordering) pcmk__ar_none;
            return false;

        } else if (pcmk_is_set(input->action->flags, pcmk_action_optional)) {
            crm_trace("Ignoring %s (%d) input %s (%d): optional",
                      action->uuid, action->id,
                      input->action->uuid, input->action->id);
            input->type = (enum pe_ordering) pcmk__ar_none;
            return false;
        }

    } else if (input->action->rsc
               && input->action->rsc != action->rsc
               && pcmk_is_set(input->action->rsc->flags, pcmk_rsc_failed)
               && !pcmk_is_set(input->action->rsc->flags, pcmk_rsc_managed)
               && pcmk__ends_with(input->action->uuid, "_stop_0")
               && pcmk__is_clone(action->rsc)) {
        crm_warn("Ignoring requirement that %s complete before %s:"
                 " unmanaged failed resources cannot prevent clone shutdown",
                 input->action->uuid, action->uuid);
        return false;

    } else if (pcmk_is_set(input->action->flags, pcmk_action_optional)
               && !pcmk_any_flags_set(input->action->flags,
                                      pcmk_action_always_in_graph
                                      |pcmk_action_added_to_graph)
               && !should_add_action_to_graph(input->action)) {
        crm_trace("Ignoring %s (%d) input %s (%d): "
                  "input optional",
                  action->uuid, action->id,
                  input->action->uuid, input->action->id);
        return false;
    }

    crm_trace("%s (%d) input %s %s (%d) on %s should be dumped: %s %s %#.6x",
              action->uuid, action->id, action_type_str(input->action->flags),
              input->action->uuid, input->action->id,
              action_node_str(input->action),
              action_runnable_str(input->action->flags),
              action_optional_str(input->action->flags), input->type);
    return true;
}

/*!
 * \internal
 * \brief Check whether an ordering creates an ordering loop
 *
 * \param[in]     init_action  "First" action in ordering
 * \param[in]     action       Callers should always set this the same as
 *                             \p init_action (this function may use a different
 *                             value for recursive calls)
 * \param[in,out] input        Action wrapper for "then" action in ordering
 *
 * \return true if the ordering creates a loop, otherwise false
 */
bool
pcmk__graph_has_loop(const pcmk_action_t *init_action,
                     const pcmk_action_t *action, pcmk__related_action_t *input)
{
    bool has_loop = false;

    if (pcmk_is_set(input->action->flags, pcmk_action_detect_loop)) {
        crm_trace("Breaking tracking loop: %s@%s -> %s@%s (%#.6x)",
                  input->action->uuid,
                  input->action->node? input->action->node->details->uname : "",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  input->type);
        return false;
    }

    // Don't need to check inputs that won't be used
    if (!should_add_input_to_graph(action, input)) {
        return false;
    }

    if (input->action == init_action) {
        crm_debug("Input loop found in %s@%s ->...-> %s@%s",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  init_action->uuid,
                  init_action->node? init_action->node->details->uname : "");
        return true;
    }

    pcmk__set_action_flags(input->action, pcmk_action_detect_loop);

    crm_trace("Checking inputs of action %s@%s input %s@%s (%#.6x)"
              "for graph loop with %s@%s ",
              action->uuid,
              action->node? action->node->details->uname : "",
              input->action->uuid,
              input->action->node? input->action->node->details->uname : "",
              input->type,
              init_action->uuid,
              init_action->node? init_action->node->details->uname : "");

    // Recursively check input itself for loops
    for (GList *iter = input->action->actions_before;
         iter != NULL; iter = iter->next) {

        if (pcmk__graph_has_loop(init_action, input->action,
                                 (pcmk__related_action_t *) iter->data)) {
            // Recursive call already logged a debug message
            has_loop = true;
            break;
        }
    }

    pcmk__clear_action_flags(input->action, pcmk_action_detect_loop);

    if (!has_loop) {
        crm_trace("No input loop found in %s@%s -> %s@%s (%#.6x)",
                  input->action->uuid,
                  input->action->node? input->action->node->details->uname : "",
                  action->uuid,
                  action->node? action->node->details->uname : "",
                  input->type);
    }
    return has_loop;
}

/*!
 * \internal
 * \brief Create a synapse XML element for a transition graph
 *
 * \param[in]     action     Action that synapse is for
 * \param[in,out] scheduler  Scheduler data containing graph
 *
 * \return Newly added XML element for new graph synapse
 */
static xmlNode *
create_graph_synapse(const pcmk_action_t *action, pcmk_scheduler_t *scheduler)
{
    int synapse_priority = 0;
    xmlNode *syn = create_xml_node(scheduler->graph, "synapse");

    crm_xml_add_int(syn, PCMK_XA_ID, scheduler->num_synapse);
    scheduler->num_synapse++;

    if (action->rsc != NULL) {
        synapse_priority = action->rsc->priority;
    }
    if (action->priority > synapse_priority) {
        synapse_priority = action->priority;
    }
    if (synapse_priority > 0) {
        crm_xml_add_int(syn, PCMK__XA_PRIORITY, synapse_priority);
    }
    return syn;
}

/*!
 * \internal
 * \brief Add an action to the transition graph XML if appropriate
 *
 * \param[in,out] data       Action to possibly add
 * \param[in,out] user_data  Scheduler data
 *
 * \note This will de-duplicate the action inputs, meaning that the
 *       pcmk__related_action_t:type flags can no longer be relied on to retain
 *       their original settings. That means this MUST be called after
 *       pcmk__apply_orderings() is complete, and nothing after this should rely
 *       on those type flags. (For example, some code looks for type equal to
 *       some flag rather than whether the flag is set, and some code looks for
 *       particular combinations of flags -- such code must be done before
 *       pcmk__create_graph().)
 */
static void
add_action_to_graph(gpointer data, gpointer user_data)
{
    pcmk_action_t *action = (pcmk_action_t *) data;
    pcmk_scheduler_t *scheduler = (pcmk_scheduler_t *) user_data;

    xmlNode *syn = NULL;
    xmlNode *set = NULL;
    xmlNode *in = NULL;

    /* If we haven't already, de-duplicate inputs (even if we won't be adding
     * the action to the graph, so that crm_simulate's dot graphs don't have
     * duplicates).
     */
    if (!pcmk_is_set(action->flags, pcmk_action_inputs_deduplicated)) {
        pcmk__deduplicate_action_inputs(action);
        pcmk__set_action_flags(action, pcmk_action_inputs_deduplicated);
    }

    if (pcmk_is_set(action->flags, pcmk_action_added_to_graph)
        || !should_add_action_to_graph(action)) {
        return; // Already added, or shouldn't be
    }
    pcmk__set_action_flags(action, pcmk_action_added_to_graph);

    crm_trace("Adding action %d (%s%s%s) to graph",
              action->id, action->uuid,
              ((action->node == NULL)? "" : " on "),
              ((action->node == NULL)? "" : action->node->details->uname));

    syn = create_graph_synapse(action, scheduler);
    set = create_xml_node(syn, "action_set");
    in = create_xml_node(syn, "inputs");

    create_graph_action(set, action, false, scheduler);

    for (GList *lpc = action->actions_before; lpc != NULL; lpc = lpc->next) {
        pcmk__related_action_t *input = lpc->data;

        if (should_add_input_to_graph(action, input)) {
            xmlNode *input_xml = create_xml_node(in, "trigger");

            input->state = pe_link_dumped;
            create_graph_action(input_xml, input->action, true, scheduler);
        }
    }
}

static int transition_id = -1;

/*!
 * \internal
 * \brief Log a message after calculating a transition
 *
 * \param[in] filename  Where transition input is stored
 */
void
pcmk__log_transition_summary(const char *filename)
{
    if (was_processing_error || crm_config_error) {
        crm_err("Calculated transition %d (with errors)%s%s",
                transition_id,
                (filename == NULL)? "" : ", saving inputs in ",
                (filename == NULL)? "" : filename);

    } else if (was_processing_warning || crm_config_warning) {
        crm_warn("Calculated transition %d (with warnings)%s%s",
                 transition_id,
                 (filename == NULL)? "" : ", saving inputs in ",
                 (filename == NULL)? "" : filename);

    } else {
        crm_notice("Calculated transition %d%s%s",
                   transition_id,
                   (filename == NULL)? "" : ", saving inputs in ",
                   (filename == NULL)? "" : filename);
    }
    if (crm_config_error) {
        crm_notice("Configuration errors found during scheduler processing,"
                   "  please run \"crm_verify -L\" to identify issues");
    }
}

/*!
 * \internal
 * \brief Add a resource's actions to the transition graph
 *
 * \param[in,out] rsc  Resource whose actions should be added
 */
void
pcmk__add_rsc_actions_to_graph(pcmk_resource_t *rsc)
{
    GList *iter = NULL;

    CRM_ASSERT(rsc != NULL);
    pcmk__rsc_trace(rsc, "Adding actions for %s to graph", rsc->id);

    // First add the resource's own actions
    g_list_foreach(rsc->actions, add_action_to_graph, rsc->cluster);

    // Then recursively add its children's actions (appropriate to variant)
    for (iter = rsc->children; iter != NULL; iter = iter->next) {
        pcmk_resource_t *child_rsc = (pcmk_resource_t *) iter->data;

        child_rsc->cmds->add_actions_to_graph(child_rsc);
    }
}

/*!
 * \internal
 * \brief Create a transition graph with all cluster actions needed
 *
 * \param[in,out] scheduler  Scheduler data
 */
void
pcmk__create_graph(pcmk_scheduler_t *scheduler)
{
    GList *iter = NULL;
    const char *value = NULL;
    long long limit = 0LL;
    GHashTable *config_hash = scheduler->config_hash;

    transition_id++;
    crm_trace("Creating transition graph %d", transition_id);

    scheduler->graph = create_xml_node(NULL, PCMK__XE_TRANSITION_GRAPH);

    value = pcmk__cluster_option(config_hash, PCMK_OPT_CLUSTER_DELAY);
    crm_xml_add(scheduler->graph, PCMK_OPT_CLUSTER_DELAY, value);

    value = pcmk__cluster_option(config_hash, PCMK_OPT_STONITH_TIMEOUT);
    crm_xml_add(scheduler->graph, PCMK_OPT_STONITH_TIMEOUT, value);

    crm_xml_add(scheduler->graph, "failed-stop-offset", "INFINITY");

    if (pcmk_is_set(scheduler->flags, pcmk_sched_start_failure_fatal)) {
        crm_xml_add(scheduler->graph, "failed-start-offset", "INFINITY");
    } else {
        crm_xml_add(scheduler->graph, "failed-start-offset", "1");
    }

    value = pcmk__cluster_option(config_hash, PCMK_OPT_BATCH_LIMIT);
    crm_xml_add(scheduler->graph, PCMK_OPT_BATCH_LIMIT, value);

    crm_xml_add_int(scheduler->graph, "transition_id", transition_id);

    value = pcmk__cluster_option(config_hash, PCMK_OPT_MIGRATION_LIMIT);
    if ((pcmk__scan_ll(value, &limit, 0LL) == pcmk_rc_ok) && (limit > 0)) {
        crm_xml_add(scheduler->graph, PCMK_OPT_MIGRATION_LIMIT, value);
    }

    if (scheduler->recheck_by > 0) {
        char *recheck_epoch = NULL;

        recheck_epoch = crm_strdup_printf("%llu",
                                          (long long) scheduler->recheck_by);
        crm_xml_add(scheduler->graph, "recheck-by", recheck_epoch);
        free(recheck_epoch);
    }

    /* The following code will de-duplicate action inputs, so nothing past this
     * should rely on the action input type flags retaining their original
     * values.
     */

    // Add resource actions to graph
    for (iter = scheduler->resources; iter != NULL; iter = iter->next) {
        pcmk_resource_t *rsc = (pcmk_resource_t *) iter->data;

        pcmk__rsc_trace(rsc, "Processing actions for %s", rsc->id);
        rsc->cmds->add_actions_to_graph(rsc);
    }

    // Add pseudo-action for list of nodes with maintenance state update
    add_maintenance_update(scheduler);

    // Add non-resource (node) actions
    for (iter = scheduler->actions; iter != NULL; iter = iter->next) {
        pcmk_action_t *action = (pcmk_action_t *) iter->data;

        if ((action->rsc != NULL)
            && (action->node != NULL)
            && action->node->details->shutdown
            && !pcmk_is_set(action->rsc->flags, pcmk_rsc_maintenance)
            && !pcmk_any_flags_set(action->flags,
                                   pcmk_action_optional|pcmk_action_runnable)
            && pcmk__str_eq(action->task, PCMK_ACTION_STOP, pcmk__str_none)) {
            /* Eventually we should just ignore the 'fence' case, but for now
             * it's the best way to detect (in CTS) when CIB resource updates
             * are being lost.
             */
            if (pcmk_is_set(scheduler->flags, pcmk_sched_quorate)
                || (scheduler->no_quorum_policy == pcmk_no_quorum_ignore)) {
                const bool managed = pcmk_is_set(action->rsc->flags,
                                                 pcmk_rsc_managed);
                const bool failed = pcmk_is_set(action->rsc->flags,
                                                pcmk_rsc_failed);

                crm_crit("Cannot %s %s because of %s:%s%s (%s)",
                         action->node->details->unclean? "fence" : "shut down",
                         pcmk__node_name(action->node), action->rsc->id,
                         (managed? " blocked" : " unmanaged"),
                         (failed? " failed" : ""), action->uuid);
            }
        }

        add_action_to_graph((gpointer) action, (gpointer) scheduler);
    }

    crm_log_xml_trace(scheduler->graph, "graph");
}

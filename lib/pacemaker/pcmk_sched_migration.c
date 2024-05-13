/*
 * Copyright 2004-2024 the Pacemaker project contributors
 *
 * The version control history for this file may have further details.
 *
 * This source code is licensed under the GNU General Public License version 2
 * or later (GPLv2+) WITHOUT ANY WARRANTY.
 */

#include <crm_internal.h>

#include <stdbool.h>

#include <crm/common/xml.h>
#include <pacemaker-internal.h>

#include "libpacemaker_private.h"

/*!
 * \internal
 * \brief Add migration source and target meta-attributes to an action
 *
 * \param[in,out] action  Action to add meta-attributes to
 * \param[in]     source  Node to add as migration source
 * \param[in]     target  Node to add as migration target
 */
static void
add_migration_meta(pcmk_action_t *action, const pcmk_node_t *source,
                   const pcmk_node_t *target)
{
    pcmk__insert_meta(action, PCMK__META_MIGRATE_SOURCE,
                      source->details->uname);

    pcmk__insert_meta(action, PCMK__META_MIGRATE_TARGET,
                      target->details->uname);
}

/*!
 * \internal
 * \brief Create internal migration actions for a migrateable resource
 *
 * \param[in,out] rsc      Resource to create migration actions for
 * \param[in]     current  Node that resource is originally active on
 */
void
pcmk__create_migration_actions(pcmk_resource_t *rsc, const pcmk_node_t *current)
{
    pcmk_action_t *migrate_to = NULL;
    pcmk_action_t *migrate_from = NULL;
    pcmk_action_t *start = NULL;
    pcmk_action_t *stop = NULL;

    pcmk__rsc_trace(rsc, "Creating actions to %smigrate %s from %s to %s",
                    ((rsc->partial_migration_target == NULL)? "" : "partially "),
                    rsc->id, pcmk__node_name(current),
                    pcmk__node_name(rsc->allocated_to));
    start = start_action(rsc, rsc->allocated_to, TRUE);
    stop = stop_action(rsc, current, TRUE);

    if (rsc->partial_migration_target == NULL) {
        migrate_to = custom_action(rsc, pcmk__op_key(rsc->id,
                                                     PCMK_ACTION_MIGRATE_TO, 0),
                                   PCMK_ACTION_MIGRATE_TO, current, TRUE,
                                   rsc->private->scheduler);
    }
    migrate_from = custom_action(rsc, pcmk__op_key(rsc->id,
                                                   PCMK_ACTION_MIGRATE_FROM, 0),
                                 PCMK_ACTION_MIGRATE_FROM, rsc->allocated_to,
                                 TRUE, rsc->private->scheduler);

    pcmk__set_action_flags(start, pcmk_action_migratable);
    pcmk__set_action_flags(stop, pcmk_action_migratable);

    // This is easier than trying to delete it from the graph
    pcmk__set_action_flags(start, pcmk_action_pseudo);

    if (rsc->partial_migration_target == NULL) {
        pcmk__set_action_flags(migrate_from, pcmk_action_migratable);
        pcmk__set_action_flags(migrate_to, pcmk_action_migratable);
        migrate_to->needs = start->needs;

        // Probe -> migrate_to -> migrate_from
        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_MONITOR, 0),
                           NULL,
                           rsc,
                           pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_TO, 0),
                           NULL, pcmk__ar_ordered, rsc->private->scheduler);
        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_TO, 0),
                           NULL,
                           rsc,
                           pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_FROM, 0),
                           NULL,
                           pcmk__ar_ordered|pcmk__ar_unmigratable_then_blocks,
                           rsc->private->scheduler);
    } else {
        pcmk__set_action_flags(migrate_from, pcmk_action_migratable);
        migrate_from->needs = start->needs;

        // Probe -> migrate_from (migrate_to already completed)
        pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_MONITOR, 0),
                           NULL,
                           rsc,
                           pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_FROM, 0),
                           NULL, pcmk__ar_ordered, rsc->private->scheduler);
    }

    // migrate_from before stop or start
    pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_FROM, 0),
                       NULL,
                       rsc, pcmk__op_key(rsc->id, PCMK_ACTION_STOP, 0),
                       NULL,
                       pcmk__ar_ordered|pcmk__ar_unmigratable_then_blocks,
                       rsc->private->scheduler);
    pcmk__new_ordering(rsc, pcmk__op_key(rsc->id, PCMK_ACTION_MIGRATE_FROM, 0),
                       NULL,
                       rsc, pcmk__op_key(rsc->id, PCMK_ACTION_START, 0),
                       NULL,
                       pcmk__ar_ordered
                       |pcmk__ar_unmigratable_then_blocks
                       |pcmk__ar_first_else_then,
                       rsc->private->scheduler);

    if (migrate_to != NULL) {
        add_migration_meta(migrate_to, current, rsc->allocated_to);

        if (!pcmk_is_set(rsc->flags, pcmk__rsc_is_remote_connection)) {
            /* migrate_to takes place on the source node, but can affect the
             * target node depending on how the agent is written. Because of
             * this, pending migrate_to actions must be recorded in the CIB,
             * in case the source node loses membership while the migrate_to
             * action is still in flight.
             *
             * However we know Pacemaker Remote connection resources don't
             * require this, so we skip this for them. (Although it wouldn't
             * hurt, and now that PCMK_META_RECORD_PENDING defaults to true,
             * skipping it matters even less.)
             */
            pcmk__insert_meta(migrate_to,
                              PCMK_META_RECORD_PENDING, PCMK_VALUE_TRUE);
        }
    }

    add_migration_meta(migrate_from, current, rsc->allocated_to);
}

/*!
 * \internal
 * \brief Abort a dangling migration by scheduling a stop (and possibly cleanup)
 *
 * \param[in]     data       Source node of dangling migration
 * \param[in,out] user_data  Resource involved in dangling migration
 */
void
pcmk__abort_dangling_migration(void *data, void *user_data)
{
    const pcmk_node_t *dangling_source = (const pcmk_node_t *) data;
    pcmk_resource_t *rsc = (pcmk_resource_t *) user_data;

    pcmk_action_t *stop = NULL;
    bool cleanup = pcmk_is_set(rsc->private->scheduler->flags,
                               pcmk_sched_remove_after_stop);

    pcmk__rsc_trace(rsc,
                    "Scheduling stop%s for %s on %s due to dangling migration",
                    (cleanup? " and cleanup" : ""), rsc->id,
                    pcmk__node_name(dangling_source));
    stop = stop_action(rsc, dangling_source, FALSE);
    pcmk__set_action_flags(stop, pcmk_action_migration_abort);
    if (cleanup) {
        pcmk__schedule_cleanup(rsc, dangling_source, false);
    }
}

/*!
 * \internal
 * \brief Check whether a resource can migrate
 *
 * \param[in] rsc   Resource to check
 * \param[in] node  Resource's current node
 *
 * \return true if \p rsc can migrate, otherwise false
 */
bool
pcmk__rsc_can_migrate(const pcmk_resource_t *rsc, const pcmk_node_t *current)
{
    CRM_CHECK(rsc != NULL, return false);

    if (!pcmk_is_set(rsc->flags, pcmk__rsc_migratable)) {
        pcmk__rsc_trace(rsc,
                        "%s cannot migrate because "
                        "the configuration does not allow it", rsc->id);
        return false;
    }

    if (!pcmk_is_set(rsc->flags, pcmk__rsc_managed)) {
        pcmk__rsc_trace(rsc, "%s cannot migrate because it is not managed",
                        rsc->id);
        return false;
    }

    if (pcmk_is_set(rsc->flags, pcmk__rsc_failed)) {
        pcmk__rsc_trace(rsc, "%s cannot migrate because it is failed", rsc->id);
        return false;
    }

    if (pcmk_is_set(rsc->flags, pcmk__rsc_start_pending)) {
        pcmk__rsc_trace(rsc, "%s cannot migrate because it has a start pending",
                        rsc->id);
        return false;
    }

    if ((current == NULL) || current->details->unclean) {
        pcmk__rsc_trace(rsc,
                        "%s cannot migrate because "
                        "its current node (%s) is unclean",
                        rsc->id, pcmk__node_name(current));
        return false;
    }

    if ((rsc->allocated_to == NULL) || rsc->allocated_to->details->unclean) {
        pcmk__rsc_trace(rsc,
                        "%s cannot migrate because "
                        "its next node (%s) is unclean",
                        rsc->id, pcmk__node_name(rsc->allocated_to));
        return false;
    }

    return true;
}

/*!
 * \internal
 * \brief Get an action name from an action or operation key
 *
 * \param[in] action  If not NULL, get action name from here
 * \param[in] key     If not NULL, get action name from here
 *
 * \return Newly allocated copy of action name (or NULL if none available)
 */
static char *
task_from_action_or_key(const pcmk_action_t *action, const char *key)
{
    char *res = NULL;

    if (action != NULL) {
        res = pcmk__str_copy(action->task);
    } else if (key != NULL) {
        parse_op_key(key, NULL, &res, NULL);
    }
    return res;
}

/*!
 * \internal
 * \brief Order migration actions equivalent to a given ordering
 *
 * Orderings involving start, stop, demote, and promote actions must be honored
 * during a migration as well, so duplicate any such ordering for the
 * corresponding migration actions.
 *
 * \param[in,out] order     Ordering constraint to check
 */
void
pcmk__order_migration_equivalents(pcmk__action_relation_t *order)
{
    char *first_task = NULL;
    char *then_task = NULL;
    bool then_migratable;
    bool first_migratable;

    // Only orderings between unrelated resources are relevant
    if ((order->rsc1 == NULL) || (order->rsc2 == NULL)
        || (order->rsc1 == order->rsc2)
        || is_parent(order->rsc1, order->rsc2)
        || is_parent(order->rsc2, order->rsc1)) {
        return;
    }

    // Only orderings involving at least one migratable resource are relevant
    first_migratable = pcmk_is_set(order->rsc1->flags, pcmk__rsc_migratable);
    then_migratable = pcmk_is_set(order->rsc2->flags, pcmk__rsc_migratable);
    if (!first_migratable && !then_migratable) {
        return;
    }

    // Check which actions are involved
    first_task = task_from_action_or_key(order->action1, order->task1);
    then_task = task_from_action_or_key(order->action2, order->task2);

    if (pcmk__str_eq(first_task, PCMK_ACTION_START, pcmk__str_none)
        && pcmk__str_eq(then_task, PCMK_ACTION_START, pcmk__str_none)) {

        uint32_t flags = pcmk__ar_ordered;

        if (first_migratable && then_migratable) {
            /* A start then B start
             * -> A migrate_from then B migrate_to */
            pcmk__new_ordering(order->rsc1,
                               pcmk__op_key(order->rsc1->id,
                                            PCMK_ACTION_MIGRATE_FROM, 0),
                               NULL, order->rsc2,
                               pcmk__op_key(order->rsc2->id,
                                            PCMK_ACTION_MIGRATE_TO, 0),
                               NULL, flags, order->rsc1->private->scheduler);
        }

        if (then_migratable) {
            if (first_migratable) {
                pcmk__set_relation_flags(flags, pcmk__ar_if_first_unmigratable);
            }

            /* A start then B start
             * -> A start then B migrate_to (if start is not part of a
             *    migration)
             */
            pcmk__new_ordering(order->rsc1,
                               pcmk__op_key(order->rsc1->id,
                                            PCMK_ACTION_START, 0),
                               NULL, order->rsc2,
                               pcmk__op_key(order->rsc2->id,
                                            PCMK_ACTION_MIGRATE_TO, 0),
                               NULL, flags, order->rsc1->private->scheduler);
        }

    } else if (then_migratable
               && pcmk__str_eq(first_task, PCMK_ACTION_STOP, pcmk__str_none)
               && pcmk__str_eq(then_task, PCMK_ACTION_STOP, pcmk__str_none)) {

        uint32_t flags = pcmk__ar_ordered;

        if (first_migratable) {
            pcmk__set_relation_flags(flags, pcmk__ar_if_first_unmigratable);
        }

        /* For an ordering "stop A then stop B", if A is moving via restart, and
         * B is migrating, enforce that B's migrate_to occurs after A's stop.
         */
        pcmk__new_ordering(order->rsc1,
                           pcmk__op_key(order->rsc1->id, PCMK_ACTION_STOP, 0),
                           NULL,
                           order->rsc2,
                           pcmk__op_key(order->rsc2->id,
                                        PCMK_ACTION_MIGRATE_TO, 0),
                           NULL, flags, order->rsc1->private->scheduler);

        // Also order B's migrate_from after A's stop during partial migrations
        if (order->rsc2->partial_migration_target != NULL) {
            pcmk__new_ordering(order->rsc1,
                               pcmk__op_key(order->rsc1->id, PCMK_ACTION_STOP,
                                            0),
                               NULL, order->rsc2,
                               pcmk__op_key(order->rsc2->id,
                                            PCMK_ACTION_MIGRATE_FROM, 0),
                               NULL, flags, order->rsc1->private->scheduler);
        }

    } else if (pcmk__str_eq(first_task, PCMK_ACTION_PROMOTE, pcmk__str_none)
               && pcmk__str_eq(then_task, PCMK_ACTION_START, pcmk__str_none)) {

        uint32_t flags = pcmk__ar_ordered;

        if (then_migratable) {
            /* A promote then B start
             * -> A promote then B migrate_to */
            pcmk__new_ordering(order->rsc1,
                               pcmk__op_key(order->rsc1->id,
                                            PCMK_ACTION_PROMOTE, 0),
                               NULL, order->rsc2,
                               pcmk__op_key(order->rsc2->id,
                                            PCMK_ACTION_MIGRATE_TO, 0),
                               NULL, flags, order->rsc1->private->scheduler);
        }

    } else if (pcmk__str_eq(first_task, PCMK_ACTION_DEMOTE, pcmk__str_none)
               && pcmk__str_eq(then_task, PCMK_ACTION_STOP, pcmk__str_none)) {

        uint32_t flags = pcmk__ar_ordered;

        if (then_migratable) {
            /* A demote then B stop
             * -> A demote then B migrate_to */
            pcmk__new_ordering(order->rsc1,
                               pcmk__op_key(order->rsc1->id,
                                            PCMK_ACTION_DEMOTE, 0),
                               NULL, order->rsc2,
                               pcmk__op_key(order->rsc2->id,
                                            PCMK_ACTION_MIGRATE_TO, 0),
                               NULL, flags, order->rsc1->private->scheduler);

            // Order B migrate_from after A demote during partial migrations
            if (order->rsc2->partial_migration_target != NULL) {
                pcmk__new_ordering(order->rsc1,
                                   pcmk__op_key(order->rsc1->id,
                                                PCMK_ACTION_DEMOTE, 0),
                                   NULL, order->rsc2,
                                   pcmk__op_key(order->rsc2->id,
                                                PCMK_ACTION_MIGRATE_FROM, 0),
                                   NULL, flags,
                                   order->rsc1->private->scheduler);
            }
        }
    }

    free(first_task);
    free(then_task);
}
